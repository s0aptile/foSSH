"""Integration verification: drive a real browser at a real page and
say whether foSSH actually saw it.

This answers the first question everyone has after installing
analytics, and the one that is otherwise answered by refreshing a
dashboard and squinting: *is it working?* A page can look perfectly
fine while its beacon 404s, while a Content-Security-Policy blocks it,
while a caching layer swallows it, or while the write key is wrong —
and none of that is visible from the server side, because from the
server side nothing arrived and nothing arriving looks exactly like
nobody visiting.

So: launch a real headless browser, load the operator's own page, and
watch the network for a request to their foSSH endpoint. Report what
actually happened.

## What this is not

It is not a browser for the operator to use, not a scraper, and not a
monitoring service. One page, one load, one verdict, then the browser
is gone.

## What it costs, stated before it runs

The visit is a **real** visit. If the integration works, it produces a
real event in the operator's own data — that is precisely the proof
being sought, so it cannot be avoided without also not testing the
thing. `USER_AGENT` marks it so it can be recognised afterwards, and
the console says so plainly before starting rather than explaining
afterwards where the extra pageview came from.

## Isolation

Every run gets a fresh, ephemeral browser context: no persistent
profile, no cookies carried in or out, no storage reused between runs,
downloads refused, and no permissions granted. Two verifications of the
same site cannot influence each other, and nothing from the operator's
own browsing is present.

Only three things are recorded from the page: the URLs of requests that
match the foSSH endpoint, their status codes, and timings. Page
content, form values, and response bodies are never read.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Callable

#: Identifies the visit in the operator's own data afterwards.
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36 foSSH-Verify/0.2.0"
)

#: Hard ceiling on a run. A page that has not fired its beacon within
#: this has not fired it.
DEFAULT_TIMEOUT_MS = 20_000

#: How long to keep watching after the page reports itself loaded.
#: Beacons are commonly sent from a deferred script or on the first
#: idle callback, so stopping at `load` would report a false negative
#: on a correct integration.
SETTLE_MS = 3_000

#: What a foSSH ingest request looks like. Deliberately broad — the
#: endpoint path is whatever the operator configured — and narrowed by
#: the caller's own `endpoint_hint` when there is one.
DEFAULT_PATTERNS = (
    r"/fossh",
    r"/collect",
    r"/px\.gif",
    r"/event",
)


@dataclass
class Hit:
    url: str
    method: str
    status: int | None
    ms_after_start: int


@dataclass
class Result:
    ok: bool
    summary: str
    detail: str = ""
    hits: list[Hit] = field(default_factory=list)
    page_status: int | None = None
    total_ms: int = 0
    #: Set when the browser could not be used at all, as opposed to the
    #: page simply not firing anything. The console shows these very
    #: differently: one is a problem with the operator's site, the
    #: other is a problem with this machine.
    unavailable: bool = False


class VerificationUnavailable(Exception):
    """Playwright or its browser is missing."""


def _install_hint() -> str:
    return (
        "Integration verification needs Playwright and its bundled Chromium, which are not "
        "packaged by Fedora and are not installed by foSSH.\n\n"
        "    pip install --user playwright\n"
        "    python3 -m playwright install chromium\n\n"
        "Everything else in this console works without them; only this check is unavailable."
    )


def available() -> bool:
    """Whether a verification could run right now.

    Checked before the button is offered, so an operator is not invited
    to press something that will only tell them it cannot work.
    """
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
    except ImportError:
        return False
    return True


def validate_target(url: str) -> str | None:
    """Refuses anything that is not an ordinary web page.

    Returns a message, or `None` when the URL is fine. The browser
    would happily open `file:///etc/shadow` and this is not a file
    viewer; the schemes are restricted to the two that make sense for
    the thing being tested.
    """
    if not url.strip():
        return "Enter the address of a page on your site."
    if not url.startswith(("http://", "https://")):
        return "That must be an http:// or https:// address."
    if any(c.isspace() or ord(c) < 32 for c in url):
        return "That address contains a space or a control character."
    return None


def verify(
    url: str,
    *,
    endpoint_hint: str = "",
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
    on_progress: Callable[[str], None] | None = None,
) -> Result:
    """Loads `url` once and reports whether foSSH saw it.

    Blocking, and expected to be called from a worker thread — never
    from the GTK main loop, which it would freeze for the full timeout.
    """

    def progress(message: str) -> None:
        if on_progress:
            on_progress(message)

    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError:
        return Result(ok=False, summary="Verification is not available", detail=_install_hint(), unavailable=True)

    patterns = list(DEFAULT_PATTERNS)
    if endpoint_hint.strip():
        # An exact endpoint beats the heuristics, so it goes first and
        # is escaped -- it is a URL, not a pattern the operator wrote.
        patterns.insert(0, re.escape(endpoint_hint.strip()))
    matcher = re.compile("|".join(patterns))

    hits: list[Hit] = []
    started = time.monotonic()

    def elapsed_ms() -> int:
        return int((time.monotonic() - started) * 1000)

    try:
        with sync_playwright() as p:
            progress("Starting a browser…")
            browser = p.chromium.launch(
                headless=True,
                # No sandbox concessions and no remote debugging port.
                # The defaults are the safe ones; this only refuses the
                # things that would weaken them.
                args=["--disable-background-networking", "--no-first-run"],
            )
            try:
                # Ephemeral by construction: `new_context` with no
                # storage state and no persistent user-data-dir means
                # nothing survives this block.
                context = browser.new_context(
                    user_agent=USER_AGENT,
                    accept_downloads=False,
                    java_script_enabled=True,
                    ignore_https_errors=False,
                )
                context.set_default_timeout(timeout_ms)
                page = context.new_page()

                # Two events, not one, and the reason is a real trap.
                #
                # `requestfinished` fires when a response body has been
                # fully read -- and a beacon endpoint answering `204 No
                # Content` has no body, so for the exact request shape
                # this feature exists to detect, it may never fire at
                # all. Verified directly against a real Chromium: for a
                # `fetch()` to a 204 endpoint, `request` and `response`
                # both fire and `requestfinished` does not.
                #
                # So `request` records that the beacon was *sent* --
                # which is the thing actually being tested, and is also
                # all that is observable for a `sendBeacon` during
                # unload -- and `response` fills in the status when
                # there is one. Keyed by URL and method so the two
                # events describe one hit rather than two.
                by_key: dict[tuple[str, str], Hit] = {}

                def record(url: str, method: str) -> Hit | None:
                    if not matcher.search(url):
                        return None
                    key = (url, method)
                    hit = by_key.get(key)
                    if hit is None:
                        hit = Hit(
                            url=url,
                            method=method,
                            status=None,
                            ms_after_start=elapsed_ms(),
                        )
                        by_key[key] = hit
                        hits.append(hit)
                    return hit

                page.on("request", lambda r: record(r.url, r.method))

                def on_response(response) -> None:
                    hit = record(response.request.url, response.request.method)
                    if hit is not None:
                        hit.status = response.status

                page.on("response", on_response)

                progress(f"Loading {url}…")
                response = page.goto(url, wait_until="load")
                page_status = response.status if response else None

                progress("Watching for the beacon…")
                # Beacons commonly fire after `load`, from a deferred
                # script or an idle callback. Waiting for network idle
                # and then a fixed settle is what makes a correct
                # integration report as correct.
                try:
                    page.wait_for_load_state("networkidle", timeout=SETTLE_MS)
                except PlaywrightError:
                    pass
                page.wait_for_timeout(SETTLE_MS)

                context.close()
            finally:
                browser.close()
    except ImportError:
        return Result(ok=False, summary="Verification is not available", detail=_install_hint(), unavailable=True)
    except Exception as exc:  # noqa: BLE001 -- playwright raises broadly
        message = str(exc)
        if "Executable doesn't exist" in message or "playwright install" in message:
            return Result(
                ok=False,
                summary="The verification browser is not installed",
                detail=_install_hint(),
                unavailable=True,
            )
        return Result(
            ok=False,
            summary="The page could not be loaded",
            detail=_first_line(message),
            total_ms=elapsed_ms(),
        )

    return _summarise(hits, page_status, elapsed_ms())


def _first_line(message: str) -> str:
    """Playwright errors are long and start with the useful sentence."""
    line = message.strip().splitlines()[0] if message.strip() else message
    return line[:300]


def _summarise(hits: list[Hit], page_status: int | None, total_ms: int) -> Result:
    if page_status is not None and page_status >= 400:
        return Result(
            ok=False,
            summary=f"That page returned {page_status}",
            detail=(
                "The browser reached your server but the page itself is an error, so nothing "
                "on it ran. Check the address before looking at the integration."
            ),
            hits=hits,
            page_status=page_status,
            total_ms=total_ms,
        )

    if not hits:
        return Result(
            ok=False,
            summary="No event reached foSSH",
            detail=(
                "The page loaded, but nothing on it sent anything to a foSSH endpoint. The "
                "usual causes are the snippet not being on this particular page, a "
                "Content-Security-Policy blocking the request, or a caching layer serving a "
                "copy of the page from before the snippet was added. If you integrated "
                "server-side rather than in the page, this check cannot see it — it only "
                "watches what the browser sends."
            ),
            hits=hits,
            page_status=page_status,
            total_ms=total_ms,
        )

    refused = [h for h in hits if h.status is not None and h.status >= 400]
    if refused and len(refused) == len(hits):
        first = refused[0]
        return Result(
            ok=False,
            summary=f"foSSH refused the event ({first.status})",
            detail=(
                "The page did send an event and your server answered, but rejected it. A 401 "
                "or 403 is usually the wrong write key; a 404 is usually the wrong endpoint "
                "path."
            ),
            hits=hits,
            page_status=page_status,
            total_ms=total_ms,
        )

    accepted = [h for h in hits if h.status is None or h.status < 400]
    first = accepted[0]
    return Result(
        ok=True,
        summary="The integration is working",
        detail=(
            f"The page sent {len(accepted)} event"
            f"{'s' if len(accepted) != 1 else ''} to foSSH, the first "
            f"{first.ms_after_start} ms after the load began. This counted as a real visit and "
            "will appear in your figures."
        ),
        hits=hits,
        page_status=page_status,
        total_ms=total_ms,
    )
