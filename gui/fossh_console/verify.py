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
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36 foSSH-Verify/0.0.2.2"
)

DEFAULT_TIMEOUT_MS = 20_000

SETTLE_MS = 3_000

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
        from playwright.sync_api import sync_playwright
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

class Cancelled(Exception):
    """Raised internally when `cancel` is set. Never escapes `verify`."""

def verify(
    url: str,
    *,
    endpoint_hint: str = "",
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
    on_progress: Callable[[str], None] | None = None,
    cancel: threading.Event | None = None,
) -> Result:
    """Loads `url` once and reports whether foSSH saw it.

    Blocking, and expected to be called from a worker thread — never
    from the GTK main loop, which it would freeze for the full timeout.

    `cancel` is checked at every phase boundary and throughout the
    settle wait. Without it, closing the dialog stopped updating the
    interface but did not stop the work: a real browser kept loading
    the operator's page for up to twenty-three more seconds, and — since
    a successful check is *by design* a real visit — the pageview it
    generated still landed in their data, with no window left open to
    say so. A Close button that does not stop the thing it appears to
    stop is worse than a slow feature.
    """

    def progress(message: str) -> None:
        if on_progress:
            on_progress(message)

    def check_cancelled() -> None:
        if cancel is not None and cancel.is_set():
            raise Cancelled

    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError:
        return Result(ok=False, summary="Verification is not available", detail=_install_hint(), unavailable=True)

    patterns = list(DEFAULT_PATTERNS)
    if endpoint_hint.strip():

        patterns.insert(0, re.escape(endpoint_hint.strip()))
    matcher = re.compile("|".join(patterns))

    hits: list[Hit] = []
    started = time.monotonic()

    def elapsed_ms() -> int:
        return int((time.monotonic() - started) * 1000)

    try:
        with sync_playwright() as p:
            check_cancelled()
            progress("Starting a browser…")
            browser = p.chromium.launch(
                headless=True,

                args=["--disable-background-networking", "--no-first-run"],
            )
            try:

                context = browser.new_context(
                    user_agent=USER_AGENT,
                    accept_downloads=False,
                    java_script_enabled=True,
                    ignore_https_errors=False,
                )
                context.set_default_timeout(timeout_ms)
                page = context.new_page()

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

                check_cancelled()
                progress(f"Loading {url}…")
                response = page.goto(url, wait_until="load")
                page_status = response.status if response else None
                check_cancelled()

                progress("Watching for the beacon…")

                try:
                    page.wait_for_load_state("networkidle", timeout=SETTLE_MS)
                except PlaywrightError:
                    pass

                waited = 0
                while waited < SETTLE_MS:
                    check_cancelled()
                    slice_ms = min(200, SETTLE_MS - waited)
                    page.wait_for_timeout(slice_ms)
                    waited += slice_ms

                context.close()
            finally:
                browser.close()
    except Cancelled:

        return Result(
            ok=False,
            summary="Cancelled",
            detail="The check was stopped before it finished.",
            total_ms=elapsed_ms(),
        )
    except ImportError:
        return Result(ok=False, summary="Verification is not available", detail=_install_hint(), unavailable=True)
    except Exception as exc:
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
