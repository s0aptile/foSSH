"""Real browser, real page, real verdict.

Every test here stands up an actual HTTP server on loopback and drives
an actual headless Chromium at it. Nothing is mocked, because the thing
being tested *is* the interaction with a real browser — a mocked
Playwright would only confirm that this file's own assumptions agree
with themselves.

Skipped, not failed, when Playwright or its browser is absent: that is
an environment fact rather than a defect in this code, and a test suite
that fails on a machine which simply has not run `playwright install`
teaches people to ignore it.

    python3 -m pytest gui/tests/test_verify.py
"""

from __future__ import annotations

import http.server
import socket
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fossh_console import verify  # noqa: E402

pytestmark = pytest.mark.skipif(
    not verify.available(), reason="Playwright is not installed"
)


PAGE_WITH_BEACON = """<!doctype html>
<html><head><title>Test</title></head>
<body>
<h1>hello</h1>
<script>
  // What a real foSSH page integration looks like from the browser's
  // side: one request to the ingest endpoint, fired after load.
  window.addEventListener('load', function () {
    fetch('/fossh/collect?p=' + encodeURIComponent(location.pathname));
  });
</script>
</body></html>
"""

PAGE_WITHOUT_BEACON = """<!doctype html>
<html><head><title>Quiet</title></head><body><h1>nothing here</h1></body></html>
"""


class _Handler(http.server.BaseHTTPRequestHandler):
    """Serves the two fixtures and answers the beacon."""

    pages: dict[str, tuple[int, str]] = {}
    beacon_status = 204

    def do_GET(self):  # noqa: N802 - stdlib naming
        path = self.path.split("?")[0]
        if path.startswith("/fossh/collect"):
            self.send_response(self.beacon_status)
            self.end_headers()
            return
        status, body = self.pages.get(path, (404, "<h1>no</h1>"))
        encoded = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *args):
        return  # keep pytest output readable


@pytest.fixture
def server():
    """A real HTTP server on a free loopback port."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    _Handler.pages = {
        "/with": (200, PAGE_WITH_BEACON),
        "/without": (200, PAGE_WITHOUT_BEACON),
        "/broken": (500, "<h1>server error</h1>"),
    }
    _Handler.beacon_status = 204

    httpd = http.server.HTTPServer(("127.0.0.1", port), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()
    httpd.server_close()


class TestTargetValidation:
    """No browser needed; these run everywhere."""

    def test_a_file_url_is_refused(self):
        # The browser would happily open it. This is not a file viewer.
        assert verify.validate_target("file:///etc/shadow") is not None

    def test_other_schemes_are_refused(self):
        for url in ["ftp://x.example", "javascript:alert(1)", "data:text/html,x", "x.example"]:
            assert verify.validate_target(url) is not None, url

    def test_ordinary_web_addresses_are_accepted(self):
        assert verify.validate_target("https://example.com/") is None
        assert verify.validate_target("http://127.0.0.1:8080/page") is None

    def test_empty_and_whitespace_are_refused_with_a_useful_message(self):
        message = verify.validate_target("")
        assert message and "address" in message.lower()

    def test_a_url_with_a_control_character_is_refused(self):
        assert verify.validate_target("https://x.example/\r\nHost: evil") is not None


class TestAgainstARealBrowser:
    def test_a_page_that_fires_a_beacon_is_reported_as_working(self, server):
        result = verify.verify(f"{server}/with", timeout_ms=25_000)
        assert result.ok, f"{result.summary}: {result.detail}"
        assert result.hits, "the beacon request was not observed at all"
        assert "/fossh/collect" in result.hits[0].url
        # The operator is told this counted, because it did.
        assert "real visit" in result.detail

    def test_a_page_with_no_beacon_is_reported_as_not_working(self, server):
        result = verify.verify(f"{server}/without", timeout_ms=25_000)
        assert not result.ok
        assert not result.hits
        assert "No event reached foSSH" in result.summary
        # The failure has to name real causes, since "it didn't work"
        # is exactly the answer the operator already had.
        assert "Content-Security-Policy" in result.detail
        assert not result.unavailable

    def test_a_page_that_errors_is_distinguished_from_a_missing_beacon(self, server):
        # These need completely different responses from the operator,
        # so conflating them would send them looking in the wrong place.
        result = verify.verify(f"{server}/broken", timeout_ms=25_000)
        assert not result.ok
        assert result.page_status == 500
        assert "500" in result.summary

    def test_a_refused_beacon_is_distinguished_from_an_absent_one(self, server):
        # A 401 means the integration IS wired up and the key is wrong;
        # reporting that as "nothing fired" would be actively
        # misleading.
        _Handler.beacon_status = 403
        result = verify.verify(f"{server}/with", timeout_ms=25_000)
        assert not result.ok
        assert result.hits, "the request was still made and must be reported"
        assert "refused" in result.summary.lower()
        assert "403" in result.summary

    def test_an_unreachable_host_fails_as_a_load_error_not_a_crash(self):
        result = verify.verify("http://127.0.0.1:9/", timeout_ms=15_000)
        assert not result.ok
        assert not result.unavailable, "the browser was available; the page was not"
        assert result.detail, "a load failure must say something"

    def test_the_visit_identifies_itself(self, server):
        # So an operator can find it afterwards in their own data.
        assert "foSSH-Verify" in verify.USER_AGENT

    def test_an_endpoint_hint_is_matched_literally_not_as_a_pattern(self, server):
        # The hint comes from configuration, and a '.' or '?' in it
        # would otherwise be regex metacharacters matching far more
        # than intended.
        result = verify.verify(
            f"{server}/with",
            endpoint_hint="/fossh/collect?p=/with",
            timeout_ms=25_000,
        )
        assert result.ok, f"{result.summary}: {result.detail}"

    def test_progress_is_reported_while_it_runs(self, server):
        seen: list[str] = []
        verify.verify(f"{server}/with", timeout_ms=25_000, on_progress=seen.append)
        assert seen, "a run this slow must report progress"
        assert any("Loading" in m for m in seen)
