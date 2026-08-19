"""Reproduces the ordering bug a reviewer found in `5ab4647`: `do_activate()`
called `warm_async()` unconditionally and synchronously, right after kicking
off an async `agent.hello` -> `selfheal.model_config` chain whose `on_err`
disables the advisor. `AdvisorBridge.disable()` only takes effect for calls
made after it runs; a `warm_async()` fired before the chain resolves can
still reach Ollama on a tampered-manifest install.

Nothing here needs a live GTK display or a spun main loop.
`ConsoleApplication` is built through `__new__` to skip
`Adw.Application.__init__`, and `Agent`/`ConsoleWindow` are swapped for
fakes that record callbacks instead of invoking them -- the same shape a
real async round trip has, without a subprocess or a window behind it.
`GLib.timeout_add_seconds` itself needs no display, so `do_activate()` runs
unmodified.

    python3 -m unittest gui.tests.test_app_ordering -v
    python3 -m pytest gui/tests/test_app_ordering.py -v
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gi.repository import GLib

from fossh_console import app as app_module

class FakeWindow:
    def __init__(self, *_args, **_kwargs) -> None:
        self.present_count = 0
        self.refresh_count = 0
        self.failures = []

    def present(self) -> None:
        self.present_count += 1

    def refresh_all(self) -> None:
        self.refresh_count += 1

    def report_startup_failure(self, error) -> None:
        self.failures.append(error)

class FakeAgent:
    def __init__(self, *_args, **_kwargs) -> None:
        self.calls: list[tuple[str, object, object]] = []
        self.handshake_cb: tuple[object, object] | None = None

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def handshake(self, *, on_ok, on_err) -> None:
        self.handshake_cb = (on_ok, on_err)

    def call(self, method, params=None, *, on_ok=None, on_err=None, timeout=None) -> None:
        self.calls.append((method, on_ok, on_err))

class FakeAdvisor:
    def __init__(self) -> None:
        self.warm_count = 0
        self.disabled_reason: str | None = None

    def warm_async(self) -> None:
        self.warm_count += 1

    def disable(self, reason: str) -> None:
        self.disabled_reason = reason

    def stop(self) -> None:
        pass

class OrderingTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._real_agent_cls = app_module.Agent
        self._real_window_cls = app_module.ConsoleWindow
        app_module.Agent = FakeAgent
        app_module.ConsoleWindow = FakeWindow

        self.application = app_module.ConsoleApplication.__new__(app_module.ConsoleApplication)
        self.application._window = None
        self.application._agent = None
        self.application._advisor = FakeAdvisor()
        self.application._tick_source = None

    def tearDown(self) -> None:
        if self.application._tick_source is not None:
            GLib.source_remove(self.application._tick_source)
        app_module.Agent = self._real_agent_cls
        app_module.ConsoleWindow = self._real_window_cls

class TestWarmAsyncWaitsForTheConfigCheck(OrderingTestCase):
    def test_do_activate_does_not_warm_before_handshake_resolves(self):
        self.application.do_activate()
        self.assertEqual(self.application._advisor.warm_count, 0)

    def test_do_activate_does_not_warm_between_handshake_and_config_check(self):
        self.application.do_activate()
        on_ok, _on_err = self.application._agent.handshake_cb
        on_ok({"protocol": 1})
        self.assertEqual(self.application._advisor.warm_count, 0)
        self.assertEqual(
            [method for method, _ok, _err in self.application._agent.calls],
            ["selfheal.model_config"],
        )

    def test_do_activate_warms_once_the_config_check_succeeds(self):
        self.application.do_activate()
        on_ok, _on_err = self.application._agent.handshake_cb
        on_ok({"protocol": 1})
        _method, config_on_ok, _config_on_err = self.application._agent.calls[0]
        config_on_ok({"configured": False})
        self.assertEqual(self.application._advisor.warm_count, 1)

    def test_do_activate_never_warms_when_the_config_check_fails(self):
        self.application.do_activate()
        on_ok, _on_err = self.application._agent.handshake_cb
        on_ok({"protocol": 1})
        _method, _config_on_ok, config_on_err = self.application._agent.calls[0]
        config_on_err(app_module.AgentError("unavailable", "tampered"))
        self.assertEqual(self.application._advisor.warm_count, 0)
        self.assertEqual(self.application._advisor.disabled_reason, "tampered")

class TestHandshakeOkInIsolation(OrderingTestCase):
    def test_success_path_warms_only_after_its_own_callback_fires(self):
        self.application._window = FakeWindow()
        self.application._agent = FakeAgent()

        self.application._on_handshake_ok({"protocol": 1})
        self.assertEqual(self.application._advisor.warm_count, 0)

        _method, on_ok, _on_err = self.application._agent.calls[0]
        on_ok({"configured": True})
        self.assertEqual(self.application._advisor.warm_count, 1)

    def test_error_path_disables_and_never_warms(self):
        self.application._window = FakeWindow()
        self.application._agent = FakeAgent()

        self.application._on_handshake_ok({"protocol": 1})
        _method, _on_ok, on_err = self.application._agent.calls[0]
        on_err(app_module.AgentError("unavailable", "tampered manifest"))

        self.assertEqual(self.application._advisor.warm_count, 0)
        self.assertEqual(self.application._advisor.disabled_reason, "tampered manifest")

if __name__ == "__main__":
    unittest.main()
