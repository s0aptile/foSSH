"""Runs `advisor_client` off the GTK main thread, the same shape `agent.py`
already established for `fossh-agent`: one dedicated worker thread, a
queue, results crossing back to the main loop only through
`GLib.idle_add`. `advisor_client.explain()` can take several real
seconds — this project already measured that — and none of that may
ever run where it would freeze the window.

Unlike `Agent`, there is no child process here: `advisor_client` talks
to Ollama itself over loopback HTTP. The thread exists to keep that
blocking call off the UI thread, not to own a subprocess.
"""

from __future__ import annotations

import queue
import threading
from typing import Any, Callable

from gi.repository import GLib

from . import advisor_client as ac

class _Job:
    __slots__ = ("kind", "arg", "on_ok", "on_err")

    def __init__(self, kind: str, arg: Any, on_ok, on_err) -> None:
        self.kind = kind
        self.arg = arg
        self.on_ok = on_ok
        self.on_err = on_err

class AdvisorBridge:
    """One worker thread, started lazily, stopped once at shutdown.

    Every call this project has already measured to be slow
    (`explain`, `warm`) goes through here rather than being called
    directly from a view.
    """

    def __init__(self) -> None:
        self._queue: queue.Queue[_Job | None] = queue.Queue()
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()

    def _ensure_started(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._worker, name="fossh-advisor-io", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        if self._stopping.is_set():
            return
        self._stopping.set()
        self._queue.put(None)

    def explain_async(
        self,
        prompt: str,
        *,
        on_ok: Callable[[str], None] | None = None,
        on_err: Callable[[Exception], None] | None = None,
    ) -> None:
        """Queues `advisor_client.explain(prompt)`. Never touches a widget."""
        if self._stopping.is_set():
            return
        self._ensure_started()
        self._queue.put(_Job("explain", prompt, on_ok, on_err))

    def warm_async(self) -> None:
        """Fire-and-forget: load the model ahead of the first real ask.

        No callback — a failed warm is not a user-facing event, just a
        slower first `explain_async`. `advisor_client.warm()` already
        swallows `AdvisorUnavailable` itself for the same reason.
        """
        if self._stopping.is_set():
            return
        self._ensure_started()
        self._queue.put(_Job("warm", None, None, None))

    def _worker(self) -> None:
        while True:
            job = self._queue.get()
            if job is None:
                return
            try:
                if job.kind == "warm":
                    ac.warm()
                    continue
                result = ac.explain(job.arg)
            except Exception as exc:  # noqa: BLE001 - reported through on_err, never raised on this thread
                if job.on_err:
                    GLib.idle_add(job.on_err, exc)
                continue
            if job.on_ok:
                GLib.idle_add(job.on_ok, result)
