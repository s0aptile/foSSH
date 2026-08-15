"""A dialog that can outlive the reply it is waiting for.

Every dialog here makes an asynchronous call and updates itself when
the answer arrives. The operator can close the dialog before that
happens — by pressing Cancel, or Escape, or because they changed their
mind — and the reply lands anyway, on a dialog that is no longer on
screen.

Two things go wrong then, and one of them is not benign.

**Touching an orphaned widget.** GTK4 tolerates this: the widgets are
still valid GObjects, merely unparented, so setting a label on one is
harmless. Wasted work, not a defect in itself.

**Closing an already-closed dialog is not tolerated.** `Adw.Dialog`
tracks whether it is presented, and a second `close()` produces

    Adwaita-CRITICAL: Trying to close ... that's not presented

Reproduced every time: press Add, then Cancel before the reply lands.
Under the default `G_DEBUG` that is a log line and execution continues.
Under `G_DEBUG=fatal-criticals` — which GNOME's own CI and several app
test harnesses set — it aborts the process.

So this exists rather than each dialog remembering to guard its own
callbacks. The pattern already appeared twice; a third dialog written
later would have hit it too.
"""

from __future__ import annotations

import threading
from typing import Callable, TypeVar

from gi.repository import Adw

T = TypeVar("T")


class AsyncDialog(Adw.Dialog):
    """An `Adw.Dialog` that knows whether it is still open.

    Subclasses call `self.guard(...)` around any callback that may
    arrive late, and `self.close_once()` instead of `close()`.
    """

    def __init__(self) -> None:
        super().__init__()
        self._is_closed = False
        # `closed` fires however the dialog went away — the close
        # button, Escape, or a programmatic close — which is why it is
        # the signal to hang this on rather than any one of them.
        self.connect("closed", self._on_closed)
        #: Set when the dialog goes away, for a worker thread to notice
        #: and stop. A dialog with no cancellable work simply never
        #: reads it.
        self.cancelled = threading.Event()

    def _on_closed(self, *_args) -> None:
        self._is_closed = True
        self.cancelled.set()

    @property
    def is_closed(self) -> bool:
        return self._is_closed

    def close_once(self) -> None:
        """Closes, unless it is already closed.

        The whole reason this module exists — see the header.
        """
        if not self._is_closed:
            self.close()

    def guard(self, callback: Callable[[T], None]) -> Callable[[T], None]:
        """Wraps a late-arriving callback so it does nothing once the
        dialog is gone.

        Returns a callable of the same shape, so a caller can pass it
        straight to `Agent.call(on_ok=..., on_err=...)` without
        restructuring anything.
        """

        def guarded(value: T) -> None:
            if self._is_closed:
                return
            callback(value)

        return guarded
