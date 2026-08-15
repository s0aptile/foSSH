"""The "is my integration actually working?" dialog.

Wraps `fossh_console.verify`, which drives a real browser and therefore
blocks for as long as a page load takes. That work happens on a worker
thread; every widget touch comes back through `GLib.idle_add`. Doing it
on the main loop would freeze the window for the full timeout, which is
the most visible way a desktop application can look broken.
"""

from __future__ import annotations

import threading

from gi.repository import Adw, GLib, Gtk

from .. import verify
from ..asyncdialog import AsyncDialog
from ..iconography import symbolic_name


class VerifyDialog(AsyncDialog):
    def __init__(self, *, site_hint: str = "") -> None:
        super().__init__()
        self.set_title("Verify integration")
        self.set_content_width(560)
        self._running = False

        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        self._close = Gtk.Button(label="Close")
        self._close.connect("clicked", lambda *_: self.close_once())
        header.pack_start(self._close)
        self._run = Gtk.Button(label="Run check")
        self._run.add_css_class("suggested-action")
        self._run.connect("clicked", lambda *_: self._start())
        header.pack_end(self._run)
        toolbar.add_top_bar(header)

        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        body.set_margin_top(16)
        body.set_margin_bottom(16)
        body.set_margin_start(16)
        body.set_margin_end(16)

        intro = Gtk.Label(xalign=0)
        intro.set_wrap(True)
        intro.add_css_class("caption")
        intro.set_text(
            "This opens a real browser on this machine, loads the page you give it, and "
            "watches whether anything on it reaches foSSH. If your integration is working, "
            "the visit is counted like any other — that is what proves it works, so it "
            "cannot be avoided."
        )
        body.append(intro)

        group = Adw.PreferencesGroup()
        self._url = Adw.EntryRow(title="Page address")
        self._url.set_text(site_hint)
        self._url.connect("changed", lambda *_: self._validate())
        group.add(self._url)
        self._endpoint = Adw.EntryRow(title="Your foSSH endpoint (optional)")
        self._endpoint.set_tooltip_text(
            "If your endpoint is at an unusual path, give it here so the check knows exactly "
            "what to look for."
        )
        group.add(self._endpoint)
        body.append(group)

        self._problem = Gtk.Label(xalign=0)
        self._problem.add_css_class("caption")
        self._problem.add_css_class("error")
        self._problem.set_wrap(True)
        self._problem.set_visible(False)
        body.append(self._problem)

        self._status = Adw.StatusPage()
        self._status.set_visible(False)
        self._status.set_vexpand(True)
        body.append(self._status)

        self._spinner_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self._spinner_row.set_visible(False)
        self._spinner_row.append(Adw.Spinner(width_request=20, height_request=20))
        self._progress = Gtk.Label(xalign=0)
        self._progress.add_css_class("caption")
        self._spinner_row.append(self._progress)
        body.append(self._spinner_row)

        toolbar.set_content(body)
        self.set_child(toolbar)
        self._validate()

    def _validate(self) -> bool:
        if self._running:
            return False
        problem = verify.validate_target(self._url.get_text())
        # Nothing typed yet is not a complaint.
        show = bool(self._url.get_text().strip()) and problem is not None
        self._problem.set_text(problem or "")
        self._problem.set_visible(show)
        ready = problem is None
        self._run.set_sensitive(ready)
        return ready

    def _start(self) -> None:
        if not self._validate():
            return
        url = self._url.get_text().strip()
        hint = self._endpoint.get_text().strip()

        self._running = True
        self._run.set_sensitive(False)
        self._status.set_visible(False)
        self._problem.set_visible(False)
        self._spinner_row.set_visible(True)
        self._progress.set_text("Starting…")

        def report(message: str) -> None:
            # Guarded: the dialog may be gone by the time this lands.
            if not self.is_closed:
                GLib.idle_add(self._progress.set_text, message)

        def work() -> None:
            # `self.cancelled` is set by AsyncDialog when the dialog
            # closes, so closing now genuinely stops the browser rather
            # than merely hiding the window it was reporting to.
            result = verify.verify(
                url, endpoint_hint=hint, on_progress=report, cancel=self.cancelled
            )
            GLib.idle_add(self._finish, result)

        threading.Thread(target=work, name="fossh-verify", daemon=True).start()

    def _finish(self, result: verify.Result) -> None:
        # The dialog may have been closed while the worker ran. Its
        # widgets are still valid GObjects, so touching them would not
        # crash — it would just be work nobody sees.
        if self.is_closed:
            return False
        self._running = False
        self._spinner_row.set_visible(False)
        self._run.set_sensitive(True)

        if result.ok:
            icon = symbolic_name("verified")
        elif result.unavailable:
            icon = symbolic_name("pending")
        else:
            icon = symbolic_name("warning")

        self._status.set_icon_name(icon)
        self._status.set_title(result.summary)
        self._status.set_description(result.detail)
        self._status.set_visible(True)
        return False
