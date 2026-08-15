#!/usr/bin/env python3
"""Renders each console page to a PNG, for looking at.

Not a test — nothing here asserts. It exists because "the process
stayed up for twenty seconds" is not evidence that anything on screen
is right, and a layout mistake is far cheaper to see than to reason
about. Renders through the window's own GSK renderer, so what lands in
the file is what the compositor would have shown.

    PYTHONPATH=gui python3 gui/tests/screenshot.py /tmp/shots
"""

from __future__ import annotations

import sys
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gdk, GLib, Graphene, Gtk  # noqa: E402

from fossh_console.agent import Agent, AgentError  # noqa: E402
from fossh_console.app import ConsoleApplication  # noqa: E402
from fossh_console.window import PAGES, ConsoleWindow  # noqa: E402

OUT_DIR = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/fossh-console-shots")


def capture(window: Gtk.Window, path: Path) -> bool:
    """Renders the realized window into `path`.

    The window background is painted first, deliberately. GTK header
    bars are transparent and rely on the window's own background
    showing through; a `WidgetPaintable` snapshot has no window behind
    it, so those regions come out with alpha 0. Saved straight to PNG
    they then composite against whatever an image viewer happens to
    use -- usually white -- and the header appears pale with
    near-invisible text.

    That is not a cosmetic problem with the file. It made a reviewer
    report a contrast defect in the header that does not exist in the
    running application, which is exactly the failure mode a
    screenshot used as a verification tool must not have.
    """
    child = window.get_content()
    if child is None:
        return False
    width = child.get_width()
    height = child.get_height()
    if width <= 0 or height <= 0:
        return False

    snapshot = Gtk.Snapshot()

    # The ground the real window paints on, under everything else.
    from fossh_console.palette import scheme
    background = Gdk.RGBA()
    background.parse(scheme(Adw.StyleManager.get_default().get_dark())["brand_bg"])
    snapshot.append_color(background, Graphene.Rect().init(0, 0, width, height))

    paintable = Gtk.WidgetPaintable.new(child)
    paintable.snapshot(snapshot, width, height)
    node = snapshot.to_node()
    if node is None:
        return False

    renderer = window.get_renderer()
    if renderer is None:
        return False
    texture = renderer.render_texture(node, None)
    path.parent.mkdir(parents=True, exist_ok=True)
    texture.save_to_png(str(path))
    return True


class Harness(ConsoleApplication):
    """Subclasses the real application rather than reimplementing it.

    An earlier revision was a bare `Adw.Application` that called
    `ConsoleApplication._load_styles(self)` as an unbound function to
    borrow the stylesheet loading. That worked until `_load_styles`
    grew a call to `_apply_scheme`, which the harness did not have —
    and the resulting AttributeError inside `do_startup` left the
    process alive but never drawing, which looks exactly like a hang.
    Inheriting means there is nothing to keep in sync.
    """

    def __init__(self) -> None:
        super().__init__()
        self.set_application_id("org.fossh.Console.Screenshot")
        self._window: ConsoleWindow | None = None
        self._agent: Agent | None = None
        self._queue = [name for name, _label, _icon in PAGES]
        self._captured: list[str] = []

    def do_activate(self) -> None:
        # Any exception raised inside a GTK vfunc is printed and then
        # swallowed, leaving the main loop running with nothing on
        # screen -- indistinguishable from a hang unless the harness
        # itself gives up. It gives up.
        try:
            self._activate()
        except Exception:
            import traceback

            traceback.print_exc()
            self.quit()

    def _activate(self) -> None:
        self._agent = Agent()
        try:
            self._agent.start()
        except AgentError as exc:
            print(f"agent: {exc}", file=sys.stderr)
            self.quit()
            return
        self._window = ConsoleWindow(self, self._agent)
        self._window.set_default_size(1100, 760)
        self._window.present()
        self._agent.handshake(
            on_ok=lambda _i: self._window.refresh_all(),
            on_err=lambda e: print(f"handshake: {e.message}", file=sys.stderr),
        )
        # Long enough for layout, the crossfade, and the agent's own
        # replies to have all landed.
        GLib.timeout_add(1800, self._next)

    def _next(self) -> bool:
        if self._window is None:
            self.quit()
            return False
        if not self._queue:
            print("wrote:")
            for name in self._captured:
                print(f"  {OUT_DIR / (name + '.png')}")
            self.quit()
            return False

        name = self._queue.pop(0)
        self._window.show_page(name)

        def shoot() -> bool:
            path = OUT_DIR / f"{name}.png"
            if capture(self._window, path):
                self._captured.append(name)
            else:
                print(f"could not render {name}", file=sys.stderr)
            GLib.timeout_add(250, self._next)
            return False

        # A beat for the page's own crossfade and its agent round trip.
        GLib.timeout_add(900, shoot)
        return False


if __name__ == "__main__":
    sys.exit(Harness().run([]))
