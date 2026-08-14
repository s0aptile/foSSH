"""The application object: owns the agent's lifetime and the stylesheet.

Nothing here draws anything. It exists so there is exactly one place
that starts the helper, one place that stops it, and one place that
loads the CSS — each of which is a bug the first time it happens twice.
"""

from __future__ import annotations

import sys
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gdk, Gio, Gtk  # noqa: E402

from .agent import Agent, AgentError  # noqa: E402
from .palette import define_colors_css  # noqa: E402
from .window import ConsoleWindow  # noqa: E402

APP_ID = "org.fossh.Console"


class ConsoleApplication(Adw.Application):
    def __init__(self) -> None:
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self._agent: Agent | None = None
        self._window: ConsoleWindow | None = None

    # -- lifecycle ---------------------------------------------------

    def do_startup(self) -> None:
        Adw.Application.do_startup(self)
        self._load_styles()

        quit_action = Gio.SimpleAction.new("quit", None)
        quit_action.connect("activate", lambda *_: self.quit())
        self.add_action(quit_action)
        self.set_accels_for_action("app.quit", ["<Control>q"])
        self.set_accels_for_action("window.close", ["<Control>w"])

    def do_activate(self) -> None:
        if self._window is None:
            self._agent = Agent()
            self._window = ConsoleWindow(self, self._agent)
            self._start_agent()
        self._window.present()

    def do_shutdown(self) -> None:
        if self._agent is not None:
            self._agent.stop()
        Adw.Application.do_shutdown(self)

    # -- the agent ---------------------------------------------------

    def _start_agent(self) -> None:
        assert self._agent is not None and self._window is not None
        try:
            self._agent.start()
        except AgentError as error:
            self._window.report_startup_failure(error)
            return

        self._agent.handshake(
            on_ok=lambda _info: self._window.refresh_all(),
            on_err=self._window.report_startup_failure,
        )

    def restart_agent(self) -> None:
        """Used by the failure page's "Try again" button — after an
        install finishes, or after the operator built the binary."""
        if self._agent is not None:
            self._agent.stop()
        self._agent = Agent()
        if self._window is not None:
            # A fresh window rather than surgery on the failed one:
            # rebuilding is cheap, and reattaching every view to a new
            # agent by hand is the kind of thing that quietly leaves
            # one view pointing at the dead one.
            self._window.close()
            self._window = ConsoleWindow(self, self._agent)
            self._start_agent()
            self._window.present()

    # -- presentation ------------------------------------------------

    def _load_styles(self) -> None:
        """Two providers, in a deliberate order.

        The colour provider goes on first and is reloaded whenever the
        system switches scheme; `style.css` sits above it and only
        ever references the names it defines. Keeping them apart is
        what makes following light/dark a one-line regeneration
        instead of two divergent stylesheets — GTK's CSS has no
        `prefers-color-scheme` query, so this is the mechanism.
        """
        display = Gdk.Display.get_default()
        if display is None:
            return

        self._colour_provider = Gtk.CssProvider()
        Gtk.StyleContext.add_provider_for_display(
            display,
            self._colour_provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
        )

        css_path = Path(__file__).resolve().parent / "style.css"
        if css_path.exists():
            structure = Gtk.CssProvider()
            structure.load_from_path(str(css_path))
            Gtk.StyleContext.add_provider_for_display(
                display,
                structure,
                # Above the theme, below a user's own overrides — an
                # app stylesheet that outranks a user stylesheet is an
                # app that cannot be corrected.
                Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION + 1,
            )
        else:
            print(f"fossh-console: stylesheet missing at {css_path}", file=sys.stderr)

        style_manager = Adw.StyleManager.get_default()
        style_manager.connect("notify::dark", lambda *_: self._apply_scheme())
        self._apply_scheme()

    def _apply_scheme(self) -> None:
        provider = getattr(self, "_colour_provider", None)
        if provider is None:
            return
        dark = Adw.StyleManager.get_default().get_dark()
        provider.load_from_string(define_colors_css(dark))


def main(argv: list[str] | None = None) -> int:
    return ConsoleApplication().run(argv if argv is not None else sys.argv)
