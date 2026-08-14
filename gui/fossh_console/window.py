"""The window: a sidebar, four views, and one toast overlay for all of
them.

`Adw.NavigationSplitView` rather than a tab bar, because the sidebar
collapses to a single pane below `BREAKPOINT_WIDTH` and the same window
then works at phone width without a second layout. `Adw.Breakpoint` is
what drives that, so it is the window manager's decision rather than a
size hint this code has to keep in sync.
"""

from __future__ import annotations

from gi.repository import Adw, Gtk

from .agent import AgentError
from .branding import Wordmark
from .iconography import icon, icon_button, symbolic_name
from .views.integrations import IntegrationsView
from .views.overview import OverviewView
from .views.setup import SetupView
from .views.telemetry import TelemetryView

#: Below this the sidebar folds away. Matches libadwaita's own
#: convention for the narrow breakpoint rather than a number picked
#: here, so this window behaves like every other adaptive GNOME app.
BREAKPOINT_WIDTH = 640

#: `(stack name, sidebar label, iconography key)`. The icon key is
#: resolved through `iconography`, which picks a Material glyph, a
#: theme symbolic, or a last-resort name depending on what is actually
#: installed — see that module.
PAGES = [
    ("overview", "Overview", "overview"),
    ("telemetry", "Telemetry", "telemetry"),
    ("integrations", "Integrations", "integrations"),
    ("setup", "Setup", "setup"),
]


class ConsoleWindow(Adw.ApplicationWindow):
    def __init__(self, application: Adw.Application, agent) -> None:
        super().__init__(application=application)
        self._agent = agent
        self.set_title("foSSH Console")
        self.set_default_size(1000, 700)

        self._toaster = Adw.ToastOverlay()

        self._views = {
            "overview": OverviewView(agent),
            "telemetry": TelemetryView(agent),
            "integrations": IntegrationsView(agent, self._toaster),
            "setup": SetupView(agent, self._toaster),
        }

        self._content_stack = Gtk.Stack()
        self._content_stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self._content_stack.set_transition_duration(200)
        for name, view in self._views.items():
            self._content_stack.add_named(view, name)

        split = Adw.NavigationSplitView()
        # Content before sidebar, and it matters: `_build_sidebar`
        # selects the first row, which fires `_on_row_selected`, which
        # sets the content pane's title. Building the sidebar first
        # meant that handler ran against a `_title` that did not exist
        # yet — an AttributeError swallowed by GTK's signal machinery,
        # leaving the title stuck and the initial refresh never fired.
        split.set_content(self._build_content())
        split.set_sidebar(self._build_sidebar())
        self._split = split

        self._toaster.set_child(split)

        # One breakpoint, one property. The sidebar collapses; nothing
        # else about the layout has to change, because every view is
        # already inside an `Adw.Clamp`.
        breakpoint_ = Adw.Breakpoint.new(
            Adw.BreakpointCondition.parse(f"max-width: {BREAKPOINT_WIDTH}px")
        )
        breakpoint_.add_setter(split, "collapsed", True)
        self.add_breakpoint(breakpoint_)

        self.set_content(self._toaster)
        self._install_shortcuts()

        # Everything above exists now, so the first navigation is safe.
        self._sidebar_list.select_row(self._sidebar_list.get_row_at_index(0))

    # -- chrome ------------------------------------------------------

    def _build_sidebar(self) -> Adw.NavigationPage:
        self._sidebar_list = Gtk.ListBox()
        self._sidebar_list.add_css_class("navigation-sidebar")
        self._sidebar_list.set_selection_mode(Gtk.SelectionMode.SINGLE)

        for name, label, icon_key in PAGES:
            row = Gtk.ListBoxRow()
            row.set_name(name)
            box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
            box.set_margin_top(8)
            box.set_margin_bottom(8)
            box.set_margin_start(8)
            box.set_margin_end(8)
            box.append(icon(icon_key))
            box.append(Gtk.Label(label=label, xalign=0))
            row.set_child(box)
            # The row's accessible name comes from its label already;
            # the icon inside is marked presentational by
            # `iconography`, so nothing announces twice.
            self._sidebar_list.append(row)

        # Deliberately NOT selecting a row here. `row-selected` fires
        # synchronously, and its handler reaches for `_title`, `_split`
        # and `_content_page` -- none of which exist until `__init__`
        # has finished assembling them. Selecting during construction
        # produced two separate AttributeErrors of exactly that shape,
        # each swallowed by GTK's signal machinery and each showing up
        # as a window that drew but never navigated. The initial
        # selection happens at the end of `__init__` instead, where
        # every field it touches is real.
        self._sidebar_list.connect("row-selected", self._on_row_selected)

        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        # The wordmark replaces the sidebar's plain title. Carried over
        # from the TUI's own chrome, diamond and all — see
        # `branding.py` for why that detail is not decoration.
        header.set_title_widget(Wordmark(size_pt=14.0, show_tagline=False))
        toolbar.add_top_bar(header)
        toolbar.set_content(self._sidebar_list)
        return Adw.NavigationPage(child=toolbar, title="foSSH")

    def _build_content(self) -> Adw.NavigationPage:
        toolbar = Adw.ToolbarView()

        header = Adw.HeaderBar()
        self._title = Adw.WindowTitle(title="Overview")
        header.set_title_widget(self._title)

        refresh = icon_button("refresh", "Refresh this page")
        refresh.add_css_class("flat")
        refresh.set_tooltip_text("Refresh (Ctrl+R)")
        refresh.connect("clicked", lambda *_: self.refresh_current())
        header.pack_end(refresh)

        menu_button = Gtk.MenuButton(icon_name=symbolic_name("menu"))
        menu_button.set_tooltip_text("Main menu")
        menu_button.update_property([Gtk.AccessibleProperty.LABEL], ["Main menu"])
        menu = Gtk.Builder.new_from_string(
            """
            <interface>
              <menu id="app-menu">
                <section>
                  <item>
                    <attribute name="label">Keyboard Shortcuts</attribute>
                    <attribute name="action">win.shortcuts</attribute>
                  </item>
                  <item>
                    <attribute name="label">About foSSH Console</attribute>
                    <attribute name="action">win.about</attribute>
                  </item>
                </section>
              </menu>
            </interface>
            """,
            -1,
        )
        menu_button.set_menu_model(menu.get_object("app-menu"))
        header.pack_end(menu_button)

        toolbar.add_top_bar(header)
        toolbar.set_content(self._content_stack)
        self._content_page = Adw.NavigationPage(child=toolbar, title="Overview")
        return self._content_page

    def _install_shortcuts(self) -> None:
        from gi.repository import Gio

        actions = [
            ("refresh", lambda *_: self.refresh_current(), ["<Control>r", "F5"]),
            ("shortcuts", lambda *_: self._show_shortcuts(), ["<Control>question"]),
            ("about", lambda *_: self._show_about(), []),
        ]
        app = self.get_application()
        for name, callback, accels in actions:
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", callback)
            self.add_action(action)
            if accels and app is not None:
                app.set_accels_for_action(f"win.{name}", accels)

        # Digit shortcuts for the four pages, the way every sidebar app
        # people already use behaves.
        for index, (page_name, _label, _icon) in enumerate(PAGES, start=1):
            action = Gio.SimpleAction.new(f"page-{page_name}", None)
            action.connect("activate", lambda *_a, n=page_name: self.show_page(n))
            self.add_action(action)
            if app is not None:
                app.set_accels_for_action(f"win.page-{page_name}", [f"<Control>{index}"])

    # -- navigation --------------------------------------------------

    def _on_row_selected(self, _listbox, row: Gtk.ListBoxRow | None) -> None:
        if row is None:
            return
        name = row.get_name()
        self._content_stack.set_visible_child_name(name)
        label = next(label for key, label, _ in PAGES if key == name)
        self._title.set_title(label)
        self._content_page.set_title(label)
        if self._split.get_collapsed():
            self._split.set_show_content(True)
        self.refresh_current()

    def show_page(self, name: str) -> None:
        for index, (page_name, _label, _icon) in enumerate(PAGES):
            if page_name == name:
                self._sidebar_list.select_row(self._sidebar_list.get_row_at_index(index))
                return

    def refresh_current(self) -> None:
        name = self._content_stack.get_visible_child_name()
        view = self._views.get(name)
        if view is not None:
            view.refresh()

    def refresh_all(self) -> None:
        for view in self._views.values():
            view.refresh()

    # -- dialogs -----------------------------------------------------

    def _show_shortcuts(self) -> None:
        lines = [
            ("Ctrl+R  /  F5", "Refresh the current page"),
            ("Ctrl+1 … Ctrl+4", "Jump to a page"),
            ("Ctrl+?", "This list"),
            ("Ctrl+W", "Close the window"),
        ]
        body = "\n".join(f"{keys}\t{what}" for keys, what in lines)
        dialog = Adw.AlertDialog(heading="Keyboard shortcuts", body=body)
        dialog.add_response("close", "Close")
        dialog.present(self)

    def _show_about(self) -> None:
        version = self._agent.info.get("version", "unknown")
        about = Adw.AboutDialog(
            application_name="foSSH Console",
            application_icon="org.fossh.Console",
            version=version,
            developer_name="$0aptile",
            license_type=Gtk.License.MIT_X11,
            website="https://github.com/s0aptile/foSSH",
            issue_url="https://github.com/s0aptile/foSSH/issues",
            comments=(
                "Local administration for a foSSH install. Privacy-preserving, self-hosted "
                "site analytics — no cross-site identity, no cookies, no fingerprinting, and "
                "no third-party egress from the ingest path."
            ),
        )
        about.present(self)

    def report_startup_failure(self, error: AgentError) -> None:
        """Replaces the whole window with one honest explanation.

        A window full of empty panels that each say "unavailable" makes
        the reader hunt for which one matters. When the helper itself
        could not be started, there is exactly one thing wrong and one
        thing to say.
        """
        page = Adw.StatusPage(
            icon_name=symbolic_name("warning"),
            title="The foSSH helper could not be started",
            description=error.message,
        )
        retry = Gtk.Button(label="Try again")
        retry.add_css_class("pill")
        retry.add_css_class("suggested-action")
        retry.set_halign(Gtk.Align.CENTER)
        retry.connect("clicked", lambda *_: self.get_application().restart_agent())
        page.set_child(retry)

        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(Adw.HeaderBar())
        toolbar.set_content(page)
        self._toaster.set_child(toolbar)
