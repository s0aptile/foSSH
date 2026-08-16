"""External services the operator has added, each with an API key.

Two things this page is careful about.

The credential is write-once. It is typed into a masked field, sent
straight to the agent, sealed on disk, and never sent back — the list
shows at most the last four characters, and only when the key is long
enough for four to be a hint rather than most of it. There is no "show
key" anywhere, because there is nothing to show: the console does not
have it. Editing a key means replacing it.

And the page says what an integration *is* for, in plain words, at the
top. foSSH's entire pitch is that it does not ship your visitors'
traffic to third parties, so a screen that adds third parties without
saying exactly what does and does not leave would be the single most
alarming thing in the app.
"""

from __future__ import annotations

from gi.repository import Adw, GLib, Gtk

from ..agent import AgentError
from ..asyncdialog import AsyncDialog
from ..iconography import symbolic_name

PLACEMENTS = [
    ("bearer", "Authorization: Bearer <key>"),
    ("header", "A header of my own"),
]

METHODS = [("GET", "GET"), ("POST", "POST")]

class IntegrationsView(Gtk.Box):
    def __init__(self, agent, toaster: Adw.ToastOverlay) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.add_css_class("content-canvas")
        self._agent = agent
        self._toaster = toaster

        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        header.set_margin_top(16)
        header.set_margin_bottom(8)
        header.set_margin_start(24)
        header.set_margin_end(24)
        spacer = Gtk.Box(hexpand=True)
        add = Gtk.Button()
        add.set_child(Adw.ButtonContent(icon_name=symbolic_name("add"), label="Add service"))
        add.add_css_class("suggested-action")
        add.connect("clicked", lambda *_: self._open_add_dialog())
        header.append(spacer)
        header.append(add)
        self.append(header)

        self._stack = Gtk.Stack()
        self._stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self._stack.set_transition_duration(250)
        self._stack.set_vexpand(True)
        self.append(self._stack)

        loading = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, valign=Gtk.Align.CENTER)
        loading.append(Adw.Spinner(width_request=32, height_request=32))
        self._stack.add_named(loading, "loading")

        self._list_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self._list_box.set_margin_start(24)
        self._list_box.set_margin_end(24)
        self._list_box.set_margin_bottom(32)
        scroller = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER)
        scroller.set_child(Adw.Clamp(maximum_size=900, child=self._list_box))
        self._stack.add_named(scroller, "list")

        self._empty = Adw.StatusPage(
            icon_name=symbolic_name("integrations"),
            title="No external services",
            description=(
                "Add one to let this console send a request to an API you control, "
                "authenticated with a key you supply. Nothing is sent anywhere until you add "
                "a service and ask for it — the ingest path itself makes no outbound "
                "connections at all, and that is enforced by which binaries can even reach "
                "the network code, not by configuration."
            ),
        )
        self._stack.add_named(self._empty, "empty")

        self._error = Adw.StatusPage(icon_name=symbolic_name("warning"))
        self._stack.add_named(self._error, "error")
        self._stack.set_visible_child_name("loading")

    def refresh(self) -> None:
        self._agent.call("integrations.list", on_ok=self._on_list, on_err=self._on_error)

    def _on_list(self, result: dict) -> None:
        items = result.get("integrations", [])

        child = self._list_box.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            self._list_box.remove(child)
            child = nxt

        if not items:
            self._stack.set_visible_child_name("empty")
            return

        group = Adw.PreferencesGroup()
        group.set_margin_top(8)
        for item in items:
            group.add(self._row(item))
        self._list_box.append(group)

        note = Gtk.Label(xalign=0)
        note.add_css_class("caption")
        note.set_wrap(True)
        note.set_text(
            "Keys are sealed on disk under this install's data key and are never sent back to "
            "this window. Testing a service sends one request from this machine: a GET, or a "
            "POST carrying a short body that says it is a connectivity test and nothing else."
        )
        self._list_box.append(note)

        self._stack.set_visible_child_name("list")

    def _row(self, item: dict) -> Adw.ActionRow:
        name = item.get("name", "?")
        row = Adw.ActionRow(title=GLib.markup_escape_text(name))

        auth = item.get("auth", {})
        placement = (
            "Bearer token"
            if auth.get("placement") == "bearer"
            else f"header {auth.get('name', '?')}"
        )
        hint = item.get("key_hint")
        key_text = f"key ····{hint}" if hint else "key hidden"
        row.set_subtitle(
            GLib.markup_escape_text(
                f"{item.get('method', 'GET')} {item.get('endpoint', '')} · {placement} · {key_text}"
            )
        )

        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        buttons.set_valign(Gtk.Align.CENTER)

        test = Gtk.Button(label="Test")
        test.add_css_class("flat")
        test.connect("clicked", lambda _b, n=name: self._test(n))
        buttons.append(test)

        remove = Gtk.Button(icon_name=symbolic_name("delete"))
        remove.add_css_class("flat")
        remove.set_tooltip_text(f"Remove {name}")
        remove.connect("clicked", lambda _b, n=name: self._confirm_remove(n))
        buttons.append(remove)

        row.add_suffix(buttons)
        return row

    def _test(self, name: str) -> None:
        self._toast(f"Testing {name}…")

        def ok(result: dict) -> None:
            status = result.get("status", 0)
            if result.get("reachable"):
                self._toast(f"{name} answered {status}.")
            else:
                body = (result.get("body") or "").strip().replace("\n", " ")
                detail = f" — {body[:120]}" if body else ""
                self._toast(f"{name} answered {status}, which it treats as a refusal{detail}")

        self._agent.call(
            "integrations.test",
            {"name": name},
            on_ok=ok,
            on_err=lambda e: self._toast(f"{name}: {e.message}"),
        )

    def _confirm_remove(self, name: str) -> None:
        dialog = Adw.AlertDialog(
            heading=f"Remove {name}?",
            body=(
                "Its endpoint and API key are deleted from this install. "
                "The key cannot be recovered afterwards — you would need to paste it again."
            ),
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("remove", "Remove")
        dialog.set_response_appearance("remove", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")

        def answered(_dialog, response: str) -> None:
            if response != "remove":
                return
            self._agent.call(
                "integrations.remove",
                {"name": name},
                on_ok=lambda _r: (self._toast(f"Removed {name}."), self.refresh()),
                on_err=lambda e: self._toast(e.message),
            )

        dialog.connect("response", answered)
        dialog.present(self)

    def _open_add_dialog(self) -> None:
        AddIntegrationDialog(self._agent, on_added=self._after_add).present(self)

    def _after_add(self, name: str) -> None:
        self._toast(f"Added {name}.")
        self.refresh()

    def _toast(self, message: str) -> None:
        self._toaster.add_toast(Adw.Toast(title=message, timeout=4))

    def _on_error(self, error: AgentError) -> None:
        self._error.set_title("Could not read the integrations file")
        self._error.set_description(error.message)
        self._stack.set_visible_child_name("error")

class AddIntegrationDialog(AsyncDialog):
    """Collects one service. Validates locally for immediate feedback,
    then lets the agent be the authority — the rules that matter for
    safety (no cleartext HTTP to a remote host, no control characters
    in a key) are enforced in Rust, and duplicating them here is for
    responsiveness only, never for enforcement."""

    def __init__(self, agent, on_added) -> None:
        super().__init__()
        self._agent = agent
        self._on_added = on_added
        self.set_title("Add an external service")
        self.set_content_width(520)

        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        self._save = Gtk.Button(label="Add")
        self._save.add_css_class("suggested-action")
        self._save.set_sensitive(False)
        self._save.connect("clicked", lambda *_: self._submit())
        cancel = Gtk.Button(label="Cancel")
        cancel.connect("clicked", lambda *_: self.close_once())
        header.pack_start(cancel)
        header.pack_end(self._save)
        toolbar.add_top_bar(header)

        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        body.set_margin_top(16)
        body.set_margin_bottom(16)
        body.set_margin_start(16)
        body.set_margin_end(16)

        group = Adw.PreferencesGroup()

        self._name = Adw.EntryRow(title="Name")
        self._name.connect("changed", lambda *_: self._validate())
        group.add(self._name)

        self._endpoint = Adw.EntryRow(title="Endpoint URL")
        self._endpoint.connect("changed", lambda *_: self._validate())
        group.add(self._endpoint)

        self._method = Adw.ComboRow(
            title="Request",
            model=Gtk.StringList.new([label for _v, label in METHODS]),
        )
        group.add(self._method)

        self._placement = Adw.ComboRow(
            title="Where the key goes",
            model=Gtk.StringList.new([label for _v, label in PLACEMENTS]),
        )
        self._placement.connect("notify::selected", lambda *_: self._on_placement_changed())
        group.add(self._placement)

        self._header_name = Adw.EntryRow(title="Header name")
        self._header_name.set_text("X-Api-Key")
        self._header_name.set_visible(False)
        self._header_name.connect("changed", lambda *_: self._validate())
        group.add(self._header_name)

        self._key = Adw.PasswordEntryRow(title="API key")
        self._key.connect("changed", lambda *_: self._validate())
        group.add(self._key)

        body.append(group)

        self._problem = Gtk.Label(xalign=0)
        self._problem.add_css_class("caption")
        self._problem.add_css_class("error")
        self._problem.set_wrap(True)
        self._problem.set_visible(False)
        body.append(self._problem)

        note = Gtk.Label(xalign=0)
        note.add_css_class("caption")
        note.set_wrap(True)
        note.set_text(
            "The key is sealed on this machine as soon as you add it, and this window never "
            "sees it again. Plain http:// is refused for anything but a loopback address, "
            "because a key sent over it is readable by anything on the path."
        )
        body.append(note)

        toolbar.set_content(body)
        self.set_child(toolbar)

    def _on_placement_changed(self) -> None:
        self._header_name.set_visible(self._placement.get_selected() == 1)
        self._validate()

    def _validate(self) -> bool:
        name = self._name.get_text().strip()
        endpoint = self._endpoint.get_text().strip()
        key = self._key.get_text()

        problem = None
        if not name:
            problem = None
        elif not all(c.islower() or c.isdigit() or c in "-_" for c in name):
            problem = "A name may only contain lowercase letters, digits, “-” and “_”."
        elif endpoint and not endpoint.startswith(("https://", "http://")):
            problem = "An endpoint URL must start with https://."
        elif key and key != key.strip():
            problem = "That key has whitespace at one end — it was probably picked up by the paste."
        elif any(ord(c) < 32 or ord(c) == 127 for c in key):
            problem = "That key contains a line break, which cannot be sent in an HTTP header."

        self._problem.set_text(problem or "")
        self._problem.set_visible(bool(problem))

        header_ok = self._placement.get_selected() != 1 or bool(
            self._header_name.get_text().strip()
        )
        ready = bool(name) and bool(endpoint) and bool(key) and problem is None and header_ok
        self._save.set_sensitive(ready)
        return ready

    def _submit(self) -> None:
        if not self._validate():
            return
        placement = PLACEMENTS[self._placement.get_selected()][0]
        auth: dict[str, str] = {"placement": placement}
        if placement == "header":
            auth["name"] = self._header_name.get_text().strip()

        name = self._name.get_text().strip()
        params = {
            "name": name,
            "endpoint": self._endpoint.get_text().strip(),
            "method": METHODS[self._method.get_selected()][0],
            "auth": auth,
            "api_key": self._key.get_text(),
        }

        self._save.set_sensitive(False)

        def ok(_result: dict) -> None:

            self._key.set_text("")

            self.close_once()

            self._on_added(name)

        def err(error: AgentError) -> None:
            self._problem.set_text(error.message)
            self._problem.set_visible(True)
            self._save.set_sensitive(True)

        self._agent.call("integrations.add", params, on_ok=ok, on_err=self.guard(err))
