"""First-run setup: prove you are the operator, once.

The flow is §3.11's, unchanged: submit the setup token the watchdog
wrote, enroll a public key (paste one or have one generated), and the
watchdog burns the token on success.

Two details this screen is built around.

The token is never displayed and never handled here. The agent read it
off disk and holds it; this page only ever learns whether a usable one
exists. There is nothing to copy, nothing to mistype, and nothing on
screen worth shoulder-surfing.

A generated private key is shown exactly once, and the screen says so
before generating rather than after. Nothing in foSSH stores it — if it
is lost between this screen and a password manager it is genuinely
gone, and an interface that implied otherwise would be lying at the
worst possible moment.
"""

from __future__ import annotations

from gi.repository import Adw, Gdk, Gtk

from ..agent import AgentError
from ..iconography import symbolic_name

class SetupView(Gtk.Box):
    def __init__(self, agent, toaster: Adw.ToastOverlay) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.add_css_class("content-canvas")
        self._agent = agent
        self._toaster = toaster
        self._generated_public_key: str | None = None

        self._stack = Gtk.Stack()
        self._stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self._stack.set_transition_duration(250)
        self._stack.set_vexpand(True)
        self.append(self._stack)

        self._stack.add_named(self._loading_page(), "loading")
        self._stack.add_named(self._no_token_page(), "no_token")
        self._stack.add_named(self._choose_page(), "choose")
        self._stack.add_named(self._paste_page(), "paste")
        self._stack.add_named(self._generated_page(), "generated")
        self._stack.add_named(self._enrolled_page(), "enrolled")
        self._problem_page = Adw.StatusPage(icon_name=symbolic_name("warning"))
        self._stack.add_named(self._problem_page, "problem")
        self._stack.set_visible_child_name("loading")

    def _loading_page(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, valign=Gtk.Align.CENTER)
        box.append(Adw.Spinner(width_request=32, height_request=32))
        return box

    def _no_token_page(self) -> Gtk.Widget:
        page = Adw.StatusPage(
            icon_name=symbolic_name("pending"),
            title="No setup token on this install",
            description=(
                "The watchdog writes a one-time setup token the first time it starts. "
                "Either it has not run yet, or setup is already finished and the token was "
                "used up — which is the normal state for an install that is working."
            ),
        )
        again = Gtk.Button(label="Look again")
        again.add_css_class("pill")

        again.add_css_class("suggested-action")
        again.set_halign(Gtk.Align.CENTER)
        again.connect("clicked", lambda *_: self.reload())
        page.set_child(again)
        return page

    def _choose_page(self) -> Gtk.Widget:
        page = Adw.StatusPage(
            icon_name=symbolic_name("key"),
            title="Enroll the operator key",
            description=(
                "A setup token is waiting. Enroll the OpenPGP key you will use to "
                "authenticate to the watchdog from now on — paste a public key you already "
                "have, or have a fresh keypair generated here."
            ),
        )
        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        buttons.set_halign(Gtk.Align.CENTER)

        paste = Gtk.Button(label="Paste a public key")
        paste.add_css_class("pill")
        paste.connect("clicked", lambda *_: self._stack.set_visible_child_name("paste"))

        generate = Gtk.Button(label="Generate a keypair")
        generate.add_css_class("pill")
        generate.add_css_class("suggested-action")
        generate.connect("clicked", lambda *_: self._confirm_generate())

        buttons.append(paste)
        buttons.append(generate)
        page.set_child(buttons)
        return page

    def _paste_page(self) -> Gtk.Widget:
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        outer.set_margin_top(24)
        outer.set_margin_bottom(24)
        outer.set_margin_start(24)
        outer.set_margin_end(24)

        heading = Gtk.Label(xalign=0)
        heading.set_markup("<b>Paste your armoured public key block</b>")
        outer.append(heading)

        caption = Gtk.Label(xalign=0)
        caption.add_css_class("caption")
        caption.set_wrap(True)
        caption.set_text(
            "The whole block, beginning with -----BEGIN PGP PUBLIC KEY BLOCK-----. "
            "Get it with:  gpg --armor --export <your key id>"
        )
        outer.append(caption)

        self._paste_buffer = Gtk.TextBuffer()
        text_view = Gtk.TextView(buffer=self._paste_buffer, monospace=True)
        text_view.set_wrap_mode(Gtk.WrapMode.CHAR)
        scroller = Gtk.ScrolledWindow(vexpand=True)
        scroller.set_child(text_view)
        scroller.add_css_class("card-surface")
        outer.append(scroller)

        self._paste_problem = Gtk.Label(xalign=0)
        self._paste_problem.add_css_class("caption")
        self._paste_problem.add_css_class("error")
        self._paste_problem.set_wrap(True)
        self._paste_problem.set_visible(False)
        outer.append(self._paste_problem)

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        actions.set_halign(Gtk.Align.END)
        back = Gtk.Button(label="Back")
        back.connect("clicked", lambda *_: self._stack.set_visible_child_name("choose"))
        self._paste_submit = Gtk.Button(label="Enroll this key")
        self._paste_submit.add_css_class("suggested-action")
        self._paste_submit.connect("clicked", lambda *_: self._enroll_pasted())
        actions.append(back)
        actions.append(self._paste_submit)
        outer.append(actions)

        return outer

    def _generated_page(self) -> Gtk.Widget:
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        outer.set_margin_top(24)
        outer.set_margin_bottom(24)
        outer.set_margin_start(24)
        outer.set_margin_end(24)

        banner = Gtk.Label(xalign=0)
        banner.set_markup(
            "<b>Save this private key now. It is shown once and is not stored anywhere.</b>"
        )
        banner.set_wrap(True)
        banner.add_css_class("privacy-note")
        outer.append(banner)

        self._generated_fingerprint = Gtk.Label(xalign=0)
        self._generated_fingerprint.add_css_class("mono")
        self._generated_fingerprint.set_selectable(True)
        outer.append(self._generated_fingerprint)

        self._private_buffer = Gtk.TextBuffer()
        text_view = Gtk.TextView(buffer=self._private_buffer, monospace=True, editable=False)
        text_view.set_wrap_mode(Gtk.WrapMode.CHAR)
        scroller = Gtk.ScrolledWindow(vexpand=True)
        scroller.set_child(text_view)
        scroller.add_css_class("card-surface")
        outer.append(scroller)

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        actions.set_halign(Gtk.Align.END)

        copy = Gtk.Button()
        copy.set_child(Adw.ButtonContent(icon_name=symbolic_name("copy"), label="Copy"))
        copy.connect("clicked", lambda *_: self._copy_private_key())
        actions.append(copy)

        self._generated_continue = Gtk.Button(label="I have saved it — enroll")
        self._generated_continue.add_css_class("suggested-action")
        self._generated_continue.connect("clicked", lambda *_: self._enroll_generated())
        actions.append(self._generated_continue)
        outer.append(actions)

        return outer

    def _enrolled_page(self) -> Gtk.Widget:
        self._enrolled_status = Adw.StatusPage(
            icon_name=symbolic_name("verified"),
            title="Operator key enrolled",
            description="Setup is complete. The setup token has been used up and deleted.",
        )
        return self._enrolled_status

    def refresh(self) -> None:
        self._agent.call("setup.state", on_ok=self._on_state, on_err=self._on_error)

    def reload(self) -> None:
        self._stack.set_visible_child_name("loading")
        self._agent.call("setup.reload", on_ok=self._on_state, on_err=self._on_error)

    def _on_state(self, result: dict) -> None:
        state = result.get("state")
        if state == "ready":
            self._stack.set_visible_child_name("choose")
        elif state == "no_token":
            self._stack.set_visible_child_name("no_token")
        elif state == "enrolled":
            fingerprint = result.get("fingerprint")
            if fingerprint:
                self._enrolled_status.set_description(
                    f"Setup is complete. The enrolled key is {fingerprint}."
                )
            self._stack.set_visible_child_name("enrolled")
        else:
            self._problem_page.set_title("The setup token cannot be used")
            self._problem_page.set_description(
                result.get("detail") or "The token file exists but could not be read."
            )
            self._stack.set_visible_child_name("problem")

    def _confirm_generate(self) -> None:
        dialog = Adw.AlertDialog(
            heading="Generate a keypair?",
            body=(
                "The private half is displayed once, on the next screen, and is not saved by "
                "foSSH anywhere. Have somewhere to put it — a password manager, an encrypted "
                "note — open before you continue."
            ),
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("go", "Generate")
        dialog.set_response_appearance("go", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("go")
        dialog.set_close_response("cancel")

        def answered(_d, response: str) -> None:
            if response == "go":
                self._generate()

        dialog.connect("response", answered)
        dialog.present(self)

    def _generate(self) -> None:
        self._stack.set_visible_child_name("loading")
        self._toast("Generating a keypair — this can take a moment.")

        def ok(result: dict) -> None:
            self._generated_public_key = result.get("public_key_armored")
            self._generated_fingerprint.set_text(result.get("fingerprint", ""))
            self._private_buffer.set_text(result.get("private_key_armored", ""))
            self._stack.set_visible_child_name("generated")

        self._agent.call(
            "setup.generate_key",
            on_ok=ok,
            on_err=self._on_error,
        )

    def _copy_private_key(self) -> None:
        start, end = self._private_buffer.get_bounds()
        text = self._private_buffer.get_text(start, end, False)
        if not text.strip():

            self._toast("There is nothing to copy.")
            return
        display = Gdk.Display.get_default()
        if display is not None:
            display.get_clipboard().set(text)
            self._toast("Private key copied. Paste it somewhere safe before closing this window.")

    def _enroll_pasted(self) -> None:
        start, end = self._paste_buffer.get_bounds()
        armored = self._paste_buffer.get_text(start, end, False).strip()
        if "BEGIN PGP PUBLIC KEY BLOCK" not in armored:
            self._paste_problem.set_text(
                "That does not look like an armoured public key block. It should begin with "
                "-----BEGIN PGP PUBLIC KEY BLOCK-----."
            )
            self._paste_problem.set_visible(True)
            return
        self._paste_problem.set_visible(False)
        self._paste_submit.set_sensitive(False)
        self._enroll(armored, on_fail=lambda: self._paste_submit.set_sensitive(True))

    def _enroll_generated(self) -> None:
        if not self._generated_public_key:
            return
        self._generated_continue.set_sensitive(False)
        self._enroll(
            self._generated_public_key,
            on_fail=lambda: self._generated_continue.set_sensitive(True),
        )

    def _enroll(self, public_key_armored: str, *, on_fail) -> None:
        def ok(result: dict) -> None:

            self._private_buffer.set_text("")
            self._generated_public_key = None
            fingerprint = result.get("fingerprint", "")
            self._enrolled_status.set_description(
                f"Setup is complete. The enrolled key is {fingerprint}."
            )
            self._stack.set_visible_child_name("enrolled")
            self._toast("Operator key enrolled.")

        def err(error: AgentError) -> None:
            on_fail()
            if error.code == "denied":

                self._toast(error.message)
                self._agent.call("setup.state", on_ok=self._on_state, on_err=self._on_error)
                return
            self._toast(error.message)

        self._agent.call(
            "setup.enroll",
            {"public_key_armored": public_key_armored},
            on_ok=ok,
            on_err=err,
        )

    def _toast(self, message: str) -> None:
        self._toaster.add_toast(Adw.Toast(title=message, timeout=6))

    def _on_error(self, error: AgentError) -> None:
        self._problem_page.set_title("Setup cannot continue")
        self._problem_page.set_description(error.message)
        self._stack.set_visible_child_name("problem")
