"""The terms, the privacy text, and the licence — in the application.

These exist as files in the source tree, which is where a developer
reads them and nowhere an operator ever will. Someone who installed a
package from a software centre has no repository checked out, and
"see tos.md" is not an answer to them.

So they are shipped with the console and rendered here, in full, as
the exact same bytes that are in the source. Nothing is summarised,
abridged, or paraphrased for display: a summary of a disclaimer is a
different disclaimer, and an interface that showed one while the file
said another would be worse than showing nothing.

## Rendering

A deliberately small subset of Markdown — headings, bold, inline code,
list items, paragraphs — turned into Pango markup. Not a Markdown
library: adding a dependency to the console to render four documents it
ships itself would be a poor trade, and the subset these files actually
use is small and known.

Everything is escaped before any markup is added. The documents are
trusted, but the escaping is unconditional so that stays true if one is
ever regenerated from something less trusted.
"""

from __future__ import annotations

import re
from pathlib import Path

from gi.repository import Adw, GLib, Gtk

from ..iconography import symbolic_name
from ..motion import Duration

DOCUMENTS = [
    ("Terms", "tos.md", "The terms this release is provided under, and the disclaimers that go with it."),
    ("Privacy", "PRIVACY.md", "What foSSH collects and what it does not — written for the people whose visits are counted."),
    ("Licence", "LICENSE", "The MIT licence, in full."),
    ("Retirement", "RETIREMENT.md", "Which releases are retired, and what was wrong with them."),
]

def _search_paths() -> list[Path]:
    """Where the documents might be, packaged or in a checkout."""
    here = Path(__file__).resolve()
    repo_root = here.parent.parent.parent.parent
    return [
        Path("/usr/share/doc/fossh-console"),
        Path("/usr/share/doc/fossh"),
        Path("/usr/share/licenses/fossh-console"),
        repo_root,
    ]

def find_document(filename: str) -> Path | None:
    for base in _search_paths():
        candidate = base / filename
        if candidate.is_file():
            return candidate
    return None

def markdown_to_pango(text: str) -> str:
    """The small subset these documents use.

    Escaping happens first and unconditionally, so no character in a
    document can ever be interpreted as markup it did not ask for.
    """
    out: list[str] = []
    for raw in text.splitlines():
        line = GLib.markup_escape_text(raw)

        heading = re.match(r"^(#{1,6})\s+(.*)$", line)
        if heading:
            level = len(heading.group(1))
            body = heading.group(2)
            size = {1: "x-large", 2: "large"}.get(level, "medium")
            out.append(f'<span size="{size}" weight="bold">{body}</span>')
            continue

        if line.strip() == "---":

            out.append('<span alpha="35%">────────────────────</span>')
            continue

        bullet = re.match(r"^[-*]\s+(.*)$", line)
        if bullet:
            line = f"  • {bullet.group(1)}"

        line = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", line)
        line = re.sub(r"`([^`]+)`", r'<tt>\1</tt>', line)
        out.append(line)
    return "\n".join(out)

class LegalView(Gtk.Box):
    def __init__(self) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.add_css_class("content-canvas")

        self._switcher_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._switcher_bar.set_margin_top(16)
        self._switcher_bar.set_margin_bottom(8)
        self._switcher_bar.set_halign(Gtk.Align.CENTER)
        self.append(self._switcher_bar)

        self._stack = Gtk.Stack()
        self._stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self._stack.set_transition_duration(Duration.STANDARD)
        self._stack.set_vexpand(True)
        self.append(self._stack)

        group = None
        for label, filename, description in DOCUMENTS:
            self._stack.add_named(self._document_page(filename, description), filename)
            button = Gtk.ToggleButton(label=label)
            button.add_css_class("flat")
            if group is None:
                group = button
                button.set_active(True)
            else:
                button.set_group(group)
            button.connect(
                "toggled",
                lambda b, name=filename: (
                    self._stack.set_visible_child_name(name) if b.get_active() else None
                ),
            )
            self._switcher_bar.append(button)

    def _document_page(self, filename: str, description: str) -> Gtk.Widget:
        path = find_document(filename)
        if path is None:
            return Adw.StatusPage(
                icon_name=symbolic_name("warning"),
                title=f"{filename} is not installed",
                description=(
                    f"This console could not find {filename}. It ships with the fossh-console "
                    "package; if you are running from a source tree, it is in the repository "
                    "root."
                ),
            )

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return Adw.StatusPage(
                icon_name=symbolic_name("warning"),
                title=f"{filename} could not be read",
                description=str(exc),
            )

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        outer.set_margin_top(8)
        outer.set_margin_bottom(32)
        outer.set_margin_start(24)
        outer.set_margin_end(24)

        caption = Gtk.Label(label=description, xalign=0)
        caption.add_css_class("caption")
        caption.set_wrap(True)
        outer.append(caption)

        body = Gtk.Label(xalign=0)
        body.set_markup(markdown_to_pango(text))
        body.set_wrap(True)
        body.set_wrap_mode(2)

        body.set_selectable(True)
        body.set_xalign(0)
        outer.append(body)

        source = Gtk.Label(xalign=0)
        source.add_css_class("caption")
        source.set_selectable(True)
        source.set_text(f"Read from {path}")
        outer.append(source)

        scroller = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER)
        scroller.set_child(Adw.Clamp(maximum_size=800, child=outer))
        return scroller

    def refresh(self) -> None:
        """Nothing to fetch — the documents are files on disk, read when
        the page was built. Present so every view has the same shape."""
        return
