"""The foSSH wordmark, and the typeface stack it sits in.

## The wordmark

`foSSH` is a typographic mark, not a picture: lowercase `fo` against
uppercase `SSH`, which is the whole idea — the name reads as one word
and as two at the same time. Setting it as plain text throws that away,
so it is set as one Pango run per part with the details that make a
logotype look drawn rather than typed:

* the caps are optically *smaller* than their nominal size. Capitals of
  the same point size as lowercase always look too large next to them,
  because cap height exceeds x-height; matching them by measurement is
  what makes a mixed-case wordmark look wrong in a way most people feel
  without being able to name.
* the caps carry negative tracking. `SSH` at bold weight sets loosely
  by default, and a logotype wants its letters locked together.
* the two parts are weighted apart rather than coloured apart at small
  sizes, so the mark survives being rendered in one colour — in a
  window title, in a high-contrast theme, or on a monochrome display.

## The typefaces

Roboto for the interface and Roboto Mono for anything that must not
change width, both Google's, both packaged by Fedora. Neither is
required: `resolve_family` checks what is actually installed through
Pango's own font map and falls back through a chain that ends at the
theme's default, so a machine without them gets a slightly different
face and nothing else. Hardcoding a family that may not exist is how an
app ends up rendering in whatever the fontconfig substitution engine
guessed, which is worse than asking for the default in the first place.
"""

from __future__ import annotations

import functools

from gi.repository import GLib, Gtk, Pango, PangoCairo

WORDMARK_FAMILIES = [
    "Bitcount Grid Single",
    "Bitcount Grid Double",
    "Bitcount Prop Single",
]

STAT_VALUE_FAMILIES = list(WORDMARK_FAMILIES)

UI_FAMILIES = ["Roboto", "Inter", "Cantarell", "Noto Sans", "Sans"]
MONO_FAMILIES = ["Roboto Mono", "Source Code Pro", "DejaVu Sans Mono", "Monospace"]

ICON_FAMILIES = ["Material Symbols Outlined", "Material Icons"]

@functools.lru_cache(maxsize=1)
def _installed_families() -> set[str]:
    """Every family Pango can actually see, lowercased."""
    font_map = PangoCairo.FontMap.get_default()
    if font_map is None:
        return set()
    return {family.get_name().lower() for family in font_map.list_families()}

def resolve_family(candidates: list[str]) -> str:
    installed = _installed_families()
    for name in candidates:
        if name.lower() in installed:
            return name
    return candidates[-1]

def ui_family() -> str:
    return resolve_family(UI_FAMILIES)

def mono_family() -> str:
    return resolve_family(MONO_FAMILIES)

def _display_family(candidates: list[str]) -> str | None:
    """The first installed face in `candidates`, or `None` for the UI face."""
    installed = _installed_families()
    for name in candidates:
        if name.lower() in installed:
            return name
    return None

def wordmark_family() -> str | None:
    """The display face for the mark, or `None` to use the UI face.

    A logotype in a face nothing else on screen uses is a common shape
    and a weak one — it reads as a sticker applied to an otherwise
    generic interface rather than as the same identity carried through.
    """
    return _display_family(WORDMARK_FAMILIES)

def stat_value_family() -> str | None:
    """The display face for a dashboard headline figure, or `None`.

    The numbers a person actually came to read are the other place
    this project's identity belongs, not just the logo — the same
    reasoning `wordmark_family` states, applied to a different element.

    Verified, not assumed, against the real font files (`fonttools`):
    Grid Single and Grid Double give every glyph — not just digits —
    identical advance width by construction (600 units, checked 0-9),
    so `.numeric`'s tabular-figure requirement in style.css is met
    whether or not a `tnum` GSUB feature exists (it does not, in
    either Grid face). Prop Single is not monospaced by default (its
    '1' is 500 units against 700 for every other digit) but does
    define a real `tnum` feature, which style.css already requests —
    so the fallback chain stays jitter-safe end to end. Digit
    disambiguation (0/1/3/6/7/8/9) was checked by rendering actual
    sample figures at 34px/700 in all three faces; 0 carries a built-in
    diagonal slash, distinguishing it from a round form on sight.
    """
    return _display_family(STAT_VALUE_FAMILIES)

def stat_value_markup(text: str) -> str:
    """Pango markup for a headline figure, in the display face.

    Falls back to the escaped text alone — no `face` attribute — when
    Bitcount is not installed, which is exactly `resolve_family`'s
    fallback-through-a-chain philosophy applied to a single face rather
    than a stack: ask for the identity, accept the theme's default
    when it is not there, never guess at a substitute.
    """
    escaped = GLib.markup_escape_text(text, -1)
    face = stat_value_family()
    if not face:
        return escaped
    return f'<span face="{face}">{escaped}</span>'

def icon_family() -> str | None:
    installed = _installed_families()
    for name in ICON_FAMILIES:
        if name.lower() in installed:
            return name
    return None

DIAMOND = "◆"
TAGLINE = "local admin console"

def wordmark_markup(size_pt: float, *, accent_hex: str | None = None) -> str:
    """Pango markup for `foSSH` at a given size.

    Sizes are in Pango units (1024ths of a point) rather than a
    CSS-ish string because the two runs need *different* sizes, and
    the ratio between them is the whole point of the mark.
    """
    face = wordmark_family()
    family_attr = f' face="{face}"' if face else ""

    lower_size = int(size_pt * Pango.SCALE)

    caps_size = int(size_pt * 0.86 * Pango.SCALE)

    colour = f' foreground="{accent_hex}"' if accent_hex else ""
    return (
        f'<span{family_attr} size="{lower_size}" weight="300">fo</span>'
        f'<span{family_attr} size="{caps_size}" weight="800" '
        f'letter_spacing="-512"{colour}>SSH</span>'
    )

class Wordmark(Gtk.Box):
    """The mark as a widget: `foSSH ◆ local admin console`.

    One accessible label covers the whole thing. Without it a screen
    reader announces the runs separately — "f o", "S S H", "black
    diamond" — because they are separate Pango runs with a size change
    between them, and the diamond is a decorative glyph with a real
    Unicode name. How the mark is *built* must not change what it
    *says*.
    """

    def __init__(self, size_pt: float = 15.0, *, show_tagline: bool = True) -> None:
        super().__init__(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.add_css_class("wordmark")

        name = Gtk.Label()

        name.add_css_class("wordmark-name")
        name.set_markup(wordmark_markup(size_pt))
        name.set_use_markup(True)
        self.append(name)

        if show_tagline:
            diamond = Gtk.Label(label=DIAMOND)
            diamond.add_css_class("wordmark-diamond")
            diamond.set_valign(Gtk.Align.CENTER)
            self.append(diamond)

            tagline = Gtk.Label(label=TAGLINE)
            tagline.add_css_class("wordmark-tagline")
            tagline.set_valign(Gtk.Align.CENTER)
            self.append(tagline)

        spoken = f"foSSH {TAGLINE}" if show_tagline else "foSSH"
        self.update_property([Gtk.AccessibleProperty.LABEL], [spoken])
        self.set_accessible_role(Gtk.AccessibleRole.IMG)
