"""The foSSH palette, carried over from the TUI, and the contrast maths
that keeps it honest.

## Why these exact colours

They are the ones `crates/fossh-tui/src/theme.rs` used, to the byte —
warm graphite behind warm off-white, with amber, sage and terracotta
carrying meaning rather than decoration (amber = pending, sage =
healthy, terracotta = error, muted = secondary). Someone who ran the
TUI and then opens this window should recognise it immediately; a
console in stock GNOME blue would read as a different product that
happens to share a name.

## Why the accents change between light and dark

The TUI was dark only, so its accents were tuned against graphite and
nothing else. Against a light background the same amber sits at about
1.9:1 — unreadable, and a WCAG 2.2 §1.4.3 failure. So each accent has
a second, darker value for light mode, chosen to keep the same hue
while clearing 4.5:1.

## Why this file computes contrast at all

Because a palette is exactly the kind of thing that gets "just
slightly" adjusted later, and a contrast failure is invisible to the
person making the adjustment — it looks fine on their monitor.
`contrast_ratio` is here so `tests/test_palette.py` can assert every
pairing this app actually renders, and fail the build rather than
shipping something someone cannot read.
"""

from __future__ import annotations


def _hex_to_rgb(value: str) -> tuple[float, float, float]:
    value = value.lstrip("#")
    return tuple(int(value[i : i + 2], 16) / 255.0 for i in (0, 2, 4))  # type: ignore[return-value]


def relative_luminance(hex_colour: str) -> float:
    """WCAG 2.x relative luminance, to the letter of the definition."""

    def channel(c: float) -> float:
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = (channel(c) for c in _hex_to_rgb(hex_colour))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(foreground: str, background: str) -> float:
    a = relative_luminance(foreground)
    b = relative_luminance(background)
    lighter, darker = max(a, b), min(a, b)
    return (lighter + 0.05) / (darker + 0.05)


#: Dark, and the original. Every value here is `theme.rs`'s, unchanged.
DARK = {
    # theme.rs GRAPHITE
    "brand_bg": "#1C1C1E",
    # One step up from the background, for cards. Not from the TUI,
    # which had no surface layering to do — a terminal cell has no
    # elevation.
    "brand_card": "#252528",
    # theme.rs FOREGROUND
    "brand_fg": "#D8D2C8",
    # theme.rs MUTED was #91877A, and this is the one identity colour
    # that had to move. Against graphite it measures 4.82:1 — passing,
    # but only just. Against the card surface above, which a terminal
    # never had because a terminal cell has no elevation, the same
    # value lands at 4.33:1: a real WCAG 2.2 §1.4.3 failure for every
    # caption on every card in this window, and one nobody would ever
    # catch by looking. Lightened by the smallest amount that clears
    # 4.5:1 on both surfaces (5.00:1 on card, 5.56:1 on graphite),
    # holding the hue. The five colours that actually carry the brand
    # — graphite, foreground, amber, sage, terracotta — are untouched.
    "brand_muted": "#9C9286",
    # theme.rs AMBER
    "brand_accent": "#E0AF68",
    # theme.rs SAGE
    "brand_success": "#87A96B",
    # theme.rs TERRACOTTA
    "brand_error": "#D67659",
    "brand_warning": "#E0AF68",
    "brand_hairline": "#3A3A3E",
}

#: Light. Same hues, pulled down in luminance until each clears 4.5:1
#: against the light background — see this module's own docstring.
LIGHT = {
    "brand_bg": "#FAF8F5",
    "brand_card": "#FFFFFF",
    "brand_fg": "#26231E",
    "brand_muted": "#5C5449",
    "brand_accent": "#8A5A00",
    "brand_success": "#4A6B33",
    "brand_error": "#A8402A",
    "brand_warning": "#8A5A00",
    "brand_hairline": "#E2DDD4",
}


def scheme(dark: bool) -> dict[str, str]:
    return DARK if dark else LIGHT


#: libadwaita's own semantic slots, mapped onto brand names. Filling
#: these is what makes stock widgets — `Adw.StatusPage`, a
#: `.suggested-action` button, an `Adw.EntryRow`'s focus ring — pick
#: the brand up, instead of every one of them needing a rule of its own
#: and the window ending up two-toned.
#:
#: `(libadwaita slot, brand name)`. The slot name is given in
#: underscore form; the CSS-variable spelling is derived by swapping
#: underscores for hyphens, which is exactly how libadwaita renamed
#: them.
ADW_SLOTS = [
    ("accent_color", "brand_accent"),
    ("accent_bg_color", "brand_accent"),
    ("accent_fg_color", "brand_bg"),
    ("success_color", "brand_success"),
    ("success_bg_color", "brand_success"),
    ("warning_color", "brand_warning"),
    ("warning_bg_color", "brand_warning"),
    ("error_color", "brand_error"),
    ("error_bg_color", "brand_error"),
    ("window_bg_color", "brand_bg"),
    ("window_fg_color", "brand_fg"),
    ("view_bg_color", "brand_bg"),
    ("view_fg_color", "brand_fg"),
    ("card_bg_color", "brand_card"),
    ("card_fg_color", "brand_fg"),
    ("headerbar_bg_color", "brand_bg"),
    ("headerbar_fg_color", "brand_fg"),
    ("sidebar_bg_color", "brand_bg"),
    ("sidebar_fg_color", "brand_fg"),
    ("dialog_bg_color", "brand_card"),
    ("dialog_fg_color", "brand_fg"),
    ("popover_bg_color", "brand_card"),
    ("popover_fg_color", "brand_fg"),
]


def define_colors_css(dark: bool) -> str:
    """The colour block for the active scheme, in both spellings.

    GTK's CSS has no `prefers-color-scheme` query, so following the
    system means regenerating this and reloading the provider when
    `Adw.StyleManager:dark` changes — `app.py` does exactly that.

    Both spellings are emitted on purpose. libadwaita 1.8 replaced its
    named colours with CSS custom properties, so `--accent-bg-color`
    is what a current build reads and `@define-color accent_bg_color`
    is what anything older reads. A package built here can be
    installed against either — EPEL 9 in particular is far behind
    Fedora — and emitting one of the two would leave the window
    half-themed on the other, which is both ugly and, for the
    contrast guarantees `REQUIRED_CONTRAST` makes, wrong. Whichever
    spelling a given libadwaita does not understand is ignored, so
    carrying both costs a few hundred bytes and nothing else.
    """
    colours = scheme(dark)

    define_lines = [f"@define-color {name} {value};" for name, value in colours.items()]
    define_lines += [
        f"@define-color {slot} {colours[brand]};" for slot, brand in ADW_SLOTS
    ]

    var_lines = [f"  --{name.replace('_', '-')}: {value};" for name, value in colours.items()]
    var_lines += [
        f"  --{slot.replace('_', '-')}: {colours[brand]};" for slot, brand in ADW_SLOTS
    ]

    return "\n".join(define_lines) + "\n:root {\n" + "\n".join(var_lines) + "\n}\n"


#: Every foreground/background pairing the app actually renders, with
#: the WCAG 2.2 level each has to clear. `tests/test_palette.py` walks
#: this; adding a colour to the app means adding its pairing here.
#:
#: 4.5 is §1.4.3 Contrast (Minimum) for body text. 3.0 is the same
#: rule's allowance for large text (>=18.66px bold or >=24px), and also
#: §1.4.11 Non-text Contrast for a UI component that carries meaning —
#: which is what the status dots are.
REQUIRED_CONTRAST = [
    ("brand_fg", "brand_bg", 4.5, "body text on the window"),
    ("brand_fg", "brand_card", 4.5, "body text on a card"),
    ("brand_muted", "brand_bg", 4.5, "captions and secondary text"),
    ("brand_muted", "brand_card", 4.5, "captions on a card"),
    ("brand_accent", "brand_bg", 3.0, "the wordmark's caps, section headings"),
    ("brand_accent", "brand_card", 3.0, "accents on a card"),
    ("brand_success", "brand_bg", 3.0, "the healthy status dot"),
    ("brand_success", "brand_card", 3.0, "the healthy status dot on a card"),
    ("brand_error", "brand_bg", 4.5, "error text"),
    ("brand_error", "brand_card", 4.5, "error text on a card"),
    ("brand_warning", "brand_bg", 3.0, "the pending status dot"),
    ("brand_bg", "brand_accent", 4.5, "label text inside a suggested button"),
]
