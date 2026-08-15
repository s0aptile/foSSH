"""Icons: Google's Material set where installed, the theme's own
symbolic icons otherwise.

Material is a *ligature* font — the glyph is produced by setting the
icon's name as text, so `"dashboard"` renders the dashboard glyph — so
using it means rendering a label rather than loading an image. That is
what makes the fallback clean: the same call produces either a label in
the icon font or a `Gtk.Image` from the icon theme, and no call site
has to know which.

## Two Material sets, and why both are handled

Fedora's `material-icons-fonts` ships the classic **Material Icons**
set. Google's current one is **Material Symbols**, which renamed a
large number of glyphs (`space_dashboard` for `dashboard`, `api` for
`extension`, and so on). Naming only one set would mean that on the
other, every icon renders as its own name spelled out in words — a
loud, obvious, and entirely avoidable failure. So each icon carries a
name for both, and the right one is chosen from the family that is
actually present.

## Ligatures are verified, not assumed

Even within one set, a given build may not carry a given glyph, and an
unresolved ligature is not a missing icon — it is the literal word
rendered at icon size, in the middle of the interface. `_resolves`
measures it: a real ligature collapses to roughly one em, while
unresolved text is several times wider. Anything that fails that check
falls back to the symbolic icon.

## Accessibility

Every icon here is decorative — it sits beside a text label, or belongs
to a control that carries its own accessible name — so each is marked
`PRESENTATION`. Without that, a screen reader announces the raw
ligature text as content, which is a common and genuinely confusing
defect in icon-font interfaces.
"""

from __future__ import annotations

import functools

import gi

# Declared before the import: PyGObject warns (and, on a machine with
# GTK3 also installed, can load the wrong one) when a typelib is
# imported without a version. `app.py` declares these too, but this
# module is imported directly by tests that never go through it.
gi.require_version("Gdk", "4.0")
gi.require_version("Gtk", "4.0")

from gi.repository import Gdk, Gtk, Pango, PangoCairo  # noqa: E402

#: Preference order. Symbols first: it is the current set, so anyone
#: who has deliberately installed one has probably installed that one.
SYMBOLS_FAMILIES = ["Material Symbols Outlined", "Material Symbols Rounded"]
CLASSIC_FAMILIES = ["Material Icons Outlined", "Material Icons"]

#: key -> (Material Symbols name, classic Material Icons name,
#:         freedesktop symbolic name)
ICONS = {
    "overview": ("space_dashboard", "dashboard", "go-home-symbolic"),
    "telemetry": ("query_stats", "insert_chart", "utilities-system-monitor-symbolic"),
    "integrations": ("api", "extension", "network-transmit-symbolic"),
    "setup": ("shield_lock", "security", "security-high-symbolic"),
    "refresh": ("refresh", "refresh", "view-refresh-symbolic"),
    "menu": ("more_vert", "more_vert", "open-menu-symbolic"),
    "add": ("add", "add", "list-add-symbolic"),
    "delete": ("delete", "delete", "user-trash-symbolic"),
    "copy": ("content_copy", "content_copy", "edit-copy-symbolic"),
    "warning": ("warning", "warning", "dialog-warning-symbolic"),
    "empty": ("inbox", "inbox", "view-list-symbolic"),
    "no_results": ("search_off", "search", "edit-find-symbolic"),
    "key": ("key_vertical", "vpn_key", "dialog-password-symbolic"),
    "verified": ("verified_user", "verified_user", "security-high-symbolic"),
    "pending": ("hourglass_empty", "hourglass_empty", "security-medium-symbolic"),
    "test": ("bolt", "flash_on", "media-playback-start-symbolic"),
    "legal": ("gavel", "gavel", "text-x-generic-symbolic"),
}

LAST_RESORT = "application-x-executable-symbolic"


@functools.lru_cache(maxsize=1)
def _installed_families() -> set[str]:
    font_map = PangoCairo.FontMap.get_default()
    if font_map is None:
        return set()
    return {family.get_name().lower() for family in font_map.list_families()}


@functools.lru_cache(maxsize=1)
def icon_font() -> tuple[str, int] | None:
    """`(family, index into ICONS' tuple)`, or `None` for no icon font.

    Index 0 selects the Material Symbols name, 1 the classic one.
    """
    installed = _installed_families()
    for name in SYMBOLS_FAMILIES:
        if name.lower() in installed:
            return (name, 0)
    for name in CLASSIC_FAMILIES:
        if name.lower() in installed:
            return (name, 1)
    return None


@functools.lru_cache(maxsize=256)
def _resolves(family: str, ligature: str) -> bool:
    """Whether `ligature` collapses to a glyph in `family`.

    Measured rather than looked up: Pango exposes no direct "does this
    ligature exist" query, but it will happily lay the text out, and
    the width tells the story. One glyph is about one em; the same
    string as letters is far wider. The threshold sits well clear of
    both.
    """
    font_map = PangoCairo.FontMap.get_default()
    if font_map is None:
        return False
    context = font_map.create_context()
    description = Pango.FontDescription()
    description.set_family(family)
    description.set_size(16 * Pango.SCALE)
    layout = Pango.Layout(context)
    layout.set_font_description(description)
    layout.set_text(ligature, -1)
    width, _height = layout.get_pixel_size()
    if width <= 0:
        return False
    # A 16pt glyph lays out near 16-24px wide once hinting and side
    # bearings are counted. Two ems is generous for a real glyph and
    # far below even the shortest unresolved name ("add" as letters is
    # already wider than one em, but "content_copy" is enormous).
    return width <= 40


def _pango_attributes(family: str, size_pt: float) -> Pango.AttrList:
    attrs = Pango.AttrList()
    attrs.insert(Pango.attr_family_new(family))
    attrs.insert(Pango.attr_size_new(int(size_pt * Pango.SCALE)))
    return attrs


def symbolic_name(key: str) -> str:
    """The freedesktop name, for APIs that accept only a name
    (`Adw.StatusPage:icon-name` and friends)."""
    entry = ICONS.get(key)
    symbolic = entry[2] if entry else LAST_RESORT
    display = Gdk.Display.get_default()
    if display is not None:
        theme = Gtk.IconTheme.get_for_display(display)
        if not theme.has_icon(symbolic):
            return LAST_RESORT
    return symbolic


def icon(key: str, *, size_pt: float = 16.0) -> Gtk.Widget:
    """A widget showing `key`, marked decorative."""
    entry = ICONS.get(key)
    if entry is None:
        return _symbolic_image(LAST_RESORT)

    chosen = icon_font()
    if chosen is not None:
        family, index = chosen
        ligature = entry[index]
        if _resolves(family, ligature):
            label = Gtk.Label(label=ligature)
            label.add_css_class("material-icon")
            # Set per widget, not in CSS: the family is only known at
            # runtime, and a CSS rule naming an absent font does
            # nothing at all, silently.
            label.set_attributes(_pango_attributes(family, size_pt))
            label.set_accessible_role(Gtk.AccessibleRole.PRESENTATION)
            return label

    return _symbolic_image(symbolic_name(key))


def _symbolic_image(name: str) -> Gtk.Image:
    image = Gtk.Image.new_from_icon_name(name)
    image.set_accessible_role(Gtk.AccessibleRole.PRESENTATION)
    return image


def labelled_button(key: str, label: str) -> Gtk.Button:
    """A button with both an icon and a word.

    Preferred over icon-only throughout: WCAG 2.2 §2.5.3 (Label in
    Name) wants the visible text to be part of the accessible name,
    which happens by itself only when there is visible text.
    """
    btn = Gtk.Button()
    content = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    content.set_halign(Gtk.Align.CENTER)
    content.append(icon(key))
    content.append(Gtk.Label(label=label))
    btn.set_child(content)
    return btn


def icon_button(key: str, accessible_label: str) -> Gtk.Button:
    """An icon-only button, which therefore must be named explicitly."""
    btn = Gtk.Button()
    btn.set_child(icon(key))
    btn.set_tooltip_text(accessible_label)
    btn.update_property([Gtk.AccessibleProperty.LABEL], [accessible_label])
    # WCAG 2.2 §2.5.8 Target Size (Minimum) is 24x24 CSS px. GTK's
    # default button clears that, but a `.flat` icon button in a header
    # bar can be shrunk by a theme, so the floor is stated rather than
    # assumed.
    btn.set_size_request(32, 32)
    return btn
