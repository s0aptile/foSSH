"""Widgets GTK does not have, drawn to the same rules as everything else.

Both of these exist because the stock alternatives get a detail wrong
that matters: a `Gtk.LevelBar` cannot show a shape over time, and a
plain `Gtk.Label` full of digits jitters as it updates.
"""

from __future__ import annotations

import math

from gi.repository import Gdk, Gtk

from .motion import Duration, animate, count_to, format_count

def _accent_rgba(widget: Gtk.Widget) -> Gdk.RGBA:
    """The accent colour libadwaita is currently using.

    Looked up rather than hardcoded so the app follows the accent the
    person picked in their settings. The fallback is only reached on a
    theme that defines no accent at all.
    """
    found, rgba = widget.get_style_context().lookup_color("accent_color")
    if found:
        return rgba
    fallback = Gdk.RGBA()
    fallback.parse("#3584e4")
    return fallback

def _foreground_rgba(widget: Gtk.Widget) -> Gdk.RGBA:
    found, rgba = widget.get_style_context().lookup_color("window_fg_color")
    if found:
        return rgba
    fallback = Gdk.RGBA()
    fallback.parse("#000000")
    return fallback

class Sparkline(Gtk.DrawingArea):
    """A small shape-over-time plot: line, soft fill, marked last point.

    Drawn rather than charted. There are no axes, no gridlines and no
    legend, because at this size they would cost more room than the
    data they annotate — the number itself is always shown next to it,
    so this only has to convey shape.
    """

    def __init__(self) -> None:
        super().__init__()
        self.add_css_class("sparkline")
        self.set_content_height(44)
        self.set_hexpand(True)
        self._values: list[float] = []

        self._reveal = 1.0
        self.set_draw_func(self._draw)

    def set_values(self, values: list[float]) -> None:
        self._values = list(values)
        self._reveal = 0.0

        def frame(progress: float) -> None:
            self._reveal = progress
            self.queue_draw()

        animate(self, Duration.LARGE, frame)

    def _draw(self, area: Gtk.DrawingArea, cr, width: int, height: int) -> None:
        values = self._values
        if len(values) < 2 or width <= 0 or height <= 0:
            return

        accent = _accent_rgba(self)

        pad = 4.0
        plot_w = max(1.0, width - pad * 2)
        plot_h = max(1.0, height - pad * 2)

        low = min(values)
        high = max(values)
        span = high - low
        if span <= 0:

            span = 1.0
            low = low - 0.5

        def point(index: int) -> tuple[float, float]:
            x = pad + (index / (len(values) - 1)) * plot_w
            y = pad + plot_h - ((values[index] - low) / span) * plot_h
            return x, y

        visible = max(2, int(math.ceil(len(values) * self._reveal)))
        pts = [point(i) for i in range(visible)]

        cr.save()
        gradient_top = pts[0][1]
        for x, y in pts:
            gradient_top = min(gradient_top, y)
        cr.move_to(pts[0][0], pad + plot_h)
        for x, y in pts:
            cr.line_to(x, y)
        cr.line_to(pts[-1][0], pad + plot_h)
        cr.close_path()
        cr.set_source_rgba(accent.red, accent.green, accent.blue, 0.14)
        cr.fill()
        cr.restore()

        cr.save()
        cr.set_line_width(2.0)
        cr.set_line_cap(1)
        cr.set_line_join(1)
        cr.set_source_rgba(accent.red, accent.green, accent.blue, 1.0)
        cr.move_to(*pts[0])
        for x, y in pts[1:]:
            cr.line_to(x, y)
        cr.stroke()
        cr.restore()

        cr.save()
        last_x, last_y = pts[-1]
        found, bg = self.get_style_context().lookup_color("card_bg_color")
        if found:
            cr.set_source_rgba(bg.red, bg.green, bg.blue, 1.0)
            cr.arc(last_x, last_y, 4.0, 0, 2 * math.pi)
            cr.fill()
        cr.set_source_rgba(accent.red, accent.green, accent.blue, 1.0)
        cr.arc(last_x, last_y, 2.5, 0, 2 * math.pi)
        cr.fill()
        cr.restore()

class StatTile(Gtk.Box):
    """One headline figure with its label, and an optional sparkline.

    The number counts to its value rather than snapping, which is what
    makes a refresh legible as "this changed" instead of the whole
    panel silently becoming different.
    """

    def __init__(self, label: str, *, with_sparkline: bool = False) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.add_css_class("stat-card")

        self._value_label = Gtk.Label(label="0", xalign=0)
        self._value_label.add_css_class("stat-value")
        self._value_label.add_css_class("numeric")

        caption = Gtk.Label(label=label, xalign=0)
        caption.add_css_class("stat-label")

        self.append(self._value_label)
        self.append(caption)

        self._sparkline: Sparkline | None = None
        if with_sparkline:
            self._sparkline = Sparkline()
            self._sparkline.set_margin_top(8)
            self.append(self._sparkline)

        self._current = 0.0

    def set_value(self, value: float, *, animated: bool = True) -> None:
        if animated:
            count_to(self._value_label, value, start=self._current)
        else:
            self._value_label.set_text(format_count(value))
        self._current = value

    def set_text_value(self, text: str) -> None:
        """For a figure that is not a number — a state word, a dash."""
        self._value_label.set_text(text)
        self._current = 0.0

    def set_series(self, values: list[float]) -> None:
        """Shows the shape, or hides the plot entirely.

        A series that is all zeros draws as a flat bar filling the
        widget, which reads as a solid block of colour rather than as
        "nothing happened yet" — worse than showing no plot at all. An
        install with no traffic today is the common first-run case, so
        this is not an edge case.
        """
        if self._sparkline is None:
            return
        if not values or all(v <= 0 for v in values):
            self._sparkline.set_visible(False)
            return
        self._sparkline.set_visible(True)
        self._sparkline.set_values(values)

class StatusRow(Gtk.Box):
    """A dot, a name, and a state word.

    The word is never omitted in favour of the dot alone: colour is not
    a signal everyone receives, and `style.css` says more about why.
    """

    STATES = {
        "ok": "ok",
        "warn": "warn",
        "bad": "bad",
        "idle": "idle",
    }

    def __init__(self, name: str) -> None:
        super().__init__(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self._dot = Gtk.Box()
        self._dot.add_css_class("status-dot")
        self._dot.add_css_class("idle")
        self._dot.set_valign(Gtk.Align.CENTER)

        title = Gtk.Label(label=name, xalign=0)
        title.set_hexpand(True)

        self._state = Gtk.Label(label="—", xalign=1)
        self._state.add_css_class("dim")

        self.append(self._dot)
        self.append(title)
        self.append(self._state)

    def set_state(self, state: str, text: str) -> None:
        for css in self.STATES.values():
            self._dot.remove_css_class(css)
        self._dot.add_css_class(self.STATES.get(state, "idle"))
        self._state.set_text(text)

def pad(widget: Gtk.Widget, *, top=0, bottom=0, start=0, end=0, all=None) -> Gtk.Widget:
    """Sets margins on the 4px grid, in one call.

    Exists because the alternative — four `set_margin_*` calls at every
    site — is where inconsistent spacing comes from: someone sets three
    of the four, or reaches for a value that is not on the grid because
    typing it is no harder than typing one that is.
    """
    if all is not None:
        top = bottom = start = end = all
    widget.set_margin_top(top)
    widget.set_margin_bottom(bottom)
    widget.set_margin_start(start)
    widget.set_margin_end(end)
    return widget

def section(title: str, subtitle: str | None = None) -> Gtk.Box:
    """A titled block, spaced on the same grid as everything else."""
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    heading = Gtk.Label(label=title, xalign=0)
    heading.add_css_class("section-title")
    box.append(heading)
    if subtitle:
        note = Gtk.Label(label=subtitle, xalign=0)
        note.add_css_class("caption")
        note.set_wrap(True)
        box.append(note)
    return box
