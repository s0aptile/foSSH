"""Animation primitives, and the one rule the rest of the app follows.

Motion here is functional: it tells you where something came from, that
a number changed, or that a panel is now the one you are looking at. It
is never decorative, and it is never in the way — every duration in
`Duration` is inside the range a person reads as "instant but not
abrupt", and nothing blocks input while it runs.

## Reduced motion is honoured, not overridden

`Gtk.Settings:gtk-enable-animations` is off when the desktop is set to
reduce motion, and for some people that setting exists because motion
makes them ill. Every helper here checks it and jumps straight to the
final value, so the app stays completely usable and simply stops
moving. That is why animation is funnelled through this module instead
of being written inline at each call site: one check, impossible to
forget.
"""

from __future__ import annotations

from typing import Callable

from gi.repository import Gtk


class Duration:
    """Milliseconds. Three steps, deliberately — a scale with a value
    for every occasion is a scale nobody applies consistently."""

    #: A control acknowledging a press; a reveal toggling.
    MICRO = 150
    #: The default. View changes, rows appearing, values counting.
    STANDARD = 250
    #: Something large moving, or a number crossing a big distance.
    LARGE = 400


def animations_enabled() -> bool:
    settings = Gtk.Settings.get_default()
    if settings is None:
        return False
    return settings.get_property("gtk-enable-animations")


def _bezier(p1x: float, p1y: float, p2x: float, p2y: float) -> Callable[[float], float]:
    """A cubic Bézier easing curve through (0,0), (p1), (p2), (1,1).

    The same parametrisation CSS `cubic-bezier()` uses, solved the same
    way browsers solve it: Newton-Raphson from a good initial guess,
    falling back to bisection when the derivative is too flat for
    Newton to be trusted. Worth doing properly rather than substituting
    a closed-form easing that is merely nearby — the difference between
    a curve that settles and one that arrives is exactly the kind of
    thing that reads as "cheap" without anyone being able to say why.
    """

    def sample(a: float, b: float, t: float) -> float:
        # Horner form of the Bézier polynomial with P0=0 and P3=1.
        c = 3.0 * a
        bb = 3.0 * (b - a) - c
        aa = 1.0 - c - bb
        return ((aa * t + bb) * t + c) * t

    def slope(a: float, b: float, t: float) -> float:
        c = 3.0 * a
        bb = 3.0 * (b - a) - c
        aa = 1.0 - c - bb
        return (3.0 * aa * t + 2.0 * bb) * t + c

    def solve_t_for_x(x: float) -> float:
        t = x
        for _ in range(8):
            error = sample(p1x, p2x, t) - x
            if abs(error) < 1e-6:
                return t
            derivative = slope(p1x, p2x, t)
            if abs(derivative) < 1e-6:
                break
            t -= error / derivative
        low, high, t = 0.0, 1.0, x
        for _ in range(24):
            value = sample(p1x, p2x, t)
            if abs(value - x) < 1e-6:
                return t
            if value > x:
                high = t
            else:
                low = t
            t = (low + high) / 2.0
        return t

    def ease(x: float) -> float:
        if x <= 0.0:
            return 0.0
        if x >= 1.0:
            return 1.0
        return sample(p1y, p2y, solve_t_for_x(x))

    return ease


#: Fast out of the gate, long gentle settle. The curve to use for
#: anything arriving or growing — it reads as the thing having weight.
EASE_OUT = _bezier(0.32, 0.72, 0.0, 1.0)

#: Symmetric. For something moving between two places it is already in.
EASE_IN_OUT = _bezier(0.65, 0.0, 0.35, 1.0)


def animate(
    widget: Gtk.Widget,
    duration_ms: int,
    on_frame: Callable[[float], None],
    *,
    easing: Callable[[float], float] = EASE_OUT,
    on_done: Callable[[], None] | None = None,
) -> None:
    """Drives `on_frame(eased_progress)` for `duration_ms`.

    Frames come from the widget's own frame clock rather than a timer,
    so they land in step with the compositor instead of tearing across
    it. When animations are off, `on_frame(1.0)` is called once and
    that is the whole animation.
    """
    if not animations_enabled() or duration_ms <= 0:
        on_frame(1.0)
        if on_done:
            on_done()
        return

    start_us: list[int] = []

    def tick(w: Gtk.Widget, clock: object) -> bool:
        now = clock.get_frame_time()
        if not start_us:
            start_us.append(now)
        elapsed_ms = (now - start_us[0]) / 1000.0
        progress = min(1.0, elapsed_ms / duration_ms)
        on_frame(easing(progress))
        if progress >= 1.0:
            if on_done:
                on_done()
            return False
        return True

    widget.add_tick_callback(tick)


def format_count(value: float) -> str:
    """Whole numbers, grouped, with no decimal tail mid-animation.

    A counter that flickers through `1234.7` on its way to `1235` looks
    broken; rounding every intermediate frame is what makes a counting
    animation read as a number changing rather than as a glitch.
    """
    return f"{int(round(value)):,}"


def count_to(
    label: Gtk.Label,
    target: float,
    *,
    start: float = 0.0,
    duration_ms: int = Duration.STANDARD,
    formatter: Callable[[float], str] = format_count,
) -> None:
    """Counts a label from `start` to `target`.

    Only for figures a person is meant to register as having changed.
    Requires the label to be using tabular figures — otherwise the
    label's width changes on nearly every frame and the whole row
    jitters. The `.numeric` class in `style.css` is what supplies them.
    """
    span = target - start

    def frame(progress: float) -> None:
        label.set_text(formatter(start + span * progress))

    animate(label, duration_ms, frame)
