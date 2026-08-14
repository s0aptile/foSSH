"""Contrast and typography checks that do not need a display.

The palette test is the one that matters. A colour is the easiest thing
in an interface to adjust and the hardest to verify by looking — it
looks fine on the monitor of whoever changed it — so every pairing the
app renders is asserted here against the WCAG 2.2 level it has to
clear, in both schemes. Getting this wrong ships something a real
person cannot read.

    python3 -m pytest gui/tests/test_palette.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fossh_console.palette import (  # noqa: E402
    ADW_SLOTS,
    DARK,
    LIGHT,
    REQUIRED_CONTRAST,
    contrast_ratio,
    define_colors_css,
    relative_luminance,
    scheme,
)


class TestContrastMaths:
    """The calculator itself, against values with known answers."""

    def test_black_on_white_is_the_documented_maximum(self):
        assert contrast_ratio("#000000", "#FFFFFF") == pytest.approx(21.0, abs=0.01)

    def test_a_colour_against_itself_is_one(self):
        assert contrast_ratio("#4A6B33", "#4A6B33") == pytest.approx(1.0, abs=0.001)

    def test_the_ratio_does_not_depend_on_which_argument_is_which(self):
        assert contrast_ratio("#E0AF68", "#1C1C1E") == pytest.approx(
            contrast_ratio("#1C1C1E", "#E0AF68")
        )

    def test_luminance_matches_the_wcag_reference_values(self):
        assert relative_luminance("#FFFFFF") == pytest.approx(1.0, abs=0.001)
        assert relative_luminance("#000000") == pytest.approx(0.0, abs=0.001)
        # Mid grey, which the spec's own worked example puts here.
        assert relative_luminance("#808080") == pytest.approx(0.2159, abs=0.001)


class TestPaletteMeetsWCAG:
    @pytest.mark.parametrize("dark", [True, False], ids=["dark", "light"])
    @pytest.mark.parametrize(
        "fg,bg,required,what",
        REQUIRED_CONTRAST,
        ids=[f"{fg}-on-{bg}" for fg, bg, _r, _w in REQUIRED_CONTRAST],
    )
    def test_every_rendered_pairing_clears_its_level(self, dark, fg, bg, required, what):
        colours = scheme(dark)
        ratio = contrast_ratio(colours[fg], colours[bg])
        assert ratio >= required, (
            f"{what} ({fg} on {bg}, {'dark' if dark else 'light'}) is {ratio:.2f}:1, "
            f"below the {required}:1 WCAG 2.2 requirement"
        )

    def test_both_schemes_define_exactly_the_same_names(self):
        # A name present in one scheme and not the other renders as
        # nothing at all in GTK, silently, in whichever scheme is
        # missing it.
        assert set(DARK) == set(LIGHT)

    def test_the_two_schemes_are_actually_different(self):
        assert DARK != LIGHT

    def test_dark_is_dark_and_light_is_light(self):
        assert relative_luminance(DARK["brand_bg"]) < 0.1
        assert relative_luminance(LIGHT["brand_bg"]) > 0.7

    def test_the_dark_scheme_still_holds_the_tui_identity_colours_exactly(self):
        # The point of the palette. If someone "tidies" one of these,
        # the brand quietly stops matching the product people used
        # before, and this says so.
        assert DARK["brand_bg"] == "#1C1C1E", "theme.rs GRAPHITE"
        assert DARK["brand_fg"] == "#D8D2C8", "theme.rs FOREGROUND"
        assert DARK["brand_accent"] == "#E0AF68", "theme.rs AMBER"
        assert DARK["brand_success"] == "#87A96B", "theme.rs SAGE"
        assert DARK["brand_error"] == "#D67659", "theme.rs TERRACOTTA"

    def test_muted_is_the_one_deliberate_deviation_and_stays_close(self):
        # `theme.rs` MUTED (#91877A) fails 4.5:1 on the card surface,
        # which is why it moved — see `palette.py`. The replacement
        # still has to look like the same colour, so the deviation is
        # bounded here rather than left to drift further on the next
        # contrast complaint.
        original = "#91877A"
        assert DARK["brand_muted"] != original
        moved = abs(relative_luminance(DARK["brand_muted"]) - relative_luminance(original))
        assert moved < 0.06, (
            f"brand_muted has drifted {moved:.3f} in luminance from the TUI's MUTED; "
            "that is further than a contrast fix needs and the brand will show it"
        )


class TestGeneratedCSS:
    @pytest.mark.parametrize("dark", [True, False], ids=["dark", "light"])
    def test_every_brand_name_reaches_the_stylesheet(self, dark):
        css = define_colors_css(dark)
        for name in scheme(dark):
            assert f"@define-color {name} " in css

    @pytest.mark.parametrize("dark", [True, False], ids=["dark", "light"])
    def test_libadwaita_semantic_names_are_redefined_too(self, dark):
        # Without these, stock widgets stay GNOME blue and the window
        # ends up two-toned.
        css = define_colors_css(dark)
        for name in (
            "accent_color",
            "accent_bg_color",
            "window_bg_color",
            "card_bg_color",
            "success_color",
            "error_color",
        ):
            assert f"@define-color {name} " in css

    @pytest.mark.parametrize("dark", [True, False], ids=["dark", "light"])
    def test_every_declaration_is_complete(self, dark):
        # A missing semicolon makes GTK discard the rest of the block,
        # which shows up as a partly-themed window rather than an error.
        for line in define_colors_css(dark).splitlines():
            stripped = line.strip()
            if stripped in (":root {", "}"):
                continue
            assert stripped.endswith(";"), line
            assert stripped.startswith("@define-color ") or stripped.startswith("--"), line

    @pytest.mark.parametrize("dark", [True, False], ids=["dark", "light"])
    def test_both_spellings_are_emitted_for_every_slot(self, dark):
        # libadwaita 1.8 replaced named colours with CSS variables, so
        # a build newer than that reads `--accent-bg-color` and
        # anything older reads `@define-color accent_bg_color`. A
        # package built here can be installed against either, and
        # emitting one spelling leaves the other half-themed.
        css = define_colors_css(dark)
        for slot, _brand in ADW_SLOTS:
            assert f"@define-color {slot} " in css, slot
            assert f"--{slot.replace('_', '-')}: " in css, slot

    @pytest.mark.parametrize("dark", [True, False], ids=["dark", "light"])
    def test_the_variable_block_is_balanced(self, dark):
        css = define_colors_css(dark)
        assert css.count("{") == css.count("}") == 1

    def test_the_button_label_pairing_is_checked_in_the_right_direction(self):
        # `accent_fg_color` is what sits *on* the accent, so it is the
        # background that is the accent here. Getting this backwards
        # would pass the assertion while shipping unreadable buttons.
        for dark in (True, False):
            colours = scheme(dark)
            assert (
                contrast_ratio(colours["brand_bg"], colours["brand_accent"]) >= 4.5
            ), "text on a suggested-action button"
