"""The display-face resolution and markup that do not need a display.

Colours get `test_palette.py`; this is the same discipline applied to
the Bitcount extension from `feat(console): the wordmark's face
carries to the dashboard's numbers` — two independent reviews of that
change flagged that fonts were held to a looser bar than colours are,
and this file is what closes that gap. Every assertion here runs
headless: font *resolution* and markup *generation* need Pango's font
map, not a live window.

    python3 -m pytest gui/tests/test_branding.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fossh_console import branding, widgets

class TestFamilyResolution:
    def test_an_uninstalled_candidate_is_skipped_for_the_next(self):
        assert branding.resolve_family(
            ["Definitely Not A Real Font XYZ", "Sans"]
        ) == "Sans"

    def test_resolve_family_falls_back_to_its_own_last_candidate(self):
        assert branding.resolve_family(
            ["Also Not Real", "Still Not Real"]
        ) == "Still Not Real"

    def test_display_family_returns_none_when_nothing_matches(self):
        assert branding._display_family(["Not Real At All"]) is None

    def test_display_family_finds_a_real_installed_face(self):
        assert branding._display_family(["Not Real", "Sans"]) == "Sans"

    def test_wordmark_and_stat_value_resolve_independently(self):
        assert branding.wordmark_family() == branding._display_family(
            branding.WORDMARK_FAMILIES
        )
        assert branding.stat_value_family() == branding._display_family(
            branding.STAT_VALUE_FAMILIES
        )

class TestTheTwoFamilyListsAreActuallyTwoLists:
    """What `feat(console)`'s design review flagged: sharing one list
    means a legibility fix to one face silently changes the other."""

    def test_they_are_not_the_same_object(self):
        assert branding.WORDMARK_FAMILIES is not branding.STAT_VALUE_FAMILIES

    def test_mutating_one_does_not_touch_the_other(self):
        original = list(branding.STAT_VALUE_FAMILIES)
        branding.WORDMARK_FAMILIES.append("Only For The Mark")
        try:
            assert branding.STAT_VALUE_FAMILIES == original
        finally:
            branding.WORDMARK_FAMILIES.remove("Only For The Mark")

class TestStatValueMarkup:
    def test_plain_text_survives_unescaped_when_no_face_is_found(self, monkeypatch):

        monkeypatch.setattr(branding, "stat_value_family", lambda: None)
        assert branding.stat_value_markup("1,234") == "1,234"

    @pytest.mark.parametrize(
        "raw,escaped",
        [
            ("<script>", "&lt;script&gt;"),
            ("R&D", "R&amp;D"),
            ('"quoted"', "&quot;quoted&quot;"),
            ("plain 8,067", "plain 8,067"),
        ],
    )
    def test_arbitrary_text_is_always_escaped(self, raw, escaped):

        markup = branding.stat_value_markup(raw)
        assert escaped in markup
        assert "<script>" not in markup.replace("&lt;script&gt;", "")

    def test_a_resolved_face_wraps_the_text_in_a_span(self):

        try:
            branding.STAT_VALUE_FAMILIES.insert(0, "Sans")
            branding._installed_families.cache_clear()
            markup = branding.stat_value_markup("42")
            assert markup == '<span face="Sans">42</span>'
        finally:
            branding.STAT_VALUE_FAMILIES.remove("Sans")
            branding._installed_families.cache_clear()

    def test_the_span_form_still_escapes_its_content(self):

        try:
            branding.STAT_VALUE_FAMILIES.insert(0, "Sans")
            branding._installed_families.cache_clear()
            markup = branding.stat_value_markup("<b>1</b>")
            assert markup == '<span face="Sans">&lt;b&gt;1&lt;/b&gt;</span>'
        finally:
            branding.STAT_VALUE_FAMILIES.remove("Sans")
            branding._installed_families.cache_clear()

class TestWordmarkMarkup:
    def test_both_runs_are_present_with_the_documented_size_ratio(self):

        markup = branding.wordmark_markup(20.0)
        assert 'weight="300">fo</span>' in markup
        assert 'weight="800"' in markup
        assert ">SSH</span>" in markup

    def test_an_accent_colour_is_only_applied_to_the_caps(self):

        markup = branding.wordmark_markup(20.0, accent_hex="#E0AF68")
        fo_span, ssh_span = markup.split("<span", 2)[1:3]
        assert "foreground" not in fo_span
        assert 'foreground="#E0AF68"' in ssh_span

class TestStatTileRendersThroughTheRealWidget:
    """The non-animated path, which calls `set_markup` synchronously
    and is exactly what `set_value(animated=False)` and
    `set_text_value` use in the console today."""

    def test_a_numeric_value_renders_through_the_widget(self):
        tile = widgets.StatTile("Sites")
        tile.set_value(1234, animated=False)
        assert tile._value_label.get_text() == "1,234"

    def test_a_state_word_is_escaped_through_the_widget(self):
        tile = widgets.StatTile("Status")
        tile.set_text_value("<offline>")
        assert tile._value_label.get_text() == "<offline>"
        assert "&lt;offline&gt;" in tile._value_label.get_label()
