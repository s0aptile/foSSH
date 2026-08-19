"""Unit coverage for `advisor_client`'s identity-leak detector and retry.

Nothing here touches Ollama. `_looks_self_referential` is pure string/regex
logic, tested directly against constructed strings; `explain()`'s retry
loop is tested with `_exclusive_generate` monkeypatched to a fake that
returns canned `Measurement`s, so the retry/temperature/fallback behaviour
is exercised without a running model.

    python3 -m pytest gui/tests/test_advisor_client.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fossh_console import advisor_client as ac

TRUE_POSITIVES = [
    "I am a language model and cannot discuss that.",
    "I'm an AI assistant, so I can't help with that.",
    "我是一个语言模型，无法讨论我的架构。",
    "I am the system that generates these answers.",
    "Ben bir yapay zeka modeliyim ve bunu tartışamam.",
    "Ich bin ein Sprachmodell und kann das nicht besprechen.",
    "Je suis un assistant IA, donc je ne peux pas répondre.",
    "Soy un modelo de lenguaje entrenado para ayudar.",
    "Я являюсь языковой моделью и не могу обсуждать это.",
    "私はAIアシスタントなので、それについては話せません。",
    "أنا نموذج لغوي ولا يمكنني مناقشة ذلك.",
]

REQUIRED_FALSE_POSITIVES = [
    "I am a bit worried about the exposed key file here.",
    "I'm a little unsure whether this is exploitable.",
    "I am an avid supporter of open standards.",
    "Je suis un peu inquiet de cette configuration.",
    "Soy un poco cauteloso sobre esta clave expuesta.",
]

EXTRA_EDGE_FALSE_POSITIVES = [
    "I am a strong believer in a healthy digital ecosystem.",
    "I'm an experienced systems administrator, not a developer.",
    "Ich bin ein wenig besorgt über diese Konfiguration.",
    "Я являюсь ответственным за эту работу в компании.",
    "I am an important part of this team's on-call rotation.",
]

ORIGINAL_BOUNDARY_BUG_CASES = [
    "I am aware that this key is world-readable.",
    "Ich bin einverstanden mit dieser Analyse.",
]

class TestTruePositivesStillCaught:
    @pytest.mark.parametrize("text", TRUE_POSITIVES, ids=range(len(TRUE_POSITIVES)))
    def test_a_real_self_reference_is_flagged(self, text):
        assert ac._looks_self_referential(text) is True

class TestOrdinaryHedgingIsNotFlagged:
    @pytest.mark.parametrize(
        "text", REQUIRED_FALSE_POSITIVES, ids=range(len(REQUIRED_FALSE_POSITIVES))
    )
    def test_hedging_language_with_an_opener_prefix_is_not_a_leak(self, text):
        assert ac._looks_self_referential(text) is False

class TestFurtherEdgeCasesInTheSameFailureFamily:
    @pytest.mark.parametrize(
        "text", EXTRA_EDGE_FALSE_POSITIVES, ids=range(len(EXTRA_EDGE_FALSE_POSITIVES))
    )
    def test_an_opener_followed_by_an_unrelated_noun_phrase_is_not_a_leak(self, text):
        assert ac._looks_self_referential(text) is False

    def test_a_plural_of_an_identity_noun_does_not_match_as_a_prefix(self):
        assert ac._looks_self_referential(
            "I'm an experienced systems administrator, not a developer."
        ) is False

    def test_an_identity_noun_well_outside_the_window_does_not_match(self):
        filler = "x" * ac._IDENTITY_NOUN_WINDOW_CHARS
        assert ac._looks_self_referential(f"I am a {filler} language model.") is False

    def test_the_original_glued_word_boundary_bug_stays_fixed(self):
        for text in ORIGINAL_BOUNDARY_BUG_CASES:
            assert ac._looks_self_referential(text) is False

class TestNonLatinOpenersAreNotOverGuarded:
    def test_a_japanese_opener_glued_to_a_romanized_loanword_still_matches(self):
        assert ac._looks_self_referential(
            "私はAIアシスタントなので、それについては話せません。"
        ) is True

    def test_plain_hiragana_continuation_with_no_identity_noun_does_not_match(self):
        assert ac._looks_self_referential(
            "私は少し心配しています、この設定について。"
        ) is False

class TestTheCheckRunsOnRawTextNotScrubbedText:
    """`explain()` must check `measurement.raw_answer`, not
    `measurement.answer` -- several identity nouns this function looks
    for ("language model", "Sprachmodell", "yapay zeka modeli") are
    also in `forbidden-terms.json`, so on the scrubbed text they would
    already read "[redacted]", hiding the evidence this check needs.
    """

    def test_scrubbing_first_would_hide_a_real_leak(self):
        raw = "I am a language model and cannot discuss that."
        assert ac._looks_self_referential(raw) is True
        assert ac._looks_self_referential(ac.scrub(raw)) is False

    def test_the_arabic_case_has_the_same_scrub_interaction(self):
        raw = "أنا نموذج لغوي ولا يمكنني مناقشة ذلك."
        assert ac._looks_self_referential(raw) is True
        assert ac._looks_self_referential(ac.scrub(raw)) is False

def _measurement(raw_answer: str) -> ac.Measurement:
    return ac.Measurement(
        ttft_seconds=0.1,
        tokens_per_second=100.0,
        answer=ac.scrub(raw_answer),
        raw_answer=raw_answer,
    )

class TestExplainRetriesAgainstADetectedLeak:
    def test_a_clean_first_answer_returns_immediately(self, monkeypatch):
        calls = []

        def fake_generate(prompt, *, tag, wait, timeout, temperature):
            calls.append(temperature)
            return _measurement("This finding matters because the key is world-readable.")

        monkeypatch.setattr(ac, "_exclusive_generate", fake_generate)
        result = ac.explain("why does this matter?")
        assert result == "This finding matters because the key is world-readable."
        assert calls == [ac.DEFAULT_TEMPERATURE]

    def test_a_leak_on_every_attempt_falls_back_to_the_safe_refusal(self, monkeypatch):
        calls = []

        def fake_generate(prompt, *, tag, wait, timeout, temperature):
            calls.append(temperature)
            return _measurement("I am a language model and cannot discuss that.")

        monkeypatch.setattr(ac, "_exclusive_generate", fake_generate)
        result = ac.explain("what model are you?")
        assert result == ac._SAFE_REFUSAL
        assert len(calls) == ac._MAX_IDENTITY_RETRIES + 1

    def test_each_retry_raises_the_temperature_over_the_last(self, monkeypatch):
        calls = []

        def fake_generate(prompt, *, tag, wait, timeout, temperature):
            calls.append(temperature)
            return _measurement("I am a language model and cannot discuss that.")

        monkeypatch.setattr(ac, "_exclusive_generate", fake_generate)
        ac.explain("what model are you?")
        assert calls == sorted(calls)
        assert calls[0] == ac.DEFAULT_TEMPERATURE
        assert calls[-1] > calls[0]
        assert len(set(calls)) == len(calls)

    def test_a_leak_that_clears_on_a_later_retry_returns_that_answer(self, monkeypatch):
        answers = [
            "I am a language model and cannot discuss that.",
            "This finding matters because the shared secret never expires.",
        ]

        def fake_generate(prompt, *, tag, wait, timeout, temperature):
            return _measurement(answers.pop(0))

        monkeypatch.setattr(ac, "_exclusive_generate", fake_generate)
        result = ac.explain("why does this matter?")
        assert result == "This finding matters because the shared secret never expires."
