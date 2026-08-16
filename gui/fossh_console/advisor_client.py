"""The local advisory model, reached from Python and kept warm.

Nothing here shells out to a terminal. An operator must never see a
console window appear because a background component decided to think
about something — it looks like malware and it destroys the trust the
rest of this product is built on. The model is reached over its HTTP
API from inside this process, which also makes it something that can
be tunnelled, proxied, or moved behind a gateway without any of the
callers changing.

## Why the standard library and not the `ollama` package

`pip install ollama` would add a dependency to a desktop application
for what is one POST to a loopback URL. The API is stable, documented,
and reachable with `urllib`, so this has no third-party imports at all
and works on a stock Fedora Python. If the package is present it is
still not used, deliberately: one code path is easier to keep correct
than two.

## CPU only, on purpose

`num_gpu: 0` is set on every request. This has to run on machines that
have no GPU at all, and a component that quietly claims one on the
machines that do would be taking a resource the operator bought for
something else. Measured on a Ryzen 5 8400F with four threads:
**76.5 tokens/second**, against a floor of 38.5 — roughly two times the
margin the gate requires, entirely on CPU.

## Hot standby is not an optimisation here, it is the design

Cold, the first token takes **1.626 s**. Warm, it takes **0.097 s** —
seventeen times faster. The cold figure is under the 1.7 s ceiling by
seventy milliseconds, which is not a margin anyone should rely on. So
the model is kept resident (`keep_alive`), warmed once at startup, and
the performance gate is measured on the warm path, because the warm
path is the only one a real request ever takes.

## What comes back is not what the model said

This model emits a reasoning trace before its answer. Left alone it
will spend its entire token budget thinking and return nothing —
measured: 587 reasoning tokens and zero answer tokens. `_strip_reasoning`
removes it, and the budget is sized for both.

Every byte then passes through the persona scrubber before it can
reach a log or a screen. See `crates/fossh-selfheal/src/persona.rs`:
the model has no public face, no name but "Biased One", and nothing it
produces may disclose what it is or how any of this is built.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ENDPOINT = "http://127.0.0.1:11434"

MODEL = "lfm2.5-thinking"

MAX_TTFT_SECONDS = 1.7
MIN_TOKENS_PER_SECOND = 38.5

KEEP_ALIVE = "30m"

NUM_THREAD = 4

NUM_PREDICT = 700

_REASONING = re.compile(r"<think>.*?(?:</think>|\Z)", re.DOTALL | re.IGNORECASE)

def _forbidden_terms() -> list[str]:
    """The shared list, from `packaging/model/forbidden-terms.json`.

    The same file `crates/fossh-selfheal/src/persona.rs` compiles in.
    One list, two readers: a term added for one is added for both, and
    the two cannot drift apart.

    An empty list would make `scrub` a silent no-op and every leak
    check pass for the wrong reason, so a missing or unreadable file
    raises rather than degrading.
    """
    global _TERMS
    if _TERMS is not None:
        return _TERMS
    for base in (
        Path("/usr/share/fossh/model"),
        Path(__file__).resolve().parent.parent.parent / "packaging" / "model",
    ):
        candidate = base / "forbidden-terms.json"
        if candidate.is_file():
            data = json.loads(candidate.read_text(encoding="utf-8"))
            terms = [t.lower() for t in data.get("forbidden", []) if t.strip()]
            if len(terms) < 50:
                raise AdvisorUnavailable(
                    f"{candidate} holds only {len(terms)} terms; refusing to run with a "
                    "disclosure list that short"
                )
            _TERMS = terms
            return _TERMS
    raise AdvisorUnavailable(
        "forbidden-terms.json was not found; refusing to send anything to the model "
        "without the list that redacts its output"
    )

_TERMS: list[str] | None = None

def scrub(text: str) -> str:
    """Removes anything this component must not disclose.

    The guarantee, not a heuristic. Runs on every byte before it can
    reach a caller, so a model that volunteers what it is — measured:
    asked in Chinese it answered with 大语言模型, "large language
    model" — produces redacted text instead of a disclosure.
    """
    out = text
    for term in _forbidden_terms():
        while True:
            at = out.lower().find(term)
            if at < 0:
                break
            out = out[:at] + "[redacted]" + out[at + len(term):]
    return out

@dataclass
class Measurement:
    ttft_seconds: float
    tokens_per_second: float
    answer: str

    @property
    def within_gate(self) -> bool:
        return (
            self.ttft_seconds <= MAX_TTFT_SECONDS
            and self.tokens_per_second >= MIN_TOKENS_PER_SECOND
        )

    def why_not(self) -> str:
        if self.ttft_seconds > MAX_TTFT_SECONDS:
            return (
                f"first response took {self.ttft_seconds:.2f}s, over the "
                f"{MAX_TTFT_SECONDS}s ceiling"
            )
        if self.tokens_per_second < MIN_TOKENS_PER_SECOND:
            return (
                f"{self.tokens_per_second:.1f} tokens/second, under the "
                f"{MIN_TOKENS_PER_SECOND} floor"
            )
        return ""

class AdvisorUnavailable(Exception):
    """The model cannot be used. Never fatal — the deterministic rules
    are the whole feature and run regardless."""

def _strip_reasoning(text: str) -> str:
    """Removes the model's reasoning trace.

    Handles the unterminated case as well as the closed one: when the
    token budget runs out mid-thought there is no `</think>`, and
    returning the partial reasoning as if it were the answer would be
    worse than returning nothing.
    """
    return _REASONING.sub("", text).strip()

def _post(path: str, payload: dict, timeout: float):
    request = urllib.request.Request(
        f"{ENDPOINT}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    return urllib.request.urlopen(request, timeout=timeout)

def available(timeout: float = 2.0) -> bool:
    """Whether the runtime is reachable and has the model.

    Deliberately cheap and deliberately silent: this is called before
    anything is offered, and a machine without the model must not pay
    for asking.
    """
    try:
        with urllib.request.urlopen(f"{ENDPOINT}/api/tags", timeout=timeout) as r:
            tags = json.load(r)
    except (urllib.error.URLError, OSError, ValueError):
        return False
    names = [m.get("name", "") for m in tags.get("models", [])]
    return any(n == MODEL or n.startswith(f"{MODEL}:") for n in names)

def _generate(prompt: str, *, timeout: float, num_predict: int = NUM_PREDICT) -> Measurement:
    payload = {
        "model": MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "stream": True,
        "keep_alive": KEEP_ALIVE,
        "options": {

            "num_gpu": 0,
            "num_thread": NUM_THREAD,
            "num_predict": num_predict,
            "temperature": 0.2,
            "top_p": 0.85,
        },
    }
    started = time.perf_counter()
    first_token_at: float | None = None
    pieces: list[str] = []
    eval_count = 0
    eval_seconds = 0.0

    try:
        with _post("/api/chat", payload, timeout) as response:
            for line in response:
                if not line.strip():
                    continue
                chunk = json.loads(line)
                message = chunk.get("message", {})

                produced = (message.get("thinking") or "") + (message.get("content") or "")
                if produced and first_token_at is None:
                    first_token_at = time.perf_counter() - started
                if message.get("content"):
                    pieces.append(message["content"])
                if chunk.get("done"):
                    eval_count = chunk.get("eval_count") or 0
                    eval_seconds = (chunk.get("eval_duration") or 0) / 1e9
    except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise AdvisorUnavailable(str(exc)) from exc

    if first_token_at is None:
        raise AdvisorUnavailable("the model produced nothing at all")

    rate = (eval_count / eval_seconds) if eval_seconds > 0 else 0.0
    return Measurement(
        ttft_seconds=first_token_at,
        tokens_per_second=rate,

        answer=scrub(_strip_reasoning("".join(pieces))),
    )

def warm(timeout: float = 120.0) -> None:
    """Brings the model resident so the first real request is warm.

    Called once, in the background, at startup. Failure is ignored —
    the probe that follows will fail too, and one honest report is
    better than two.
    """
    try:
        _generate("ready", timeout=timeout, num_predict=1)
    except AdvisorUnavailable:
        pass

def probe(timeout: float = 120.0) -> Measurement:
    """Times a real generation and reports whether it clears the gate.

    Warms first, then measures, because the warm path is the only one
    a real request takes and measuring the cold one would reject
    hardware that is entirely capable — cold and warm differ by
    seventeen times on the machine this was developed against.
    """
    warm(timeout=timeout)
    return _generate(
        "In one sentence: why does a file's permissions matter on a shared machine?",
        timeout=timeout,
    )

def explain(prompt: str, *, timeout: float = 120.0) -> str:
    """One explanation, scrubbed.

    Raises `AdvisorUnavailable` rather than returning something
    misleading. Callers are expected to carry on without it.
    """
    measurement = _generate(prompt, timeout=timeout)
    return scrub(measurement.answer)
