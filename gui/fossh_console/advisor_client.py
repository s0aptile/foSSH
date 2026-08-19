from __future__ import annotations

import base64
import fcntl
import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ENDPOINT = os.environ.get("FOSSH_MODEL_ENDPOINT", "http://127.0.0.1:11435")

MODEL_SECRET_PATH = Path(
    os.environ.get("FOSSH_MODEL_SECRET_FILE", "/etc/fossh-model/model-access-secret")
)

REVISION = "0.0.2.2"

ADVISOR = f"fossh-advisor:{REVISION}"
WITNESS = f"fossh-witness:{REVISION}"

ADVISOR_BASE = "lfm2.5-thinking"
WITNESS_BASE = "qwen3.5:4b"

MAX_TTFT_SECONDS = 1.7
MIN_TOKENS_PER_SECOND = 38.5

MAX_TOTAL_SECONDS = 3.0

VISION_TTFT_CEILING_SECONDS = 90.0

KEEP_ALIVE = "30m"
NUM_THREAD = 4
NUM_PREDICT = 2048
WITNESS_NUM_PREDICT = 2048

VISION_MAX_EDGE = (1280, 720)

LOCK_PATH = Path(os.environ.get("FOSSH_RUNTIME_DIR", "/run/fossh-selfheal")) / "advisor.model.lock"
LOCK_FALLBACK = Path.home() / ".cache" / "fossh" / "advisor.model.lock"

ADVISOR_LOCK_WAIT_SECONDS = 2.0

_REASONING = re.compile(r"<think>.*?(?:</think>|\Z)", re.DOTALL | re.IGNORECASE)

_TERMS: list[str] | None = None

class AdvisorUnavailable(Exception):
    pass

class ModelBusy(AdvisorUnavailable):
    pass

def _forbidden_terms() -> list[str]:
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

def scrub(text: str) -> str:
    out = text
    for term in _forbidden_terms():
        while True:
            at = out.lower().find(term)
            if at < 0:
                break
            out = out[:at] + "[redacted]" + out[at + len(term):]
    return out

def exclusivity_is_shared() -> bool:
    parent = LOCK_PATH.parent
    return parent.is_dir() and os.access(parent, os.W_OK)

def _lock_path() -> Path:
    if exclusivity_is_shared():
        return LOCK_PATH
    LOCK_FALLBACK.parent.mkdir(parents=True, exist_ok=True)
    return LOCK_FALLBACK

class _Exclusive:
    def __init__(self, wait_seconds: float, *, shared_required: bool = False) -> None:
        self._wait = wait_seconds
        self._shared_required = shared_required
        self._fh = None

    def __enter__(self):
        if self._shared_required and not exclusivity_is_shared():
            raise ModelBusy(
                f"{LOCK_PATH.parent} is not writable by this process, so a lock taken "
                "here would not exclude one taken by a process running as another "
                "user; refusing to start a second model rather than relying on a "
                "guarantee that is not in force"
            )
        path = _lock_path()
        fh = open(path, "a+")
        deadline = time.monotonic() + self._wait
        while True:
            try:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                self._fh = fh
                return self
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    fh.close()
                    raise ModelBusy(
                        "another generation holds the model lock; "
                        "declining rather than queueing behind it"
                    )
                time.sleep(0.05)
            except OSError:
                fh.close()
                raise

    def __exit__(self, *exc):
        if self._fh is not None:
            try:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            finally:
                self._fh.close()
                self._fh = None
        return False

@dataclass
class Measurement:
    ttft_seconds: float
    tokens_per_second: float
    answer: str
    ceiling_seconds: float = MAX_TTFT_SECONDS
    total_seconds: float = 0.0
    total_ceiling_seconds: float = MAX_TOTAL_SECONDS

    @property
    def within_gate(self) -> bool:
        return (
            self.ttft_seconds <= self.ceiling_seconds
            and self.tokens_per_second >= MIN_TOKENS_PER_SECOND
            and self.total_seconds <= self.total_ceiling_seconds
        )

    def why_not(self) -> str:
        if self.ttft_seconds > self.ceiling_seconds:
            return (
                f"first response took {self.ttft_seconds:.2f}s, over the "
                f"{self.ceiling_seconds}s ceiling"
            )
        if self.tokens_per_second < MIN_TOKENS_PER_SECOND:
            return (
                f"{self.tokens_per_second:.1f} tokens/second, under the "
                f"{MIN_TOKENS_PER_SECOND} floor"
            )
        if self.total_seconds > self.total_ceiling_seconds:
            return (
                f"the whole answer took {self.total_seconds:.2f}s, over the "
                f"{self.total_ceiling_seconds}s ceiling — throughput and first-token "
                "latency both passed, but a long reasoning trace still kept the "
                "operator waiting"
            )
        return ""

def _strip_reasoning(text: str) -> str:
    return _REASONING.sub("", text).strip()

def _gateway_headers() -> dict[str, str]:
    """The header fossh-model.conf's Apache gateway requires.

    Ollama's own bind stops the network reaching it; it does nothing
    about another local account on this machine reaching it directly.
    The gateway (packaging/apache/fossh-model.conf, port 11435) is what
    actually closes that, and it has always required this header — the
    console simply never sent it, which left the gateway installed and
    the secret generated with nothing on this side ever presenting it.
    Read fresh every call rather than cached: a rotated secret must
    take effect on the next request, not after a restart.
    """
    try:
        secret = MODEL_SECRET_PATH.read_text().strip()
    except OSError:
        return {}
    if not secret:
        return {}
    return {"X-foSSH-Model-Key": secret}

def _post(path: str, payload: dict, timeout: float):
    request = urllib.request.Request(
        f"{ENDPOINT}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **_gateway_headers()},
    )
    return urllib.request.urlopen(request, timeout=timeout)

def installed_tags(timeout: float = 2.0) -> list[str]:
    try:
        request = urllib.request.Request(f"{ENDPOINT}/api/tags", headers=_gateway_headers())
        with urllib.request.urlopen(request, timeout=timeout) as r:
            tags = json.load(r)
    except (urllib.error.URLError, OSError, ValueError):
        return []
    return [m.get("name", "") for m in tags.get("models", [])]

def resident_tags(timeout: float = 2.0) -> list[str]:
    try:
        request = urllib.request.Request(f"{ENDPOINT}/api/ps", headers=_gateway_headers())
        with urllib.request.urlopen(request, timeout=timeout) as r:
            ps = json.load(r)
    except (urllib.error.URLError, OSError, ValueError):
        return []
    return [m.get("name", "") for m in ps.get("models", [])]

def has_tag(tag: str, timeout: float = 2.0) -> bool:
    names = installed_tags(timeout=timeout)
    return any(n == tag or n.startswith(f"{tag}:") for n in names)

def available(timeout: float = 2.0) -> bool:
    return has_tag(ADVISOR, timeout=timeout)

def unload(tag: str, timeout: float = 30.0) -> bool:
    try:
        with _post("/api/generate", {"model": tag, "keep_alive": 0}, timeout) as r:
            body = json.loads(r.read().decode("utf-8") or "{}")
    except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError):
        return False
    return body.get("done_reason") == "unload"

def encode_image(path: str | Path) -> str:
    try:
        from PIL import Image
    except ImportError as exc:
        raise AdvisorUnavailable(
            "Pillow is required to read a screenshot. A full-resolution image is not "
            "sent unscaled as a fallback: measured, 1920x1080 costs 3.1 times what "
            "1280x720 costs and returns the same answer, and the runtime's own "
            "1024-token floor means anything smaller than 1280x720 costs the same "
            "again. Sending the original would be slower for no benefit"
        ) from exc

    import io

    with Image.open(path) as img:
        img = img.convert("RGB")
        img.thumbnail(VISION_MAX_EDGE)
        buf = io.BytesIO()
        img.save(buf, format="PNG", optimize=True)
    return base64.b64encode(buf.getvalue()).decode("ascii")

def _generate(
    prompt: str,
    *,
    tag: str,
    timeout: float,
    num_predict: int = NUM_PREDICT,
    images: list[str] | None = None,
    ceiling: float = MAX_TTFT_SECONDS,
    total_ceiling: float = MAX_TOTAL_SECONDS,
    think: bool | None = None,
) -> Measurement:
    message: dict = {"role": "user", "content": prompt}
    if images:
        message["images"] = images

    payload = {
        "model": tag,
        "messages": [message],
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
    if think is not None:
        payload["think"] = think
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
                msg = chunk.get("message", {})
                if msg.get("content"):
                    if first_token_at is None:
                        first_token_at = time.perf_counter() - started
                    pieces.append(msg["content"])
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
        ceiling_seconds=ceiling,
        total_seconds=time.perf_counter() - started,
        total_ceiling_seconds=total_ceiling,
    )

WITNESS_MIN_PHYSICAL_CORES = 6
WITNESS_MIN_RAM_BYTES = 16 * 1024 * 1024 * 1024

def _physical_cores() -> int:
    try:
        ids = set()
        current: dict[str, str] = {}
        for raw in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if not raw.strip():
                if current:
                    ids.add((current.get("physical id", "0"), current.get("core id", "0")))
                current = {}
                continue
            key, _, value = raw.partition(":")
            current[key.strip()] = value.strip()
        if current:
            ids.add((current.get("physical id", "0"), current.get("core id", "0")))
        return len(ids) or (os.cpu_count() or 1)
    except OSError:
        return os.cpu_count() or 1

def _ram_bytes() -> int:
    try:
        for raw in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if raw.startswith("MemTotal:"):
                return int(raw.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return 0

def _has_avx512() -> bool:
    try:
        text = Path("/proc/cpuinfo").read_text(encoding="utf-8")
    except OSError:
        return False
    return " avx512f" in text or "\tavx512f" in text

def witness_hardware_ok() -> bool:
    return (
        _physical_cores() >= WITNESS_MIN_PHYSICAL_CORES
        and _ram_bytes() >= WITNESS_MIN_RAM_BYTES
        and _has_avx512()
    )

def witness_available(timeout: float = 2.0) -> bool:
    return (
        witness_hardware_ok()
        and exclusivity_is_shared()
        and has_tag(WITNESS, timeout=timeout)
    )

def _require_witness() -> None:
    if not witness_hardware_ok():
        raise AdvisorUnavailable(
            f"this machine does not meet the bar for a second model: "
            f"{_physical_cores()} physical cores and "
            f"{_ram_bytes() // (1024 ** 3)} GiB, against a floor of "
            f"{WITNESS_MIN_PHYSICAL_CORES} cores, "
            f"{WITNESS_MIN_RAM_BYTES // (1024 ** 3)} GiB and AVX-512"
        )

def _exclusive_generate(
    prompt: str, *, tag: str, wait: float, shared_required: bool = False, **kw
) -> Measurement:
    with _Exclusive(wait, shared_required=shared_required):
        for other in resident_tags():
            if other != tag and other.split(":")[0] in (
                ADVISOR.split(":")[0],
                WITNESS.split(":")[0],
                ADVISOR_BASE,
                WITNESS_BASE.split(":")[0],
            ):
                unload(other)
        return _generate(prompt, tag=tag, **kw)

def warm(tag: str = ADVISOR, timeout: float = 120.0) -> None:
    try:
        _exclusive_generate(
            "ready", tag=tag, wait=ADVISOR_LOCK_WAIT_SECONDS, timeout=timeout, num_predict=1
        )
    except AdvisorUnavailable:
        pass

def probe(tag: str = ADVISOR, timeout: float = 120.0) -> Measurement:
    warm(tag=tag, timeout=timeout)
    return _exclusive_generate(
        "In one sentence: why does a file's permissions matter on a shared machine?",
        tag=tag,
        wait=ADVISOR_LOCK_WAIT_SECONDS,
        timeout=timeout,
    )

_SELF_REFERENTIAL_OPENERS = (
    "i am a", "i am an", "i'm a", "i'm an", "i am the",
    "ben bir",
    "ich bin ein", "ich bin eine",
    "je suis un", "je suis une",
    "soy un", "soy una",
    "я являюсь", "я — ", "я -",
    "我是",
    "私は", "僕は",
    "أنا ",
)

_SELF_REFERENTIAL_PATTERN = re.compile(
    "(?:" + "|".join(re.escape(o) for o in _SELF_REFERENTIAL_OPENERS) + r")(?![a-z])"
)

_MAX_IDENTITY_RETRIES = 2

_SAFE_REFUSAL = "I can't discuss that."

def _looks_self_referential(text: str) -> bool:
    """Whether `text` opens by describing what the model is.

    Narrow and specific to the one shape every identity leak measured
    this session shared: a self-referential opening ("I am a...",
    "我是...", and the equivalent in each of the battery's languages),
    checked only in the first 24 characters. This is not a restatement
    of forbidden-terms.json's broader vendor/architecture list — that
    list keeps matching and redacting mid-sentence disclosures exactly
    as before; this catches the one shape it cannot, because a generic
    "I am an AI" opener names no vendor term for scrub() to find.

    The trailing `(?![a-z])` matters: without it, "i am a" also matches
    inside "I am aware..." and "ich bin ein" inside "Ich bin
    einverstanden...", turning ordinary diagnostic phrasing into a
    false leak. CJK/Arabic/Cyrillic openers are unaffected either way,
    since their scripts never fall in `[a-z]`.
    """
    head = text.strip().lower()[:24]
    return _SELF_REFERENTIAL_PATTERN.search(head) is not None

def explain(prompt: str, *, timeout: float = 120.0) -> str:
    """Explains a finding, with a bounded retry against self-disclosure.

    Two layers on top of the model's own SYSTEM-level fence: scrub()
    redacts a matched vendor/architecture term after generation, and
    this retries generation, then falls back to a fixed refusal,
    against the one leak shape scrub() cannot see — a generic
    self-referential opening with no term to match. A retry has real
    odds of succeeding cleanly, since a leak here has been measured as
    a low-probability sample, not a deterministic failure; the fixed
    refusal after two retries is what makes the property structural
    rather than probabilistic — the worst case a caller ever sees is
    this fallback, never an actual disclosure.
    """
    answer = _SAFE_REFUSAL
    for _ in range(_MAX_IDENTITY_RETRIES + 1):
        measurement = _exclusive_generate(
            prompt, tag=ADVISOR, wait=ADVISOR_LOCK_WAIT_SECONDS, timeout=timeout
        )
        answer = scrub(measurement.answer)
        if not _looks_self_referential(answer):
            return answer
    return _SAFE_REFUSAL

def crosscheck(claim: str, *, timeout: float = 120.0) -> str:
    _require_witness()
    prompt = (
        "You are checking another component's explanation of a system diagnostic. "
        "Reply with AGREE or DISAGREE on the first line, then at most two sentences "
        "saying why. Do not restate the explanation.\n\n"
        f"Explanation to check:\n{claim}"
    )
    measurement = _exclusive_generate(
        prompt,
        tag=WITNESS,
        wait=0.0,
        shared_required=True,
        timeout=timeout,
        num_predict=WITNESS_NUM_PREDICT,
        total_ceiling=float("inf"),
        think=False,
    )
    return scrub(measurement.answer)

def read_screenshot(image_path: str | Path, question: str, *, timeout: float = 300.0) -> Measurement:
    _require_witness()
    return _exclusive_generate(
        question,
        tag=WITNESS,
        wait=0.0,
        shared_required=True,
        timeout=timeout,
        num_predict=WITNESS_NUM_PREDICT,
        images=[encode_image(image_path)],
        ceiling=VISION_TTFT_CEILING_SECONDS,
        total_ceiling=float("inf"),
        think=False,
    )
