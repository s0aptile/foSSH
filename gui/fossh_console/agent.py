"""The console's half of the `fossh-agent` bridge protocol.

One `fossh-agent` child process, one JSON object per line in each
direction over its stdin/stdout. See `crates/fossh-agent/src/protocol.rs`
for the wire types and ADR-0061 for why the protocol logic lives in Rust
rather than being reimplemented here.

## Threading

GTK has exactly one thread that may touch widgets, and several agent
calls genuinely block for seconds — a QUIC status query against an
absent watchdog waits out its timeout, `gpg --quick-generate-key` waits
on entropy and can take longer still. Doing either on the main loop
freezes the window, which is the single most visible way a desktop app
can feel broken.

So: one dedicated I/O thread owns both pipes and services a queue,
strictly one request at a time (which is also exactly how the agent
itself behaves — it is a serial read/dispatch/write loop, so pipelining
would buy nothing). Results come back to the main loop through
`GLib.idle_add`, which is the one documented-safe way to cross that
boundary. No widget is ever touched from the I/O thread.
"""

from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Callable

from gi.repository import GLib

#: Bumped in lockstep with `PROTOCOL_VERSION` in the Rust side. A
#: mismatch means a half-upgraded install — a console from the new RPM
#: against an agent still on disk from the old one — and is reported
#: rather than guessed at, because the alternative is a missing field
#: surfacing much later as an unrelated-looking crash.
PROTOCOL_VERSION = 1

#: A ceiling on any single call. Every agent operation has its own,
#: tighter internal timeout; this exists only so that a wedged child can
#: never strand the queue permanently.
DEFAULT_TIMEOUT_SECONDS = 90.0


class AgentError(Exception):
    """A structured failure from the agent, or from reaching it.

    `code` is one of the closed set the Rust side defines
    (`bad_request`, `not_found`, `unavailable`, `denied`, `conflict`,
    `internal`), plus `transport` for a failure that never got a reply.
    Views branch on it; only `message` is shown to a person.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    @property
    def is_unavailable(self) -> bool:
        """Something that is a *state*, not a fault.

        A watchdog that is not running, a build without QUIC support, a
        database that does not exist yet. The console explains these
        calmly instead of showing them as errors.
        """
        return self.code in ("unavailable", "transport")


def find_agent_binary() -> Path | None:
    """Where `fossh-agent` is, in the order worth trying.

    An explicit override first, then the packaged location, then the
    two Cargo output directories — so a checkout runs against a freshly
    built agent without anyone having to install anything first.
    """
    override = os.environ.get("FOSSH_AGENT_BIN")
    if override:
        candidate = Path(override)
        return candidate if candidate.exists() else None

    packaged = Path("/usr/libexec/fossh/fossh-agent")
    if packaged.exists():
        return packaged

    # gui/fossh_console/agent.py -> gui/fossh_console -> gui -> repo root
    repo_root = Path(__file__).resolve().parent.parent.parent
    for profile in ("release", "debug"):
        candidate = repo_root / "target" / profile / "fossh-agent"
        if candidate.exists():
            return candidate

    found = shutil.which("fossh-agent")
    return Path(found) if found else None


class _Call:
    __slots__ = ("request_id", "line", "on_ok", "on_err", "timeout")

    def __init__(self, request_id, line, on_ok, on_err, timeout):
        self.request_id = request_id
        self.line = line
        self.on_ok = on_ok
        self.on_err = on_err
        self.timeout = timeout


class Agent:
    """A running `fossh-agent` child, and the queue in front of it."""

    def __init__(self, binary: Path | None = None, env: dict[str, str] | None = None) -> None:
        self._binary = binary or find_agent_binary()
        self._env_overrides = env or {}
        self._process: subprocess.Popen | None = None
        self._queue: queue.Queue[_Call | None] = queue.Queue()
        self._thread: threading.Thread | None = None
        self._next_id = 1
        self._id_lock = threading.Lock()
        self._stopping = threading.Event()
        self.info: dict[str, Any] = {}

    # -- lifecycle ---------------------------------------------------

    def start(self) -> None:
        """Spawns the child and starts the I/O thread.

        Raises `AgentError` if the binary is missing or will not run;
        the window turns that into a status page naming the binary,
        rather than an empty broken-looking window.
        """
        if self._binary is None:
            raise AgentError(
                "transport",
                "The fossh-agent helper could not be found. It ships with the fossh package "
                "at /usr/libexec/fossh/fossh-agent; in a source checkout, build it first with "
                "`cargo build --release -p fossh-agent`.",
            )

        env = os.environ.copy()
        env.update(self._env_overrides)

        try:
            self._process = subprocess.Popen(
                [str(self._binary)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                # Left attached to the console's own stderr on purpose:
                # under a desktop session that is the journal, which is
                # where a diagnostic belongs. It is never parsed.
                stderr=None,
                env=env,
                # Text mode with an explicit encoding rather than the
                # locale's: the protocol is UTF-8 by definition, and a
                # non-UTF-8 locale must not change how it is decoded.
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
        except OSError as exc:
            raise AgentError("transport", f"Could not start {self._binary}: {exc}") from exc

        self._thread = threading.Thread(target=self._io_loop, name="fossh-agent-io", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Ends the session and reaps the child.

        Closing stdin is the agent's documented shutdown signal — its
        read loop returns EOF and it exits successfully — so this is a
        clean stop rather than a kill, with a kill only as the fallback
        for a child that ignores it.
        """
        if self._stopping.is_set():
            return
        self._stopping.set()
        self._queue.put(None)

        process, self._process = self._process, None
        if process is None:
            return
        try:
            if process.stdin:
                process.stdin.close()
        except OSError:
            pass
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass

    @property
    def binary_path(self) -> Path | None:
        return self._binary

    # -- calling -----------------------------------------------------

    def call(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        on_ok: Callable[[dict[str, Any]], None] | None = None,
        on_err: Callable[[AgentError], None] | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        """Queues a call. Both callbacks run on the GTK main loop."""
        if self._stopping.is_set() or self._process is None:
            if on_err:
                GLib.idle_add(
                    on_err, AgentError("transport", "The helper process is not running.")
                )
            return

        with self._id_lock:
            request_id = self._next_id
            self._next_id += 1

        line = json.dumps(
            {"id": request_id, "method": method, "params": params or {}},
            # The agent caps a request line at 1 MiB and treats crossing
            # it as fatal, so the console must not emit a needlessly
            # large frame: no indentation, no spaces.
            separators=(",", ":"),
            ensure_ascii=False,
        )
        self._queue.put(_Call(request_id, line, on_ok, on_err, timeout))

    def handshake(
        self,
        *,
        on_ok: Callable[[dict[str, Any]], None],
        on_err: Callable[[AgentError], None],
    ) -> None:
        """`agent.hello`, with the version check applied to the result."""

        def _check(result: dict[str, Any]) -> None:
            their_version = result.get("protocol")
            if their_version != PROTOCOL_VERSION:
                on_err(
                    AgentError(
                        "internal",
                        f"This console speaks agent protocol {PROTOCOL_VERSION}, but "
                        f"{self._binary} speaks {their_version}. They come from the same "
                        "package, so this usually means an interrupted upgrade — reinstall "
                        "fossh, or restart the console if the upgrade has since finished.",
                    )
                )
                return
            self.info = result
            on_ok(result)

        self.call("agent.hello", on_ok=_check, on_err=on_err)

    # -- the I/O thread ----------------------------------------------

    def _io_loop(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                return
            try:
                self._serve(item)
            except Exception as exc:  # noqa: BLE001 - the thread must not die
                self._fail(item, AgentError("transport", f"Talking to the helper failed: {exc}"))

    def _serve(self, call: _Call) -> None:
        process = self._process
        if process is None or process.stdin is None or process.stdout is None:
            self._fail(call, AgentError("transport", "The helper process is not running."))
            return

        try:
            process.stdin.write(call.line + "\n")
            process.stdin.flush()
        except (BrokenPipeError, OSError):
            self._fail(call, self._death_error(process))
            return

        # A blocking readline, bounded by a watchdog timer that kills
        # the child if it never answers. Without the timer a wedged
        # agent would strand this thread — and therefore every later
        # call — with no way out.
        timer = threading.Timer(call.timeout, self._kill_wedged_child)
        timer.daemon = True
        timer.start()
        try:
            raw = process.stdout.readline()
        except OSError:
            raw = ""
        finally:
            timer.cancel()

        if not raw:
            self._fail(call, self._death_error(process))
            return

        try:
            frame = json.loads(raw)
        except json.JSONDecodeError:
            self._fail(
                call,
                AgentError(
                    "internal",
                    "The helper sent something that is not a valid response frame.",
                ),
            )
            return

        frame_id = frame.get("id")
        if frame_id != call.request_id:
            # The agent answers serially, so the only frame that can
            # arrive here is the answer to this request. An id of 0 is
            # its documented "I could not parse what you sent", which
            # is a console bug worth surfacing rather than retrying.
            if frame_id == 0:
                message = frame.get("error", {}).get(
                    "message", "the helper could not parse that request"
                )
                self._fail(call, AgentError("bad_request", message))
                return
            self._fail(
                call,
                AgentError(
                    "internal",
                    f"The helper answered request {frame_id} while {call.request_id} was "
                    "outstanding; the connection is out of step.",
                ),
            )
            return

        if frame.get("ok"):
            result = frame.get("result") or {}
            if call.on_ok:
                GLib.idle_add(call.on_ok, result)
            return

        error = frame.get("error") or {}
        self._fail(
            call,
            AgentError(
                error.get("code", "internal"),
                error.get("message", "The helper reported a failure with no detail."),
            ),
        )

    def _death_error(self, process: subprocess.Popen) -> AgentError:
        code = process.poll()
        if code is None:
            return AgentError("transport", "The helper stopped responding.")
        return AgentError(
            "transport",
            f"The helper exited (status {code}). Its own diagnostics are in the journal: "
            "`journalctl --user -t fossh-console`.",
        )

    def _kill_wedged_child(self) -> None:
        process = self._process
        if process is not None and process.poll() is None:
            print(
                f"fossh-console: the agent did not answer within "
                f"{DEFAULT_TIMEOUT_SECONDS:.0f}s; terminating it",
                file=sys.stderr,
            )
            process.kill()

    def _fail(self, call: _Call, error: AgentError) -> None:
        if call.on_err:
            GLib.idle_add(call.on_err, error)
