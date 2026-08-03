(* §3.3 responsibility 1: restart foSSH core on crash. "Core" here
   means `fossh-fcgi` specifically — the one persistent, long-running
   process in this architecture. `fossh-cgi` is spawned fresh per
   request by fcgiwrap and has no persistent instance for a supervisor
   to watch or restart. *)

type restart_policy = { max_restarts : int; window_seconds : float }

(* Not asked for explicitly by §3.3, but "restart on crash" with no
   bound at all turns one crash-looping binary into a self-inflicted
   denial-of-service (and a log-flooding one). A conservative sliding
   window cap is applied and documented here rather than silently
   restarting forever. *)
let default_policy = { max_restarts = 5; window_seconds = 60.0 }

type t = {
  program : string;
  args : string array;
  mutable child_pid : int option;
  mutable restart_times : float list;
  policy : restart_policy;
  (* §3.4: set by `request_termination` right before it signals the
     currently-tracked child, consumed (read-and-reset) exactly once
     by the main supervision loop's own next `wait_for_exit` — see
     `take_requested_termination` and both below for why this exists
     at all: a verified restart/reload command must not be treated as
     an unplanned crash by the same crash-storm accounting a genuine
     crash loop needs. *)
  mutable termination_was_requested : bool;
}

let create ?(policy = default_policy) ~(program : string) (args : string array)
    : t =
  { program; args; child_pid = None; restart_times = []; policy; termination_was_requested = false }

let spawn (t : t) : int =
  let pid = Unix.create_process t.program t.args Unix.stdin Unix.stdout Unix.stderr in
  t.child_pid <- Some pid;
  pid

(* Returns [true] if a restart is still within policy (and records
   this attempt), [false] if the sliding window is already at the
   cap — the caller must not spawn again in that case. *)
let record_restart_and_check_storm (t : t) : bool =
  let now = Unix.gettimeofday () in
  let cutoff = now -. t.policy.window_seconds in
  let recent = now :: List.filter (fun ts -> ts >= cutoff) t.restart_times in
  t.restart_times <- recent;
  List.length recent <= t.policy.max_restarts

type wait_outcome = Exited of int | Signaled of int | Stopped of int

(* Blocks until the currently-supervised child exits. Callers loop:
   wait, decide whether to restart (tamper check + storm guard), spawn
   again if so. *)
let wait_for_exit (t : t) : wait_outcome =
  match t.child_pid with
  | None -> invalid_arg "Supervisor.wait_for_exit: nothing spawned yet"
  | Some pid -> (
      let _, status = Unix.waitpid [] pid in
      t.child_pid <- None;
      match status with
      | Unix.WEXITED code -> Exited code
      | Unix.WSIGNALED n -> Signaled n
      | Unix.WSTOPPED n -> Stopped n)

(* The tamper-check gate shared by both the initial spawn and every
   restart — adversarial review found the *initial* spawn bypassing
   this check entirely in an earlier version, so a binary tampered
   with before the watchdog's own launch would run at least once no
   matter what, and indefinitely if it never happened to crash. There
   is now exactly one path into `spawn`, from either caller. See
   ADR-0041. *)
let tamper_check (t : t) ~(gnupghome : string) ~(expected_key_fingerprint : string)
    ~(clearsigned_manifest : string) : (unit, Manifest.check_result) result =
  match
    Manifest.check ~gnupghome ~expected_key_fingerprint ~program:t.program
      ~clearsigned_manifest
  with
  | Ok_manifest _ -> Ok ()
  | (Signature_invalid _ | Hash_mismatch _ | Program_not_covered _ | Io_error _)
    as result ->
      Error result

type spawn_decision =
  | Spawned of int
  | Spawn_refused_tamper of Manifest.check_result

let spawn_if_safe (t : t) ~(gnupghome : string) ~(expected_key_fingerprint : string)
    ~(clearsigned_manifest : string) : spawn_decision =
  match tamper_check t ~gnupghome ~expected_key_fingerprint ~clearsigned_manifest with
  | Error result -> Spawn_refused_tamper result
  | Ok () -> Spawned (spawn t)

type restart_decision =
  | Restarted of int
  | Restart_refused_tamper of Manifest.check_result
  | Restart_refused_storm

let restart_if_safe (t : t) ~(gnupghome : string) ~(expected_key_fingerprint : string)
    ~(clearsigned_manifest : string) : restart_decision =
  match tamper_check t ~gnupghome ~expected_key_fingerprint ~clearsigned_manifest with
  | Error result -> Restart_refused_tamper result
  | Ok () ->
      if record_restart_and_check_storm t then Restarted (spawn t)
      else Restart_refused_storm

(* §3.4: lets a verified `restart`/`reload` command received over the
   QUIC command channel (a different thread than the one running the
   `wait_for_exit`/`restart_if_safe` loop above) actually take effect,
   without that channel needing its own copy of — or direct access
   to — the tamper-check-then-respawn sequence those two already
   implement correctly. This function does the one thing genuinely
   safe to do cross-thread: read the currently-tracked child pid and
   ask it to exit. The supervision loop's own `wait_for_exit` (already
   running, on the thread that owns `t`) observes that exit exactly as
   it would any other, and proceeds through its existing, unmodified,
   already-tested tamper-check-then-restart logic — this function
   never calls `spawn`/`restart_if_safe` itself, and never touches
   `t.child_pid`/`t.restart_times` beyond the one read below.

   `SIGTERM`, not `SIGKILL`: gives the current child a chance to shut
   down cleanly (`fossh-fcgi` finishing an in-flight write, closing
   its own listener socket) rather than losing whatever it was in the
   middle of — the same reasoning `Command_protocol`'s "restart" and
   "reload" both already funnel through this one path for (see
   `dev/DURUM.md`'s own note on this deliberate simplification).

   Accepted, documented race: reading `t.child_pid` here and the
   signal actually reaching that specific process are not atomic with
   the supervision thread's own `waitpid`/respawn sequence — in the
   narrow window where the old child has *just* been reaped and a
   *new* one already spawned with a reused pid before this function's
   `Unix.kill` runs, the signal could reach the wrong (newly spawned)
   process. Not fixed with a `Mutex` this pass: closing it properly
   needs the signal-then-wait sequence itself to be atomic with
   respect to the supervision thread, not just the pid read, which is
   a larger synchronization redesign of the main loop this specific
   channel-wiring pass does not also take on — see DECISIONS.md
   (ADR-0050). A human operator or core itself triggering this via an
   already mTLS-authenticated, session-verified channel is a low-
   frequency, non-adversarial-at-will trigger, unlike e.g. attacker-
   controlled network input, which is why this narrow window is an
   accepted tradeoff here and would not be one elsewhere in this
   project.

   Also sets `termination_was_requested` — see that field's own
   comment and `restart_after_requested_termination` below for why:
   adversarial review found (and a real, reproduced repro confirmed)
   that without this, the exit this SIGTERM causes was
   indistinguishable from a genuine crash to the main loop, which
   funneled it through the *same* crash-storm counter and, on the 6th
   verified reload command within the default policy's 60-second
   window, refused the restart and called `exit 4` — ending the
   *entire watchdog process*, not just one restart, over an ordinary
   operational pattern (an operator or automation reloading a few
   times in under a minute) that involves no crash at all. *)
let request_termination (t : t) : unit =
  match t.child_pid with
  | None -> ()
  | Some pid ->
      t.termination_was_requested <- true;
      (try Unix.kill pid Sys.sigterm with Unix.Unix_error _ -> ())

(* Reads and clears `termination_was_requested` in one step — meant to
   be called by the main supervision loop exactly once per
   `wait_for_exit` return, immediately after it, so "was *this specific*
   exit the one `request_termination` asked for" is answered freshly
   each cycle rather than leaking a stale `true` from an earlier one.
   Safe without a `Mutex` for the same reason `request_termination`'s
   own cross-thread pid read is: this project's OCaml threads are
   `Thread`-module systhreads sharing one OCaml 5 domain (cooperative
   scheduling, not true parallel field access), and — separately —
   the QUIC command server only ever processes one connection at a
   time (`serve_forever`), so there is never a second
   `request_termination` call racing this one before the main loop
   gets to consume the flag. *)
let take_requested_termination (t : t) : bool =
  let was_requested = t.termination_was_requested in
  t.termination_was_requested <- false;
  was_requested

type requested_restart_decision =
  | Requested_restart_completed of int
  | Requested_restart_refused_tamper of Manifest.check_result

(* The `request_termination` counterpart to `restart_if_safe`:
   identical tamper-check safety (a verified command must never be
   able to relaunch a tampered binary any more than a crash could),
   deliberately *without* the crash-storm guard — see
   `request_termination`'s own comment for the real, reproduced bug
   this exists to fix. Skipping the storm guard here rather than
   giving command-triggered restarts a separate, more generous counter
   of their own is a deliberate scope cut, not an oversight: reaching
   this function at all already requires completing a real mTLS
   handshake *and* presenting a fresh, connection-scoped, replay-proof
   session token (`command_protocol.ml`'s own job), which is a
   materially different, already-gated threat model from "a binary is
   crash-looping on its own" — the guard's original purpose. See
   DECISIONS.md (ADR-0050) for the full reasoning and the explicitly
   left-open question of whether a separate rate limit belongs here in
   a later release. *)
let restart_after_requested_termination (t : t) ~(gnupghome : string)
    ~(expected_key_fingerprint : string) ~(clearsigned_manifest : string) :
    requested_restart_decision =
  match tamper_check t ~gnupghome ~expected_key_fingerprint ~clearsigned_manifest with
  | Error result -> Requested_restart_refused_tamper result
  | Ok () -> Requested_restart_completed (spawn t)
