(* §3.3 responsibility 1: restart foSSH core on crash. "Core" here
   means `fossh-fcgi` specifically — the one persistent, long-running
   process in this architecture. `fossh-cgi` is spawned fresh per
   request by fcgiwrap and has no persistent instance for a supervisor
   to watch or restart. *)

type restart_policy = {
  max_restarts : int;
  window_seconds : float;
}

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
}

let create ?(policy = default_policy) ~(program : string) (args : string array)
    : t =
  { program; args; child_pid = None; restart_times = []; policy }

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

type wait_outcome =
  | Exited of int
  | Signaled of int
  | Stopped of int

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

type restart_decision =
  | Restarted of int
  | Refused_tamper_detected of Manifest.check_result
  | Refused_restart_storm

(* The single gate every restart goes through: tamper check first
   (fail closed — a Signature_invalid, Hash_mismatch, or Io_error all
   refuse equally, since "the manifest itself won't verify" and "a
   file doesn't match" are both reasons not to trust what's about to
   run), then the storm guard. Order matters: a storm of *tampered*
   restarts should be reported as tamper detection, not miscounted as
   an ordinary restart storm. *)
let restart_if_safe (t : t) ~(gnupghome : string) ~(clearsigned_manifest : string)
    : restart_decision =
  match Manifest.check ~gnupghome ~clearsigned_manifest with
  | (Signature_invalid _ | Hash_mismatch _ | Io_error _) as result ->
      Refused_tamper_detected result
  | Ok_manifest _ ->
      if record_restart_and_check_storm t then Restarted (spawn t)
      else Refused_restart_storm
