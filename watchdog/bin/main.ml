(* fossh-watchdog: process supervision + tamper-detection gate for
   `fossh-fcgi` (§3.3, responsibilities 1 and 3).

   Deliberately NOT wired up yet in this binary: the challenge-response
   auth gate's network listener and the QUIC IPC channel to core
   (§2.1/§3.4) — Auth/Session (lib/auth.ml, lib/session.ml) are real,
   tested, standalone modules, but nothing in this file accepts a
   connection and calls them yet. That's the next pass; see
   DECISIONS.md and dev/DURUM.md for exactly what's built versus
   still open. Running this binary today gives you real crash-restart
   plus real tamper detection on every restart *and* on the initial
   launch, and nothing else.

   Usage:
     fossh-watchdog <program> <gnupghome> <expected-key-fingerprint>
                     <manifest-path> [args...]
     fossh-watchdog bootstrap-send <socket-path> <fingerprint>

   The second form is §2.4's bootstrap handoff — sends this
   installation's fingerprint to core's listener
   (`fossh_admin::watchdog_pin::run_bootstrap_listener`, the Rust
   side) exactly once, with a bounded retry since the two processes
   have no guaranteed startup ordering. Still not wired into the first
   form's own startup sequence yet — see dev/DURUM.md for exactly
   what's connected versus still separate pieces (in particular: this
   binary does not yet generate its own keypair, so nothing calls
   `bootstrap-send` automatically today; it exists as a real,
   independently-usable operation, exercised by a real cross-language
   test against the actual Rust listener, not just scaffolding).

   Exit codes (distinct on purpose — §3.6 requires being able to tell
   "refused, needs attention" apart from "exited cleanly", and a
   restart-storm refusal apart from a tamper-detected one, so an
   eventual systemd unit/alerting hook has something to key off):
     0 - supervised program exited 0 (clean, intentional shutdown);
         or bootstrap-send succeeded
     2 - usage error
     3 - tamper detected; restart or initial launch refused
     4 - restart-storm guard tripped
     5 - could not even read the manifest file (fails closed the same
         as a tamper detection, distinguished for diagnosability)
     6 - bootstrap-send failed (exhausted retries) *)

open Fossh_watchdog_lib

let log fmt = Printf.eprintf ("fossh-watchdog: " ^^ fmt ^^ "\n%!")

(* 1 MiB is generous for any real manifest — even several thousand
   watched files at ~70 bytes/entry stays well under it — while still
   bounding the worst case an oversized or misconfigured
   `manifest_path` could do to this process, which is the only thing
   standing between a core-process crash and a restart. *)
let max_manifest_bytes = 1 * 1024 * 1024

type manifest_read_error = Missing | Not_a_file | Too_large of int | Unreadable of string

let read_manifest (path : string) : (string, manifest_read_error) result =
  match Unix.stat path with
  | exception Unix.Unix_error (Unix.ENOENT, _, _) -> Error Missing
  | exception Unix.Unix_error (e, _, _) -> Error (Unreadable (Unix.error_message e))
  | { Unix.st_kind = Unix.S_REG; st_size; _ } when st_size > max_manifest_bytes ->
      Error (Too_large st_size)
  | { Unix.st_kind = Unix.S_REG; _ } -> (
      try Ok (Fileutil.read_all_bytes path)
      with Sys_error msg -> Error (Unreadable msg))
  | _ -> Error Not_a_file

let describe_manifest_error = function
  | Missing -> "manifest file does not exist"
  | Not_a_file -> "manifest path is not a regular file"
  | Too_large n -> Printf.sprintf "manifest file too large (%d bytes, cap %d)" n max_manifest_bytes
  | Unreadable msg -> Printf.sprintf "could not read manifest: %s" msg

let describe_check_result = function
  | Manifest.Signature_invalid e -> Printf.sprintf "manifest signature invalid: %s" e
  | Manifest.Hash_mismatch { path; expected; actual } ->
      Printf.sprintf "tamper detected in %s (expected %s, got %s)" path expected actual
  | Manifest.Program_not_covered p ->
      Printf.sprintf "manifest does not cover the program about to run (%s)" p
  | Manifest.Io_error e -> Printf.sprintf "could not verify manifest: %s" e
  | Manifest.Ok_manifest _ -> assert false (* never passed to this function *)

(* Every real filesystem/process operation on this hot path is
   wrapped so an exception here becomes a refuse-and-exit, not an
   uncaught crash — adversarial review found a missing manifest file,
   a manifest path that's a directory, a nonexistent `program`, and a
   non-executable `program` all took down the whole watchdog process
   with `Fatal error: exception ...`, which is a worse outcome than
   any single refused restart: the trust anchor itself disappears,
   not just one restart decision. See ADR-0041. *)
let spawn_or_refuse (supervisor : Supervisor.t) ~gnupghome ~expected_key_fingerprint
    ~manifest_path : int option =
  match read_manifest manifest_path with
  | Error e ->
      log "REFUSING TO LAUNCH: %s" (describe_manifest_error e);
      exit 5
  | Ok clearsigned_manifest -> (
      match
        try
          Ok
            (Supervisor.spawn_if_safe supervisor ~gnupghome ~expected_key_fingerprint
               ~clearsigned_manifest)
        with Unix.Unix_error (e, fn, _) -> Error (Printf.sprintf "%s: %s" fn (Unix.error_message e))
      with
      | Error e ->
          log "REFUSING TO LAUNCH: could not spawn %s: %s" supervisor.program e;
          exit 3
      | Ok (Spawned pid) ->
          log "spawned %s (pid %d)" supervisor.program pid;
          Some pid
      | Ok (Spawn_refused_tamper result) ->
          log "REFUSING TO LAUNCH: %s" (describe_check_result result);
          exit 3)

let () =
  match Array.to_list Sys.argv with
  | _ :: "bootstrap-send" :: socket_path :: fingerprint :: _ -> (
      match Bootstrap.send_fingerprint_with_retry ~socket_path fingerprint with
      | Ok () ->
          log "bootstrap handoff sent to %s" socket_path;
          exit 0
      | Error e ->
          log "BOOTSTRAP HANDOFF FAILED: %s" (Bootstrap.describe_error e);
          exit 6)
  | _ :: program :: gnupghome :: expected_key_fingerprint :: manifest_path :: rest
    ->
      let args = Array.of_list (program :: rest) in
      let supervisor = Supervisor.create ~program args in
      let (_ : int option) =
        spawn_or_refuse supervisor ~gnupghome ~expected_key_fingerprint ~manifest_path
      in
      let running = ref true in
      while !running do
        (match Supervisor.wait_for_exit supervisor with
        | Exited 0 ->
            log "%s exited 0 (clean shutdown) — not restarting" program;
            running := false
        | Exited code -> log "%s exited %d" program code
        | Signaled n -> log "%s killed by signal %d" program n
        | Stopped n -> log "%s stopped by signal %d" program n);
        if !running then
          match read_manifest manifest_path with
          | Error e ->
              log "REFUSING RESTART: %s" (describe_manifest_error e);
              exit 5
          | Ok clearsigned_manifest -> (
              match
                try
                  Ok
                    (Supervisor.restart_if_safe supervisor ~gnupghome
                       ~expected_key_fingerprint ~clearsigned_manifest)
                with
                | Unix.Unix_error (e, fn, _) ->
                    Error (Printf.sprintf "%s: %s" fn (Unix.error_message e))
              with
              | Error e ->
                  log "REFUSING RESTART: could not spawn %s: %s" program e;
                  exit 3
              | Ok (Restarted pid) -> log "restarted %s (pid %d)" program pid
              | Ok (Restart_refused_tamper result) ->
                  log "REFUSING RESTART: %s" (describe_check_result result);
                  exit 3
              | Ok Restart_refused_storm ->
                  log "REFUSING RESTART: too many restarts too fast (policy: %d/%.0fs)"
                    supervisor.policy.max_restarts supervisor.policy.window_seconds;
                  exit 4)
      done
  | _ ->
      prerr_endline
        "usage: fossh-watchdog <program> <gnupghome> <expected-key-fingerprint> \
         <manifest-path> [args...]\n\
        \       fossh-watchdog bootstrap-send <socket-path> <fingerprint>";
      exit 2
