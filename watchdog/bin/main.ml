(* fossh-watchdog: process supervision + tamper-detection gate for
   `fossh-fcgi` (§3.3, responsibilities 1 and 3).

   Deliberately NOT wired up yet in this binary: the challenge-response
   auth gate's network listener and the QUIC IPC channel to core
   (§2.1/§3.4) — Auth/Session (lib/auth.ml, lib/session.ml) are real,
   tested, standalone modules, but nothing in this file accepts a
   connection and calls them yet. Also not wired: automatically
   calling `bootstrap-send` from this startup path. That's deliberate,
   not an oversight — see the `bootstrap-send` paragraph below for
   why. See dev/DURUM.md for exactly what's connected versus still
   separate pieces.

   Usage:
     fossh-watchdog <program> <gnupghome> <manifest-path> [args...]
     fossh-watchdog bootstrap-send <socket-path> <gnupghome> <tls-dir> <core-cert-pin-path>

   The manifest is always verified against *this watchdog's own* key
   — `Keypair.ensure_keypair` loads it from `gnupghome` if one already
   exists there, or generates a fresh Ed25519 signing key on first
   run if not (§2.4: per-install, never shipped in the installer,
   never silently regenerated once it exists). An earlier version of
   this binary took the expected fingerprint as a separate CLI
   argument — dropped, because the manifest is always supposed to be
   signed by the watchdog's own key (§3.3: "sign it with the
   watchdog's own key"), so accepting a *different* fingerprint from
   an operator was a real footgun (a copy-paste mistake would have
   silently pointed verification at the wrong key) with no legitimate
   use for it.

   `bootstrap-send` (§2.4's handoff to core, `fossh_admin::watchdog_pin`
   on the Rust side) exists as a real, independently-usable, tested
   operation — including a real cross-language test against the
   compiled Rust listener — but is not auto-invoked from the
   supervision loop above. Deliberately: the handoff is meant to run
   exactly once per install, and this binary has no local record yet
   of "have I already handed off successfully" independent of asking
   core (whose own listener is itself one-shot and may simply no
   longer be listening after a prior success) — auto-calling it on
   every restart without that state would either hammer a socket
   that's usually gone, or need a second persisted marker file whose
   own failure semantics (what if the handoff succeeded but writing
   the marker failed?) deserve deliberate design, not a rushed
   addition alongside unrelated changes. Tracked as open, not silently
   skipped — see dev/DURUM.md.

   Extended (see ADR-0048/ADR-0050): `bootstrap-send` no longer takes
   a fingerprint as a literal argument — the same footgun already
   fixed above for manifest verification (an operator-supplied value
   that could mismatch what's actually loaded) applied equally here,
   so it now derives its own fingerprint via `Keypair.ensure_keypair`
   and its own X.509 identity via `Tls_identity.ensure_identity`
   (`tls-dir`), the same get-or-generate-once shape as the keypair.
   Core's certificate, received in the same handoff, is persisted at
   `core-cert-pin-path` via `Core_pin` — this watchdog's own mirror of
   `fossh_admin::watchdog_pin`'s pin files, refusing to overwrite an
   existing one for the same "no silent rotation" reason.

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
     6 - bootstrap-send failed (could not establish its own keypair or
         TLS identity, exhausted its connection retries, or could not
         persist core's certificate)
     7 - could not establish this watchdog's own keypair at startup
         (main supervision path only — bootstrap-send's own keypair
         failures use exit code 6, scoped to that subcommand) *)

open Fossh_watchdog_lib
open Fossh_watchdog_quic

let log fmt = Printf.eprintf ("fossh-watchdog: " ^^ fmt ^^ "\n%!")

let env_var (key : string) : string option =
  match Sys.getenv_opt key with Some "" -> None | v -> v

let env_var_default (key : string) ~(default : string) : string =
  Option.value (env_var key) ~default

(* "host:port", nothing fancier — matches the one shape this project's
   own default (and every real invocation so far) ever needs. Returns
   [None] on anything else so a bad override degrades to "QUIC command
   server disabled, logged" rather than a startup crash — see
   Quic_command_server's own run and this function's one caller. *)
let parse_inet_addr (s : string) : Unix.sockaddr option =
  match String.rindex_opt s ':' with
  | None -> None
  | Some i -> (
      let host = String.sub s 0 i in
      let port_str = String.sub s (i + 1) (String.length s - i - 1) in
      match int_of_string_opt port_str with
      | None -> None
      | Some port -> (
          try Some (Unix.ADDR_INET (Unix.inet_addr_of_string host, port))
          with Failure _ -> None))

(* §3.4: the real, running QUIC command server (see
   Quic_command_server's own module doc and DECISIONS.md's ADR-0050).
   Same default address both sides agree on out of the box
   (crates/fossh-fcgi's own quic_client.rs defaults
   FOSSH_QUIC_CONNECT_ADDR identically) so a real install needs no
   configuration at all beyond completing the bootstrap handoff.
   Every failure here is soft (logged, server left disabled) — matches
   this project's own already-established "additive capability, not a
   startup requirement" posture for this same channel on core's side. *)
let start_quic_command_server (supervisor : Supervisor.t) : unit =
  match parse_inet_addr (env_var_default "FOSSH_QUIC_LISTEN_ADDR" ~default:"127.0.0.1:7443") with
  | None -> log "FOSSH_QUIC_LISTEN_ADDR is not a valid host:port — QUIC command server disabled"
  | Some listen_addr ->
      let config : Quic_command_server.config =
        {
          tls_dir = env_var_default "FOSSH_WATCHDOG_TLS_DIR" ~default:"/var/lib/fossh-watchdog/tls";
          core_cert_pin_path =
            env_var_default "FOSSH_CORE_CERT_PIN" ~default:"/var/lib/fossh-watchdog/core-cert.pin";
          listen_addr;
        }
      in
      let (_ : Thread.t) = Thread.create (fun () -> Quic_command_server.run config supervisor) () in
      ()

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
  | _ :: "bootstrap-send" :: socket_path :: gnupghome :: tls_dir :: core_cert_pin_path :: _ -> (
      match Keypair.ensure_keypair ~gnupghome ~uid:"fossh-watchdog" with
      | Error e ->
          log "BOOTSTRAP HANDOFF FAILED: could not establish watchdog keypair: %s"
            (Keypair.describe_error e);
          exit 6
      | Ok fingerprint -> (
          match Tls_identity.ensure_identity ~dir:tls_dir ~common_name:"fossh-watchdog" with
          | Error e ->
              log "BOOTSTRAP HANDOFF FAILED: could not establish TLS identity: %s"
                (Tls_identity.describe_error e);
              exit 6
          | Ok identity -> (
              (* Adversarial-review finding: reading a just-validated
                 file moments after `ensure_identity` returned it is a
                 narrow window, but `Fileutil.read_all_bytes` (a
                 `Stdlib` channel op under the hood) raises `Sys_error`
                 on failure, not a typed result — the same "uncaught
                 exception instead of the documented exit code" gap
                 already found and fixed twice elsewhere in this same
                 pass (`bootstrap.ml`'s reply read, `core_pin.ml`'s
                 write path). *)
              match
                try Ok (Fileutil.read_all_bytes identity.cert_pem_path)
                with Sys_error msg -> Error msg
              with
              | Error msg ->
                  log "BOOTSTRAP HANDOFF FAILED: could not read own certificate at %s: %s"
                    identity.cert_pem_path msg;
                  exit 6
              | Ok cert_pem -> (
              match Bootstrap.send_handoff_with_retry ~socket_path ~fingerprint cert_pem with
              | Error e ->
                  log "BOOTSTRAP HANDOFF FAILED: %s" (Bootstrap.describe_error e);
                  exit 6
              | Ok core_cert_pem -> (
                  match Core_pin.persist_pin core_cert_pin_path core_cert_pem with
                  | Error e ->
                      log "BOOTSTRAP HANDOFF FAILED: could not persist core's certificate: %s"
                        (Core_pin.describe_error e);
                      exit 6
                  | Ok () ->
                      log "bootstrap handoff completed with %s" socket_path;
                      (* stdout, deliberately separate from the log
                         lines above (all stderr): the one piece of
                         this handoff an external caller — an install
                         script, or this project's own cross-language
                         interop test — cannot learn any other way,
                         since the fingerprint is derived internally
                         from `gnupghome` rather than supplied. *)
                      print_endline fingerprint;
                      exit 0)))))
  | _ :: program :: gnupghome :: manifest_path :: rest ->
      let expected_key_fingerprint =
        match Keypair.ensure_keypair ~gnupghome ~uid:"fossh-watchdog" with
        | Ok fpr ->
            log "watchdog key fingerprint: %s" fpr;
            fpr
        | Error e ->
            log "COULD NOT ESTABLISH WATCHDOG KEYPAIR: %s" (Keypair.describe_error e);
            exit 7
      in
      let args = Array.of_list (program :: rest) in
      let supervisor = Supervisor.create ~program args in
      start_quic_command_server supervisor;
      let (_ : int option) =
        spawn_or_refuse supervisor ~gnupghome ~expected_key_fingerprint ~manifest_path
      in
      let running = ref true in
      while !running do
        let outcome = Supervisor.wait_for_exit supervisor in
        (* Read *and clear* immediately after wait_for_exit, before
           anything else — see Supervisor.take_requested_termination's
           own doc comment. Adversarial review found a real bug here
           (ADR-0050): without distinguishing "this exit is the one a
           verified restart/reload command just asked for" from an
           actual crash, every such exit fed the exact same crash-storm
           counter a real crash loop needs, and a 6th verified reload
           within one policy window refused the restart and `exit 4`'d
           the *entire watchdog process* — reproduced directly against
           the compiled binary. *)
        let was_requested = Supervisor.take_requested_termination supervisor in
        (match outcome with
        | Exited 0 when not was_requested ->
            log "%s exited 0 (clean shutdown) — not restarting" program;
            running := false
        | Exited 0 -> log "%s exited 0 after a verified restart/reload command" program
        | Exited code -> log "%s exited %d" program code
        | Signaled n when was_requested ->
            log "%s exited via a verified restart/reload command (signal %d)" program n
        | Signaled n -> log "%s killed by signal %d" program n
        | Stopped n -> log "%s stopped by signal %d" program n);
        if !running then
          match read_manifest manifest_path with
          | Error e ->
              log "REFUSING RESTART: %s" (describe_manifest_error e);
              exit 5
          | Ok clearsigned_manifest ->
              if was_requested then
                match
                  try
                    Ok
                      (Supervisor.restart_after_requested_termination supervisor ~gnupghome
                         ~expected_key_fingerprint ~clearsigned_manifest)
                  with
                  | Unix.Unix_error (e, fn, _) ->
                      Error (Printf.sprintf "%s: %s" fn (Unix.error_message e))
                with
                | Error e ->
                    log "REFUSING RESTART: could not spawn %s: %s" program e;
                    exit 3
                | Ok (Supervisor.Requested_restart_completed pid) ->
                    log "restarted %s (pid %d) after a verified command" program pid
                | Ok (Supervisor.Requested_restart_refused_tamper result) ->
                    log "REFUSING RESTART: %s" (describe_check_result result);
                    exit 3
              else (
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
        "usage: fossh-watchdog <program> <gnupghome> <manifest-path> [args...]\n\
        \       fossh-watchdog bootstrap-send <socket-path> <gnupghome> <tls-dir> \
         <core-cert-pin-path>";
      exit 2
