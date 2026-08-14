(* fossh-watchdog: process supervision + tamper-detection gate for
   `fossh-fcgi` (§3.3, responsibilities 1 and 3).

   §2.1's challenge-response auth gate is now wired — see
   start_operator_auth_server below (Operator_auth_server, over a Unix
   domain socket, per §3.9/§3.11's "same local QUIC/Unix-socket
   channels already defined, not a new transport"). (§3.4's QUIC IPC
   channel to core is wired too — see start_quic_command_server below.)
   §2.6's first-run setup token is now generated here too
   (Setup_token.ensure, idempotent — recovers from an existing token
   file or a fresh install with no key enrolled yet, and correctly does
   nothing once a key IS enrolled) and Operator_key.enroll is now only
   reachable through Operator_auth_server's own gated first-run setup
   flow (Setup_token.verify + a burn-on-success call), not directly —
   see operator_auth_server.ml's own .mli for the full wire protocol
   and operator_auth_server.ml's handle_setup_flow for the replay
   reasoning. The TUI-side client that actually speaks this listener's
   wire protocol end to end (submit token, paste/generate a key,
   confirm) is now wired too — crates/fossh-tui/src/wizard.rs, no
   longer the standalone/demo mode it used to be; see that file's own
   module doc and DECISIONS.md's ADR-0059 for what closed this gap
   (ADR-0058's own retrospective, Finding 5, is where the gap was
   found).
   Also not wired: automatically
   calling `bootstrap-send` from this startup path. That's deliberate,
   not an oversight — see the `bootstrap-send` paragraph below for
   why. See dev/DURUM.md for exactly what's connected versus still
   separate pieces.

   Usage:
     fossh-watchdog <program> <gnupghome> <manifest-path> [args...]
     fossh-watchdog bootstrap-send <socket-path> <gnupghome> <tls-dir> <core-cert-pin-path>
     fossh-watchdog generate-manifest <gnupghome> <manifest-path> <path>...

   `generate-manifest` is the §3.6 bootstrap step nothing else in this
   codebase performs: it hashes every listed path, signs the result
   with this watchdog's own key (generating one via `Keypair.
   ensure_keypair` if `gnupghome` doesn't have one yet, same
   get-or-create shape as the main supervision path), and writes the
   clearsigned manifest to `manifest-path`. Meant to run exactly once,
   right after install and before the main supervision path is ever
   started against real paths — `packaging/rpm/fossh.spec`'s `%post`
   now calls this covering the freshly-installed `fossh-fcgi` binary.
   Without it, a fresh install has no manifest at all and the normal
   `<program> <gnupghome> <manifest-path>` path below refuses to
   launch on its very first start (exit 5) before its own setup-token/
   operator-auth listener (started earlier in this same process, see
   start_operator_auth_server) can stay up — found live, not by
   inspection, re-running this project's clean-VM install verification
   against 0.1.3's rewritten `wizard.rs` (DECISIONS.md's ADR-0059) for
   the first time.

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
         failures use exit code 6, scoped to that subcommand)
     9 - refused to start because privilege separation is impossible:
         supervision must hand the child off to `fossh-svc`, which
         needs root, and this process is not root. Distinguished from
         every code above because it is a deployment mistake fixable
         before anything runs, not a runtime refusal — see
         `resolve_privdrop_target`
     8 - generate-manifest failed (could not establish its own keypair
         or passphrase, could not hash/sign one of the given paths, or
         could not write the manifest file) *)

open Fossh_watchdog_lib
open Fossh_watchdog_quic

let log fmt = Printf.eprintf ("fossh-watchdog: " ^^ fmt ^^ "\n%!")

(* §2.3: the account every real, supervised `fossh-fcgi` child must run
   as — never this process's own `fossh-watchdog` identity. A literal
   constant, not an env var, deliberately: matching
   `crates/fossh-cgi/src/privdrop.rs`'s own `TARGET_USER` const, since
   this is a fixed architectural boundary (§2.3), not a per-deployment
   knob. See `Supervisor.privdrop_argv`'s own doc for the full
   mechanism this feeds into. *)
let fossh_svc_user = "fossh-svc"

let env_var (key : string) : string option =
  match Sys.getenv_opt key with Some "" -> None | v -> v

(* Decides whether this process can actually hand its child off to
   `fossh-svc`, and refuses to run at all if it cannot.

   `Supervisor.spawn` implements the drop by exec'ing `setpriv
   --reuid=fossh-svc`, and `setresuid(2)` is only permitted to a
   process with CAP_SETUID — in practice, only to root. Run as an
   ordinary user, every single spawn therefore dies instantly with
   `setpriv: setresuid failed: Operation not permitted` and exit 127.

   Before this gate existed, that produced a genuinely misleading
   failure rather than an error: the supervisor treated each instant
   death as a crash, restarted, hit the 5-restarts-in-60s storm cap
   after about a second, and exited the *whole watchdog* — taking the
   operator-auth server and the QUIC command server down with it. Every
   client mid-handshake at that moment saw `Broken pipe`, which is a
   description of the symptom four layers removed from the cause. Both
   of this project's cross-language interop tests had been failing
   exactly this way, and the message gave no hint that the real problem
   was "this is not root".

   Refusing is deliberate, and silently continuing without the drop
   would be the wrong repair: a watchdog that appears to work while
   running core with the invoking user's full privileges is a real
   §2.3 violation, and a quiet one. The escape hatch exists for tests
   and development only, has to be asked for explicitly, and says so
   loudly every time it is used. *)
let allow_no_privdrop_var = "FOSSH_WATCHDOG_ALLOW_NO_PRIVDROP"

let resolve_privdrop_target () : string option =
  if Unix.geteuid () = 0 then Some fossh_svc_user
  else
    match env_var allow_no_privdrop_var with
    | Some "1" ->
        log
          "WARNING: running without privilege separation — the supervised child will inherit \
           this process's own uid (%d), not %s. This is a development and test mode only; %s \
           must never be set on a real install."
          (Unix.geteuid ()) fossh_svc_user allow_no_privdrop_var;
        None
    | _ ->
        log
          "REFUSING TO START: supervision drops the child's privileges to %s, which requires \
           running as root (euid is %d). Start this via its systemd unit, or set %s=1 to \
           supervise without privilege separation — a development mode that is not safe on a \
           real install."
          fossh_svc_user (Unix.geteuid ()) allow_no_privdrop_var;
        exit 9

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
let start_quic_command_server (supervisor : Supervisor.t) ~(gnupghome : string)
    ~(expected_key_fingerprint : string) ~(manifest_path : string) : unit =
  match parse_inet_addr (env_var_default "FOSSH_QUIC_LISTEN_ADDR" ~default:"127.0.0.1:7443") with
  | None -> log "FOSSH_QUIC_LISTEN_ADDR is not a valid host:port — QUIC command server disabled"
  | Some listen_addr ->
      let config : Quic_command_server.config =
        {
          tls_dir = env_var_default "FOSSH_WATCHDOG_TLS_DIR" ~default:"/var/lib/fossh-watchdog/tls";
          core_cert_pin_path =
            env_var_default "FOSSH_CORE_CERT_PIN" ~default:"/var/lib/fossh-watchdog/core-cert.pin";
          listen_addr;
          gnupghome;
          expected_key_fingerprint;
          manifest_path;
        }
      in
      let (_ : Thread.t) = Thread.create (fun () -> Quic_command_server.run config supervisor) () in
      ()

(* §2.1: the operator challenge-response listener (Operator_auth_server
   in lib/, wire protocol documented on its own .mli). Same "additive
   capability, soft-fail" posture as start_quic_command_server above —
   a bind failure is logged, not fatal to the supervision loop it
   shares a process with.

   §2.6's setup token is established here too, synchronously, before
   the socket is ever opened for connections — Setup_token.ensure is
   idempotent (safe to call on every start) and its own fail-closed
   default (Setup_token.verify returns false when nothing was ever
   successfully ensured) means a failure here degrades to "first-run
   setup unavailable until this is fixed," logged, never a silent
   enrollment bypass. *)
let start_operator_auth_server () : unit =
  let socket_path =
    env_var_default "FOSSH_OPERATOR_AUTH_SOCKET"
      ~default:"/var/lib/fossh-watchdog/operator-auth.sock"
  in
  let operator_key_dir =
    env_var_default "FOSSH_OPERATOR_KEY_DIR" ~default:"/var/lib/fossh-watchdog/operator-key"
  in
  let token_path = env_var_default "FOSSH_SETUP_TOKEN_PATH" ~default:"/etc/fossh/setup-token" in
  (* Setup_token.ensure already returns a typed Result end to end (an
     adversarial-review-found Sys_error escape in its own hashing path
     was fixed at the source, watchdog/lib/setup_token.ml), but this is
     main.ml's own top-level dispatch, called before anything else this
     process does -- an extra try/with here is the same defense-in-depth
     spawn_or_refuse below already applies around an already-Result-
     returning Supervisor call, not a sign the inner guard is doubted. *)
  (match try Setup_token.ensure ~token_path ~operator_key_dir with e -> Error (Setup_token.Io_error (Printexc.to_string e)) with
  | Ok () -> ()
  | Error e ->
      log "setup-token init failed (first-run setup unavailable until this is fixed): %s"
        (Setup_token.describe_error e));
  let config : Operator_auth_server.config = { socket_path; operator_key_dir } in
  let (_ : Thread.t) =
    Thread.create
      (fun () ->
        match Operator_auth_server.run config with
        | Ok () -> ()
        | Error e -> log "operator auth server disabled: %s" e)
      ()
  in
  ()

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
  match Manifest.read_from_path manifest_path with
  | Error e ->
      log "REFUSING TO LAUNCH: %s" (Manifest.describe_read_error e);
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
  (* Adversarial review of the §2.1 operator-auth listener found this
     the hard way: OCaml's default SIGPIPE disposition is SIG_DFL, so
     any write to a stream socket whose peer already closed its read
     end kills this ENTIRE PROCESS outright -- not a catchable
     Sys_error, the process is just gone, signal never reaching this
     binary's own exception handling at all. Every socket-writing
     module in this codebase (bootstrap.ml, core_pin.ml,
     operator_auth_server.ml) already correctly catches Sys_error on
     its writes, matching this project's own established discipline
     of never letting an exception escape as a crash -- but none of
     that code can ever run if the process is already dead from the
     signal before write() gets a chance to return EPIPE. This is
     reachable by ANY local process simply connecting to and then
     disconnecting from operator_auth_server.ml's socket at the wrong
     moment (confirmed empirically) -- a trivial way to kill the
     watchdog and, with it, all supervision of fossh-fcgi. Ignoring
     SIGPIPE here, once, before anything else runs, is what actually
     turns those already-written Sys_error handlers into real
     protection instead of dead code. *)
  Sys.set_signal Sys.sigpipe Sys.Signal_ignore;
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
  | _ :: "generate-manifest" :: gnupghome :: manifest_path :: paths -> (
      if paths = [] then (
        prerr_endline
          "usage: fossh-watchdog generate-manifest <gnupghome> <manifest-path> <path>...";
        exit 2);
      match Keypair.ensure_keypair ~gnupghome ~uid:"fossh-watchdog" with
      | Error e ->
          log "MANIFEST GENERATION FAILED: could not establish watchdog keypair: %s"
            (Keypair.describe_error e);
          exit 8
      | Ok fingerprint -> (
          match Keypair.ensure_passphrase gnupghome with
          | Error e ->
              log "MANIFEST GENERATION FAILED: could not establish keypair passphrase: %s"
                (Keypair.describe_error e);
              exit 8
          | Ok passphrase -> (
              match
                Manifest.generate_and_sign ~gnupghome ~key_id:fingerprint ~passphrase paths
              with
              | Error e ->
                  log "MANIFEST GENERATION FAILED: %s" e;
                  exit 8
              | Ok signed -> (
                  (* Write-then-rename: a reader (this same binary's own
                     spawn_or_refuse, on the very next start) must never
                     observe a partially-written manifest file. Same
                     0600 as the passphrase file next to it — no group
                     or other access, matching this directory's own
                     0700 ownership by fossh-watchdog alone. *)
                  let tmp_path = manifest_path ^ ".tmp" in
                  match
                    try
                      let fd =
                        Unix.openfile tmp_path [ Unix.O_WRONLY; Unix.O_CREAT; Unix.O_TRUNC ] 0o600
                      in
                      let oc = Unix.out_channel_of_descr fd in
                      output_string oc signed;
                      close_out oc;
                      Unix.rename tmp_path manifest_path;
                      Ok ()
                    with
                    | Unix.Unix_error (e, fn, _) -> Error (Printf.sprintf "%s: %s" fn (Unix.error_message e))
                    | Sys_error msg -> Error msg
                  with
                  | Error e ->
                      log "MANIFEST GENERATION FAILED: could not write %s: %s" manifest_path e;
                      exit 8
                  | Ok () ->
                      log "wrote signed manifest covering %d path(s) to %s"
                        (List.length paths) manifest_path;
                      exit 0)))
      )
  | _ :: program :: gnupghome :: manifest_path :: rest ->
      let expected_key_fingerprint =
        match Keypair.ensure_keypair ~gnupghome ~uid:"fossh-watchdog" with
        | Ok fpr ->
            log "watchdog key fingerprint: %s" fpr;
            log "watchdog key passphrase: %s" (Filename.concat gnupghome "passphrase");
            fpr
        | Error e ->
            log "COULD NOT ESTABLISH WATCHDOG KEYPAIR: %s" (Keypair.describe_error e);
            exit 7
      in
      let args = Array.of_list (program :: rest) in
      let supervisor =
        Supervisor.create ~drop_privileges_to:(resolve_privdrop_target ()) ~program args
      in
      start_quic_command_server supervisor ~gnupghome ~expected_key_fingerprint ~manifest_path;
      start_operator_auth_server ();
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
            log "%s exited via a verified restart/reload command (signal %s)" program
              (Subprocess.describe_signal n)
        | Signaled n -> log "%s killed by signal %s" program (Subprocess.describe_signal n)
        | Stopped n -> log "%s stopped by signal %s" program (Subprocess.describe_signal n));
        if !running then
          match Manifest.read_from_path manifest_path with
          | Error e ->
              log "REFUSING RESTART: %s" (Manifest.describe_read_error e);
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
         <core-cert-pin-path>\n\
        \       fossh-watchdog generate-manifest <gnupghome> <manifest-path> <path>...";
      exit 2
