(* §3.4: the watchdog's half of the real, running QUIC command server —
   accepts connections from core, issues a fresh session, verifies one
   command per connection, and dispatches it: `restart`/`reload` to
   `Supervisor.request_termination`, `status` to a live re-read of the
   currently-supervised child and a fresh on-demand tamper recheck
   (see `live_child_state`/`live_tamper_state` below). See DECISIONS.md
   (ADR-0050) for
   the full design: one command per connection rather than a held-open
   channel (sidesteps needing reconnection-handling logic entirely);
   why `Restart` and `Reload` both currently dispatch to the exact same
   action; the accepted pid-reuse race documented on
   `Supervisor.request_termination` itself. `command_protocol.ml`'s own
   header comment already flagged this exact gap as not-yet-built
   ("Wiring this onto real quic.ml streams... is a separate,
   not-yet-built piece") — this module is that wiring.

   Stream layout: stream 1 carries the server's SESSION hello (server
   -> client only); stream 4 carries the client's COMMAND (client ->
   server) and this side's OK/ERROR reply (server -> client) — the
   same bidirectional stream, opposite directions, each independently
   fin-terminated, matching watchdog/test/test_quic.ml's own already-
   proven request/reply-on-one-stream shape for that second one.
   Deliberately *not* stream 0 for the session hello: QUIC stream IDs
   encode who is allowed to be the first to write on them in their low
   two bits (0 = client-initiated bidi, 1 = server-initiated bidi),
   and this is enforced, not just convention — a real, reproduced
   `quiche_conn_stream_send` failure (QUICHE_ERR_INVALID_STREAM_STATE,
   code -7) during this module's own development came from trying to
   have the server speak first on stream 0, a client-initiated ID the
   server has no standing to open. Stream 1 is the first ID the
   server-initiated-bidi space actually grants it. *)

open Fossh_watchdog_lib

let session_stream = 1L
let command_stream = 4L

let log fmt = Printf.eprintf ("fossh-watchdog(quic): " ^^ fmt ^^ "\n%!")

let deadline_in (seconds : float) : float = Unix.gettimeofday () +. seconds

type config = {
  tls_dir : string;
  core_cert_pin_path : string;
  listen_addr : Unix.sockaddr;
  (* Everything a live Status query needs to re-run the exact same
     tamper gate `Supervisor.spawn_if_safe`/`restart_if_safe` already
     run before every real spawn/restart — see `live_tamper_state`
     below. Not carried on `Supervisor.t` itself: that type's own job
     is process supervision, and every existing caller already threads
     these three values through explicitly at each spawn/restart call
     site rather than storing them, a shape this reuses rather than
     changes. *)
  gnupghome : string;
  expected_key_fingerprint : string;
  manifest_path : string;
}

(* Supervisor.t's own `child_pid` field is read directly here, cross-
   thread, with no lock — safe for the identical reason
   `Supervisor.request_termination`'s own doc comment already
   documents for its own cross-thread pid read: this project's OCaml
   threads are `Thread`-module systhreads on one cooperatively
   scheduled OCaml 5 domain, and the QUIC command server only ever
   processes one connection at a time. *)
let live_child_state (supervisor : Supervisor.t) : Command_protocol.child_state =
  match supervisor.child_pid with
  | Some _ -> Command_protocol.Child_running
  | None -> Command_protocol.Child_stopped

(* Answers "would a restart be allowed right now", not a cached belief
   from whenever the child last actually spawned — re-reads the
   manifest file and re-runs `Supervisor.tamper_check` fresh, on every
   query, the same fail-closed gate every real spawn/restart already
   goes through. `Tamper_unknown` (not a crash, not a false "clean")
   covers every way this can't produce a real answer: the manifest is
   currently unreadable, or the check itself raises (an operator
   deleting the manifest mid-query, or a `Unix_error` from the
   underlying `sha256sum`/`gpg` subprocesses, e.g. under fd
   exhaustion — the exact class of failure ADR-0050's finding #1
   already found reachable from this same connection-handling path). *)
let live_tamper_state (supervisor : Supervisor.t) (config : config) : Command_protocol.tamper_state =
  match Manifest.read_from_path config.manifest_path with
  | Error _ -> Command_protocol.Tamper_unknown
  | Ok clearsigned_manifest -> (
      try
        match
          Supervisor.tamper_check supervisor ~gnupghome:config.gnupghome
            ~expected_key_fingerprint:config.expected_key_fingerprint ~clearsigned_manifest
        with
        | Ok _ -> Command_protocol.Tamper_clean
        | Error _ -> Command_protocol.Tamper_tampered
      with Unix.Unix_error _ -> Command_protocol.Tamper_unknown)

(* One connection's worth of work: issue a session, read one verified
   command, dispatch it, reply. Every failure here is caught and
   turned into either an ERROR reply (if the connection is still
   usable enough to carry one) or just a logged outcome — this must
   never raise, since it runs inside the long-lived accept loop below,
   and one misbehaving connection must not end that loop for every
   connection after it. *)
let handle_one_connection (state : Quic.t) (supervisor : Supervisor.t) (config : config) : unit =
  let session = Command_protocol.issue_session () in
  Fun.protect
    ~finally:(fun () -> Command_protocol.revoke_session session)
    (fun () ->
      match
        Quic.send_on_stream state ~stream_id:session_stream
          ~data:(Command_protocol.encode_session_hello session)
          ~fin:true (deadline_in 10.0)
      with
      | Error e -> log "could not send session hello: %s" (Quic.describe_error e)
      | Ok () -> (
          match Quic.recv_from_stream state ~stream_id:command_stream (deadline_in 10.0) with
          | Error e -> log "could not read a command: %s" (Quic.describe_error e)
          | Ok (line, _fin) ->
              let reply =
                match Command_protocol.decode_command line with
                | Error e -> Command_protocol.encode_error e
                | Ok (presented_token, cmd) -> (
                    match Command_protocol.verify_command ~expected_token:session ~presented_token with
                    | Error e -> Command_protocol.encode_error e
                    | Ok () -> (
                        match cmd with
                        | Command_protocol.Status ->
                            let child = live_child_state supervisor in
                            let tamper = live_tamper_state supervisor config in
                            log "dispatched a verified status query (child=%s tamper=%s)"
                              (Command_protocol.describe_child_state child)
                              (Command_protocol.describe_tamper_state tamper);
                            Command_protocol.encode_status child tamper
                        | Command_protocol.Restart | Command_protocol.Reload ->
                            Supervisor.request_termination supervisor;
                            log "dispatched a verified %s command" (Command_protocol.command_name cmd);
                            Command_protocol.encode_ok ()))
              in
              (match
                 Quic.send_on_stream state ~stream_id:command_stream ~data:reply ~fin:true
                   (deadline_in 10.0)
               with
              | Ok () -> ()
              | Error e -> log "could not send reply: %s" (Quic.describe_error e))))

(* Blocks forever, accepting and handling one connection at a time —
   this channel is exactly one watchdog and exactly one core, never a
   concurrent multi-client server (matching `Quic.accept_one`'s own
   documented scope), so there is no need to hand connections off to a
   worker pool the way `fossh-fcgi` does for its own, genuinely
   concurrent, listener. Each `accept_one` call is given a bounded
   (not infinite) per-attempt deadline purely so a `Deadline_exceeded`
   timeout is a normal, silent loop-and-retry rather than this
   function needing its own separate "is anyone even trying to
   connect yet" signal — `accept_one` already rebinds a fresh socket
   on every call, so timing out and calling it again costs nothing
   beyond that rebind. *)
let rec serve_forever (config : config) (tls : Quic.tls_paths) (supervisor : Supervisor.t) : unit =
  match Quic.accept_one ~listen_addr:config.listen_addr ~tls ~deadline:(deadline_in 300.0) with
  | Error Quic.Deadline_exceeded -> serve_forever config tls supervisor
  | Error e ->
      log "accept_one failed: %s (retrying in 1s)" (Quic.describe_error e);
      Unix.sleepf 1.0;
      serve_forever config tls supervisor
  | Ok state ->
      (* Adversarial-review finding (CRITICAL): `handle_one_connection`
         itself calls `Command_protocol.issue_session`, which reaches
         `Nonce.generate`'s `open_in_bin "/dev/urandom"` — an ordinary
         `Sys_error` on fd exhaustion, reproduced under a real
         `ulimit -n`, that was not caught anywhere between there and
         here. `Quic.accept_one` already defends the identical call
         (for its own connection-ID generation) via
         `with_unix_errors_as_io_errors`; this call site is new code
         from this same pass that didn't repeat that pattern. Without
         this `try`, one such failure — or any other exception this
         function's own internals didn't anticipate — would escape
         `Fun.protect`'s re-raise and terminate this whole recursive
         loop, silently disabling `restart`/`reload` for the rest of
         this process's life with no further logging. *)
      (try
         Fun.protect
           ~finally:(fun () -> Quic.close state)
           (fun () -> handle_one_connection state supervisor config)
       with exn ->
         log "connection handling raised an unexpected exception: %s (continuing to serve future connections)"
           (Printexc.to_string exn));
      serve_forever config tls supervisor

(* Establishes this side's own TLS identity and waits for core's
   certificate to be pinned (via the bootstrap handoff — a real,
   already-completed manual operator step, or one still pending; see
   `Core_pin`'s own module doc) before ever binding a listening
   socket. A missing pin is a real, expected, transient state before
   an operator has run the handoff — logged once and left disabled
   for this process's lifetime, not retried forever on a channel that
   cannot possibly succeed without a pin no code path here can create
   on its own. *)
let run (config : config) (supervisor : Supervisor.t) : unit =
  match Tls_identity.ensure_identity ~dir:config.tls_dir ~common_name:"fossh-watchdog" with
  | Error e -> log "could not establish this process's own TLS identity: %s — QUIC command server disabled" (Tls_identity.describe_error e)
  | Ok identity -> (
      match Core_pin.load_pin config.core_cert_pin_path with
      | Error e -> log "could not read core's pinned certificate: %s — QUIC command server disabled" (Core_pin.describe_error e)
      | Ok None ->
          log "no core certificate pinned yet (bootstrap handoff not completed) — QUIC command server disabled for this process's lifetime"
      | Ok (Some _) ->
          (* The pin file itself already holds core's raw certificate
             PEM content, written verbatim by the bootstrap handoff —
             it doubles as the trust-anchor file `Quic.tls_paths`
             needs directly, no separate copy required. *)
          let tls : Quic.tls_paths =
            {
              cert_chain_pem = identity.cert_pem_path;
              priv_key_pem = identity.key_pem_path;
              trusted_peer_cert_pem = config.core_cert_pin_path;
            }
          in
          log "ready — listening for core's command connections";
          serve_forever config tls supervisor)
