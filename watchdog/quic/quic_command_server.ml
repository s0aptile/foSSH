open Fossh_watchdog_lib

let session_stream = 1L
let command_stream = 4L

let log fmt = Printf.eprintf ("fossh-watchdog(quic): " ^^ fmt ^^ "\n%!")

let deadline_in (seconds : float) : float = Unix.gettimeofday () +. seconds

type config = {
  tls_dir : string;
  core_cert_pin_path : string;
  listen_addr : Unix.sockaddr;

  gnupghome : string;
  expected_key_fingerprint : string;
  manifest_path : string;
}

let live_child_state (supervisor : Supervisor.t) : Command_protocol.child_state =
  match supervisor.child_pid with
  | Some _ -> Command_protocol.Child_running
  | None -> Command_protocol.Child_stopped

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

let rec serve_forever (config : config) (tls : Quic.tls_paths) (supervisor : Supervisor.t) : unit =
  match Quic.accept_one ~listen_addr:config.listen_addr ~tls ~deadline:(deadline_in 300.0) with
  | Error Quic.Deadline_exceeded -> serve_forever config tls supervisor
  | Error e ->
      log "accept_one failed: %s (retrying in 1s)" (Quic.describe_error e);
      Unix.sleepf 1.0;
      serve_forever config tls supervisor
  | Ok state ->

      (try
         Fun.protect
           ~finally:(fun () -> Quic.close state)
           (fun () -> handle_one_connection state supervisor config)
       with exn ->
         log "connection handling raised an unexpected exception: %s (continuing to serve future connections)"
           (Printexc.to_string exn));
      serve_forever config tls supervisor

let run (config : config) (supervisor : Supervisor.t) : unit =
  match Tls_identity.ensure_identity ~dir:config.tls_dir ~common_name:"fossh-watchdog" with
  | Error e -> log "could not establish this process's own TLS identity: %s — QUIC command server disabled" (Tls_identity.describe_error e)
  | Ok identity -> (
      match Core_pin.load_pin config.core_cert_pin_path with
      | Error e -> log "could not read core's pinned certificate: %s — QUIC command server disabled" (Core_pin.describe_error e)
      | Ok None ->
          log "no core certificate pinned yet (bootstrap handoff not completed) — QUIC command server disabled for this process's lifetime"
      | Ok (Some _) ->

          let tls : Quic.tls_paths =
            {
              cert_chain_pem = identity.cert_pem_path;
              priv_key_pem = identity.key_pem_path;
              trusted_peer_cert_pem = config.core_cert_pin_path;
            }
          in
          log "ready — listening for core's command connections";
          serve_forever config tls supervisor)
