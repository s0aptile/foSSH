(* §3.4: the real, wired-up path — a genuine QUIC/mTLS connection
   carrying a genuine session-token-verified command that dispatches
   to a genuine `Supervisor.t` tracking a genuine child process. Same
   two-cert, real-openssl-subprocess setup as
   watchdog/test/test_quic.ml, extended to drive
   `Quic_command_server.handle_one_connection` itself rather than
   stopping at "the transport works" — this is the one place that
   actually proves a command sent over the wire ends in a real
   process receiving a real signal, which neither `command_protocol`'s
   own QUIC-independent tests nor `quic`'s own protocol-independent
   tests could ever see on their own. *)

open Fossh_watchdog_lib
open Fossh_watchdog_quic
open Test_helpers

type cert = { dir : string; cert_pem : string; key_pem : string }

let generate_self_signed_cert (common_name : string) : cert =
  let dir = mkdtemp () in
  let cert_pem = Filename.concat dir "cert.pem" in
  let key_pem = Filename.concat dir "key.pem" in
  match
    Subprocess.run ~prog:"/usr/bin/openssl"
      ~argv:
        [|
          "openssl"; "req"; "-x509"; "-newkey"; "ec"; "-pkeyopt";
          "ec_paramgen_curve:prime256v1"; "-days"; "1"; "-nodes"; "-keyout"; key_pem; "-out";
          cert_pem; "-subj"; Printf.sprintf "/CN=%s" common_name;
        |]
      ~stdin_content:""
  with
  | Ok _ -> { dir; cert_pem; key_pem }
  | Error e -> failwith (Printf.sprintf "openssl req failed for %s: %s" common_name e)

let find_free_loopback_port () : int =
  let probe = Unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
  Unix.bind probe (Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 0));
  let port = match Unix.getsockname probe with Unix.ADDR_INET (_, p) -> p | _ -> assert false in
  Unix.close probe;
  port

let deadline_in (seconds : float) : float = Unix.gettimeofday () +. seconds

let pid_is_alive (pid : int) : bool =
  match Unix.kill pid 0 with () -> true | exception Unix.Unix_error (Unix.ESRCH, _, _) -> false

(* A real, well-formed COMMAND round trip: watchdog receives it,
   verifies it against the session it itself just issued, dispatches
   it, and the real child process this test spawned actually receives
   SIGTERM as a result. *)
let a_verified_reload_command_actually_terminates_the_real_child () =
  let watchdog_cert = generate_self_signed_cert "fossh-watchdog-cmdtest" in
  let core_cert = generate_self_signed_cert "fossh-core-cmdtest" in
  let port = find_free_loopback_port () in
  let listen_addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", port) in

  let supervisor = Supervisor.create ~program:"/bin/sleep" [| "/bin/sleep"; "30" |] in
  let (_ : int) = Supervisor.spawn supervisor in

  let server_thread =
    Thread.create
      (fun () ->
        let tls : Quic.tls_paths =
          {
            cert_chain_pem = watchdog_cert.cert_pem;
            priv_key_pem = watchdog_cert.key_pem;
            trusted_peer_cert_pem = core_cert.cert_pem;
          }
        in
        match Quic.accept_one ~listen_addr ~tls ~deadline:(deadline_in 5.0) with
        | Error _ -> ()
        | Ok state ->
            Quic_command_server.handle_one_connection state supervisor;
            Quic.close state)
      ()
  in

  let client_tls : Quic.tls_paths =
    {
      cert_chain_pem = core_cert.cert_pem;
      priv_key_pem = core_cert.key_pem;
      trusted_peer_cert_pem = watchdog_cert.cert_pem;
    }
  in
  let deadline = deadline_in 5.0 in
  (match Quic.connect ~peer_addr:listen_addr ~tls:client_tls ~deadline with
  | Error e -> check ("connect failed: " ^ Quic.describe_error e) false
  | Ok state ->
      (match Quic.recv_from_stream state ~stream_id:1L deadline with
      | Error e -> check ("recv session hello failed: " ^ Quic.describe_error e) false
      | Ok (hello, _fin) -> (
          match Command_protocol.decode_session_hello hello with
          | Error e -> check ("session hello: " ^ Command_protocol.describe_error e) false
          | Ok token -> (
              let command_line = Command_protocol.encode_command token Command_protocol.Reload in
              match Quic.send_on_stream state ~stream_id:4L ~data:command_line ~fin:true deadline with
              | Error e -> check ("send command failed: " ^ Quic.describe_error e) false
              | Ok () -> (
                  match Quic.recv_from_stream state ~stream_id:4L deadline with
                  | Error e -> check ("recv reply failed: " ^ Quic.describe_error e) false
                  | Ok (reply, _fin) -> (
                      match Command_protocol.decode_response reply with
                      | Ok Command_protocol.Ok_response ->
                          check "watchdog replied OK to a genuinely valid, in-session command" true
                      | _ -> check "watchdog replied OK to a genuinely valid, in-session command" false))
              )));
      Quic.close state);

  Thread.join server_thread;

  (match Supervisor.wait_for_exit supervisor with
  | Signaled n when n = Sys.sigterm ->
      check "the real supervised child actually received SIGTERM as a result" true
  | _ -> check "the real supervised child actually received SIGTERM as a result" false);

  rm_rf watchdog_cert.dir;
  rm_rf core_cert.dir

(* The replay-protection property this whole layered design (mTLS +
   per-connection session token) exists for: a command presenting a
   token that is *not* the one this connection's own session issued
   (a wrong/forged/replayed-from-elsewhere token, same shape but wrong
   value) must be refused, and — the part a purely wire-level test of
   `command_protocol` alone could never show — the real child must be
   left completely untouched by a refused command. *)
let a_command_with_the_wrong_token_is_refused_and_the_child_is_untouched () =
  let watchdog_cert = generate_self_signed_cert "fossh-watchdog-wrongtoken" in
  let core_cert = generate_self_signed_cert "fossh-core-wrongtoken" in
  let port = find_free_loopback_port () in
  let listen_addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", port) in

  let supervisor = Supervisor.create ~program:"/bin/sleep" [| "/bin/sleep"; "30" |] in
  let pid = Supervisor.spawn supervisor in

  let server_thread =
    Thread.create
      (fun () ->
        let tls : Quic.tls_paths =
          {
            cert_chain_pem = watchdog_cert.cert_pem;
            priv_key_pem = watchdog_cert.key_pem;
            trusted_peer_cert_pem = core_cert.cert_pem;
          }
        in
        match Quic.accept_one ~listen_addr ~tls ~deadline:(deadline_in 5.0) with
        | Error _ -> ()
        | Ok state ->
            Quic_command_server.handle_one_connection state supervisor;
            Quic.close state)
      ()
  in

  let client_tls : Quic.tls_paths =
    {
      cert_chain_pem = core_cert.cert_pem;
      priv_key_pem = core_cert.key_pem;
      trusted_peer_cert_pem = watchdog_cert.cert_pem;
    }
  in
  let deadline = deadline_in 5.0 in
  (match Quic.connect ~peer_addr:listen_addr ~tls:client_tls ~deadline with
  | Error e -> check ("connect failed: " ^ Quic.describe_error e) false
  | Ok state ->
      (match Quic.recv_from_stream state ~stream_id:1L deadline with
      | Error e -> check ("recv session hello failed: " ^ Quic.describe_error e) false
      | Ok (_hello, _fin) ->
          (* A syntactically valid but definitely-not-the-real-one
             token — 64 lowercase hex chars, never issued by this
             connection's own session. *)
          let wrong_token = String.make 64 'a' in
          let command_line = Command_protocol.encode_command wrong_token Command_protocol.Reload in
          (match Quic.send_on_stream state ~stream_id:4L ~data:command_line ~fin:true deadline with
          | Error e -> check ("send command failed: " ^ Quic.describe_error e) false
          | Ok () -> (
              match Quic.recv_from_stream state ~stream_id:4L deadline with
              | Error e -> check ("recv reply failed: " ^ Quic.describe_error e) false
              | Ok (reply, _fin) -> (
                  match Command_protocol.decode_response reply with
                  | Ok (Command_protocol.Error_response _) ->
                      check "a wrong-token command is refused with an ERROR reply" true
                  | _ -> check "a wrong-token command is refused with an ERROR reply" false))));
      Quic.close state);

  Thread.join server_thread;

  (* Give a genuinely-delivered-but-shouldn't-have-been-sent signal a
     moment to land before checking — this is checking the ABSENCE of
     an effect, so a check that ran too early would pass for the
     wrong reason. *)
  Unix.sleepf 0.1;
  check "the real supervised child was never sent SIGTERM by a refused command" (pid_is_alive pid);

  (try Unix.kill pid Sys.sigkill with Unix.Unix_error _ -> ());
  (match Supervisor.wait_for_exit supervisor with _ -> ());
  rm_rf watchdog_cert.dir;
  rm_rf core_cert.dir

let () =
  a_verified_reload_command_actually_terminates_the_real_child ();
  a_command_with_the_wrong_token_is_refused_and_the_child_is_untouched ();
  summarize ()
