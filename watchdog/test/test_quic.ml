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

let a_real_mtls_quic_handshake_completes_and_a_stream_round_trips () =
  let watchdog_cert = generate_self_signed_cert "fossh-watchdog-test" in
  let core_cert = generate_self_signed_cert "fossh-core-test" in
  let port = find_free_loopback_port () in
  let listen_addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", port) in

  let server_ok = ref false in
  let server_error = ref "" in
  let server_thread =
    Thread.create
      (fun () ->
        try
          let tls : Quic.tls_paths =
            {
              cert_chain_pem = core_cert.cert_pem;
              priv_key_pem = core_cert.key_pem;
              trusted_peer_cert_pem = watchdog_cert.cert_pem;
            }
          in
          let deadline = deadline_in 5.0 in
          match Quic.accept_one ~listen_addr ~tls ~deadline with
          | Error e -> server_error := "accept_one: " ^ Quic.describe_error e
          | Ok state ->
              let peer_cert = Quic.peer_cert state in
              let peer_cert_ok = match peer_cert with Some s -> String.length s > 0 | None -> false in
              (match Quic.recv_from_stream state ~stream_id:4L deadline with
              | Error e -> server_error := "recv_from_stream: " ^ Quic.describe_error e
              | Ok (msg, fin) ->
                  if msg <> "hello from watchdog" || not fin || not peer_cert_ok then
                    server_error := "server: unexpected message/fin/peer_cert"
                  else (
                    match
                      Quic.send_on_stream state ~stream_id:4L ~data:"hello from core" ~fin:true deadline
                    with
                    | Error e -> server_error := "send_on_stream: " ^ Quic.describe_error e
                    | Ok () -> server_ok := true));
              Quic.close state
        with e -> server_error := "server exception: " ^ Printexc.to_string e)
      ()
  in

  let client_tls : Quic.tls_paths =
    {
      cert_chain_pem = watchdog_cert.cert_pem;
      priv_key_pem = watchdog_cert.key_pem;
      trusted_peer_cert_pem = core_cert.cert_pem;
    }
  in
  let deadline = deadline_in 5.0 in
  (match Quic.connect ~peer_addr:listen_addr ~tls:client_tls ~deadline with
  | Error e -> check ("connect failed: " ^ Quic.describe_error e) false
  | Ok state ->
      let peer_cert = Quic.peer_cert state in
      check "client sees a non-empty peer certificate"
        (match peer_cert with Some s -> String.length s > 0 | None -> false);
      (match Quic.send_on_stream state ~stream_id:4L ~data:"hello from watchdog" ~fin:true deadline with
      | Error e -> check ("send_on_stream failed: " ^ Quic.describe_error e) false
      | Ok () -> (
          match Quic.recv_from_stream state ~stream_id:4L deadline with
          | Error e -> check ("recv_from_stream failed: " ^ Quic.describe_error e) false
          | Ok (msg, fin) ->
              check "client received the exact expected reply" (msg = "hello from core");
              check "client saw fin on the reply stream" fin));
      Quic.close state);

  Thread.join server_thread;
  check ("server side completed without error (" ^ !server_error ^ ")") !server_ok;

  rm_rf watchdog_cert.dir;
  rm_rf core_cert.dir

let a_client_presenting_the_wrong_certificate_is_rejected () =
  let watchdog_cert = generate_self_signed_cert "fossh-watchdog-wrongcert" in
  let core_cert = generate_self_signed_cert "fossh-core-wrongcert" in

  let impostor_cert = generate_self_signed_cert "impostor" in
  let port = find_free_loopback_port () in
  let listen_addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", port) in

  let server_rejected = ref false in
  let server_thread =
    Thread.create
      (fun () ->
        let tls : Quic.tls_paths =
          {
            cert_chain_pem = core_cert.cert_pem;
            priv_key_pem = core_cert.key_pem;
            trusted_peer_cert_pem = watchdog_cert.cert_pem;
          }
        in
        let deadline = deadline_in 3.0 in
        match Quic.accept_one ~listen_addr ~tls ~deadline with
        | Error _ -> server_rejected := true
        | Ok state ->

            server_rejected := false;
            Quic.close state)
      ()
  in

  let client_tls : Quic.tls_paths =
    {
      cert_chain_pem = impostor_cert.cert_pem;
      priv_key_pem = impostor_cert.key_pem;
      trusted_peer_cert_pem = core_cert.cert_pem;
    }
  in
  let deadline = deadline_in 3.0 in

  (match Quic.connect ~peer_addr:listen_addr ~tls:client_tls ~deadline with
  | Ok state -> Quic.close state
  | Error _ -> ());

  Thread.join server_thread;
  check "server never establishes a connection with an untrusted client cert" !server_rejected;

  rm_rf watchdog_cert.dir;
  rm_rf core_cert.dir;
  rm_rf impostor_cert.dir

let closing_a_connection_twice_does_not_crash () =
  let watchdog_cert = generate_self_signed_cert "fossh-watchdog-doubleclose" in
  let core_cert = generate_self_signed_cert "fossh-core-doubleclose" in
  let port = find_free_loopback_port () in
  let listen_addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", port) in

  let server_thread =
    Thread.create
      (fun () ->
        let tls : Quic.tls_paths =
          {
            cert_chain_pem = core_cert.cert_pem;
            priv_key_pem = core_cert.key_pem;
            trusted_peer_cert_pem = watchdog_cert.cert_pem;
          }
        in
        match Quic.accept_one ~listen_addr ~tls ~deadline:(deadline_in 5.0) with
        | Ok state -> Quic.close state
        | Error _ -> ())
      ()
  in

  let client_tls : Quic.tls_paths =
    {
      cert_chain_pem = watchdog_cert.cert_pem;
      priv_key_pem = watchdog_cert.key_pem;
      trusted_peer_cert_pem = core_cert.cert_pem;
    }
  in
  (match Quic.connect ~peer_addr:listen_addr ~tls:client_tls ~deadline:(deadline_in 5.0) with
  | Error e -> check ("connect failed: " ^ Quic.describe_error e) false
  | Ok state ->
      Quic.close state;
      Quic.close state;
      check "closing the same connection twice did not crash the process" true);

  Thread.join server_thread;
  rm_rf watchdog_cert.dir;
  rm_rf core_cert.dir

let () =
  a_real_mtls_quic_handshake_completes_and_a_stream_round_trips ();
  a_client_presenting_the_wrong_certificate_is_rejected ();
  closing_a_connection_twice_does_not_crash ();
  summarize ()
