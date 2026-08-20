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
      ~stdin_content:"" ()
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

let unused_status_config ~(listen_addr : Unix.sockaddr) : Quic_command_server.config =
  {
    tls_dir = "unused";
    core_cert_pin_path = "unused";
    listen_addr;
    gnupghome = "unused";
    expected_key_fingerprint = "unused";
    manifest_path = "/does/not/exist";
  }

let write_file path content =
  let oc = open_out_bin path in
  output_string oc content;
  close_out oc

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
            Quic_command_server.handle_one_connection state supervisor (unused_status_config ~listen_addr);
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
            Quic_command_server.handle_one_connection state supervisor (unused_status_config ~listen_addr);
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

  Unix.sleepf 0.1;
  check "the real supervised child was never sent SIGTERM by a refused command" (pid_is_alive pid);

  (try Unix.kill pid Sys.sigkill with Unix.Unix_error _ -> ());
  (match Supervisor.wait_for_exit supervisor with _ -> ());
  rm_rf watchdog_cert.dir;
  rm_rf core_cert.dir

let send_one_status_query ~(listen_addr : Unix.sockaddr) ~(client_tls : Quic.tls_paths) :
    (Command_protocol.response, string) result =
  let deadline = deadline_in 5.0 in
  match Quic.connect ~peer_addr:listen_addr ~tls:client_tls ~deadline with
  | Error e -> Error ("connect failed: " ^ Quic.describe_error e)
  | Ok state ->
      let result =
        match Quic.recv_from_stream state ~stream_id:1L deadline with
        | Error e -> Error ("recv session hello failed: " ^ Quic.describe_error e)
        | Ok (hello, _fin) -> (
            match Command_protocol.decode_session_hello hello with
            | Error e -> Error ("session hello: " ^ Command_protocol.describe_error e)
            | Ok token -> (
                let command_line = Command_protocol.encode_command token Command_protocol.Status in
                match Quic.send_on_stream state ~stream_id:4L ~data:command_line ~fin:true deadline with
                | Error e -> Error ("send command failed: " ^ Quic.describe_error e)
                | Ok () -> (
                    match Quic.recv_from_stream state ~stream_id:4L deadline with
                    | Error e -> Error ("recv reply failed: " ^ Quic.describe_error e)
                    | Ok (reply, _fin) -> (
                        match Command_protocol.decode_response reply with
                        | Ok response -> Ok response
                        | Error e -> Error ("decode response: " ^ Command_protocol.describe_error e)))))
      in
      Quic.close state;
      result

let start_status_server (listen_addr : Unix.sockaddr) (watchdog_cert : cert) (core_cert : cert)
    (supervisor : Supervisor.t) (config : Quic_command_server.config) : Thread.t =
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
          Quic_command_server.handle_one_connection state supervisor config;
          Quic.close state)
    ()

let a_status_query_reports_a_running_child_and_a_clean_tamper_check () =
  let watchdog_cert = generate_self_signed_cert "fossh-watchdog-status-clean" in
  let core_cert = generate_self_signed_cert "fossh-core-status-clean" in
  let port = find_free_loopback_port () in
  let listen_addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", port) in

  let key = generate_key () in
  let supervised_program = "/bin/sleep" in
  let dir = mkdtemp () in
  let manifest_path = Filename.concat dir "manifest.clearsigned" in
  (match Manifest.hash_all [ supervised_program ] with
  | Error e -> failwith ("hash_all failed: " ^ e)
  | Ok entries -> (
      match
        Manifest.sign ~gnupghome:key.gnupghome ~key_id:key.fingerprint ~passphrase:key.passphrase
          (Manifest.render entries)
      with
      | Error e -> failwith ("sign failed: " ^ e)
      | Ok signed -> write_file manifest_path signed));

  let config : Quic_command_server.config =
    {
      tls_dir = "unused";
      core_cert_pin_path = "unused";
      listen_addr;
      gnupghome = key.gnupghome;
      expected_key_fingerprint = key.fingerprint;
      manifest_path;
    }
  in
  let supervisor = Supervisor.create ~program:supervised_program [| supervised_program; "30" |] in
  let pid = Supervisor.spawn supervisor in
  let server_thread = start_status_server listen_addr watchdog_cert core_cert supervisor config in
  let client_tls : Quic.tls_paths =
    {
      cert_chain_pem = core_cert.cert_pem;
      priv_key_pem = core_cert.key_pem;
      trusted_peer_cert_pem = watchdog_cert.cert_pem;
    }
  in
  (match send_one_status_query ~listen_addr ~client_tls with
  | Ok (Command_protocol.Status_response (Command_protocol.Child_running, Command_protocol.Tamper_clean)) ->
      check "a status query against a running, untampered child reports running/clean" true
  | Ok _ -> check "a status query against a running, untampered child reports running/clean" false
  | Error e -> check ("status query failed: " ^ e) false);

  Thread.join server_thread;
  (try Unix.kill pid Sys.sigkill with Unix.Unix_error _ -> ());
  (match Supervisor.wait_for_exit supervisor with _ -> ());
  rm_rf watchdog_cert.dir;
  rm_rf core_cert.dir;
  rm_rf dir

let a_status_query_reports_a_stopped_child_and_an_unreadable_manifest_as_unknown () =
  let watchdog_cert = generate_self_signed_cert "fossh-watchdog-status-unknown" in
  let core_cert = generate_self_signed_cert "fossh-core-status-unknown" in
  let port = find_free_loopback_port () in
  let listen_addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", port) in

  let config : Quic_command_server.config =
    {
      tls_dir = "unused";
      core_cert_pin_path = "unused";
      listen_addr;
      gnupghome = "unused";
      expected_key_fingerprint = "unused";
      manifest_path = "/does/not/exist";
    }
  in
  let supervisor = Supervisor.create ~program:"/bin/sleep" [| "/bin/sleep"; "30" |] in
  let server_thread = start_status_server listen_addr watchdog_cert core_cert supervisor config in
  let client_tls : Quic.tls_paths =
    {
      cert_chain_pem = core_cert.cert_pem;
      priv_key_pem = core_cert.key_pem;
      trusted_peer_cert_pem = watchdog_cert.cert_pem;
    }
  in
  (match send_one_status_query ~listen_addr ~client_tls with
  | Ok (Command_protocol.Status_response (Command_protocol.Child_stopped, Command_protocol.Tamper_unknown)) ->
      check
        "a status query with no supervised child and an unreadable manifest reports stopped/unknown" true
  | Ok _ ->
      check
        "a status query with no supervised child and an unreadable manifest reports stopped/unknown" false
  | Error e -> check ("status query failed: " ^ e) false);

  Thread.join server_thread;
  rm_rf watchdog_cert.dir;
  rm_rf core_cert.dir

let a_status_query_reports_tampered_when_the_manifest_hash_does_not_match () =
  let watchdog_cert = generate_self_signed_cert "fossh-watchdog-status-tampered" in
  let core_cert = generate_self_signed_cert "fossh-core-status-tampered" in
  let port = find_free_loopback_port () in
  let listen_addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", port) in

  let key = generate_key () in
  let supervised_program = "/bin/sleep" in
  let dir = mkdtemp () in
  let manifest_path = Filename.concat dir "manifest.clearsigned" in
  let wrong_entry : Manifest.entry = { path = supervised_program; expected_sha256 = String.make 64 '0' } in
  (match
     Manifest.sign ~gnupghome:key.gnupghome ~key_id:key.fingerprint ~passphrase:key.passphrase
       (Manifest.render [ wrong_entry ])
   with
  | Error e -> failwith ("sign failed: " ^ e)
  | Ok signed -> write_file manifest_path signed);

  let config : Quic_command_server.config =
    {
      tls_dir = "unused";
      core_cert_pin_path = "unused";
      listen_addr;
      gnupghome = key.gnupghome;
      expected_key_fingerprint = key.fingerprint;
      manifest_path;
    }
  in
  let supervisor = Supervisor.create ~program:supervised_program [| supervised_program; "30" |] in
  let pid = Supervisor.spawn supervisor in
  let server_thread = start_status_server listen_addr watchdog_cert core_cert supervisor config in
  let client_tls : Quic.tls_paths =
    {
      cert_chain_pem = core_cert.cert_pem;
      priv_key_pem = core_cert.key_pem;
      trusted_peer_cert_pem = watchdog_cert.cert_pem;
    }
  in
  (match send_one_status_query ~listen_addr ~client_tls with
  | Ok (Command_protocol.Status_response (Command_protocol.Child_running, Command_protocol.Tamper_tampered)) ->
      check "a status query against a manifest with a wrong hash reports tampered, not clean" true
  | Ok _ -> check "a status query against a manifest with a wrong hash reports tampered, not clean" false
  | Error e -> check ("status query failed: " ^ e) false);

  Thread.join server_thread;
  check "a status query never sends SIGTERM to the real child, even when it reports tampered"
    (pid_is_alive pid);

  (try Unix.kill pid Sys.sigkill with Unix.Unix_error _ -> ());
  (match Supervisor.wait_for_exit supervisor with _ -> ());
  rm_rf watchdog_cert.dir;
  rm_rf core_cert.dir;
  rm_rf dir

let () =
  a_verified_reload_command_actually_terminates_the_real_child ();
  a_command_with_the_wrong_token_is_refused_and_the_child_is_untouched ();
  a_status_query_reports_a_running_child_and_a_clean_tamper_check ();
  a_status_query_reports_a_stopped_child_and_an_unreadable_manifest_as_unknown ();
  a_status_query_reports_tampered_when_the_manifest_hash_does_not_match ();
  summarize ()
