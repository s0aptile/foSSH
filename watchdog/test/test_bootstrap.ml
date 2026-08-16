open Fossh_watchdog_lib
open Test_helpers

let fake_watchdog_cert_pem = "-----BEGIN CERTIFICATE-----\nZmFrZS13YXRjaGRvZw==\n-----END CERTIFICATE-----\n"
let fake_core_cert_pem = "-----BEGIN CERTIFICATE-----\nZmFrZS1jb3Jl\n-----END CERTIFICATE-----\n"

let accept_and_respond ~(socket_path : string) ~(reply_cert_pem : string) () : string * string =
  let listener = Unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  Unix.bind listener (Unix.ADDR_UNIX socket_path);
  Unix.listen listener 1;
  let conn, _ = Unix.accept listener in
  let ic = Unix.in_channel_of_descr conn in
  let fingerprint = input_line ic in
  let buf = Buffer.create 256 in
  let rec read_cert () =
    let line = input_line ic in
    Buffer.add_string buf line;
    Buffer.add_char buf '\n';
    if line <> "-----END CERTIFICATE-----" then read_cert ()
  in
  read_cert ();
  let oc = Unix.out_channel_of_descr conn in
  output_string oc reply_cert_pem;
  flush oc;
  Unix.close listener;
  Unix.close conn;
  (fingerprint, Buffer.contents buf)

let accept_and_vanish_after_reading ~(socket_path : string) () : unit =
  let listener = Unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  Unix.bind listener (Unix.ADDR_UNIX socket_path);
  Unix.listen listener 1;
  let conn, _ = Unix.accept listener in
  let ic = Unix.in_channel_of_descr conn in
  let (_ : string) = input_line ic in
  let rec drain_cert () = if input_line ic <> "-----END CERTIFICATE-----" then drain_cert () in
  drain_cert ();
  Unix.close listener;
  Unix.close conn

let accept_and_reset_immediately ~(socket_path : string) () : unit =
  let listener = Unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  Unix.bind listener (Unix.ADDR_UNIX socket_path);
  Unix.listen listener 1;
  let conn, _ = Unix.accept listener in
  Unix.close listener;
  Unix.close conn

let fast_accept_and_reset ~(socket_path : string) () : unit =
  let listener = Unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  Unix.bind listener (Unix.ADDR_UNIX socket_path);
  Unix.listen listener 1;
  let rec spin () =
    match Unix.select [ listener ] [] [] 0.0 with
    | [], _, _ -> spin ()
    | _ ->
        let conn, _ = Unix.accept listener in
        Unix.close conn
  in
  spin ();
  Unix.close listener

let () =
  let dir = mkdtemp () in
  Fun.protect
    ~finally:(fun () -> rm_rf dir)
    (fun () ->
      let socket_path = Filename.concat dir "handoff.sock" in

      let received = ref ("", "") in
      let listener_thread =
        Thread.create
          (fun () ->
            received := accept_and_respond ~socket_path ~reply_cert_pem:fake_core_cert_pem ())
          ()
      in
      Unix.sleepf 0.05;
      let result =
        Bootstrap.send_handoff ~socket_path ~fingerprint:"AA:BB:CC:DD:EE:FF"
          ~cert_pem:fake_watchdog_cert_pem
      in
      Thread.join listener_thread;
      check "send_handoff succeeds against a real, already-listening peer"
        (result = Ok fake_core_cert_pem);
      let received_fingerprint, received_cert = !received in
      check "the exact fingerprint bytes arrive on the wire, newline-terminated"
        (received_fingerprint = "AA:BB:CC:DD:EE:FF");
      check "the exact certificate PEM arrives on the wire" (received_cert = fake_watchdog_cert_pem);

      check "connecting to a socket path nothing is listening on fails cleanly, not an exception"
        (match
           Bootstrap.send_handoff ~socket_path:(Filename.concat dir "nobody-home.sock") ~fingerprint:"x"
             ~cert_pem:fake_watchdog_cert_pem
         with
        | Error (Bootstrap.Connect_failed _) -> true
        | _ -> false);

      let delayed_socket_path = Filename.concat dir "delayed.sock" in
      let delayed_received = ref ("", "") in
      let delayed_thread =
        Thread.create
          (fun () ->
            Unix.sleepf 0.3;
            delayed_received :=
              accept_and_respond ~socket_path:delayed_socket_path ~reply_cert_pem:fake_core_cert_pem ())
          ()
      in
      let retry_result =
        Bootstrap.send_handoff_with_retry ~socket_path:delayed_socket_path ~max_attempts:50
          ~delay_seconds:0.02 ~fingerprint:"retried-fingerprint" fake_watchdog_cert_pem
      in
      Thread.join delayed_thread;
      check "send_handoff_with_retry succeeds once the listener appears mid-retry"
        (retry_result = Ok fake_core_cert_pem);
      check "the retried send still carries the correct fingerprint"
        (fst !delayed_received = "retried-fingerprint");

      check "send_handoff_with_retry gives up cleanly after max_attempts against nobody"
        (match
           Bootstrap.send_handoff_with_retry ~socket_path:(Filename.concat dir "never-appears.sock")
             ~max_attempts:3 ~delay_seconds:0.01 ~fingerprint:"x" fake_watchdog_cert_pem
         with
        | Error (Bootstrap.Connect_failed _) -> true
        | _ -> false);

      let unterminated_socket_path = Filename.concat dir "unterminated.sock" in
      let unterminated_thread =
        Thread.create
          (fun () -> accept_and_vanish_after_reading ~socket_path:unterminated_socket_path ())
          ()
      in
      Unix.sleepf 0.05;
      let unterminated_result =
        Bootstrap.send_handoff ~socket_path:unterminated_socket_path ~fingerprint:"x"
          ~cert_pem:fake_watchdog_cert_pem
      in
      Thread.join unterminated_thread;
      check "a peer that reads everything then closes without replying is Peer_cert_unterminated"
        (unterminated_result = Error Bootstrap.Peer_cert_unterminated);

      let reset_socket_path = Filename.concat dir "reset.sock" in
      let reset_thread =
        Thread.create (fun () -> accept_and_reset_immediately ~socket_path:reset_socket_path ()) ()
      in
      Unix.sleepf 0.05;
      let reset_result =
        Bootstrap.send_handoff ~socket_path:reset_socket_path ~fingerprint:"x"
          ~cert_pem:fake_watchdog_cert_pem
      in
      Thread.join reset_thread;

      check "a peer that resets the connection before reading is Recv_failed or Send_failed, not a crash"
        (match reset_result with
        | Error (Bootstrap.Recv_failed _) | Error (Bootstrap.Send_failed _) -> true
        | _ -> false);

      let oversized_socket_path = Filename.concat dir "oversized.sock" in
      let oversized_thread =
        Thread.create
          (fun () ->
            let listener = Unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 in
            Unix.bind listener (Unix.ADDR_UNIX oversized_socket_path);
            Unix.listen listener 1;
            let conn, _ = Unix.accept listener in
            let ic = Unix.in_channel_of_descr conn in
            let (_ : string) = input_line ic in
            let rec drain_cert () = if input_line ic <> "-----END CERTIFICATE-----" then drain_cert () in
            drain_cert ();
            let oc = Unix.out_channel_of_descr conn in

            output_string oc (String.make (Bootstrap.max_cert_pem_len + 100) 'A');
            output_char oc '\n';
            flush oc;
            Unix.close listener;
            Unix.close conn)
          ()
      in
      Unix.sleepf 0.05;
      let oversized_result =
        Bootstrap.send_handoff ~socket_path:oversized_socket_path ~fingerprint:"x"
          ~cert_pem:fake_watchdog_cert_pem
      in
      Thread.join oversized_thread;
      check "an oversized reply certificate is Peer_cert_too_large"
        (match oversized_result with Error (Bootstrap.Peer_cert_too_large _) -> true | _ -> false);

      let sigpipe_trial_count = 25 in
      let sigpipe_trial_results = ref [] in
      for i = 0 to sigpipe_trial_count - 1 do
        let trial_socket_path = Filename.concat dir (Printf.sprintf "sigpipe-trial-%d.sock" i) in
        let trial_thread =
          Thread.create (fun () -> fast_accept_and_reset ~socket_path:trial_socket_path ()) ()
        in
        Unix.sleepf 0.01;
        let result =
          Bootstrap.send_handoff ~socket_path:trial_socket_path ~fingerprint:"x"
            ~cert_pem:fake_watchdog_cert_pem
        in
        Thread.join trial_thread;
        sigpipe_trial_results := result :: !sigpipe_trial_results
      done;
      check
        (Printf.sprintf
           "%d/%d send_handoff calls against a peer closing without reading all completed \
            (none crashed the process via SIGPIPE)"
           sigpipe_trial_count sigpipe_trial_count)
        (List.length !sigpipe_trial_results = sigpipe_trial_count);
      check "every one of those calls returned a definite Error, never a false Ok"
        (List.for_all (function Error _ -> true | Ok _ -> false) !sigpipe_trial_results);

      summarize ())
