open Fossh_watchdog_lib
open Test_helpers

let fake_watchdog_cert_pem = "-----BEGIN CERTIFICATE-----\nZmFrZS13YXRjaGRvZw==\n-----END CERTIFICATE-----\n"
let fake_core_cert_pem = "-----BEGIN CERTIFICATE-----\nZmFrZS1jb3Jl\n-----END CERTIFICATE-----\n"

(* Plays core's role for this test: accept one connection, read the
   fingerprint line and a PEM-block certificate exactly as
   fossh_admin::watchdog_pin::accept_one_handoff does, then write
   [reply_cert_pem] back before closing — enough of the real protocol
   for this module's own send-side logic to be exercised against a
   real peer, without pulling the Rust crate itself into this test. *)
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

(* Reads the fingerprint and certificate fully (draining exactly what
   a real peer would), then closes without ever writing a reply back —
   the accepted "pins land, then the reply write itself fails"
   asymmetry this module's own header comment documents. Because
   everything sent has already been read, the client's own subsequent
   read sees a clean EOF, not a reset. *)
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

(* Accepts a connection and closes it immediately, before ever reading
   the bytes this side is sending — the kernel treats a close with
   unread data still pending in the receive buffer as abortive, so the
   client's subsequent read raises `Sys_error "Connection reset by
   peer"`, not a clean EOF. A real, reproduced crash during
   development (an uncaught exception took down the whole process)
   before `read_pem_block` learned to catch this distinctly as
   `Recv_failed` — see this module's own comment there. *)
let accept_and_reset_immediately ~(socket_path : string) () : unit =
  let listener = Unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  Unix.bind listener (Unix.ADDR_UNIX socket_path);
  Unix.listen listener 1;
  let conn, _ = Unix.accept listener in
  Unix.close listener;
  Unix.close conn

let () =
  let dir = mkdtemp () in
  Fun.protect
    ~finally:(fun () -> rm_rf dir)
    (fun () ->
      let socket_path = Filename.concat dir "handoff.sock" in

      (* A real listener, a real connect, real bytes on the wire in
         both directions — checking exactly what
         fossh_admin::watchdog_pin's own Rust-side reader expects, and
         that this side correctly returns core's reply. *)
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

      (* Retry: the listener doesn't exist yet when the first attempt
         fires, then appears mid-retry -- this is the real race
         between two independently-started processes the retry logic
         exists for, not a contrived scenario. *)
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
      check "a peer that resets the connection before reading is Recv_failed, not a crash"
        (match reset_result with Error (Bootstrap.Recv_failed _) -> true | _ -> false);

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
            (* One line, well past the cap, with no END marker
               anywhere in it — read_pem_block must bail out once the
               cap is exceeded rather than buffering an unbounded
               reply. Reads the incoming fingerprint+cert fully first,
               same as accept_and_vanish_after_reading above and for
               the same reason: closing with unread data still pending
               risks an abortive reset instead of the clean condition
               this test means to exercise. *)
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

      summarize ())
