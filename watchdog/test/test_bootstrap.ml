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

(* A tight-spin variant of accept_and_reset_immediately: polls via a
   zero-timeout Unix.select instead of blocking in Unix.accept, so it
   reacts to a pending connection with as little added latency as
   possible, then closes without reading or writing anything. Used
   (many trials, see below) to chase the real race a plain blocking
   accept_and_reset_immediately can also hit but less reliably: the
   watchdog's own write, inside send_handoff, landing strictly after
   this side has already closed — an EPIPE/SIGPIPE condition on the
   WRITE itself, not just the "peer closed before I could read the
   reply" condition the *existing* accept_and_reset_immediately test
   already covers deterministically via the read side. *)
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
      (* Both Recv_failed and Send_failed are correct, non-crashing
         outcomes here, not just Recv_failed: which one comes back
         depends on exactly where this side's write lands relative to
         the peer's close (write completes just before close -> the
         *next* read sees the reset -> Recv_failed; write itself lands
         after the close -> Send_failed from the write's own EPIPE).
         Before this file's SIGPIPE fix (see send_handoff's own header
         comment and this file's new sigpipe_trial_count-trial test
         below), only Recv_failed was ever actually observed here — not
         because Send_failed couldn't happen, but because hitting that
         exact race used to kill the whole process outright before any
         result, Send_failed included, could ever be returned. Accepting
         both here is the correct fix, not a loosened assertion: the
         narrower original was an artifact of the SIGPIPE bug silently
         hiding one of its two real, safe outcomes. *)
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

      (* Regression test for a real, fresh-sweep SIGPIPE finding:
         send_handoff writes to a Unix-domain STREAM socket (a real
         SIGPIPE risk, unlike quic.ml's own UDP sockets) but, unlike
         Operator_auth_server.run, never ignored SIGPIPE itself — safe
         only because main.ml's entry point already does, process-wide,
         before dispatching to the bootstrap-send subcommand that's this
         function's one real caller. This test calls send_handoff
         directly, the same way a future embedder (or this very test
         file, this whole time) would, with no such caller-side
         protection — before the fix, a real, deterministic reproduction
         (a hand-rolled probe using this exact write-to-a-freshly-closed-
         Unix-stream-socket shape) confirmed the process is simply
         killed outright by SIGPIPE, silently, before any of this
         module's own Sys_error handling ever runs (exit via signal, no
         output at all) — not a Recv_failed/Send_failed result, no
         result at all. Fixed by ignoring SIGPIPE at the top of
         send_handoff itself, the same defensive posture
         Operator_auth_server.run already established for the identical
         reason.

         fast_accept_and_reset's own accept-via-select spin loop chases
         the real race (this side's write landing strictly after the
         peer has already closed) more reliably than a plain blocking
         accept would, but the exact interleaving is still real OS
         thread scheduling, not something forced deterministically
         through send_handoff's own black-box API (it owns connect,
         write, and read as one call, with no seam to synchronize a test
         against in between) — so this runs many real trials rather than
         asserting a single one. If SIGPIPE were still unguarded, ANY
         one trial hitting the write-after-close race would kill this
         entire test binary outright (no partial credit, no later
         "checks passed" line at all, exactly as reproduced standalone)
         — every trial in this loop actually running to completion and
         producing a definite, non-Ok result is itself the evidence the
         fix holds, independent of which exact Bootstrap.error variant
         any single trial happens to land on. *)
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
