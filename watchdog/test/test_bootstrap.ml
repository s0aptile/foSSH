open Fossh_watchdog_lib
open Test_helpers

let read_line_from_unix_socket (socket_path : string) : string =
  let listener = Unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  Unix.bind listener (Unix.ADDR_UNIX socket_path);
  Unix.listen listener 1;
  let conn, _ = Unix.accept listener in
  let ic = Unix.in_channel_of_descr conn in
  let line = input_line ic in
  Unix.close listener;
  Unix.close conn;
  line

let () =
  let dir = mkdtemp () in
  Fun.protect
    ~finally:(fun () -> rm_rf dir)
    (fun () ->
      let socket_path = Filename.concat dir "handoff.sock" in

      (* A real listener, a real connect, a real line of bytes on the
         wire — checking exactly what fossh_admin::watchdog_pin's own
         Rust-side reader expects: one newline-terminated line, no
         other framing. *)
      let received = ref "" in
      let listener_thread =
        Thread.create (fun () -> received := read_line_from_unix_socket socket_path) ()
      in
      Unix.sleepf 0.05;
      let result = Bootstrap.send_fingerprint ~socket_path "AA:BB:CC:DD:EE:FF" in
      Thread.join listener_thread;
      check "send_fingerprint succeeds against a real, already-listening peer"
        (result = Ok ());
      check "the exact fingerprint bytes arrive on the wire, newline-terminated"
        (!received = "AA:BB:CC:DD:EE:FF");

      check "connecting to a socket path nothing is listening on fails cleanly, not an exception"
        (match Bootstrap.send_fingerprint ~socket_path:(Filename.concat dir "nobody-home.sock") "x" with
        | Error (Connect_failed _) -> true
        | _ -> false);

      (* Retry: the listener doesn't exist yet when the first attempt
         fires, then appears mid-retry -- this is the real race
         between two independently-started processes the retry logic
         exists for, not a contrived scenario. *)
      let delayed_socket_path = Filename.concat dir "delayed.sock" in
      let delayed_received = ref "" in
      let delayed_thread =
        Thread.create
          (fun () ->
            Unix.sleepf 0.3;
            delayed_received := read_line_from_unix_socket delayed_socket_path)
          ()
      in
      let retry_result =
        Bootstrap.send_fingerprint_with_retry ~socket_path:delayed_socket_path
          ~max_attempts:50 ~delay_seconds:0.02 "retried-fingerprint"
      in
      Thread.join delayed_thread;
      check "send_fingerprint_with_retry succeeds once the listener appears mid-retry"
        (retry_result = Ok ());
      check "the retried send still carries the correct fingerprint"
        (!delayed_received = "retried-fingerprint");

      check "send_fingerprint_with_retry gives up cleanly after max_attempts against nobody"
        (match
           Bootstrap.send_fingerprint_with_retry
             ~socket_path:(Filename.concat dir "never-appears.sock")
             ~max_attempts:3 ~delay_seconds:0.01 "x"
         with
        | Error (Connect_failed _) -> true
        | _ -> false);

      summarize ())
