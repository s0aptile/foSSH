open Fossh_watchdog_lib
open Test_helpers

(* Test_helpers.detach_sign produces a binary signature -- this
   listener's wire protocol needs an armored one (see
   Operator_auth_server's own .mli), so this test signs locally with
   --armor added rather than changing the shared helper for every
   other test that doesn't need it. *)
let detach_sign_armored (k : key) (data : string) : string =
  Tempfile.with_contents data (fun data_path ->
      let sig_path = Filename.temp_file "fossh-watchdog-test-" ".asc" in
      Fun.protect
        ~finally:(fun () -> try Sys.remove sig_path with Sys_error _ -> ())
        (fun () ->
          let (_ : string) =
            run_gpg_ok ~gnupghome:k.gnupghome
              [
                "--pinentry-mode"; "loopback"; "--passphrase"; k.passphrase;
                "--local-user"; k.fingerprint; "--yes"; "--armor"; "--detach-sign";
                "--output"; sig_path; data_path;
              ]
          in
          Fileutil.read_all_bytes sig_path))

let connect (socket_path : string) : Unix.file_descr * in_channel * out_channel =
  let sock = Unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  Unix.connect sock (Unix.ADDR_UNIX socket_path);
  (sock, Unix.in_channel_of_descr sock, Unix.out_channel_of_descr sock)

let nonce_of_line (line : string) : string =
  let prefix = "NONCE " in
  if String.length line > String.length prefix && String.sub line 0 (String.length prefix) = prefix then
    String.sub line (String.length prefix) (String.length line - String.length prefix)
  else failwith ("expected a NONCE line, got: " ^ line)

let () =
  let key_dir = mkdtemp () in
  let socket_dir = mkdtemp () in
  Fun.protect
    ~finally:(fun () ->
      rm_rf key_dir;
      rm_rf socket_dir)
    (fun () ->
      let socket_path = Filename.concat socket_dir "operator-auth.sock" in
      let config : Operator_auth_server.config = { socket_path; operator_key_dir = key_dir } in
      let (_ : Thread.t) =
        Thread.create
          (fun () ->
            match Operator_auth_server.run ~connection_timeout_seconds:0.3 config with
            | Ok () -> ()
            | Error e -> prerr_endline e)
          ()
      in
      let rec wait_for_socket n =
        if n <= 0 then failwith "operator auth server never bound its socket"
        else if Sys.file_exists socket_path then ()
        else (
          Unix.sleepf 0.02;
          wait_for_socket (n - 1))
      in
      wait_for_socket 200;

      (* Sanity check on the final state (0600, not the looser
         mode a default umask would otherwise leave it at) -- the
         actual TOCTOU window this closes (a real, measured 0755
         immediately after bind(), before this fix) was confirmed by
         a manual empirical repro (stat() right after bind(), before
         chmod()) during review, not by this test: the window is
         between two syscalls milliseconds apart, not something a
         black-box test connecting from outside can reliably observe
         without adding test-only synchronization hooks into
         production code just to make it observable. *)
      check "the socket file's final permissions are 0600"
        (let st = Unix.stat socket_path in
         st.Unix.st_perm = 0o600);

      let sock, ic, _oc = connect socket_path in
      check "NOT_ENROLLED before any key is enrolled" (input_line ic = "NOT_ENROLLED");
      Unix.close sock;

      let operator = generate_key ~uid:"operator <operator@example.invalid>" () in
      (match Operator_key.enroll ~dir:key_dir (export_pubkey operator) with
      | Ok _ -> ()
      | Error e -> failwith (Operator_key.describe_error e));

      let sock, ic, oc = connect socket_path in
      let nonce = nonce_of_line (input_line ic) in
      let sig_armored = detach_sign_armored operator nonce in
      output_string oc sig_armored;
      flush oc;
      let reply = input_line ic in
      check "a correctly signed nonce is accepted with an OK <token>"
        (String.length reply > 3 && String.sub reply 0 3 = "OK ");
      Unix.close sock;

      let impostor = generate_key ~uid:"impostor <impostor@example.invalid>" () in
      let sock, ic, oc = connect socket_path in
      let nonce = nonce_of_line (input_line ic) in
      let bad_sig = detach_sign_armored impostor nonce in
      output_string oc bad_sig;
      flush oc;
      check "a signature from a non-enrolled key is DENIED" (input_line ic = "DENIED");
      Unix.close sock;
      cleanup impostor;

      let sock, ic, oc = connect socket_path in
      let real_nonce = nonce_of_line (input_line ic) in
      let sig_over_wrong_data = detach_sign_armored operator "not-the-real-nonce" in
      ignore real_nonce;
      output_string oc sig_over_wrong_data;
      flush oc;
      check "a valid signature over the wrong data is DENIED, not accepted" (input_line ic = "DENIED");
      Unix.close sock;

      let sock, ic, oc = connect socket_path in
      let (_ : string) = input_line ic in
      output_string oc "-----BEGIN PGP SIGNATURE-----\nbogus\n-----END PGP SIGNATURE-----\n";
      flush oc;
      check "garbage signature bytes are DENIED, not a crash" (input_line ic = "DENIED");
      Unix.close sock;

      (* Regression test for a real bug caught before this ever left
         the sandbox: a client that connects and reads the nonce but
         never sends a signature must not hang the single-threaded
         accept loop forever. The server above runs with a 0.3s
         SO_RCVTIMEO specifically so this test can prove that bound
         exists without waiting out the real 10s default: the second
         connection can only be *accepted* once the stalled one's read
         times out and the accept loop moves on, so seeing the second
         connection served at all, well under the real default, is
         itself the proof. *)
      let stalled_sock, stalled_ic, _stalled_oc = connect socket_path in
      let (_ : string) = nonce_of_line (input_line stalled_ic) in
      let started = Unix.gettimeofday () in
      let sock, ic, oc = connect socket_path in
      let nonce = nonce_of_line (input_line ic) in
      let sig_armored = detach_sign_armored operator nonce in
      output_string oc sig_armored;
      flush oc;
      let reply = input_line ic in
      let waited = Unix.gettimeofday () -. started in
      check "a second connection is eventually served despite a stalled first connection ahead of it"
        (String.length reply > 3 && String.sub reply 0 3 = "OK ");
      check "the wait is bounded by the (short, test-only) timeout, not indefinite" (waited < 5.0);
      Unix.close sock;
      Unix.close stalled_sock;

      (* Regression test for the real drip-DoS adversarial review
         found: an attacker who sends one byte at a time, each well
         under the per-syscall timeout, never completing a signature.
         The server above runs with connection_timeout_seconds:0.3 so
         this can run fast; the drip sends a byte every 0.1s (well
         under 0.3s) for 2s total (well over the connection deadline) --
         under the old (broken) fix this would never be interrupted
         by anything but the per-syscall timeout, which a drip that
         never stops defeats entirely. *)
      let drip_sock = Unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 in
      Unix.connect drip_sock (Unix.ADDR_UNIX socket_path);
      let drip_ic = Unix.in_channel_of_descr drip_sock in
      let (_ : string) = nonce_of_line (input_line drip_ic) in
      let drip_oc = Unix.out_channel_of_descr drip_sock in
      let drip_started = Unix.gettimeofday () in
      (try
         for _ = 1 to 20 do
           output_char drip_oc 'x';
           flush drip_oc;
           Unix.sleepf 0.1
         done
       with Sys_error _ -> ());
      let drip_elapsed = Unix.gettimeofday () -. drip_started in
      check "a byte-at-a-time drip attack is cut off near the connection deadline, not left to run 2s+"
        (drip_elapsed < 1.5);
      (try Unix.close drip_sock with Unix.Unix_error _ -> ());

      let started2 = Unix.gettimeofday () in
      let sock, ic, oc = connect socket_path in
      let nonce = nonce_of_line (input_line ic) in
      let sig_armored = detach_sign_armored operator nonce in
      output_string oc sig_armored;
      flush oc;
      let reply = input_line ic in
      let waited2 = Unix.gettimeofday () -. started2 in
      check "a legitimate connection right after a drip attack is still served promptly"
        (String.length reply > 3 && String.sub reply 0 3 = "OK " && waited2 < 2.0);
      Unix.close sock;

      cleanup operator;
      summarize ())
