(* End-to-end tests for §2.6/§3.11's first-run setup flow, driven over
   a real Operator_auth_server socket exactly the way a real client
   (eventually the TUI) would -- not by calling Setup_token/Operator_key
   directly. Complements test_setup_token.ml (module-level) and
   test_operator_auth_server.ml (the pre-existing challenge-response
   flow, unchanged by this addition). *)

open Fossh_watchdog_lib
open Test_helpers

let export_pubkey_armored (k : key) : string =
  run_gpg_ok ~gnupghome:k.gnupghome [ "--armor"; "--export"; k.fingerprint ]

let connect (socket_path : string) : Unix.file_descr * in_channel * out_channel =
  let sock = Unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  Unix.connect sock (Unix.ADDR_UNIX socket_path);
  (sock, Unix.in_channel_of_descr sock, Unix.out_channel_of_descr sock)

let start_server ~(socket_path : string) ~(operator_key_dir : string) : unit =
  let config : Operator_auth_server.config = { socket_path; operator_key_dir } in
  let (_ : Thread.t) =
    Thread.create
      (fun () ->
        match Operator_auth_server.run config with
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
  wait_for_socket 200

let () =
  (* Scenario 1: the real happy path, driven entirely over the socket
     -- submit the token, then paste a fresh key, get ENROLLED back,
     and confirm the token file is actually gone afterward. *)
  let key_dir = mkdtemp () in
  let token_dir = mkdtemp () in
  let socket_dir = mkdtemp () in
  Fun.protect
    ~finally:(fun () ->
      rm_rf key_dir;
      rm_rf token_dir;
      rm_rf socket_dir)
    (fun () ->
      let token_path = Filename.concat token_dir "setup-token" in
      (match Setup_token.ensure ~token_path ~operator_key_dir:key_dir with
      | Ok () -> ()
      | Error e -> failwith (Setup_token.describe_error e));
      let token = String.trim (Fileutil.read_all_bytes token_path) in

      let socket_path = Filename.concat socket_dir "operator-auth.sock" in
      start_server ~socket_path ~operator_key_dir:key_dir;

      let operator = generate_key ~uid:"operator <operator@example.invalid>" () in
      let sock, ic, oc = connect socket_path in
      check "NOT_ENROLLED before setup" (input_line ic = "NOT_ENROLLED");
      output_string oc (Printf.sprintf "SETUP %s\n" token);
      flush oc;
      check "a correct token gets SETUP_OK" (input_line ic = "SETUP_OK");
      output_string oc (export_pubkey_armored operator);
      flush oc;
      let reply = input_line ic in
      check "a valid key after SETUP_OK is ENROLLED"
        (String.length reply > 9 && String.sub reply 0 9 = "ENROLLED ");
      check "the reported fingerprint is the real one"
        (reply = Printf.sprintf "ENROLLED %s" operator.fingerprint);
      Unix.close sock;

      check "the setup token file is gone after a successful enrollment" (not (Sys.file_exists token_path));
      check "Operator_key reflects the real enrollment"
        (Operator_key.enrolled_fingerprint ~dir:key_dir = Ok (Some operator.fingerprint));

      (* Replay: once enrolled, the setup flow is not reachable at all
         any more -- a fresh connection gets the challenge-response
         NONCE, never NOT_ENROLLED, so there is no SETUP command to
         even send the old token to. *)
      let sock2, ic2, _oc2 = connect socket_path in
      let first_line = input_line ic2 in
      check "after enrollment, a fresh connection gets NONCE, not NOT_ENROLLED (setup is unreachable)"
        (String.length first_line >= 5 && String.sub first_line 0 5 = "NONCE");
      Unix.close sock2;

      cleanup operator);

  (* Scenario 2: a wrong token is denied, and does NOT disturb the
     real, still-valid token -- a legitimate follow-up attempt with
     the correct token must still succeed afterward. *)
  let key_dir2 = mkdtemp () in
  let token_dir2 = mkdtemp () in
  let socket_dir2 = mkdtemp () in
  Fun.protect
    ~finally:(fun () ->
      rm_rf key_dir2;
      rm_rf token_dir2;
      rm_rf socket_dir2)
    (fun () ->
      let token_path = Filename.concat token_dir2 "setup-token" in
      (match Setup_token.ensure ~token_path ~operator_key_dir:key_dir2 with
      | Ok () -> ()
      | Error e -> failwith (Setup_token.describe_error e));
      let token = String.trim (Fileutil.read_all_bytes token_path) in

      let socket_path = Filename.concat socket_dir2 "operator-auth.sock" in
      start_server ~socket_path ~operator_key_dir:key_dir2;

      let sock, ic, oc = connect socket_path in
      let (_ : string) = input_line ic in
      output_string oc "SETUP definitely-the-wrong-token\n";
      flush oc;
      check "a wrong token gets SETUP_DENIED" (input_line ic = "SETUP_DENIED");
      Unix.close sock;

      check "a wrong SETUP attempt does not burn the real token" (Sys.file_exists token_path);
      check "the real token still verifies after a wrong attempt" (Setup_token.verify token);

      let operator = generate_key ~uid:"operator2 <operator2@example.invalid>" () in
      let sock2, ic2, oc2 = connect socket_path in
      let (_ : string) = input_line ic2 in
      output_string oc2 (Printf.sprintf "SETUP %s\n" token);
      flush oc2;
      check "the correct token still works after an earlier wrong attempt" (input_line ic2 = "SETUP_OK");
      output_string oc2 (export_pubkey_armored operator);
      flush oc2;
      let reply = input_line ic2 in
      check "enrollment succeeds after an earlier wrong SETUP attempt"
        (reply = Printf.sprintf "ENROLLED %s" operator.fingerprint);
      Unix.close sock2;
      cleanup operator);

  (* Scenario 3: correct token, but garbage key material -- must be
     ENROLL_FAILED, and must NOT burn the token, so the operator can
     retry with the real key material over a fresh connection. *)
  let key_dir3 = mkdtemp () in
  let token_dir3 = mkdtemp () in
  let socket_dir3 = mkdtemp () in
  Fun.protect
    ~finally:(fun () ->
      rm_rf key_dir3;
      rm_rf token_dir3;
      rm_rf socket_dir3)
    (fun () ->
      let token_path = Filename.concat token_dir3 "setup-token" in
      (match Setup_token.ensure ~token_path ~operator_key_dir:key_dir3 with
      | Ok () -> ()
      | Error e -> failwith (Setup_token.describe_error e));
      let token = String.trim (Fileutil.read_all_bytes token_path) in

      let socket_path = Filename.concat socket_dir3 "operator-auth.sock" in
      start_server ~socket_path ~operator_key_dir:key_dir3;

      let sock, ic, oc = connect socket_path in
      let (_ : string) = input_line ic in
      output_string oc (Printf.sprintf "SETUP %s\n" token);
      flush oc;
      check "correct token still gets SETUP_OK" (input_line ic = "SETUP_OK");
      output_string oc "this is not real key material\n-----END PGP PUBLIC KEY BLOCK-----\n";
      flush oc;
      check "garbage key material is ENROLL_FAILED, not a crash or a false ENROLLED"
        (input_line ic = "ENROLL_FAILED invalid_key");
      Unix.close sock;

      check "a failed enrollment does not burn the token" (Sys.file_exists token_path);
      check "the token still verifies after a failed enrollment attempt" (Setup_token.verify token);

      let operator = generate_key ~uid:"operator3 <operator3@example.invalid>" () in
      let sock2, ic2, oc2 = connect socket_path in
      let (_ : string) = input_line ic2 in
      output_string oc2 (Printf.sprintf "SETUP %s\n" token);
      flush oc2;
      let (_ : string) = input_line ic2 in
      output_string oc2 (export_pubkey_armored operator);
      flush oc2;
      let reply = input_line ic2 in
      check "the same token can be retried successfully with real key material afterward"
        (reply = Printf.sprintf "ENROLLED %s" operator.fingerprint);
      Unix.close sock2;
      cleanup operator);

  (* Scenario 4: several real clients submit the same valid token with
     distinct keys via genuinely concurrent connection attempts.
     Adversarial review correctly noted this does NOT exercise real
     concurrent execution of handle_setup_flow itself -- accept_loop
     is single-threaded and fully serial, so at most one connection's
     SETUP/ENROLL logic ever actually runs at a time; what this
     scenario verifies is that concurrently-arriving clients each get
     one, and only one, definitive and correct outcome once the server
     works through its queue -- exactly one ENROLLED, everyone else
     explicitly refused (never dropped, never duplicated), and the
     token left burned afterward. See test_setup_token.ml's own
     "Scenario H" for a test that forces genuinely overlapping
     execution of verify/enroll/burn directly (bypassing this server's
     current single-threaded accept loop via an explicit barrier), the
     thing this scenario's name previously implied it was covering but
     wasn't. Keys are generated up front (slow, real gpg keygen) so
     the race itself is only socket I/O, not confounded by keygen
     time. *)
  let key_dir4 = mkdtemp () in
  let token_dir4 = mkdtemp () in
  let socket_dir4 = mkdtemp () in
  Fun.protect
    ~finally:(fun () ->
      rm_rf key_dir4;
      rm_rf token_dir4;
      rm_rf socket_dir4)
    (fun () ->
      let token_path = Filename.concat token_dir4 "setup-token" in
      (match Setup_token.ensure ~token_path ~operator_key_dir:key_dir4 with
      | Ok () -> ()
      | Error e -> failwith (Setup_token.describe_error e));
      let token = String.trim (Fileutil.read_all_bytes token_path) in

      let socket_path = Filename.concat socket_dir4 "operator-auth.sock" in
      start_server ~socket_path ~operator_key_dir:key_dir4;

      let contestants =
        List.init 5 (fun i -> generate_key ~uid:(Printf.sprintf "racer%d <racer%d@example.invalid>" i i) ())
      in
      let armored = List.map export_pubkey_armored contestants in
      let replies = Array.make (List.length contestants) "" in
      let threads =
        List.mapi
          (fun i pubkey ->
            Thread.create
              (fun () ->
                try
                  let sock, ic, oc = connect socket_path in
                  let first_line = input_line ic in
                  (* A connection only accepted after the winner has
                     already finished gets NONCE, not NOT_ENROLLED --
                     the setup flow is genuinely unreachable for it,
                     matching the single-connection replay test above.
                     A real client with no enrolled key can't answer a
                     NONCE challenge; record that distinctly instead of
                     blindly sending a SETUP line into a NONCE-shaped
                     connection and waiting out the read deadline. *)
                  if first_line = "NOT_ENROLLED" then (
                    output_string oc (Printf.sprintf "SETUP %s\n" token);
                    flush oc;
                    let setup_reply = input_line ic in
                    if setup_reply = "SETUP_OK" then (
                      output_string oc pubkey;
                      flush oc;
                      replies.(i) <- input_line ic)
                    else replies.(i) <- setup_reply)
                  else replies.(i) <- "ALREADY_ENROLLED_BEFORE_ACCEPT";
                  Unix.close sock
                with e -> replies.(i) <- "EXN " ^ Printexc.to_string e)
              ())
          armored
      in
      List.iter Thread.join threads;

      let enrolled_replies =
        Array.to_list replies |> List.filter (fun r -> String.length r > 9 && String.sub r 0 9 = "ENROLLED ")
      in
      (* A loser can be refused in one of three places, all correct,
         depending on exactly when the single-threaded accept loop got
         around to it relative to the winner: still in the enrollment
         race itself (ENROLL_FAILED already_enrolled, from
         Operator_key.enroll's own exclusivity) if its connection
         reached SETUP_OK before the winner finished; SETUP_DENIED if
         its connection was accepted (still NOT_ENROLLED) but its
         SETUP command wasn't read until after the winner had already
         burned the token; or ALREADY_ENROLLED_BEFORE_ACCEPT if it
         wasn't even accepted until after the winner's enrollment was
         already visible, so it got NONCE instead of NOT_ENROLLED and
         the setup flow was never reachable at all. Either way, "not
         silently dropped or duplicated" is what matters -- every
         non-winner must be a real, explicit refusal, never empty,
         never a second ENROLLED. *)
      let refused_replies =
        Array.to_list replies
        |> List.filter (fun r ->
               r = "ENROLL_FAILED already_enrolled" || r = "SETUP_DENIED"
               || r = "ALREADY_ENROLLED_BEFORE_ACCEPT")
      in
      check "no racing attempt raised an exception"
        (Array.for_all (fun r -> String.length r < 3 || String.sub r 0 3 <> "EXN") replies);
      check "exactly one concurrent enrollment attempt wins" (List.length enrolled_replies = 1);
      check "every other concurrent attempt is explicitly refused, not silently dropped or duplicated"
        (List.length refused_replies = List.length contestants - 1);

      let winner_fingerprint =
        match enrolled_replies with
        | [ r ] -> String.sub r 9 (String.length r - 9)
        | _ -> failwith "expected exactly one winner"
      in
      check "the actually-enrolled key is one of the contestants"
        (List.exists (fun k -> k.fingerprint = winner_fingerprint) contestants);
      check "Operator_key agrees on who won"
        (Operator_key.enrolled_fingerprint ~dir:key_dir4 = Ok (Some winner_fingerprint));
      check "the token is burned after the race settles" (not (Sys.file_exists token_path));
      check "the burned token no longer verifies" (not (Setup_token.verify token));

      List.iter cleanup contestants);

  summarize ()
