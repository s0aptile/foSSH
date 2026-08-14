open Fossh_watchdog_lib
open Test_helpers

(* [session_token] is intentionally abstract (see command_protocol.mli)
   — a real initiator only ever sees the *wire form* of a token, via
   decode_session_hello, never the responder's own session_token
   value. This helper mirrors that: it round-trips through the same
   encode/decode a real peer would use, rather than reaching for
   anything internal, so these tests exercise the same boundary real
   usage would. *)
let wire_form_of (token : Command_protocol.session_token) : string =
  match Command_protocol.decode_session_hello (Command_protocol.encode_session_hello token) with
  | Ok s -> s
  | Error e -> failwith ("wire_form_of: " ^ Command_protocol.describe_error e)

let () =
  (* Session hello round-trip. *)
  let token = Command_protocol.issue_session () in
  let token_str = wire_form_of token in
  check "issued session token is 64 hex chars (Nonce.generate's own shape)"
    (String.length token_str = 64);
  let hello_line = Command_protocol.encode_session_hello token in
  check "encoded hello ends in a newline"
    (String.length hello_line > 0 && hello_line.[String.length hello_line - 1] = '\n');

  (* Session hello: malformed input. *)
  (match Command_protocol.decode_session_hello "not a hello at all\n" with
  | Error (Command_protocol.Malformed_message _) -> check "garbage hello line is Malformed_message" true
  | _ -> check "garbage hello line should be rejected" false);
  (match Command_protocol.decode_session_hello "SESSION\n" with
  | Error (Command_protocol.Malformed_message _) ->
      check "hello with a missing token is Malformed_message" true
  | _ -> check "hello with a missing token should be rejected" false);
  (match Command_protocol.decode_session_hello "SESSION not-really-hex-and-wrong-length\n" with
  | Error (Command_protocol.Malformed_message _) ->
      check "a token that isn't 64 lowercase hex chars is rejected as Malformed_message" true
  | _ -> check "a non-hex/wrong-length token should be rejected" false);
  (match Command_protocol.decode_session_hello (Printf.sprintf "SESSION %s\ninjected\n" token_str) with
  | Error (Command_protocol.Malformed_message _) ->
      check "a token field containing an embedded literal newline is rejected" true
  | _ -> check "a token with an embedded newline should be rejected" false);

  (* Command round-trip, both variants. *)
  List.iter
    (fun cmd ->
      let line = Command_protocol.encode_command token_str cmd in
      match Command_protocol.decode_command line with
      | Ok (decoded_token, decoded_cmd) ->
          check
            (Printf.sprintf "command round-trip preserves the token (%s)"
               (Command_protocol.command_name cmd))
            (String.equal decoded_token token_str);
          check
            (Printf.sprintf "command round-trip preserves the command (%s)"
               (Command_protocol.command_name cmd))
            (decoded_cmd = cmd)
      | Error e -> check ("command decode failed: " ^ Command_protocol.describe_error e) false)
    [ Command_protocol.Restart; Command_protocol.Reload; Command_protocol.Status ];

  (* Command: unknown command name. *)
  (match Command_protocol.decode_command (Printf.sprintf "COMMAND %s launch_the_missiles\n" token_str) with
  | Error (Command_protocol.Unknown_command "launch_the_missiles") ->
      check "an unrecognized command name is Unknown_command, not silently accepted" true
  | _ -> check "an unrecognized command name should be rejected as Unknown_command" false);

  (* Command: malformed input (missing token, extra fields, empty, bad token shape). *)
  List.iter
    (fun bad_line ->
      match Command_protocol.decode_command bad_line with
      | Error (Command_protocol.Malformed_message _) -> check ("rejects: " ^ String.trim bad_line) true
      | _ -> check ("should reject: " ^ String.trim bad_line) false)
    [
      "COMMAND restart\n"; "COMMAND\n"; "\n"; "COMMAND a b c restart\n";
      "COMMAND short restart\n" (* not 64 hex chars *);
    ];

  (* verify_command: the whole point of this module -- session binding
     and replay resistance across connections. The abstract
     session_token type means there is no way to even *attempt* the
     bypass an earlier, unabstracted version of this module allowed
     (sourcing expected_token from wire-parsed data) -- that mistake
     is now a compile error, not merely a test that happens to pass. *)
  let token_a = Command_protocol.issue_session () in
  let token_a_str = wire_form_of token_a in
  let token_b = Command_protocol.issue_session () in
  let token_b_str = wire_form_of token_b in
  check "distinct connections get distinct session tokens" (not (String.equal token_a_str token_b_str));
  (match Command_protocol.verify_command ~expected_token:token_a ~presented_token:token_a_str with
  | Ok () -> check "a connection's own token verifies against itself" true
  | Error _ -> check "a connection's own token should verify against itself" false);
  (match Command_protocol.verify_command ~expected_token:token_a ~presented_token:token_b_str with
  | Error Command_protocol.Session_invalid ->
      check "connection B's token presented against connection A's expected token is rejected" true
  | _ ->
      check
        "a captured command carrying a DIFFERENT connection's token must not verify -- this is \
         exactly the cross-connection replay §3.4 requires be impossible"
        false);
  Command_protocol.revoke_session token_a;
  (match Command_protocol.verify_command ~expected_token:token_a ~presented_token:token_a_str with
  | Error Command_protocol.Session_invalid ->
      check "a revoked session's own token no longer verifies, even presented correctly" true
  | _ -> check "a revoked session token must not verify" false);

  (* A successfully verified command extends the session rather than
     leaving it on its original fixed lifetime -- §3.4's channel is
     meant to persist far longer than §2.1's original 15-minute
     default was sized for. Exercised through the real public API
     (issue_session's own optional lifetime, verify_command's own
     internal touch-on-success), not by reaching around it. *)
  let short_lived = Command_protocol.issue_session ~lifetime_seconds:0.15 () in
  let short_lived_str = wire_form_of short_lived in
  Unix.sleepf 0.05;
  (match Command_protocol.verify_command ~expected_token:short_lived ~presented_token:short_lived_str with
  | Ok () -> check "a short-lived session verifies successfully before its original expiry" true
  | Error _ -> check "a short-lived session should verify before its original expiry" false);
  Unix.sleepf 0.15;
  (* Past the *original* 0.15s deadline (0.05 + 0.15 = 0.2s elapsed),
     but verify_command's own success above should have pushed the
     real deadline out further. *)
  (match Command_protocol.verify_command ~expected_token:short_lived ~presented_token:short_lived_str with
  | Ok () ->
      check "a successfully verified command extends the session past its original fixed lifetime" true
  | Error _ ->
      check "a session touched by a successful verification should survive past its original deadline"
        false);

  (match
     Command_protocol.verify_command ~expected_token:token_a
       ~presented_token:"0000000000000000000000000000000000000000000000000000000000000000"
   with
  | Error Command_protocol.Session_invalid ->
      check "a token nobody ever issued (already-revoked slot notwithstanding) is rejected" true
  | _ -> check "an unissued/wrong-length-but-unrelated token must not verify" false);

  (* Response round-trip. *)
  (match Command_protocol.decode_response (Command_protocol.encode_ok ()) with
  | Ok Command_protocol.Ok_response -> check "OK response round-trips" true
  | _ -> check "OK response should round-trip" false);
  (match Command_protocol.decode_response (Command_protocol.encode_error Command_protocol.Session_invalid)
  with
  | Ok (Command_protocol.Error_response reason) ->
      check "ERROR response round-trips with its reason text"
        (String.length reason > 0 && reason = Command_protocol.describe_error Command_protocol.Session_invalid)
  | _ -> check "ERROR response should round-trip" false);
  (match Command_protocol.decode_response "garbage\n" with
  | Error (Command_protocol.Malformed_message _) -> check "a garbage response line is rejected" true
  | _ -> check "a garbage response line should be rejected" false);

  (* Status round trip: every (child_state, tamper_state) combination. *)
  List.iter
    (fun (child, tamper) ->
      let line = Command_protocol.encode_status child tamper in
      match Command_protocol.decode_response line with
      | Ok (Command_protocol.Status_response (decoded_child, decoded_tamper)) ->
          check
            (Printf.sprintf "status round-trip preserves child=%s tamper=%s"
               (Command_protocol.describe_child_state child) (Command_protocol.describe_tamper_state tamper))
            (decoded_child = child && decoded_tamper = tamper)
      | _ ->
          check
            (Printf.sprintf "status round-trip should preserve child=%s tamper=%s"
               (Command_protocol.describe_child_state child) (Command_protocol.describe_tamper_state tamper))
            false)
    [
      (Command_protocol.Child_running, Command_protocol.Tamper_clean);
      (Command_protocol.Child_running, Command_protocol.Tamper_tampered);
      (Command_protocol.Child_stopped, Command_protocol.Tamper_unknown);
    ];

  (* Status: malformed tokens in either field are rejected, not
     silently mapped to some default state. *)
  List.iter
    (fun bad_line ->
      match Command_protocol.decode_response bad_line with
      | Error (Command_protocol.Malformed_message _) -> check ("rejects: " ^ String.trim bad_line) true
      | _ -> check ("should reject: " ^ String.trim bad_line) false)
    [
      "STATUS running\n"; "STATUS not-a-real-state clean\n"; "STATUS running not-a-real-state\n";
      "STATUS running clean extra\n"; "STATUS\n";
    ];

  (* A malformed line longer than the truncation threshold doesn't
     blow up describe_error/encode_error, and the echoed error stays
     bounded rather than reflecting the whole input back. *)
  let huge_line = String.make 5000 'x' in
  (match Command_protocol.decode_command huge_line with
  | Error e ->
      let encoded = Command_protocol.encode_error e in
      check "a 5000-byte malformed line does not produce an unbounded echoed error"
        (String.length encoded < 1000)
  | Ok _ -> check "a 5000-byte garbage line should not parse as a valid command" false);

  summarize ()
