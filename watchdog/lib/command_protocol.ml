(* §3.4's app-level command protocol: restart/reload commands bound to
   the current session context, so a captured, valid command cannot be
   replayed over a newly established connection.

   Deliberately QUIC-independent pure logic here, matching how
   Auth/Manifest/Session are all pure logic too, tested without a live
   network connection. Wiring this onto real quic.ml streams — which
   side listens vs connects, QUIC stream ID allocation, concurrent
   command handling — is a separate, not-yet-built piece; see
   dev/DURUM.md's §3.4 row for exactly what is and isn't connected.

   Session model: whichever side accepts commands (the "responder")
   issues one fresh Session token per QUIC connection, sent once as
   the very first message on that connection. Every subsequent
   command on that *same* connection must carry that exact token.
   This is deliberately layered on top of, not a replacement for, the
   QUIC channel's own mTLS: the handshake already proves both sides
   hold the private key matching their pinned certificate — the same
   guarantee §2.1's own nonce-challenge model provides, just via the
   TLS transcript instead of an app-level signed nonce — so this
   layer's only job is making a captured command+token pair from one
   connection useless on a different one, not re-proving identity a
   second time.

   [session_token] is abstract (see command_protocol.mli) specifically
   so [verify_command]'s [expected_token] can only ever be a value
   this module's own [issue_session] produced, never a plain [string]
   parsed straight off the wire. An adversarial review of an earlier,
   unabstracted version of this file found that with both parameters
   as bare strings, the natural-looking but wrong integration
   `verify_command ~expected_token:wire_token ~presented_token:
   wire_token` type-checks, passes every unit test that supplies
   correctly-sourced tokens, and silently collapses the check to "is
   this any live session token, issued to any connection at all" —
   exactly the connection-agnostic, replayable check this whole module
   exists to go beyond. Wrapping the type doesn't make a *deliberately*
   wrong caller impossible (the constructor is visible inside this
   file), but it does make the accidental version of that mistake a
   compile error instead of an invisible one. *)

type session_token = Issued_token of string

type command = Restart | Reload

let command_name = function Restart -> "restart" | Reload -> "reload"

let command_of_name = function
  | "restart" -> Some Restart
  | "reload" -> Some Reload
  | _ -> None

type error = Malformed_message of string | Unknown_command of string | Session_invalid

(* Attacker/peer-controlled content (the raw line, an unrecognized
   command name) is echoed back for diagnostics — truncated, not
   passed through at unbounded length, so a malformed-on-purpose
   multi-megabyte line doesn't turn into a multi-megabyte ERROR
   response echoed straight back over the wire. *)
let truncate_for_display (s : string) : string =
  let limit = 200 in
  if String.length s <= limit then s else String.sub s 0 limit ^ "...(truncated)"

let describe_error = function
  | Malformed_message line -> Printf.sprintf "malformed message: %S" (truncate_for_display line)
  | Unknown_command name -> Printf.sprintf "unknown command: %S" (truncate_for_display name)
  | Session_invalid -> "session token missing, expired, revoked, or not this connection's own"

(* Legitimate tokens are always Nonce.generate's own output shape: 64
   lowercase hex characters. Rejecting anything else here — rather
   than accepting "any nonempty byte sequence with no spaces" the way
   an earlier version of this parser did — closes a real, if not
   independently exploitable, gap an adversarial review found: without
   this, a "token" field could contain an embedded literal newline
   (String.trim/split_on_char ' ' only constrain whitespace at the
   edges and at spaces, not arbitrary control bytes in the middle),
   which nothing downstream currently mishandles, but which this
   module has no business accepting as syntactically valid in the
   first place given it always knows the exact expected shape. *)
let looks_like_a_token (s : string) : bool =
  String.length s = 64
  && String.for_all (fun c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) s

(* The responder calls this once, right after a connection is
   established, and sends the result verbatim (via
   encode_session_hello) as that connection's first message — see
   this file's own header comment for why this is a fresh token per
   connection, never a shared or reused one. *)
let issue_session ?lifetime_seconds () : session_token =
  Issued_token (Session.issue ?lifetime_seconds ())

let revoke_session (Issued_token token) : unit = Session.revoke token

let encode_session_hello (Issued_token token) : string = "SESSION " ^ token ^ "\n"

let decode_session_hello (line : string) : (string, error) result =
  match String.split_on_char ' ' (String.trim line) with
  | [ "SESSION"; token ] when looks_like_a_token token -> Ok token
  | _ -> Error (Malformed_message line)

let encode_command (session_token : string) (cmd : command) : string =
  Printf.sprintf "COMMAND %s %s\n" session_token (command_name cmd)

let decode_command (line : string) : (string * command, error) result =
  match String.split_on_char ' ' (String.trim line) with
  | [ "COMMAND"; token; name ] when looks_like_a_token token -> (
      match command_of_name name with
      | Some cmd -> Ok (token, cmd)
      | None -> Error (Unknown_command name))
  | _ -> Error (Malformed_message line)

(* [expected_token] can only be a [session_token] this module's own
   [issue_session] produced (see the abstract-type comment at the top
   of this file) — not a lookup against every session ever issued,
   which is exactly what would let a token captured on one connection
   be replayed on a different one. Checking Session.is_valid too (not
   just a byte-for-byte match) means a connection's own token stops
   working the moment it's revoked (e.g. the connection closing), even
   if somehow presented again before its natural expiry. Uses
   Nonce.constant_time_equal, not `=`/String.equal — this is the exact
   reachable path ADR-0041 identified when it deferred fixing this.

   A successful verification also touches the session, extending its
   expiry — §3.4's channel is meant to persist for an install's whole
   uptime, not the single bounded request flow Session's original
   15-minute default was sized for (§2.1); an adversarial review
   pointed out that reusing that default unmodified here would reject
   commands from a legitimately still-open, still-authenticated
   connection for no reason other than it having been idle-but-open
   past 15 minutes. Touching only on success (not on every presented
   token regardless of validity) means an attacker spraying wrong
   tokens at a real connection can't use this to keep an otherwise-
   idle, soon-to-expire session alive either. *)
let verify_command ~(expected_token : session_token) ~(presented_token : string) : (unit, error) result =
  let (Issued_token expected) = expected_token in
  if not (Session.is_valid expected) then Error Session_invalid
  else if not (Nonce.constant_time_equal expected presented_token) then Error Session_invalid
  else (
    Session.touch expected;
    Ok ())

let encode_ok () : string = "OK\n"
let encode_error (e : error) : string = "ERROR " ^ describe_error e ^ "\n"

type response = Ok_response | Error_response of string

let decode_response (line : string) : (response, error) result =
  let trimmed = String.trim line in
  if String.equal trimmed "OK" then Ok Ok_response
  else
    match String.length trimmed >= 6 && String.sub trimmed 0 6 = "ERROR " with
    | true -> Ok (Error_response (String.sub trimmed 6 (String.length trimmed - 6)))
    | false -> Error (Malformed_message line)
