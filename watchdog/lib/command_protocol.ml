type session_token = Issued_token of string

type command = Restart | Reload | Status

let command_name = function Restart -> "restart" | Reload -> "reload" | Status -> "status"

let command_of_name = function
  | "restart" -> Some Restart
  | "reload" -> Some Reload
  | "status" -> Some Status
  | _ -> None

type child_state = Child_running | Child_stopped
type tamper_state = Tamper_clean | Tamper_tampered | Tamper_unknown

let describe_child_state = function Child_running -> "running" | Child_stopped -> "stopped"

let child_state_of_name = function
  | "running" -> Some Child_running
  | "stopped" -> Some Child_stopped
  | _ -> None

let describe_tamper_state = function
  | Tamper_clean -> "clean"
  | Tamper_tampered -> "tampered"
  | Tamper_unknown -> "unknown"

let tamper_state_of_name = function
  | "clean" -> Some Tamper_clean
  | "tampered" -> Some Tamper_tampered
  | "unknown" -> Some Tamper_unknown
  | _ -> None

type error = Malformed_message of string | Unknown_command of string | Session_invalid

let truncate_for_display (s : string) : string =
  let limit = 200 in
  if String.length s <= limit then s else String.sub s 0 limit ^ "...(truncated)"

let describe_error = function
  | Malformed_message line -> Printf.sprintf "malformed message: %S" (truncate_for_display line)
  | Unknown_command name -> Printf.sprintf "unknown command: %S" (truncate_for_display name)
  | Session_invalid -> "session token missing, expired, revoked, or not this connection's own"

let looks_like_a_token (s : string) : bool =
  String.length s = 64
  && String.for_all (fun c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) s

let issue_session ?lifetime_seconds () : session_token =
  Issued_token (Session.issue ?lifetime_seconds ())

let issue_session_opt ?lifetime_seconds () : session_token option =
  match Session.issue ?lifetime_seconds () with
  | token -> Some (Issued_token token)
  | exception Session.Too_many_sessions -> None

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

let verify_command ~(expected_token : session_token) ~(presented_token : string) : (unit, error) result =
  let (Issued_token expected) = expected_token in
  if not (Session.is_valid expected) then Error Session_invalid
  else if not (Nonce.constant_time_equal expected presented_token) then Error Session_invalid
  else (
    Session.touch expected;
    Ok ())

let encode_ok () : string = "OK\n"
let encode_error (e : error) : string = "ERROR " ^ describe_error e ^ "\n"

let encode_status (child : child_state) (tamper : tamper_state) : string =
  Printf.sprintf "STATUS %s %s\n" (describe_child_state child) (describe_tamper_state tamper)

type response = Ok_response | Error_response of string | Status_response of child_state * tamper_state

let decode_response (line : string) : (response, error) result =
  let trimmed = String.trim line in
  if String.equal trimmed "OK" then Ok Ok_response
  else if String.length trimmed >= 6 && String.sub trimmed 0 6 = "ERROR " then
    Ok (Error_response (String.sub trimmed 6 (String.length trimmed - 6)))
  else
    match String.split_on_char ' ' trimmed with
    | [ "STATUS"; child_tok; tamper_tok ] -> (
        match (child_state_of_name child_tok, tamper_state_of_name tamper_tok) with
        | Some child, Some tamper -> Ok (Status_response (child, tamper))
        | _ -> Error (Malformed_message line))
    | _ -> Error (Malformed_message line)
