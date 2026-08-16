type session_token

type command = Restart | Reload | Status

type error = Malformed_message of string | Unknown_command of string | Session_invalid

type child_state = Child_running | Child_stopped
type tamper_state = Tamper_clean | Tamper_tampered | Tamper_unknown

val describe_error : error -> string
val command_name : command -> string
val command_of_name : string -> command option
val describe_child_state : child_state -> string
val describe_tamper_state : tamper_state -> string

val issue_session : ?lifetime_seconds:float -> unit -> session_token

val issue_session_opt : ?lifetime_seconds:float -> unit -> session_token option
val revoke_session : session_token -> unit
val encode_session_hello : session_token -> string
val decode_session_hello : string -> (string, error) result

val encode_command : string -> command -> string
val decode_command : string -> (string * command, error) result

val verify_command : expected_token:session_token -> presented_token:string -> (unit, error) result

val encode_ok : unit -> string
val encode_error : error -> string
val encode_status : child_state -> tamper_state -> string

type response = Ok_response | Error_response of string | Status_response of child_state * tamper_state

val decode_response : string -> (response, error) result
