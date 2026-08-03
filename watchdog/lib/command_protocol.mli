(* See command_protocol.ml's own header comment for the full design
   rationale. The one thing that lives here rather than there:
   [session_token] is exposed *without* its constructor, so the only
   way any caller outside this module can produce a value of this
   type is [issue_session] — a wire-parsed [string] can never be
   silently substituted for one, which is the actual, compiler-
   enforced point of this file existing at all. *)

type session_token

type command = Restart | Reload

type error = Malformed_message of string | Unknown_command of string | Session_invalid

val describe_error : error -> string
val command_name : command -> string
val command_of_name : string -> command option

val issue_session : ?lifetime_seconds:float -> unit -> session_token
val revoke_session : session_token -> unit
val encode_session_hello : session_token -> string
val decode_session_hello : string -> (string, error) result

val encode_command : string -> command -> string
val decode_command : string -> (string * command, error) result

val verify_command : expected_token:session_token -> presented_token:string -> (unit, error) result

val encode_ok : unit -> string
val encode_error : error -> string

type response = Ok_response | Error_response of string

val decode_response : string -> (response, error) result
