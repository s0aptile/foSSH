(* §2.4: the watchdog's half of the one-time bootstrap handoff —
   connects to core's Unix domain socket and sends its own public
   key/cert fingerprint, exactly once. Core (`fossh-svc`) is the
   listener; see `fossh-admin::watchdog_pin` (the Rust crate) for its
   side and the SO_PEERCRED-based peer verification that actually
   enforces "this really is the watchdog process", not just
   "something connected to the right socket path".

   Wire format is deliberately the simplest thing that works: the
   fingerprint as a single line, newline-terminated, nothing else —
   matching exactly what `fossh_admin::watchdog_pin::accept_one_handoff`
   reads via `read_to_string` + `trim`. This is a one-shot, one-message
   exchange, not a protocol that needs framing beyond that. *)

type error = Connect_failed of string | Send_failed of string

let describe_error = function
  | Connect_failed e -> Printf.sprintf "could not connect to core: %s" e
  | Send_failed e -> Printf.sprintf "could not send fingerprint to core: %s" e

let send_fingerprint ~(socket_path : string) (fingerprint : string) :
    (unit, error) result =
  match Unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 with
  | exception Unix.Unix_error (e, fn, _) ->
      Error (Connect_failed (Printf.sprintf "%s: %s" fn (Unix.error_message e)))
  | sock ->
      Fun.protect
        ~finally:(fun () -> try Unix.close sock with Unix.Unix_error _ -> ())
        (fun () ->
          match Unix.connect sock (Unix.ADDR_UNIX socket_path) with
          | exception Unix.Unix_error (e, fn, _) ->
              Error (Connect_failed (Printf.sprintf "%s: %s" fn (Unix.error_message e)))
          | () -> (
              let oc = Unix.out_channel_of_descr sock in
              try
                output_string oc (fingerprint ^ "\n");
                flush oc;
                Ok ()
              with Sys_error msg -> Error (Send_failed msg)))

(* Core and the watchdog are two independently-started processes with
   no guaranteed ordering — whichever starts first will find nobody
   listening yet on the very first attempt. A short, bounded retry
   loop is a genuine operational necessity here, not a test-only
   convenience; a one-time bootstrap step failing outright just
   because it happened to run half a second before core finished its
   own startup would be a real, avoidable reliability gap. *)
let send_fingerprint_with_retry ~(socket_path : string)
    ?(max_attempts = 50) ?(delay_seconds = 0.1) (fingerprint : string) :
    (unit, error) result =
  let rec go attempt last_error =
    if attempt >= max_attempts then Error last_error
    else
      match send_fingerprint ~socket_path fingerprint with
      | Ok () -> Ok ()
      | Error e ->
          Unix.sleepf delay_seconds;
          go (attempt + 1) e
  in
  go 0 (Connect_failed "no attempts made")
