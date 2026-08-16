let max_cert_pem_len = 8192
let cert_pem_end_marker = "-----END CERTIFICATE-----"

type error =
  | Connect_failed of string
  | Send_failed of string
  | Recv_failed of string
  | Peer_cert_too_large of int
  | Peer_cert_unterminated

let describe_error = function
  | Connect_failed e -> Printf.sprintf "could not connect to core: %s" e
  | Send_failed e -> Printf.sprintf "could not send handoff to core: %s" e
  | Recv_failed e -> Printf.sprintf "could not read core's reply: %s" e
  | Peer_cert_too_large n ->
      Printf.sprintf "core's certificate reply exceeded the %d-byte cap (got %d)" max_cert_pem_len n
  | Peer_cert_unterminated ->
      "core's certificate reply ended before a terminating \"-----END CERTIFICATE-----\" line"

let ensure_trailing_newline (s : string) : string =
  if String.length s > 0 && s.[String.length s - 1] = '\n' then s else s ^ "\n"

let read_pem_block (ic : in_channel) : (string, error) result =
  let buf = Buffer.create 512 in
  let rec go () =
    match input_line ic with
    | exception End_of_file -> Error Peer_cert_unterminated
    | exception Sys_error msg -> Error (Recv_failed msg)
    | line -> (
        Buffer.add_string buf line;
        Buffer.add_char buf '\n';
        if Buffer.length buf > max_cert_pem_len then Error (Peer_cert_too_large (Buffer.length buf))
        else if line = cert_pem_end_marker then Ok (Buffer.contents buf)
        else go ())
  in
  go ()

let send_handoff ~(socket_path : string) ~(fingerprint : string) ~(cert_pem : string) :
    (string, error) result =
  Sys.set_signal Sys.sigpipe Sys.Signal_ignore;
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
              match
                output_string oc (fingerprint ^ "\n");
                output_string oc (ensure_trailing_newline cert_pem);
                flush oc
              with
              | exception Sys_error msg -> Error (Send_failed msg)
              | () ->
                  let ic = Unix.in_channel_of_descr sock in
                  read_pem_block ic))

let send_handoff_with_retry ~(socket_path : string) ?(max_attempts = 50) ?(delay_seconds = 0.1)
    ~(fingerprint : string) (cert_pem : string) : (string, error) result =
  let rec go attempt last_error =
    if attempt >= max_attempts then Error last_error
    else
      match send_handoff ~socket_path ~fingerprint ~cert_pem with
      | Ok core_cert_pem -> Ok core_cert_pem
      | Error e ->
          Unix.sleepf delay_seconds;
          go (attempt + 1) e
  in
  go 0 (Connect_failed "no attempts made")
