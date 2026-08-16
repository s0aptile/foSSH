let sig_end_marker = "-----END PGP SIGNATURE-----"
let max_signature_len = 8192

let setup_command_prefix = "SETUP "
let max_setup_command_len = 4096
let public_key_end_marker = "-----END PGP PUBLIC KEY BLOCK-----"
let max_public_key_len = 262144

let default_connection_timeout_seconds = 10.0

let log fmt = Printf.eprintf ("fossh-watchdog(auth): " ^^ fmt ^^ "\n%!")

type config = { socket_path : string; operator_key_dir : string }

let send_line (oc : out_channel) (line : string) : (unit, string) result =
  match
    output_string oc line;
    output_char oc '\n';
    flush oc
  with
  | () -> Ok ()
  | exception Sys_error msg -> Error msg
  | exception Sys_blocked_io -> Error "timed out"

let contains_substring ~(needle : string) (haystack : string) : bool =
  let hn = String.length needle and hh = String.length haystack in
  let rec go i = (i + hn <= hh) && (String.sub haystack i hn = needle || go (i + 1)) in
  hn = 0 || go 0

let read_until ?(seed = "") (conn : Unix.file_descr) ~(deadline : float) ~(needle : string)
    ~(max_len : int) : (string, [ `Unterminated | `Recv_failed of string ]) result =
  let needle_len = String.length needle in
  let buf = Buffer.create 512 in
  Buffer.add_string buf seed;
  let chunk = Bytes.create 256 in

  let found_in_tail ~(scanned_len : int) : bool =
    let scan_from = max 0 (scanned_len - needle_len + 1) in
    let tail = Buffer.sub buf scan_from (Buffer.length buf - scan_from) in
    needle_len = 0 || contains_substring ~needle tail
  in
  let rec go ~(scanned_len : int) =
    if found_in_tail ~scanned_len then Ok (Buffer.contents buf)
    else if Unix.gettimeofday () > deadline then Error `Unterminated
    else if Buffer.length buf > max_len then Error `Unterminated
    else
      match Unix.read conn chunk 0 (Bytes.length chunk) with
      | exception Unix.Unix_error ((Unix.EAGAIN | Unix.EWOULDBLOCK), _, _) -> Error `Unterminated
      | exception Unix.Unix_error (e, fn, _) ->
          Error (`Recv_failed (Printf.sprintf "%s: %s" fn (Unix.error_message e)))
      | 0 -> Error `Unterminated
      | n ->
          let prev_len = Buffer.length buf in
          Buffer.add_subbytes buf chunk 0 n;
          go ~scanned_len:prev_len
  in
  go ~scanned_len:0

let read_signature_block (conn : Unix.file_descr) ~(deadline : float) :
    (string, [ `Unterminated | `Recv_failed of string ]) result =
  read_until conn ~deadline ~needle:sig_end_marker ~max_len:max_signature_len

let up_to_first_newline (s : string) : string =
  match String.index_opt s '\n' with Some i -> String.sub s 0 i | None -> s

let after_first_newline (s : string) : string =
  match String.index_opt s '\n' with
  | Some i -> String.sub s (i + 1) (String.length s - i - 1)
  | None -> ""

let enroll_failure_code = function
  | Operator_key.Already_enrolled -> "already_enrolled"
  | Operator_key.Import_failed _ -> "invalid_key"
  | Operator_key.Fingerprint_not_found -> "invalid_key"
  | Operator_key.Multiple_keys_imported -> "multiple_keys"
  | Operator_key.Io_error _ -> "internal_error"

let handle_setup_flow (conn : Unix.file_descr) (oc : out_channel) ~(operator_key_dir : string)
    ~(deadline : float) : unit =
  match read_until conn ~deadline ~needle:"\n" ~max_len:max_setup_command_len with
  | Error `Unterminated -> ()
  | Error (`Recv_failed msg) -> log "could not read setup command: %s" msg
  | Ok raw -> (
      let line = up_to_first_newline raw in

      let leftover = after_first_newline raw in
      let prefix_len = String.length setup_command_prefix in
      if String.length line <= prefix_len || String.sub line 0 prefix_len <> setup_command_prefix then
        ignore (send_line oc "SETUP_DENIED")
      else
        let submitted = String.sub line prefix_len (String.length line - prefix_len) in
        if not (Setup_token.verify submitted) then ignore (send_line oc "SETUP_DENIED")
        else
          match send_line oc "SETUP_OK" with
          | Error msg -> log "could not send SETUP_OK: %s" msg
          | Ok () -> (
              match
                read_until conn ~deadline ~needle:public_key_end_marker ~max_len:max_public_key_len
                  ~seed:leftover
              with
              | Error `Unterminated -> ignore (send_line oc "ENROLL_FAILED unterminated_key")
              | Error (`Recv_failed msg) -> log "could not read public key material: %s" msg
              | Ok public_key_armored -> (
                  match Operator_key.enroll ~dir:operator_key_dir public_key_armored with
                  | Error e ->
                      log "setup enrollment attempt failed: %s" (Operator_key.describe_error e);
                      ignore (send_line oc (Printf.sprintf "ENROLL_FAILED %s" (enroll_failure_code e)))
                  | Ok fingerprint ->
                      (match Setup_token.burn () with
                      | Ok () -> ()
                      | Error e ->
                          log "enrollment succeeded but burning the setup token failed: %s"
                            (Setup_token.describe_error e));
                      ignore (send_line oc (Printf.sprintf "ENROLLED %s" fingerprint)))))

let handle_one_connection (conn : Unix.file_descr) ~(operator_key_dir : string) ~(deadline : float) : unit =
  let oc = Unix.out_channel_of_descr conn in
  match Operator_key.enrolled_fingerprint ~dir:operator_key_dir with
  | Error e -> log "could not read enrolled operator key: %s" (Operator_key.describe_error e)
  | Ok None -> (
      match send_line oc "NOT_ENROLLED" with
      | Error msg -> log "could not send NOT_ENROLLED: %s" msg
      | Ok () -> handle_setup_flow conn oc ~operator_key_dir ~deadline)
  | Ok (Some expected_key_fingerprint) -> (
      let nonce = Nonce.generate () in
      match send_line oc (Printf.sprintf "NONCE %s" nonce) with
      | Error msg -> log "could not send nonce: %s" msg
      | Ok () -> (
          match read_signature_block conn ~deadline with
          | Error `Unterminated -> ignore (send_line oc "DENIED")
          | Error (`Recv_failed msg) -> log "could not read signature: %s" msg
          | Ok signature_armored ->
              let gnupghome = Operator_key.gnupghome_of ~dir:operator_key_dir in
              let verified =
                Auth.verify_signature ~gnupghome ~expected_key_fingerprint ~data:nonce
                  ~signature_binary:signature_armored
              in

              let reply =
                if not verified then "DENIED"
                else
                  match Session.issue () with
                  | token -> Printf.sprintf "OK %s" token
                  | exception Session.Too_many_sessions ->
                      log "refusing a new session: %d already live" (Session.live_count ());
                      "DENIED"
              in
              ignore (send_line oc reply)))

let rec accept_loop ~(connection_timeout_seconds : float) (config : config) (listener : Unix.file_descr) :
    unit =
  (match Unix.accept listener with
  | exception Unix.Unix_error (e, fn, _) ->
      log "accept failed: %s: %s" fn (Unix.error_message e);
      Unix.sleepf 0.5
  | conn, _ ->
      Fun.protect
        ~finally:(fun () -> try Unix.close conn with Unix.Unix_error _ -> ())
        (fun () ->
          try
            Unix.setsockopt_float conn Unix.SO_RCVTIMEO connection_timeout_seconds;
            Unix.setsockopt_float conn Unix.SO_SNDTIMEO connection_timeout_seconds;
            let deadline = Unix.gettimeofday () +. connection_timeout_seconds in
            handle_one_connection conn ~operator_key_dir:config.operator_key_dir ~deadline
          with e -> log "connection handler raised: %s" (Printexc.to_string e)));
  accept_loop ~connection_timeout_seconds config listener

let run ?(connection_timeout_seconds = default_connection_timeout_seconds) (config : config) :
    (unit, string) result =

  Sys.set_signal Sys.sigpipe Sys.Signal_ignore;
  (try Sys.remove config.socket_path with Sys_error _ -> ());
  match Unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 with
  | exception Unix.Unix_error (e, fn, _) -> Error (Printf.sprintf "%s: %s" fn (Unix.error_message e))
  | sock -> (
      match

        let old_umask = Unix.umask 0o077 in
        let bind_result =
          try
            Unix.bind sock (Unix.ADDR_UNIX config.socket_path);
            Ok ()
          with Unix.Unix_error _ as e -> Error e
        in
        let (_ : int) = Unix.umask old_umask in
        (match bind_result with Ok () -> () | Error e -> raise e);
        Unix.chmod config.socket_path 0o600;
        Unix.listen sock 16
      with
      | () -> Ok (accept_loop ~connection_timeout_seconds config sock)
      | exception Unix.Unix_error (e, fn, _) ->
          (try Unix.close sock with Unix.Unix_error _ -> ());
          Error (Printf.sprintf "%s: %s" fn (Unix.error_message e)))
