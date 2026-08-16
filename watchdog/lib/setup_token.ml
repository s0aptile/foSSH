type live_token = { path : string; hash : string }

let state : live_token option ref = ref None
let state_mutex = Mutex.create ()

type error = Io_error of string | Hash_error of string

let describe_error = function
  | Io_error e -> Printf.sprintf "setup-token I/O error: %s" e
  | Hash_error e -> Printf.sprintf "setup-token hashing error: %s" e

let sha256_hex_of_string (s : string) : (string, string) result =
  try Tempfile.with_contents s (fun path -> Manifest.sha256_hex path)
  with Sys_error msg -> Error msg

let hash_of_file (path : string) : (string, error) result =
  match Fileutil.read_all_bytes path with
  | exception Sys_error msg -> Error (Io_error msg)
  | contents -> (
      match sha256_hex_of_string (String.trim contents) with
      | Ok hash -> Ok hash
      | Error e -> Error (Hash_error e))

let recover ~(token_path : string) : (unit, error) result =
  match hash_of_file token_path with
  | Error e -> Error e
  | Ok hash ->
      Mutex.protect state_mutex (fun () -> state := Some { path = token_path; hash });
      Ok ()

let generate_fresh ~(token_path : string) : (unit, error) result =
  (try Unix.mkdir (Filename.dirname token_path) 0o700
   with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
  try
    let plaintext = Nonce.generate () in
    let fd = Unix.openfile token_path [ Unix.O_WRONLY; Unix.O_CREAT; Unix.O_EXCL ] 0o600 in
    let oc = Unix.out_channel_of_descr fd in
    output_string oc plaintext;
    close_out oc;
    match sha256_hex_of_string plaintext with
    | Ok hash ->
        Mutex.protect state_mutex (fun () -> state := Some { path = token_path; hash });
        Ok ()
    | Error e -> Error (Hash_error e)
  with
  | Unix.Unix_error (e, fn, _) -> Error (Io_error (Printf.sprintf "%s: %s" fn (Unix.error_message e)))
  | Sys_error msg -> Error (Io_error msg)

let ensure ~(token_path : string) ~(operator_key_dir : string) : (unit, error) result =
  match Operator_key.enrolled_fingerprint ~dir:operator_key_dir with
  | Error e -> Error (Io_error (Operator_key.describe_error e))
  | Ok (Some _) ->
      Mutex.protect state_mutex (fun () -> state := None);
      Ok ()
  | Ok None -> if Sys.file_exists token_path then recover ~token_path else generate_fresh ~token_path

let verify (submitted : string) : bool =
  match Mutex.protect state_mutex (fun () -> !state) with
  | None -> false
  | Some { hash; _ } -> (
      match sha256_hex_of_string submitted with
      | Error _ -> false
      | Ok submitted_hash -> Nonce.constant_time_equal submitted_hash hash)

let burn () : (unit, error) result =
  match Mutex.protect state_mutex (fun () ->
            let current = !state in
            state := None;
            current)
  with
  | None -> Ok ()
  | Some { path; _ } -> (
      match Unix.unlink path with
      | () -> Ok ()
      | exception Unix.Unix_error (Unix.ENOENT, _, _) -> Ok ()
      | exception Unix.Unix_error (e, fn, _) ->
          Error (Io_error (Printf.sprintf "%s: %s" fn (Unix.error_message e))))
