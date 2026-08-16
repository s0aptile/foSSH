let sha256_path = "/usr/bin/sha256sum"

let sha256_hex (path : string) : (string, string) result =
  if not (Sys.file_exists path) then
    Error (Printf.sprintf "missing file: %s" path)
  else
    match
      Subprocess.run ~prog:sha256_path
        ~argv:[| "sha256sum"; "--"; path |]
        ~stdin_content:""
    with
    | Error e -> Error e
    | Ok output -> (

        match String.index_opt output ' ' with
        | Some i when i = 64 -> Ok (String.sub output 0 64)
        | _ ->
            Error (Printf.sprintf "unexpected sha256sum output for %s" path))

type entry = { path : string; expected_sha256 : string }

let hash_all (paths : string list) : (entry list, string) result =
  let rec go acc = function
    | [] -> Ok (List.rev acc)
    | p :: rest -> (
        match sha256_hex p with
        | Ok hash -> go ({ path = p; expected_sha256 = hash } :: acc) rest
        | Error e -> Error e)
  in
  go [] paths

let render (entries : entry list) : string =
  entries
  |> List.map (fun e -> Printf.sprintf "%s  %s" e.expected_sha256 e.path)
  |> String.concat "\n"
  |> fun body -> body ^ "\n"

let parse (body : string) : (entry list, string) result =
  let lines =
    String.split_on_char '\n' body |> List.filter (fun l -> l <> "")
  in
  let parse_line line =
    if String.length line > 66 && String.sub line 64 2 = "  " then
      let path = String.sub line 66 (String.length line - 66) in
      if Filename.is_relative path then
        Error (Printf.sprintf "manifest path must be absolute: %S" path)
      else Ok { expected_sha256 = String.sub line 0 64; path }
    else Error (Printf.sprintf "malformed manifest line: %S" line)
  in
  let rec go acc = function
    | [] -> Ok (List.rev acc)
    | l :: rest -> (
        match parse_line l with
        | Ok e -> go (e :: acc) rest
        | Error e -> Error e)
  in
  go [] lines

let gpg_path = "/usr/bin/gpg"

let sign ~(gnupghome : string) ~(key_id : string) ~(passphrase : string) (content : string) :
    (string, string) result =
  Subprocess.run ~prog:gpg_path
    ~argv:
      [|
        "gpg"; "--batch"; "--pinentry-mode"; "loopback"; "--passphrase"; passphrase;
        "--homedir"; gnupghome; "--local-user"; key_id; "--clearsign";
      |]
    ~stdin_content:content

let generate_and_sign ~(gnupghome : string) ~(key_id : string) ~(passphrase : string)
    (paths : string list) : (string, string) result =
  match hash_all paths with
  | Error e -> Error e
  | Ok entries -> sign ~gnupghome ~key_id ~passphrase (render entries)

let verify_and_extract ~(gnupghome : string) ~(expected_key_fingerprint : string)
    (clearsigned : string) : (string, string) result =
  try
    Tempfile.with_contents "" (fun status_path ->
        match
          Subprocess.run ~prog:gpg_path
            ~argv:
              [|
                "gpg"; "--batch"; "--homedir"; gnupghome; "--status-file";
                status_path; "--decrypt";
              |]
            ~stdin_content:clearsigned
        with
        | Error e -> Error e
        | Ok body -> (
            match Gpg_status.parse (Fileutil.read_all_bytes status_path) with
            | Good_signature_by key_id ->
                if
                  Gpg_status.key_id_matches_fingerprint ~key_id
                    ~fingerprint:expected_key_fingerprint
                then Ok body
                else Error "clearsign verified against an unexpected key"
            | Revoked_key -> Error "manifest signed by a revoked key"
            | Expired_key -> Error "manifest signed by an expired key"
            | No_good_signature -> Error "no good signature on manifest"))
  with Sys_error msg -> Error (Printf.sprintf "could not read gpg status output: %s" msg)

type check_result =
  | Ok_manifest of entry list
  | Signature_invalid of string
  | Hash_mismatch of { path : string; expected : string; actual : string }
  | Program_not_covered of string

  | Program_replaced of string
  | Io_error of string

type file_identity = { dev : int; ino : int; size : int; mtime : float }

let identity_of (path : string) : (file_identity, string) result =
  match Unix.stat path with
  | s ->
      Ok
        {
          dev = s.Unix.st_dev;
          ino = s.Unix.st_ino;
          size = s.Unix.st_size;
          mtime = s.Unix.st_mtime;
        }
  | exception Unix.Unix_error (e, fn, _) ->
      Error (Printf.sprintf "%s: %s: %s" path fn (Unix.error_message e))

let check ~(gnupghome : string) ~(expected_key_fingerprint : string)
    ~(program : string) ~(clearsigned_manifest : string) : check_result =
  match
    verify_and_extract ~gnupghome ~expected_key_fingerprint clearsigned_manifest
  with
  | Error e -> Signature_invalid e
  | Ok body -> (
      match parse body with
      | Error e -> Io_error e
      | Ok [] -> Program_not_covered program
      | Ok entries ->
          if not (List.exists (fun e -> e.path = program) entries) then
            Program_not_covered program
          else
            let rec check_entries = function
              | [] -> Ok_manifest entries
              | e :: rest -> (
                  match sha256_hex e.path with
                  | Error err -> Io_error err
                  | Ok actual ->
                      if actual = e.expected_sha256 then check_entries rest
                      else
                        Hash_mismatch
                          { path = e.path; expected = e.expected_sha256; actual })
            in
            check_entries entries)

type read_error = Missing | Not_a_file | Too_large of int | Unreadable of string

let max_manifest_bytes = 1 * 1024 * 1024

let describe_read_error = function
  | Missing -> "manifest file does not exist"
  | Not_a_file -> "manifest path is not a regular file"
  | Too_large n -> Printf.sprintf "manifest file too large (%d bytes, cap %d)" n max_manifest_bytes
  | Unreadable msg -> Printf.sprintf "could not read manifest: %s" msg

let read_from_path (path : string) : (string, read_error) result =
  match Unix.stat path with
  | exception Unix.Unix_error (Unix.ENOENT, _, _) -> Error Missing
  | exception Unix.Unix_error (e, _, _) -> Error (Unreadable (Unix.error_message e))
  | { Unix.st_kind = Unix.S_REG; st_size; _ } when st_size > max_manifest_bytes ->
      Error (Too_large st_size)
  | { Unix.st_kind = Unix.S_REG; _ } -> (
      try Ok (Fileutil.read_all_bytes path)
      with Sys_error msg -> Error (Unreadable msg))
  | _ -> Error Not_a_file
