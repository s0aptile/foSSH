let gpg_path = "/usr/bin/gpg"

type error =
  | Already_enrolled
  | Import_failed of string
  | Fingerprint_not_found
  | Multiple_keys_imported
  | Io_error of string

let describe_error = function
  | Already_enrolled -> "an operator key is already enrolled"
  | Import_failed e -> Printf.sprintf "importing operator public key: %s" e
  | Fingerprint_not_found -> "imported a key but could not read back its fingerprint"
  | Multiple_keys_imported ->
      "the supplied material imported as more than one key; enroll exactly one"
  | Io_error e -> Printf.sprintf "operator key I/O error: %s" e

let gnupghome_of ~(dir : string) : string = Filename.concat dir "operator-gnupghome"
let fingerprint_pin_path ~(dir : string) : string = Filename.concat dir "operator-fingerprint.pin"

let run_gpg ~(gnupghome : string) (args : string list) : (string, string) result =
  Subprocess.run ~extra_env:[ ("GNUPGHOME", gnupghome) ] ~prog:gpg_path
    ~argv:(Array.of_list ("gpg" :: "--batch" :: "--homedir" :: gnupghome :: args))
    ~stdin_content:"" ()

let extract_single_fingerprint (with_colons_listing : string) : (string, error) result =
  let is_record_type prefix line = String.length line >= 4 && String.sub line 0 4 = prefix in
  let rec collect_primary_fprs acc expecting_primary_fpr = function
    | [] -> List.rev acc
    | line :: rest ->
        if is_record_type "pub:" line then collect_primary_fprs acc true rest
        else if is_record_type "sub:" line then collect_primary_fprs acc false rest
        else if expecting_primary_fpr && is_record_type "fpr:" line then (
          match String.split_on_char ':' line with
          | _ :: _ :: _ :: _ :: _ :: _ :: _ :: _ :: _ :: fpr :: _ ->
              collect_primary_fprs (fpr :: acc) false rest
          | _ -> collect_primary_fprs acc false rest)
        else collect_primary_fprs acc expecting_primary_fpr rest
  in
  match collect_primary_fprs [] false (String.split_on_char '\n' with_colons_listing) with
  | [] -> Error Fingerprint_not_found
  | [ fpr ] -> Ok fpr
  | _ :: _ :: _ -> Error Multiple_keys_imported

let persist_fingerprint (path : string) (fingerprint : string) : (unit, error) result =
  let tmp_path = Printf.sprintf "%s.tmp-%d-%s" path (Unix.getpid ()) (Nonce.generate ()) in
  match
    let fd = Unix.openfile tmp_path [ Unix.O_WRONLY; Unix.O_CREAT; Unix.O_EXCL ] 0o600 in
    Fun.protect
      ~finally:(fun () -> try Sys.remove tmp_path with Sys_error _ -> ())
      (fun () ->
        let oc = Unix.out_channel_of_descr fd in
        output_string oc fingerprint;
        close_out oc;
        Unix.link tmp_path path)
  with
  | () -> Ok ()
  | exception Unix.Unix_error (Unix.EEXIST, "link", _) -> Error Already_enrolled
  | exception Unix.Unix_error (e, fn, _) ->
      Error (Io_error (Printf.sprintf "%s: %s" fn (Unix.error_message e)))
  | exception Sys_error msg -> Error (Io_error msg)

let rec rm_rf (path : string) : unit =
  match Unix.((lstat path).st_kind) with
  | Unix.S_DIR ->
      (try Sys.readdir path |> Array.iter (fun name -> rm_rf (Filename.concat path name))
       with Sys_error _ -> ());
      (try Unix.rmdir path with Unix.Unix_error _ -> ())
  | _ -> ( try Sys.remove path with Sys_error _ -> ())
  | exception Unix.Unix_error (Unix.ENOENT, _, _) -> ()

let enroll ~(dir : string) (public_key_armored : string) : (string, error) result =
  if Sys.file_exists (fingerprint_pin_path ~dir) then Error Already_enrolled
  else
    match
      (try Unix.mkdir dir 0o700 with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
      let tmp_gnupghome =
        Filename.concat dir
          (Printf.sprintf "operator-gnupghome.tmp-%d-%s" (Unix.getpid ()) (Nonce.generate_n 8))
      in
      rm_rf tmp_gnupghome;
      Unix.mkdir tmp_gnupghome 0o700;
      tmp_gnupghome
    with
    | exception Unix.Unix_error (e, fn, _) ->
        Error (Io_error (Printf.sprintf "%s: %s" fn (Unix.error_message e)))
    | tmp_gnupghome -> (

    try
    Fun.protect
      ~finally:(fun () -> if Sys.file_exists tmp_gnupghome then rm_rf tmp_gnupghome)
      (fun () ->
        Tempfile.with_contents public_key_armored (fun key_path ->
            match run_gpg ~gnupghome:tmp_gnupghome [ "--import"; key_path ] with
            | Error e -> Error (Import_failed e)
            | Ok _ -> (
                match run_gpg ~gnupghome:tmp_gnupghome [ "--with-colons"; "--list-keys" ] with
                | Error e -> Error (Import_failed e)
                | Ok listing -> (
                    match extract_single_fingerprint listing with
                    | Error e -> Error e
                    | Ok fingerprint -> (
                        match persist_fingerprint (fingerprint_pin_path ~dir) fingerprint with
                        | Error e -> Error e
                        | Ok () -> (

                            let gnupghome = gnupghome_of ~dir in
                            match
                              rm_rf gnupghome;
                              Unix.rename tmp_gnupghome gnupghome
                            with
                            | () -> Ok fingerprint
                            | exception Unix.Unix_error (e, fn, _) ->
                                Error (Io_error (Printf.sprintf "%s: %s" fn (Unix.error_message e)))))))))
    with Sys_error msg -> Error (Io_error msg))

let enrolled_fingerprint ~(dir : string) : (string option, error) result =
  let path = fingerprint_pin_path ~dir in
  if not (Sys.file_exists path) then Ok None
  else
    match Fileutil.read_all_bytes path with
    | contents -> Ok (Some contents)
    | exception Sys_error msg -> Error (Io_error msg)
