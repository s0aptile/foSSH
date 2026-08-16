let gpg_path = "/usr/bin/gpg"

type error =
  | Generate_failed of string
  | List_failed of string
  | Fingerprint_not_found
  | Passphrase_io_error of string

let describe_error = function
  | Generate_failed e -> Printf.sprintf "generating watchdog keypair: %s" e
  | List_failed e -> Printf.sprintf "listing watchdog keys: %s" e
  | Fingerprint_not_found ->
      "generated a key but could not read back its fingerprint"
  | Passphrase_io_error e -> Printf.sprintf "watchdog keypair passphrase I/O error: %s" e

let passphrase_path (gnupghome : string) : string = Filename.concat gnupghome "passphrase"

let ensure_passphrase (gnupghome : string) : (string, error) result =
  let path = passphrase_path gnupghome in
  if Sys.file_exists path then
    try Ok (Fileutil.read_all_bytes path) with Sys_error msg -> Error (Passphrase_io_error msg)
  else
    try
      let passphrase = Nonce.generate () in
      let fd = Unix.openfile path [ Unix.O_WRONLY; Unix.O_CREAT; Unix.O_EXCL ] 0o600 in
      let oc = Unix.out_channel_of_descr fd in
      output_string oc passphrase;
      close_out oc;
      Ok passphrase
    with
    | Unix.Unix_error (e, fn, _) ->
        Error (Passphrase_io_error (Printf.sprintf "%s: %s" fn (Unix.error_message e)))
    | Sys_error msg -> Error (Passphrase_io_error msg)

let run_gpg ~(gnupghome : string) (args : string list) : (string, string) result
    =
  Subprocess.run ~prog:gpg_path
    ~argv:(Array.of_list ("gpg" :: "--batch" :: "--homedir" :: gnupghome :: args))
    ~stdin_content:""

let extract_fingerprint (with_colons_listing : string) : string option =
  String.split_on_char '\n' with_colons_listing
  |> List.find_map (fun line ->
         if String.length line > 4 && String.sub line 0 4 = "fpr:" then
           match String.split_on_char ':' line with
           | _ :: _ :: _ :: _ :: _ :: _ :: _ :: _ :: _ :: fpr :: _ -> Some fpr
           | _ -> None
         else None)

let existing_fingerprint ~(gnupghome : string) : (string option, error) result
    =
  match run_gpg ~gnupghome [ "--with-colons"; "--list-secret-keys" ] with
  | Error e -> Error (List_failed e)
  | Ok listing -> Ok (extract_fingerprint listing)

let ensure_keypair ~(gnupghome : string) ~(uid : string) :
    (string, error) result =
  (try Unix.mkdir gnupghome 0o700
   with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
  match existing_fingerprint ~gnupghome with
  | Error e -> Error e
  | Ok (Some fpr) -> Ok fpr
  | Ok None -> (
      match ensure_passphrase gnupghome with
      | Error e -> Error e
      | Ok passphrase -> (
          match
            run_gpg ~gnupghome
              [
                "--passphrase"; passphrase; "--quick-generate-key"; uid; "ed25519";
                "sign"; "0";
              ]
          with
          | Error e -> Error (Generate_failed e)
          | Ok _ -> (
              match existing_fingerprint ~gnupghome with
              | Error e -> Error e
              | Ok (Some fpr) -> Ok fpr
              | Ok None -> Error Fingerprint_not_found)))
