(* §2.4: the watchdog's own per-install OpenPGP keypair — generated
   once on first start, reused on every start after that. Never
   shipped in the installer (per-machine, matching the per-install
   pattern the rest of this project already uses for the core's own
   data-encryption key, §3.8), and — critically — never regenerated
   silently once it exists: a new key would carry a new fingerprint,
   orphaning whatever core already pinned via the bootstrap handoff
   (Bootstrap, fossh_admin::watchdog_pin), which itself already
   refuses to accept a second, different fingerprint over an existing
   pin. Silently regenerating the watchdog's own key would make that
   protection pointless by invalidating its own premise before the
   handoff even runs. *)

let gpg_path = "/usr/bin/gpg"

type error =
  | Generate_failed of string
  | List_failed of string
  | Fingerprint_not_found

let describe_error = function
  | Generate_failed e -> Printf.sprintf "generating watchdog keypair: %s" e
  | List_failed e -> Printf.sprintf "listing watchdog keys: %s" e
  | Fingerprint_not_found ->
      "generated a key but could not read back its fingerprint"

let run_gpg ~(gnupghome : string) (args : string list) : (string, string) result
    =
  Subprocess.run ~prog:gpg_path
    ~argv:(Array.of_list ("gpg" :: "--batch" :: "--homedir" :: gnupghome :: args))
    ~stdin_content:""

(* `--with-colons`'s `fpr:` line: `fpr:::::::::<FINGERPRINT>:` — the
   fingerprint is the 10th colon-separated field. Verified directly
   against real `gpg --with-colons` output (not guessed at) while
   building the test suite this module is now extracted from — see
   ADR-0040. *)
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

(* Idempotent: returns the existing key's fingerprint if [gnupghome]
   already has one, generating a fresh Ed25519 signing-only key only
   if it doesn't. Never regenerates over an existing key — see this
   module's header comment. *)
let ensure_keypair ~(gnupghome : string) ~(uid : string) :
    (string, error) result =
  (try Unix.mkdir gnupghome 0o700
   with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
  match existing_fingerprint ~gnupghome with
  | Error e -> Error e
  | Ok (Some fpr) -> Ok fpr
  | Ok None -> (
      match
        run_gpg ~gnupghome
          [
            "--passphrase"; ""; "--quick-generate-key"; uid; "ed25519"; "sign";
            "0";
          ]
      with
      | Error e -> Error (Generate_failed e)
      | Ok _ -> (
          match existing_fingerprint ~gnupghome with
          | Error e -> Error e
          | Ok (Some fpr) -> Ok fpr
          | Ok None -> Error Fingerprint_not_found))
