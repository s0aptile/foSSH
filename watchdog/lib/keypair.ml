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
  | Passphrase_io_error of string

let describe_error = function
  | Generate_failed e -> Printf.sprintf "generating watchdog keypair: %s" e
  | List_failed e -> Printf.sprintf "listing watchdog keys: %s" e
  | Fingerprint_not_found ->
      "generated a key but could not read back its fingerprint"
  | Passphrase_io_error e -> Printf.sprintf "watchdog keypair passphrase I/O error: %s" e

(* This key used to be generated with an empty passphrase (`gpg
   --passphrase ""`) — real, but undocumented anywhere public until an
   adversarial-review-style question ("is this passphrase actually
   protected?") traced it back to this exact line. Fixed by generating
   a real, high-entropy passphrase and persisting it here, mode 0600,
   alongside the keypair it protects. Not burned after first use, the
   way §2.6's setup token is: that token's whole job ends the moment
   setup completes; this passphrase protects a key meant to persist
   for the install's entire lifetime, and is needed again every time
   an operator re-signs the tamper-detection manifest (after an
   update, say), not just once at generation time. Routine, unattended
   startup is unaffected either way: `Manifest.check` (called on every
   restart) only ever reads the *public* key, which `gpg --verify`
   does without touching a passphrase at all — only signing needs one,
   and signing is an operator-initiated action, never something this
   process does to itself automatically. *)
let passphrase_path (gnupghome : string) : string = Filename.concat gnupghome "passphrase"

(* Idempotent, the same shape as `ensure_keypair` itself: returns the
   existing passphrase if one is already on disk, generating and
   persisting a fresh one only if not. Safe to call repeatedly (e.g.
   once to protect a freshly generated key, then again later whenever
   a caller needs to sign something) — the second and every later call
   just reads the file back. *)
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
