(* Shared test scaffolding: fresh, throwaway GNUPGHOMEs with real
   Ed25519 keys generated in them — every test in this suite exercises
   the real `gpg`/`gpgv` binaries against real keys, not a mock or a
   hand-rolled stand-in for OpenPGP semantics. *)

open Fossh_watchdog_lib

let mkdtemp () =
  let base = Filename.temp_file "fossh-watchdog-test-" "" in
  Sys.remove base;
  Unix.mkdir base 0o700;
  base

let rec rm_rf path =
  match Unix.((lstat path).st_kind) with
  | Unix.S_DIR ->
      Sys.readdir path
      |> Array.iter (fun name -> rm_rf (Filename.concat path name));
      Unix.rmdir path
  | _ -> Sys.remove path
  | exception Unix.Unix_error (Unix.ENOENT, _, _) -> ()

let run_gpg_ok ~(gnupghome : string) (args : string list) : string =
  match
    Subprocess.run ~prog:"/usr/bin/gpg"
      ~argv:(Array.of_list ("gpg" :: "--batch" :: "--homedir" :: gnupghome :: args))
      ~stdin_content:""
  with
  | Ok out -> out
  | Error e -> failwith ("gpg " ^ String.concat " " args ^ " failed: " ^ e)

type key = { gnupghome : string; fingerprint : string }

(* Delegates to the real product code (Keypair.ensure_keypair) rather
   than duplicating gpg key-generation logic here — every test that
   calls [generate_key] (nearly all of them, across every test file in
   this suite) now exercises the exact function real watchdog startup
   will call, not a parallel test-only reimplementation of it. *)
let generate_key ?(uid = "test <test@example.invalid>") () : key =
  let gnupghome = mkdtemp () in
  match Keypair.ensure_keypair ~gnupghome ~uid with
  | Ok fingerprint -> { gnupghome; fingerprint }
  | Error e -> failwith (Keypair.describe_error e)

let export_pubkey (k : key) : string =
  run_gpg_ok ~gnupghome:k.gnupghome [ "--export"; k.fingerprint ]

(* Imports [pubkey_binary] into a fresh homedir and returns its path
   (caller must [rm_rf] it) — used wherever a test needs a verifier
   whose keyring state is independent of the signer's own homedir,
   e.g. "this verifier only ever saw the already-revoked key". *)
let fresh_homedir_with_key (pubkey_binary : string) : string =
  let homedir = mkdtemp () in
  Tempfile.with_contents pubkey_binary (fun path ->
      let (_ : string) = run_gpg_ok ~gnupghome:homedir [ "--import"; path ] in
      ());
  homedir

(* Revokes [k]'s key in place (its own homedir). GnuPG prefixes the
   auto-generated revocation certificate's armor header with a colon
   (`:-----BEGIN PGP...`) specifically so it can never be imported by
   accident — real, deliberate GnuPG safety behavior, confirmed by
   reading the certificate file's own explanatory comment, not assumed
   — so this strips exactly that one leading colon before importing,
   the same manual step a human following GnuPG's own instructions
   would take. *)
let revoke_in_place (k : key) : unit =
  let rev_path = Filename.concat k.gnupghome "openpgp-revocs.d" in
  let rev_file =
    Sys.readdir rev_path |> Array.to_list
    |> List.find (fun f -> Filename.check_suffix f ".rev")
    |> Filename.concat rev_path
  in
  let armored = Fileutil.read_all_bytes rev_file in
  let cleaned =
    String.split_on_char '\n' armored
    |> List.map (fun line ->
           if String.length line > 0 && line.[0] = ':' then
             String.sub line 1 (String.length line - 1)
           else line)
    |> String.concat "\n"
  in
  Tempfile.with_contents cleaned (fun path ->
      let (_ : string) = run_gpg_ok ~gnupghome:k.gnupghome [ "--import"; path ] in
      ())

let detach_sign (k : key) (data : string) : string =
  Tempfile.with_contents data (fun data_path ->
      let sig_path = Filename.temp_file "fossh-watchdog-test-" ".sig" in
      Fun.protect
        ~finally:(fun () -> try Sys.remove sig_path with Sys_error _ -> ())
        (fun () ->
          let (_ : string) =
            run_gpg_ok ~gnupghome:k.gnupghome
              [
                "--local-user"; k.fingerprint; "--yes"; "--detach-sign";
                "--output"; sig_path; data_path;
              ]
          in
          Fileutil.read_all_bytes sig_path))

let cleanup (k : key) : unit = rm_rf k.gnupghome

let checks_run = ref 0
let checks_failed = ref 0

let check name cond =
  incr checks_run;
  if not cond then (
    incr checks_failed;
    Printf.eprintf "FAIL: %s\n%!" name)
  else Printf.eprintf "ok:   %s\n%!" name

let summarize () =
  Printf.eprintf "\n%d/%d checks passed\n%!"
    (!checks_run - !checks_failed)
    !checks_run;
  if !checks_failed > 0 then exit 1
