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

type key = { gnupghome : string; fingerprint : string; passphrase : string }

(* Delegates to the real product code (Keypair.ensure_keypair) rather
   than duplicating gpg key-generation logic here — every test that
   calls [generate_key] (nearly all of them, across every test file in
   this suite) now exercises the exact function real watchdog startup
   will call, not a parallel test-only reimplementation of it. Fetches
   the real passphrase too (Keypair.ensure_passphrase, same idempotent
   shape — reads back what ensure_keypair already generated) since
   Manifest.sign now needs one for every real signing key, tests
   included. *)
let generate_key ?(uid = "test <test@example.invalid>") () : key =
  let gnupghome = mkdtemp () in
  match Keypair.ensure_keypair ~gnupghome ~uid with
  | Error e -> failwith (Keypair.describe_error e)
  | Ok fingerprint -> (
      match Keypair.ensure_passphrase gnupghome with
      | Error e -> failwith (Keypair.describe_error e)
      | Ok passphrase -> { gnupghome; fingerprint; passphrase })

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
                "--pinentry-mode"; "loopback"; "--passphrase"; k.passphrase;
                "--local-user"; k.fingerprint; "--yes"; "--detach-sign";
                "--output"; sig_path; data_path;
              ]
          in
          Fileutil.read_all_bytes sig_path))

let cleanup (k : key) : unit = rm_rf k.gnupghome

(* A real countdown latch, not a sleep-based stagger: every
   participating thread calls [arrive_and_wait l n], blocking until
   all [n] have arrived, then all are released together. A sleep-based
   stagger only makes overlapping execution *likely*; this makes every
   participant's post-latch work start from the same instant, every
   run -- the difference that actually found the real thread-collision
   bug in Operator_key.enroll's temp-gnupghome naming (see
   test_operator_key.ml and test_setup_token.ml's own latch-based
   scenarios), which two-threads-and-hope testing had not caught. *)
type latch = { mutex : Mutex.t; cond : Condition.t; mutable arrived : int }

let make_latch () : latch = { mutex = Mutex.create (); cond = Condition.create (); arrived = 0 }

let arrive_and_wait (l : latch) (n : int) : unit =
  Mutex.lock l.mutex;
  l.arrived <- l.arrived + 1;
  if l.arrived >= n then Condition.broadcast l.cond
  else while l.arrived < n do Condition.wait l.cond l.mutex done;
  Mutex.unlock l.mutex

(* Deterministic, in-process fd-exhaustion fault injection — the same
   real trigger this project has already found and fixed one Sys_error
   escape with (Nonce.generate's own open_in_bin "/dev/urandom", per
   DECISIONS.md: "reproduced directly under a real ulimit -n 256").
   `dup`ing one already-open fd is far cheaper than repeatedly opening a
   real path, and doesn't need an external `ulimit` wrapper process (a
   plain [Unix.putenv "TMPDIR" ...] mid-process was tried and confirmed
   NOT to work for this purpose: [Filename.get_temp_dir_name] reads the
   environment once, cached for the life of the process, not on every
   call — confirmed directly against the stdlib before settling on this
   approach). Returns the fds to pass to [release_exhausted_fds]. *)
let exhaust_fds () : Unix.file_descr list =
  let base = Unix.openfile "/dev/null" [ Unix.O_RDONLY ] 0 in
  let acquired = ref [ base ] in
  (try
     while true do
       acquired := Unix.dup base :: !acquired
     done
   with Unix.Unix_error (Unix.EMFILE, _, _) -> ());
  !acquired

let release_exhausted_fds (fds : Unix.file_descr list) : unit =
  List.iter (fun fd -> try Unix.close fd with Unix.Unix_error _ -> ()) fds

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
