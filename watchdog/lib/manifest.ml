(* Tamper detection (§3.6): a manifest of expected SHA-256 hashes for
   the core binary and its config, clear-signed with the watchdog's
   own OpenPGP key (`gpg --clearsign`) so the manifest's *expected*
   content and its signature travel as one file. An attacker who can
   edit the manifest on disk still can't produce a valid signature
   over their edited version without the watchdog's private key,
   which lives under a directory `fossh-svc` — the thing being
   measured — has no access to at all (§2.3).

   Policy, per §3.6's explicit requirement to pick one and document
   it: a failed verification means REFUSE RESTART, not
   restart-and-log. Restarting a binary this component itself cannot
   vouch for defeats the entire point of having tamper detection in
   the first place. This module only detects; the caller (Supervisor)
   is what actually refuses.

   `check` requires the manifest to explicitly cover the program
   about to be executed (`Program_not_covered` otherwise) — an
   earlier version let a validly-signed but *irrelevant* manifest
   (wrong files listed, or even zero entries) pass trivially, which
   adversarial review demonstrated actually running a swapped-out
   binary despite a "successful" tamper check. See ADR-0041. *)

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
        (* `sha256sum` prints "<64 hex chars>  <path>\n". *)
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

(* Inverse of [render]. Strict about the fixed-width hash field so a
   malformed line fails closed (an Error) rather than being silently
   skipped, and requires every path to be absolute — a relative path
   would resolve against whatever the watchdog process's own current
   working directory happens to be at check time, making the same
   manifest mean different things depending on how the watchdog was
   launched, which is exactly the kind of ambiguity a signed manifest
   is supposed to eliminate. *)
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

(* `--pinentry-mode loopback`, alongside `--passphrase`: required as of
   `Keypair.ensure_keypair` protecting the watchdog's key with a real
   passphrase instead of an empty one — without it, `--batch` mode has
   no interactive pinentry to fall back to and this call fails
   (or hangs waiting for a terminal that will never come) rather than
   using the passphrase handed to it directly. `passphrase` itself
   comes from `Keypair.ensure_passphrase`, called with the same
   `gnupghome` this function signs against. *)
let sign ~(gnupghome : string) ~(key_id : string) ~(passphrase : string) (content : string) :
    (string, string) result =
  Subprocess.run ~prog:gpg_path
    ~argv:
      [|
        "gpg"; "--batch"; "--pinentry-mode"; "loopback"; "--passphrase"; passphrase;
        "--homedir"; gnupghome; "--local-user"; key_id; "--clearsign";
      |]
    ~stdin_content:content

(* One-shot admin bootstrap step for §3.6: hash every path in [paths],
   render, and sign with the watchdog's own key — the single composed
   operation `fossh-watchdog generate-manifest` (bin/main.ml) exposes
   as a real CLI action. This is the only place a manifest is ever
   produced; the supervision loop (Supervisor, via `check` above) only
   ever reads and verifies one, never writes one — see this module's
   header comment. Found necessary, not theoretical: a totally fresh
   install has no manifest at all (nothing in packaging/rpm/fossh.spec
   ever created one, and this file's own `check`/`read_from_path` only
   consume an existing one), so `fossh-watchdog.service`'s first-ever
   start refused to launch and exited before its own setup-token/
   operator-auth listener could stay up — caught live in the 0.1.3
   clean-VM re-verification, not by inspection. *)
let generate_and_sign ~(gnupghome : string) ~(key_id : string) ~(passphrase : string)
    (paths : string list) : (string, string) result =
  match hash_all paths with
  | Error e -> Error e
  | Ok entries -> sign ~gnupghome ~key_id ~passphrase (render entries)

(* `gpg --decrypt` on a clear-signed (not actually encrypted) message
   verifies the signature and emits the original text on stdout — the
   standard way gpg itself handles this message type, not a special
   case this module invented. `--status-file` (Gpg_status) is what
   actually decides pass/fail here, not the bare exit code: a manifest
   clearsigned by a since-revoked or expired watchdog key must not be
   trusted just because the cryptographic math still checks out — see
   this module's header comment and ADR-0041. *)
(* Adversarial review (fresh sweep, real repro): both `Tempfile.with_contents`'s
   own write (creating `status_path`) and `Fileutil.read_all_bytes`'s read of it
   back are `Stdlib` channel ops — raise `Sys_error`, not `Unix.Unix_error` —
   the same "Stdlib channel op raises `Sys_error`, escapes as an uncaught
   exception" bug class already found and fixed four times elsewhere in this
   codebase (`bootstrap.ml`, `core_pin.ml`, `main.ml`'s cert-path read,
   `Setup_token`'s hashing path). This is the fifth, and the most
   safety-critical: reached from `Manifest.check`, which `Supervisor.tamper_check`
   runs on EVERY spawn and EVERY restart, and every one of `main.ml`'s call
   sites around that path only catches `Unix.Unix_error`, not `Sys_error`. An
   uncaught `Sys_error` here (fd exhaustion, a transient unwritable/unreadable
   temp dir — the same real triggers already reproduced for the other four
   instances) would have crashed the entire watchdog process on the one
   function that exists specifically to keep it trustworthy, not just refused
   a single restart. Guarded the same way `Setup_token.sha256_hex_of_string`
   already is: the whole body, not just the inner read, since the *write* half
   of `Tempfile.with_contents` can raise exactly the same way. *)
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
  (* The path verified fine, but by the time it was launched it no
     longer referred to the same file. See Supervisor.ensure_unchanged. *)
  | Program_replaced of string
  | Io_error of string

(* Which file a path referred to at a particular moment.

   The hash check below reads a file by *path*, and whoever spawns it
   later opens that path again. Between the two the path can be pointed
   at a different file -- the classic time-of-check/time-of-use gap.
   Comparing the identity recorded here against a fresh stat right
   before the exec does not eliminate that gap, but it shrinks it from
   the whole verification (a gpg subprocess plus one sha256sum per
   entry -- tens of milliseconds) to two syscalls.

   Size and mtime are included alongside the inode because inode
   numbers are reused: a delete-and-recreate can land on the same
   (dev, ino) pair, and on a busy filesystem that is not exotic. *)
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

(* The one function `Supervisor` actually calls before every spawn
   and every restart: verify the manifest's own signature first (so a
   tampered manifest can't just claim different hashes), require it
   to explicitly cover [program] (the exact path about to be
   executed), then re-hash every entry's real, current file and
   compare. *)
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

(* Moved here from bin/main.ml (which used it only for the initial
   spawn/every restart) so watchdog/quic/quic_command_server.ml can
   re-read the manifest fresh for a live Status query too, without a
   second, drifting copy of the same read-with-a-size-cap logic. *)
type read_error = Missing | Not_a_file | Too_large of int | Unreadable of string

(* 1 MiB is generous for any real manifest (see hash_all's own large-
   manifest test) while still bounding the worst case an oversized or
   misconfigured manifest path could do to whichever process reads it. *)
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
