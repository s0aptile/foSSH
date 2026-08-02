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
   the first place — see DECISIONS.md's ADR for the OCaml watchdog
   chapter for the full reasoning. This module only detects; the
   caller (Supervisor) is what actually refuses. *)

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

(* Inverse of [render] — tolerant of blank lines, strict about the
   fixed-width hash field so a malformed line fails closed (an Error)
   rather than being silently skipped. *)
let parse (body : string) : (entry list, string) result =
  let lines =
    String.split_on_char '\n' body |> List.filter (fun l -> l <> "")
  in
  let parse_line line =
    if String.length line > 66 && String.sub line 64 2 = "  " then
      Ok
        {
          expected_sha256 = String.sub line 0 64;
          path = String.sub line 66 (String.length line - 66);
        }
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

let run_gpg ~(gnupghome : string) (args : string list) ~(stdin_content : string)
    : (string, string) result =
  Subprocess.run ~prog:gpg_path
    ~argv:(Array.of_list ("gpg" :: "--batch" :: "--homedir" :: gnupghome :: args))
    ~stdin_content

let sign ~(gnupghome : string) ~(key_id : string) (content : string) :
    (string, string) result =
  run_gpg ~gnupghome [ "--local-user"; key_id; "--clearsign" ]
    ~stdin_content:content

(* `gpg --decrypt` on a clear-signed (not actually encrypted) message
   verifies the signature and emits the original text on stdout,
   exiting non-zero on a bad or missing signature — the standard way
   gpg itself handles this message type, not a special case this
   module invented. *)
let verify_and_extract ~(gnupghome : string) (clearsigned : string) :
    (string, string) result =
  run_gpg ~gnupghome [ "--decrypt" ] ~stdin_content:clearsigned

type check_result =
  | Ok_manifest of entry list
  | Signature_invalid of string
  | Hash_mismatch of { path : string; expected : string; actual : string }
  | Io_error of string

(* The one function `Supervisor` actually calls before every restart:
   verify the manifest's own signature first (so a tampered manifest
   can't just claim different hashes), then re-hash every entry's
   real, current file and compare. *)
let check ~(gnupghome : string) ~(clearsigned_manifest : string) : check_result
    =
  match verify_and_extract ~gnupghome clearsigned_manifest with
  | Error e -> Signature_invalid e
  | Ok body -> (
      match parse body with
      | Error e -> Io_error e
      | Ok entries ->
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
