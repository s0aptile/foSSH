(* See .mli. Fingerprint pin file uses the same write-temp-then-link
   atomicity as Core_pin.persist_pin (link fails outright if the
   destination exists, which is what actually enforces "no silent
   re-enrollment" rather than that being only a comment). *)

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
  Subprocess.run ~prog:gpg_path
    ~argv:(Array.of_list ("gpg" :: "--batch" :: "--homedir" :: gnupghome :: args))
    ~stdin_content:""

(* Adversarial review (real repro, not assumed): a naive "count every
   fpr: line" approach, as an earlier version of this function did,
   false-positives as Multiple_keys_imported on any normal key that
   has a subkey — the default shape `gpg --full-gen-key` and virtually
   every real-world OpenPGP identity produces, since --with-colons
   emits one fpr: line per subkey too, not just the primary. A real
   operator pasting their actual existing key would have failed to
   enroll at all.

   Fixed by only counting fpr: lines that immediately follow a pub:
   record (a primary key), never a sub: record — GnuPG's own
   --with-colons format always places fpr: directly after the pub:/
   sub: line it describes, no intervening lines, confirmed against
   real output while fixing this. This correctly still rejects a
   multi-primary-key import (the actual, intended check) while
   accepting any single primary key regardless of how many subkeys it
   carries. *)
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

(* Adversarial review (real repro, same root cause and same fix as
   enroll's own tmp_gnupghome, found in the same forced-overlap
   thread-latch test run): [tmp_path] used to be named from
   [Unix.getpid ()] alone here too -- a second instance of the
   identical bug class in the same file, since two racing threads of
   the same process share one pid and therefore compute the identical
   tmp_path. The [Unix.openfile ... O_EXCL] a losing thread hits then
   raises EEXIST from "open", not "link" -- only the latter is this
   function's own intended, documented exclusivity signal
   (Already_enrolled) -- so a thread-level collision here fell through
   to the generic Io_error branch instead: a real, reproduced
   "operator key I/O error: open: File exists" standing in for what
   should have been a clean Already_enrolled refusal. Same fix: fold a
   fresh Nonce.generate() into the path so no two calls, thread or
   process, can ever compute the same tmp_path. *)
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

(* Adversarial review (real repro): the previous version imported
   directly into the one shared, permanent gnupghome. Any rejected
   import (a multi-key paste, or the subkey false-positive this file
   used to have) left that extra key material behind forever, with no
   cleanup and no reset path -- confirmed serially (retry the exact
   same single key that should enroll cleanly, on a gnupghome already
   poisoned by one earlier bad attempt: still rejected) and under real
   concurrency (two threads enrolling different keys into an empty
   dir, 5/5 trials: both lose, enrolled_fingerprint ends up None, yet
   both keys' material survives in the shared gnupghome). *)
let rec rm_rf (path : string) : unit =
  match Unix.((lstat path).st_kind) with
  | Unix.S_DIR ->
      (try Sys.readdir path |> Array.iter (fun name -> rm_rf (Filename.concat path name))
       with Sys_error _ -> ());
      (try Unix.rmdir path with Unix.Unix_error _ -> ())
  | _ -> ( try Sys.remove path with Sys_error _ -> ())
  | exception Unix.Unix_error (Unix.ENOENT, _, _) -> ()

(* Each call works in its own fresh, disposable temp gnupghome --
   never the shared permanent one -- and only commits (via
   persist_fingerprint's own atomic link-based exclusivity, then an
   atomic rename into place) once that exclusivity is actually won.
   Any failure at any step, including losing a concurrent race, tears
   down only this attempt's own temp state and leaves the permanent
   gnupghome/pin untouched -- no shared mutable state exists for two
   concurrent attempts to corrupt each other through.

   Adversarial review (real repro, found while building a *different*
   module's own concurrency test -- watchdog/test/test_setup_token.ml's
   "Scenario H" -- against this function directly, not through any
   caller): the temp gnupghome path used to be named from
   [Unix.getpid ()] alone. That uniquely identifies a *process*, not a
   *call* -- harmless for the two-separate-processes shape this was
   apparently verified against before ("two threads... 5/5 trials", per
   this file's own commit history), but a real collision for two
   concurrent THREADS of the same process, which share one pid. Forcing
   six real threads to call this function at the same literal instant
   (a countdown latch, not a hopeful sleep) reproduced it every run:
   every thread computed the identical tmp_gnupghome path, so whichever
   thread's [Unix.mkdir tmp_gnupghome] lost the race got a bare
   Io_error("mkdir: File exists") -- but worse, any thread whose
   [rm_rf tmp_gnupghome] ran *after* another thread had already
   [Unix.mkdir]'d and started importing into that same path deleted the
   other thread's in-flight gnupghome out from under it mid-gpg-
   operation, corrupting both: real, garbled `gpg` failures ("directory
   does not exist", "lock not made", "invalid packet") on every one of
   the six threads, zero clean winners, not the intended "one winner,
   five clean Already_enrolled refusals." Not reachable through this
   project's real, current callers today (Operator_auth_server's own
   accept loop is single-threaded and fully serial, so no two
   Operator_key.enroll calls are ever actually concurrent in the
   running watchdog) -- but this function's own contract makes no such
   promise, is documented above as safe under concurrent attempts, and
   a future caller (or a differently-shaped accept loop) relying on
   that documented guarantee would inherit this bug silently. Fixed by
   folding a fresh Nonce.generate() into the path -- 256 bits of
   entropy per call makes an actual collision, thread or process,
   astronomically unlikely, closing the root cause rather than only
   the symptom a pid-uniqueness assumption happened to mostly cover. *)
(* Real, reproduced bug (found by this project's own clean-VM install
   verification running the actual hardened `fossh-watchdog.service`
   for the first time, not by inspection): with the full
   `Nonce.generate ()` (64 hex chars) folded into this path, the
   resulting temp `gnupghome` under the real default
   `/var/lib/fossh-watchdog/operator-key` comes out well over 130
   bytes — past the kernel's ~108-byte `AF_UNIX` `sun_path` limit once
   `gpg-agent` appends its own `/S.gpg-agent`-family socket name. `gpg
   --import` itself still succeeded (it doesn't need the agent for a
   bare public-key import), but the very next call this function makes
   — `--list-keys`, to read the fingerprint back — does start
   `gpg-agent`, which failed to bind its (too-long) socket path and
   exited 2, surfacing as `Import_failed`/`ENROLL_FAILED invalid_key`
   to a real operator every single time, on the real default install
   path. Never caught by this project's own automated cross-language
   interop test, which points `FOSSH_OPERATOR_KEY_DIR` at a short
   `std::env::temp_dir()`-based path, nowhere near the limit. 8 bytes
   (16 hex chars) here is not a security-relevant amount of entropy —
   this suffix's only job is avoiding a same-instant collision between
   two concurrent callers (see this function's own header comment),
   which 64 bits already makes astronomically unlikely — it exists to
   buy back the ~48 bytes of path budget the real default `dir` needs. *)
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
    (* Adversarial review (fresh sweep, real repro): `Tempfile.with_contents`'s
       own write (creating a temp file for `public_key_armored`) is a Stdlib
       channel op -- raises `Sys_error`, not `Unix.Unix_error` -- the same bug
       class already found and fixed in `bootstrap.ml`, `core_pin.ml`,
       `main.ml`'s cert-path read, and `Setup_token`'s hashing path. Not
       process-crashing today (the one real caller, `Operator_auth_server`'s
       `handle_setup_flow`, already runs inside `accept_loop`'s own
       connection-level catch-all), but still an exception escaping a
       function whose whole contract is "return a typed `Io_error`, never
       raise" -- fixed for the same defense-in-depth reason as the rest. *)
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
                            (* We just won the only exclusivity gate that
                               matters -- any pre-existing content at the
                               permanent path is orphaned garbage from
                               before this fix, safe to discard. *)
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
