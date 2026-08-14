open Fossh_watchdog_lib
open Test_helpers

let write_file path content =
  let oc = open_out_bin path in
  output_string oc content;
  close_out oc

let () =
  let k = generate_key () in
  let other = generate_key () in
  let watched_dir = mkdtemp () in
  Fun.protect
    ~finally:(fun () ->
      cleanup k;
      cleanup other;
      rm_rf watched_dir)
    (fun () ->
      let file_a = Filename.concat watched_dir "a.bin" in
      let file_b = Filename.concat watched_dir "b.bin" in
      write_file file_a "core binary contents (stand-in)";
      write_file file_b "config contents (stand-in)";

      (* hash_all / render / parse round trip *)
      let entries =
        match Manifest.hash_all [ file_a; file_b ] with
        | Ok e -> e
        | Error msg -> failwith ("hash_all failed: " ^ msg)
      in
      check "hash_all produces one entry per input path"
        (List.length entries = 2);
      check "every hash is 64 hex chars"
        (List.for_all
           (fun (e : Manifest.entry) -> String.length e.expected_sha256 = 64)
           entries);

      let rendered = Manifest.render entries in
      let reparsed =
        match Manifest.parse rendered with
        | Ok e -> e
        | Error msg -> failwith ("parse failed: " ^ msg)
      in
      check "render -> parse round-trips to the same entries"
        (reparsed = entries);

      check "a malformed manifest line is a parse Error, not a crash"
        (match Manifest.parse "not a valid manifest line at all\n" with
        | Error _ -> true
        | Ok _ -> false);

      check "a relative manifest path is rejected"
        (let bad =
           Printf.sprintf "%s  relative/path.bin\n" (String.make 64 'a')
         in
         match Manifest.parse bad with Error _ -> true | Ok _ -> false);

      (* sign / verify_and_extract round trip *)
      let signed =
        match Manifest.sign ~gnupghome:k.gnupghome ~key_id:k.fingerprint ~passphrase:k.passphrase rendered with
        | Ok s -> s
        | Error msg -> failwith ("sign failed: " ^ msg)
      in
      check "a real clearsigned manifest verifies and returns the original body"
        (match
           Manifest.verify_and_extract ~gnupghome:k.gnupghome
             ~expected_key_fingerprint:k.fingerprint signed
         with
        | Ok body -> body = rendered
        | Error _ -> false);

      check "verifying against a homedir that doesn't have the signer's key fails"
        (match
           Manifest.verify_and_extract ~gnupghome:other.gnupghome
             ~expected_key_fingerprint:k.fingerprint signed
         with
        | Error _ -> true
        | Ok _ -> false);

      check "verifying a real good signature against the wrong pinned fingerprint fails"
        (match
           Manifest.verify_and_extract ~gnupghome:k.gnupghome
             ~expected_key_fingerprint:other.fingerprint signed
         with
        | Error _ -> true
        | Ok _ -> false);

      (* the end-to-end `check` gate Supervisor actually calls — must
         cover the exact program path, per ADR-0041 (adversarial
         review found an earlier version let any validly-signed
         manifest pass regardless of whether it mentioned the program
         actually being executed at all). *)
      (match
         Manifest.check ~gnupghome:k.gnupghome ~expected_key_fingerprint:k.fingerprint
           ~program:file_a ~clearsigned_manifest:signed
       with
      | Ok_manifest e -> check "check() succeeds when the program is covered and nothing changed" (e = entries)
      | _ -> check "check() succeeds when the program is covered and nothing changed" false);

      (match
         Manifest.check ~gnupghome:k.gnupghome ~expected_key_fingerprint:k.fingerprint
           ~program:(Filename.concat watched_dir "not-in-the-manifest.bin")
           ~clearsigned_manifest:signed
       with
      | Program_not_covered _ ->
          check "check() refuses when the program isn't listed in the manifest at all" true
      | _ -> check "check() refuses when the program isn't listed in the manifest at all" false);

      let empty_signed =
        match Manifest.sign ~gnupghome:k.gnupghome ~key_id:k.fingerprint ~passphrase:k.passphrase "" with
        | Ok s -> s
        | Error msg -> failwith ("sign (empty) failed: " ^ msg)
      in
      (match
         Manifest.check ~gnupghome:k.gnupghome ~expected_key_fingerprint:k.fingerprint
           ~program:file_a ~clearsigned_manifest:empty_signed
       with
      | Program_not_covered _ ->
          check "check() refuses a validly-signed but EMPTY manifest, not Ok_manifest []" true
      | _ -> check "check() refuses a validly-signed but EMPTY manifest, not Ok_manifest []" false);

      write_file file_a "TAMPERED core binary contents";
      (match
         Manifest.check ~gnupghome:k.gnupghome ~expected_key_fingerprint:k.fingerprint
           ~program:file_a ~clearsigned_manifest:signed
       with
      | Hash_mismatch { path; _ } ->
          check "check() catches a modified watched file" (path = file_a)
      | _ -> check "check() catches a modified watched file" false);
      write_file file_a "core binary contents (stand-in)";
      (* restore, so later checks start from a known-good state *)

      let hand_edited_manifest =
        (* An attacker who can write the manifest file but does not
           have the watchdog's private key: same clearsign envelope
           shape, different (attacker-chosen, unsigned-by-the-real-key)
           content underneath. *)
        match Manifest.sign ~gnupghome:other.gnupghome ~key_id:other.fingerprint ~passphrase:other.passphrase rendered with
        | Ok s -> s
        | Error msg -> failwith ("sign (other key) failed: " ^ msg)
      in
      (match
         Manifest.check ~gnupghome:k.gnupghome ~expected_key_fingerprint:k.fingerprint
           ~program:file_a ~clearsigned_manifest:hand_edited_manifest
       with
      | Signature_invalid _ ->
          check "check() refuses a manifest signed by the wrong key" true
      | _ -> check "check() refuses a manifest signed by the wrong key" false);

      let missing_file_manifest =
        let entries =
          [
            {
              Manifest.path = Filename.concat watched_dir "does-not-exist";
              expected_sha256 = String.make 64 '0';
            };
          ]
        in
        match
          Manifest.sign ~gnupghome:k.gnupghome ~key_id:k.fingerprint ~passphrase:k.passphrase
            (Manifest.render entries)
        with
        | Ok s -> s
        | Error msg -> failwith ("sign (missing file) failed: " ^ msg)
      in
      (match
         Manifest.check ~gnupghome:k.gnupghome ~expected_key_fingerprint:k.fingerprint
           ~program:(Filename.concat watched_dir "does-not-exist")
           ~clearsigned_manifest:missing_file_manifest
       with
      | Io_error _ -> check "check() reports Io_error for a missing watched file" true
      | _ -> check "check() reports Io_error for a missing watched file" false);

      (* Regression test for a real, reproduced hang (ADR-0041,
         finding #4): a much earlier version of Subprocess.run wrote
         all of stdin before reading any output, which deadlocked
         against `gpg --decrypt` once a clearsigned manifest got large
         enough (~a few hundred KB — not contrived; a deployment
         watching several thousand files reaches this) because gpg
         starts producing output before it has drained stdin. This
         signs and verifies a genuinely large (~600KB) manifest for
         real, through the same code path `check` uses, with no
         timeout wrapper needed — if the deadlock were still present,
         this call simply would never return and the whole test
         binary would hang instead of reaching `summarize ()` below. *)
      let many_entries =
        List.init 6000 (fun i ->
            {
              Manifest.path = Printf.sprintf "/watched/file-%06d.bin" i;
              expected_sha256 = String.make 64 (Char.chr (Char.code 'a' + (i mod 6)));
            })
      in
      let big_rendered = Manifest.render many_entries in
      check "a large (~600KB) manifest renders to a substantial body"
        (String.length big_rendered > 400_000);
      let big_signed =
        match Manifest.sign ~gnupghome:k.gnupghome ~key_id:k.fingerprint ~passphrase:k.passphrase big_rendered with
        | Ok s -> s
        | Error msg -> failwith ("sign (large manifest) failed: " ^ msg)
      in
      check "signing and verifying a large manifest completes (does not hang) and round-trips"
        (match
           Manifest.verify_and_extract ~gnupghome:k.gnupghome
             ~expected_key_fingerprint:k.fingerprint big_signed
         with
        | Ok body -> body = big_rendered
        | Error _ -> false);

      (* Regression test for a real bug found by a fresh adversarial
         sweep (the fifth instance of this codebase's own recurring
         "Stdlib channel op raises Sys_error, not Unix.Unix_error, and
         escapes as an uncaught exception" bug class — see bootstrap.ml,
         core_pin.ml, main.ml's cert-path read, and Setup_token's
         hashing path for the first four): verify_and_extract's
         Tempfile.with_contents "" (creating status_path) and the later
         Fileutil.read_all_bytes status_path were both unguarded.
         Reachable via Manifest.check, which Supervisor.tamper_check
         runs on EVERY spawn and EVERY restart — and every one of
         main.ml's call sites around that path only catches
         Unix.Unix_error, not Sys_error, so an uncaught Sys_error here
         would have crashed the entire watchdog process, not just
         refused one restart.

         Reproduced with real fd exhaustion (Test_helpers.exhaust_fds),
         the same trigger this project already used once for a related
         Sys_error escape (Nonce.generate's own open_in_bin
         "/dev/urandom" — DECISIONS.md: "reproduced directly under a
         real ulimit -n 256"). A [TMPDIR]-pointed-at-a-missing-directory
         approach was tried first and abandoned: confirmed directly
         against the stdlib that [Filename.get_temp_dir_name] caches the
         environment once at process start rather than re-reading it, so
         a mid-process [Unix.putenv "TMPDIR" ...] has no effect and
         cannot reproduce this bug from inside an already-running test
         binary — [exhaust_fds] doesn't have that problem, since it acts
         on the process's live fd table directly. Under real exhaustion,
         [Tempfile.with_contents]'s own [open_out_bin] for [status_path]
         is the very first Stdlib channel op in the whole call chain
         (before [Subprocess.run]'s own pipes are ever created), so this
         exercises exactly the guard this fix added. *)
      let exhausted = exhaust_fds () in
      Fun.protect
        ~finally:(fun () -> release_exhausted_fds exhausted)
        (fun () ->
          check "verify_and_extract under real fd exhaustion is a clean Error, not an uncaught exception"
            (match
               Manifest.verify_and_extract ~gnupghome:k.gnupghome
                 ~expected_key_fingerprint:k.fingerprint signed
             with
            | Error _ -> true
            | Ok _ -> false);
          check "check() under real fd exhaustion is a clean result, not a crash of the whole tamper gate"
            (match
               Manifest.check ~gnupghome:k.gnupghome ~expected_key_fingerprint:k.fingerprint
                 ~program:file_a ~clearsigned_manifest:signed
             with
            | Ok_manifest _ -> false (* must not silently pass under fd exhaustion *)
            | Signature_invalid _ | Hash_mismatch _ | Program_not_covered _ | Io_error _ -> true));
      check "a real check() call succeeds again once fds are released (no lingering state)"
        (match
           Manifest.check ~gnupghome:k.gnupghome ~expected_key_fingerprint:k.fingerprint
             ~program:file_a ~clearsigned_manifest:signed
         with
        | Ok_manifest e -> e = entries
        | _ -> false);

      (* generate_and_sign: the composed hash_all/render/sign operation
         `fossh-watchdog generate-manifest` actually calls. Its output
         must be exactly what check() accepts as valid for the paths it
         covered — proves the CLI subcommand and the supervision loop's
         own verification agree on the same manifest shape, not just
         that each half works in isolation. *)
      let generated =
        match
          Manifest.generate_and_sign ~gnupghome:k.gnupghome ~key_id:k.fingerprint
            ~passphrase:k.passphrase [ file_a; file_b ]
        with
        | Ok s -> s
        | Error msg -> failwith ("generate_and_sign failed: " ^ msg)
      in
      check "generate_and_sign's output passes check() for every path it covered"
        (match
           Manifest.check ~gnupghome:k.gnupghome ~expected_key_fingerprint:k.fingerprint
             ~program:file_a ~clearsigned_manifest:generated
         with
        | Ok_manifest e -> e = entries
        | _ -> false);
      check "generate_and_sign fails closed on a path that does not exist"
        (match
           Manifest.generate_and_sign ~gnupghome:k.gnupghome ~key_id:k.fingerprint
             ~passphrase:k.passphrase
             [ Filename.concat watched_dir "does-not-exist" ]
         with
        | Error _ -> true
        | Ok _ -> false);

      summarize ())
