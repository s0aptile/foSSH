open Fossh_watchdog_lib
open Test_helpers

let () =
  let dir = mkdtemp () in
  Fun.protect
    ~finally:(fun () -> rm_rf dir)
    (fun () ->
      let gnupghome = Filename.concat dir "gnupghome" in
      let uid = "watchdog <watchdog@example.invalid>" in

      let first =
        match Keypair.ensure_keypair ~gnupghome ~uid with
        | Ok fpr -> fpr
        | Error e -> failwith (Keypair.describe_error e)
      in
      check "a fresh homedir gets a real 40-hex-char fingerprint"
        (String.length first = 40
        && String.for_all
             (fun c ->
               (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'))
             first);

      let second =
        match Keypair.ensure_keypair ~gnupghome ~uid with
        | Ok fpr -> fpr
        | Error e -> failwith (Keypair.describe_error e)
      in
      check "calling ensure_keypair again on the same homedir returns the SAME fingerprint, not a new one"
        (first = second);

      (* Confirmed independently of ensure_keypair's own return value:
         only one secret key actually exists in the homedir after two
         calls, not two. *)
      let secret_key_count =
        match Subprocess.run ~prog:"/usr/bin/gpg"
                ~argv:[| "gpg"; "--batch"; "--homedir"; gnupghome; "--with-colons"; "--list-secret-keys" |]
                ~stdin_content:""
        with
        | Error e -> failwith e
        | Ok listing ->
            String.split_on_char '\n' listing
            |> List.filter (fun l -> String.length l >= 3 && String.sub l 0 3 = "sec")
            |> List.length
      in
      check "exactly one secret key exists after two ensure_keypair calls, not two"
        (secret_key_count = 1);

      let other_uid_fpr =
        match
          Keypair.ensure_keypair ~gnupghome ~uid:"different <different@example.invalid>"
        with
        | Ok fpr -> fpr
        | Error e -> failwith (Keypair.describe_error e)
      in
      check "a THIRD call, even with a different uid, still returns the original key (existing key wins)"
        (other_uid_fpr = first);

      let other_dir = Filename.concat dir "other-gnupghome" in
      let other_fpr =
        match Keypair.ensure_keypair ~gnupghome:other_dir ~uid with
        | Ok fpr -> fpr
        | Error e -> failwith (Keypair.describe_error e)
      in
      check "a different homedir gets a genuinely different key"
        (other_fpr <> first);

      (* §2.4, extended: this key used to be generated with an empty
         passphrase — real, but not what a public description of "your
         OpenPGP key's passphrase" should have implied. These checks
         prove the replacement is genuine protection, not just a file
         that happens to exist alongside the key. *)
      let passphrase =
        match Keypair.ensure_passphrase gnupghome with
        | Ok p -> p
        | Error e -> failwith (Keypair.describe_error e)
      in
      check "the generated passphrase is a real, high-entropy value, not empty"
        (String.length passphrase >= 32);

      let passphrase_path = Filename.concat gnupghome "passphrase" in
      check "the passphrase file exists on disk" (Sys.file_exists passphrase_path);
      check "the passphrase file is mode 0600"
        (let st = Unix.stat passphrase_path in
         st.Unix.st_perm = 0o600);

      let passphrase_again =
        match Keypair.ensure_passphrase gnupghome with
        | Ok p -> p
        | Error e -> failwith (Keypair.describe_error e)
      in
      check "calling ensure_passphrase again returns the SAME passphrase, not a new one"
        (passphrase = passphrase_again);

      check "signing with the correct passphrase succeeds"
        (match Manifest.sign ~gnupghome ~key_id:first ~passphrase "real manifest content\n" with
        | Ok signed -> String.length signed > 0
        | Error _ -> false);

      (* A fresh, separate key for the wrong-passphrase check —
         deliberately not the same key the "correct passphrase" check
         just unlocked above. A real, reproduced gotcha found while
         writing this exact test: gpg-agent caches an unlocked key's
         session for a period after a successful sign, so a second
         sign attempt against the *same* gnupghome — even with a
         wrong passphrase — can spuriously succeed by riding that
         cache rather than actually checking the passphrase given to
         it. Confirmed directly (a standalone repro against a
         never-before-unlocked key correctly failed with gpg's own
         "Bad passphrase", exit 2) that the underlying protection
         itself is real; the ordering above was the test bug, not
         Keypair/Manifest. A fresh key sidesteps the cache entirely
         rather than trying to defeat or reset gpg-agent mid-test. *)
      let wrong_pass_key = generate_key ~uid () in
      check "signing with the WRONG passphrase is genuinely rejected, not silently accepted"
        (match
           Manifest.sign ~gnupghome:wrong_pass_key.gnupghome ~key_id:wrong_pass_key.fingerprint
             ~passphrase:"definitely-the-wrong-passphrase" "real manifest content\n"
         with
        | Error _ -> true
        | Ok _ -> false);

      summarize ())
