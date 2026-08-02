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

      summarize ())
