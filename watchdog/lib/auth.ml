let gpg_path = "/usr/bin/gpg"

let verify_signature ~(gnupghome : string) ~(expected_key_fingerprint : string)
    ~(data : string) ~(signature_binary : string) : bool =
  try
    Tempfile.with_contents data (fun data_path ->
        Tempfile.with_contents signature_binary (fun sig_path ->
            Tempfile.with_contents "" (fun status_path ->
                match
                  Subprocess.run ~extra_env:[ ("GNUPGHOME", gnupghome) ]
                    ~prog:gpg_path
                    ~argv:
                      [|
                        "gpg";
                        "--batch";
                        "--homedir";
                        gnupghome;
                        "--status-file";
                        status_path;
                        "--verify";
                        "--";
                        sig_path;
                        data_path;
                      |]
                    ~stdin_content:"" ()
                with
                | Error _ -> false
                | Ok _ -> (
                    match
                      Gpg_status.parse (Fileutil.read_all_bytes status_path)
                    with
                    | Good_signature_by key_id ->
                        Gpg_status.key_id_matches_fingerprint ~key_id
                          ~fingerprint:expected_key_fingerprint
                    | Revoked_key | Expired_key | No_good_signature -> false))))
  with Sys_error _ -> false
