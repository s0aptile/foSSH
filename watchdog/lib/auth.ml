(* Challenge-response verification (§2.1): the watchdog issues a
   nonce (Nonce.generate), a client signs it with their enrolled
   private key, and this module verifies that signature against the
   pinned public key enrolled at setup (§3.11).

   Uses full `gpg --verify` against a persistent `gnupghome` (where
   the enrolled key was already imported), not `gpgv` against a raw
   keyring — an earlier version of this module used `gpgv` for its
   minimalism, but `gpgv` was found (adversarial review) not to check
   key revocation or expiry at all: a signature made by a since-
   revoked key still exits 0 with "Good signature", silently
   defeating the standard incident-response action of revoking a
   compromised key. `gpg --verify` plus its `--status-file` output
   (Gpg_status) gives the same cryptographic check *and* a real
   revocation/expiry veto. See ADR-0041.

   `expected_key_fingerprint` pins to exactly the enrolled key, not
   "any key gpg's keyring happens to trust" — §2.1's whole model is a
   *pinned* public key, and a homedir could in principle hold more
   than one imported key. *)

let gpg_path = "/usr/bin/gpg"

(* Adversarial review (fresh sweep, real repro): same Sys_error-escape gap as
   `Manifest.verify_and_extract` (see that function's own comment for the full
   bug-class history) — this function's three nested `Tempfile.with_contents`
   calls and the `Fileutil.read_all_bytes` of `status_path` are all Stdlib
   channel ops. Not process-crashing today (the one real caller,
   `Operator_auth_server.handle_one_connection`, already runs inside
   `accept_loop`'s own connection-level catch-all), but still an undocumented
   exception escaping a function whose whole contract is "return a bool,
   never raise" — fixed for the same reason the rest of this codebase already
   holds itself to. Fails closed (`false`), matching every other failure path
   this function already has. *)
let verify_signature ~(gnupghome : string) ~(expected_key_fingerprint : string)
    ~(data : string) ~(signature_binary : string) : bool =
  try
    Tempfile.with_contents data (fun data_path ->
        Tempfile.with_contents signature_binary (fun sig_path ->
            Tempfile.with_contents "" (fun status_path ->
                match
                  Subprocess.run ~prog:gpg_path
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
                    ~stdin_content:""
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
