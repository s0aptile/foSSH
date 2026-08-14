open Fossh_watchdog_lib
open Test_helpers

let () =
  let k = generate_key () in
  let other = generate_key () in
  Fun.protect
    ~finally:(fun () ->
      cleanup k;
      cleanup other)
    (fun () ->
      let nonce = Nonce.generate () in
      let sig_bytes = detach_sign k nonce in

      check "valid signature, correct key, unmodified nonce verifies"
        (Auth.verify_signature ~gnupghome:k.gnupghome
           ~expected_key_fingerprint:k.fingerprint ~data:nonce
           ~signature_binary:sig_bytes);

      check "signature over a *different* nonce, verified against original, fails"
        (not
           (Auth.verify_signature ~gnupghome:k.gnupghome
              ~expected_key_fingerprint:k.fingerprint ~data:(Nonce.generate ())
              ~signature_binary:sig_bytes));

      let tampered_sig =
        let b = Bytes.of_string sig_bytes in
        Bytes.set b 10 (Char.chr (Char.code (Bytes.get b 10) lxor 0xff));
        Bytes.to_string b
      in
      check "bit-flipped signature fails"
        (not
           (Auth.verify_signature ~gnupghome:k.gnupghome
              ~expected_key_fingerprint:k.fingerprint ~data:nonce
              ~signature_binary:tampered_sig));

      check "garbage bytes as a signature is rejected, not an exception"
        (not
           (Auth.verify_signature ~gnupghome:k.gnupghome
              ~expected_key_fingerprint:k.fingerprint ~data:nonce
              ~signature_binary:"not a real signature at all"));

      (* Pinning: k.gnupghome has ONLY k's key, so a good signature
         checked against the wrong expected fingerprint must fail even
         though the crypto itself checks out. *)
      check "a real good signature checked against the wrong pinned fingerprint fails"
        (not
           (Auth.verify_signature ~gnupghome:k.gnupghome
              ~expected_key_fingerprint:other.fingerprint ~data:nonce
              ~signature_binary:sig_bytes));

      (* A verifier homedir that never saw k's key at all. *)
      let empty_homedir = mkdtemp () in
      Fun.protect
        ~finally:(fun () -> rm_rf empty_homedir)
        (fun () ->
          check "verifying with no relevant public key imported anywhere fails, not crashes"
            (not
               (Auth.verify_signature ~gnupghome:empty_homedir
                  ~expected_key_fingerprint:k.fingerprint ~data:nonce
                  ~signature_binary:sig_bytes)));

      (* Revocation: sign while the key is still usable, revoke it,
         then verify from a fresh homedir that only ever imports the
         already-revoked public key — this is what a real client
         re-fetching an enrolled key after it was revoked would see.
         gpgv (the original implementation) was found to accept this;
         see ADR-0041. *)
      let revoke_target = generate_key ~uid:"revme <revme@example.invalid>" () in
      Fun.protect
        ~finally:(fun () -> cleanup revoke_target)
        (fun () ->
          let revoked_nonce = Nonce.generate () in
          let revoked_sig = detach_sign revoke_target revoked_nonce in
          revoke_in_place revoke_target;
          let revoked_pubkey_after = export_pubkey revoke_target in
          let verifier_homedir = fresh_homedir_with_key revoked_pubkey_after in
          Fun.protect
            ~finally:(fun () -> rm_rf verifier_homedir)
            (fun () ->
              check "a signature made by a now-revoked key is rejected"
                (not
                   (Auth.verify_signature ~gnupghome:verifier_homedir
                      ~expected_key_fingerprint:revoke_target.fingerprint
                      ~data:revoked_nonce ~signature_binary:revoked_sig))));

      (* Regression test for a real, fresh-sweep finding: verify_signature's
         three nested Tempfile.with_contents calls plus the
         Fileutil.read_all_bytes of status_path were unguarded Stdlib
         channel ops (raise Sys_error, not Unix.Unix_error) — the same
         bug class Manifest.verify_and_extract had (see that module's own
         test for the full history and why real fd exhaustion, not a
         mid-process TMPDIR change, is what actually reproduces it). Not
         process-crashing here even before the fix (the one real caller
         already runs inside accept_loop's own connection-level
         catch-all), but this function's whole contract is "return a
         bool, never raise" — confirmed it now holds under the identical
         real fault. *)
      let exhausted = exhaust_fds () in
      Fun.protect
        ~finally:(fun () -> release_exhausted_fds exhausted)
        (fun () ->
          check "verify_signature under real fd exhaustion returns false, not an uncaught exception"
            (not
               (Auth.verify_signature ~gnupghome:k.gnupghome
                  ~expected_key_fingerprint:k.fingerprint ~data:nonce
                  ~signature_binary:sig_bytes)));
      check "a real verify_signature call succeeds again once fds are released"
        (Auth.verify_signature ~gnupghome:k.gnupghome
           ~expected_key_fingerprint:k.fingerprint ~data:nonce
           ~signature_binary:sig_bytes);

      summarize ())
