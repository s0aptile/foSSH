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
        (Auth.verify_signature ~pubkey_binary:k.pubkey_binary ~data:nonce
           ~signature_binary:sig_bytes);

      check "signature over a *different* nonce, verified against original, fails"
        (not
           (Auth.verify_signature ~pubkey_binary:k.pubkey_binary
              ~data:(Nonce.generate ()) ~signature_binary:sig_bytes));

      let tampered_sig =
        let b = Bytes.of_string sig_bytes in
        Bytes.set b 10 (Char.chr (Char.code (Bytes.get b 10) lxor 0xff));
        Bytes.to_string b
      in
      check "bit-flipped signature fails"
        (not
           (Auth.verify_signature ~pubkey_binary:k.pubkey_binary ~data:nonce
              ~signature_binary:tampered_sig));

      check "signature verified against the WRONG public key fails"
        (not
           (Auth.verify_signature ~pubkey_binary:other.pubkey_binary
              ~data:nonce ~signature_binary:sig_bytes));

      check "garbage bytes as a signature is rejected, not an exception"
        (not
           (Auth.verify_signature ~pubkey_binary:k.pubkey_binary ~data:nonce
              ~signature_binary:"not a real signature at all"));

      summarize ())
