(* Challenge-response verification (§2.1): the watchdog issues a
   nonce (Nonce.generate), a client signs it with their enrolled
   private key, and this module verifies that signature against the
   pinned public key enrolled at setup (§3.11). Shells out to `gpgv`
   rather than depending on an OCaml OpenPGP library — gpgv is
   exactly the tool suite's own lightweight, keyring-only verifier (no
   web-of-trust, no gpg-agent, no ambient keyring), which both matches
   §3.3's "keep this component's dependency tree minimal" requirement
   and is real, standards-compliant OpenPGP verification rather than a
   hand-rolled signature scheme reviewed by nobody but this project. *)

let gpgv_path = "/usr/bin/gpgv"

(* [pubkey_binary] must already be in gpgv's binary keyring format
   (concatenated OpenPGP public-key packets — `gpg --dearmor` an
   ASCII-armored key once, at enrollment time, §3.11), not on every
   verification call. *)
let verify_signature ~(pubkey_binary : string) ~(data : string)
    ~(signature_binary : string) : bool =
  Tempfile.with_contents pubkey_binary (fun keyring_path ->
      Tempfile.with_contents data (fun data_path ->
          Tempfile.with_contents signature_binary (fun sig_path ->
              match
                Subprocess.run ~prog:gpgv_path
                  ~argv:
                    [|
                      "gpgv"; "--keyring"; keyring_path; sig_path; data_path;
                    |]
                  ~stdin_content:""
              with
              | Ok _ -> true
              | Error _ -> false)))
