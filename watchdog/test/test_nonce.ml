open Fossh_watchdog_lib
open Test_helpers

let () =
  let a = Nonce.generate () in
  let b = Nonce.generate () in
  check "nonce is 64 hex chars (32 bytes)" (String.length a = 64);
  check "nonce is all lowercase hex"
    (String.for_all
       (fun c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
       a);
  check "two nonces are not equal" (a <> b);
  let sample = List.init 200 (fun _ -> Nonce.generate ()) in
  let unique = List.sort_uniq compare sample in
  check "200 generated nonces are all unique"
    (List.length unique = List.length sample);
  check "constant_time_equal: a token equals itself" (Nonce.constant_time_equal a a);
  check "constant_time_equal: two independently generated nonces differ"
    (not (Nonce.constant_time_equal a b));
  check "constant_time_equal: differing only in the last byte is still unequal"
    (let flipped = Bytes.of_string a in
     Bytes.set flipped (Bytes.length flipped - 1)
       (if a.[String.length a - 1] = '0' then '1' else '0');
     not (Nonce.constant_time_equal a (Bytes.unsafe_to_string flipped)));
  check "constant_time_equal: different lengths are unequal, not an exception"
    (not (Nonce.constant_time_equal a (a ^ "0")));
  check "constant_time_equal: empty strings equal each other" (Nonce.constant_time_equal "" "");

  check "a huge request fails cleanly rather than escaping as Sys_error"
    (match Nonce.read_random_bytes max_int with
     | exception Nonce.Entropy_unavailable _ -> true
     | exception Out_of_memory -> true
     | exception Invalid_argument _ -> true
     | _ -> false);
  check "repeated reads do not leak file descriptors"
    (let before = Sys.readdir "/proc/self/fd" |> Array.length in
     for _ = 1 to 200 do ignore (Nonce.read_random_bytes 32) done;
     let after = Sys.readdir "/proc/self/fd" |> Array.length in
     after <= before + 2);

  let full = "305885A276CF155B94AD29FC35715893BCA6F73D" in
  let real_gpg_output =
    "[GNUPG:] NEWSIG\n\
     [GNUPG:] KEY_CONSIDERED " ^ full ^ " 0\n\
     [GNUPG:] GOODSIG 35715893BCA6F73D fossh-test <t@example.invalid>\n\
     [GNUPG:] VALIDSIG " ^ full ^ " 2026-08-15 1786789306 0 4 0 22 10 01 " ^ full ^ "\n\
     [GNUPG:] TRUST_ULTIMATE 0 pgp\n"
  in
  check "a good signature reports the FULL fingerprint, not the short key id"
    (match Gpg_status.parse real_gpg_output with
     | Gpg_status.Good_signature_by reported -> String.length reported = 40 && reported = full
     | _ -> false);
  check "the reported value matches the pinned fingerprint exactly"
    (match Gpg_status.parse real_gpg_output with
     | Gpg_status.Good_signature_by reported ->
         Gpg_status.key_id_matches_fingerprint ~key_id:reported ~fingerprint:full
     | _ -> false);
  check "a GOODSIG with no VALIDSIG still verifies, on the short id"
    (match Gpg_status.parse "[GNUPG:] GOODSIG 35715893BCA6F73D x\n" with
     | Gpg_status.Good_signature_by reported -> String.length reported = 16
     | _ -> false);
  check "a VALIDSIG with no GOODSIG is NOT a good signature"
    (match Gpg_status.parse ("[GNUPG:] VALIDSIG " ^ full ^ " 2026\n") with
     | Gpg_status.No_good_signature -> true
     | _ -> false);
  check "a revoked key still vetoes, whatever VALIDSIG says"
    (match Gpg_status.parse
             ("[GNUPG:] REVKEYSIG 1 x\n[GNUPG:] GOODSIG 1 x\n[GNUPG:] VALIDSIG " ^ full ^ " 2026\n")
     with
     | Gpg_status.Revoked_key -> true
     | _ -> false);
  summarize ()
