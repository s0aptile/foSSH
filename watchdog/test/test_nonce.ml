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
  summarize ()
