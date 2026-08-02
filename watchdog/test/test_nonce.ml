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
  summarize ()
