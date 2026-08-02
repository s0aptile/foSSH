open Fossh_watchdog_lib
open Test_helpers

let () =
  let t = Session.issue () in
  check "freshly issued token is valid" (Session.is_valid t);
  check "a random string is not a valid token" (not (Session.is_valid (Nonce.generate ())));

  Session.revoke t;
  check "revoked token is no longer valid" (not (Session.is_valid t));

  let short = Session.issue ~lifetime_seconds:0.05 () in
  check "just-issued short-lived token is valid" (Session.is_valid short);
  Unix.sleepf 0.15;
  check "short-lived token is invalid once expired" (not (Session.is_valid short));

  let a = Session.issue () in
  let b = Session.issue () in
  check "two issued tokens are distinct" (a <> b);

  Session.revoke_all ();
  check "revoke_all clears an outstanding token" (not (Session.is_valid a));

  summarize ()
