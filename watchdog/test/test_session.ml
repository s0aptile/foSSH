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

  Session.revoke_all ();
  for _ = 1 to 50 do
    ignore (Session.issue ~lifetime_seconds:0.05 ())
  done;
  check "50 abandoned tokens are all live while unexpired" (Session.live_count () = 50);
  Unix.sleepf 0.15;
  check "abandoned tokens are reclaimed once expired, without anyone looking them up"
    (Session.live_count () = 0);

  Session.revoke_all ();
  let first_of_the_batch = Session.issue () in
  let issued = ref 1 in
  let refused = ref false in
  (try
     for _ = 1 to Session.max_live_sessions + 10 do
       ignore (Session.issue ());
       incr issued
     done
   with Session.Too_many_sessions -> refused := true);
  check "issuing past the cap raises rather than growing forever" !refused;
  check "the cap is where it says it is" (!issued = Session.max_live_sessions);
  check "the table stops at the cap" (Session.live_count () = Session.max_live_sessions);

  Session.revoke first_of_the_batch;
  let recovered =
    match Session.issue () with exception Session.Too_many_sessions -> false | _ -> true
  in
  check "revoking one session makes room for the next" recovered;

  summarize ()
