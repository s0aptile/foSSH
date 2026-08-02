(* Short-lived session tokens (§2.1): issued once a challenge-response
   round succeeds, so a client doesn't have to re-sign a nonce for
   every subsequent request in the same session. Held in memory only,
   never on disk — a watchdog restart invalidating every outstanding
   session is the correct, conservative failure mode for a component
   whose entire job is being the trust anchor after a restart; a
   session that silently survived a watchdog restart would mean an
   already-authenticated client outlives the process that authenticated
   it. *)

type entry = { expires_at : float }

let sessions : (string, entry) Hashtbl.t = Hashtbl.create 16
let default_lifetime_seconds = 900.0 (* 15 minutes *)

let issue ?(lifetime_seconds = default_lifetime_seconds) () : string =
  let token = Nonce.generate () in
  Hashtbl.replace sessions token
    { expires_at = Unix.gettimeofday () +. lifetime_seconds };
  token

(* Expired entries are pruned lazily, on lookup, rather than by a
   background timer — this module has no thread/event loop of its own
   and shouldn't need one just to garbage-collect a handful of tokens
   that expire in minutes. *)
let is_valid (token : string) : bool =
  match Hashtbl.find_opt sessions token with
  | None -> false
  | Some e ->
      if Unix.gettimeofday () > e.expires_at then (
        Hashtbl.remove sessions token;
        false)
      else true

let revoke (token : string) : unit = Hashtbl.remove sessions token
let revoke_all () : unit = Hashtbl.reset sessions
