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

(* Refusing rather than evicting: evicting to make room would let a
   client that can complete challenge-response repeatedly push every
   other operator's live session out, which is a worse failure than
   declining to open a new one. Well above any legitimate use — an
   install has a handful of operators, not hundreds. *)
let max_live_sessions = 256

exception Too_many_sessions

(* Drops every expired entry, not merely the one being looked up.
   Lazy pruning on lookup covers a token that is used again; it does
   nothing for one that is issued and then abandoned, and abandonment is
   the ordinary case — a client that reconnects completes a fresh
   challenge-response and simply never mentions the old token again.
   Those accumulated for the life of the process, which for a watchdog
   is measured in months. *)
let prune_expired () : unit =
  let now = Unix.gettimeofday () in
  let dead = Hashtbl.fold (fun t e acc -> if now > e.expires_at then t :: acc else acc) sessions [] in
  List.iter (Hashtbl.remove sessions) dead

let live_count () : int =
  prune_expired ();
  Hashtbl.length sessions

let issue ?(lifetime_seconds = default_lifetime_seconds) () : string =
  (* Before the table grows, not after: this is the only entry point
     that adds to it, so it is the only place a bound can hold. *)
  prune_expired ();
  if Hashtbl.length sessions >= max_live_sessions then raise Too_many_sessions;
  let token = Nonce.generate () in
  Hashtbl.replace sessions token
    { expires_at = Unix.gettimeofday () +. lifetime_seconds };
  token

(* Expired entries are also pruned lazily, on lookup — that path stays
   as it was, because it is the one that matters for correctness (an
   expired token must not validate) as opposed to for memory. *)
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

(* Extends an existing, still-valid session's expiry without changing
   its token value — "activity keeps a session alive," needed once a
   token represents a potentially long-lived channel (§3.4's QUIC
   connection between the watchdog and core, meant to persist for the
   install's whole uptime) rather than a single bounded request flow
   this module's original 15-minute default was sized for. A no-op,
   not an error, if the token is already invalid or unknown — the
   caller finds that out via is_valid, whatever check it was already
   going to do, not via this function's return value (it has none). *)
let touch ?(lifetime_seconds = default_lifetime_seconds) (token : string) : unit =
  match Hashtbl.find_opt sessions token with
  | None -> ()
  | Some e ->
      if Unix.gettimeofday () > e.expires_at then Hashtbl.remove sessions token
      else Hashtbl.replace sessions token { expires_at = Unix.gettimeofday () +. lifetime_seconds }
