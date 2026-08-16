type entry = { expires_at : float }

let sessions : (string, entry) Hashtbl.t = Hashtbl.create 16
let default_lifetime_seconds = 900.0

let max_live_sessions = 256

exception Too_many_sessions

let prune_expired () : unit =
  let now = Unix.gettimeofday () in
  let dead = Hashtbl.fold (fun t e acc -> if now > e.expires_at then t :: acc else acc) sessions [] in
  List.iter (Hashtbl.remove sessions) dead

let live_count () : int =
  prune_expired ();
  Hashtbl.length sessions

let issue ?(lifetime_seconds = default_lifetime_seconds) () : string =

  prune_expired ();
  if Hashtbl.length sessions >= max_live_sessions then raise Too_many_sessions;
  let token = Nonce.generate () in
  Hashtbl.replace sessions token
    { expires_at = Unix.gettimeofday () +. lifetime_seconds };
  token

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

let touch ?(lifetime_seconds = default_lifetime_seconds) (token : string) : unit =
  match Hashtbl.find_opt sessions token with
  | None -> ()
  | Some e ->
      if Unix.gettimeofday () > e.expires_at then Hashtbl.remove sessions token
      else Hashtbl.replace sessions token { expires_at = Unix.gettimeofday () +. lifetime_seconds }
