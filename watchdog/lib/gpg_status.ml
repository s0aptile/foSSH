type verdict =
  | Good_signature_by of string
  | Revoked_key
  | Expired_key
  | No_good_signature

let has_line_starting_with (lines : string list) (prefix : string) : bool =
  List.exists
    (fun l ->
      String.length l >= String.length prefix
      && String.sub l 0 (String.length prefix) = prefix)
    lines

let validsig_fingerprint (lines : string list) : string option =
  let prefix = "[GNUPG:] VALIDSIG " in
  List.find_map
    (fun l ->
      if
        String.length l > String.length prefix
        && String.sub l 0 (String.length prefix) = prefix
      then
        let rest =
          String.sub l (String.length prefix) (String.length l - String.length prefix)
        in
        let field = match String.index_opt rest ' ' with
          | Some i -> String.sub rest 0 i
          | None -> rest
        in

        if String.length field = 40 then Some field else None
      else None)
    lines

let goodsig_key_id (lines : string list) : string option =
  let prefix = "[GNUPG:] GOODSIG " in
  List.find_map
    (fun l ->
      if
        String.length l > String.length prefix
        && String.sub l 0 (String.length prefix) = prefix
      then
        let rest =
          String.sub l (String.length prefix) (String.length l - String.length prefix)
        in
        match String.index_opt rest ' ' with
        | Some i -> Some (String.sub rest 0 i)
        | None -> Some rest
      else None)
    lines

let parse (status_text : string) : verdict =
  let lines = String.split_on_char '\n' status_text in
  if has_line_starting_with lines "[GNUPG:] REVKEYSIG" then Revoked_key
  else if has_line_starting_with lines "[GNUPG:] EXPKEYSIG" then Expired_key
  else

    match goodsig_key_id lines with
    | None -> No_good_signature
    | Some key_id -> (
        match validsig_fingerprint lines with
        | Some fingerprint -> Good_signature_by fingerprint
        | None -> Good_signature_by key_id)

let key_id_matches_fingerprint ~(key_id : string) ~(fingerprint : string) :
    bool =
  let key_id = String.uppercase_ascii key_id in
  let fingerprint = String.uppercase_ascii fingerprint in
  let kl = String.length key_id and fl = String.length fingerprint in
  kl > 0 && fl >= kl && String.sub fingerprint (fl - kl) kl = key_id
