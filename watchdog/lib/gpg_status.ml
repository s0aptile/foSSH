(* Parses GnuPG's `--status-file` line protocol (`[GNUPG:] KEYWORD
   args...`) just enough to answer the one question every caller in
   this codebase needs: did this verify against a good, non-revoked,
   non-expired signature by exactly the expected key?

   This exists because `gpgv`'s bare exit code — what `Auth` and
   `Manifest` originally used — was found (adversarial review, first
   QA pass on this component) to say nothing at all about key
   revocation or expiry: a signature made by a since-revoked key still
   exits 0 with "Good signature". `gpgv` is documented as a minimal,
   policy-free verifier by design; the fix is to use full `gpg
   --verify`/`--decrypt` and read its status vocabulary instead of
   trusting the exit code alone. See ADR-0041. *)

type verdict =
  | Good_signature_by of string  (** the 16-hex-char long key ID GOODSIG reported *)
  | Revoked_key
  | Expired_key
  | No_good_signature

let has_line_starting_with (lines : string list) (prefix : string) : bool =
  List.exists
    (fun l ->
      String.length l >= String.length prefix
      && String.sub l 0 (String.length prefix) = prefix)
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

(* Deliberately checks REVKEYSIG/EXPKEYSIG only, not the more general
   KEYREVOKED/KEYEXPIRED — per GnuPG's own DETAILS documentation
   (/usr/share/doc/gnupg2/DETAILS, "KEYEXPIRED" entry): "This status
   line is not very useful because it will also be emitted for
   expired subkeys even if this subkey is not used. To check whether
   a key used to sign a message has expired, the EXPKEYSIG status
   line is to be used." KEYREVOKED has the same "which key, in what
   context" ambiguity. REVKEYSIG/EXPKEYSIG are documented as emitted
   specifically when *the signature being checked* was made by a
   revoked/expired key — exactly the question this function answers —
   so using the broader pair would risk rejecting a perfectly good,
   current signature over an unrelated expired/revoked subkey. Per
   DETAILS: "For each signature only one of the codes GOODSIG, BADSIG,
   EXPSIG, EXPKEYSIG, REVKEYSIG or ERRSIG will be emitted" — REVKEYSIG
   and GOODSIG are mutually exclusive for the same signature, so
   checking REVKEYSIG/EXPKEYSIG first is a precise veto, not a
   defensive guess. *)
let parse (status_text : string) : verdict =
  let lines = String.split_on_char '\n' status_text in
  if has_line_starting_with lines "[GNUPG:] REVKEYSIG" then Revoked_key
  else if has_line_starting_with lines "[GNUPG:] EXPKEYSIG" then Expired_key
  else
    match goodsig_key_id lines with
    | Some key_id -> Good_signature_by key_id
    | None -> No_good_signature

(* A v4 OpenPGP long key ID is the low-order 64 bits (16 hex chars) of
   the full 40-hex-char fingerprint — checking suffix match lets
   callers pin a full fingerprint (what they actually store/compare
   for "the enrolled key") against what GOODSIG reports (always the
   shorter form), without this module needing to know or care which
   length the caller happened to keep on hand. *)
let key_id_matches_fingerprint ~(key_id : string) ~(fingerprint : string) :
    bool =
  let key_id = String.uppercase_ascii key_id in
  let fingerprint = String.uppercase_ascii fingerprint in
  let kl = String.length key_id and fl = String.length fingerprint in
  kl > 0 && fl >= kl && String.sub fingerprint (fl - kl) kl = key_id
