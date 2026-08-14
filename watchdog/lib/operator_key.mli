(* §2.1/§3.11: storage for the enrolled human-operator public key that
   Auth.verify_signature pins against. Separate from Keypair (the
   watchdog's own manifest-signing key) and separate from Core_pin
   (core's X.509 cert) — three distinct pinned identities, not one. *)

type error =
  | Already_enrolled
  | Import_failed of string
  | Fingerprint_not_found
  | Multiple_keys_imported
  | Io_error of string

val describe_error : error -> string

(* The gnupghome Auth.verify_signature should be given alongside
   whatever fingerprint enrolled_fingerprint returns. *)
val gnupghome_of : dir:string -> string

(* Imports [public_key_armored] and pins its fingerprint under [dir].
   Refuses (does not replace) if a key is already enrolled. *)
val enroll : dir:string -> string -> (string, error) result

val enrolled_fingerprint : dir:string -> (string option, error) result
