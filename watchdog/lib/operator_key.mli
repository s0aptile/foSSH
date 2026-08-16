type error =
  | Already_enrolled
  | Import_failed of string
  | Fingerprint_not_found
  | Multiple_keys_imported
  | Io_error of string

val describe_error : error -> string

val gnupghome_of : dir:string -> string

val enroll : dir:string -> string -> (string, error) result

val enrolled_fingerprint : dir:string -> (string option, error) result
