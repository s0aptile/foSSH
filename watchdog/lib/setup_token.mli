(* §2.6: the first-run setup-token model, watchdog-owned. See .ml for
   the full design rationale (storage model, why Nonce.generate() over
   porting the Rust demo's base32 scheme, the burn ordering). *)

type error = Io_error of string | Hash_error of string

val describe_error : error -> string

(* Idempotent generate-or-recover, called on every watchdog start (not
   just the first) — the same shape as Core_pin/Keypair/Tls_identity's
   own ensure_* functions. If an operator key is already enrolled,
   there is nothing left to verify against, regardless of any leftover
   file. Otherwise: recovers the hash from [token_path] if it already
   exists, generating a fresh token there only if it doesn't. *)
val ensure : token_path:string -> operator_key_dir:string -> (unit, error) result

(* Constant-time compare of SHA256(submitted) against the live,
   in-memory hash [ensure] most recently established. [false] if
   nothing is currently live (never ensured, ensure failed, already
   burned, or a key is already enrolled). *)
val verify : string -> bool

(* §2.6's exact ordering: invalidates the in-memory hash first (once
   this returns, no concurrent or later [verify] call can ever succeed
   again for this token), then deletes the plaintext file second.
   Idempotent — a no-op success if nothing is currently live. *)
val burn : unit -> (unit, error) result
