(* §2.6: the first-run setup-token model, watchdog-owned. See .mli for
   the exported shape; this comment is the design rationale.

   The Rust demo implementation (crates/fossh-admin/src/setup_token.rs
   — at the time this module was written, only ever driven by
   fossh-tui's own standalone/demo mode; that demo mode has since been
   replaced with a real client of this module's own wire protocol, see
   fossh-tui/src/wizard.rs's module doc and DECISIONS.md's ADR-0059) is
   NOT reused here, and this is not an oversight:
   §3.3 asks for the watchdog's own dependency tree to stay minimal,
   and reusing that module would mean either linking OCaml against
   Rust FFI just for this, or hand-porting its base32 alphabet to OCaml
   purely for cosmetic cross-language format parity with a *demo* mode
   that is not itself the real source of truth. The real source of
   truth is whichever process actually generates the token and later
   verifies submissions against it — here, that is this module, alone,
   self-consistently. Nonce.generate() (64 lowercase hex chars, 256
   bits, already reads straight from /dev/urandom) is reused for the
   random token material rather than reimplementing a second encoding
   scheme: it's already the project's one audited CSPRNG entry point,
   already used for the exact same "single-use, high-entropy, human-
   copyable token" role for Session's own tokens.

   SHA256, specifically, per §2.6's own wording — matching
   setup_token.rs's own comment on the same point: this is the one
   place the chapter names a specific primitive, not BLAKE3 (used
   everywhere else in this project), and there's no reason to
   relitigate that. Hashing is done by shelling out to `sha256sum`
   (via Manifest.sha256_hex, already established there) rather than
   adding a second sha256 code path — the plaintext is written to a
   throwaway temp file (Tempfile.with_contents) purely so the existing
   file-hashing helper can be reused unchanged.

   Storage model — the actual design decision this module had to make
   that isn't just "port the Rust version": §2.6 says only
   SHA256(token) is ever stored, never the plaintext, "anywhere beyond
   that one file." The plaintext file at [token_path] is therefore the
   only durable, on-disk state this module owns; the hash is held
   *only* in memory (a mutable ref, guarded by a Mutex — see [state]
   below), never written to a second file anywhere. This is safe
   specifically because the plaintext file is durable and
   self-describing: if the watchdog restarts before setup completes,
   [ensure] just re-reads the still-present plaintext file and
   re-derives the identical hash from it — nothing is lost by not
   persisting the hash separately, and persisting it separately would
   only create a second copy of security-relevant state that could
   drift from the file (e.g. a hash file surviving a token file that
   got manually deleted, or vice versa). The only state that would
   actually be lost across a restart is a hash held in memory *without*
   the plaintext file surviving too — which is exactly the case §2.6
   itself already treats as intentional and terminal: once the file is
   deleted (burn), setup is over, and a restart finding no file and an
   already-enrolled key correctly reports "nothing left to verify
   against" (see [ensure]'s enrolled-first check) rather than trying to
   resurrect a dead token.

   Ordering inside [burn] mirrors setup_token.rs's own [burn] exactly,
   and for the same reason (see that function's doc comment, restated
   here since this is a from-scratch OCaml implementation rather than
   a call into it): invalidate the in-memory hash first — the
   security-critical half, since once [state] is cleared no concurrent
   or later [verify] call can ever succeed again for this token no
   matter what happens next — then delete the plaintext file second,
   as cleanup. The reverse order would leave the strictly worse window
   (plaintext gone, hash still live and usable by anyone holding an
   earlier copy of the file's contents); this order's worst case if the
   second step fails is an inert leftover file an operator can remove
   by hand, never a live credential. *)

type live_token = { path : string; hash : string }

let state : live_token option ref = ref None
let state_mutex = Mutex.create ()

type error = Io_error of string | Hash_error of string

let describe_error = function
  | Io_error e -> Printf.sprintf "setup-token I/O error: %s" e
  | Hash_error e -> Printf.sprintf "setup-token hashing error: %s" e

(* Adversarial review (real repro): Tempfile.with_contents's own
   Filename.temp_file call raises Sys_error (not Unix_error) whenever
   the temp directory is unwritable/full/missing -- unguarded here,
   this was a fourth instance of the exact "Stdlib channel op raises
   Sys_error, escapes as an uncaught exception" bug class already
   fixed three times elsewhere in this codebase (bootstrap.ml,
   core_pin.ml, and main.ml's own read of ensure_identity's cert path).
   Reached from ensure's recover path -- called on every watchdog
   restart while a token file exists but setup isn't finished yet --
   with no guard anywhere between here and main.ml's top level, this
   killed the entire watchdog process (not just denied the auth
   listener) on a real, plausible trigger (read-only/full /tmp under
   systemd hardening). Guarded once here so every caller (hash_of_file,
   generate_fresh, verify) gets it for free. *)
let sha256_hex_of_string (s : string) : (string, string) result =
  try Tempfile.with_contents s (fun path -> Manifest.sha256_hex path)
  with Sys_error msg -> Error msg

let hash_of_file (path : string) : (string, error) result =
  match Fileutil.read_all_bytes path with
  | exception Sys_error msg -> Error (Io_error msg)
  | contents -> (
      match sha256_hex_of_string (String.trim contents) with
      | Ok hash -> Ok hash
      | Error e -> Error (Hash_error e))

let recover ~(token_path : string) : (unit, error) result =
  match hash_of_file token_path with
  | Error e -> Error e
  | Ok hash ->
      Mutex.protect state_mutex (fun () -> state := Some { path = token_path; hash });
      Ok ()

(* Same flat try/with shape as Keypair.ensure_passphrase — the
   established local precedent for "generate a single secret, write it
   once at 0600 via O_EXCL, persist it" — deliberately not layering on
   extra defensive machinery (e.g. a fallback-to-recover branch on a
   racing EEXIST) that no sibling module in this codebase bothers with
   for the same class of once-at-startup, effectively-single-caller
   idempotent init either; a raced EEXIST here surfaces as an Io_error,
   same as it would for Keypair's own passphrase file. *)
let generate_fresh ~(token_path : string) : (unit, error) result =
  (try Unix.mkdir (Filename.dirname token_path) 0o700
   with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
  try
    let plaintext = Nonce.generate () in
    let fd = Unix.openfile token_path [ Unix.O_WRONLY; Unix.O_CREAT; Unix.O_EXCL ] 0o600 in
    let oc = Unix.out_channel_of_descr fd in
    output_string oc plaintext;
    close_out oc;
    match sha256_hex_of_string plaintext with
    | Ok hash ->
        Mutex.protect state_mutex (fun () -> state := Some { path = token_path; hash });
        Ok ()
    | Error e -> Error (Hash_error e)
  with
  | Unix.Unix_error (e, fn, _) -> Error (Io_error (Printf.sprintf "%s: %s" fn (Unix.error_message e)))
  | Sys_error msg -> Error (Io_error msg)

(* Idempotent, the same generate-or-recover shape as
   Core_pin/Keypair.ensure_passphrase/Tls_identity.ensure_identity:
   call it on every watchdog start, not just the first.

   Checks enrollment status FIRST, before even looking at the
   filesystem for a token file — if an operator key is already
   enrolled, there is nothing left to legitimately verify a setup
   token against (Operator_key.enroll's own Already_enrolled refusal
   is the real, independent protection at that point regardless of
   what this module does), so this deliberately does not try to
   "recover" a hash from a stale leftover token file that might still
   be sitting on disk (e.g. because a previous burn's file-deletion
   step failed after its hash-invalidation step already succeeded —
   see burn's own doc comment). Only when nothing is enrolled yet does
   it fall back to "recover from an existing file" or, failing that,
   "generate a fresh one" — matching prrr.md's own instruction: "only
   generate fresh if no token file exists AND no key is enrolled yet." *)
let ensure ~(token_path : string) ~(operator_key_dir : string) : (unit, error) result =
  match Operator_key.enrolled_fingerprint ~dir:operator_key_dir with
  | Error e -> Error (Io_error (Operator_key.describe_error e))
  | Ok (Some _) ->
      Mutex.protect state_mutex (fun () -> state := None);
      Ok ()
  | Ok None -> if Sys.file_exists token_path then recover ~token_path else generate_fresh ~token_path

(* Constant-time compare (Nonce.constant_time_equal — safe here since
   both sides are fixed-length, non-secret-length hex-encoded SHA256
   digests, exactly the property that function's own doc comment
   requires of any call site) of SHA256(submitted) against whatever
   [ensure] most recently established as live. [false] if nothing is
   currently live — never ensured, ensure failed, already burned, or a
   key is already enrolled — a fail-closed default, not an error. *)
let verify (submitted : string) : bool =
  match Mutex.protect state_mutex (fun () -> !state) with
  | None -> false
  | Some { hash; _ } -> (
      match sha256_hex_of_string submitted with
      | Error _ -> false
      | Ok submitted_hash -> Nonce.constant_time_equal submitted_hash hash)

(* See this module's header comment for the full ordering rationale.
   Idempotent: a [burn] call when nothing is live (never ensured,
   ensure failed, or already burned by an earlier call) is a no-op
   success, not an error — a retry after a partial earlier failure
   (e.g. the file-delete half failing last time) must not itself fail,
   and must not require the caller to know whether a previous attempt
   partially succeeded. Thread-safe by construction: the mutex-guarded
   swap below is the one moment [state] transitions, so two concurrent
   [burn] calls can never both observe (and act on) the same live
   token — at most one ever sees [Some], the other sees [None] and
   returns immediately. *)
let burn () : (unit, error) result =
  match Mutex.protect state_mutex (fun () ->
            let current = !state in
            state := None;
            current)
  with
  | None -> Ok ()
  | Some { path; _ } -> (
      match Unix.unlink path with
      | () -> Ok ()
      | exception Unix.Unix_error (Unix.ENOENT, _, _) -> Ok ()
      | exception Unix.Unix_error (e, fn, _) ->
          Error (Io_error (Printf.sprintf "%s: %s" fn (Unix.error_message e))))
