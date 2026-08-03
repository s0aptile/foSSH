(* §2.4/§3.4: the watchdog's own per-install X.509 identity for the
   QUIC/mTLS channel to core — generated once on first start, reused
   on every start after that, the same idempotent shape as Keypair's
   OpenPGP key (ensure_keypair) but for a completely different
   purpose and format: quiche/BoringSSL's mTLS needs a real X.509
   certificate + private key, not an OpenPGP key, and nothing before
   this module generated one anywhere in this project — see ADR-0048
   for how that gap was found and the full plan around it (this
   module is only the first, self-contained piece of that plan; the
   bootstrap handoff's own wire format still needs to grow to carry a
   full certificate, and core's Rust side needs its own equivalent —
   both real, tracked follow-ups, not built here).

   EC P-256, not Ed25519: matches the exact curve `crates/fossh-ipc`'s
   and `watchdog/quic/`'s own tests already proved interoperates
   correctly with quiche's BoringSSL backend, after an earlier version
   of that test infrastructure hit a real `Quiche(TlsFail)` using
   Ed25519 instead (see ADR-0044). No reason to risk rediscovering
   that here with a real, persistent identity instead of a disposable
   test one. *)

let openssl_path = "/usr/bin/openssl"

(* 10 years, not the 1-day validity every existing test fixture in
   this project uses for a throwaway cert generated fresh per test run
   — this certificate is meant to persist for an install's whole
   lifetime, pinned once by the peer at bootstrap and never silently
   rotated (§2.4: "Regeneration requires a full re-bootstrap handoff,
   not a silent rotation"). A certificate that quietly expired on its
   own well before an operator ever chose to rotate anything would
   defeat that guarantee just as surely as a silent rotation would,
   just via a different mechanism. *)
let validity_days = 3650

type error =
  | Generate_failed of string
  | Invalid_common_name of string
  | Io_error of string

let describe_error = function
  | Generate_failed e -> Printf.sprintf "generating TLS identity: %s" e
  | Invalid_common_name cn -> Printf.sprintf "invalid common name %S" cn
  | Io_error e -> Printf.sprintf "TLS identity I/O error: %s" e

type t = { cert_pem_path : string; key_pem_path : string }

(* Only characters that can never be misread by `openssl req -subj`'s
   own `/key=value` grammar — rejecting anything else (rather than
   trying to escape it) closes a real, reproduced Subject-DN injection
   found by adversarial review: `common_name` containing a literal `/`
   or `=` lets a caller smuggle *additional* RDN fields into the
   certificate's Subject (confirmed: "innocuous/O=Evil Corp/OU=Fake
   Unit" produces a three-field Subject from one string argument).
   Nothing in this project currently trusts a certificate's Subject DN
   for any security decision (pinning here is exact-byte, not CN/SAN
   based — see quic.ml's own TlsPaths doc comment), so this isn't
   exploitable today, but there is no legitimate reason for a common
   name to need either character, and rejecting up front is cheaper
   and safer than trying to get `-subj` escaping right. *)
let valid_common_name_re =
  let is_ok c =
    (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c = '-' || c = '.'
  in
  fun s -> String.length s > 0 && String.length s <= 64 && String.for_all is_ok s

(* Real validity, not merely "the file exists and is non-empty" —
   asks openssl's own parser, the same authority that will actually
   load this file later, rather than a size/existence proxy for it.
   This is what makes ensure_identity below safe against a half-
   written identity left behind by an interrupted previous run (killed
   mid-generation, disk full partway through, etc.): openssl req
   writes cert.pem and key.pem directly, with no atomic rename-into-
   place of its own, so a prior failure could leave either file
   missing, empty, or truncated garbage under its final name.
   Regenerating over a genuinely *invalid* leftover is not the
   "silently orphan an existing pin" risk this module's idempotency
   otherwise guards against — an unusable identity was never
   functional (and, since it was never usable, nothing could
   legitimately have pinned it yet either) — so falling through to
   regenerate is a safe default, not a compromise.

   cert_is_valid also checks the certificate has not expired (-checkend
   0), not just that it parses — adversarial review confirmed a bare
   `openssl x509 -noout` parse exits 0 on a certificate that expired
   years ago; `-checkend 0` is what actually answers "is this usable
   right now", which is the question this function exists to answer.
   Without it, this module's own 10-year-validity design rationale (a
   cert that silently expires defeats the "no silent rotation"
   guarantee just as surely as an actual silent rotation would) would
   have nothing in the code actually enforcing it — the identity would
   just keep reporting itself healthy past its own expiry. *)
let cert_is_valid (path : string) : bool =
  Sys.file_exists path
  &&
  match
    Subprocess.run ~prog:openssl_path
      ~argv:[| "openssl"; "x509"; "-in"; path; "-noout"; "-checkend"; "0" |]
      ~stdin_content:""
  with
  | Ok _ -> true
  | Error _ -> false

let key_is_valid (path : string) : bool =
  Sys.file_exists path
  &&
  match
    Subprocess.run ~prog:openssl_path ~argv:[| "openssl"; "pkey"; "-in"; path; "-noout" |]
      ~stdin_content:""
  with
  | Ok _ -> true
  | Error _ -> false

(* Guards the whole check-then-generate-then-persist sequence in
   ensure_identity below against two callers racing on the same
   directory — adversarial review reproduced this for real: two
   concurrent `openssl req` invocations targeting the same cert.pem/
   key.pem paths independently, each individually well-formed, landed
   as a *mismatched* pair (this invocation's key, that invocation's
   cert) in 10 of 80 trials — a state cert_is_valid/key_is_valid
   cannot detect (each file is individually perfectly valid) and that
   persists forever once it happens, since nothing else in this module
   ever re-derives or cross-checks the pairing. A plain OCaml Mutex is
   what actually closes this for the reachable case: this module is
   meant to be called once at process startup, but ADR-0048's own
   near-term plan calls for adding a QUIC-serving background thread to
   the watchdog next, and it is exactly the kind of future refactor
   that could plausibly end up calling this from two threads during
   startup without anyone noticing the collision. A `Unix.lockf`-style
   file lock was considered instead/also, for the separate cross-
   *process* case (e.g. the watchdog accidentally started twice) — not
   added here, since POSIX advisory locks are scoped to the process,
   not the thread, so one alone would not have closed the actually-
   reproduced race above, and guarding against a second full watchdog
   instance running at all is a deployment-level concern handled
   elsewhere in this project (e.g. fossh-fcgi's own socket_is_live
   check), not something this key-generation module should also take
   on. *)
let generation_lock = Mutex.create ()

(* Idempotent: reuses the existing certificate and key at
   [dir]/cert.pem and [dir]/key.pem if both are already present *and*
   independently verified valid (see cert_is_valid/key_is_valid
   above — this is stronger than merely checking both files exist),
   generating a fresh keypair otherwise. Never regenerates over a
   genuinely valid, already-complete existing identity — mirrors
   Keypair.ensure_keypair's own reasoning exactly: a freshly generated
   certificate carries a new fingerprint, and this identity is handed
   off and pinned by the peer exactly once, so regenerating a *working*
   one out from under an existing pin would silently orphan that pin. *)
let ensure_identity ~(dir : string) ~(common_name : string) : (t, error) result =
  if not (valid_common_name_re common_name) then Error (Invalid_common_name common_name)
  else
    Mutex.protect generation_lock (fun () ->
        try
          (try Unix.mkdir dir 0o700 with Unix.Unix_error (Unix.EEXIST, _, _) -> ());
          let cert_pem_path = Filename.concat dir "cert.pem" in
          let key_pem_path = Filename.concat dir "key.pem" in
          if cert_is_valid cert_pem_path && key_is_valid key_pem_path then
            Ok { cert_pem_path; key_pem_path }
          else
            match
              Subprocess.run ~prog:openssl_path
                ~argv:
                  [|
                    "openssl"; "req"; "-x509"; "-newkey"; "ec"; "-pkeyopt";
                    "ec_paramgen_curve:prime256v1"; "-days"; string_of_int validity_days; "-nodes";
                    "-keyout"; key_pem_path; "-out"; cert_pem_path; "-subj";
                    Printf.sprintf "/CN=%s" common_name;
                  |]
                ~stdin_content:""
            with
            | Error e -> Error (Generate_failed e)
            | Ok _ ->
                (* Explicit, not left to umask — this is private key
                   material, and §2.3 requires files under the
                   watchdog's own directory be mode 600, not "whatever
                   the process's umask happened to produce". (Confirmed
                   separately that this project's openssl already
                   creates -keyout output at mode 600 by default, even
                   under umask 000 — this chmod is deliberate defense-
                   in-depth against a different/older openssl build
                   behaving less carefully, not compensation for an
                   active gap.) *)
                Unix.chmod key_pem_path 0o600;
                Ok { cert_pem_path; key_pem_path }
        with Unix.Unix_error (e, fn, _) -> Error (Io_error (Printf.sprintf "%s: %s" fn (Unix.error_message e))))
