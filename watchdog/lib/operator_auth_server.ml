(* See .mli for the wire protocol. *)

let sig_end_marker = "-----END PGP SIGNATURE-----"
let max_signature_len = 8192

(* §2.6/§3.11's first-run setup flow, added alongside the
   already-existing challenge-response flow above (see this module's
   own .mli for the combined wire protocol). "SETUP " with the
   trailing space is the literal prefix a client's single command line
   must start with, matching this project's own established minimal-
   parsing style (Command_protocol's fixed-prefix parsing) rather than
   a heavier framed/length-prefixed format for what is, on the wire,
   still just one line. *)
let setup_command_prefix = "SETUP "
let max_setup_command_len = 4096
let public_key_end_marker = "-----END PGP PUBLIC KEY BLOCK-----"
let max_public_key_len = 262144

(* A client that connects and never writes (or never finishes writing)
   would otherwise block this single-threaded accept loop forever,
   denying the auth gate to every legitimate connection queued behind
   it. Two layers close this, not one: SO_RCVTIMEO/SO_SNDTIMEO bound
   any single blocking syscall (same 10s budget quic_command_server.ml's
   own deadline_in 10.0 already uses for the analogous channel), and
   read_signature_block's own overall wall-clock deadline bounds the
   whole connection regardless of how many individual syscalls a slow
   drip spreads across -- see that function's own comment for why the
   socket timeout alone was not enough. *)
let default_connection_timeout_seconds = 10.0

let log fmt = Printf.eprintf ("fossh-watchdog(auth): " ^^ fmt ^^ "\n%!")

type config = { socket_path : string; operator_key_dir : string }

let send_line (oc : out_channel) (line : string) : (unit, string) result =
  match
    output_string oc line;
    output_char oc '\n';
    flush oc
  with
  | () -> Ok ()
  | exception Sys_error msg -> Error msg
  | exception Sys_blocked_io -> Error "timed out"

let contains_substring ~(needle : string) (haystack : string) : bool =
  let hn = String.length needle and hh = String.length haystack in
  let rec go i = (i + hn <= hh) && (String.sub haystack i hn = needle || go (i + 1)) in
  hn = 0 || go 0

(* Adversarial review (real repro, twice): a first fix here checked an
   overall wall-clock deadline before each `input_line` call -- looked
   right, measured wrong. A byte-at-a-time drip with no newline ever
   sent keeps a SINGLE `input_line` call blocked indefinitely, since
   it loops internally across many small `read()`s (each individually
   bounded by SO_RCVTIMEO, none of them ever seeing the drip gap
   needed to time out) without ever returning control to the deadline
   check between calls -- reproduced directly: the check fired zero
   times, the connection only ever unblocked once the drip itself
   stopped and a read finally sat idle past SO_RCVTIMEO, at ~2.6x the
   intended deadline. Fixed for real by reading raw bytes via
   Unix.read directly instead of the buffered channel, so the deadline
   check runs between every individual syscall, not every line --
   confirmed empirically this time to actually cut off a drip at the
   intended deadline, not the SO_RCVTIMEO fallback. A timed-out
   Unix.read raises Unix_error EAGAIN (confirmed directly, not
   assumed -- OCaml's Unix module does not raise Sys_blocked_io the
   way Stdlib channel ops do for the same underlying condition). *)
(* Generalized from a first version that only ever read up to
   [sig_end_marker] — the setup flow below needs the identical
   raw-Unix.read-with-a-deadline-checked-between-every-syscall
   discipline (see the comment above) to read a one-line command and,
   separately, an armored public-key block, so this takes the needle
   and the length cap as parameters rather than duplicating the whole
   function a second and third time. [read_signature_block] below is
   now a thin instance of this for the pre-existing caller.

   Adversarial review (real repro, two findings, both fixed here):

   1. CRITICAL — the original version called [contains_substring] on
      [Buffer.contents buf] (a full, fresh copy of the WHOLE
      accumulated buffer) after every single 256-byte chunk, making
      total work O(n^2) in the payload length. Harmless at the
      pre-existing [max_signature_len = 8192]; a real, measured 65+
      second single-threaded CPU burn from one ordinary (non-
      adversarial, non-trickled) write at the new
      [max_public_key_len = 262144] this flow introduces — which also
      starves every other connection queued behind it, since
      [accept_loop] is single-threaded. Fixed by only rescanning the
      *new* tail of the buffer each iteration (the old data plus up to
      [needle]'s own length minus one, the only region a
      newly-arrived needle could newly complete) via [Buffer.sub]
      rather than [Buffer.contents], and only materializing the full
      buffer once, on an actual match — O(n) total instead of O(n^2).

   2. MEDIUM — a client that pipelines its next message into the same
      underlying write as this one (e.g. sending "SETUP <token>\n" and
      the public-key block's opening bytes in one [write]/[sendall]
      call, a completely ordinary thing for a client library to do
      rather than waiting for SETUP_OK first) had those extra,
      already-buffered bytes silently discarded: each call started a
      fresh, empty [Buffer], so anything read past the first call's
      own needle was thrown away rather than carried into the next
      call, corrupting the start of an otherwise-valid key block.
      Fixed with an optional [~seed], prepended to this call's own
      buffer before the first scan (and before any socket read is even
      attempted, so a seed that already contains the needle resolves
      with zero syscalls) — handle_setup_flow below now threads
      whatever a SETUP-line read over-consumed into the public-key
      read's own seed instead of dropping it. *)
let read_until ?(seed = "") (conn : Unix.file_descr) ~(deadline : float) ~(needle : string)
    ~(max_len : int) : (string, [ `Unterminated | `Recv_failed of string ]) result =
  let needle_len = String.length needle in
  let buf = Buffer.create 512 in
  Buffer.add_string buf seed;
  let chunk = Bytes.create 256 in
  (* [scanned_len] is how much of [buf] was already covered by a
     previous (failed) scan — everything before [scanned_len -
     needle_len + 1] cannot newly contain the needle now that it
     didn't before, so only the tail from there on ever needs
     re-checking. *)
  let found_in_tail ~(scanned_len : int) : bool =
    let scan_from = max 0 (scanned_len - needle_len + 1) in
    let tail = Buffer.sub buf scan_from (Buffer.length buf - scan_from) in
    needle_len = 0 || contains_substring ~needle tail
  in
  let rec go ~(scanned_len : int) =
    if found_in_tail ~scanned_len then Ok (Buffer.contents buf)
    else if Unix.gettimeofday () > deadline then Error `Unterminated
    else if Buffer.length buf > max_len then Error `Unterminated
    else
      match Unix.read conn chunk 0 (Bytes.length chunk) with
      | exception Unix.Unix_error ((Unix.EAGAIN | Unix.EWOULDBLOCK), _, _) -> Error `Unterminated
      | exception Unix.Unix_error (e, fn, _) ->
          Error (`Recv_failed (Printf.sprintf "%s: %s" fn (Unix.error_message e)))
      | 0 -> Error `Unterminated
      | n ->
          let prev_len = Buffer.length buf in
          Buffer.add_subbytes buf chunk 0 n;
          go ~scanned_len:prev_len
  in
  go ~scanned_len:0

let read_signature_block (conn : Unix.file_descr) ~(deadline : float) :
    (string, [ `Unterminated | `Recv_failed of string ]) result =
  read_until conn ~deadline ~needle:sig_end_marker ~max_len:max_signature_len

let up_to_first_newline (s : string) : string =
  match String.index_opt s '\n' with Some i -> String.sub s 0 i | None -> s

(* The counterpart of [up_to_first_newline] — whatever a client had
   already pushed past its command line's own newline, in the same
   read, that [read_until] would otherwise discard. Fed forward as the
   next [read_until] call's [~seed] (see that function's own comment,
   finding 2) so a pipelining client's key-block bytes aren't lost. *)
let after_first_newline (s : string) : string =
  match String.index_opt s '\n' with
  | Some i -> String.sub s (i + 1) (String.length s - i - 1)
  | None -> ""

(* Never echoes Operator_key's own describe_error text back over the
   wire (unlike this module's other replies, which are already fixed,
   non-attacker-influenced strings) — that text can embed real gpg
   stderr output, which is useful in a server log but not something to
   hand an unauthenticated-so-far peer purely because it happened to
   guess a null/near-miss on this endpoint. Logged in full server-side
   instead (see handle_setup_flow's own call site). *)
let enroll_failure_code = function
  | Operator_key.Already_enrolled -> "already_enrolled"
  | Operator_key.Import_failed _ -> "invalid_key"
  | Operator_key.Fingerprint_not_found -> "invalid_key"
  | Operator_key.Multiple_keys_imported -> "multiple_keys"
  | Operator_key.Io_error _ -> "internal_error"

(* §2.6/§3.11's first-run setup flow: only ever reached right after
   NOT_ENROLLED (see handle_one_connection below) — once a key is
   enrolled this code path is simply never entered again for the
   lifetime of the install, which is what actually makes this "not a
   standing bypass" rather than a second, permanent way into
   Operator_key.enroll (see this module's .mli for the full wire
   protocol).

   Replay: no state from this function survives past the one
   connection it runs in. There is no server-side "SETUP_OK was
   already sent, now awaiting a key" flag stored anywhere outside this
   call's own local control flow, so a captured/observed valid SETUP
   submission from one connection cannot be replayed into completing
   enrollment from a *different*, later connection — a fresh
   connection gets a fresh NOT_ENROLLED/SETUP round trip and must
   supply the token again, still checked fresh against
   Setup_token.verify's current live state every single time. The
   token proof itself is also single-use independent of
   Operator_key.enroll's own Already_enrolled refusal: a successful
   enroll burns the token (Setup_token.burn) in the same call that
   produced it, so even a second connection racing in with a
   still-remembered-but-now-stale copy of the same token gets
   SETUP_DENIED, not a second chance at Already_enrolled. A *failed*
   enroll attempt (bad key material) deliberately does NOT burn the
   token — see the Ok/Error split below — so a garbled paste can be
   retried with the same still-valid token, matching §3.11's wizard
   flow (submit token once, then possibly retry key entry). *)
let handle_setup_flow (conn : Unix.file_descr) (oc : out_channel) ~(operator_key_dir : string)
    ~(deadline : float) : unit =
  match read_until conn ~deadline ~needle:"\n" ~max_len:max_setup_command_len with
  | Error `Unterminated -> ()
  | Error (`Recv_failed msg) -> log "could not read setup command: %s" msg
  | Ok raw -> (
      let line = up_to_first_newline raw in
      (* Whatever the client already pushed past its own SETUP line's
         newline, in the same read, is a real prefix of the public-key
         block for a pipelining client (see read_until's own comment,
         finding 2) — carried forward as that read's seed rather than
         dropped. *)
      let leftover = after_first_newline raw in
      let prefix_len = String.length setup_command_prefix in
      if String.length line <= prefix_len || String.sub line 0 prefix_len <> setup_command_prefix then
        ignore (send_line oc "SETUP_DENIED")
      else
        let submitted = String.sub line prefix_len (String.length line - prefix_len) in
        if not (Setup_token.verify submitted) then ignore (send_line oc "SETUP_DENIED")
        else
          match send_line oc "SETUP_OK" with
          | Error msg -> log "could not send SETUP_OK: %s" msg
          | Ok () -> (
              match
                read_until conn ~deadline ~needle:public_key_end_marker ~max_len:max_public_key_len
                  ~seed:leftover
              with
              | Error `Unterminated -> ignore (send_line oc "ENROLL_FAILED unterminated_key")
              | Error (`Recv_failed msg) -> log "could not read public key material: %s" msg
              | Ok public_key_armored -> (
                  match Operator_key.enroll ~dir:operator_key_dir public_key_armored with
                  | Error e ->
                      log "setup enrollment attempt failed: %s" (Operator_key.describe_error e);
                      ignore (send_line oc (Printf.sprintf "ENROLL_FAILED %s" (enroll_failure_code e)))
                  | Ok fingerprint ->
                      (match Setup_token.burn () with
                      | Ok () -> ()
                      | Error e ->
                          log "enrollment succeeded but burning the setup token failed: %s"
                            (Setup_token.describe_error e));
                      ignore (send_line oc (Printf.sprintf "ENROLLED %s" fingerprint)))))

(* One connection's worth of work. Every failure here ends this one
   connection, never the accept loop -- see run's own catch-all around
   this call. *)
let handle_one_connection (conn : Unix.file_descr) ~(operator_key_dir : string) ~(deadline : float) : unit =
  let oc = Unix.out_channel_of_descr conn in
  match Operator_key.enrolled_fingerprint ~dir:operator_key_dir with
  | Error e -> log "could not read enrolled operator key: %s" (Operator_key.describe_error e)
  | Ok None -> (
      match send_line oc "NOT_ENROLLED" with
      | Error msg -> log "could not send NOT_ENROLLED: %s" msg
      | Ok () -> handle_setup_flow conn oc ~operator_key_dir ~deadline)
  | Ok (Some expected_key_fingerprint) -> (
      let nonce = Nonce.generate () in
      match send_line oc (Printf.sprintf "NONCE %s" nonce) with
      | Error msg -> log "could not send nonce: %s" msg
      | Ok () -> (
          match read_signature_block conn ~deadline with
          | Error `Unterminated -> ignore (send_line oc "DENIED")
          | Error (`Recv_failed msg) -> log "could not read signature: %s" msg
          | Ok signature_armored ->
              let gnupghome = Operator_key.gnupghome_of ~dir:operator_key_dir in
              let verified =
                Auth.verify_signature ~gnupghome ~expected_key_fingerprint ~data:nonce
                  ~signature_binary:signature_armored
              in
              (* Session.issue can refuse once the live-session cap is
                 reached. Letting that exception escape would take the
                 whole watchdog down over a full table, which is a
                 far worse outcome than one operator being told to try
                 again -- and the watchdog is the component whose job is
                 to still be running. *)
              let reply =
                if not verified then "DENIED"
                else
                  match Session.issue () with
                  | token -> Printf.sprintf "OK %s" token
                  | exception Session.Too_many_sessions ->
                      log "refusing a new session: %d already live" (Session.live_count ());
                      "DENIED"
              in
              ignore (send_line oc reply)))

let rec accept_loop ~(connection_timeout_seconds : float) (config : config) (listener : Unix.file_descr) :
    unit =
  (match Unix.accept listener with
  | exception Unix.Unix_error (e, fn, _) ->
      log "accept failed: %s: %s" fn (Unix.error_message e);
      Unix.sleepf 0.5
  | conn, _ ->
      Fun.protect
        ~finally:(fun () -> try Unix.close conn with Unix.Unix_error _ -> ())
        (fun () ->
          try
            Unix.setsockopt_float conn Unix.SO_RCVTIMEO connection_timeout_seconds;
            Unix.setsockopt_float conn Unix.SO_SNDTIMEO connection_timeout_seconds;
            let deadline = Unix.gettimeofday () +. connection_timeout_seconds in
            handle_one_connection conn ~operator_key_dir:config.operator_key_dir ~deadline
          with e -> log "connection handler raised: %s" (Printexc.to_string e)));
  accept_loop ~connection_timeout_seconds config listener

let run ?(connection_timeout_seconds = default_connection_timeout_seconds) (config : config) :
    (unit, string) result =
  (* Adversarial review (real repro): a peer that closes its end right
     before this side's reply write delivers SIGPIPE, whose default
     disposition kills the whole process outright -- not a catchable
     Sys_error, the process is just gone before send_line's own error
     handling ever runs. Also set at main.ml's entry point (protects
     the whole binary, including the bootstrap-send path this module
     has nothing to do with); set here too so this module is safe on
     its own for any caller -- test or future embedder -- that doesn't
     happen to go through main.ml. Idempotent, harmless to set twice. *)
  Sys.set_signal Sys.sigpipe Sys.Signal_ignore;
  (try Sys.remove config.socket_path with Sys_error _ -> ());
  match Unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 with
  | exception Unix.Unix_error (e, fn, _) -> Error (Printf.sprintf "%s: %s" fn (Unix.error_message e))
  | sock -> (
      match
        (* Adversarial review (real repro): AF_UNIX sockets have no
           mode argument of their own -- the special file's
           permissions come from the process umask alone at bind()
           time. bind() then a separate chmod() left a measured,
           real window (0755 under this system's default 022 umask)
           where the socket was briefly world-connectable before the
           chmod caught up. Bracketing bind() with a tight umask
           creates it at the right mode directly, closing the window
           rather than narrowing it; the chmod stays as defense in
           depth for any umask this project doesn't control. *)
        let old_umask = Unix.umask 0o077 in
        let bind_result =
          try
            Unix.bind sock (Unix.ADDR_UNIX config.socket_path);
            Ok ()
          with Unix.Unix_error _ as e -> Error e
        in
        let (_ : int) = Unix.umask old_umask in
        (match bind_result with Ok () -> () | Error e -> raise e);
        Unix.chmod config.socket_path 0o600;
        Unix.listen sock 16
      with
      | () -> Ok (accept_loop ~connection_timeout_seconds config sock)
      | exception Unix.Unix_error (e, fn, _) ->
          (try Unix.close sock with Unix.Unix_error _ -> ());
          Error (Printf.sprintf "%s: %s" fn (Unix.error_message e)))
