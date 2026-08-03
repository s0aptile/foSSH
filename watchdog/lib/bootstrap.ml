(* §2.4: the watchdog's half of the one-time bootstrap handoff —
   connects to core's Unix domain socket and sends its own public
   key/cert fingerprint, exactly once. Core (`fossh-svc`) is the
   listener; see `fossh-admin::watchdog_pin` (the Rust crate) for its
   side and the SO_PEERCRED-based peer verification that actually
   enforces "this really is the watchdog process", not just
   "something connected to the right socket path".

   **Extended beyond the original OpenPGP-fingerprint-only exchange**
   (see ADR-0048/ADR-0050): §3.4's QUIC mTLS needs each side to hold
   the other's actual X.509 certificate content, not just an OpenPGP
   fingerprint — quiche/BoringSSL loads a real PEM certificate as a
   trust anchor, not a hash of one. The wire exchange is now: this
   side sends its OpenPGP fingerprint (one line, newline-terminated,
   exactly as before), then its X.509 certificate (a PEM block
   terminated by its own "-----END CERTIFICATE-----" line — PEM's own
   delimiter used as-is, not a new framing convention invented here);
   core verifies the peer via SO_PEERCRED, persists both, and writes
   *its own* X.509 certificate back over the same connection before it
   closes — which this module reads and returns to its caller. Still
   one Unix-domain-socket round trip, not a new transport. *)

let max_cert_pem_len = 8192
let cert_pem_end_marker = "-----END CERTIFICATE-----"

type error =
  | Connect_failed of string
  | Send_failed of string
  | Recv_failed of string
  | Peer_cert_too_large of int
  | Peer_cert_unterminated

let describe_error = function
  | Connect_failed e -> Printf.sprintf "could not connect to core: %s" e
  | Send_failed e -> Printf.sprintf "could not send handoff to core: %s" e
  | Recv_failed e -> Printf.sprintf "could not read core's reply: %s" e
  | Peer_cert_too_large n ->
      Printf.sprintf "core's certificate reply exceeded the %d-byte cap (got %d)" max_cert_pem_len n
  | Peer_cert_unterminated ->
      "core's certificate reply ended before a terminating \"-----END CERTIFICATE-----\" line"

let ensure_trailing_newline (s : string) : string =
  if String.length s > 0 && s.[String.length s - 1] = '\n' then s else s ^ "\n"

(* Mirrors `fossh_admin::watchdog_pin::read_pem_block` exactly: read
   lines until one equals the end marker, bounded by `max_cert_pem_len`
   checked after every line (not only at the end), so a peer that never
   sends the marker is `Peer_cert_unterminated`, not an unbounded read
   or a silent hang. `input_line` already strips the trailing newline
   itself, so no separate trim is needed before the equality check.

   Two distinct ways a read can fail short of a full block, both
   caught here rather than left to escape as an uncaught exception (a
   real, reproduced crash during development: a peer that closes with
   this side's already-sent bytes still unread in its receive buffer
   makes the kernel treat the close as abortive, and the next read
   here raises `Sys_error "Connection reset by peer"`, not
   `End_of_file` — the same "uncaught exception takes down the whole
   process" failure class ADR-0041 already found and fixed elsewhere
   in this codebase, recurring here in new code): a clean EOF
   (`End_of_file`) and a lower-level I/O failure like a reset
   connection (`Sys_error`) are reported as the distinct
   `Peer_cert_unterminated` / `Recv_failed` cases respectively, both
   typed results, never a bare exception escaping to the caller. *)
let read_pem_block (ic : in_channel) : (string, error) result =
  let buf = Buffer.create 512 in
  let rec go () =
    match input_line ic with
    | exception End_of_file -> Error Peer_cert_unterminated
    | exception Sys_error msg -> Error (Recv_failed msg)
    | line -> (
        Buffer.add_string buf line;
        Buffer.add_char buf '\n';
        if Buffer.length buf > max_cert_pem_len then Error (Peer_cert_too_large (Buffer.length buf))
        else if line = cert_pem_end_marker then Ok (Buffer.contents buf)
        else go ())
  in
  go ()

(* Sends this side's fingerprint and certificate, then reads and
   returns core's own certificate PEM from its reply. Both writes
   happen before any read: core's own reader is line/marker-bounded,
   not EOF-bounded (see the Rust side's `read_line`/`read_pem_block`),
   so no half-close or shutdown is needed between writing and
   reading. *)
let send_handoff ~(socket_path : string) ~(fingerprint : string) ~(cert_pem : string) :
    (string, error) result =
  match Unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 with
  | exception Unix.Unix_error (e, fn, _) ->
      Error (Connect_failed (Printf.sprintf "%s: %s" fn (Unix.error_message e)))
  | sock ->
      Fun.protect
        ~finally:(fun () -> try Unix.close sock with Unix.Unix_error _ -> ())
        (fun () ->
          match Unix.connect sock (Unix.ADDR_UNIX socket_path) with
          | exception Unix.Unix_error (e, fn, _) ->
              Error (Connect_failed (Printf.sprintf "%s: %s" fn (Unix.error_message e)))
          | () -> (
              let oc = Unix.out_channel_of_descr sock in
              match
                output_string oc (fingerprint ^ "\n");
                output_string oc (ensure_trailing_newline cert_pem);
                flush oc
              with
              | exception Sys_error msg -> Error (Send_failed msg)
              | () ->
                  let ic = Unix.in_channel_of_descr sock in
                  read_pem_block ic))

(* Core and the watchdog are two independently-started processes with
   no guaranteed ordering — whichever starts first will find nobody
   listening yet on the very first attempt. A short, bounded retry
   loop is a genuine operational necessity here, not a test-only
   convenience; a one-time bootstrap step failing outright just
   because it happened to run half a second before core finished its
   own startup would be a real, avoidable reliability gap. *)
let send_handoff_with_retry ~(socket_path : string) ?(max_attempts = 50) ?(delay_seconds = 0.1)
    ~(fingerprint : string) (cert_pem : string) : (string, error) result =
  let rec go attempt last_error =
    if attempt >= max_attempts then Error last_error
    else
      match send_handoff ~socket_path ~fingerprint ~cert_pem with
      | Ok core_cert_pem -> Ok core_cert_pem
      | Error e ->
          Unix.sleepf delay_seconds;
          go (attempt + 1) e
  in
  go 0 (Connect_failed "no attempts made")
