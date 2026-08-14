(* §3.4: the watchdog's half of the steady-state watchdog<->core
   QUIC/mTLS IPC channel — the OCaml/ctypes counterpart to
   crates/fossh-ipc (core's side, which gets this for nearly free from
   quiche's safe Rust API). This module's connection-driving logic is
   a deliberate, close translation of fossh-ipc's own drive_until,
   connect, accept_one, send_on_stream, and recv_from_stream — right
   down to mirroring the exact phase ordering ADR-0044's two real,
   reproduced bugs on the Rust side forced: the done check runs only
   after both the recv-drain and send-drain phases, every pass, since
   checking earlier can return before a fatal recv error's send-drain
   pass ever runs, and quiche needs that pass to flush its own
   CONNECTION_CLOSE packet. Also ported: the 2ms poll granularity
   ADR-0045 measured on that same Rust side, a 24x-30x real difference
   between 100ms and 2ms, on the identical problem of a blocking read
   with a timeout being unable to tell nothing more, ever apart from
   check back soon without waiting the timeout out — which applies
   here via Unix.select's timeout exactly the way it applied to
   UdpSocket::set_read_timeout on the Rust side. Ported deliberately,
   not rediscovered from scratch, since both bugs were already paid
   for once.

   This module covers the transport primitives: real, verified
   connection establishment with mutual TLS and basic stream
   send/recv — matching fossh-ipc's own identical scope note. The
   app-level command protocol (session-token-bound commands, replay
   protection per §3.4's own requirement) and its wiring into the
   watchdog's real supervisor loop are built too, but live in
   lib/command_protocol.ml and quic/quic_command_server.ml
   respectively — see ADR-0047/ADR-0050 and dev/DURUM.md for exactly
   what's connected. *)

let quiche_err_done = -1
let quiche_max_conn_id_len = 20
let max_datagram_size = 1350
let recv_bufsize = 65535
let alpn = "fossh-ipc/1"

(* 2ms — see this file's own header comment and ADR-0045. `Unix.select`'s
   timeout, not a socket-level SO_RCVTIMEO: OCaml's `Unix` module does
   not expose the latter, and `select` gives the identical "wake up
   periodically without blocking forever on a peer that may never send
   again" property fossh-ipc's own read timeout exists for. *)
let socket_poll_timeout = 0.002

let af_inet = Quic_bindings.af_inet
let af_inet6 = Quic_bindings.af_inet6

type tls_paths = {
  cert_chain_pem : string;
  priv_key_pem : string;
  trusted_peer_cert_pem : string;
}

type error =
  | Quiche_error of int
  | Config_error of string
  | Address_error of string
  | Connection_failed
  | Connection_closed
  | Deadline_exceeded
  | Io_error of string

let describe_error = function
  | Quiche_error code -> Printf.sprintf "quiche error (code %d)" code
  | Config_error msg -> Printf.sprintf "quiche config error: %s" msg
  | Address_error msg -> Printf.sprintf "address error: %s" msg
  | Connection_failed -> "quiche_connect/quiche_accept returned NULL"
  | Connection_closed -> "connection closed"
  | Deadline_exceeded -> "deadline exceeded"
  | Io_error msg -> Printf.sprintf "I/O error: %s" msg

(* Used only within this file's own connect/accept_one to unwind a
   partially-built connection on any failure without either deeply
   nested Result matches or repeating the same cleanup logic at every
   branch — never escapes this module. *)
exception Setup_failed of error

type t = {
  conn : Quic_bindings.conn_t;
  (* Kept alive for the connection's whole lifetime, freed only in
     [close] — quiche.h itself documents quiche_config as "shared
     between multiple connections", meaning a connection cannot be
     assumed to hold its own independent copy of everything the config
     supplied (BoringSSL's own SSL_CTX/SSL pattern, which quiche is
     built on, normally works exactly this way: an SSL_CTX is
     reference-counted, not deep-copied, when an SSL is created from
     it). This is *more* conservative than fossh-ipc's own Rust side
     strictly needs to be: there, `config` is a purely local binding
     inside `connect`/`accept_one`, never part of either function's
     returned tuple, so it is dropped (freed) the moment the function
     returns — before the caller ever does anything else with the
     connection — and ADR-0044's own verification (5 consecutive clean
     handshake-plus-stream-round-trip runs) is real evidence that
     freeing that early is fine with this quiche version. This module
     does not rely on that evidence, since nothing here has actually
     tested freeing config early in OCaml specifically; keeping it
     alive until [close] costs one small, cheap-to-keep allocation in
     exchange for not needing to. *)
  config : Quic_bindings.config_t;
  socket : Unix.file_descr;
  local_family : int;
  local_ip : string;
  local_port : int;
  peer_family : int;
  peer_ip : string;
  peer_port : int;
  peer_sockaddr : Unix.sockaddr;
  (* [close] must tolerate being called more than once — quiche_conn_
     free/quiche_config_free are not idempotent like Unix.close is
     already treated as below, and freeing either twice is a real,
     reproduced double-free (glibc tcache abort), not a theoretical
     one. *)
  closed : bool ref;
}

(* Every `Unix.X` call anywhere in this module's connection-driving
   path (bind, select, sendto, recvfrom, and — via
   Fossh_watchdog_lib.Nonce.read_random_bytes's own open_in_bin —
   Sys_error from a channel op) can raise on a condition that is
   ordinary for this protocol, not exceptional: EADDRINUSE on bind,
   ECONNREFUSED/ENETUNREACH on a send after the peer vanished, and so
   on. fossh-ipc's own Rust side never has this gap — every socket call
   there already returns a `Result`, converted via `?` — so an
   OCaml function in this module raising instead of returning `Error`
   would be a real deviation from the thing this module is a deliberate
   port of, not just an inconvenience. Every public function below
   runs its body through this so a plain, ordinary I/O failure always
   comes back as `Error (Io_error _)`, never an uncaught exception. *)
let with_unix_errors_as_io_errors (f : unit -> ('a, error) result) : ('a, error) result =
  try f () with
  | Unix.Unix_error (e, fn, _) -> Error (Io_error (Printf.sprintf "%s: %s" fn (Unix.error_message e)))
  | Sys_error msg -> Error (Io_error msg)

let decompose_sockaddr (addr : Unix.sockaddr) : (int * string * int, error) result =
  match addr with
  | Unix.ADDR_UNIX _ -> Error (Address_error "expected an AF_INET(6) address, got a Unix socket path")
  | Unix.ADDR_INET (inet_addr, port) -> (
      match Unix.domain_of_sockaddr addr with
      | Unix.PF_INET -> Ok (af_inet, Unix.string_of_inet_addr inet_addr, port)
      | Unix.PF_INET6 -> Ok (af_inet6, Unix.string_of_inet_addr inet_addr, port)
      | Unix.PF_UNIX -> Error (Address_error "unexpected PF_UNIX for an ADDR_INET value"))

let encode_alpn_wire (proto : string) : bytes =
  let len = String.length proto in
  let b = Bytes.create (1 + len) in
  Bytes.set b 0 (Char.chr len);
  Bytes.blit_string proto 0 b 1 len;
  b

(* Shared by both client and server, matching fossh-ipc's own
   `build_config`: real mTLS (`verify_peer true` unconditionally —
   §3.4 requires both directions to verify the peer, not one side
   trusting the other by default) and identical transport parameters,
   so the two sides negotiate the same channel shape. *)
let build_config (tls : tls_paths) : (Quic_bindings.config_t, error) result =
  let cfg = Quic_bindings.quiche_config_new (Unsigned.UInt32.of_int 1) in
  if Ctypes.is_null cfg then Error (Config_error "quiche_config_new returned NULL")
  else
    let load name f path =
      let rc = f cfg path in
      if rc <> 0 then Error (Config_error (Printf.sprintf "%s(%s) failed (rc=%d)" name path rc)) else Ok ()
    in
    match load "quiche_config_load_cert_chain_from_pem_file"
            Quic_bindings.quiche_config_load_cert_chain_from_pem_file tls.cert_chain_pem
    with
    | Error e -> Quic_bindings.quiche_config_free cfg; Error e
    | Ok () -> (
        match load "quiche_config_load_priv_key_from_pem_file"
                Quic_bindings.quiche_config_load_priv_key_from_pem_file tls.priv_key_pem
        with
        | Error e -> Quic_bindings.quiche_config_free cfg; Error e
        | Ok () -> (
            match load "quiche_config_load_verify_locations_from_file"
                    Quic_bindings.quiche_config_load_verify_locations_from_file
                    tls.trusted_peer_cert_pem
            with
            | Error e -> Quic_bindings.quiche_config_free cfg; Error e
            | Ok () ->
                Quic_bindings.quiche_config_verify_peer cfg true;
                let alpn_wire = encode_alpn_wire alpn in
                let rc =
                  Quic_bindings.quiche_config_set_application_protos cfg
                    (Ctypes.ocaml_bytes_start alpn_wire)
                    (Unsigned.Size_t.of_int (Bytes.length alpn_wire))
                in
                if rc <> 0 then (
                  Quic_bindings.quiche_config_free cfg;
                  Error (Config_error (Printf.sprintf "quiche_config_set_application_protos failed (rc=%d)" rc)))
                else (
                  Quic_bindings.quiche_config_set_max_idle_timeout cfg (Unsigned.UInt64.of_int 30_000);
                  Quic_bindings.quiche_config_set_max_recv_udp_payload_size cfg
                    (Unsigned.Size_t.of_int max_datagram_size);
                  Quic_bindings.quiche_config_set_max_send_udp_payload_size cfg
                    (Unsigned.Size_t.of_int max_datagram_size);
                  Quic_bindings.quiche_config_set_initial_max_data cfg (Unsigned.UInt64.of_int 1_000_000);
                  Quic_bindings.quiche_config_set_initial_max_stream_data_bidi_local cfg
                    (Unsigned.UInt64.of_int 1_000_000);
                  Quic_bindings.quiche_config_set_initial_max_stream_data_bidi_remote cfg
                    (Unsigned.UInt64.of_int 1_000_000);
                  Quic_bindings.quiche_config_set_initial_max_streams_bidi cfg (Unsigned.UInt64.of_int 4);
                  Quic_bindings.quiche_config_set_disable_active_migration cfg true;
                  Ok cfg)))

(* Ok None: recv-drain finished cleanly (either nothing more was
   available within the poll window, or the peer's last packet this
   pass produced QUICHE_ERR_DONE). Ok (Some code): a fatal quiche-level
   error was seen and captured but NOT yet returned — see this file's
   header comment on why (mirrors fossh-ipc's `recv_error` local
   exactly). Error _: a genuine socket-level I/O failure, distinct
   from anything quiche reported. *)
let recv_drain (state : t) : (int option, error) result =
  let buf = Bytes.create recv_bufsize in
  let rec loop () =
    match Unix.select [ state.socket ] [] [] socket_poll_timeout with
    | [], _, _ -> Ok None
    | _ -> (
        match Unix.recvfrom state.socket buf 0 (Bytes.length buf) [] with
        | exception Unix.Unix_error ((Unix.EAGAIN | Unix.EWOULDBLOCK), _, _) -> Ok None
        | exception Unix.Unix_error (e, fn, _) ->
            Error (Io_error (Printf.sprintf "%s: %s" fn (Unix.error_message e)))
        | n, _from ->
            let rc =
              PosixTypes.Ssize.to_int
                (Quic_bindings.fossh_quiche_conn_recv state.conn (Ctypes.ocaml_bytes_start buf)
                   (Unsigned.Size_t.of_int n) state.local_family state.local_ip
                   (Unsigned.UInt16.of_int state.local_port) state.peer_family state.peer_ip
                   (Unsigned.UInt16.of_int state.peer_port))
            in
            if rc = quiche_err_done then Ok None else if rc >= 0 then loop () else Ok (Some rc))
  in
  loop ()

let send_drain (state : t) : (unit, error) result =
  let buf = Bytes.create max_datagram_size in
  let rec loop () =
    let rc =
      PosixTypes.Ssize.to_int
        (Quic_bindings.fossh_quiche_conn_send state.conn (Ctypes.ocaml_bytes_start buf)
           (Unsigned.Size_t.of_int (Bytes.length buf)))
    in
    if rc = quiche_err_done then Ok ()
    else if rc >= 0 then (
      let (_ : int) = Unix.sendto state.socket buf 0 rc [] state.peer_sockaddr in
      loop ())
    else Error (Quiche_error rc)
  in
  loop ()

(* [is_done] is checked exactly once per iteration, after *both*
   drive phases have run — never in between. See this file's header
   comment and ADR-0044 finding #1: checking earlier is correct for
   "have we become established" but silently drops queued data for
   "send this, then stop" callers, since it can return before the
   send-drain phase that would actually flush anything ever runs. *)
let rec drive_until (state : t) (deadline : float) (is_done : unit -> bool) : (unit, error) result =
  match recv_drain state with
  | Error _ as e -> e
  | Ok recv_error -> (
      if Quic_bindings.quiche_conn_is_closed state.conn then Error Connection_closed
      else
        match send_drain state with
        | Error _ as e -> e
        | Ok () -> (
            match recv_error with
            | Some code -> Error (Quiche_error code)
            | None ->
                if Quic_bindings.quiche_conn_is_closed state.conn then Error Connection_closed
                else if is_done () then Ok ()
                else if Unix.gettimeofday () >= deadline then Error Deadline_exceeded
                else drive_until state deadline is_done))

let close (state : t) : unit =
  if not !(state.closed) then (
    state.closed := true;
    Quic_bindings.quiche_conn_free state.conn;
    Quic_bindings.quiche_config_free state.config;
    try Unix.close state.socket with Unix.Unix_error _ -> ())

let peer_cert (state : t) : string option =
  let out_ptr = Ctypes.allocate (Ctypes.ptr Ctypes.uint8_t) (Ctypes.from_voidp Ctypes.uint8_t Ctypes.null) in
  let out_len = Ctypes.allocate Ctypes.size_t Unsigned.Size_t.zero in
  Quic_bindings.quiche_conn_peer_cert state.conn out_ptr out_len;
  let len = Unsigned.Size_t.to_int (Ctypes.( !@ ) out_len) in
  let data_ptr = Ctypes.( !@ ) out_ptr in
  if len = 0 || Ctypes.is_null data_ptr then None
  else
    let char_ptr = Ctypes.coerce (Ctypes.ptr Ctypes.uint8_t) (Ctypes.ptr Ctypes.char) data_ptr in
    Some (Ctypes.string_from_ptr char_ptr ~length:len)

let bind_wildcard_for (family : int) : Unix.sockaddr =
  if family = af_inet then Unix.ADDR_INET (Unix.inet_addr_of_string "0.0.0.0", 0)
  else Unix.ADDR_INET (Unix.inet_addr_of_string "::", 0)

let fresh_scid () : bytes =
  Bytes.of_string (Fossh_watchdog_lib.Nonce.read_random_bytes quiche_max_conn_id_len)

(* Connects to [peer_addr] and drives the handshake to completion (or
   [deadline]). Mirrors fossh-ipc's own `connect`: the returned [t] is
   fully established and ready for `send_on_stream`/`recv_from_stream`
   for the connection's remaining lifetime. *)
let connect ~(peer_addr : Unix.sockaddr) ~(tls : tls_paths) ~(deadline : float) : (t, error) result =
  match decompose_sockaddr peer_addr with
  | Error e -> Error e
  | Ok (peer_family, peer_ip, peer_port) ->
      let domain = if peer_family = af_inet then Unix.PF_INET else Unix.PF_INET6 in
      let socket = Unix.socket domain Unix.SOCK_DGRAM 0 in
      let config : Quic_bindings.config_t option ref = ref None in
      let conn : Quic_bindings.conn_t option ref = ref None in
      let cleanup () =
        (match !conn with Some c -> Quic_bindings.quiche_conn_free c | None -> ());
        (match !config with Some c -> Quic_bindings.quiche_config_free c | None -> ());
        try Unix.close socket with Unix.Unix_error _ -> ()
      in
      let result =
        with_unix_errors_as_io_errors (fun () ->
            try
              Unix.bind socket (bind_wildcard_for peer_family);
              let cfg = match build_config tls with Ok c -> c | Error e -> raise (Setup_failed e) in
              config := Some cfg;
              let local_family, local_ip, local_port =
                match decompose_sockaddr (Unix.getsockname socket) with
                | Ok v -> v
                | Error e -> raise (Setup_failed e)
              in
              let scid = fresh_scid () in
              let c =
                Quic_bindings.fossh_quiche_connect None (Ctypes.ocaml_bytes_start scid)
                  (Unsigned.Size_t.of_int (Bytes.length scid)) local_family local_ip
                  (Unsigned.UInt16.of_int local_port) peer_family peer_ip
                  (Unsigned.UInt16.of_int peer_port) cfg
              in
              if Ctypes.is_null c then raise (Setup_failed Connection_failed);
              conn := Some c;
              let state =
                { conn = c; config = cfg; socket; local_family; local_ip; local_port; peer_family;
                  peer_ip; peer_port; peer_sockaddr = peer_addr; closed = ref false }
              in
              (* quiche_connect only prepares handshake state; nothing is
                 on the wire yet until an explicit send, matching
                 fossh-ipc's own connect() flushing the initial packet
                 before its first drive_until call. *)
              (match send_drain state with Ok () -> () | Error e -> raise (Setup_failed e));
              (match
                 drive_until state deadline (fun () -> Quic_bindings.quiche_conn_is_established state.conn)
               with
              | Ok () -> Ok state
              | Error e -> raise (Setup_failed e))
            with Setup_failed e -> Error e)
      in
      (match result with Ok _ -> () | Error _ -> cleanup ());
      result

(* Binds [listen_addr] and accepts exactly one connection, driving it
   to completion (or [deadline]) — this channel is a single, persistent
   connection between exactly one watchdog and exactly one core, not a
   multi-client server, matching fossh-ipc's own `accept_one` and its
   documented reasoning (see this file's header comment). *)
let accept_one ~(listen_addr : Unix.sockaddr) ~(tls : tls_paths) ~(deadline : float) : (t, error) result =
  match decompose_sockaddr listen_addr with
  | Error e -> Error e
  | Ok (local_family, _, _) ->
      let domain = if local_family = af_inet then Unix.PF_INET else Unix.PF_INET6 in
      let socket = Unix.socket domain Unix.SOCK_DGRAM 0 in
      let config : Quic_bindings.config_t option ref = ref None in
      let conn : Quic_bindings.conn_t option ref = ref None in
      let cleanup () =
        (match !conn with Some c -> Quic_bindings.quiche_conn_free c | None -> ());
        (match !config with Some c -> Quic_bindings.quiche_config_free c | None -> ());
        try Unix.close socket with Unix.Unix_error _ -> ()
      in
      let result =
        with_unix_errors_as_io_errors (fun () ->
            try
              Unix.bind socket listen_addr;
              let local_family, local_ip, local_port =
                match decompose_sockaddr (Unix.getsockname socket) with
                | Ok v -> v
                | Error e -> raise (Setup_failed e)
              in
              let cfg = match build_config tls with Ok c -> c | Error e -> raise (Setup_failed e) in
              config := Some cfg;
              let buf = Bytes.create recv_bufsize in
              let rec wait_for_first_packet () =
                match Unix.select [ socket ] [] [] socket_poll_timeout with
                | [], _, _ ->
                    if Unix.gettimeofday () >= deadline then raise (Setup_failed Deadline_exceeded)
                    else wait_for_first_packet ()
                | _ -> (
                    match Unix.recvfrom socket buf 0 (Bytes.length buf) [] with
                    | exception Unix.Unix_error ((Unix.EAGAIN | Unix.EWOULDBLOCK), _, _) ->
                        wait_for_first_packet ()
                    | exception Unix.Unix_error (e, fn, _) ->
                        raise (Setup_failed (Io_error (Printf.sprintf "%s: %s" fn (Unix.error_message e))))
                    | len, from_addr -> (len, from_addr))
              in
              let len, from_addr = wait_for_first_packet () in
              let peer_family, peer_ip, peer_port =
                match decompose_sockaddr from_addr with Ok v -> v | Error e -> raise (Setup_failed e)
              in
              let scid = fresh_scid () in
              let c =
                Quic_bindings.fossh_quiche_accept (Ctypes.ocaml_bytes_start scid)
                  (Unsigned.Size_t.of_int (Bytes.length scid)) local_family local_ip
                  (Unsigned.UInt16.of_int local_port) peer_family peer_ip
                  (Unsigned.UInt16.of_int peer_port) cfg
              in
              if Ctypes.is_null c then raise (Setup_failed Connection_failed);
              conn := Some c;
              let rc =
                PosixTypes.Ssize.to_int
                  (Quic_bindings.fossh_quiche_conn_recv c (Ctypes.ocaml_bytes_start buf)
                     (Unsigned.Size_t.of_int len) local_family local_ip (Unsigned.UInt16.of_int local_port)
                     peer_family peer_ip (Unsigned.UInt16.of_int peer_port))
              in
              if rc < 0 && rc <> quiche_err_done then raise (Setup_failed (Quiche_error rc));
              let state =
                { conn = c; config = cfg; socket; local_family; local_ip; local_port; peer_family;
                  peer_ip; peer_port; peer_sockaddr = from_addr; closed = ref false }
              in
              (match
                 drive_until state deadline (fun () -> Quic_bindings.quiche_conn_is_established state.conn)
               with
              | Ok () -> Ok state
              | Error e -> raise (Setup_failed e))
            with Setup_failed e -> Error e)
      in
      (match result with Ok _ -> () | Error _ -> cleanup ());
      result

(* Sends [data] on [stream_id], driving the connection until quiche has
   flushed everything it's willing to send this pass or [deadline]
   passes. Any negative return from quiche_conn_stream_send (including
   QUICHE_ERR_DONE) is a real error here — unlike inside the drive
   phases above, there is no loop for a one-shot stream write to fall
   through to, matching fossh-ipc's own `stream_send(...)?`, which
   propagates every error including `Done` via `?`. *)
let send_on_stream (state : t) ~(stream_id : int64) ~(data : string) ~(fin : bool) (deadline : float) :
    (unit, error) result =
  with_unix_errors_as_io_errors (fun () ->
      let data_bytes = Bytes.of_string data in
      let err_out = Ctypes.allocate Ctypes.uint64_t Unsigned.UInt64.zero in
      let rc =
        PosixTypes.Ssize.to_int
          (Quic_bindings.quiche_conn_stream_send state.conn (Unsigned.UInt64.of_int64 stream_id)
             (Ctypes.ocaml_bytes_start data_bytes) (Unsigned.Size_t.of_int (Bytes.length data_bytes)) fin
             err_out)
      in
      if rc < 0 then Error (Quiche_error rc) else drive_until state deadline (fun () -> true))

(* Blocks (up to [deadline]) until at least one full message has
   arrived on [stream_id], returning it plus whether the peer signaled
   end-of-stream. Reads directly inside `drive_until`'s own [is_done]
   closure rather than checking readability first and reading
   separately afterward — matching fossh-ipc's own `recv_from_stream`
   and the exact real, reproduced bug that shape avoids (see its own
   doc comment: a separate post-loop read step can miss data that
   genuinely arrived, depending on drive_until's own pass
   interleaving). *)
let recv_from_stream (state : t) ~(stream_id : int64) (deadline : float) : (string * bool, error) result =
  with_unix_errors_as_io_errors (fun () ->
      let collected = Buffer.create 4096 in
      let got_fin = ref false in
      let buf = Bytes.create recv_bufsize in
      let stream_id_u = Unsigned.UInt64.of_int64 stream_id in
      let is_done () =
        let rec loop () =
          let fin_out = Ctypes.allocate Ctypes.bool false in
          let err_out = Ctypes.allocate Ctypes.uint64_t Unsigned.UInt64.zero in
          let rc =
            PosixTypes.Ssize.to_int
              (Quic_bindings.quiche_conn_stream_recv state.conn stream_id_u
                 (Ctypes.ocaml_bytes_start buf) (Unsigned.Size_t.of_int (Bytes.length buf)) fin_out
                 err_out)
          in
          if rc = quiche_err_done then false
          else if rc > 0 then (
            Buffer.add_subbytes collected buf 0 rc;
            if Ctypes.( !@ ) fin_out then (
              got_fin := true;
              true)
            else loop ())
          else false
          (* rc = 0, or rc < 0 and not Done: no data-carrying path back
             to the caller from inside this closure (bool only), so
             treated as "not done yet" rather than surfaced directly —
             matching fossh-ipc's identical, already-adversarially-
             reviewed choice here (see ADR-0044), not a gap specific to
             this port. Known, accepted imprecision inherited from that
             design, not fixed independently on just this side: a
             negative rc here can be QUICHE_ERR_STREAM_STOPPED or
             QUICHE_ERR_STREAM_RESET (per quiche.h), a peer resetting
             only *this* stream — a real, RFC 9000-defined outcome that
             does not close the whole connection, so drive_until's own
             is_closed() check will *not* always catch it on a later
             pass the way this reasoning previously assumed. In that
             specific case this loop keeps retrying the same stream
             until the caller's own deadline ends it — a bounded
             fail-slow, not a hang, but not the fail-fast a stream-reset
             signal deserves either. Worth a real fix on both sides of
             this channel together, not asymmetrically on just the
             OCaml port. *)
        in
        loop ()
      in
      match drive_until state deadline is_done with
      | Error e -> Error e
      | Ok () -> Ok (Buffer.contents collected, !got_fin))
