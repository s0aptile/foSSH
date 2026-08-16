let quiche_err_done = -1
let quiche_max_conn_id_len = 20
let max_datagram_size = 1350
let recv_bufsize = 65535
let alpn = "fossh-ipc/1"

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

exception Setup_failed of error

type t = {
  conn : Quic_bindings.conn_t;

  config : Quic_bindings.config_t;
  socket : Unix.file_descr;
  local_family : int;
  local_ip : string;
  local_port : int;
  peer_family : int;
  peer_ip : string;
  peer_port : int;
  peer_sockaddr : Unix.sockaddr;

  closed : bool ref;
}

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

        in
        loop ()
      in
      match drive_until state deadline is_done with
      | Error e -> Error e
      | Ok () -> Ok (Buffer.contents collected, !got_fin))
