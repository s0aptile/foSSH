open Ctypes
open Foreign

let af_inet = 0
let af_inet6 = 1

type quiche_config
type quiche_conn

let quiche_config : quiche_config structure typ = structure "quiche_config"
let quiche_conn : quiche_conn structure typ = structure "quiche_conn"
let config_ptr = ptr quiche_config
let conn_ptr = ptr quiche_conn

type config_t = quiche_config structure Ctypes.ptr
type conn_t = quiche_conn structure Ctypes.ptr

external touch_stub_archive : unit -> unit = "fossh_quic_shim_touch"
let () = touch_stub_archive ()

let quiche_config_new = foreign "quiche_config_new" (uint32_t @-> returning config_ptr)
let quiche_config_free = foreign "quiche_config_free" (config_ptr @-> returning void)

let quiche_config_load_cert_chain_from_pem_file =
  foreign "quiche_config_load_cert_chain_from_pem_file" (config_ptr @-> string @-> returning int)

let quiche_config_load_priv_key_from_pem_file =
  foreign "quiche_config_load_priv_key_from_pem_file" (config_ptr @-> string @-> returning int)

let quiche_config_load_verify_locations_from_file =
  foreign "quiche_config_load_verify_locations_from_file" (config_ptr @-> string @-> returning int)

let quiche_config_verify_peer =
  foreign "quiche_config_verify_peer" (config_ptr @-> bool @-> returning void)

let quiche_config_set_application_protos =
  foreign "quiche_config_set_application_protos"
    (config_ptr @-> ocaml_bytes @-> size_t @-> returning int)

let quiche_config_set_max_idle_timeout =
  foreign "quiche_config_set_max_idle_timeout" (config_ptr @-> uint64_t @-> returning void)

let quiche_config_set_max_recv_udp_payload_size =
  foreign "quiche_config_set_max_recv_udp_payload_size" (config_ptr @-> size_t @-> returning void)

let quiche_config_set_max_send_udp_payload_size =
  foreign "quiche_config_set_max_send_udp_payload_size" (config_ptr @-> size_t @-> returning void)

let quiche_config_set_initial_max_data =
  foreign "quiche_config_set_initial_max_data" (config_ptr @-> uint64_t @-> returning void)

let quiche_config_set_initial_max_stream_data_bidi_local =
  foreign "quiche_config_set_initial_max_stream_data_bidi_local"
    (config_ptr @-> uint64_t @-> returning void)

let quiche_config_set_initial_max_stream_data_bidi_remote =
  foreign "quiche_config_set_initial_max_stream_data_bidi_remote"
    (config_ptr @-> uint64_t @-> returning void)

let quiche_config_set_initial_max_streams_bidi =
  foreign "quiche_config_set_initial_max_streams_bidi" (config_ptr @-> uint64_t @-> returning void)

let quiche_config_set_disable_active_migration =
  foreign "quiche_config_set_disable_active_migration" (config_ptr @-> bool @-> returning void)

let fossh_quiche_connect =
  foreign "fossh_quiche_connect"
    (string_opt @-> ocaml_bytes @-> size_t @-> int @-> string @-> uint16_t @-> int @-> string
   @-> uint16_t @-> config_ptr @-> returning conn_ptr)

let fossh_quiche_accept =
  foreign "fossh_quiche_accept"
    (ocaml_bytes @-> size_t @-> int @-> string @-> uint16_t @-> int @-> string @-> uint16_t
   @-> config_ptr @-> returning conn_ptr)

let fossh_quiche_conn_recv =
  foreign "fossh_quiche_conn_recv"
    (conn_ptr @-> ocaml_bytes @-> size_t @-> int @-> string @-> uint16_t @-> int @-> string
   @-> uint16_t @-> returning PosixTypes.ssize_t)

let fossh_quiche_conn_send =
  foreign "fossh_quiche_conn_send"
    (conn_ptr @-> ocaml_bytes @-> size_t @-> returning PosixTypes.ssize_t)

let quiche_conn_is_established = foreign "quiche_conn_is_established" (conn_ptr @-> returning bool)
let quiche_conn_is_closed = foreign "quiche_conn_is_closed" (conn_ptr @-> returning bool)
let quiche_conn_on_timeout = foreign "quiche_conn_on_timeout" (conn_ptr @-> returning void)

let quiche_conn_timeout_as_millis =
  foreign "quiche_conn_timeout_as_millis" (conn_ptr @-> returning uint64_t)

let quiche_conn_free = foreign "quiche_conn_free" (conn_ptr @-> returning void)

let quiche_conn_stream_send =
  foreign "quiche_conn_stream_send"
    (conn_ptr @-> uint64_t @-> ocaml_bytes @-> size_t @-> bool @-> ptr uint64_t
   @-> returning PosixTypes.ssize_t)

let quiche_conn_stream_recv =
  foreign "quiche_conn_stream_recv"
    (conn_ptr @-> uint64_t @-> ocaml_bytes @-> size_t @-> ptr bool @-> ptr uint64_t
   @-> returning PosixTypes.ssize_t)

let quiche_conn_peer_cert =
  foreign "quiche_conn_peer_cert" (conn_ptr @-> ptr (ptr uint8_t) @-> ptr size_t @-> returning void)
