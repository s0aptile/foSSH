(* Raw ctypes declarations against libquiche's C ABI (quiche.h,
   vendored into vendor/ by scripts/build-quiche-ffi.sh) plus this
   directory's own quic_shim.c (see its header comment for why the
   handful of sockaddr-taking functions are wrapped rather than bound
   directly).

   Deliberately the thinnest possible layer: one `Foreign.foreign` line
   per C function, no logic. Quic.ml is where connection-driving logic,
   error handling, and anything resembling a safe API actually lives —
   mirroring the split fossh-ipc's own Rust side doesn't need (quiche's
   Rust API is already safe), but which this file exists specifically
   to recreate for C, matching how any hand-written ctypes binding to a
   C library is expected to be layered. *)

open Ctypes
open Foreign

(* Must match FOSSH_AF_INET / FOSSH_AF_INET6 in quic_shim.h exactly —
   deliberately not the platform's own raw AF_INET/AF_INET6 values,
   see that header's comment for why. *)
let af_inet = 0
let af_inet6 = 1

(* Opaque handles — this project never looks inside a quiche_config or
   quiche_conn, only passes pointers to it back into quiche's own
   functions, so both are declared as zero-field structures purely for
   the type distinction (the compiler will reject passing a `conn ptr`
   where a `config ptr` is expected, unlike if both were `unit ptr`). *)
type quiche_config
type quiche_conn

let quiche_config : quiche_config structure typ = structure "quiche_config"
let quiche_conn : quiche_conn structure typ = structure "quiche_conn"
let config_ptr = ptr quiche_config
let conn_ptr = ptr quiche_conn

(* Ergonomic aliases so Quic.ml's own type annotations don't have to
   spell out `quiche_conn Ctypes.structure Ctypes.ptr` everywhere. *)
type config_t = quiche_config structure Ctypes.ptr
type conn_t = quiche_conn structure Ctypes.ptr

(* libquiche.so is linked in at build time (see dune's c_library_flags:
   -lquiche against quic/vendor, plus -Wl,--no-as-needed, since nothing
   below creates a compile-time reference to any quiche_* symbol for
   the linker to see a reason to keep the dependency for otherwise)
   rather than dlopen'd at runtime, so its exports are already loaded
   into this executable's own process image by the time any `foreign`
   call below runs — no `Dl.library` handle is needed.

   This is *not* verified merely by a clean build, unlike ordinary
   OCaml `external` declarations: every symbol below is resolved via
   `Foreign.foreign`, which is effectively a `dlsym` lookup happening
   at module-load time, not a link-time relocation the linker checks
   ahead of time. A wrong or missing symbol name here fails silently
   at `dune build` and loudly, but only later, the first time this
   module is loaded (`Dl.DL_error("... undefined symbol: ...")`) —
   reproduced for real while getting this file's own build working:
   -Wl,--export-dynamic was still required even with libquiche.so
   correctly linked, and this file's own quic_shim.c functions needed
   a genuine compile-time reference (fossh_quic_shim_touch, called
   once just below) to keep the linker from dropping that whole
   object file, since a static-archive member nothing references at
   link time is simply omitted by ordinary lazy extraction — ctypes'
   runtime lookup mechanism gives the linker no way to see that
   dropping it would be wrong until this module actually loads.

   That fix is scoped to exactly one object file: touch_stub_archive
   forces quic_shim.o specifically to stay linked, because that is the
   only .c file foreign_stubs' (names ...) list in quic/dune currently
   builds. If a *second* .c file is ever added to that list, its own
   functions need their own equivalent compile-time-referenced
   external — merely adding new Foreign.foreign lines against it here
   would reproduce this exact silent-at-build/loud-at-first-use failure
   for that new file specifically, not be covered by this one. *)

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

(* quic_shim.c's own wrappers — see its header for the FOSSH_AF_INET /
   FOSSH_AF_INET6 / FOSSH_SHIM_ERR_BAD_ADDRESS constants mirrored in
   Quic.ml, and for why the sockaddr marshalling lives in C. *)

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
