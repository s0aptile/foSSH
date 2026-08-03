/* Thin wrappers around the handful of quiche_* C functions whose
 * signatures take raw `struct sockaddr *` pointers.
 *
 * fossh-ipc (crates/fossh-ipc, core's/Rust's side of this same §3.4
 * channel) gets sockaddr marshalling for free from quiche's safe Rust
 * API, which builds real `std::net::SocketAddr` values under the
 * hood. The OCaml watchdog has no equivalent, and hand-rolling the
 * `struct sockaddr_in` / `sockaddr_in6` / `sockaddr_storage` layouts
 * directly as OCaml ctypes structs would mean trusting a hand-typed
 * copy of glibc's field order and padding to stay correct forever,
 * with a wrong guess showing up as silent handshake corruption rather
 * than a compile error. The real system headers (<netinet/in.h> et
 * al., pulled in transitively below) are the authority on that layout
 * instead — this file exists so OCaml never has to reproduce it.
 *
 * This channel is always exactly one UDP socket talking to exactly
 * one fixed, already-known peer for the connection's entire lifetime
 * (matching fossh-ipc's own documented scope: one watchdog, one core,
 * per install, never more — and `quiche_config_set_disable_active_
 * migration(config, true)` is set on both sides, so the peer address
 * genuinely cannot change mid-connection). So unlike quiche's own
 * general-purpose C API, `fossh_quiche_conn_send` below does not hand
 * a destination address back out to its caller: the caller already
 * knows the one peer address this connection will ever use, the same
 * way fossh-ipc's Rust side does.
 *
 * Addresses cross this boundary as plain numeric strings ("127.0.0.1",
 * "::1"), parsed with `inet_pton` — not as raw address bytes handed
 * over from OCaml. `Unix.inet_addr` has no public accessor for its
 * underlying bytes in OCaml's standard library, and `Unix.
 * string_of_inet_addr` already gives exactly the string form
 * `inet_pton` wants, so there is no reason to go further than that. */

#ifndef FOSSH_QUIC_SHIM_H
#define FOSSH_QUIC_SHIM_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include <caml/mlvalues.h>

#include "quiche.h"

/* fossh's own address-family tags — deliberately not the platform's
 * raw AF_INET/AF_INET6 values, so the OCaml side never has to
 * hardcode a libc-specific numeric constant. */
#define FOSSH_AF_INET 0
#define FOSSH_AF_INET6 1

/* A shim-level failure distinct from any real `enum quiche_error`
 * value (all of which are -1 through -23 as of the vendored quiche
 * version — see quiche.h) — namespaced below quiche's own range the
 * same way quiche.h namespaces its own HTTP/3 error codes
 * (`QUICHE_H3_TRANSPORT_ERR_* = QUICHE_ERR_* - 1000`). Returned only
 * if OCaml ever passes a malformed address string, which should not
 * happen given callers only ever pass addresses already validated by
 * `Unix.inet_addr_of_string` before reaching this boundary — but a
 * shim-internal parse failure is still reported as a distinct,
 * checkable error rather than silently producing an all-zero address,
 * matching this project's fail-closed default elsewhere. */
#define FOSSH_SHIM_ERR_BAD_ADDRESS (-1000)

/* Client-side connection setup. `server_name` may be NULL (this
 * channel verifies the peer by exact pinned-certificate match, not by
 * hostname — see fossh-ipc's own `TlsPaths` doc comment for why). */
quiche_conn *fossh_quiche_connect(const char *server_name, const uint8_t *scid,
                                   size_t scid_len, int local_family,
                                   const char *local_ip, uint16_t local_port,
                                   int peer_family, const char *peer_ip,
                                   uint16_t peer_port, quiche_config *config);

/* Server-side connection setup for the very first packet of a new
 * connection. No retry/original-destination-connection-ID support —
 * matching fossh-ipc's own identical scope decision (a single,
 * already-known peer never needs QUIC's anti-amplification retry
 * dance a public-facing server would). */
quiche_conn *fossh_quiche_accept(const uint8_t *scid, size_t scid_len,
                                  int local_family, const char *local_ip,
                                  uint16_t local_port, int peer_family,
                                  const char *peer_ip, uint16_t peer_port,
                                  quiche_config *config);

/* Same return convention as `quiche_conn_recv`: >=0 bytes processed,
 * or a negative `enum quiche_error` code (or
 * `FOSSH_SHIM_ERR_BAD_ADDRESS`). */
ssize_t fossh_quiche_conn_recv(quiche_conn *conn, uint8_t *buf, size_t buf_len,
                                int local_family, const char *local_ip,
                                uint16_t local_port, int peer_family,
                                const char *peer_ip, uint16_t peer_port);

/* Same return convention as `quiche_conn_send`: >=0 bytes written, or
 * a negative `enum quiche_error` code. See the file header comment
 * for why the destination address isn't returned to the caller. */
ssize_t fossh_quiche_conn_send(quiche_conn *conn, uint8_t *out, size_t out_len);

/* A real OCaml external, unlike everything above (which OCaml only
 * ever reaches via ctypes' Foreign.foreign — effectively a runtime
 * dlsym lookup, invisible to the static linker's own notion of "is
 * this archive member referenced"). Quic_bindings.ml calls this once,
 * at module load, purely to give the linker one genuine compile-time
 * reference into this object file: an OCaml `external` creates a real
 * undefined-symbol reference the static linker must resolve, and
 * resolving it pulls in this *entire* object file — including the
 * four functions above, which Foreign.foreign could otherwise never
 * find, since a stub archive member nothing references at link time
 * is simply dropped by ordinary lazy archive extraction. See
 * Quic_bindings.ml's own comment for the rest of this reasoning. */
value fossh_quic_shim_touch(value unit);

#endif
