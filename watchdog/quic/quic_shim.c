#include "quic_shim.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

/* Fills `storage` with a real `sockaddr_in`/`sockaddr_in6` built by
 * `inet_pton` (never hand-assembled byte-by-byte) and returns its
 * length, or 0 if `ip_str` does not parse as an address of the
 * requested family. */
static socklen_t fill_sockaddr(struct sockaddr_storage *storage, int family,
                                const char *ip_str, uint16_t port) {
  memset(storage, 0, sizeof(*storage));

  if (family == FOSSH_AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in *)storage;
    if (inet_pton(AF_INET, ip_str, &sin->sin_addr) != 1) return 0;
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    return (socklen_t)sizeof(struct sockaddr_in);
  }

  if (family == FOSSH_AF_INET6) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)storage;
    if (inet_pton(AF_INET6, ip_str, &sin6->sin6_addr) != 1) return 0;
    sin6->sin6_family = AF_INET6;
    sin6->sin6_port = htons(port);
    return (socklen_t)sizeof(struct sockaddr_in6);
  }

  return 0;
}

quiche_conn *fossh_quiche_connect(const char *server_name, const uint8_t *scid,
                                   size_t scid_len, int local_family,
                                   const char *local_ip, uint16_t local_port,
                                   int peer_family, const char *peer_ip,
                                   uint16_t peer_port, quiche_config *config) {
  struct sockaddr_storage local, peer;
  socklen_t local_len = fill_sockaddr(&local, local_family, local_ip, local_port);
  socklen_t peer_len = fill_sockaddr(&peer, peer_family, peer_ip, peer_port);
  if (local_len == 0 || peer_len == 0) return NULL;

  return quiche_connect(server_name, scid, scid_len, (struct sockaddr *)&local,
                         local_len, (struct sockaddr *)&peer, peer_len, config);
}

quiche_conn *fossh_quiche_accept(const uint8_t *scid, size_t scid_len,
                                  int local_family, const char *local_ip,
                                  uint16_t local_port, int peer_family,
                                  const char *peer_ip, uint16_t peer_port,
                                  quiche_config *config) {
  struct sockaddr_storage local, peer;
  socklen_t local_len = fill_sockaddr(&local, local_family, local_ip, local_port);
  socklen_t peer_len = fill_sockaddr(&peer, peer_family, peer_ip, peer_port);
  if (local_len == 0 || peer_len == 0) return NULL;

  return quiche_accept(scid, scid_len, NULL, 0, (struct sockaddr *)&local,
                        local_len, (struct sockaddr *)&peer, peer_len, config);
}

ssize_t fossh_quiche_conn_recv(quiche_conn *conn, uint8_t *buf, size_t buf_len,
                                int local_family, const char *local_ip,
                                uint16_t local_port, int peer_family,
                                const char *peer_ip, uint16_t peer_port) {
  struct sockaddr_storage local, peer;
  socklen_t local_len = fill_sockaddr(&local, local_family, local_ip, local_port);
  socklen_t peer_len = fill_sockaddr(&peer, peer_family, peer_ip, peer_port);
  if (local_len == 0 || peer_len == 0) return FOSSH_SHIM_ERR_BAD_ADDRESS;

  quiche_recv_info info = {
      .from = (struct sockaddr *)&peer,
      .from_len = peer_len,
      .to = (struct sockaddr *)&local,
      .to_len = local_len,
  };

  return quiche_conn_recv(conn, buf, buf_len, &info);
}

ssize_t fossh_quiche_conn_send(quiche_conn *conn, uint8_t *out, size_t out_len) {
  quiche_send_info info;
  memset(&info, 0, sizeof(info));
  return quiche_conn_send(conn, out, out_len, &info);
}

value fossh_quic_shim_touch(value unit) {
  (void)unit;
  return Val_unit;
}
