#ifndef FOSSH_QUIC_SHIM_H
#define FOSSH_QUIC_SHIM_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include <caml/mlvalues.h>

#include "quiche.h"

#define FOSSH_AF_INET 0
#define FOSSH_AF_INET6 1

#define FOSSH_SHIM_ERR_BAD_ADDRESS (-1000)

quiche_conn *fossh_quiche_connect(const char *server_name, const uint8_t *scid,
                                   size_t scid_len, int local_family,
                                   const char *local_ip, uint16_t local_port,
                                   int peer_family, const char *peer_ip,
                                   uint16_t peer_port, quiche_config *config);

quiche_conn *fossh_quiche_accept(const uint8_t *scid, size_t scid_len,
                                  int local_family, const char *local_ip,
                                  uint16_t local_port, int peer_family,
                                  const char *peer_ip, uint16_t peer_port,
                                  quiche_config *config);

ssize_t fossh_quiche_conn_recv(quiche_conn *conn, uint8_t *buf, size_t buf_len,
                                int local_family, const char *local_ip,
                                uint16_t local_port, int peer_family,
                                const char *peer_ip, uint16_t peer_port);

ssize_t fossh_quiche_conn_send(quiche_conn *conn, uint8_t *out, size_t out_len);

value fossh_quic_shim_touch(value unit);

#endif
