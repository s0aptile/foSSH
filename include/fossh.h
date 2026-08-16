#ifndef FOSSH_H
#define FOSSH_H

#include "stdint.h"
#include "stddef.h"

#define FOSSH_ABI_VERSION 1

enum fossh_err_t
#if defined(__cplusplus) || __STDC_VERSION__ >= 202311L
  : int32_t
#endif
 {

  FOSSH_ERR_T_INTERNAL = -1,

  FOSSH_ERR_T_INVALID_ARGUMENT = -2,

  FOSSH_ERR_T_NO_KEY_SET = -3,

  FOSSH_ERR_T_UNAUTHORIZED = -4,

  FOSSH_ERR_T_REJECTED = -5,

  FOSSH_ERR_T_TOO_LARGE = -6,

  FOSSH_ERR_T_RATE_LIMITED = -7,

  FOSSH_ERR_T_WRITE_FAILED = -8,
};
#ifndef __cplusplus
#if __STDC_VERSION__ >= 202311L
typedef enum fossh_err_t fossh_err_t;
#else
typedef int32_t fossh_err_t;
#endif
#endif

typedef struct fossh_ctx fossh_ctx;

#ifdef __cplusplus
extern "C" {
#endif

 uint32_t fossh_abi_version(void);

 struct fossh_ctx *fossh_init(const char *config_path);

 void fossh_free(struct fossh_ctx *ctx);

 int32_t fossh_last_error(const struct fossh_ctx *ctx, char *buf, size_t len);

 int32_t fossh_set_key(struct fossh_ctx *ctx, const char *key);

int32_t fossh_pageview(struct fossh_ctx *ctx,
                       const char *path,
                       const char *referrer,
                       const char *client_ip,
                       const char *user_agent);

int32_t fossh_event(struct fossh_ctx *ctx,
                    const char *name,
                    int64_t value,
                    const char *props_json);

 int32_t fossh_timing(struct fossh_ctx *ctx, const char *name, int64_t millis);

int32_t fossh_record_env(struct fossh_ctx *ctx,
                         const char *const *envp,
                         size_t envc,
                         const uint8_t *body,
                         size_t body_len);

 int32_t fossh_flush(struct fossh_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif
