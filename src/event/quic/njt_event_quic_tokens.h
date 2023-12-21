
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_EVENT_QUIC_TOKENS_H_INCLUDED_
#define _NJT_EVENT_QUIC_TOKENS_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


#define NJT_QUIC_MAX_TOKEN_SIZE              64
    /* SHA-1(addr)=20 + sizeof(time_t) + retry(1) + odcid.len(1) + odcid */

#define NJT_QUIC_AES_256_GCM_IV_LEN          12
#define NJT_QUIC_AES_256_GCM_TAG_LEN         16

#define NJT_QUIC_TOKEN_BUF_SIZE             (NJT_QUIC_AES_256_GCM_IV_LEN      \
                                             + NJT_QUIC_MAX_TOKEN_SIZE        \
                                             + NJT_QUIC_AES_256_GCM_TAG_LEN)


njt_int_t njt_quic_new_sr_token(njt_connection_t *c, njt_str_t *cid,
    u_char *secret, u_char *token);
njt_int_t njt_quic_new_token(njt_log_t *log, struct sockaddr *sockaddr,
    socklen_t socklen, u_char *key, njt_str_t *token, njt_str_t *odcid,
    time_t expires, njt_uint_t is_retry);
njt_int_t njt_quic_validate_token(njt_connection_t *c,
    u_char *key, njt_quic_header_t *pkt);

#endif /* _NJT_EVENT_QUIC_TOKENS_H_INCLUDED_ */
