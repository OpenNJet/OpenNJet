
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_EVENT_QUIC_OUTPUT_H_INCLUDED_
#define _NJT_EVENT_QUIC_OUTPUT_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


njt_int_t njt_quic_output(njt_connection_t *c);

njt_int_t njt_quic_negotiate_version(njt_connection_t *c,
    njt_quic_header_t *inpkt);

njt_int_t njt_quic_send_stateless_reset(njt_connection_t *c,
    njt_quic_conf_t *conf, njt_quic_header_t *pkt);
njt_int_t njt_quic_send_cc(njt_connection_t *c);
njt_int_t njt_quic_send_early_cc(njt_connection_t *c,
    njt_quic_header_t *inpkt, njt_uint_t err, const char *reason);

njt_int_t njt_quic_send_retry(njt_connection_t *c,
    njt_quic_conf_t *conf, njt_quic_header_t *pkt);
njt_int_t njt_quic_send_new_token(njt_connection_t *c, njt_quic_path_t *path);

njt_int_t njt_quic_send_ack(njt_connection_t *c,
    njt_quic_send_ctx_t *ctx);
njt_int_t njt_quic_send_ack_range(njt_connection_t *c,
    njt_quic_send_ctx_t *ctx, uint64_t smallest, uint64_t largest);

njt_int_t njt_quic_frame_sendto(njt_connection_t *c, njt_quic_frame_t *frame,
    size_t min, njt_quic_path_t *path);
size_t njt_quic_path_limit(njt_connection_t *c, njt_quic_path_t *path,
    size_t size);

#endif /* _NJT_EVENT_QUIC_OUTPUT_H_INCLUDED_ */
