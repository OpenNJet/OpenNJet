
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_EVENT_QUIC_ACK_H_INCLUDED_
#define _NJT_EVENT_QUIC_ACK_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


njt_int_t njt_quic_handle_ack_frame(njt_connection_t *c,
    njt_quic_header_t *pkt, njt_quic_frame_t *f);

void njt_quic_congestion_ack(njt_connection_t *c,
    njt_quic_frame_t *frame);
void njt_quic_resend_frames(njt_connection_t *c, njt_quic_send_ctx_t *ctx);
void njt_quic_set_lost_timer(njt_connection_t *c);
void njt_quic_pto_handler(njt_event_t *ev);
njt_msec_t njt_quic_pto(njt_connection_t *c, njt_quic_send_ctx_t *ctx);

njt_int_t njt_quic_ack_packet(njt_connection_t *c,
    njt_quic_header_t *pkt);
njt_int_t njt_quic_generate_ack(njt_connection_t *c,
    njt_quic_send_ctx_t *ctx);

#endif /* _NJT_EVENT_QUIC_ACK_H_INCLUDED_ */
