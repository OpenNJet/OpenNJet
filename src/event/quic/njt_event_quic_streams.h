
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_EVENT_QUIC_STREAMS_H_INCLUDED_
#define _NJT_EVENT_QUIC_STREAMS_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


njt_int_t njt_quic_handle_stream_frame(njt_connection_t *c,
    njt_quic_header_t *pkt, njt_quic_frame_t *frame);
void njt_quic_handle_stream_ack(njt_connection_t *c,
    njt_quic_frame_t *f);
njt_int_t njt_quic_handle_max_data_frame(njt_connection_t *c,
    njt_quic_max_data_frame_t *f);
njt_int_t njt_quic_handle_streams_blocked_frame(njt_connection_t *c,
    njt_quic_header_t *pkt, njt_quic_streams_blocked_frame_t *f);
njt_int_t njt_quic_handle_data_blocked_frame(njt_connection_t *c,
    njt_quic_header_t *pkt, njt_quic_data_blocked_frame_t *f);
njt_int_t njt_quic_handle_stream_data_blocked_frame(njt_connection_t *c,
    njt_quic_header_t *pkt, njt_quic_stream_data_blocked_frame_t *f);
njt_int_t njt_quic_handle_max_stream_data_frame(njt_connection_t *c,
    njt_quic_header_t *pkt, njt_quic_max_stream_data_frame_t *f);
njt_int_t njt_quic_handle_reset_stream_frame(njt_connection_t *c,
    njt_quic_header_t *pkt, njt_quic_reset_stream_frame_t *f);
njt_int_t njt_quic_handle_stop_sending_frame(njt_connection_t *c,
    njt_quic_header_t *pkt, njt_quic_stop_sending_frame_t *f);
njt_int_t njt_quic_handle_max_streams_frame(njt_connection_t *c,
    njt_quic_header_t *pkt, njt_quic_max_streams_frame_t *f);

njt_int_t njt_quic_init_streams(njt_connection_t *c);
void njt_quic_rbtree_insert_stream(njt_rbtree_node_t *temp,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel);
njt_quic_stream_t *njt_quic_find_stream(njt_rbtree_t *rbtree,
    uint64_t id);
njt_int_t njt_quic_close_streams(njt_connection_t *c,
    njt_quic_connection_t *qc);

#endif /* _NJT_EVENT_QUIC_STREAMS_H_INCLUDED_ */
