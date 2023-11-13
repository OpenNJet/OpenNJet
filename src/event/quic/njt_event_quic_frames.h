
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_EVENT_QUIC_FRAMES_H_INCLUDED_
#define _NJT_EVENT_QUIC_FRAMES_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


typedef njt_int_t (*njt_quic_frame_handler_pt)(njt_connection_t *c,
    njt_quic_frame_t *frame, void *data);


njt_quic_frame_t *njt_quic_alloc_frame(njt_connection_t *c);
void njt_quic_free_frame(njt_connection_t *c, njt_quic_frame_t *frame);
void njt_quic_free_frames(njt_connection_t *c, njt_queue_t *frames);
void njt_quic_queue_frame(njt_quic_connection_t *qc, njt_quic_frame_t *frame);
njt_int_t njt_quic_split_frame(njt_connection_t *c, njt_quic_frame_t *f,
    size_t len);

njt_chain_t *njt_quic_alloc_chain(njt_connection_t *c);
void njt_quic_free_chain(njt_connection_t *c, njt_chain_t *in);

njt_chain_t *njt_quic_copy_buffer(njt_connection_t *c, u_char *data,
    size_t len);
njt_chain_t *njt_quic_read_buffer(njt_connection_t *c, njt_quic_buffer_t *qb,
    uint64_t limit);
njt_chain_t *njt_quic_write_buffer(njt_connection_t *c, njt_quic_buffer_t *qb,
    njt_chain_t *in, uint64_t limit, uint64_t offset);
void njt_quic_skip_buffer(njt_connection_t *c, njt_quic_buffer_t *qb,
    uint64_t offset);
void njt_quic_free_buffer(njt_connection_t *c, njt_quic_buffer_t *qb);

#if (NJT_DEBUG)
void njt_quic_log_frame(njt_log_t *log, njt_quic_frame_t *f, njt_uint_t tx);
#else
#define njt_quic_log_frame(log, f, tx)
#endif

#endif /* _NJT_EVENT_QUIC_FRAMES_H_INCLUDED_ */
