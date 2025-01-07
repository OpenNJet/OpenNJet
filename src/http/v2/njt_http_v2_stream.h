/*
 * Copyright (C) 2024 Kern
 */

#ifndef _NJT_HTTP_V2_STREAM_H_INCLUDED_
#define _NJT_HTTP_V2_STREAM_H_INCLUDED_

#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>

typedef struct {
    uint64_t                       size;
    njt_chain_t                   *chain;
    njt_chain_t                   **last_chain;
} njt_http_v2_stream_buffer_t;

#define njt_http_v2_get_connection(c)                                            \
    (((c)->stream) ? (((njt_http_v2_stream_t *)((c)->stream))->connection) : NULL)

ssize_t njt_http_v2_stream_send(njt_connection_t *c, u_char *buf, size_t size);
ssize_t njt_http_v2_stream_recv(njt_connection_t *c, u_char *buf, size_t size);
njt_chain_t *njt_http_v2_write_chain(njt_connection_t *c, njt_http_v2_stream_buffer_t *qb,
    njt_chain_t *in, uint64_t limit);
njt_int_t njt_http_v2_write_buffer(njt_connection_t *c, u_char *data,size_t len);
ssize_t njt_http_v2_recv_chain(njt_connection_t *fc, njt_chain_t *in, off_t limit);

#endif