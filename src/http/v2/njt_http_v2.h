/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 * Copyright (C) Valentin V. Bartenev
 */


#ifndef _NJT_HTTP_V2_H_INCLUDED_
#define _NJT_HTTP_V2_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


#define NJT_HTTP_V2_ALPN_PROTO           "\x02h2"

#define NJT_HTTP_V2_STATE_BUFFER_SIZE    16

#define NJT_HTTP_V2_DEFAULT_FRAME_SIZE   (1 << 14)
#define NJT_HTTP_V2_MAX_FRAME_SIZE       ((1 << 24) - 1)

#define NJT_HTTP_V2_INT_OCTETS           4
#define NJT_HTTP_V2_MAX_FIELD                                                 \
    (127 + (1 << (NJT_HTTP_V2_INT_OCTETS - 1) * 7) - 1)

#define NJT_HTTP_V2_FRAME_HEADER_SIZE    9

/* frame types */
#define NJT_HTTP_V2_DATA_FRAME           0x0
#define NJT_HTTP_V2_HEADERS_FRAME        0x1
#define NJT_HTTP_V2_PRIORITY_FRAME       0x2
#define NJT_HTTP_V2_RST_STREAM_FRAME     0x3
#define NJT_HTTP_V2_SETTINGS_FRAME       0x4
#define NJT_HTTP_V2_PUSH_PROMISE_FRAME   0x5
#define NJT_HTTP_V2_PING_FRAME           0x6
#define NJT_HTTP_V2_GOAWAY_FRAME         0x7
#define NJT_HTTP_V2_WINDOW_UPDATE_FRAME  0x8
#define NJT_HTTP_V2_CONTINUATION_FRAME   0x9

/* frame flags */
#define NJT_HTTP_V2_NO_FLAG              0x00
#define NJT_HTTP_V2_ACK_FLAG             0x01
#define NJT_HTTP_V2_END_STREAM_FLAG      0x01
#define NJT_HTTP_V2_END_HEADERS_FLAG     0x04
#define NJT_HTTP_V2_PADDED_FLAG          0x08
#define NJT_HTTP_V2_PRIORITY_FLAG        0x20

#define NJT_HTTP_V2_MAX_WINDOW           ((1U << 31) - 1)
#define NJT_HTTP_V2_DEFAULT_WINDOW       65535

#define NJT_HTTP_V2_DEFAULT_WEIGHT       16


typedef struct njt_http_v2_connection_s   njt_http_v2_connection_t;
typedef struct njt_http_v2_node_s         njt_http_v2_node_t;
typedef struct njt_http_v2_out_frame_s    njt_http_v2_out_frame_t;


typedef u_char *(*njt_http_v2_handler_pt) (njt_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);


typedef struct {
    njt_flag_t                       enable;
    size_t                           pool_size;
    njt_uint_t                       concurrent_streams;
    size_t                           preread_size;
    njt_uint_t                       streams_index_mask;
} njt_http_v2_srv_conf_t;

typedef struct {
    njt_str_t                        name;
    njt_str_t                        value;
} njt_http_v2_header_t;


typedef struct {
    njt_uint_t                       sid;
    size_t                           length;
    size_t                           padding;
    unsigned                         flags:8;

    unsigned                         incomplete:1;
    unsigned                         keep_pool:1;

    /* HPACK */
    unsigned                         parse_name:1;
    unsigned                         parse_value:1;
    unsigned                         index:1;
    njt_http_v2_header_t             header;
    size_t                           header_limit;
    u_char                           field_state;
    u_char                          *field_start;
    u_char                          *field_end;
    size_t                           field_rest;
    njt_pool_t                      *pool;

    njt_http_v2_stream_t            *stream;

    u_char                           buffer[NJT_HTTP_V2_STATE_BUFFER_SIZE];
    size_t                           buffer_used;
    njt_http_v2_handler_pt           handler;
} njt_http_v2_state_t;



typedef struct {
    njt_http_v2_header_t           **entries;

    njt_uint_t                       added;
    njt_uint_t                       deleted;
    njt_uint_t                       reused;
    njt_uint_t                       allocated;

    size_t                           size;
    size_t                           free;
    u_char                          *storage;
    u_char                          *pos;
} njt_http_v2_hpack_t;


struct njt_http_v2_connection_s {
    njt_connection_t                *connection;
    njt_http_connection_t           *http_connection;

    off_t                            total_bytes;
    off_t                            payload_bytes;

    njt_uint_t                       processing;
    njt_uint_t                       frames;
    njt_uint_t                       idle;
    njt_uint_t                       new_streams;
    njt_uint_t                       refused_streams;
    njt_uint_t                       priority_limit;

    size_t                           send_window;
    size_t                           recv_window;
    size_t                           init_window;

    size_t                           frame_size;

    njt_queue_t                      waiting;

    njt_http_v2_state_t              state;

    njt_http_v2_hpack_t              hpack;

    njt_pool_t                      *pool;

    njt_http_v2_out_frame_t         *free_frames;
    njt_connection_t                *free_fake_connections;

    njt_http_v2_node_t             **streams_index;

    njt_http_v2_out_frame_t         *last_out;

    njt_queue_t                      dependencies;
    njt_queue_t                      closed;

    njt_uint_t                       closed_nodes;
    njt_uint_t                       last_sid;

    time_t                           lingering_time;

    unsigned                         settings_ack:1;
    unsigned                         table_update:1;
    unsigned                         blocked:1;
    unsigned                         goaway:1;
};


struct njt_http_v2_node_s {
    njt_uint_t                       id;
    njt_http_v2_node_t              *index;
    njt_http_v2_node_t              *parent;
    njt_queue_t                      queue;
    njt_queue_t                      children;
    njt_queue_t                      reuse;
    njt_uint_t                       rank;
    njt_uint_t                       weight;
    double                           rel_weight;
    njt_http_v2_stream_t            *stream;
};


struct njt_http_v2_stream_s {
    njt_http_request_t              *request;
    njt_http_v2_connection_t        *connection;
    njt_http_v2_node_t              *node;

    njt_uint_t                       queued;

    /*
     * A change to SETTINGS_INITIAL_WINDOW_SIZE could cause the
     * send_window to become negative, hence it's signed.
     */
    ssize_t                          send_window;
    size_t                           recv_window;

    njt_buf_t                       *preread;

    njt_uint_t                       frames;

    njt_http_v2_out_frame_t         *free_frames;
    njt_chain_t                     *free_frame_headers;
    njt_chain_t                     *free_bufs;

    njt_queue_t                      queue;

    njt_array_t                     *cookies;

    njt_pool_t                      *pool;

    unsigned                         waiting:1;
    unsigned                         blocked:1;
    unsigned                         exhausted:1;
    unsigned                         in_closed:1;
    unsigned                         out_closed:1;
    unsigned                         rst_sent:1;
    unsigned                         no_flow_control:1;
    unsigned                         skip_data:1;
};


struct njt_http_v2_out_frame_s {
    njt_http_v2_out_frame_t         *next;
    njt_chain_t                     *first;
    njt_chain_t                     *last;
    njt_int_t                      (*handler)(njt_http_v2_connection_t *h2c,
                                        njt_http_v2_out_frame_t *frame);

    njt_http_v2_stream_t            *stream;
    size_t                           length;

    unsigned                         blocked:1;
    unsigned                         fin:1;
};


static njt_inline void
njt_http_v2_queue_frame(njt_http_v2_connection_t *h2c,
    njt_http_v2_out_frame_t *frame)
{
    njt_http_v2_out_frame_t  **out;

    for (out = &h2c->last_out; *out; out = &(*out)->next) {

        if ((*out)->blocked || (*out)->stream == NULL) {
            break;
        }

        if ((*out)->stream->node->rank < frame->stream->node->rank
            || ((*out)->stream->node->rank == frame->stream->node->rank
                && (*out)->stream->node->rel_weight
                   >= frame->stream->node->rel_weight))
        {
            break;
        }
    }

    frame->next = *out;
    *out = frame;
}


static njt_inline void
njt_http_v2_queue_blocked_frame(njt_http_v2_connection_t *h2c,
    njt_http_v2_out_frame_t *frame)
{
    njt_http_v2_out_frame_t  **out;

    for (out = &h2c->last_out; *out; out = &(*out)->next) {

        if ((*out)->blocked || (*out)->stream == NULL) {
            break;
        }
    }

    frame->next = *out;
    *out = frame;
}


static njt_inline void
njt_http_v2_queue_ordered_frame(njt_http_v2_connection_t *h2c,
    njt_http_v2_out_frame_t *frame)
{
    frame->next = h2c->last_out;
    h2c->last_out = frame;
}


void njt_http_v2_init(njt_event_t *rev);

njt_int_t njt_http_v2_read_request_body(njt_http_request_t *r);
njt_int_t njt_http_v2_read_unbuffered_request_body(njt_http_request_t *r);

void njt_http_v2_close_stream(njt_http_v2_stream_t *stream, njt_int_t rc);

njt_int_t njt_http_v2_send_output_queue(njt_http_v2_connection_t *h2c);


njt_str_t *njt_http_v2_get_static_name(njt_uint_t index);
njt_str_t *njt_http_v2_get_static_value(njt_uint_t index);

njt_int_t njt_http_v2_get_indexed_header(njt_http_v2_connection_t *h2c,
    njt_uint_t index, njt_uint_t name_only);
njt_int_t njt_http_v2_add_header(njt_http_v2_connection_t *h2c,
    njt_http_v2_header_t *header);
njt_int_t njt_http_v2_table_size(njt_http_v2_connection_t *h2c, size_t size);


#define njt_http_v2_prefix(bits)  ((1 << (bits)) - 1)


#if (NJT_HAVE_NONALIGNED)

#define njt_http_v2_parse_uint16(p)  ntohs(*(uint16_t *) (p))
#define njt_http_v2_parse_uint32(p)  ntohl(*(uint32_t *) (p))

#else

#define njt_http_v2_parse_uint16(p)  ((p)[0] << 8 | (p)[1])
#define njt_http_v2_parse_uint32(p)                                           \
    ((uint32_t) (p)[0] << 24 | (p)[1] << 16 | (p)[2] << 8 | (p)[3])

#endif

#define njt_http_v2_parse_length(p)  ((p) >> 8)
#define njt_http_v2_parse_type(p)    ((p) & 0xff)
#define njt_http_v2_parse_sid(p)     (njt_http_v2_parse_uint32(p) & 0x7fffffff)
#define njt_http_v2_parse_window(p)  (njt_http_v2_parse_uint32(p) & 0x7fffffff)


#define njt_http_v2_write_uint16_aligned(p, s)                                \
    (*(uint16_t *) (p) = htons((uint16_t) (s)), (p) + sizeof(uint16_t))
#define njt_http_v2_write_uint32_aligned(p, s)                                \
    (*(uint32_t *) (p) = htonl((uint32_t) (s)), (p) + sizeof(uint32_t))

#if (NJT_HAVE_NONALIGNED)

#define njt_http_v2_write_uint16  njt_http_v2_write_uint16_aligned
#define njt_http_v2_write_uint32  njt_http_v2_write_uint32_aligned

#else

#define njt_http_v2_write_uint16(p, s)                                        \
    ((p)[0] = (u_char) ((s) >> 8),                                            \
     (p)[1] = (u_char)  (s),                                                  \
     (p) + sizeof(uint16_t))

#define njt_http_v2_write_uint32(p, s)                                        \
    ((p)[0] = (u_char) ((s) >> 24),                                           \
     (p)[1] = (u_char) ((s) >> 16),                                           \
     (p)[2] = (u_char) ((s) >> 8),                                            \
     (p)[3] = (u_char)  (s),                                                  \
     (p) + sizeof(uint32_t))

#endif

#define njt_http_v2_write_len_and_type(p, l, t)                               \
    njt_http_v2_write_uint32_aligned(p, (l) << 8 | (t))

#define njt_http_v2_write_sid  njt_http_v2_write_uint32


#define njt_http_v2_indexed(i)      (128 + (i))
#define njt_http_v2_inc_indexed(i)  (64 + (i))

#define njt_http_v2_write_name(dst, src, len, tmp)                            \
    njt_http_v2_string_encode(dst, src, len, tmp, 1)
#define njt_http_v2_write_value(dst, src, len, tmp)                           \
    njt_http_v2_string_encode(dst, src, len, tmp, 0)

#define NJT_HTTP_V2_ENCODE_RAW            0
#define NJT_HTTP_V2_ENCODE_HUFF           0x80

#define NJT_HTTP_V2_AUTHORITY_INDEX       1

#define NJT_HTTP_V2_METHOD_INDEX          2
#define NJT_HTTP_V2_METHOD_GET_INDEX      2
#define NJT_HTTP_V2_METHOD_POST_INDEX     3

#define NJT_HTTP_V2_PATH_INDEX            4
#define NJT_HTTP_V2_PATH_ROOT_INDEX       4

#define NJT_HTTP_V2_SCHEME_HTTP_INDEX     6
#define NJT_HTTP_V2_SCHEME_HTTPS_INDEX    7

#define NJT_HTTP_V2_STATUS_INDEX          8
#define NJT_HTTP_V2_STATUS_200_INDEX      8
#define NJT_HTTP_V2_STATUS_204_INDEX      9
#define NJT_HTTP_V2_STATUS_206_INDEX      10
#define NJT_HTTP_V2_STATUS_304_INDEX      11
#define NJT_HTTP_V2_STATUS_400_INDEX      12
#define NJT_HTTP_V2_STATUS_404_INDEX      13
#define NJT_HTTP_V2_STATUS_500_INDEX      14

#define NJT_HTTP_V2_CONTENT_LENGTH_INDEX  28
#define NJT_HTTP_V2_CONTENT_TYPE_INDEX    31
#define NJT_HTTP_V2_DATE_INDEX            33
#define NJT_HTTP_V2_LAST_MODIFIED_INDEX   44
#define NJT_HTTP_V2_LOCATION_INDEX        46
#define NJT_HTTP_V2_SERVER_INDEX          54
#define NJT_HTTP_V2_VARY_INDEX            59

#define NJT_HTTP_V2_PREFACE_START         "PRI * HTTP/2.0\r\n"
#define NJT_HTTP_V2_PREFACE_END           "\r\nSM\r\n\r\n"
#define NJT_HTTP_V2_PREFACE               NJT_HTTP_V2_PREFACE_START           \
                                          NJT_HTTP_V2_PREFACE_END


u_char *njt_http_v2_string_encode(u_char *dst, u_char *src, size_t len,
    u_char *tmp, njt_uint_t lower);


extern njt_module_t  njt_http_v2_module;


#endif /* _NJT_HTTP_V2_H_INCLUDED_ */
