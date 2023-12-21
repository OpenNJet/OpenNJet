
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_V3_H_INCLUDED_
#define _NJT_HTTP_V3_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>

#include <njt_http_v3_parse.h>
#include <njt_http_v3_encode.h>
#include <njt_http_v3_uni.h>
#include <njt_http_v3_table.h>


#define NJT_HTTP_V3_ALPN_PROTO                     "\x02h3"
#define NJT_HTTP_V3_HQ_ALPN_PROTO                  "\x0Ahq-interop"
#define NJT_HTTP_V3_HQ_PROTO                       "hq-interop"

#define NJT_HTTP_V3_VARLEN_INT_LEN                 4
#define NJT_HTTP_V3_PREFIX_INT_LEN                 11

#define NJT_HTTP_V3_STREAM_CONTROL                 0x00
#define NJT_HTTP_V3_STREAM_PUSH                    0x01
#define NJT_HTTP_V3_STREAM_ENCODER                 0x02
#define NJT_HTTP_V3_STREAM_DECODER                 0x03

#define NJT_HTTP_V3_FRAME_DATA                     0x00
#define NJT_HTTP_V3_FRAME_HEADERS                  0x01
#define NJT_HTTP_V3_FRAME_CANCEL_PUSH              0x03
#define NJT_HTTP_V3_FRAME_SETTINGS                 0x04
#define NJT_HTTP_V3_FRAME_PUSH_PROMISE             0x05
#define NJT_HTTP_V3_FRAME_GOAWAY                   0x07
#define NJT_HTTP_V3_FRAME_MAX_PUSH_ID              0x0d

#define NJT_HTTP_V3_PARAM_MAX_TABLE_CAPACITY       0x01
#define NJT_HTTP_V3_PARAM_MAX_FIELD_SECTION_SIZE   0x06
#define NJT_HTTP_V3_PARAM_BLOCKED_STREAMS          0x07

#define NJT_HTTP_V3_MAX_TABLE_CAPACITY             4096

#define NJT_HTTP_V3_STREAM_CLIENT_CONTROL          0
#define NJT_HTTP_V3_STREAM_SERVER_CONTROL          1
#define NJT_HTTP_V3_STREAM_CLIENT_ENCODER          2
#define NJT_HTTP_V3_STREAM_SERVER_ENCODER          3
#define NJT_HTTP_V3_STREAM_CLIENT_DECODER          4
#define NJT_HTTP_V3_STREAM_SERVER_DECODER          5
#define NJT_HTTP_V3_MAX_KNOWN_STREAM               6
#define NJT_HTTP_V3_MAX_UNI_STREAMS                3

/* HTTP/3 errors */
#define NJT_HTTP_V3_ERR_NO_ERROR                   0x100
#define NJT_HTTP_V3_ERR_GENERAL_PROTOCOL_ERROR     0x101
#define NJT_HTTP_V3_ERR_INTERNAL_ERROR             0x102
#define NJT_HTTP_V3_ERR_STREAM_CREATION_ERROR      0x103
#define NJT_HTTP_V3_ERR_CLOSED_CRITICAL_STREAM     0x104
#define NJT_HTTP_V3_ERR_FRAME_UNEXPECTED           0x105
#define NJT_HTTP_V3_ERR_FRAME_ERROR                0x106
#define NJT_HTTP_V3_ERR_EXCESSIVE_LOAD             0x107
#define NJT_HTTP_V3_ERR_ID_ERROR                   0x108
#define NJT_HTTP_V3_ERR_SETTINGS_ERROR             0x109
#define NJT_HTTP_V3_ERR_MISSING_SETTINGS           0x10a
#define NJT_HTTP_V3_ERR_REQUEST_REJECTED           0x10b
#define NJT_HTTP_V3_ERR_REQUEST_CANCELLED          0x10c
#define NJT_HTTP_V3_ERR_REQUEST_INCOMPLETE         0x10d
#define NJT_HTTP_V3_ERR_CONNECT_ERROR              0x10f
#define NJT_HTTP_V3_ERR_VERSION_FALLBACK           0x110

/* QPACK errors */
#define NJT_HTTP_V3_ERR_DECOMPRESSION_FAILED       0x200
#define NJT_HTTP_V3_ERR_ENCODER_STREAM_ERROR       0x201
#define NJT_HTTP_V3_ERR_DECODER_STREAM_ERROR       0x202


#define njt_http_v3_get_session(c)                                            \
    ((njt_http_v3_session_t *) ((c)->quic ? (c)->quic->parent->data           \
                                          : (c)->data))

#define njt_http_quic_get_connection(c)                                       \
    (njt_http_v3_get_session(c)->http_connection)

#define njt_http_v3_get_module_loc_conf(c, module)                            \
    njt_http_get_module_loc_conf(njt_http_quic_get_connection(c)->conf_ctx,   \
                                 module)

#define njt_http_v3_get_module_srv_conf(c, module)                            \
    njt_http_get_module_srv_conf(njt_http_quic_get_connection(c)->conf_ctx,   \
                                 module)

#define njt_http_v3_finalize_connection(c, code, reason)                      \
    njt_quic_finalize_connection((c)->quic ? (c)->quic->parent : (c),         \
                                 code, reason)

#define njt_http_v3_shutdown_connection(c, code, reason)                      \
    njt_quic_shutdown_connection((c)->quic ? (c)->quic->parent : (c),         \
                                 code, reason)


typedef struct {
    njt_flag_t                    enable;
    njt_flag_t                    enable_hq;
    size_t                        max_table_capacity;
    njt_uint_t                    max_blocked_streams;
    njt_uint_t                    max_concurrent_streams;
    njt_quic_conf_t               quic;
} njt_http_v3_srv_conf_t;


struct njt_http_v3_parse_s {
    size_t                        header_limit;
    njt_http_v3_parse_headers_t   headers;
    njt_http_v3_parse_data_t      body;
    njt_array_t                  *cookies;
};


struct njt_http_v3_session_s {
    njt_http_connection_t        *http_connection;

    njt_http_v3_dynamic_table_t   table;

    njt_event_t                   keepalive;
    njt_uint_t                    nrequests;

    njt_queue_t                   blocked;
    njt_uint_t                    nblocked;

    uint64_t                      next_request_id;

    off_t                         total_bytes;
    off_t                         payload_bytes;

    unsigned                      goaway:1;
    unsigned                      hq:1;

    njt_connection_t             *known_streams[NJT_HTTP_V3_MAX_KNOWN_STREAM];
};


void njt_http_v3_init_stream(njt_connection_t *c);
void njt_http_v3_reset_stream(njt_connection_t *c);
njt_int_t njt_http_v3_init_session(njt_connection_t *c);
njt_int_t njt_http_v3_check_flood(njt_connection_t *c);
njt_int_t njt_http_v3_init(njt_connection_t *c);
void njt_http_v3_shutdown(njt_connection_t *c);

njt_int_t njt_http_v3_read_request_body(njt_http_request_t *r);
njt_int_t njt_http_v3_read_unbuffered_request_body(njt_http_request_t *r);


extern njt_module_t  njt_http_v3_module;


#endif /* _NJT_HTTP_V3_H_INCLUDED_ */
