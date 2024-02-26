
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#ifndef _NJT_STREAM_STS_MODULE_H_INCLUDED_
#define _NJT_STREAM_STS_MODULE_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>
#include <njt_stream_dyn_module.h>

#include "njt_stream_server_traffic_status_string.h"
#include "njt_stream_server_traffic_status_node.h"

#define NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_NO          0
#define NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_UA          1
#define NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_UG          2
#define NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_FG          3

#define NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAMS            (u_char *) "NO\0UA\0UG\0FG\0"

#define NJT_STREAM_SERVER_TRAFFIC_STATUS_NODE_NONE            0
#define NJT_STREAM_SERVER_TRAFFIC_STATUS_NODE_FIND            1

#define NJT_STREAM_SERVER_TRAFFIC_STATUS_KEY_SEPARATOR        (u_char) 0x1f

#define NJT_STREAM_SERVER_TRAFFIC_STATUS_AVERAGE_METHOD_AMM   0
#define NJT_STREAM_SERVER_TRAFFIC_STATUS_AVERAGE_METHOD_WMA   1

#define NJT_STREAM_SERVER_TRAFFIC_STATUS_DEFAULT_SHM_NAME     "stream_server_traffic_status"
#define NJT_STREAM_SERVER_TRAFFIC_STATUS_DEFAULT_SHM_SIZE     0xfffff
#define NJT_STREAM_SERVER_TRAFFIC_STATUS_DEFAULT_AVG_PERIOD   60

#define njt_stream_server_traffic_status_add_rc(s, n) {                   \
    if(s < 200) {n->stat_1xx_counter++;}                                  \
    else if(s < 300) {n->stat_2xx_counter++;}                             \
    else if(s < 400) {n->stat_3xx_counter++;}                             \
    else if(s < 500) {n->stat_4xx_counter++;}                             \
    else {n->stat_5xx_counter++;}                                         \
}

#define njt_stream_server_traffic_status_add_oc(o, c) {                   \
    if (o->stat_connect_counter > c->stat_connect_counter) {              \
        c->stat_connect_counter_oc++;                                     \
    }                                                                     \
    if (o->stat_in_bytes > c->stat_in_bytes) {                            \
        c->stat_in_bytes_oc++;                                            \
    }                                                                     \
    if (o->stat_out_bytes > c->stat_out_bytes) {                          \
        c->stat_out_bytes_oc++;                                           \
    }                                                                     \
    if (o->stat_1xx_counter > c->stat_1xx_counter) {                      \
        c->stat_1xx_counter_oc++;                                         \
    }                                                                     \
    if (o->stat_2xx_counter > c->stat_2xx_counter) {                      \
        c->stat_2xx_counter_oc++;                                         \
    }                                                                     \
    if (o->stat_3xx_counter > c->stat_3xx_counter) {                      \
        c->stat_2xx_counter_oc++;                                         \
    }                                                                     \
    if (o->stat_4xx_counter > c->stat_4xx_counter) {                      \
        c->stat_4xx_counter_oc++;                                         \
    }                                                                     \
    if (o->stat_5xx_counter > c->stat_5xx_counter) {                      \
        c->stat_5xx_counter_oc++;                                         \
    }                                                                     \
    if (o->stat_session_time_counter > c->stat_session_time_counter) {    \
        c->stat_session_time_counter_oc++;                                \
    }                                                                     \
}

#define njt_stream_server_traffic_status_group_to_string(n) (u_char *) (  \
    (n > 3)                                                               \
    ? NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAMS                          \
    : NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAMS + 3 * n                  \
)

#define njt_stream_server_traffic_status_string_to_group(s) (unsigned) (  \
{                                                                         \
    unsigned n = NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_NO;            \
    if (*s == 'N' && *(s + 1) == 'O') {                                   \
        n = NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_NO;                 \
    } else if (*s == 'U' && *(s + 1) == 'A') {                            \
        n = NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_UA;                 \
    } else if (*s == 'U' && *(s + 1) == 'G') {                            \
        n = NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_UG;                 \
    } else if (*s == 'F' && *(s + 1) == 'G') {                            \
        n = NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_FG;                 \
    }                                                                     \
    n;                                                                    \
}                                                                         \
)

#define njt_stream_server_traffic_status_triangle(n) (unsigned) (         \
    n * (n + 1) / 2                                                       \
)

njt_msec_t njt_stream_server_traffic_status_current_msec(void);
njt_msec_int_t njt_stream_server_traffic_status_session_time(njt_stream_session_t *s);
njt_msec_int_t njt_stream_server_traffic_status_upstream_response_time(njt_stream_session_t *s,
    uintptr_t data);

extern njt_module_t njt_stream_stsc_module;


#endif /* _NJT_STREAM_STS_MODULE_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
