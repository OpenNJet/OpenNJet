
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#ifndef _NJT_HTTP_STREAM_STS_MODULE_H_INCLUDED_
#define _NJT_HTTP_STREAM_STS_MODULE_H_INCLUDED_

#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_stream.h>
#include <njt_stream_dyn_module.h>

#include "njt_http_stream_server_traffic_status_string.h"
#include "njt_http_stream_server_traffic_status_node.h"

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_NO          0
#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_UA          1
#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_UG          2
#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_FG          3

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAMS            \
    (u_char *) "NO\0UA\0UG\0FG\0"

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_NODE_NONE            0
#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_NODE_FIND            1

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_KEY_SEPARATOR        (u_char) 0x1f

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_FORMAT_NONE          0
#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_FORMAT_JSON          1
#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_FORMAT_HTML          2
#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_FORMAT_JSONP         3
#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_FORMAT_PROMETHEUS    4

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_AVERAGE_METHOD_AMM   0
#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_AVERAGE_METHOD_WMA   1

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_DEFAULT_SHM_NAME                 \
    "stream_server_traffic_status"

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_DEFAULT_JSONP                    \
    "njt_http_stream_server_traffic_status_jsonp_callback"

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_DEFAULT_AVG_PERIOD   60

#define njt_http_stream_server_traffic_status_add_oc(o, c) {                   \
    if (o->stat_connect_counter > c->stat_connect_counter) {                   \
        c->stat_connect_counter_oc++;                                          \
    }                                                                          \
    if (o->stat_in_bytes > c->stat_in_bytes) {                                 \
        c->stat_in_bytes_oc++;                                                 \
    }                                                                          \
    if (o->stat_out_bytes > c->stat_out_bytes) {                               \
        c->stat_out_bytes_oc++;                                                \
    }                                                                          \
    if (o->stat_1xx_counter > c->stat_1xx_counter) {                           \
        c->stat_1xx_counter_oc++;                                              \
    }                                                                          \
    if (o->stat_2xx_counter > c->stat_2xx_counter) {                           \
        c->stat_2xx_counter_oc++;                                              \
    }                                                                          \
    if (o->stat_3xx_counter > c->stat_3xx_counter) {                           \
        c->stat_3xx_counter_oc++;                                              \
    }                                                                          \
    if (o->stat_4xx_counter > c->stat_4xx_counter) {                           \
        c->stat_4xx_counter_oc++;                                              \
    }                                                                          \
    if (o->stat_5xx_counter > c->stat_5xx_counter) {                           \
        c->stat_5xx_counter_oc++;                                              \
    }                                                                          \
    if (o->stat_session_time_counter > c->stat_session_time_counter) {         \
        c->stat_session_time_counter_oc++;                                     \
    }                                                                          \
}

#define njt_http_stream_server_traffic_status_group_to_string(n) (u_char *) (  \
    (n > 3)                                                                    \
    ? NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAMS                          \
    : NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAMS + 3 * n                  \
)

#define njt_http_stream_server_traffic_status_max_integer                      \
    (NJT_ATOMIC_T_LEN < 12)                                                    \
    ? "4294967295"                                                             \
    : "18446744073709551615"

#define njt_http_stream_server_traffic_status_boolean_to_string(b)             \
    (b) ? "true" : "false"

#define njt_http_stream_server_traffic_status_triangle(n) (unsigned) (         \
    n * (n + 1) / 2                                                            \
)


/* must be the same as njt_stream_server_traffic_status_ctx_t */
typedef struct {
    njt_rbtree_t                                   *rbtree;

    /* array of njt_http_stream_server_traffic_status_filter_t */
    njt_array_t                                    *filter_keys;

    /* array of njt_http_stream_server_traffic_status_limit_t */
    njt_array_t                                    *limit_traffics;

    /* array of njt_http_stream_server_traffic_status_limit_t */
    njt_array_t                                    *limit_filter_traffics;

    njt_flag_t                                      enable;
    njt_flag_t                                      filter_check_duplicate;
    njt_flag_t                                      limit_check_duplicate;

    njt_stream_upstream_main_conf_t                *upstream;
    njt_str_t                                       shm_name;
    ssize_t                                         shm_size;
} njt_http_stream_server_traffic_status_ctx_t;


typedef struct {
    njt_shm_zone_t                                 *shm_zone;
    njt_flag_t                                      enable;

    njt_str_t                                       shm_name;
    njt_http_stream_server_traffic_status_node_t    stats;
    njt_msec_t                                      start_msec;
    njt_flag_t                                      format;
    njt_str_t                                       jsonp;

    njt_flag_t                                      average_method;
    njt_msec_t                                      average_period;

    njt_rbtree_node_t                             **node_caches;
} njt_http_stream_server_traffic_status_loc_conf_t;


njt_msec_t njt_http_stream_server_traffic_status_current_msec(void);

extern njt_module_t njt_stream_stsd_module;
extern njt_module_t njt_stream_stsc_module;
extern njt_cycle_t *njet_master_cycle;

#endif /* _NJT_HTTP_STREAM_STS_MODULE_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
