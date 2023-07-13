
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 * Copyright (C), 2021-2023, TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_VTS_MODULE_H_INCLUDED_
#define _NJT_HTTP_VTS_MODULE_H_INCLUDED_


#include <njet.h>
#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>

#include "njt_http_vhost_traffic_status_string.h"
#include "njt_http_vhost_traffic_status_node.h"

/*
 * This version should follow the stable releases.
 * The format should follow https://semver.org/
 *
 * If a change has some important impact, include the commit short hash here.
 * I.E "v0.2.0+h0a1s2h"
 *
 */
#define NJT_HTTP_VTS_MODULE_VERSION "v0.2.1"

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO          0
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA          1
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG          2
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC          3
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG          4

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAMS            (u_char *) "NO\0UA\0UG\0CC\0FG\0"

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_NODE_NONE            0
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_NODE_FIND            1

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR        (u_char) 0x1f

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_NONE          0
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSON          1
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_HTML          2
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSONP         3
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_PROMETHEUS    4

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_AVERAGE_METHOD_AMM   0
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_AVERAGE_METHOD_WMA   1

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_SHM_NAME     "njt_http_vhost_traffic_status"
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_SHM_SIZE     0xfffff
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_JSONP        "njt_http_vhost_traffic_status_jsonp_callback"
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_SUM_KEY      "*"
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_AVG_PERIOD   60
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_DUMP_PERIOD  60

#define njt_http_vhost_traffic_status_add_rc(s, n) {                           \
    if(s < 200) {n->stat_1xx_counter++;}                                       \
    else if(s < 300) {n->stat_2xx_counter++;}                                  \
    else if(s < 400) {n->stat_3xx_counter++;}                                  \
    else if(s < 500) {n->stat_4xx_counter++;}                                  \
    else {n->stat_5xx_counter++;}                                              \
}

#if (NJT_HTTP_CACHE)

#if !defined(njet_version) || njet_version < 1005007
#define njt_http_vhost_traffic_status_add_cc(s, n) {                           \
    if(s == NJT_HTTP_CACHE_MISS) {n->stat_cache_miss_counter++;}               \
    else if(s == NJT_HTTP_CACHE_BYPASS) {n->stat_cache_bypass_counter++;}      \
    else if(s == NJT_HTTP_CACHE_EXPIRED) {n->stat_cache_expired_counter++;}    \
    else if(s == NJT_HTTP_CACHE_STALE) {n->stat_cache_stale_counter++;}        \
    else if(s == NJT_HTTP_CACHE_UPDATING) {n->stat_cache_updating_counter++;}  \
    else if(s == NJT_HTTP_CACHE_HIT) {n->stat_cache_hit_counter++;}            \
    else if(s == NJT_HTTP_CACHE_SCARCE) {n->stat_cache_scarce_counter++;}      \
}
#else
#define njt_http_vhost_traffic_status_add_cc(s, n) {                           \
    if(s == NJT_HTTP_CACHE_MISS) {                                             \
        n->stat_cache_miss_counter++;                                          \
    }                                                                          \
    else if(s == NJT_HTTP_CACHE_BYPASS) {                                      \
        n->stat_cache_bypass_counter++;                                        \
    }                                                                          \
    else if(s == NJT_HTTP_CACHE_EXPIRED) {                                     \
        n->stat_cache_expired_counter++;                                       \
    }                                                                          \
    else if(s == NJT_HTTP_CACHE_STALE) {                                       \
        n->stat_cache_stale_counter++;                                         \
    }                                                                          \
    else if(s == NJT_HTTP_CACHE_UPDATING) {                                    \
        n->stat_cache_updating_counter++;                                      \
    }                                                                          \
    else if(s == NJT_HTTP_CACHE_REVALIDATED) {                                 \
        n->stat_cache_revalidated_counter++;                                   \
    }                                                                          \
    else if(s == NJT_HTTP_CACHE_HIT) {                                         \
        n->stat_cache_hit_counter++;                                           \
    }                                                                          \
    else if(s == NJT_HTTP_CACHE_SCARCE) {                                      \
        n->stat_cache_scarce_counter++;                                        \
    }                                                                          \
}
#endif

#endif

#if (NJT_HTTP_CACHE)
#define njt_http_vhost_traffic_status_add_oc(o, c) {                           \
    if (o->stat_request_counter > c->stat_request_counter) {                   \
        c->stat_request_counter_oc++;                                          \
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
    if (o->stat_request_time_counter > c->stat_request_time_counter) {         \
        c->stat_request_time_counter_oc++;                                     \
    }                                                                          \
    if (o->stat_cache_miss_counter > c->stat_cache_miss_counter) {             \
        c->stat_cache_miss_counter_oc++;                                       \
    }                                                                          \
    if (o->stat_cache_bypass_counter > c->stat_cache_bypass_counter) {         \
        c->stat_cache_bypass_counter_oc++;                                     \
    }                                                                          \
    if (o->stat_cache_expired_counter > c->stat_cache_expired_counter) {       \
        c->stat_cache_expired_counter_oc++;                                    \
    }                                                                          \
    if (o->stat_cache_stale_counter > c->stat_cache_stale_counter) {           \
        c->stat_cache_stale_counter_oc++;                                      \
    }                                                                          \
    if (o->stat_cache_updating_counter > c->stat_cache_updating_counter) {     \
        c->stat_cache_updating_counter_oc++;                                   \
    }                                                                          \
    if (o->stat_cache_revalidated_counter > c->stat_cache_revalidated_counter) \
    {                                                                          \
        c->stat_cache_revalidated_counter_oc++;                                \
    }                                                                          \
    if (o->stat_cache_hit_counter > c->stat_cache_hit_counter) {               \
        c->stat_cache_hit_counter_oc++;                                        \
    }                                                                          \
    if (o->stat_cache_scarce_counter > c->stat_cache_scarce_counter) {         \
        c->stat_cache_scarce_counter_oc++;                                     \
    }                                                                          \
}
#else
#define njt_http_vhost_traffic_status_add_oc(o, c) {                           \
    if (o->stat_request_counter > c->stat_request_counter) {                   \
        c->stat_request_counter_oc++;                                          \
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
    if (o->stat_request_time_counter > c->stat_request_time_counter) {         \
        c->stat_request_time_counter_oc++;                                     \
    }                                                                          \
}
#endif

#define njt_http_vhost_traffic_status_group_to_string(n) (u_char *) (          \
    (n > 4)                                                                    \
    ? NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAMS                                  \
    : NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAMS + 3 * n                          \
)

#define njt_http_vhost_traffic_status_string_to_group(s) (unsigned) (          \
{                                                                              \
    unsigned n = NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO;                    \
    if (*s == 'N' && *(s + 1) == 'O') {                                        \
        n = NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO;                         \
    } else if (*s == 'U' && *(s + 1) == 'A') {                                 \
        n = NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA;                         \
    } else if (*s == 'U' && *(s + 1) == 'G') {                                 \
        n = NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG;                         \
    } else if (*s == 'C' && *(s + 1) == 'C') {                                 \
        n = NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC;                         \
    } else if (*s == 'F' && *(s + 1) == 'G') {                                 \
        n = NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG;                         \
    }                                                                          \
    n;                                                                         \
}                                                                              \
)

#define njt_http_vhost_traffic_status_max_integer (NJT_ATOMIC_T_LEN < 12)      \
    ? "4294967295"                                                             \
    : "18446744073709551615"

#define njt_http_vhost_traffic_status_boolean_to_string(b) (b) ? "true" : "false"

#define njt_http_vhost_traffic_status_triangle(n) (unsigned) (                 \
    n * (n + 1) / 2                                                            \
)


typedef struct {
    njt_rbtree_t                           *rbtree;

    /* array of njt_http_vhost_traffic_status_filter_t */
    njt_array_t                            *filter_keys;
#if (NJT_HTTP_VTS_DYNCONF)
    njt_array_t                            *filter_keys_dyn;
    njt_pool_t                             *dyn_pool;
#endif

    /* array of njt_http_vhost_traffic_status_limit_t */
    njt_array_t                            *limit_traffics;

    /* array of njt_http_vhost_traffic_status_limit_t */
    njt_array_t                            *limit_filter_traffics;

    /* array of njt_http_vhost_traffic_status_filter_match_t */
    njt_array_t                            *filter_max_node_matches;

    njt_uint_t                              filter_max_node;

    njt_flag_t                              enable;
    njt_flag_t                              filter_check_duplicate;
    njt_flag_t                              limit_check_duplicate;
    njt_shm_zone_t                         *shm_zone;
    njt_str_t                               shm_name;
    ssize_t                                 shm_size;

    njt_flag_t                              dump;
    njt_str_t                               dump_file;
    njt_msec_t                              dump_period;
    njt_event_t                             dump_event;
} njt_http_vhost_traffic_status_ctx_t;


typedef struct {
    njt_shm_zone_t                         *shm_zone;
    njt_str_t                               shm_name;
    njt_flag_t                              enable;
    njt_flag_t                              filter;
    njt_flag_t                              filter_host;
    njt_flag_t                              filter_check_duplicate;

    /* array of njt_http_vhost_traffic_status_filter_t */
    njt_array_t                            *filter_keys;

    /* array of njt_http_vhost_traffic_status_filter_variable_t */
    njt_array_t                            *filter_vars;

    njt_flag_t                              limit;
    njt_flag_t                              limit_check_duplicate;

    /* array of njt_http_vhost_traffic_status_limit_t */
    njt_array_t                            *limit_traffics;

    /* array of njt_http_vhost_traffic_status_limit_t */
    njt_array_t                            *limit_filter_traffics;

    njt_http_vhost_traffic_status_node_t    stats;
    njt_msec_t                              start_msec;
    njt_flag_t                              format;
    njt_str_t                               jsonp;
    njt_str_t                               sum_key;

    njt_flag_t                              average_method;
    njt_msec_t                              average_period;

    /* array of njt_http_vhost_traffic_status_node_histogram_t */
    njt_array_t                            *histogram_buckets;

    njt_flag_t                              bypass_limit;
    njt_flag_t                              bypass_stats;

    njt_rbtree_node_t                     **node_caches;
} njt_http_vhost_traffic_status_loc_conf_t;


njt_msec_t njt_http_vhost_traffic_status_current_msec(void);
njt_msec_int_t njt_http_vhost_traffic_status_request_time(njt_http_request_t *r);
njt_msec_int_t njt_http_vhost_traffic_status_upstream_response_time(njt_http_request_t *r);
njt_http_vhost_traffic_status_node_t *
    njt_http_vhost_traffic_status_get_node(njt_rbtree_node_t *node);
void njt_http_vhost_traffic_status_sum_node(njt_http_vhost_traffic_status_node_t *vtsn,
    njt_http_vhost_traffic_status_loc_conf_t  *vtscf);

extern njt_flag_t njt_http_vts_enable;
extern njt_module_t *njt_http_vtsp_module;
extern njt_module_t *njt_http_vtscp_module;
extern njt_module_t *njt_http_vtsdp_module;
extern njt_shm_zone_t *njt_http_vts_shm_zone;
extern njt_rbtree_t *njt_http_vts_rbtree;
extern njt_str_t njt_http_vts_shm_name;
extern ssize_t njt_http_vts_shm_size;
extern njt_cycle_t *njt_http_vtsp_cycle;
extern njt_cycle_t *njet_master_cycle;
extern njt_cycle_t *njet_cycle;

#define njt_http_vhost_traffic_status_module    (*njt_http_vtsp_module)


#endif /* _NJT_HTTP_VTS_MODULE_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
