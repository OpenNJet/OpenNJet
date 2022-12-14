/* Copyright 2021 Qiming Sun <q.sun@f5.com> */

#ifndef NJT_HTTP_STICKY_MODULE_H_
#define NJT_HTTP_STICKY_MODULE_H_

#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_md5.h>

#define MD5_LENGTH 16

#define HTTP_STICKY_TYPE_COOKIE 1
#define HTTP_STICKY_TYPE_ROUTE 2
#define HTTP_STICKY_TYPE_LEARN 3

typedef struct {
    njt_str_t route_name;
    njt_str_t domain;
    njt_str_t samesite;
    njt_str_t path;
    njt_flag_t httponly;
    njt_flag_t secure;
    time_t expires;
	njt_int_t cookie;
	njt_int_t uri;
} njt_http_sticky_route_conf_t;

typedef struct {
    njt_str_t cookie_name;
    njt_str_t domain;
    njt_str_t samesite;
    njt_str_t path;
    njt_flag_t httponly;
    njt_flag_t secure;
    time_t expires;
} njt_http_sticky_cookie_conf_t;

typedef struct {
    njt_flag_t header;
    njt_msec_t timeout;
    njt_array_t *lookup;
    njt_array_t *create;
    njt_shm_zone_t *shm_zone;
    /* the upstream process header callback */
    njt_int_t (*set_header)(njt_http_request_t *r);
} njt_http_sticky_learn_conf_t;
#if(NJT_STREAM_ZONE_SYNC)
typedef struct {
    njt_queue_t zones;
    njt_rbtree_t lookup_tree;
    njt_rbtree_node_t sentinel;
}njt_http_sticky_learn_main_conf_t;
typedef struct {
    njt_queue_t queue;
    njt_http_conf_ctx_t *ctx;
    njt_rbtree_node_t tree_node;
    njt_str_t zone_name;
    njt_http_sticky_learn_conf_t  *server_cf;
}njt_http_sticky_learn_zone_info_t;

typedef struct  __attribute__((packed)) {
    u_int32_t key_len;
    u_int32_t server_len;
    u_int32_t diff;
}njt_http_sticky_learn_sync_data_t;

#endif
typedef struct {
    njt_uint_t type;
	njt_http_sticky_route_conf_t  *route_cf;
    njt_http_sticky_cookie_conf_t *cookie_cf;
    njt_http_sticky_learn_conf_t *learn_cf;
} njt_http_sticky_conf_t;

typedef struct {
    /* the round robin data must be first */
    njt_http_upstream_rr_peer_data_t  rrp;
    njt_http_sticky_conf_t            *conf;
    njt_http_request_t                *request;
    void                              *data;
    njt_str_t                          md5;
    u_char                             tries;
    njt_event_free_peer_pt             original_free_peer;
    njt_event_get_peer_pt              original_get_peer;
} njt_http_sticky_peer_data_t;

njt_int_t njt_http_sticky_md5(njt_pool_t *pool, struct sockaddr *in,
                              njt_str_t *out);

static njt_inline void _debug_echo_headers(njt_log_t *log,
        njt_list_t *headers)
{

    njt_table_elt_t *elt;
    njt_list_part_t *part;
    njt_uint_t       i;

    njt_log_error(NJT_LOG_DEBUG, log, 0, "checking headers");
    part = &headers->part;
    while (part != NULL) {
        elt = part->elts;
        for (i = 0; i < part->nelts; ++i) {
            njt_log_error(NJT_LOG_DEBUG, log, 0, "[header] %V: %V", &elt[i].key,
                          &elt[i].value);
        }
        part = part->next;
    }
}

static njt_inline void _debug_show_process_info(njt_log_t *log,
        njt_str_t *desc)
{

    if (njt_process == NJT_PROCESS_MASTER) {
        njt_log_error(NJT_LOG_DEBUG, log, 0, "[%V] current process: Master", desc);
    } else if (njt_process == NJT_PROCESS_WORKER) {
        njt_log_error(NJT_LOG_DEBUG, log, 0, "[%V] current process: Worker-%d",
                      desc, njt_worker);
    } else if (njt_process == NJT_PROCESS_SINGLE) {
        njt_log_error(NJT_LOG_DEBUG, log, 0, "[%V] current process: Single", desc);
    } else {
        njt_log_error(NJT_LOG_DEBUG, log, 0, "[%V] current process: %d", desc,
                      njt_process);
    }
}

#endif  // NJT_HTTP_STICKY_MODULE_H_
