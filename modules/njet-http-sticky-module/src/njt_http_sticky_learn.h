/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */
#ifndef NJT_HTTP_STICKY_LEARN_H_
#define NJT_HTTP_STICKY_LEARN_H_

#include "njt_http_sticky_module.h"
#if(NJT_STREAM_ZONE_SYNC)
#include <njt_stream_zone_sync.h>
#define NJT_HTTP_STICKY_MODULE_ID 0x53544b59 // "STKY"
#define NJT_HTTP_STICKY_MODULE_VER 1
#endif

extern njt_module_t njt_http_sticky_module;

/* rb tree node */
typedef struct njt_http_sticky_learn_node_t {
    njt_rbtree_node_t rbnode;
    /* custom per-node data */
    njt_msec_t time;      /* the last access time */
    njt_str_t server;     /* the server addr */
    njt_str_t value;      /* the value for looking up */
    njt_queue_t lru_node; /* the node in LRU queue */
} njt_http_sticky_learn_node_t;

/* rb tree */
typedef struct {
    njt_rbtree_t *tree;
    njt_rbtree_node_t *sentinel;
    /* custom per-tree data */
    njt_event_t *event;      /* event to remove the timed-out sessions */
    njt_msec_t timeout;      /* timeout after clear a node */
    njt_flag_t has_timer;    /* whether a timer has been set */
    njt_uint_t event_worker; /* the worker who is managing the tree */
    njt_queue_t queue;       /* LRU Cache Queue */
#if(NJT_STREAM_ZONE_SYNC)
    njt_stream_zone_status_info_t status_info;
#endif
} njt_http_sticky_learn_tree_t;

char *njt_http_sticky_learn_setup(njt_conf_t *cf, njt_http_sticky_conf_t *scf,
                                  njt_str_t *value);
njt_int_t njt_http_sticky_learn_get_peer(njt_peer_connection_t *pc,
        njt_http_sticky_peer_data_t *sp);
void njt_http_sticky_learn_free_peer(njt_peer_connection_t *pc,
                                     njt_http_sticky_peer_data_t *sp,
                                     njt_uint_t state);
void njt_http_sticky_learn_rbtree_insert_value(njt_rbtree_node_t *temp,
        njt_rbtree_node_t *node,
        njt_rbtree_node_t *sentinel);
njt_http_sticky_learn_node_t *njt_http_sticky_learn_rbtree_lookup(
    njt_rbtree_t *rbtree, njt_str_t *val, uint32_t hash);
njt_int_t njt_http_sticky_learn_process_header(njt_http_request_t *r);

static njt_inline void njt_http_sticky_learn_find_variable_in_array(
    njt_http_request_t *r, njt_array_t *arr, njt_str_t *out)
{
    /* This function accepts an array of the ngx variable-indices, it finds the
     * first match of the exist one. */
    njt_uint_t i;
    njt_int_t *create_indices;
    njt_http_variable_value_t *v;

    v = NULL;
    create_indices = arr->elts;

    for (i = 0; i < arr->nelts; ++i) {
        /* the first non-empty variable is used */
        v = njt_http_get_indexed_variable(r, create_indices[i]);
        if (v == NULL || v->not_found) {
            continue;
        }
        out->data = v->data;
        out->len = v->len;
        break;
    }
}

static njt_inline void njt_http_sticky_learn_cleanup_on_exit(
    njt_http_sticky_learn_tree_t *sticky_tree, njt_log_t *log)
{
    /* when the process is quiting or terminating, we need to gracefully shuting
     * the management worker down, so that another process will be nominated as
     * a manager in next cycle */
    if ((njt_quit || njt_terminate) && sticky_tree->event_worker == njt_worker) {
        njt_log_error(NJT_LOG_DEBUG, log, 0, "[event]: worker %d is shutting down.",
                      njt_worker);
        sticky_tree->has_timer = 0;
        sticky_tree->event_worker = 0;
        sticky_tree->event = NULL;
        njt_del_timer(sticky_tree->event);
        njt_pfree(njt_cycle->pool, sticky_tree->event);
        njt_log_error(NJT_LOG_DEBUG, log, 0, "[event]: event has been cleaned.");
    }
}

#endif  // NJT_HTTP_STICKY_LEARN_H_
