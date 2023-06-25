
/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */

#ifndef NJT_HTTP_CLUSTER_LIMIT_CONN_H_
#define NJT_HTTP_CLUSTER_LIMIT_CONN_H_

#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>

#include "njt_gossip.h"
#include <msgpuck.h>

#define SIBLING_MAX 10
#define NODE_VALID_TIMEOUT 1000

typedef struct
{
    u_short conn;
    u_char data[256];
    size_t len;
} njt_http_cluster_limit_conn_item_t;

typedef struct
{
    njt_http_cluster_limit_conn_item_t             sibling_item;
    njt_msec_t                                     last_changed;
} njt_http_limit_sibling_t;

// typedef struct sync_queue_s sync_queue_t;
typedef struct sync_queue_s
{
    njt_http_limit_sibling_t    q_item;
    struct                      sync_queue_s *next;
    struct                      sync_queue_s *prev;
} sync_queue_t;


typedef struct
{
    u_char                      color;
    u_char                      len;
    u_short                     conn;
    njt_http_limit_sibling_t    sibling[SIBLING_MAX];
    sync_queue_t                *snap;
    u_char                      data[1];
} njt_http_cluster_limit_conn_node_t;

typedef struct
{
    njt_shm_zone_t              *shm_zone;
    njt_rbtree_node_t           *node;
    njt_str_t                   key;
} njt_http_cluster_limit_conn_cleanup_t;

typedef struct
{
    njt_rbtree_t                rbtree;
    njt_rbtree_node_t           sentinel;
    sync_queue_t                *clients;
} njt_http_cluster_limit_conn_shctx_t;

typedef struct
{
    njt_http_cluster_limit_conn_shctx_t *sh;
    njt_slab_pool_t                     *shpool;
    njt_http_complex_value_t            key;
    njt_str_t                           zone_name;
    njt_str_t                           zone_size;
    //by stdanley
    njt_log_t                           *log;
    njt_str_t                           *node_name;
    njt_pool_t                          *pool;
    //end

} njt_http_cluster_limit_conn_ctx_t;

typedef struct
{
    njt_shm_zone_t          *shm_zone;
    njt_uint_t              conn;
} njt_http_cluster_limit_conn_limit_t;

typedef struct
{
    njt_array_t         limits;
    njt_array_t         limit_zones;
    njt_uint_t          log_level;
    njt_uint_t          status_code;
    njt_flag_t          dry_run;

} njt_http_cluster_limit_conn_conf_t;

typedef struct
{
    njt_str_t          save;
} njt_http_cluster_limit_conn_main_conf_t;


#endif //NJT_HTTP_CLUSTER_LIMIT_CONN_H_