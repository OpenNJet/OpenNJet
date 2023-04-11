/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef NJT_STREAM_UPSTREAM_HC_MODULE_H
#define NJT_STREAM_UPSTREAM_HC_MODULE_H

#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>

#define  NJT_STREAM_MATCH_CONTAIN       0
#define  NJT_STREAM_MATCH_NOT_CONTAIN   1
#define  NJT_STREAM_MATCH_EQUAL         2
#define  NJT_STREAM_MATCH_NOT_EQUAL     4
#define  NJT_STREAM_MATCH_REG_MATCH     8
#define  NJT_STREAM_MATCH_NOT_REG_MATCH 16

extern njt_module_t njt_stream_match_module;

struct njt_stream_match_srv_conf_s{
    njt_rbtree_node_t tree_node;
    njt_str_t match_name;
    njt_stream_conf_ctx_t *ctx;
    njt_str_t send;
    njt_str_t expect;
#if (NJT_PCRE)
    njt_regex_t  *regex;
#endif
    njt_uint_t     operation;
    unsigned regular:1;
};

typedef struct njt_stream_match_srv_conf_s njt_stream_match_srv_conf_t;

typedef struct njt_stream_match_srv_conf_s njt_stream_match_t;

struct njt_stream_match_main_conf_s{
    njt_rbtree_t match_tree;
    njt_rbtree_node_t        sentinel;
};

typedef struct njt_stream_match_main_conf_s njt_stream_match_main_conf_t;

//add a backend server to health checker system.
njt_uint_t njt_stream_upstream_check_add_peer(njt_conf_t *cf,
                                              njt_stream_upstream_srv_conf_t *us, njt_addr_t *peer);

//get status of one backend .
njt_uint_t njt_stream_upstream_check_peer_down(njt_uint_t index);

//inc peer's busyness cnt
void njt_stream_upstream_check_get_peer(njt_uint_t index);

//dec peer's busyness cnt
void njt_stream_upstream_check_free_peer(njt_uint_t index);

njt_int_t njt_stream_match_regular_str(njt_regex_t *regex,njt_uint_t operation,njt_str_t str);

njt_stream_match_srv_conf_t* njt_stream_match_lookup_name(njt_stream_match_main_conf_t *mmcf,njt_str_t name);

njt_stream_match_t* njt_stream_match_create(njt_conf_t *cf, njt_str_t *name);


#endif //NJT_STREAM_UPSTREAM_HC_MODULE_H
