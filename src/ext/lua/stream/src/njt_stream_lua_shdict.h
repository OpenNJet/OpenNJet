
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_shdict.h.tt2
 */


/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef _NJT_STREAM_LUA_SHDICT_H_INCLUDED_
#define _NJT_STREAM_LUA_SHDICT_H_INCLUDED_


#include "njt_stream_lua_common.h"


typedef struct {
    u_char                       color;
    uint8_t                      value_type;
    u_short                      key_len;
    uint32_t                     value_len;
    uint64_t                     expires;
    njt_queue_t                  queue;
    uint32_t                     user_flags;
    u_char                       data[1];
} njt_stream_lua_shdict_node_t;


typedef struct {
    njt_queue_t                  queue;
    uint32_t                     value_len;
    uint8_t                      value_type;
    u_char                       data[1];
} njt_stream_lua_shdict_list_node_t;


typedef struct {
    njt_rbtree_t                  rbtree;
    njt_rbtree_node_t             sentinel;
    njt_queue_t                   lru_queue;
} njt_stream_lua_shdict_shctx_t;


typedef struct {
    njt_stream_lua_shdict_shctx_t       *sh;
    njt_slab_pool_t                     *shpool;
    njt_str_t                            name;
    njt_stream_lua_main_conf_t          *main_conf;
    njt_log_t                           *log;
} njt_stream_lua_shdict_ctx_t;


typedef struct {
    njt_log_t                           *log;
    njt_stream_lua_main_conf_t          *lmcf;
    njt_cycle_t                         *cycle;
    njt_shm_zone_t                       zone;
} njt_stream_lua_shm_zone_ctx_t;


njt_int_t njt_stream_lua_shdict_init_zone(njt_shm_zone_t *shm_zone, void *data);
void njt_stream_lua_shdict_rbtree_insert_value(njt_rbtree_node_t *temp,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel);
void njt_stream_lua_inject_shdict_api(njt_stream_lua_main_conf_t *lmcf,
    lua_State *L);


#endif /* _NJT_STREAM_LUA_SHDICT_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
