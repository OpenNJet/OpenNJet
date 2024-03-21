
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) cuiweixie
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.yy
 * I hereby assign copyright in this code to the lua-njet-module project,
 * to be licensed under the same terms as the rest of the code.
 */


#ifndef _NJT_HTTP_LUA_SEMAPHORE_H_INCLUDED_
#define _NJT_HTTP_LUA_SEMAPHORE_H_INCLUDED_


#include "njt_http_lua_common.h"


typedef struct njt_http_lua_sema_mm_block_s {
    njt_uint_t                       used;
    njt_http_lua_sema_mm_t          *mm;
    njt_uint_t                       epoch;
} njt_http_lua_sema_mm_block_t;


struct njt_http_lua_sema_mm_s {
    njt_queue_t                  free_queue;
    njt_uint_t                   total;
    njt_uint_t                   used;
    njt_uint_t                   num_per_block;
    njt_uint_t                   cur_epoch;
    njt_http_lua_main_conf_t    *lmcf;
};


typedef struct njt_http_lua_sema_s {
    njt_queue_t                          wait_queue;
    njt_queue_t                          chain;
    njt_event_t                          sem_event;
    njt_http_lua_sema_mm_block_t        *block;
    int                                  resource_count;
    unsigned                             wait_count;
} njt_http_lua_sema_t;


void njt_http_lua_sema_mm_cleanup(void *data);
njt_int_t njt_http_lua_sema_mm_init(njt_conf_t *cf,
    njt_http_lua_main_conf_t *lmcf);


#endif /* _NJT_HTTP_LUA_SEMAPHORE_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
