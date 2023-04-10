
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_LUA_INITWORKERBY_H_INCLUDED_
#define _NJT_HTTP_LUA_INITWORKERBY_H_INCLUDED_


#include "njt_http_lua_common.h"


njt_int_t njt_http_lua_init_worker_by_inline(njt_log_t *log,
    njt_http_lua_main_conf_t *lmcf, lua_State *L);

njt_int_t njt_http_lua_init_worker_by_file(njt_log_t *log,
    njt_http_lua_main_conf_t *lmcf, lua_State *L);

njt_int_t njt_http_lua_init_worker(njt_cycle_t *cycle);


#endif /* _NJT_HTTP_LUA_INITWORKERBY_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
