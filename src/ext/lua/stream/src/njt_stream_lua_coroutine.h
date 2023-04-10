
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_coroutine.h.tt2
 */


/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_STREAM_LUA_COROUTINE_H_INCLUDED_
#define _NJT_STREAM_LUA_COROUTINE_H_INCLUDED_


#include "njt_stream_lua_common.h"


void njt_stream_lua_inject_coroutine_api(njt_log_t *log, lua_State *L);

int njt_stream_lua_coroutine_create_helper(lua_State *L,
    njt_stream_lua_request_t *r, njt_stream_lua_ctx_t *ctx,
    njt_stream_lua_co_ctx_t **pcoctx);


#endif /* _NJT_STREAM_LUA_COROUTINE_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
