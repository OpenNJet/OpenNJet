
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_LUA_COROUTINE_H_INCLUDED_
#define _NJT_HTTP_LUA_COROUTINE_H_INCLUDED_


#include "njt_http_lua_common.h"


void njt_http_lua_inject_coroutine_api(njt_log_t *log, lua_State *L);

int njt_http_lua_coroutine_create_helper(lua_State *L, njt_http_request_t *r,
    njt_http_lua_ctx_t *ctx, njt_http_lua_co_ctx_t **pcoctx, int *co_ref);


#endif /* _NJT_HTTP_LUA_COROUTINE_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
