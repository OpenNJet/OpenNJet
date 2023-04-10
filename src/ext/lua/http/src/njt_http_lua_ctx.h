
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_LUA_CTX_H_INCLUDED_
#define _NJT_HTTP_LUA_CTX_H_INCLUDED_


#include "njt_http_lua_common.h"


int njt_http_lua_njt_set_ctx_helper(lua_State *L, njt_http_request_t *r,
    njt_http_lua_ctx_t *ctx, int index);


#endif /* _NJT_HTTP_LUA_CTX_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
