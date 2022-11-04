
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) TMLake, Inc.
 */


#ifndef _NJT_HTTP_LUA_HEADERS_OUT_H_INCLUDED_
#define _NJT_HTTP_LUA_HEADERS_OUT_H_INCLUDED_


#include "njt_http_lua_common.h"


njt_int_t njt_http_lua_set_output_header(njt_http_request_t *r,
    njt_http_lua_ctx_t *ctx, njt_str_t key, njt_str_t value, unsigned override);
int njt_http_lua_get_output_header(lua_State *L, njt_http_request_t *r,
    njt_http_lua_ctx_t *ctx, njt_str_t *key);


#endif /* _NJT_HTTP_LUA_HEADERS_OUT_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
