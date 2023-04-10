
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_LUA_CONTENT_BY_H_INCLUDED_
#define _NJT_HTTP_LUA_CONTENT_BY_H_INCLUDED_


#include "njt_http_lua_common.h"


njt_int_t njt_http_lua_content_by_chunk(lua_State *L, njt_http_request_t *r);
void njt_http_lua_content_wev_handler(njt_http_request_t *r);
njt_int_t njt_http_lua_content_handler_file(njt_http_request_t *r);
njt_int_t njt_http_lua_content_handler_inline(njt_http_request_t *r);
njt_int_t njt_http_lua_content_handler(njt_http_request_t *r);
njt_int_t njt_http_lua_content_run_posted_threads(lua_State *L,
    njt_http_request_t *r, njt_http_lua_ctx_t *ctx, int n);


#endif /* _NJT_HTTP_LUA_CONTENT_BY_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
