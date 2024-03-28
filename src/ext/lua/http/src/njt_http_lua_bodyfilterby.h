
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_LUA_BODYFILTERBY_H_INCLUDED_
#define _NJT_HTTP_LUA_BODYFILTERBY_H_INCLUDED_


#include "njt_http_lua_common.h"


extern njt_http_output_body_filter_pt njt_http_lua_next_filter_body_filter;


njt_int_t njt_http_lua_body_filter_init(void);
njt_int_t njt_http_lua_body_filter_by_chunk(lua_State *L,
    njt_http_request_t *r, njt_chain_t *in);
njt_int_t njt_http_lua_body_filter_inline(njt_http_request_t *r,
    njt_chain_t *in);
njt_int_t njt_http_lua_body_filter_file(njt_http_request_t *r,
    njt_chain_t *in);
int njt_http_lua_body_filter_param_set(lua_State *L, njt_http_request_t *r,
    njt_http_lua_ctx_t *ctx);


#endif /* _NJT_HTTP_LUA_BODYFILTERBY_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
