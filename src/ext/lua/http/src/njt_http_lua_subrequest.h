
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.yy
 */


#ifndef _NJT_HTTP_LUA_SUBREQUEST_H_INCLUDED_
#define _NJT_HTTP_LUA_SUBREQUEST_H_INCLUDED_


#include "njt_http_lua_common.h"


void njt_http_lua_inject_subrequest_api(lua_State *L);
njt_int_t njt_http_lua_post_subrequest(njt_http_request_t *r, void *data,
    njt_int_t rc);


extern njt_str_t  njt_http_lua_get_method;
extern njt_str_t  njt_http_lua_put_method;
extern njt_str_t  njt_http_lua_post_method;
extern njt_str_t  njt_http_lua_head_method;
extern njt_str_t  njt_http_lua_delete_method;
extern njt_str_t  njt_http_lua_options_method;
extern njt_str_t  njt_http_lua_copy_method;
extern njt_str_t  njt_http_lua_move_method;
extern njt_str_t  njt_http_lua_lock_method;
extern njt_str_t  njt_http_lua_mkcol_method;
extern njt_str_t  njt_http_lua_propfind_method;
extern njt_str_t  njt_http_lua_proppatch_method;
extern njt_str_t  njt_http_lua_unlock_method;
extern njt_str_t  njt_http_lua_patch_method;
extern njt_str_t  njt_http_lua_trace_method;


typedef struct njt_http_lua_post_subrequest_data_s {
    njt_http_lua_ctx_t          *ctx;
    njt_http_lua_co_ctx_t       *pr_co_ctx;

} njt_http_lua_post_subrequest_data_t;


#endif /* _NJT_HTTP_LUA_SUBREQUEST_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
