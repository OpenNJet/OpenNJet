
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_LUA_HEADERS_OUT_H_INCLUDED_
#define _NJT_HTTP_LUA_HEADERS_OUT_H_INCLUDED_


#include "njt_http_lua_common.h"


#if (NJT_DARWIN)
typedef struct {
    njt_http_request_t   *r;
    const char           *key_data;
    size_t                key_len;
    int                   is_nil;
    const char           *sval;
    size_t                sval_len;
    void                 *mvals;
    size_t                mvals_len;
    int                   override;
    char                **errmsg;
} njt_http_lua_set_resp_header_params_t;
#endif


njt_int_t njt_http_lua_set_output_header(njt_http_request_t *r,
    njt_http_lua_ctx_t *ctx, njt_str_t key, njt_str_t value, unsigned override);
int njt_http_lua_get_output_header(lua_State *L, njt_http_request_t *r,
    njt_http_lua_ctx_t *ctx, njt_str_t *key);
njt_int_t njt_http_lua_init_builtin_headers_out(njt_conf_t *cf,
    njt_http_lua_main_conf_t *lmcf);


#endif /* _NJT_HTTP_LUA_HEADERS_OUT_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
