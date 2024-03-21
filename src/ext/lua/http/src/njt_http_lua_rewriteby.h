
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.yy
 */


#ifndef _NJT_HTTP_LUA_REWRITEBY_H_INCLUDED_
#define _NJT_HTTP_LUA_REWRITEBY_H_INCLUDED_


#include "njt_http_lua_common.h"


njt_int_t njt_http_lua_rewrite_handler(njt_http_request_t *r);
njt_int_t njt_http_lua_rewrite_handler_inline(njt_http_request_t *r);
njt_int_t njt_http_lua_rewrite_handler_file(njt_http_request_t *r);


#endif /* _NJT_HTTP_LUA_REWRITEBY_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
