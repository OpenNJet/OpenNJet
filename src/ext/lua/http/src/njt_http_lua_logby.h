
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_LUA_LOGBY_H_INCLUDED_
#define _NJT_HTTP_LUA_LOGBY_H_INCLUDED_


#include "njt_http_lua_common.h"


njt_int_t njt_http_lua_log_handler(njt_http_request_t *r);
njt_int_t njt_http_lua_log_handler_inline(njt_http_request_t *r);
njt_int_t njt_http_lua_log_handler_file(njt_http_request_t *r);


#endif /* _NJT_HTTP_LUA_LOGBY_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
