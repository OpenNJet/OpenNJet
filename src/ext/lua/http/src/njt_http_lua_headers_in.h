
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) xYichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_LUA_HEADERS_IN_H_INCLUDED_
#define _NJT_HTTP_LUA_HEADERS_IN_H_INCLUDED_


#include <njet.h>
#include "njt_http_lua_common.h"


njt_int_t njt_http_lua_set_input_header(njt_http_request_t *r, njt_str_t key,
    njt_str_t value, unsigned override);


#endif /* _NJT_HTTP_LUA_HEADERS_IN_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
