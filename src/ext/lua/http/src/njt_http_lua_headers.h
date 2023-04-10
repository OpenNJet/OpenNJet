
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_LUA_HEADERS_H_INCLUDED_
#define _NJT_HTTP_LUA_HEADERS_H_INCLUDED_


#include "njt_http_lua_common.h"


void njt_http_lua_inject_resp_header_api(lua_State *L);
void njt_http_lua_inject_req_header_api(lua_State *L);
void njt_http_lua_create_headers_metatable(njt_log_t *log, lua_State *L);
#if (njet_version >= 1011011)
void njt_http_lua_njt_raw_header_cleanup(void *data);
#endif


#endif /* _NJT_HTTP_LUA_HEADERS_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
