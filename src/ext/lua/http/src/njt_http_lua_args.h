
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_LUA_ARGS_H_INCLUDED_
#define _NJT_HTTP_LUA_ARGS_H_INCLUDED_


#include "njt_http_lua_common.h"


void njt_http_lua_inject_req_args_api(lua_State *L);
int njt_http_lua_parse_args(lua_State *L, u_char *buf, u_char *last, int max);


#endif /* _NJT_HTTP_LUA_ARGS_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
