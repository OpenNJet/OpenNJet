
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_LUA_NDK_H_INCLUDED_
#define _NJT_HTTP_LUA_NDK_H_INCLUDED_


#include "njt_http_lua_common.h"


#if defined(NDK) && NDK
void njt_http_lua_inject_ndk_api(lua_State *L);
#endif


#endif /* _NJT_HTTP_LUA_NDK_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
