
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_LUA_LEX_H_INCLUDED_
#define _NJT_HTTP_LUA_LEX_H_INCLUDED_


#include "njt_http_lua_common.h"


int njt_http_lua_lex(const u_char *const s, size_t len, int *const ovec);


#endif
