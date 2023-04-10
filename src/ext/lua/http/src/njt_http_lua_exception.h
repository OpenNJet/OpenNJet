
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_LUA_EXCEPTION_H_INCLUDED_
#define _NJT_HTTP_LUA_EXCEPTION_H_INCLUDED_


#include "njt_http_lua_common.h"


#define NJT_LUA_EXCEPTION_TRY                                                \
    if (setjmp(njt_http_lua_exception) == 0)

#define NJT_LUA_EXCEPTION_CATCH                                              \
    else

#define NJT_LUA_EXCEPTION_THROW(x)                                           \
    longjmp(njt_http_lua_exception, (x))


extern jmp_buf njt_http_lua_exception;


int njt_http_lua_atpanic(lua_State *L);


#endif /* _NJT_HTTP_LUA_EXCEPTION_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
