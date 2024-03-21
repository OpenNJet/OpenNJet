
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_exception.c.tt2
 */


/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_stream_lua_exception.h"
#include "njt_stream_lua_util.h"


/*  longjmp mark for restoring njet execution after Lua VM crashing */
jmp_buf njt_stream_lua_exception;

/**
 * Override default Lua panic handler, output VM crash reason to njet error
 * log, and restore execution to the nearest jmp-mark.
 *
 * @param L Lua state pointer
 * @retval Long jump to the nearest jmp-mark, never returns.
 * @note njet request pointer should be stored in Lua thread's globals table
 * in order to make logging working.
 * */
int
njt_stream_lua_atpanic(lua_State *L)
{
#ifdef NJT_LUA_ABORT_AT_PANIC
    abort();
#else
    u_char                  *s = NULL;
    size_t                   len = 0;

    if (lua_type(L, -1) == LUA_TSTRING) {
        s = (u_char *) lua_tolstring(L, -1, &len);
    }

    if (s == NULL) {
        s = (u_char *) "unknown reason";
        len = sizeof("unknown reason") - 1;
    }

    njt_log_stderr(0, "lua atpanic: Lua VM crashed, reason: %*s", len, s);
    njt_quit = 1;

    /*  restore njet execution */
    NJT_LUA_EXCEPTION_THROW(1);

    /* impossible to reach here */
#endif
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
