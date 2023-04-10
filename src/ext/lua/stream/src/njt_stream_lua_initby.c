
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_initby.c.tt2
 */


/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif

#include "ddebug.h"
#include "njt_stream_lua_initby.h"
#include "njt_stream_lua_util.h"


njt_int_t
njt_stream_lua_init_by_inline(njt_log_t *log, njt_stream_lua_main_conf_t *lmcf,
    lua_State *L)
{
    int         status;

    status = luaL_loadbuffer(L, (char *) lmcf->init_src.data,
                             lmcf->init_src.len, "=init_by_lua")
             || njt_stream_lua_do_call(log, L);

    return njt_stream_lua_report(log, L, status, "init_by_lua");
}


njt_int_t
njt_stream_lua_init_by_file(njt_log_t *log, njt_stream_lua_main_conf_t *lmcf,
    lua_State *L)
{
    int         status;

    status = luaL_loadfile(L, (char *) lmcf->init_src.data)
             || njt_stream_lua_do_call(log, L);

    return njt_stream_lua_report(log, L, status, "init_by_lua_file");
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
