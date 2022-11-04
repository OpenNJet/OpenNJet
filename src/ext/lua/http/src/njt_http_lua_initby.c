
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) TMLake, Inc.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif

#include "ddebug.h"
#include "njt_http_lua_initby.h"
#include "njt_http_lua_util.h"


njt_int_t
njt_http_lua_init_by_inline(njt_log_t *log, njt_http_lua_main_conf_t *lmcf,
    lua_State *L)
{
    int         status;

    status = luaL_loadbuffer(L, (char *) lmcf->init_src.data,
                             lmcf->init_src.len, "=init_by_lua")
             || njt_http_lua_do_call(log, L);

    return njt_http_lua_report(log, L, status, "init_by_lua");
}


njt_int_t
njt_http_lua_init_by_file(njt_log_t *log, njt_http_lua_main_conf_t *lmcf,
    lua_State *L)
{
    int         status;

    status = luaL_loadfile(L, (char *) lmcf->init_src.data)
             || njt_http_lua_do_call(log, L);

    return njt_http_lua_report(log, L, status, "init_by_lua_file");
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
