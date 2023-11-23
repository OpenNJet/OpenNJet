
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_config.c.tt2
 */


/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_stream_lua_config.h"
#include "api/njt_stream_lua_api.h"


static int njt_stream_lua_config_prefix(lua_State *L);
static int njt_stream_lua_config_configure(lua_State *L);


void
njt_stream_lua_inject_config_api(lua_State *L)
{
    /* njt.config */

    lua_createtable(L, 0, 6 /* nrec */);    /* .config */

#if (NJT_DEBUG)
    lua_pushboolean(L, 1);
#else
    lua_pushboolean(L, 0);
#endif
    lua_setfield(L, -2, "debug");

    lua_pushcfunction(L, njt_stream_lua_config_prefix);
    lua_setfield(L, -2, "prefix");

    lua_pushinteger(L, njet_version);
    lua_setfield(L, -2, "njet_version");

    lua_pushinteger(L, njt_stream_lua_version);
    lua_setfield(L, -2, "njt_lua_version");

    lua_pushcfunction(L, njt_stream_lua_config_configure);
    lua_setfield(L, -2, "njet_configure");

    lua_pushliteral(L, "stream");
    lua_setfield(L, -2, "subsystem");

    lua_setfield(L, -2, "config");
}


static int
njt_stream_lua_config_prefix(lua_State *L)
{
    lua_pushlstring(L, (char *) njt_cycle->prefix.data,
                    njt_cycle->prefix.len);
    return 1;
}


static int
njt_stream_lua_config_configure(lua_State *L)
{
    lua_pushliteral(L, NJT_CONFIGURE);
    return 1;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
