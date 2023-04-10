
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_consts.c.tt2
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


#include "njt_stream_lua_consts.h"


void
njt_stream_lua_inject_core_consts(lua_State *L)
{
    /* {{{ core constants */
    lua_pushinteger(L, NJT_OK);
    lua_setfield(L, -2, "OK");

    lua_pushinteger(L, NJT_AGAIN);
    lua_setfield(L, -2, "AGAIN");

    lua_pushinteger(L, NJT_DONE);
    lua_setfield(L, -2, "DONE");

    lua_pushinteger(L, NJT_DECLINED);
    lua_setfield(L, -2, "DECLINED");

    lua_pushinteger(L, NJT_ERROR);
    lua_setfield(L, -2, "ERROR");

    lua_pushlightuserdata(L, NULL);
    lua_setfield(L, -2, "null");
    /* }}} */
}



/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
