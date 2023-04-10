
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_clfactory.h.tt2
 */


/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_STREAM_LUA_CLFACTORY_H_INCLUDED_
#define _NJT_STREAM_LUA_CLFACTORY_H_INCLUDED_


#include "njt_stream_lua_common.h"


njt_int_t njt_stream_lua_clfactory_loadfile(lua_State *L, const char *filename);
njt_int_t njt_stream_lua_clfactory_loadbuffer(lua_State *L, const char *buff,
    size_t size, const char *name);


#endif /* _NJT_STREAM_LUA_CLFACTORY_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
