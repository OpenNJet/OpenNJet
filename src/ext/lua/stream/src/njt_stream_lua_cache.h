
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_cache.h.tt2
 */


/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_STREAM_LUA_CACHE_H_INCLUDED_
#define _NJT_STREAM_LUA_CACHE_H_INCLUDED_


#include "njt_stream_lua_common.h"


njt_int_t njt_stream_lua_cache_loadbuffer(njt_log_t *log, lua_State *L,
    const u_char *src, size_t src_len, const u_char *cache_key,
    const char *name);
njt_int_t njt_stream_lua_cache_loadfile(njt_log_t *log, lua_State *L,
    const u_char *script, const u_char *cache_key);


#endif /* _NJT_STREAM_LUA_CACHE_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
