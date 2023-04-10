
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_LUA_CACHE_H_INCLUDED_
#define _NJT_HTTP_LUA_CACHE_H_INCLUDED_


#include "njt_http_lua_common.h"


njt_int_t njt_http_lua_cache_loadbuffer(njt_log_t *log, lua_State *L,
    const u_char *src, size_t src_len, int *cache_ref, const u_char *cache_key,
    const char *name);
njt_int_t njt_http_lua_cache_loadfile(njt_log_t *log, lua_State *L,
    const u_char *script, int *cache_ref, const u_char *cache_key);
u_char *njt_http_lua_gen_chunk_cache_key(njt_conf_t *cf, const char *tag,
    const u_char *src, size_t src_len);
u_char *njt_http_lua_gen_file_cache_key(njt_conf_t *cf, const u_char *src,
    size_t src_len);


#endif /* _NJT_HTTP_LUA_CACHE_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
