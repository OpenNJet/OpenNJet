
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_pcrefix.h.tt2
 */


/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_STREAM_LUA_PCREFIX_H_INCLUDED_
#define _NJT_STREAM_LUA_PCREFIX_H_INCLUDED_


#include "njt_stream_lua_common.h"


#if (NJT_PCRE)
njt_pool_t *njt_stream_lua_pcre_malloc_init(njt_pool_t *pool);
void njt_stream_lua_pcre_malloc_done(njt_pool_t *old_pool);

#if (NJT_PCRE2)
void *njt_stream_lua_pcre_malloc(size_t size, void *data);
void njt_stream_lua_pcre_free(void *ptr, void *data);
#endif
#endif


#endif /* _NJT_STREAM_LUA_PCREFIX_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
