
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) TMLake, Inc.
 */


#ifndef _NJT_HTTP_LUA_PCREFIX_H_INCLUDED_
#define _NJT_HTTP_LUA_PCREFIX_H_INCLUDED_


#include "njt_http_lua_common.h"


#if (NJT_PCRE)
njt_pool_t *njt_http_lua_pcre_malloc_init(njt_pool_t *pool);
void njt_http_lua_pcre_malloc_done(njt_pool_t *old_pool);
#endif


#endif /* _NJT_HTTP_LUA_PCREFIX_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
