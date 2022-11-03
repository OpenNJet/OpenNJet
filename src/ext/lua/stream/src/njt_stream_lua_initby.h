
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_initby.h.tt2
 */


/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef _NJT_STREAM_LUA_INITBY_H_INCLUDED_
#define _NJT_STREAM_LUA_INITBY_H_INCLUDED_


#include "njt_stream_lua_common.h"


njt_int_t njt_stream_lua_init_by_inline(njt_log_t *log,
    njt_stream_lua_main_conf_t *lmcf, lua_State *L);

njt_int_t njt_stream_lua_init_by_file(njt_log_t *log,
    njt_stream_lua_main_conf_t *lmcf, lua_State *L);


#endif /* _NJT_STREAM_LUA_INITBY_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
