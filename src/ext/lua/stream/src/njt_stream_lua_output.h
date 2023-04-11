
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_output.h.tt2
 */


/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_STREAM_LUA_OUTPUT_H_INCLUDED_
#define _NJT_STREAM_LUA_OUTPUT_H_INCLUDED_


#include "njt_stream_lua_common.h"


void njt_stream_lua_inject_output_api(lua_State *L);

size_t njt_stream_lua_calc_strlen_in_table(lua_State *L, int index, int arg_i,
    unsigned strict);

u_char *njt_stream_lua_copy_str_in_table(lua_State *L, int index, u_char *dst);

njt_int_t njt_stream_lua_flush_resume_helper(njt_stream_lua_request_t *r,
    njt_stream_lua_ctx_t *ctx);


#endif /* _NJT_STREAM_LUA_OUTPUT_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
