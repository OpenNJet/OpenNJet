
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_log.h.tt2
 */


/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_STREAM_LUA_LOG_H_INCLUDED_
#define _NJT_STREAM_LUA_LOG_H_INCLUDED_


#include "njt_stream_lua_common.h"


void njt_stream_lua_inject_log_api(lua_State *L);

#ifdef HAVE_INTERCEPT_ERROR_LOG_PATCH
njt_int_t njt_stream_lua_capture_log_handler(njt_log_t *log,
    njt_uint_t level, u_char *buf, size_t n);
#endif


#endif /* _NJT_STREAM_LUA_LOG_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
