
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_logby.h.tt2
 */


/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_STREAM_LUA_LOGBY_H_INCLUDED_
#define _NJT_STREAM_LUA_LOGBY_H_INCLUDED_


#include "njt_stream_lua_common.h"


njt_int_t njt_stream_lua_log_handler(njt_stream_session_t *r);

njt_int_t njt_stream_lua_log_handler_inline(njt_stream_lua_request_t *r);
njt_int_t njt_stream_lua_log_handler_file(njt_stream_lua_request_t *r);


#endif /* _NJT_STREAM_LUA_LOGBY_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
