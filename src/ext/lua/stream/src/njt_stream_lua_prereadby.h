
/*
 * Copyright (C) OpenResty Inc.
 */


#ifndef _NJT_STREAM_LUA_PREREAD_H_INCLUDED_
#define _NJT_STREAM_LUA_PREREAD_H_INCLUDED_


#include "njt_stream_lua_common.h"


njt_int_t njt_stream_lua_preread_handler(njt_stream_session_t *s);
njt_int_t njt_stream_lua_preread_handler_inline(njt_stream_lua_request_t *r);
njt_int_t njt_stream_lua_preread_handler_file(njt_stream_lua_request_t *r);


#endif /* _NJT_STREAM_LUA_PREREAD_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
