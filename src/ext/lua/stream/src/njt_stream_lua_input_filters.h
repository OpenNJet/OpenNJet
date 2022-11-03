
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_input_filters.h.tt2
 */


/*
 * Copyright (C) by OpenResty Inc.
 */


#ifndef _NJT_STREAM_LUA_INPUT_FILTERS_H_INCLUDED_
#define _NJT_STREAM_LUA_INPUT_FILTERS_H_INCLUDED_


#include "njt_stream_lua_common.h"


njt_int_t njt_stream_lua_read_bytes(njt_buf_t *src, njt_chain_t *buf_in,
    size_t *rest, ssize_t bytes, njt_log_t *log);

njt_int_t njt_stream_lua_read_all(njt_buf_t *src, njt_chain_t *buf_in,
    ssize_t bytes, njt_log_t *log);

njt_int_t njt_stream_lua_read_any(njt_buf_t *src, njt_chain_t *buf_in,
    size_t *max, ssize_t bytes, njt_log_t *log);

njt_int_t njt_stream_lua_read_line(njt_buf_t *src, njt_chain_t *buf_in,
    ssize_t bytes, njt_log_t *log);


#endif /* _NJT_STREAM_LUA_INPUT_FILTERS_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
