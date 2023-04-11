
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_script.h.tt2
 */


/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_STREAM_LUA_SCRIPT_H_INCLUDED_
#define _NJT_STREAM_LUA_SCRIPT_H_INCLUDED_


#include "njt_stream_lua_common.h"


typedef struct {
    njt_log_t                  *log;
    njt_pool_t                 *pool;
    njt_str_t                  *source;

    njt_array_t               **lengths;
    njt_array_t               **values;

    njt_uint_t                  variables;

    unsigned                    complete_lengths:1;
    unsigned                    complete_values:1;
} njt_stream_lua_script_compile_t;


typedef struct {
    njt_str_t                   value;
    void                       *lengths;
    void                       *values;
} njt_stream_lua_complex_value_t;


typedef struct {
    njt_log_t                       *log;
    njt_pool_t                      *pool;
    njt_str_t                       *value;

    njt_stream_lua_complex_value_t          *complex_value;
} njt_stream_lua_compile_complex_value_t;


typedef struct {
    u_char                     *ip;
    u_char                     *pos;

    njt_str_t                   buf;

    int                        *captures;
    njt_uint_t                  ncaptures;
    u_char                     *captures_data;

    unsigned                    skip:1;

    njt_log_t                  *log;
} njt_stream_lua_script_engine_t;


typedef void (*njt_stream_lua_script_code_pt) (
    njt_stream_lua_script_engine_t *e);
typedef size_t (*njt_stream_lua_script_len_code_pt)
    (njt_stream_lua_script_engine_t *e);


typedef struct {
    njt_stream_lua_script_code_pt           code;
    uintptr_t                               len;
} njt_stream_lua_script_copy_code_t;


typedef struct {
    njt_stream_lua_script_code_pt           code;
    uintptr_t                               n;
} njt_stream_lua_script_capture_code_t;


njt_int_t njt_stream_lua_compile_complex_value(
    njt_stream_lua_compile_complex_value_t *ccv);
njt_int_t njt_stream_lua_complex_value(njt_stream_lua_request_t *r,
    njt_str_t *subj, size_t offset, njt_int_t count, int *cap,
    njt_stream_lua_complex_value_t *val, luaL_Buffer *luabuf);


#endif /* _NJT_STREAM_LUA_SCRIPT_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
