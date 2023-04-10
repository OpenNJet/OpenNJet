
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_LUA_OUTPUT_H_INCLUDED_
#define _NJT_HTTP_LUA_OUTPUT_H_INCLUDED_


#include "njt_http_lua_common.h"


void njt_http_lua_inject_output_api(lua_State *L);

size_t njt_http_lua_calc_strlen_in_table(lua_State *L, int index, int arg_i,
    unsigned strict);

u_char *njt_http_lua_copy_str_in_table(lua_State *L, int index, u_char *dst);

njt_int_t njt_http_lua_flush_resume_helper(njt_http_request_t *r,
    njt_http_lua_ctx_t *ctx);


/* Get the maximum possible length, not the actual length */
static njt_inline size_t
njt_http_lua_get_num_len(lua_State *L, int idx)
{
    double     num;

    num = (double) lua_tonumber(L, idx);
    if (num == (double) (int32_t) num) {
        return NJT_INT32_LEN;
    }

    return NJT_DOUBLE_LEN;
}


static njt_inline u_char *
njt_http_lua_write_num(lua_State *L, int idx, u_char *dst)
{
    double     num;
    int        n;

    num = (double) lua_tonumber(L, idx);
    /*
     * luajit format number with only 14 significant digits.
     * To be consistent with lujit, don't use (double) (long) below
     * or integer greater than 99,999,999,999,999 will different from luajit.
     */
    if (num == (double) (int32_t) num) {
        dst = njt_snprintf(dst, NJT_INT64_LEN, "%D", (int32_t) num);

    } else {
        /*
         * The maximum number of significant digits is 14 in lua.
         * Please refer to lj_strfmt.c for more details.
         */
        n = snprintf((char *) dst, NJT_DOUBLE_LEN, "%.14g", num);
        if (n < 0) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, njt_errno,
                          "snprintf(\"%f\") failed");

        } else {
            dst += n;
        }
    }

    return dst;
}


#endif /* _NJT_HTTP_LUA_OUTPUT_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
