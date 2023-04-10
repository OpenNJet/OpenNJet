
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_control.c.tt2
 */


/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_stream_lua_control.h"
#include "njt_stream_lua_util.h"
#include "njt_stream_lua_coroutine.h"




static int njt_stream_lua_on_abort(lua_State *L);


void
njt_stream_lua_inject_control_api(njt_log_t *log, lua_State *L)
{

    /* njt.on_abort */

    lua_pushcfunction(L, njt_stream_lua_on_abort);
    lua_setfield(L, -2, "on_abort");
}




static int
njt_stream_lua_on_abort(lua_State *L)
{
    njt_stream_lua_request_t             *r;
    njt_stream_lua_ctx_t                 *ctx;
    njt_stream_lua_co_ctx_t              *coctx = NULL;
    njt_stream_lua_loc_conf_t            *llcf;

    r = njt_stream_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    njt_stream_lua_check_fake_request2(L, r, ctx);

    if (ctx->on_abort_co_ctx) {
        lua_pushnil(L);
        lua_pushliteral(L, "duplicate call");
        return 2;
    }

    llcf = njt_stream_lua_get_module_loc_conf(r, njt_stream_lua_module);
    if (!llcf->check_client_abort) {
        lua_pushnil(L);
        lua_pushliteral(L, "lua_check_client_abort is off");
        return 2;
    }

    njt_stream_lua_coroutine_create_helper(L, r, ctx, &coctx);

    lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(
                          coroutines_key));
    lua_rawget(L, LUA_REGISTRYINDEX);
    lua_pushvalue(L, -2);

    dd("on_wait thread 1: %p", lua_tothread(L, -1));

    coctx->co_ref = luaL_ref(L, -2);
    lua_pop(L, 1);

    coctx->is_uthread = 1;
    ctx->on_abort_co_ctx = coctx;

    dd("on_wait thread 2: %p", coctx->co);

    coctx->co_status = NJT_STREAM_LUA_CO_SUSPENDED;
    coctx->parent_co_ctx = ctx->cur_co_ctx;

    lua_pushinteger(L, 1);
    return 1;
}


int
njt_stream_lua_ffi_exit(njt_stream_lua_request_t *r, int status, u_char *err,
    size_t *errlen)
{
    njt_stream_lua_ctx_t             *ctx;

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        *errlen = njt_snprintf(err, *errlen, "no request ctx found") - err;
        return NJT_ERROR;
    }


    if (njt_stream_lua_ffi_check_context(ctx, NJT_STREAM_LUA_CONTEXT_CONTENT
        | NJT_STREAM_LUA_CONTEXT_TIMER
        | NJT_STREAM_LUA_CONTEXT_BALANCER
        | NJT_STREAM_LUA_CONTEXT_SSL_CLIENT_HELLO
        | NJT_STREAM_LUA_CONTEXT_SSL_CERT
        | NJT_STREAM_LUA_CONTEXT_PREREAD,
        err, errlen) != NJT_OK)
    {
        return NJT_ERROR;
    }

    if (ctx->context & (NJT_STREAM_LUA_CONTEXT_SSL_CERT
                        | NJT_STREAM_LUA_CONTEXT_SSL_CLIENT_HELLO ))
    {

#if (NJT_STREAM_SSL)

        ctx->exit_code = status;
        ctx->exited = 1;

        njt_log_debug1(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                       "lua exit with code %d", status);


        return NJT_OK;

#else

        return NJT_ERROR;

#endif
    }


    ctx->exit_code = status;
    ctx->exited = 1;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "lua exit with code %i", ctx->exit_code);

    if (ctx->context & NJT_STREAM_LUA_CONTEXT_BALANCER) {
        return NJT_DONE;
    }

    return NJT_OK;
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
