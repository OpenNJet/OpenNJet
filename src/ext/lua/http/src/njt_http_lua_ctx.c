
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_http_lua_util.h"
#include "njt_http_lua_ssl.h"
#include "njt_http_lua_ctx.h"


typedef struct {
    int              ref;
    lua_State       *vm;
} njt_http_lua_njt_ctx_cleanup_data_t;


static njt_int_t njt_http_lua_njt_ctx_add_cleanup(njt_http_request_t *r,
    njt_pool_t *pool, int ref);
static void njt_http_lua_njt_ctx_cleanup(void *data);


int
njt_http_lua_njt_set_ctx_helper(lua_State *L, njt_http_request_t *r,
    njt_http_lua_ctx_t *ctx, int index)
{
    njt_pool_t              *pool;

    if (index < 0) {
        index = lua_gettop(L) + index + 1;
    }

    if (ctx->ctx_ref == LUA_NOREF) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "lua create njt.ctx table for the current request");

        lua_pushliteral(L, njt_http_lua_ctx_tables_key);
        lua_rawget(L, LUA_REGISTRYINDEX);
        lua_pushvalue(L, index);
        ctx->ctx_ref = luaL_ref(L, -2);
        lua_pop(L, 1);

        pool = r->pool;
        if (njt_http_lua_njt_ctx_add_cleanup(r, pool, ctx->ctx_ref) != NJT_OK) {
            return luaL_error(L, "no memory");
        }

        return 0;
    }

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua fetching existing njt.ctx table for the current "
                   "request");

    lua_pushliteral(L, njt_http_lua_ctx_tables_key);
    lua_rawget(L, LUA_REGISTRYINDEX);
    luaL_unref(L, -1, ctx->ctx_ref);
    lua_pushvalue(L, index);
    ctx->ctx_ref = luaL_ref(L, -2);
    lua_pop(L, 1);

    return 0;
}


int
njt_http_lua_ffi_get_ctx_ref(njt_http_request_t *r, int *in_ssl_phase,
    int *ssl_ctx_ref)
{
    njt_http_lua_ctx_t              *ctx;
#if (NJT_HTTP_SSL)
    njt_http_lua_ssl_ctx_t          *ssl_ctx;
#endif

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
    if (ctx == NULL) {
        return NJT_HTTP_LUA_FFI_NO_REQ_CTX;
    }

    if (ctx->ctx_ref >= 0 || in_ssl_phase == NULL) {
        return ctx->ctx_ref;
    }

    *in_ssl_phase = ctx->context & (NJT_HTTP_LUA_CONTEXT_SSL_CERT
                                    | NJT_HTTP_LUA_CONTEXT_SSL_CLIENT_HELLO
                                    | NJT_HTTP_LUA_CONTEXT_SSL_SESS_FETCH
                                    | NJT_HTTP_LUA_CONTEXT_SSL_SESS_STORE);
    *ssl_ctx_ref = LUA_NOREF;

#if (NJT_HTTP_SSL)
    if (r->connection->ssl != NULL) {
        ssl_ctx = njt_http_lua_ssl_get_ctx(r->connection->ssl->connection);

        if (ssl_ctx != NULL) {
            *ssl_ctx_ref = ssl_ctx->ctx_ref;
        }
    }
#endif

    return LUA_NOREF;
}


int
njt_http_lua_ffi_set_ctx_ref(njt_http_request_t *r, int ref)
{
    njt_pool_t                      *pool;
    njt_http_lua_ctx_t              *ctx;
#if (NJT_HTTP_SSL)
    njt_connection_t                *c;
    njt_http_lua_ssl_ctx_t          *ssl_ctx;
#endif

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
    if (ctx == NULL) {
        return NJT_HTTP_LUA_FFI_NO_REQ_CTX;
    }

#if (NJT_HTTP_SSL)
    if (ctx->context & (NJT_HTTP_LUA_CONTEXT_SSL_CERT
                        | NJT_HTTP_LUA_CONTEXT_SSL_CLIENT_HELLO
                        | NJT_HTTP_LUA_CONTEXT_SSL_SESS_FETCH
                        | NJT_HTTP_LUA_CONTEXT_SSL_SESS_STORE))
    {
        ssl_ctx = njt_http_lua_ssl_get_ctx(r->connection->ssl->connection);
        if (ssl_ctx == NULL) {
            return NJT_ERROR;
        }

        ssl_ctx->ctx_ref = ref;
        c = njt_ssl_get_connection(r->connection->ssl->connection);
        pool = c->pool;

    } else {
        pool = r->pool;
    }

#else
    pool = r->pool;
#endif

    ctx->ctx_ref = ref;

    if (njt_http_lua_njt_ctx_add_cleanup(r, pool, ref) != NJT_OK) {
        return NJT_ERROR;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_lua_njt_ctx_add_cleanup(njt_http_request_t *r, njt_pool_t *pool,
    int ref)
{
    lua_State                   *L;
    njt_pool_cleanup_t          *cln;
    njt_http_lua_ctx_t          *ctx;

    njt_http_lua_njt_ctx_cleanup_data_t    *data;

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
    L = njt_http_lua_get_lua_vm(r, ctx);

    cln = njt_pool_cleanup_add(pool,
                               sizeof(njt_http_lua_njt_ctx_cleanup_data_t));
    if (cln == NULL) {
        return NJT_ERROR;
    }

    cln->handler = njt_http_lua_njt_ctx_cleanup;

    data = cln->data;
    data->vm = L;
    data->ref = ref;

    return NJT_OK;
}


static void
njt_http_lua_njt_ctx_cleanup(void *data)
{
    lua_State       *L;

    njt_http_lua_njt_ctx_cleanup_data_t    *clndata = data;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "lua release njt.ctx at ref %d", clndata->ref);

    L = clndata->vm;

    lua_pushliteral(L, njt_http_lua_ctx_tables_key);
    lua_rawget(L, LUA_REGISTRYINDEX);
    luaL_unref(L, -1, clndata->ref);
    lua_pop(L, 1);
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
