
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_http_lua_control.h"
#include "njt_http_lua_util.h"
#include "njt_http_lua_coroutine.h"


static int njt_http_lua_njt_exec(lua_State *L);
static int njt_http_lua_njt_redirect(lua_State *L);
static int njt_http_lua_on_abort(lua_State *L);


void
njt_http_lua_inject_control_api(njt_log_t *log, lua_State *L)
{
    /* njt.redirect */

    lua_pushcfunction(L, njt_http_lua_njt_redirect);
    lua_setfield(L, -2, "redirect");

    /* njt.exec */

    lua_pushcfunction(L, njt_http_lua_njt_exec);
    lua_setfield(L, -2, "exec");

    /* njt.on_abort */

    lua_pushcfunction(L, njt_http_lua_on_abort);
    lua_setfield(L, -2, "on_abort");
}


static int
njt_http_lua_njt_exec(lua_State *L)
{
    int                          n;
    njt_http_request_t          *r;
    njt_http_lua_ctx_t          *ctx;
    njt_str_t                    uri;
    njt_str_t                    args, user_args;
    njt_uint_t                   flags;
    u_char                      *p;
    u_char                      *q;
    size_t                       len;
    const char                  *msg;

    n = lua_gettop(L);
    if (n != 1 && n != 2) {
        return luaL_error(L, "expecting one or two arguments, but got %d",
                          n);
    }

    r = njt_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request object found");
    }

    njt_str_null(&args);

    /* read the 1st argument (uri) */

    p = (u_char *) luaL_checklstring(L, 1, &len);

    if (len == 0) {
        return luaL_error(L, "The uri argument is empty");
    }

    uri.data = njt_palloc(r->pool, len);
    if (uri.data == NULL) {
        return luaL_error(L, "no memory");
    }

    njt_memcpy(uri.data, p, len);

    uri.len = len;

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no ctx found");
    }

    njt_http_lua_check_context(L, ctx, NJT_HTTP_LUA_CONTEXT_REWRITE
                               | NJT_HTTP_LUA_CONTEXT_SERVER_REWRITE
                               | NJT_HTTP_LUA_CONTEXT_ACCESS
                               | NJT_HTTP_LUA_CONTEXT_CONTENT);

    njt_http_lua_check_if_abortable(L, ctx);

    flags = NJT_HTTP_LOG_UNSAFE;

    if (njt_http_parse_unsafe_uri(r, &uri, &args, &flags) != NJT_OK) {
        return luaL_error(L, "unsafe uri");
    }

    if (n == 2) {
        /* read the 2nd argument (args) */
        dd("args type: %s", luaL_typename(L, 2));

        switch (lua_type(L, 2)) {
        case LUA_TNUMBER:
        case LUA_TSTRING:
            p = (u_char *) lua_tolstring(L, 2, &len);

            user_args.data = njt_palloc(r->pool, len);
            if (user_args.data == NULL) {
                return luaL_error(L, "no memory");
            }

            njt_memcpy(user_args.data, p, len);

            user_args.len = len;
            break;

        case LUA_TTABLE:
            njt_http_lua_process_args_option(r, L, 2, &user_args);

            dd("user_args: %.*s", (int) user_args.len, user_args.data);

            break;

        case LUA_TNIL:
            njt_str_null(&user_args);
            break;

        default:
            msg = lua_pushfstring(L, "string, number, or table expected, "
                                  "but got %s", luaL_typename(L, 2));
            return luaL_argerror(L, 2, msg);
        }

    } else {
        user_args.data = NULL;
        user_args.len = 0;
    }

    if (user_args.len) {
        if (args.len == 0) {
            args = user_args;

        } else {
            p = njt_palloc(r->pool, args.len + user_args.len + 1);
            if (p == NULL) {
                return luaL_error(L, "no memory");
            }

            q = njt_copy(p, args.data, args.len);
            *q++ = '&';
            njt_memcpy(q, user_args.data, user_args.len);

            args.data = p;
            args.len += user_args.len + 1;
        }
    }

    if (r->header_sent || ctx->header_sent) {
        return luaL_error(L, "attempt to call njt.exec after "
                          "sending out response headers");
    }

    ctx->exec_uri = uri;
    ctx->exec_args = args;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua exec \"%V?%V\"",
                   &ctx->exec_uri, &ctx->exec_args);

    return lua_yield(L, 0);
}


static int
njt_http_lua_njt_redirect(lua_State *L)
{
    njt_http_lua_ctx_t          *ctx;
    njt_int_t                    rc;
    int                          n;
    u_char                      *p;
    u_char                      *uri;
    u_char                       byte;
    size_t                       len;
    njt_table_elt_t             *h;
    njt_http_request_t          *r;
    size_t                       buf_len;
    u_char                      *buf;

    n = lua_gettop(L);

    if (n != 1 && n != 2) {
        return luaL_error(L, "expecting one or two arguments");
    }

    p = (u_char *) luaL_checklstring(L, 1, &len);

    if (n == 2) {
        rc = (njt_int_t) luaL_checknumber(L, 2);

        if (rc != NJT_HTTP_MOVED_TEMPORARILY
            && rc != NJT_HTTP_MOVED_PERMANENTLY
            && rc != NJT_HTTP_SEE_OTHER
            && rc != NJT_HTTP_PERMANENT_REDIRECT
            && rc != NJT_HTTP_TEMPORARY_REDIRECT)
        {
            return luaL_error(L, "only njt.HTTP_MOVED_TEMPORARILY, "
                              "njt.HTTP_MOVED_PERMANENTLY, "
                              "njt.HTTP_PERMANENT_REDIRECT, "
                              "njt.HTTP_SEE_OTHER, and "
                              "njt.HTTP_TEMPORARY_REDIRECT are allowed");
        }

    } else {
        rc = NJT_HTTP_MOVED_TEMPORARILY;
    }

    r = njt_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request object found");
    }

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    njt_http_lua_check_context(L, ctx, NJT_HTTP_LUA_CONTEXT_REWRITE
                               | NJT_HTTP_LUA_CONTEXT_SERVER_REWRITE
                               | NJT_HTTP_LUA_CONTEXT_ACCESS
                               | NJT_HTTP_LUA_CONTEXT_CONTENT);

    njt_http_lua_check_if_abortable(L, ctx);

    if (r->header_sent || ctx->header_sent) {
        return luaL_error(L, "attempt to call njt.redirect after sending out "
                          "the headers");
    }

    if (njt_http_lua_check_unsafe_uri_bytes(r, p, len, &byte) != NJT_OK) {
        buf_len = njt_http_lua_escape_log(NULL, p, len) + 1;
        buf = njt_palloc(r->pool, buf_len);
        if (buf == NULL) {
            return NJT_ERROR;
        }

        njt_http_lua_escape_log(buf, p, len);
        buf[buf_len - 1] = '\0';
        return luaL_error(L, "unsafe byte \"0x%02x\" in redirect uri \"%s\"",
                          byte, buf);
    }

    uri = njt_palloc(r->pool, len);
    if (uri == NULL) {
        return luaL_error(L, "no memory");
    }

    njt_memcpy(uri, p, len);

    h = njt_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return luaL_error(L, "no memory");
    }

    h->hash = njt_http_lua_location_hash;

#if 0
    dd("location hash: %lu == %lu",
       (unsigned long) h->hash,
       (unsigned long) njt_hash_key_lc((u_char *) "Location",
                                       sizeof("Location") - 1));
#endif

    h->value.len = len;
    h->value.data = uri;
#if defined(njet_version) && njet_version >= 1023000
    h->next = NULL;
#endif
    njt_str_set(&h->key, "Location");

    r->headers_out.status = rc;

    ctx->exit_code = rc;
    ctx->exited = 1;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua redirect to \"%V\" with code %i",
                   &h->value, ctx->exit_code);

    if (len && uri[0] != '/') {
        r->headers_out.location = h;
    }

    /*
     * we do not set r->headers_out.location here to avoid the handling
     * the local redirects without a host name by njt_http_header_filter()
     */

    return lua_yield(L, 0);
}


static int
njt_http_lua_on_abort(lua_State *L)
{
    int                           co_ref;
    njt_http_request_t           *r;
    njt_http_lua_ctx_t           *ctx;
    njt_http_lua_co_ctx_t        *coctx = NULL;
    njt_http_lua_loc_conf_t      *llcf;

    r = njt_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    njt_http_lua_check_fake_request2(L, r, ctx);

    if (ctx->on_abort_co_ctx) {
        lua_pushnil(L);
        lua_pushliteral(L, "duplicate call");
        return 2;
    }

    llcf = njt_http_get_module_loc_conf(r, njt_http_lua_module);
    if (!llcf->check_client_abort) {
        lua_pushnil(L);
        lua_pushliteral(L, "lua_check_client_abort is off");
        return 2;
    }

    njt_http_lua_coroutine_create_helper(L, r, ctx, &coctx, &co_ref);

    coctx->co_ref = co_ref;
    coctx->is_uthread = 1;
    ctx->on_abort_co_ctx = coctx;

    dd("on_wait thread 2: %p", coctx->co);

    coctx->co_status = NJT_HTTP_LUA_CO_SUSPENDED;
    coctx->parent_co_ctx = ctx->cur_co_ctx;

    lua_pushinteger(L, 1);
    return 1;
}


int
njt_http_lua_ffi_exit(njt_http_request_t *r, int status, u_char *err,
    size_t *errlen)
{
    njt_http_lua_ctx_t       *ctx;

    if (status == NJT_AGAIN || status == NJT_DONE) {
        *errlen = njt_snprintf(err, *errlen,
                               "bad argument to 'njt.exit': does not accept "
                               "NJT_AGAIN or NJT_DONE")
                  - err;
        return NJT_ERROR;
    }

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
    if (ctx == NULL) {
        *errlen = njt_snprintf(err, *errlen, "no request ctx found") - err;
        return NJT_ERROR;
    }

    if (njt_http_lua_ffi_check_context(ctx, NJT_HTTP_LUA_CONTEXT_REWRITE
                                       | NJT_HTTP_LUA_CONTEXT_SERVER_REWRITE
                                       | NJT_HTTP_LUA_CONTEXT_ACCESS
                                       | NJT_HTTP_LUA_CONTEXT_CONTENT
                                       | NJT_HTTP_LUA_CONTEXT_TIMER
                                       | NJT_HTTP_LUA_CONTEXT_HEADER_FILTER
                                       | NJT_HTTP_LUA_CONTEXT_BALANCER
                                       | NJT_HTTP_LUA_CONTEXT_SSL_CLIENT_HELLO
                                       | NJT_HTTP_LUA_CONTEXT_SSL_CERT
                                       | NJT_HTTP_LUA_CONTEXT_SSL_SESS_STORE
                                       | NJT_HTTP_LUA_CONTEXT_SSL_SESS_FETCH,
                                       err, errlen)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    if (ctx->context & (NJT_HTTP_LUA_CONTEXT_SSL_CERT
                        | NJT_HTTP_LUA_CONTEXT_SSL_CLIENT_HELLO
                        | NJT_HTTP_LUA_CONTEXT_SSL_SESS_STORE
                        | NJT_HTTP_LUA_CONTEXT_SSL_SESS_FETCH))
    {

#if (NJT_HTTP_SSL)

        ctx->exit_code = status;
        ctx->exited = 1;

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "lua exit with code %d", status);

        if (ctx->context == NJT_HTTP_LUA_CONTEXT_SSL_SESS_STORE) {
            return NJT_DONE;
        }

        return NJT_OK;

#else

        return NJT_ERROR;

#endif
    }

    if (ctx->no_abort
        && status != NJT_ERROR
        && status != NJT_HTTP_CLOSE
        && status != NJT_HTTP_REQUEST_TIME_OUT
        && status != NJT_HTTP_CLIENT_CLOSED_REQUEST)
    {
        *errlen = njt_snprintf(err, *errlen,
                               "attempt to abort with pending subrequests")
                  - err;
        return NJT_ERROR;
    }

    if ((r->header_sent || ctx->header_sent)
        && status >= NJT_HTTP_SPECIAL_RESPONSE
        && status != NJT_HTTP_REQUEST_TIME_OUT
        && status != NJT_HTTP_CLIENT_CLOSED_REQUEST
        && status != NJT_HTTP_CLOSE)
    {
        if (status != (njt_int_t) r->headers_out.status) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "attempt to "
                          "set status %d via njt.exit after sending out the "
                          "response status %ui", status,
                          r->headers_out.status);
        }

        status = NJT_HTTP_OK;
    }

    ctx->exit_code = status;
    ctx->exited = 1;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua exit with code %i", ctx->exit_code);

    if (ctx->context & (NJT_HTTP_LUA_CONTEXT_HEADER_FILTER
                        | NJT_HTTP_LUA_CONTEXT_BALANCER))
    {
        return NJT_DONE;
    }

    return NJT_OK;
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
