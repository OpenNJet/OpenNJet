
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.yy
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_http_lua_uri.h"
#include "njt_http_lua_util.h"


static int njt_http_lua_njt_req_set_uri(lua_State *L);


void
njt_http_lua_inject_req_uri_api(njt_log_t *log, lua_State *L)
{
    lua_pushcfunction(L, njt_http_lua_njt_req_set_uri);
    lua_setfield(L, -2, "set_uri");
}


static int
njt_http_lua_njt_req_set_uri(lua_State *L)
{
    njt_http_request_t          *r;
    size_t                       len;
    u_char                      *p;
    u_char                       byte;
    int                          n;
    int                          jump = 0;
    int                          binary = 0;
    njt_http_lua_ctx_t          *ctx;
    size_t                       buf_len;
    u_char                      *buf;

    n = lua_gettop(L);

    if (n < 1 || n > 3) {
        return luaL_error(L, "expecting 1, 2 or 3 arguments but seen %d", n);
    }

    r = njt_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    njt_http_lua_check_fake_request(L, r);

    p = (u_char *) luaL_checklstring(L, 1, &len);

    if (len == 0) {
        return luaL_error(L, "attempt to use zero-length uri");
    }

    if (n >= 3) {
        luaL_checktype(L, 3, LUA_TBOOLEAN);
        binary = lua_toboolean(L, 3);
    }

    if (!binary
        && njt_http_lua_check_unsafe_uri_bytes(r, p, len, &byte) != NJT_OK)
    {
        buf_len = njt_http_lua_escape_log(NULL, p, len) + 1;
        buf = njt_palloc(r->pool, buf_len);
        if (buf == NULL) {
            return NJT_ERROR;
        }

        njt_http_lua_escape_log(buf, p, len);
        buf[buf_len - 1] = '\0';

        return luaL_error(L, "unsafe byte \"0x%02x\" in uri \"%s\" "
                          "(maybe you want to set the 'binary' argument?)",
                          byte, buf);
    }

    if (n >= 2) {
        luaL_checktype(L, 2, LUA_TBOOLEAN);
        jump = lua_toboolean(L, 2);

        if (jump) {

            ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
            if (ctx == NULL) {
                return luaL_error(L, "no ctx found");
            }

            dd("server_rewrite: %d, rewrite: %d, access: %d, content: %d",
               (int) ctx->entered_server_rewrite_phase,
               (int) ctx->entered_rewrite_phase,
               (int) ctx->entered_access_phase,
               (int) ctx->entered_content_phase);

            njt_http_lua_check_context(L, ctx, NJT_HTTP_LUA_CONTEXT_REWRITE
                                       | NJT_HTTP_LUA_CONTEXT_SERVER_REWRITE);

            njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "lua set uri jump to \"%*s\"", len, p);

            njt_http_lua_check_if_abortable(L, ctx);
        }
    }

    r->uri.data = njt_palloc(r->pool, len);
    if (r->uri.data == NULL) {
        return luaL_error(L, "no memory");
    }

    njt_memcpy(r->uri.data, p, len);

    r->uri.len = len;

    r->internal = 1;
    r->valid_unparsed_uri = 0;

    njt_http_set_exten(r);

    if (jump) {
        r->uri_changed = 1;

        return lua_yield(L, 0);
    }

    r->valid_location = 0;
    r->uri_changed = 0;

    return 0;
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
