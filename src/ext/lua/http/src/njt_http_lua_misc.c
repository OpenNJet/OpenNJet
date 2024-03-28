
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_http_lua_misc.h"
#include "njt_http_lua_util.h"


static int njt_http_lua_njt_req_is_internal(lua_State *L);


void
njt_http_lua_inject_req_misc_api(lua_State *L)
{
    lua_pushcfunction(L, njt_http_lua_njt_req_is_internal);
    lua_setfield(L, -2, "is_internal");
}


static int
njt_http_lua_njt_req_is_internal(lua_State *L)
{
    njt_http_request_t  *r;

    r = njt_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request object found");
    }

    lua_pushboolean(L, r->internal == 1);
    return 1;
}


int
njt_http_lua_ffi_get_resp_status(njt_http_request_t *r)
{
    if (r->connection->fd == (njt_socket_t) -1) {
        return NJT_HTTP_LUA_FFI_BAD_CONTEXT;
    }

    if (r->err_status) {
        return r->err_status;

    } else if (r->headers_out.status) {
        return r->headers_out.status;

    } else if (r->http_version == NJT_HTTP_VERSION_9) {
        return 9;

    } else {
        return 0;
    }
}


int
njt_http_lua_ffi_set_resp_status(njt_http_request_t *r, int status)
{
    if (r->connection->fd == (njt_socket_t) -1) {
        return NJT_HTTP_LUA_FFI_BAD_CONTEXT;
    }

    if (r->header_sent) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "attempt to set njt.status after sending out "
                      "response headers");
        return NJT_DECLINED;
    }

    r->headers_out.status = status;

    if (r->err_status) {
        r->err_status = 0;
    }

    if (status == 101) {
        /*
         * XXX work-around a bug in the NJet core older than 1.5.5
         * that 101 does not have a default status line
         */

        njt_str_set(&r->headers_out.status_line, "101 Switching Protocols");

    } else {
        r->headers_out.status_line.len = 0;
    }

    return NJT_OK;
}


int
njt_http_lua_ffi_req_is_internal(njt_http_request_t *r)
{
    if (r->connection->fd == (njt_socket_t) -1) {
        return NJT_HTTP_LUA_FFI_BAD_CONTEXT;
    }

    return r->internal;
}


int
njt_http_lua_ffi_is_subrequest(njt_http_request_t *r)
{
    if (r->connection->fd == (njt_socket_t) -1) {
        return NJT_HTTP_LUA_FFI_BAD_CONTEXT;
    }

    return r != r->main;
}


int
njt_http_lua_ffi_headers_sent(njt_http_request_t *r)
{
    njt_http_lua_ctx_t          *ctx;

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
    if (ctx == NULL) {
        return NJT_HTTP_LUA_FFI_NO_REQ_CTX;
    }

    if (r->connection->fd == (njt_socket_t) -1) {
        return NJT_HTTP_LUA_FFI_BAD_CONTEXT;
    }

    return r->header_sent ? 1 : 0;
}


int
njt_http_lua_ffi_get_conf_env(u_char *name, u_char **env_buf, size_t *name_len)
{
    njt_uint_t            i;
    njt_str_t            *var;
    njt_core_conf_t      *ccf;

    ccf = (njt_core_conf_t *) njt_get_conf(njt_cycle->conf_ctx,
                                           njt_core_module);

    var = ccf->env.elts;

    for (i = 0; i < ccf->env.nelts; i++) {
        if (var[i].data[var[i].len] == '='
            && njt_strncmp(name, var[i].data, var[i].len) == 0)
        {
            *env_buf = var[i].data;
            *name_len = var[i].len;

            return NJT_OK;
        }
    }

    return NJT_DECLINED;
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
