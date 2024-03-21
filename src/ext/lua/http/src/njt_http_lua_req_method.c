
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.yy
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif


#include "ddebug.h"
#include "njt_http_lua_subrequest.h"


int
njt_http_lua_ffi_req_get_method(njt_http_request_t *r)
{
    if (r->connection->fd == (njt_socket_t) -1) {
        return NJT_HTTP_LUA_FFI_BAD_CONTEXT;
    }

    return r->method;
}


int
njt_http_lua_ffi_req_get_method_name(njt_http_request_t *r, u_char **name,
    size_t *len)
{
    if (r->connection->fd == (njt_socket_t) -1) {
        return NJT_HTTP_LUA_FFI_BAD_CONTEXT;
    }

    *name = r->method_name.data;
    *len = r->method_name.len;

    return NJT_OK;
}


int
njt_http_lua_ffi_req_set_method(njt_http_request_t *r, int method)
{
    if (r->connection->fd == (njt_socket_t) -1) {
        return NJT_HTTP_LUA_FFI_BAD_CONTEXT;
    }

    switch (method) {
        case NJT_HTTP_GET:
            r->method_name = njt_http_lua_get_method;
            break;

        case NJT_HTTP_POST:
            r->method_name = njt_http_lua_post_method;
            break;

        case NJT_HTTP_PUT:
            r->method_name = njt_http_lua_put_method;
            break;

        case NJT_HTTP_HEAD:
            r->method_name = njt_http_lua_head_method;
            break;

        case NJT_HTTP_DELETE:
            r->method_name = njt_http_lua_delete_method;
            break;

        case NJT_HTTP_OPTIONS:
            r->method_name = njt_http_lua_options_method;
            break;

        case NJT_HTTP_MKCOL:
            r->method_name = njt_http_lua_mkcol_method;
            break;

        case NJT_HTTP_COPY:
            r->method_name = njt_http_lua_copy_method;
            break;

        case NJT_HTTP_MOVE:
            r->method_name = njt_http_lua_move_method;
            break;

        case NJT_HTTP_PROPFIND:
            r->method_name = njt_http_lua_propfind_method;
            break;

        case NJT_HTTP_PROPPATCH:
            r->method_name = njt_http_lua_proppatch_method;
            break;

        case NJT_HTTP_LOCK:
            r->method_name = njt_http_lua_lock_method;
            break;

        case NJT_HTTP_UNLOCK:
            r->method_name = njt_http_lua_unlock_method;
            break;

        case NJT_HTTP_PATCH:
            r->method_name = njt_http_lua_patch_method;
            break;

        case NJT_HTTP_TRACE:
            r->method_name = njt_http_lua_trace_method;
            break;

        default:
            return NJT_DECLINED;
    }

    r->method = method;
    return NJT_OK;
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
