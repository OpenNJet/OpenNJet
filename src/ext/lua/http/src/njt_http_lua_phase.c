
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_http_lua_common.h"


int
njt_http_lua_ffi_get_phase(njt_http_request_t *r, char **err)
{
    njt_http_lua_ctx_t  *ctx;

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
    if (ctx == NULL) {
        *err = "no request context";
        return NJT_ERROR;
    }

    return ctx->context;
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
