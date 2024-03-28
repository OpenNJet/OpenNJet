
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.yy
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#if (NJT_HTTP_SSL)


int njt_http_lua_ssl_ctx_index = -1;


njt_int_t
njt_http_lua_ssl_init(njt_log_t *log)
{
    if (njt_http_lua_ssl_ctx_index == -1) {
        njt_http_lua_ssl_ctx_index = SSL_get_ex_new_index(0, NULL, NULL,
                                                          NULL, NULL);

        if (njt_http_lua_ssl_ctx_index == -1) {
            njt_ssl_error(NJT_LOG_ALERT, log, 0,
                          "lua: SSL_get_ex_new_index() for ctx failed");
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


#endif /* NJT_HTTP_SSL */
