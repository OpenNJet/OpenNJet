
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.yy
 */


#ifndef _NJT_HTTP_LUA_SSL_H_INCLUDED_
#define _NJT_HTTP_LUA_SSL_H_INCLUDED_


#include "njt_http_lua_common.h"


#if (NJT_HTTP_SSL)


typedef struct {
    njt_connection_t        *connection; /* original true connection */
    njt_http_request_t      *request;    /* fake request */
    njt_pool_cleanup_pt     *cleanup;

    njt_ssl_session_t       *session;    /* return value for openssl's
                                          * session_get_cb */

    njt_str_t                session_id;

    int                      exit_code;  /* exit code for openssl's
                                            set_client_hello_cb or
                                            set_cert_cb callback */

    int                      ctx_ref;  /*  reference to anchor
                                           request ctx data in lua
                                           registry */

    unsigned                 done:1;
    unsigned                 aborted:1;

    unsigned                 entered_client_hello_handler:1;
    unsigned                 entered_cert_handler:1;
    unsigned                 entered_sess_fetch_handler:1;
} njt_http_lua_ssl_ctx_t;


njt_int_t njt_http_lua_ssl_init(njt_log_t *log);


extern int njt_http_lua_ssl_ctx_index;


#endif


#endif  /* _NJT_HTTP_LUA_SSL_H_INCLUDED_ */
