
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef _NJT_HTTP_LUA_SSL_SESSION_FETCHBY_H_INCLUDED_
#define _NJT_HTTP_LUA_SSL_SESSION_FETCHBY_H_INCLUDED_


#include "njt_http_lua_common.h"


#if (NJT_HTTP_SSL)
njt_int_t njt_http_lua_ssl_sess_fetch_handler_inline(njt_http_request_t *r,
    njt_http_lua_srv_conf_t *lscf, lua_State *L);

njt_int_t njt_http_lua_ssl_sess_fetch_handler_file(njt_http_request_t *r,
    njt_http_lua_srv_conf_t *lscf, lua_State *L);

char *njt_http_lua_ssl_sess_fetch_by_lua(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);

char *njt_http_lua_ssl_sess_fetch_by_lua_block(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);

njt_ssl_session_t *njt_http_lua_ssl_sess_fetch_handler(
    njt_ssl_conn_t *ssl_conn,
#if OPENSSL_VERSION_NUMBER >= 0x10100003L
    const
#endif
    u_char *id, int len, int *copy);
#endif


#endif /* _NJT_HTTP_LUA_SSL_SESSION_FETCHBY_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
