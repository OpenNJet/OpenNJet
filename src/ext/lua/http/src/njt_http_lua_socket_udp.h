
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.yy
 */


#ifndef _NJT_HTTP_LUA_SOCKET_UDP_H_INCLUDED_
#define _NJT_HTTP_LUA_SOCKET_UDP_H_INCLUDED_


#include "njt_http_lua_common.h"


typedef struct njt_http_lua_socket_udp_upstream_s
    njt_http_lua_socket_udp_upstream_t;


typedef
    int (*njt_http_lua_socket_udp_retval_handler)(njt_http_request_t *r,
        njt_http_lua_socket_udp_upstream_t *u, lua_State *L);


typedef void (*njt_http_lua_socket_udp_upstream_handler_pt)
    (njt_http_request_t *r, njt_http_lua_socket_udp_upstream_t *u);


typedef struct {
    njt_connection_t         *connection;
    struct sockaddr          *sockaddr;
    socklen_t                 socklen;
    njt_str_t                 server;
    njt_log_t                 log;
} njt_http_lua_udp_connection_t;


struct njt_http_lua_socket_udp_upstream_s {
    njt_http_lua_socket_udp_retval_handler          prepare_retvals;
    njt_http_lua_socket_udp_upstream_handler_pt     read_event_handler;

    njt_http_lua_loc_conf_t         *conf;
    njt_http_cleanup_pt             *cleanup;
    njt_http_request_t              *request;
    njt_http_lua_udp_connection_t    udp_connection;

    njt_msec_t                       read_timeout;

    njt_http_upstream_resolved_t    *resolved;

    njt_uint_t                       ft_type;
    njt_err_t                        socket_errno;
    size_t                           received; /* for receive */
    size_t                           recv_buf_size;

    njt_http_lua_co_ctx_t           *co_ctx;

    unsigned                         waiting; /* :1 */
};


void njt_http_lua_inject_socket_udp_api(njt_log_t *log, lua_State *L);


#endif /* _NJT_HTTP_LUA_SOCKET_UDP_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
