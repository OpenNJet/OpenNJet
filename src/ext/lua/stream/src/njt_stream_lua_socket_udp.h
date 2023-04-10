
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_socket_udp.h.tt2
 */


/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_STREAM_LUA_SOCKET_UDP_H_INCLUDED_
#define _NJT_STREAM_LUA_SOCKET_UDP_H_INCLUDED_


#include "njt_stream_lua_common.h"


typedef struct njt_stream_lua_socket_udp_upstream_s
    njt_stream_lua_socket_udp_upstream_t;


typedef
    int (*njt_stream_lua_socket_udp_retval_handler)(njt_stream_lua_request_t *r,
        njt_stream_lua_socket_udp_upstream_t *u, lua_State *L);


typedef void (*njt_stream_lua_socket_udp_upstream_handler_pt)
    (njt_stream_lua_request_t *r, njt_stream_lua_socket_udp_upstream_t *u);


typedef struct {
    njt_connection_t         *connection;
    struct sockaddr          *sockaddr;
    socklen_t                 socklen;
    njt_str_t                 server;
    njt_log_t                 log;
} njt_stream_lua_udp_connection_t;


struct njt_stream_lua_socket_udp_upstream_s {
    njt_stream_lua_socket_udp_retval_handler                prepare_retvals;
    njt_stream_lua_socket_udp_upstream_handler_pt           read_event_handler;

    njt_stream_lua_loc_conf_t               *conf;
    njt_stream_lua_cleanup_pt               *cleanup;
    njt_stream_lua_request_t                *request;
    njt_stream_lua_udp_connection_t          udp_connection;

    njt_msec_t                               read_timeout;

    njt_stream_upstream_resolved_t          *resolved;

    njt_uint_t                               ft_type;
    njt_err_t                                socket_errno;
    size_t                                   received; /* for receive */
    size_t                                   recv_buf_size;

    njt_stream_lua_co_ctx_t                 *co_ctx;

    unsigned                                 waiting:1;

    unsigned                                 raw_downstream:1;
};


void njt_stream_lua_inject_socket_udp_api(njt_log_t *log, lua_State *L);
int njt_stream_lua_req_socket_udp(lua_State *L);


#endif /* _NJT_STREAM_LUA_SOCKET_UDP_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
