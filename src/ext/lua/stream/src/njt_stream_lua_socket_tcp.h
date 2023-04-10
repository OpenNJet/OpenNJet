
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_socket_tcp.h.tt2
 */


/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_STREAM_LUA_SOCKET_TCP_H_INCLUDED_
#define _NJT_STREAM_LUA_SOCKET_TCP_H_INCLUDED_


#include "njt_stream_lua_common.h"


#define NJT_STREAM_LUA_SOCKET_FT_ERROR         0x0001
#define NJT_STREAM_LUA_SOCKET_FT_TIMEOUT       0x0002
#define NJT_STREAM_LUA_SOCKET_FT_CLOSED        0x0004
#define NJT_STREAM_LUA_SOCKET_FT_RESOLVER      0x0008
#define NJT_STREAM_LUA_SOCKET_FT_BUFTOOSMALL   0x0010
#define NJT_STREAM_LUA_SOCKET_FT_NOMEM         0x0020
#define NJT_STREAM_LUA_SOCKET_FT_PARTIALWRITE  0x0040
#define NJT_STREAM_LUA_SOCKET_FT_CLIENTABORT   0x0080
#define NJT_STREAM_LUA_SOCKET_FT_SSL           0x0100


typedef struct njt_stream_lua_socket_tcp_upstream_s
        njt_stream_lua_socket_tcp_upstream_t;


typedef
    int (*njt_stream_lua_socket_tcp_retval_handler)(njt_stream_lua_request_t *r,
        njt_stream_lua_socket_tcp_upstream_t *u, lua_State *L);


typedef void (*njt_stream_lua_socket_tcp_upstream_handler_pt)
    (njt_stream_lua_request_t *r, njt_stream_lua_socket_tcp_upstream_t *u);


typedef struct {
    njt_event_t                                     event;
    njt_queue_t                                     queue;
    njt_str_t                                       host;
    njt_stream_lua_cleanup_pt                      *cleanup;
    njt_stream_lua_socket_tcp_upstream_t           *u;
    in_port_t                                       port;
} njt_stream_lua_socket_tcp_conn_op_ctx_t;


#define njt_stream_lua_socket_tcp_free_conn_op_ctx(conn_op_ctx)              \
    njt_free(conn_op_ctx->host.data);                                        \
    njt_free(conn_op_ctx)


typedef struct {
    lua_State                         *lua_vm;

    njt_int_t                          size;
    njt_queue_t                        cache_connect_op;
    njt_queue_t                        wait_connect_op;

    /* connections == active connections + pending connect operations,
     * while active connections == out-of-pool reused connections
     *                             + in-pool connections */
    njt_int_t                          connections;

    /* queues of njt_stream_lua_socket_pool_item_t: */
    njt_queue_t                        cache;
    njt_queue_t                        free;

    njt_int_t                          backlog;

    u_char                             key[1];

} njt_stream_lua_socket_pool_t;


struct njt_stream_lua_socket_tcp_upstream_s {
    njt_stream_lua_socket_tcp_retval_handler            read_prepare_retvals;
    njt_stream_lua_socket_tcp_retval_handler            write_prepare_retvals;
    njt_stream_lua_socket_tcp_upstream_handler_pt       read_event_handler;
    njt_stream_lua_socket_tcp_upstream_handler_pt       write_event_handler;

    njt_stream_lua_socket_pool_t            *socket_pool;

    njt_stream_lua_loc_conf_t               *conf;
    njt_stream_lua_cleanup_pt               *cleanup;
    njt_stream_lua_request_t                *request;

    njt_peer_connection_t            peer;

    njt_msec_t                       read_timeout;
    njt_msec_t                       send_timeout;
    njt_msec_t                       connect_timeout;

    njt_stream_upstream_resolved_t          *resolved;

    njt_chain_t                     *bufs_in; /* input data buffers */
    njt_chain_t                     *buf_in; /* last input data buffer */
    njt_buf_t                        buffer; /* receive buffer */

    size_t                           length;
    size_t                           rest;

    njt_err_t                        socket_errno;

    njt_int_t                      (*input_filter)(void *data, ssize_t bytes);
    void                            *input_filter_ctx;

    size_t                           request_len;
    njt_chain_t                     *request_bufs;

    njt_stream_lua_co_ctx_t                 *read_co_ctx;
    njt_stream_lua_co_ctx_t                 *write_co_ctx;

    njt_uint_t                       reused;

#if (NJT_STREAM_SSL)
    njt_str_t                        ssl_name;
#endif

    unsigned                         ft_type:16;
    unsigned                         no_close:1;
    unsigned                         conn_waiting:1;
    unsigned                         read_waiting:1;
    unsigned                         write_waiting:1;
    unsigned                         eof:1;
    unsigned                         body_downstream:1;
    unsigned                         raw_downstream:1;
    unsigned                         read_closed:1;
    unsigned                         write_closed:1;
    unsigned                         conn_closed:1;
    unsigned                         read_consumed:1;
#if (NJT_STREAM_SSL)
    unsigned                         ssl_verify:1;
    unsigned                         ssl_session_reuse:1;
#endif
};


typedef struct njt_stream_lua_dfa_edge_s  njt_stream_lua_dfa_edge_t;


struct njt_stream_lua_dfa_edge_s {
    njt_stream_lua_dfa_edge_t       *next;
    int                              new_state;
    u_char                           chr;
};


typedef struct {
    njt_stream_lua_socket_tcp_upstream_t        *upstream;

    njt_str_t                            pattern;
    njt_stream_lua_dfa_edge_t          **recovering;
    int                                  state;

    unsigned                             inclusive:1;
} njt_stream_lua_socket_compiled_pattern_t;


typedef struct {
    njt_stream_lua_socket_pool_t            *socket_pool;

    njt_queue_t                      queue;
    njt_connection_t                *connection;

    socklen_t                        socklen;
    struct sockaddr_storage          sockaddr;

    njt_uint_t                       reused;

} njt_stream_lua_socket_pool_item_t;


void njt_stream_lua_inject_socket_tcp_api(njt_log_t *log, lua_State *L);
void njt_stream_lua_cleanup_conn_pools(lua_State *L);
int njt_stream_lua_req_socket_tcp(lua_State *L);


#endif /* _NJT_STREAM_LUA_SOCKET_TCP_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
