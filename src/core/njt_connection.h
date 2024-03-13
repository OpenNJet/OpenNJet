
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_CONNECTION_H_INCLUDED_
#define _NJT_CONNECTION_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>

#define NJT_HTTP_SERVER_TYPE 1
#define NJT_STREAM_SERVER_TYPE 2
#define NJT_MAIL_SERVER_TYPE 2

typedef struct njt_listening_s  njt_listening_t;

struct njt_listening_s {
    njt_socket_t        fd;

    struct sockaddr    *sockaddr;
    socklen_t           socklen;    /* size of sockaddr */
    size_t              addr_text_max_len;
    njt_str_t           addr_text;

    int                 type;   //socket type

    int                 backlog;
    int                 rcvbuf;
    int                 sndbuf;
#if (NJT_HAVE_KEEPALIVE_TUNABLE)
    int                 keepidle;
    int                 keepintvl;
    int                 keepcnt;
#endif

    /* handler of accepted connection */
    njt_connection_handler_pt   handler;

    void               *servers;  /* array of njt_http_in_addr_t, for example */
    int                 server_type; // server 类型
    njt_log_t           log;
    njt_log_t          *logp;

    size_t              pool_size;
    /* should be here because of the AcceptEx() preread */
    size_t              post_accept_buffer_size;

    njt_listening_t    *previous;
    njt_connection_t   *connection;

    njt_rbtree_t        rbtree;
    njt_rbtree_node_t   sentinel;

    njt_uint_t          worker;

    unsigned            open:1;
    unsigned            remain:1;
    unsigned            ignore:1;

    unsigned            bound:1;       /* already bound */
    unsigned            inherited:1;   /* inherited from previous process */
    unsigned            nonblocking_accept:1;
    unsigned            listen:1;
    unsigned            nonblocking:1;
    unsigned            shared:1;    /* shared between threads or processes */
    unsigned            addr_ntop:1;
    unsigned            wildcard:1;

#if (NJT_HAVE_INET6)
    unsigned            ipv6only:1;
#endif
    unsigned            reuseport:1;
    unsigned            add_reuseport:1;
    unsigned            keepalive:2;
    unsigned            quic:1;

//add by clb, used for tcp and udp traffic hack
    unsigned          mesh:1;
//end add by clb

    unsigned            deferred_accept:1;
    unsigned            delete_deferred:1;
    unsigned            add_deferred:1;
#if (NJT_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    char               *accept_filter;
#endif
#if (NJT_HAVE_SETFIB)
    int                 setfib;
#endif

#if (NJT_HAVE_TCP_FASTOPEN)
    int                 fastopen;
#endif

};


typedef enum {
    NJT_ERROR_ALERT = 0,
    NJT_ERROR_ERR,
    NJT_ERROR_INFO,
    NJT_ERROR_IGNORE_ECONNRESET,
    NJT_ERROR_IGNORE_EINVAL,
    NJT_ERROR_IGNORE_EMSGSIZE
} njt_connection_log_error_e;


typedef enum {
    NJT_TCP_NODELAY_UNSET = 0,
    NJT_TCP_NODELAY_SET,
    NJT_TCP_NODELAY_DISABLED
} njt_connection_tcp_nodelay_e;


typedef enum {
    NJT_TCP_NOPUSH_UNSET = 0,
    NJT_TCP_NOPUSH_SET,
    NJT_TCP_NOPUSH_DISABLED
} njt_connection_tcp_nopush_e;


#define NJT_LOWLEVEL_BUFFERED  0x0f
#define NJT_SSL_BUFFERED       0x01
#define NJT_HTTP_V2_BUFFERED   0x02


struct njt_connection_s {
    void               *data;
    njt_event_t        *read;
    njt_event_t        *write;

    njt_socket_t        fd;

    njt_recv_pt         recv;
    njt_send_pt         send;
    njt_recv_chain_pt   recv_chain;
    njt_send_chain_pt   send_chain;

    njt_listening_t    *listening;

    off_t               sent;

    njt_log_t          *log;

    njt_pool_t         *pool;

    int                 type;

    struct sockaddr    *sockaddr;
    socklen_t           socklen;
    njt_str_t           addr_text;

    njt_proxy_protocol_t  *proxy_protocol;

#if (NJT_QUIC || NJT_COMPAT)
    njt_quic_stream_t     *quic;
#endif

#if (NJT_SSL || NJT_COMPAT)
    njt_ssl_connection_t  *ssl;
#endif

    njt_udp_connection_t  *udp;

    struct sockaddr    *local_sockaddr;
    socklen_t           local_socklen;

    //add by clb, used for udp traffic hack
    struct sockaddr_storage     mesh_dst_addr;
    //end by clb

    njt_buf_t          *buffer;

    njt_queue_t         queue;

    njt_atomic_uint_t   number;

    njt_msec_t          start_time;
    njt_uint_t          requests;

    unsigned            buffered:8;

    unsigned            log_error:3;     /* njt_connection_log_error_e */

    unsigned            timedout:1;
    unsigned            error:1;
    unsigned            destroyed:1;
    unsigned            pipeline:1;

    unsigned            idle:1;
    unsigned            reusable:1;
    unsigned            close:1;
    unsigned            shared:1;

    unsigned            sendfile:1;
    unsigned            sndlowat:1;
    unsigned            tcp_nodelay:2;   /* njt_connection_tcp_nodelay_e */
    unsigned            tcp_nopush:2;    /* njt_connection_tcp_nopush_e */

    unsigned            need_last_buf:1;
    unsigned            need_flush_buf:1;

#if (NJT_HAVE_SENDFILE_NODISKIO || NJT_COMPAT)
    unsigned            busy_count:2;
#endif

#if (NJT_THREADS || NJT_COMPAT)
    njt_thread_task_t  *sendfile_task;
#endif
};


#define njt_set_connection_log(c, l)                                         \
                                                                             \
    c->log->file = l->file;                                                  \
    c->log->next = l->next;                                                  \
    c->log->writer = l->writer;                                              \
    c->log->wdata = l->wdata;                                                \
    if (!(c->log->log_level & NJT_LOG_DEBUG_CONNECTION)) {                   \
        c->log->log_level = l->log_level;                                    \
    }


njt_listening_t *njt_create_listening(njt_conf_t *cf, struct sockaddr *sockaddr,
    socklen_t socklen);
njt_int_t njt_clone_listening(njt_cycle_t *cycle, njt_listening_t *ls);
njt_int_t njt_set_inherited_sockets(njt_cycle_t *cycle);
njt_int_t njt_open_listening_sockets(njt_cycle_t *cycle);
void njt_configure_listening_sockets(njt_cycle_t *cycle);
void njt_close_listening_sockets(njt_cycle_t *cycle);
void njt_close_connection(njt_connection_t *c);
void njt_close_idle_connections(njt_cycle_t *cycle);
njt_int_t njt_connection_local_sockaddr(njt_connection_t *c, njt_str_t *s,
    njt_uint_t port);
njt_int_t njt_tcp_nodelay(njt_connection_t *c);
njt_int_t njt_connection_error(njt_connection_t *c, njt_err_t err, char *text);

njt_connection_t *njt_get_connection(njt_socket_t s, njt_log_t *log);
void njt_free_connection(njt_connection_t *c);
njt_listening_t * njt_get_listening(njt_conf_t *cf, struct sockaddr *sockaddr, socklen_t socklen);
void njt_reusable_connection(njt_connection_t *c, njt_uint_t reusable);

#endif /* _NJT_CONNECTION_H_INCLUDED_ */
