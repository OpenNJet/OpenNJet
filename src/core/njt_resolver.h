
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


#ifndef _NJT_RESOLVER_H_INCLUDED_
#define _NJT_RESOLVER_H_INCLUDED_


#define NJT_RESOLVE_A         1
#define NJT_RESOLVE_CNAME     5
#define NJT_RESOLVE_PTR       12
#define NJT_RESOLVE_MX        15
#define NJT_RESOLVE_TXT       16
#if (NJT_HAVE_INET6)
#define NJT_RESOLVE_AAAA      28
#endif
#define NJT_RESOLVE_SRV       33
#define NJT_RESOLVE_DNAME     39

#define NJT_RESOLVE_FORMERR   1
#define NJT_RESOLVE_SERVFAIL  2
#define NJT_RESOLVE_NXDOMAIN  3
#define NJT_RESOLVE_NOTIMP    4
#define NJT_RESOLVE_REFUSED   5
#define NJT_RESOLVE_TIMEDOUT  NJT_ETIMEDOUT


#define NJT_NO_RESOLVER       (void *) -1

#define NJT_RESOLVER_MAX_RECURSION    50


typedef struct njt_resolver_s  njt_resolver_t;


typedef struct {
    njt_connection_t         *udp;
    njt_connection_t         *tcp;
    struct sockaddr          *sockaddr;
    socklen_t                 socklen;
    njt_str_t                 server;
    njt_log_t                 log;
    njt_buf_t                *read_buf;
    njt_buf_t                *write_buf;
    njt_resolver_t           *resolver;
} njt_resolver_connection_t;


typedef struct njt_resolver_ctx_s  njt_resolver_ctx_t;

typedef void (*njt_resolver_handler_pt)(njt_resolver_ctx_t *ctx);


typedef struct {
    struct sockaddr          *sockaddr;
    socklen_t                 socklen;
    njt_str_t                 name;
    u_short                   priority;
    u_short                   weight;
} njt_resolver_addr_t;


typedef struct {
    njt_str_t                 name;
    u_short                   priority;
    u_short                   weight;
    u_short                   port;
} njt_resolver_srv_t;


typedef struct {
    njt_str_t                 name;
    u_short                   priority;
    u_short                   weight;
    u_short                   port;

    njt_resolver_ctx_t       *ctx;
    njt_int_t                 state;

    njt_uint_t                naddrs;
    njt_addr_t               *addrs;
} njt_resolver_srv_name_t;


typedef struct {
    njt_rbtree_node_t         node;
    njt_queue_t               queue;

    /* PTR: resolved name, A: name to resolve */
    u_char                   *name;

#if (NJT_HAVE_INET6)
    /* PTR: IPv6 address to resolve (IPv4 address is in rbtree node key) */
    struct in6_addr           addr6;
#endif

    u_short                   nlen;
    u_short                   qlen;

    u_char                   *query;
#if (NJT_HAVE_INET6)
    u_char                   *query6;
#endif

    union {
        in_addr_t             addr;
        in_addr_t            *addrs;
        u_char               *cname;
        njt_resolver_srv_t   *srvs;
    } u;

    u_char                    code;
    u_short                   naddrs;
    u_short                   nsrvs;
    u_short                   cnlen;

#if (NJT_HAVE_INET6)
    union {
        struct in6_addr       addr6;
        struct in6_addr      *addrs6;
    } u6;

    u_short                   naddrs6;
#endif

    time_t                    expire;
    time_t                    valid;
    uint32_t                  ttl;

    unsigned                  tcp:1;
#if (NJT_HAVE_INET6)
    unsigned                  tcp6:1;
#endif

    njt_uint_t                last_connection;

    njt_resolver_ctx_t       *waiting;
} njt_resolver_node_t;


struct njt_resolver_s {
    /* has to be pointer because of "incomplete type" */
    njt_event_t              *event;
    void                     *dummy;
    njt_log_t                *log;

    /* event ident must be after 3 pointers as in njt_connection_t */
    njt_int_t                 ident;

    /* simple round robin DNS peers balancer */
    njt_array_t               connections;
    njt_uint_t                last_connection;

    njt_rbtree_t              name_rbtree;
    njt_rbtree_node_t         name_sentinel;

    njt_rbtree_t              srv_rbtree;
    njt_rbtree_node_t         srv_sentinel;

    njt_rbtree_t              addr_rbtree;
    njt_rbtree_node_t         addr_sentinel;

    njt_queue_t               name_resend_queue;
    njt_queue_t               srv_resend_queue;
    njt_queue_t               addr_resend_queue;

    njt_queue_t               name_expire_queue;
    njt_queue_t               srv_expire_queue;
    njt_queue_t               addr_expire_queue;

    unsigned                  ipv4:1;

#if (NJT_HAVE_INET6)
    unsigned                  ipv6:1;
    njt_rbtree_t              addr6_rbtree;
    njt_rbtree_node_t         addr6_sentinel;
    njt_queue_t               addr6_resend_queue;
    njt_queue_t               addr6_expire_queue;
#endif

    time_t                    resend_timeout;
    time_t                    tcp_timeout;
    time_t                    expire;
    time_t                    valid;

    njt_uint_t                log_level;
};


struct njt_resolver_ctx_s {
    njt_resolver_ctx_t       *next;
    njt_resolver_t           *resolver;
    njt_resolver_node_t      *node;

    /* event ident must be after 3 pointers as in njt_connection_t */
    njt_int_t                 ident;

    njt_int_t                 state;
    njt_str_t                 name;
    njt_str_t                 service;

    time_t                    valid;
    njt_uint_t                naddrs;
    njt_resolver_addr_t      *addrs;
    njt_resolver_addr_t       addr;
    struct sockaddr_in        sin;

    njt_uint_t                count;
    njt_uint_t                nsrvs;
    njt_resolver_srv_name_t  *srvs;

    njt_resolver_handler_pt   handler;
    void                     *data;
    njt_msec_t                timeout;

    unsigned                  quick:1;
    unsigned                  async:1;
    unsigned                  cancelable:1;
    njt_uint_t                recursion;
    njt_event_t              *event;
};


njt_resolver_t *njt_resolver_create(njt_conf_t *cf, njt_str_t *names,
    njt_uint_t n);
njt_resolver_ctx_t *njt_resolve_start(njt_resolver_t *r,
    njt_resolver_ctx_t *temp);
njt_int_t njt_resolve_name(njt_resolver_ctx_t *ctx);
void njt_resolve_name_done(njt_resolver_ctx_t *ctx);
njt_int_t njt_resolve_addr(njt_resolver_ctx_t *ctx);
void njt_resolve_addr_done(njt_resolver_ctx_t *ctx);
char *njt_resolver_strerror(njt_int_t err);


#endif /* _NJT_RESOLVER_H_INCLUDED_ */
