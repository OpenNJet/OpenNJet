
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_INET_H_INCLUDED_
#define _NJT_INET_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


#define NJT_INET_ADDRSTRLEN   (sizeof("255.255.255.255") - 1)
#define NJT_INET6_ADDRSTRLEN                                                 \
    (sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255") - 1)
#define NJT_UNIX_ADDRSTRLEN                                                  \
    (sizeof("unix:") - 1 +                                                   \
     sizeof(struct sockaddr_un) - offsetof(struct sockaddr_un, sun_path))

#if (NJT_HAVE_UNIX_DOMAIN)
#define NJT_SOCKADDR_STRLEN   NJT_UNIX_ADDRSTRLEN
#elif (NJT_HAVE_INET6)
#define NJT_SOCKADDR_STRLEN   (NJT_INET6_ADDRSTRLEN + sizeof("[]:65535") - 1)
#else
#define NJT_SOCKADDR_STRLEN   (NJT_INET_ADDRSTRLEN + sizeof(":65535") - 1)
#endif

/* compatibility */
#define NJT_SOCKADDRLEN       sizeof(njt_sockaddr_t)


typedef union {
    struct sockaddr           sockaddr;
    struct sockaddr_in        sockaddr_in;
#if (NJT_HAVE_INET6)
    struct sockaddr_in6       sockaddr_in6;
#endif
#if (NJT_HAVE_UNIX_DOMAIN)
    struct sockaddr_un        sockaddr_un;
#endif
} njt_sockaddr_t;


typedef struct {
    in_addr_t                 addr;
    in_addr_t                 mask;
} njt_in_cidr_t;


#if (NJT_HAVE_INET6)

typedef struct {
    struct in6_addr           addr;
    struct in6_addr           mask;
} njt_in6_cidr_t;

#endif


typedef struct {
    njt_uint_t                family;
    union {
        njt_in_cidr_t         in;
#if (NJT_HAVE_INET6)
        njt_in6_cidr_t        in6;
#endif
    } u;
} njt_cidr_t;


typedef struct {
    struct sockaddr          *sockaddr;
    socklen_t                 socklen;
    njt_str_t                 name;
} njt_addr_t;


typedef struct {
    njt_str_t                 url;
    njt_str_t                 host;
    njt_str_t                 port_text;
    njt_str_t                 uri;

    in_port_t                 port;
    in_port_t                 default_port;
    in_port_t                 last_port;
    int                       family;

    unsigned                  listen:1;
    unsigned                  uri_part:1;
    unsigned                  no_resolve:1;

    unsigned                  no_port:1;
    unsigned                  wildcard:1;

    socklen_t                 socklen;
    njt_sockaddr_t            sockaddr;

    njt_addr_t               *addrs;
    njt_uint_t                naddrs;

    char                     *err;
} njt_url_t;


in_addr_t njt_inet_addr(u_char *text, size_t len);
#if (NJT_HAVE_INET6)
njt_int_t njt_inet6_addr(u_char *p, size_t len, u_char *addr);
size_t njt_inet6_ntop(u_char *p, u_char *text, size_t len);
#endif
size_t njt_sock_ntop(struct sockaddr *sa, socklen_t socklen, u_char *text,
    size_t len, njt_uint_t port);
size_t njt_inet_ntop(int family, void *addr, u_char *text, size_t len);
njt_int_t njt_ptocidr(njt_str_t *text, njt_cidr_t *cidr);
njt_int_t njt_cidr_match(struct sockaddr *sa, njt_array_t *cidrs);
njt_int_t njt_parse_addr(njt_pool_t *pool, njt_addr_t *addr, u_char *text,
    size_t len);
njt_int_t njt_parse_addr_port(njt_pool_t *pool, njt_addr_t *addr,
    u_char *text, size_t len);
njt_int_t njt_parse_url(njt_pool_t *pool, njt_url_t *u);
njt_int_t njt_inet_resolve_host(njt_pool_t *pool, njt_url_t *u);
njt_int_t njt_cmp_sockaddr(struct sockaddr *sa1, socklen_t slen1,
    struct sockaddr *sa2, socklen_t slen2, njt_uint_t cmp_port);
in_port_t njt_inet_get_port(struct sockaddr *sa);
void njt_inet_set_port(struct sockaddr *sa, in_port_t port);
njt_uint_t njt_inet_wildcard(struct sockaddr *sa);


#endif /* _NJT_INET_H_INCLUDED_ */
