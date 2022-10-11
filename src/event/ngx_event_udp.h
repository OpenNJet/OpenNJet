
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NJT_EVENT_UDP_H_INCLUDED_
#define _NJT_EVENT_UDP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#if !(NJT_WIN32)

#if ((NJT_HAVE_MSGHDR_MSG_CONTROL)                                            \
     && (NJT_HAVE_IP_SENDSRCADDR || NJT_HAVE_IP_RECVDSTADDR                   \
         || NJT_HAVE_IP_PKTINFO                                               \
         || (NJT_HAVE_INET6 && NJT_HAVE_IPV6_RECVPKTINFO)))
#define NJT_HAVE_ADDRINFO_CMSG  1

#endif


#if (NJT_HAVE_ADDRINFO_CMSG)

typedef union {
#if (NJT_HAVE_IP_SENDSRCADDR || NJT_HAVE_IP_RECVDSTADDR)
    struct in_addr        addr;
#endif

#if (NJT_HAVE_IP_PKTINFO)
    struct in_pktinfo     pkt;
#endif

#if (NJT_HAVE_INET6 && NJT_HAVE_IPV6_RECVPKTINFO)
    struct in6_pktinfo    pkt6;
#endif
} ngx_addrinfo_t;

size_t ngx_set_srcaddr_cmsg(struct cmsghdr *cmsg,
    struct sockaddr *local_sockaddr);
ngx_int_t ngx_get_srcaddr_cmsg(struct cmsghdr *cmsg,
    struct sockaddr *local_sockaddr);

#endif

void ngx_event_recvmsg(ngx_event_t *ev);
ssize_t ngx_sendmsg(ngx_connection_t *c, struct msghdr *msg, int flags);
void ngx_udp_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
#endif

void ngx_delete_udp_connection(void *data);


#endif /* _NJT_EVENT_UDP_H_INCLUDED_ */
