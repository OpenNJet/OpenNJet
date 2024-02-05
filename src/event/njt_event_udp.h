
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_EVENT_UDP_H_INCLUDED_
#define _NJT_EVENT_UDP_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


#if !(NJT_WIN32)

#if ((NJT_HAVE_MSGHDR_MSG_CONTROL)                                            \
     && (NJT_HAVE_IP_SENDSRCADDR || NJT_HAVE_IP_RECVDSTADDR                   \
         || NJT_HAVE_IP_PKTINFO                                               \
         || (NJT_HAVE_INET6 && NJT_HAVE_IPV6_RECVPKTINFO)))
#define NJT_HAVE_ADDRINFO_CMSG  1

#endif


struct njt_udp_connection_s {
    njt_rbtree_node_t   node;
    njt_connection_t   *connection;
    //add by clb, used for udp traffic hack, send msg use this socket
    njt_socket_t 		real_sock;
    //end add by clb
    njt_buf_t          *buffer;
    njt_str_t           key;
};


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
} njt_addrinfo_t;

size_t njt_set_srcaddr_cmsg(struct cmsghdr *cmsg,
    struct sockaddr *local_sockaddr);
njt_int_t njt_get_srcaddr_cmsg(struct cmsghdr *cmsg,
    struct sockaddr *local_sockaddr);

#endif

void njt_event_recvmsg(njt_event_t *ev);
ssize_t njt_sendmsg(njt_connection_t *c, struct msghdr *msg, int flags);
void njt_udp_rbtree_insert_value(njt_rbtree_node_t *temp,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel);
#endif

void njt_delete_udp_connection(void *data);


#endif /* _NJT_EVENT_UDP_H_INCLUDED_ */
