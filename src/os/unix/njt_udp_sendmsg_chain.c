
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


static njt_chain_t *njt_udp_output_chain_to_iovec(njt_iovec_t *vec,
    njt_chain_t *in, njt_log_t *log);
static ssize_t njt_sendmsg_vec(njt_connection_t *c, njt_iovec_t *vec);


njt_chain_t *
njt_udp_unix_sendmsg_chain(njt_connection_t *c, njt_chain_t *in, off_t limit)
{
    ssize_t        n;
    off_t          send;
    njt_chain_t   *cl;
    njt_event_t   *wev;
    njt_iovec_t    vec;
    struct iovec   iovs[NJT_IOVS_PREALLOCATE];

    wev = c->write;

    if (!wev->ready) {
        return in;
    }

#if (NJT_HAVE_KQUEUE)

    if ((njt_event_flags & NJT_USE_KQUEUE_EVENT) && wev->pending_eof) {
        (void) njt_connection_error(c, wev->kq_errno,
                               "kevent() reported about an closed connection");
        wev->error = 1;
        return NJT_CHAIN_ERROR;
    }

#endif

    /* the maximum limit size is the maximum size_t value - the page size */

    if (limit == 0 || limit > (off_t) (NJT_MAX_SIZE_T_VALUE - njt_pagesize)) {
        limit = NJT_MAX_SIZE_T_VALUE - njt_pagesize;
    }

    send = 0;

    vec.iovs = iovs;
    vec.nalloc = NJT_IOVS_PREALLOCATE;

    for ( ;; ) {

        /* create the iovec and coalesce the neighbouring bufs */

        cl = njt_udp_output_chain_to_iovec(&vec, in, c->log);

        if (cl == NJT_CHAIN_ERROR) {
            return NJT_CHAIN_ERROR;
        }

        if (cl && cl->buf->in_file) {
            njt_log_error(NJT_LOG_ALERT, c->log, 0,
                          "file buf in sendmsg "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            njt_debug_point();

            return NJT_CHAIN_ERROR;
        }

        if (cl == in) {
            return in;
        }

        send += vec.size;

        n = njt_sendmsg_vec(c, &vec);

        if (n == NJT_ERROR) {
            return NJT_CHAIN_ERROR;
        }

        if (n == NJT_AGAIN) {
            wev->ready = 0;
            return in;
        }

        c->sent += n;

        in = njt_chain_update_sent(in, n);

        if (send >= limit || in == NULL) {
            return in;
        }
    }
}


static njt_chain_t *
njt_udp_output_chain_to_iovec(njt_iovec_t *vec, njt_chain_t *in, njt_log_t *log)
{
    size_t         total, size;
    u_char        *prev;
    njt_uint_t     n, flush;
    njt_chain_t   *cl;
    struct iovec  *iov;

    cl = in;
    iov = NULL;
    prev = NULL;
    total = 0;
    n = 0;
    flush = 0;

    for ( /* void */ ; in && !flush; in = in->next) {

        if (in->buf->flush || in->buf->last_buf) {
            flush = 1;
        }

        if (njt_buf_special(in->buf)) {
            continue;
        }

        if (in->buf->in_file) {
            break;
        }

        if (!njt_buf_in_memory(in->buf)) {
            njt_log_error(NJT_LOG_ALERT, log, 0,
                          "bad buf in output chain "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          in->buf->temporary,
                          in->buf->recycled,
                          in->buf->in_file,
                          in->buf->start,
                          in->buf->pos,
                          in->buf->last,
                          in->buf->file,
                          in->buf->file_pos,
                          in->buf->file_last);

            njt_debug_point();

            return NJT_CHAIN_ERROR;
        }

        size = in->buf->last - in->buf->pos;

        if (prev == in->buf->pos && iov != NULL) {
            iov->iov_len += size;

        } else {
            if (n == vec->nalloc) {
                njt_log_error(NJT_LOG_ALERT, log, 0,
                              "too many parts in a datagram");
                return NJT_CHAIN_ERROR;
            }

            iov = &vec->iovs[n++];

            iov->iov_base = (void *) in->buf->pos;
            iov->iov_len = size;
        }

        prev = in->buf->pos + size;
        total += size;
    }

    if (!flush) {
#if (NJT_SUPPRESS_WARN)
        vec->size = 0;
        vec->count = 0;
#endif
        return cl;
    }

    /* zero-sized datagram; pretend to have at least 1 iov */
    if (n == 0) {
        iov = &vec->iovs[n++];
        iov->iov_base = NULL;
        iov->iov_len = 0;
    }

    vec->count = n;
    vec->size = total;

    return in;
}


static ssize_t
njt_sendmsg_vec(njt_connection_t *c, njt_iovec_t *vec)
{
    struct msghdr    msg;

#if (NJT_HAVE_ADDRINFO_CMSG)
    struct cmsghdr  *cmsg;
    u_char           msg_control[CMSG_SPACE(sizeof(njt_addrinfo_t))];
#endif

    njt_memzero(&msg, sizeof(struct msghdr));

    if (c->socklen) {
        msg.msg_name = c->sockaddr;
        msg.msg_namelen = c->socklen;
    }

    msg.msg_iov = vec->iovs;
    msg.msg_iovlen = vec->count;

#if (NJT_HAVE_ADDRINFO_CMSG)
    if (c->listening && c->listening->wildcard && c->local_sockaddr) {

        msg.msg_control = msg_control;
        msg.msg_controllen = sizeof(msg_control);
        njt_memzero(msg_control, sizeof(msg_control));

        cmsg = CMSG_FIRSTHDR(&msg);

        msg.msg_controllen = njt_set_srcaddr_cmsg(cmsg, c->local_sockaddr);
    }
#endif

    return njt_sendmsg(c, &msg, 0);
}


#if (NJT_HAVE_ADDRINFO_CMSG)

size_t
njt_set_srcaddr_cmsg(struct cmsghdr *cmsg, struct sockaddr *local_sockaddr)
{
    size_t                len;
#if (NJT_HAVE_IP_SENDSRCADDR)
    struct in_addr       *addr;
    struct sockaddr_in   *sin;
#elif (NJT_HAVE_IP_PKTINFO)
    struct in_pktinfo    *pkt;
    struct sockaddr_in   *sin;
#endif

#if (NJT_HAVE_INET6 && NJT_HAVE_IPV6_RECVPKTINFO)
    struct in6_pktinfo   *pkt6;
    struct sockaddr_in6  *sin6;
#endif


#if (NJT_HAVE_IP_SENDSRCADDR) || (NJT_HAVE_IP_PKTINFO)

    if (local_sockaddr->sa_family == AF_INET) {

        cmsg->cmsg_level = IPPROTO_IP;

#if (NJT_HAVE_IP_SENDSRCADDR)

        cmsg->cmsg_type = IP_SENDSRCADDR;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_addr));
        len = CMSG_SPACE(sizeof(struct in_addr));

        sin = (struct sockaddr_in *) local_sockaddr;

        addr = (struct in_addr *) CMSG_DATA(cmsg);
        *addr = sin->sin_addr;

#elif (NJT_HAVE_IP_PKTINFO)

        cmsg->cmsg_type = IP_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
        len = CMSG_SPACE(sizeof(struct in_pktinfo));

        sin = (struct sockaddr_in *) local_sockaddr;

        pkt = (struct in_pktinfo *) CMSG_DATA(cmsg);
        njt_memzero(pkt, sizeof(struct in_pktinfo));
        pkt->ipi_spec_dst = sin->sin_addr;

#endif
        return len;
    }

#endif

#if (NJT_HAVE_INET6 && NJT_HAVE_IPV6_RECVPKTINFO)
    if (local_sockaddr->sa_family == AF_INET6) {

        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
        len = CMSG_SPACE(sizeof(struct in6_pktinfo));

        sin6 = (struct sockaddr_in6 *) local_sockaddr;

        pkt6 = (struct in6_pktinfo *) CMSG_DATA(cmsg);
        njt_memzero(pkt6, sizeof(struct in6_pktinfo));
        pkt6->ipi6_addr = sin6->sin6_addr;

        return len;
    }
#endif

    return 0;
}


njt_int_t
njt_get_srcaddr_cmsg(struct cmsghdr *cmsg, struct sockaddr *local_sockaddr)
{
#if (NJT_HAVE_IP_RECVDSTADDR)
    struct in_addr       *addr;
    struct sockaddr_in   *sin;
#elif (NJT_HAVE_IP_PKTINFO)
    struct in_pktinfo    *pkt;
    struct sockaddr_in   *sin;
#endif

#if (NJT_HAVE_INET6 && NJT_HAVE_IPV6_RECVPKTINFO)
    struct in6_pktinfo   *pkt6;
    struct sockaddr_in6  *sin6;
#endif

 #if (NJT_HAVE_IP_RECVDSTADDR)
    if (cmsg->cmsg_level == IPPROTO_IP
        && cmsg->cmsg_type == IP_RECVDSTADDR
        && local_sockaddr->sa_family == AF_INET)
    {
        addr = (struct in_addr *) CMSG_DATA(cmsg);
        sin = (struct sockaddr_in *) local_sockaddr;
        sin->sin_addr = *addr;

        return NJT_OK;
    }

#elif (NJT_HAVE_IP_PKTINFO)

    if (cmsg->cmsg_level == IPPROTO_IP
        && cmsg->cmsg_type == IP_PKTINFO
        && local_sockaddr->sa_family == AF_INET)
    {
        pkt = (struct in_pktinfo *) CMSG_DATA(cmsg);
        sin = (struct sockaddr_in *) local_sockaddr;
        sin->sin_addr = pkt->ipi_addr;

        return NJT_OK;
    }

#endif

#if (NJT_HAVE_INET6 && NJT_HAVE_IPV6_RECVPKTINFO)

    if (cmsg->cmsg_level == IPPROTO_IPV6
        && cmsg->cmsg_type == IPV6_PKTINFO
        && local_sockaddr->sa_family == AF_INET6)
    {
        pkt6 = (struct in6_pktinfo *) CMSG_DATA(cmsg);
        sin6 = (struct sockaddr_in6 *) local_sockaddr;
        sin6->sin6_addr = pkt6->ipi6_addr;

        return NJT_OK;
    }

#endif

    return NJT_DECLINED;
}

#endif


ssize_t
njt_sendmsg(njt_connection_t *c, struct msghdr *msg, int flags)
{
    ssize_t    n;
    njt_err_t  err;
#if (NJT_DEBUG)
    size_t      size;
    njt_uint_t  i;
#endif

eintr:
    //modify by clb, udp traffic hack need use real_sock send msg to client
    if(c->udp && c->udp->real_sock != (njt_socket_t)-1){
        n = sendmsg(c->udp->real_sock, msg, flags);
    }else{
        n = sendmsg(c->fd, msg, flags);
    }
    //end modify by clb

    if (n == -1) {
        err = njt_errno;

        switch (err) {
        case NJT_EAGAIN:
            njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, err,
                           "sendmsg() not ready");
            return NJT_AGAIN;

        case NJT_EINTR:
            njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, err,
                           "sendmsg() was interrupted");
            goto eintr;

        default:
            c->write->error = 1;
            njt_connection_error(c, err, "sendmsg() failed");
            return NJT_ERROR;
        }
    }

#if (NJT_DEBUG)
    for (i = 0, size = 0; i < (size_t) msg->msg_iovlen; i++) {
        size += msg->msg_iov[i].iov_len;
    }

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "sendmsg: %z of %uz", n, size);
#endif

    return n;
}
