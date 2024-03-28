
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_event_connect.h>


#if (NJT_HAVE_TRANSPARENT_PROXY)
static njt_int_t njt_event_connect_set_transparent(njt_peer_connection_t *pc,
    njt_socket_t s);
#endif


njt_int_t
njt_event_connect_peer(njt_peer_connection_t *pc)
{
    int                rc, type, value;
#if (NJT_HAVE_IP_BIND_ADDRESS_NO_PORT || NJT_LINUX)
    in_port_t          port;
#endif
    njt_int_t          event;
    njt_err_t          err;
    njt_uint_t         level;
    njt_socket_t       s;
    njt_event_t       *rev, *wev;
    njt_connection_t  *c;

    rc = pc->get(pc, pc->data);
    if (rc != NJT_OK) {
        return rc;
    }

    type = (pc->type ? pc->type : SOCK_STREAM);

#if (NJT_HAVE_SOCKET_CLOEXEC) // openresty patch
    s = njt_socket(pc->sockaddr->sa_family, type | SOCK_CLOEXEC, 0);

#else
     s = njt_socket(pc->sockaddr->sa_family, type, 0);

#endif // openresty patch end
    // s = njt_socket(pc->sockaddr->sa_family, type, 0); openresty patch

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, pc->log, 0, "%s socket %d",
                   (type == SOCK_STREAM) ? "stream" : "dgram", s);

    if (s == (njt_socket_t) -1) {
        njt_log_error(NJT_LOG_ALERT, pc->log, njt_socket_errno,
                      njt_socket_n " failed");
        return NJT_ERROR;
    }


    c = njt_get_connection(s, pc->log);

    if (c == NULL) {
        if (njt_close_socket(s) == -1) {
            njt_log_error(NJT_LOG_ALERT, pc->log, njt_socket_errno,
                          njt_close_socket_n " failed");
        }

        return NJT_ERROR;
    }

    c->type = type;

    if (pc->rcvbuf) {
        if (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
                       (const void *) &pc->rcvbuf, sizeof(int)) == -1)
        {
            njt_log_error(NJT_LOG_ALERT, pc->log, njt_socket_errno,
                          "setsockopt(SO_RCVBUF) failed");
            goto failed;
        }
    }

    if (pc->so_keepalive) {
        value = 1;

        if (setsockopt(s, SOL_SOCKET, SO_KEEPALIVE,
                       (const void *) &value, sizeof(int))
            == -1)
        {
            njt_log_error(NJT_LOG_ALERT, pc->log, njt_socket_errno,
                          "setsockopt(SO_KEEPALIVE) failed, ignored");
        }
    }

    if (njt_nonblocking(s) == -1) {
        njt_log_error(NJT_LOG_ALERT, pc->log, njt_socket_errno,
                      njt_nonblocking_n " failed");

        goto failed;
    }

#if (NJT_HAVE_FD_CLOEXEC) // openresty patch
    if (njt_cloexec(s) == -1) {
        njt_log_error(NJT_LOG_ALERT, pc->log, njt_socket_errno,
                      njt_cloexec_n " failed");

        goto failed;
    }
#endif // openresty patch end

    if (pc->local) {

#if (NJT_HAVE_TRANSPARENT_PROXY)
        if (pc->transparent) {
            if (njt_event_connect_set_transparent(pc, s) != NJT_OK) {
                goto failed;
            }
        }
#endif

#if (NJT_HAVE_IP_BIND_ADDRESS_NO_PORT || NJT_LINUX)
        port = njt_inet_get_port(pc->local->sockaddr);
#endif

#if (NJT_HAVE_IP_BIND_ADDRESS_NO_PORT)

        if (pc->sockaddr->sa_family != AF_UNIX && port == 0) {
            static int  bind_address_no_port = 1;

            if (bind_address_no_port) {
                if (setsockopt(s, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT,
                               (const void *) &bind_address_no_port,
                               sizeof(int)) == -1)
                {
                    err = njt_socket_errno;

                    if (err != NJT_EOPNOTSUPP && err != NJT_ENOPROTOOPT) {
                        njt_log_error(NJT_LOG_ALERT, pc->log, err,
                                      "setsockopt(IP_BIND_ADDRESS_NO_PORT) "
                                      "failed, ignored");

                    } else {
                        bind_address_no_port = 0;
                    }
                }
            }
        }

#endif

#if (NJT_LINUX)

        if (pc->type == SOCK_DGRAM && port != 0) {
            int  reuse_addr = 1;

            if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                           (const void *) &reuse_addr, sizeof(int))
                 == -1)
            {
                njt_log_error(NJT_LOG_ALERT, pc->log, njt_socket_errno,
                              "setsockopt(SO_REUSEADDR) failed");
                goto failed;
            }
        }

#endif

        if (bind(s, pc->local->sockaddr, pc->local->socklen) == -1) {
            njt_log_error(NJT_LOG_CRIT, pc->log, njt_socket_errno,
                          "bind(%V) failed", &pc->local->name);

            goto failed;
        }
    }

    if (type == SOCK_STREAM) {
        c->recv = njt_recv;
        c->send = njt_send;
        c->recv_chain = njt_recv_chain;
        c->send_chain = njt_send_chain;

        c->sendfile = 1;

        if (pc->sockaddr->sa_family == AF_UNIX) {
            c->tcp_nopush = NJT_TCP_NOPUSH_DISABLED;
            c->tcp_nodelay = NJT_TCP_NODELAY_DISABLED;

#if (NJT_SOLARIS)
            /* Solaris's sendfilev() supports AF_NCA, AF_INET, and AF_INET6 */
            c->sendfile = 0;
#endif
        }

    } else { /* type == SOCK_DGRAM */
        c->recv = njt_udp_recv;
        c->send = njt_send;
        c->send_chain = njt_udp_send_chain;

        c->need_flush_buf = 1;
    }

    c->log_error = pc->log_error;

    rev = c->read;
    wev = c->write;

    rev->log = pc->log;
    wev->log = pc->log;

    pc->connection = c;

    c->number = njt_atomic_fetch_add(njt_connection_counter, 1);

    c->start_time = njt_current_msec;

    if (njt_add_conn) {
        if (njt_add_conn(c) == NJT_ERROR) {
            goto failed;
        }
    }

    njt_log_debug3(NJT_LOG_DEBUG_EVENT, pc->log, 0,
                   "connect to %V, fd:%d #%uA", pc->name, s, c->number);

    rc = connect(s, pc->sockaddr, pc->socklen);

    if (rc == -1) {
        err = njt_socket_errno;


        if (err != NJT_EINPROGRESS
#if (NJT_WIN32)
            /* Winsock returns WSAEWOULDBLOCK (NJT_EAGAIN) */
            && err != NJT_EAGAIN
#endif
            )
        {
            if (err == NJT_ECONNREFUSED
#if (NJT_LINUX)
                /*
                 * Linux returns EAGAIN instead of ECONNREFUSED
                 * for unix sockets if listen queue is full
                 */
                || err == NJT_EAGAIN
#endif
                || err == NJT_ECONNRESET
                || err == NJT_ENETDOWN
                || err == NJT_ENETUNREACH
                || err == NJT_EHOSTDOWN
                || err == NJT_EHOSTUNREACH)
            {
                level = NJT_LOG_ERR;

            } else {
                level = NJT_LOG_CRIT;
            }

            njt_log_error(level, c->log, err, "connect() to %V failed",
                          pc->name);

            njt_close_connection(c);
            pc->connection = NULL;

            return NJT_DECLINED;
        }
    }

    if (njt_add_conn) {
        if (rc == -1) {

            /* NJT_EINPROGRESS */

            return NJT_AGAIN;
        }

        njt_log_debug0(NJT_LOG_DEBUG_EVENT, pc->log, 0, "connected");

        wev->ready = 1;

        return NJT_OK;
    }

    if (njt_event_flags & NJT_USE_IOCP_EVENT) {

        njt_log_debug1(NJT_LOG_DEBUG_EVENT, pc->log, njt_socket_errno,
                       "connect(): %d", rc);

        if (njt_blocking(s) == -1) {
            njt_log_error(NJT_LOG_ALERT, pc->log, njt_socket_errno,
                          njt_blocking_n " failed");
            goto failed;
        }

        /*
         * FreeBSD's aio allows to post an operation on non-connected socket.
         * NT does not support it.
         *
         * TODO: check in Win32, etc. As workaround we can use NJT_ONESHOT_EVENT
         */

        rev->ready = 1;
        wev->ready = 1;

        return NJT_OK;
    }

    if (njt_event_flags & NJT_USE_CLEAR_EVENT) {

        /* kqueue */

        event = NJT_CLEAR_EVENT;

    } else {

        /* select, poll, /dev/poll */

        event = NJT_LEVEL_EVENT;
    }

    if (njt_add_event(rev, NJT_READ_EVENT, event) != NJT_OK) {
        goto failed;
    }

    if (rc == -1) {

        /* NJT_EINPROGRESS */

        if (njt_add_event(wev, NJT_WRITE_EVENT, event) != NJT_OK) {
            goto failed;
        }

        return NJT_AGAIN;
    }

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, pc->log, 0, "connected");

    wev->ready = 1;

    return NJT_OK;

failed:

    njt_close_connection(c);
    pc->connection = NULL;

    return NJT_ERROR;
}


#if (NJT_HAVE_TRANSPARENT_PROXY)

static njt_int_t
njt_event_connect_set_transparent(njt_peer_connection_t *pc, njt_socket_t s)
{
    int  value;

    value = 1;

#if defined(SO_BINDANY)

    if (setsockopt(s, SOL_SOCKET, SO_BINDANY,
                   (const void *) &value, sizeof(int)) == -1)
    {
        njt_log_error(NJT_LOG_ALERT, pc->log, njt_socket_errno,
                      "setsockopt(SO_BINDANY) failed");
        return NJT_ERROR;
    }

#else

    switch (pc->local->sockaddr->sa_family) {

    case AF_INET:

#if defined(IP_TRANSPARENT)

        if (setsockopt(s, IPPROTO_IP, IP_TRANSPARENT,
                       (const void *) &value, sizeof(int)) == -1)
        {
            njt_log_error(NJT_LOG_ALERT, pc->log, njt_socket_errno,
                          "setsockopt(IP_TRANSPARENT) failed");
            return NJT_ERROR;
        }

#elif defined(IP_BINDANY)

        if (setsockopt(s, IPPROTO_IP, IP_BINDANY,
                       (const void *) &value, sizeof(int)) == -1)
        {
            njt_log_error(NJT_LOG_ALERT, pc->log, njt_socket_errno,
                          "setsockopt(IP_BINDANY) failed");
            return NJT_ERROR;
        }

#endif

        break;

#if (NJT_HAVE_INET6)

    case AF_INET6:

#if defined(IPV6_TRANSPARENT)

        if (setsockopt(s, IPPROTO_IPV6, IPV6_TRANSPARENT,
                       (const void *) &value, sizeof(int)) == -1)
        {
            njt_log_error(NJT_LOG_ALERT, pc->log, njt_socket_errno,
                          "setsockopt(IPV6_TRANSPARENT) failed");
            return NJT_ERROR;
        }

#elif defined(IPV6_BINDANY)

        if (setsockopt(s, IPPROTO_IPV6, IPV6_BINDANY,
                       (const void *) &value, sizeof(int)) == -1)
        {
            njt_log_error(NJT_LOG_ALERT, pc->log, njt_socket_errno,
                          "setsockopt(IPV6_BINDANY) failed");
            return NJT_ERROR;
        }

#else

        njt_log_error(NJT_LOG_ALERT, pc->log, 0,
                      "could not enable transparent proxying for IPv6 "
                      "on this platform");

        return NJT_ERROR;

#endif

        break;

#endif /* NJT_HAVE_INET6 */

    }

#endif /* SO_BINDANY */

    return NJT_OK;
}

#endif


njt_int_t
njt_event_get_peer(njt_peer_connection_t *pc, void *data)
{
    return NJT_OK;
}
