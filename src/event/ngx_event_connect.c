
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>


#if (NJET_HAVE_TRANSPARENT_PROXY)
static ngx_int_t ngx_event_connect_set_transparent(ngx_peer_connection_t *pc,
    ngx_socket_t s);
#endif


ngx_int_t
ngx_event_connect_peer(ngx_peer_connection_t *pc)
{
    int                rc, type, value;
#if (NJET_HAVE_IP_BIND_ADDRESS_NO_PORT || NJET_LINUX)
    in_port_t          port;
#endif
    ngx_int_t          event;
    ngx_err_t          err;
    ngx_uint_t         level;
    ngx_socket_t       s;
    ngx_event_t       *rev, *wev;
    ngx_connection_t  *c;

    rc = pc->get(pc, pc->data);
    if (rc != NJET_OK) {
        return rc;
    }

    type = (pc->type ? pc->type : SOCK_STREAM);

    s = ngx_socket(pc->sockaddr->sa_family, type, 0);

    ngx_log_debug2(NJET_LOG_DEBUG_EVENT, pc->log, 0, "%s socket %d",
                   (type == SOCK_STREAM) ? "stream" : "dgram", s);

    if (s == (ngx_socket_t) -1) {
        ngx_log_error(NJET_LOG_ALERT, pc->log, ngx_socket_errno,
                      ngx_socket_n " failed");
        return NJET_ERROR;
    }


    c = ngx_get_connection(s, pc->log);

    if (c == NULL) {
        if (ngx_close_socket(s) == -1) {
            ngx_log_error(NJET_LOG_ALERT, pc->log, ngx_socket_errno,
                          ngx_close_socket_n " failed");
        }

        return NJET_ERROR;
    }

    c->type = type;

    if (pc->rcvbuf) {
        if (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
                       (const void *) &pc->rcvbuf, sizeof(int)) == -1)
        {
            ngx_log_error(NJET_LOG_ALERT, pc->log, ngx_socket_errno,
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
            ngx_log_error(NJET_LOG_ALERT, pc->log, ngx_socket_errno,
                          "setsockopt(SO_KEEPALIVE) failed, ignored");
        }
    }

    if (ngx_nonblocking(s) == -1) {
        ngx_log_error(NJET_LOG_ALERT, pc->log, ngx_socket_errno,
                      ngx_nonblocking_n " failed");

        goto failed;
    }

    if (pc->local) {

#if (NJET_HAVE_TRANSPARENT_PROXY)
        if (pc->transparent) {
            if (ngx_event_connect_set_transparent(pc, s) != NJET_OK) {
                goto failed;
            }
        }
#endif

#if (NJET_HAVE_IP_BIND_ADDRESS_NO_PORT || NJET_LINUX)
        port = ngx_inet_get_port(pc->local->sockaddr);
#endif

#if (NJET_HAVE_IP_BIND_ADDRESS_NO_PORT)

        if (pc->sockaddr->sa_family != AF_UNIX && port == 0) {
            static int  bind_address_no_port = 1;

            if (bind_address_no_port) {
                if (setsockopt(s, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT,
                               (const void *) &bind_address_no_port,
                               sizeof(int)) == -1)
                {
                    err = ngx_socket_errno;

                    if (err != NJET_EOPNOTSUPP && err != NJET_ENOPROTOOPT) {
                        ngx_log_error(NJET_LOG_ALERT, pc->log, err,
                                      "setsockopt(IP_BIND_ADDRESS_NO_PORT) "
                                      "failed, ignored");

                    } else {
                        bind_address_no_port = 0;
                    }
                }
            }
        }

#endif

#if (NJET_LINUX)

        if (pc->type == SOCK_DGRAM && port != 0) {
            int  reuse_addr = 1;

            if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                           (const void *) &reuse_addr, sizeof(int))
                 == -1)
            {
                ngx_log_error(NJET_LOG_ALERT, pc->log, ngx_socket_errno,
                              "setsockopt(SO_REUSEADDR) failed");
                goto failed;
            }
        }

#endif

        if (bind(s, pc->local->sockaddr, pc->local->socklen) == -1) {
            ngx_log_error(NJET_LOG_CRIT, pc->log, ngx_socket_errno,
                          "bind(%V) failed", &pc->local->name);

            goto failed;
        }
    }

    if (type == SOCK_STREAM) {
        c->recv = ngx_recv;
        c->send = ngx_send;
        c->recv_chain = ngx_recv_chain;
        c->send_chain = ngx_send_chain;

        c->sendfile = 1;

        if (pc->sockaddr->sa_family == AF_UNIX) {
            c->tcp_nopush = NJET_TCP_NOPUSH_DISABLED;
            c->tcp_nodelay = NJET_TCP_NODELAY_DISABLED;

#if (NJET_SOLARIS)
            /* Solaris's sendfilev() supports AF_NCA, AF_INET, and AF_INET6 */
            c->sendfile = 0;
#endif
        }

    } else { /* type == SOCK_DGRAM */
        c->recv = ngx_udp_recv;
        c->send = ngx_send;
        c->send_chain = ngx_udp_send_chain;

        c->need_flush_buf = 1;
    }

    c->log_error = pc->log_error;

    rev = c->read;
    wev = c->write;

    rev->log = pc->log;
    wev->log = pc->log;

    pc->connection = c;

    c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

    c->start_time = ngx_current_msec;

    if (ngx_add_conn) {
        if (ngx_add_conn(c) == NJET_ERROR) {
            goto failed;
        }
    }

    ngx_log_debug3(NJET_LOG_DEBUG_EVENT, pc->log, 0,
                   "connect to %V, fd:%d #%uA", pc->name, s, c->number);

    rc = connect(s, pc->sockaddr, pc->socklen);

    if (rc == -1) {
        err = ngx_socket_errno;


        if (err != NJET_EINPROGRESS
#if (NJET_WIN32)
            /* Winsock returns WSAEWOULDBLOCK (NJET_EAGAIN) */
            && err != NJET_EAGAIN
#endif
            )
        {
            if (err == NJET_ECONNREFUSED
#if (NJET_LINUX)
                /*
                 * Linux returns EAGAIN instead of ECONNREFUSED
                 * for unix sockets if listen queue is full
                 */
                || err == NJET_EAGAIN
#endif
                || err == NJET_ECONNRESET
                || err == NJET_ENETDOWN
                || err == NJET_ENETUNREACH
                || err == NJET_EHOSTDOWN
                || err == NJET_EHOSTUNREACH)
            {
                level = NJET_LOG_ERR;

            } else {
                level = NJET_LOG_CRIT;
            }

            ngx_log_error(level, c->log, err, "connect() to %V failed",
                          pc->name);

            ngx_close_connection(c);
            pc->connection = NULL;

            return NJET_DECLINED;
        }
    }

    if (ngx_add_conn) {
        if (rc == -1) {

            /* NJET_EINPROGRESS */

            return NJET_AGAIN;
        }

        ngx_log_debug0(NJET_LOG_DEBUG_EVENT, pc->log, 0, "connected");

        wev->ready = 1;

        return NJET_OK;
    }

    if (ngx_event_flags & NJET_USE_IOCP_EVENT) {

        ngx_log_debug1(NJET_LOG_DEBUG_EVENT, pc->log, ngx_socket_errno,
                       "connect(): %d", rc);

        if (ngx_blocking(s) == -1) {
            ngx_log_error(NJET_LOG_ALERT, pc->log, ngx_socket_errno,
                          ngx_blocking_n " failed");
            goto failed;
        }

        /*
         * FreeBSD's aio allows to post an operation on non-connected socket.
         * NT does not support it.
         *
         * TODO: check in Win32, etc. As workaround we can use NJET_ONESHOT_EVENT
         */

        rev->ready = 1;
        wev->ready = 1;

        return NJET_OK;
    }

    if (ngx_event_flags & NJET_USE_CLEAR_EVENT) {

        /* kqueue */

        event = NJET_CLEAR_EVENT;

    } else {

        /* select, poll, /dev/poll */

        event = NJET_LEVEL_EVENT;
    }

    if (ngx_add_event(rev, NJET_READ_EVENT, event) != NJET_OK) {
        goto failed;
    }

    if (rc == -1) {

        /* NJET_EINPROGRESS */

        if (ngx_add_event(wev, NJET_WRITE_EVENT, event) != NJET_OK) {
            goto failed;
        }

        return NJET_AGAIN;
    }

    ngx_log_debug0(NJET_LOG_DEBUG_EVENT, pc->log, 0, "connected");

    wev->ready = 1;

    return NJET_OK;

failed:

    ngx_close_connection(c);
    pc->connection = NULL;

    return NJET_ERROR;
}


#if (NJET_HAVE_TRANSPARENT_PROXY)

static ngx_int_t
ngx_event_connect_set_transparent(ngx_peer_connection_t *pc, ngx_socket_t s)
{
    int  value;

    value = 1;

#if defined(SO_BINDANY)

    if (setsockopt(s, SOL_SOCKET, SO_BINDANY,
                   (const void *) &value, sizeof(int)) == -1)
    {
        ngx_log_error(NJET_LOG_ALERT, pc->log, ngx_socket_errno,
                      "setsockopt(SO_BINDANY) failed");
        return NJET_ERROR;
    }

#else

    switch (pc->local->sockaddr->sa_family) {

    case AF_INET:

#if defined(IP_TRANSPARENT)

        if (setsockopt(s, IPPROTO_IP, IP_TRANSPARENT,
                       (const void *) &value, sizeof(int)) == -1)
        {
            ngx_log_error(NJET_LOG_ALERT, pc->log, ngx_socket_errno,
                          "setsockopt(IP_TRANSPARENT) failed");
            return NJET_ERROR;
        }

#elif defined(IP_BINDANY)

        if (setsockopt(s, IPPROTO_IP, IP_BINDANY,
                       (const void *) &value, sizeof(int)) == -1)
        {
            ngx_log_error(NJET_LOG_ALERT, pc->log, ngx_socket_errno,
                          "setsockopt(IP_BINDANY) failed");
            return NJET_ERROR;
        }

#endif

        break;

#if (NJET_HAVE_INET6)

    case AF_INET6:

#if defined(IPV6_TRANSPARENT)

        if (setsockopt(s, IPPROTO_IPV6, IPV6_TRANSPARENT,
                       (const void *) &value, sizeof(int)) == -1)
        {
            ngx_log_error(NJET_LOG_ALERT, pc->log, ngx_socket_errno,
                          "setsockopt(IPV6_TRANSPARENT) failed");
            return NJET_ERROR;
        }

#elif defined(IPV6_BINDANY)

        if (setsockopt(s, IPPROTO_IPV6, IPV6_BINDANY,
                       (const void *) &value, sizeof(int)) == -1)
        {
            ngx_log_error(NJET_LOG_ALERT, pc->log, ngx_socket_errno,
                          "setsockopt(IPV6_BINDANY) failed");
            return NJET_ERROR;
        }

#else

        ngx_log_error(NJET_LOG_ALERT, pc->log, 0,
                      "could not enable transparent proxying for IPv6 "
                      "on this platform");

        return NJET_ERROR;

#endif

        break;

#endif /* NJET_HAVE_INET6 */

    }

#endif /* SO_BINDANY */

    return NJET_OK;
}

#endif


ngx_int_t
ngx_event_get_peer(ngx_peer_connection_t *pc, void *data)
{
    return NJET_OK;
}
