
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


static njt_int_t njt_disable_accept_events(njt_cycle_t *cycle, njt_uint_t all);
#if (NJT_HAVE_EPOLLEXCLUSIVE)
static void njt_reorder_accept_events(njt_listening_t *ls);
#endif
static void njt_close_accepted_connection(njt_connection_t *c);


void
njt_event_accept(njt_event_t *ev)
{
    socklen_t          socklen;
    njt_err_t          err;
    njt_log_t         *log;
    njt_uint_t         level;
    njt_socket_t       s;
    njt_event_t       *rev, *wev;
    njt_sockaddr_t     sa;
    njt_listening_t   *ls;
    njt_connection_t  *c, *lc;
    njt_event_conf_t  *ecf;
#if (NJT_HAVE_ACCEPT4)
    static njt_uint_t  use_accept4 = 1;
#endif

    if (ev->timedout) {
        if (njt_enable_accept_events((njt_cycle_t *) njt_cycle) != NJT_OK) {
            return;
        }

        ev->timedout = 0;
    }

    ecf = njt_event_get_conf(njt_cycle->conf_ctx, njt_event_core_module);

    if (!(njt_event_flags & NJT_USE_KQUEUE_EVENT)) {
        ev->available = ecf->multi_accept;
    }

    lc = ev->data;
    ls = lc->listening;
    ev->ready = 0;

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                   "accept on %V, ready: %d", &ls->addr_text, ev->available);

    do {
        socklen = sizeof(njt_sockaddr_t);

#if (NJT_HAVE_ACCEPT4)
        if (use_accept4) {
            // s = accept4(lc->fd, &sa.sockaddr, &socklen, SOCK_NONBLOCK); openresty patch
            s = accept4(lc->fd, &sa.sockaddr, &socklen, 
                        SOCK_NONBLOCK | SOCK_CLOEXEC); // openresty patch

        } else {
            s = accept(lc->fd, &sa.sockaddr, &socklen);
        }
#else
        s = accept(lc->fd, &sa.sockaddr, &socklen);
#endif

        if (s == (njt_socket_t) -1) {
            err = njt_socket_errno;

            if (err == NJT_EAGAIN) {
                njt_log_debug0(NJT_LOG_DEBUG_EVENT, ev->log, err,
                               "accept() not ready");
                return;
            }

            level = NJT_LOG_ALERT;

            if (err == NJT_ECONNABORTED) {
                level = NJT_LOG_ERR;

            } else if (err == NJT_EMFILE || err == NJT_ENFILE) {
                level = NJT_LOG_CRIT;
            }

#if (NJT_HAVE_ACCEPT4)
            njt_log_error(level, ev->log, err,
                          use_accept4 ? "accept4() failed" : "accept() failed");

            if (use_accept4 && err == NJT_ENOSYS) {
                use_accept4 = 0;
                njt_inherited_nonblocking = 0;
                continue;
            }
#else
            njt_log_error(level, ev->log, err, "accept() failed");
#endif

            if (err == NJT_ECONNABORTED) {
                if (njt_event_flags & NJT_USE_KQUEUE_EVENT) {
                    ev->available--;
                }

                if (ev->available) {
                    continue;
                }
            }

            if (err == NJT_EMFILE || err == NJT_ENFILE) {
                if (njt_disable_accept_events((njt_cycle_t *) njt_cycle, 1)
                    != NJT_OK)
                {
                    return;
                }

                if (njt_use_accept_mutex) {
                    if (njt_accept_mutex_held) {
                        njt_shmtx_unlock(&njt_accept_mutex);
                        njt_accept_mutex_held = 0;
                    }

                    njt_accept_disabled = 1;

                } else {
                    njt_add_timer(ev, ecf->accept_mutex_delay);
                }
            }

            return;
        }

#if (NJT_STAT_STUB)
        (void) njt_atomic_fetch_add(njt_stat_accepted, 1);
#endif

        njt_accept_disabled = njt_cycle->connection_n / 8
                              - njt_cycle->free_connection_n;

        c = njt_get_connection(s, ev->log);

        if (c == NULL) {
            if (njt_close_socket(s) == -1) {
                njt_log_error(NJT_LOG_ALERT, ev->log, njt_socket_errno,
                              njt_close_socket_n " failed");
            }

            return;
        }

        c->type = SOCK_STREAM;

#if (NJT_STAT_STUB)
        (void) njt_atomic_fetch_add(njt_stat_active, 1);
#endif

        c->pool = njt_create_pool(ls->pool_size, ev->log);
        if (c->pool == NULL) {
            njt_close_accepted_connection(c);
            return;
        }

        if (socklen > (socklen_t) sizeof(njt_sockaddr_t)) {
            socklen = sizeof(njt_sockaddr_t);
        }

        c->sockaddr = njt_palloc(c->pool, socklen);
        if (c->sockaddr == NULL) {
            njt_close_accepted_connection(c);
            return;
        }

        njt_memcpy(c->sockaddr, &sa, socklen);

        log = njt_palloc(c->pool, sizeof(njt_log_t));
        if (log == NULL) {
            njt_close_accepted_connection(c);
            return;
        }

        /* set a blocking mode for iocp and non-blocking mode for others */

        if (njt_inherited_nonblocking) {
            if (njt_event_flags & NJT_USE_IOCP_EVENT) {
                if (njt_blocking(s) == -1) {
                    njt_log_error(NJT_LOG_ALERT, ev->log, njt_socket_errno,
                                  njt_blocking_n " failed");
                    njt_close_accepted_connection(c);
                    return;
                }
            }

        } else {
            if (!(njt_event_flags & NJT_USE_IOCP_EVENT)) {
                if (njt_nonblocking(s) == -1) {
                    njt_log_error(NJT_LOG_ALERT, ev->log, njt_socket_errno,
                                  njt_nonblocking_n " failed");
                    njt_close_accepted_connection(c);
                    return;
                }

#if (NJT_HAVE_FD_CLOEXEC) // openresty patch
                if (njt_cloexec(s) == -1) {
                    njt_log_error(NJT_LOG_ALERT, ev->log, njt_socket_errno,
                                  njt_cloexec_n " failed");
                    njt_close_accepted_connection(c);
                    return;
                }
#endif // openresty patch end

            }
        }

        *log = ls->log;

        c->recv = njt_recv;
        c->send = njt_send;
        c->recv_chain = njt_recv_chain;
        c->send_chain = njt_send_chain;

        c->log = log;
        c->pool->log = log;

        c->socklen = socklen;
        c->listening = ls;
        c->local_sockaddr = ls->sockaddr;
        c->local_socklen = ls->socklen;

#if (NJT_HAVE_UNIX_DOMAIN)
        if (c->sockaddr->sa_family == AF_UNIX) {
            c->tcp_nopush = NJT_TCP_NOPUSH_DISABLED;
            c->tcp_nodelay = NJT_TCP_NODELAY_DISABLED;
#if (NJT_SOLARIS)
            /* Solaris's sendfilev() supports AF_NCA, AF_INET, and AF_INET6 */
            c->sendfile = 0;
#endif
        }
#endif

        rev = c->read;
        wev = c->write;

        wev->ready = 1;

        if (njt_event_flags & NJT_USE_IOCP_EVENT) {
            rev->ready = 1;
        }

        if (ev->deferred_accept) {
            rev->ready = 1;
#if (NJT_HAVE_KQUEUE || NJT_HAVE_EPOLLRDHUP)
            rev->available = 1;
#endif
        }

        rev->log = log;
        wev->log = log;

        /*
         * TODO: MT: - njt_atomic_fetch_add()
         *             or protection by critical section or light mutex
         *
         * TODO: MP: - allocated in a shared memory
         *           - njt_atomic_fetch_add()
         *             or protection by critical section or light mutex
         */

        c->number = njt_atomic_fetch_add(njt_connection_counter, 1);

        c->start_time = njt_current_msec;

#if (NJT_STAT_STUB)
        (void) njt_atomic_fetch_add(njt_stat_handled, 1);
#endif

        if (ls->addr_ntop) {
            c->addr_text.data = njt_pnalloc(c->pool, ls->addr_text_max_len);
            if (c->addr_text.data == NULL) {
                njt_close_accepted_connection(c);
                return;
            }

            c->addr_text.len = njt_sock_ntop(c->sockaddr, c->socklen,
                                             c->addr_text.data,
                                             ls->addr_text_max_len, 0);
            if (c->addr_text.len == 0) {
                njt_close_accepted_connection(c);
                return;
            }
        }

#if (NJT_DEBUG)
        {
        njt_str_t  addr;
        u_char     text[NJT_SOCKADDR_STRLEN];

        njt_debug_accepted_connection(ecf, c);

        if (log->log_level & NJT_LOG_DEBUG_EVENT) {
            addr.data = text;
            addr.len = njt_sock_ntop(c->sockaddr, c->socklen, text,
                                     NJT_SOCKADDR_STRLEN, 1);

            njt_log_debug3(NJT_LOG_DEBUG_EVENT, log, 0,
                           "*%uA accept: %V fd:%d", c->number, &addr, s);
        }

        }
#endif

        if (njt_add_conn && (njt_event_flags & NJT_USE_EPOLL_EVENT) == 0) {
            if (njt_add_conn(c) == NJT_ERROR) {
                njt_close_accepted_connection(c);
                return;
            }
        }

        log->data = NULL;
        log->handler = NULL;

        ls->handler(c);

        if (njt_event_flags & NJT_USE_KQUEUE_EVENT) {
            ev->available--;
        }

    } while (ev->available);

#if (NJT_HAVE_EPOLLEXCLUSIVE)
    njt_reorder_accept_events(ls);
#endif
}


njt_int_t
njt_trylock_accept_mutex(njt_cycle_t *cycle)
{
    if (njt_shmtx_trylock(&njt_accept_mutex)) {

        njt_log_debug0(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                       "accept mutex locked");

        if (njt_accept_mutex_held && njt_accept_events == 0) {
            return NJT_OK;
        }

        if (njt_enable_accept_events(cycle) == NJT_ERROR) {
            njt_shmtx_unlock(&njt_accept_mutex);
            return NJT_ERROR;
        }

        njt_accept_events = 0;
        njt_accept_mutex_held = 1;

        return NJT_OK;
    }

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                   "accept mutex lock failed: %ui", njt_accept_mutex_held);

    if (njt_accept_mutex_held) {
        if (njt_disable_accept_events(cycle, 0) == NJT_ERROR) {
            return NJT_ERROR;
        }

        njt_accept_mutex_held = 0;
    }

    return NJT_OK;
}


njt_int_t
njt_enable_accept_events(njt_cycle_t *cycle)
{
    njt_uint_t         i;
    njt_listening_t   *ls;
    njt_connection_t  *c;

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

        c = ls[i].connection;

        if (c == NULL || c->read->active) {
            continue;
        }

        if (njt_add_event(c->read, NJT_READ_EVENT, 0) == NJT_ERROR) {
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


static njt_int_t
njt_disable_accept_events(njt_cycle_t *cycle, njt_uint_t all)
{
    njt_uint_t         i;
    njt_listening_t   *ls;
    njt_connection_t  *c;

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

        c = ls[i].connection;

        if (c == NULL || !c->read->active) {
            continue;
        }

#if (NJT_HAVE_REUSEPORT)

        /*
         * do not disable accept on worker's own sockets
         * when disabling accept events due to accept mutex
         */

        if (ls[i].reuseport && !all) {
            continue;
        }

#endif

        if (njt_del_event(c->read, NJT_READ_EVENT, NJT_DISABLE_EVENT)
            == NJT_ERROR)
        {
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


#if (NJT_HAVE_EPOLLEXCLUSIVE)

static void
njt_reorder_accept_events(njt_listening_t *ls)
{
    njt_connection_t  *c;

    /*
     * Linux with EPOLLEXCLUSIVE usually notifies only the process which
     * was first to add the listening socket to the epoll instance.  As
     * a result most of the connections are handled by the first worker
     * process.  To fix this, we re-add the socket periodically, so other
     * workers will get a chance to accept connections.
     */

    if (!njt_use_exclusive_accept) {
        return;
    }

#if (NJT_HAVE_REUSEPORT)

    if (ls->reuseport) {
        return;
    }

#endif

    c = ls->connection;

    if (c->requests++ % 16 != 0
        && njt_accept_disabled <= 0)
    {
        return;
    }

    if (njt_del_event(c->read, NJT_READ_EVENT, NJT_DISABLE_EVENT)
        == NJT_ERROR)
    {
        return;
    }

    if (njt_add_event(c->read, NJT_READ_EVENT, NJT_EXCLUSIVE_EVENT)
        == NJT_ERROR)
    {
        return;
    }
}

#endif


static void
njt_close_accepted_connection(njt_connection_t *c)
{
    njt_socket_t  fd;

    njt_free_connection(c);

    fd = c->fd;
    c->fd = (njt_socket_t) -1;

    if (njt_close_socket(fd) == -1) {
        njt_log_error(NJT_LOG_ALERT, c->log, njt_socket_errno,
                      njt_close_socket_n " failed");
    }

    if (c->pool) {
        njt_destroy_pool(c->pool);
    }

#if (NJT_STAT_STUB)
    (void) njt_atomic_fetch_add(njt_stat_active, -1);
#endif
}


u_char *
njt_accept_log_error(njt_log_t *log, u_char *buf, size_t len)
{
    return njt_snprintf(buf, len, " while accepting new connection on %V",
                        log->data);
}


#if (NJT_DEBUG)

void
njt_debug_accepted_connection(njt_event_conf_t *ecf, njt_connection_t *c)
{
    struct sockaddr_in   *sin;
    njt_cidr_t           *cidr;
    njt_uint_t            i;
#if (NJT_HAVE_INET6)
    struct sockaddr_in6  *sin6;
    njt_uint_t            n;
#endif

    cidr = ecf->debug_connection.elts;
    for (i = 0; i < ecf->debug_connection.nelts; i++) {
        if (cidr[i].family != (njt_uint_t) c->sockaddr->sa_family) {
            goto next;
        }

        switch (cidr[i].family) {

#if (NJT_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) c->sockaddr;
            for (n = 0; n < 16; n++) {
                if ((sin6->sin6_addr.s6_addr[n]
                    & cidr[i].u.in6.mask.s6_addr[n])
                    != cidr[i].u.in6.addr.s6_addr[n])
                {
                    goto next;
                }
            }
            break;
#endif

#if (NJT_HAVE_UNIX_DOMAIN)
        case AF_UNIX:
            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) c->sockaddr;
            if ((sin->sin_addr.s_addr & cidr[i].u.in.mask)
                != cidr[i].u.in.addr)
            {
                goto next;
            }
            break;
        }

        c->log->log_level = NJT_LOG_DEBUG_CONNECTION|NJT_LOG_DEBUG_ALL;
        break;

    next:
        continue;
    }
}

#endif
