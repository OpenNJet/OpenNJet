
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


njt_os_io_t  njt_io;


static void njt_drain_connections(njt_cycle_t *cycle);


njt_listening_t *
njt_create_listening(njt_conf_t *cf, struct sockaddr *sockaddr,
    socklen_t socklen)
{
    size_t            len;
    njt_listening_t  *ls;
    struct sockaddr  *sa;
    u_char            text[NJT_SOCKADDR_STRLEN];

    ls = njt_array_push(&cf->cycle->listening);
    if (ls == NULL) {
        return NULL;
    }
    njt_memzero(ls, sizeof(njt_listening_t));

    sa = njt_palloc(cf->pool, socklen);
    if (sa == NULL) {
        return NULL;
    }

    njt_memcpy(sa, sockaddr, socklen);

    ls->sockaddr = sa;
    ls->socklen = socklen;

    len = njt_sock_ntop(sa, socklen, text, NJT_SOCKADDR_STRLEN, 1);
    ls->addr_text.len = len;

    switch (ls->sockaddr->sa_family) {
#if (NJT_HAVE_INET6)
    case AF_INET6:
        ls->addr_text_max_len = NJT_INET6_ADDRSTRLEN;
        break;
#endif
#if (NJT_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
        ls->addr_text_max_len = NJT_UNIX_ADDRSTRLEN;
        len++;
        break;
#endif
    case AF_INET:
        ls->addr_text_max_len = NJT_INET_ADDRSTRLEN;
        break;
    default:
        ls->addr_text_max_len = NJT_SOCKADDR_STRLEN;
        break;
    }

    ls->addr_text.data = njt_pnalloc(cf->pool, len);
    if (ls->addr_text.data == NULL) {
        return NULL;
    }

    njt_memcpy(ls->addr_text.data, text, len);

#if !(NJT_WIN32)
    njt_rbtree_init(&ls->rbtree, &ls->sentinel, njt_udp_rbtree_insert_value);
#endif


    ls->fd = (njt_socket_t) -1;
    ls->type = SOCK_STREAM;

    ls->backlog = NJT_LISTEN_BACKLOG;
    ls->rcvbuf = -1;
    ls->sndbuf = -1;

#if (NJT_HAVE_SETFIB)
    ls->setfib = -1;
#endif

#if (NJT_HAVE_TCP_FASTOPEN)
    ls->fastopen = -1;
#endif

    return ls;
}


njt_int_t
njt_clone_listening(njt_cycle_t *cycle, njt_listening_t *ls)
{
#if (NJT_HAVE_REUSEPORT)

    njt_int_t         n;
    njt_core_conf_t  *ccf;
    njt_listening_t   ols;

    if (!ls->reuseport || ls->worker != 0) {
        return NJT_OK;
    }

    ols = *ls;

    ccf = (njt_core_conf_t *) njt_get_conf(cycle->conf_ctx, njt_core_module);

    for (n = 1; n < ccf->worker_processes; n++) {

        /* create a socket for each worker process */

        ls = njt_array_push(&cycle->listening);
        if (ls == NULL) {
            return NJT_ERROR;
        }

        *ls = ols;
        ls->worker = n;
    }

#endif

    return NJT_OK;
}


njt_int_t
njt_set_inherited_sockets(njt_cycle_t *cycle)
{
    size_t                     len;
    njt_uint_t                 i;
    njt_listening_t           *ls;
    socklen_t                  olen;
#if (NJT_HAVE_DEFERRED_ACCEPT || NJT_HAVE_TCP_FASTOPEN)
    njt_err_t                  err;
#endif
#if (NJT_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    struct accept_filter_arg   af;
#endif
#if (NJT_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
    int                        timeout;
#endif
#if (NJT_HAVE_REUSEPORT)
    int                        reuseport;
#endif

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

        ls[i].sockaddr = njt_palloc(cycle->pool, sizeof(njt_sockaddr_t));
        if (ls[i].sockaddr == NULL) {
            return NJT_ERROR;
        }

        ls[i].socklen = sizeof(njt_sockaddr_t);
        if (getsockname(ls[i].fd, ls[i].sockaddr, &ls[i].socklen) == -1) {
            njt_log_error(NJT_LOG_CRIT, cycle->log, njt_socket_errno,
                          "getsockname() of the inherited "
                          "socket #%d failed", ls[i].fd);
            ls[i].ignore = 1;
            continue;
        }

        if (ls[i].socklen > (socklen_t) sizeof(njt_sockaddr_t)) {
            ls[i].socklen = sizeof(njt_sockaddr_t);
        }

        switch (ls[i].sockaddr->sa_family) {

#if (NJT_HAVE_INET6)
        case AF_INET6:
            ls[i].addr_text_max_len = NJT_INET6_ADDRSTRLEN;
            len = NJT_INET6_ADDRSTRLEN + sizeof("[]:65535") - 1;
            break;
#endif

#if (NJT_HAVE_UNIX_DOMAIN)
        case AF_UNIX:
            ls[i].addr_text_max_len = NJT_UNIX_ADDRSTRLEN;
            len = NJT_UNIX_ADDRSTRLEN;
            break;
#endif

        case AF_INET:
            ls[i].addr_text_max_len = NJT_INET_ADDRSTRLEN;
            len = NJT_INET_ADDRSTRLEN + sizeof(":65535") - 1;
            break;

        default:
            njt_log_error(NJT_LOG_CRIT, cycle->log, njt_socket_errno,
                          "the inherited socket #%d has "
                          "an unsupported protocol family", ls[i].fd);
            ls[i].ignore = 1;
            continue;
        }

        ls[i].addr_text.data = njt_pnalloc(cycle->pool, len);
        if (ls[i].addr_text.data == NULL) {
            return NJT_ERROR;
        }

        len = njt_sock_ntop(ls[i].sockaddr, ls[i].socklen,
                            ls[i].addr_text.data, len, 1);
        if (len == 0) {
            return NJT_ERROR;
        }

        ls[i].addr_text.len = len;

        ls[i].backlog = NJT_LISTEN_BACKLOG;

        olen = sizeof(int);

        if (getsockopt(ls[i].fd, SOL_SOCKET, SO_TYPE, (void *) &ls[i].type,
                       &olen)
            == -1)
        {
            njt_log_error(NJT_LOG_CRIT, cycle->log, njt_socket_errno,
                          "getsockopt(SO_TYPE) %V failed", &ls[i].addr_text);
            ls[i].ignore = 1;
            continue;
        }

        olen = sizeof(int);

        if (getsockopt(ls[i].fd, SOL_SOCKET, SO_RCVBUF, (void *) &ls[i].rcvbuf,
                       &olen)
            == -1)
        {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_socket_errno,
                          "getsockopt(SO_RCVBUF) %V failed, ignored",
                          &ls[i].addr_text);

            ls[i].rcvbuf = -1;
        }

        olen = sizeof(int);

        if (getsockopt(ls[i].fd, SOL_SOCKET, SO_SNDBUF, (void *) &ls[i].sndbuf,
                       &olen)
            == -1)
        {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_socket_errno,
                          "getsockopt(SO_SNDBUF) %V failed, ignored",
                          &ls[i].addr_text);

            ls[i].sndbuf = -1;
        }

#if 0
        /* SO_SETFIB is currently a set only option */

#if (NJT_HAVE_SETFIB)

        olen = sizeof(int);

        if (getsockopt(ls[i].fd, SOL_SOCKET, SO_SETFIB,
                       (void *) &ls[i].setfib, &olen)
            == -1)
        {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_socket_errno,
                          "getsockopt(SO_SETFIB) %V failed, ignored",
                          &ls[i].addr_text);

            ls[i].setfib = -1;
        }

#endif
#endif

#if (NJT_HAVE_REUSEPORT)

        reuseport = 0;
        olen = sizeof(int);

#ifdef SO_REUSEPORT_LB

        if (getsockopt(ls[i].fd, SOL_SOCKET, SO_REUSEPORT_LB,
                       (void *) &reuseport, &olen)
            == -1)
        {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_socket_errno,
                          "getsockopt(SO_REUSEPORT_LB) %V failed, ignored",
                          &ls[i].addr_text);

        } else {
            ls[i].reuseport = reuseport ? 1 : 0;
        }

#else

        if (getsockopt(ls[i].fd, SOL_SOCKET, SO_REUSEPORT,
                       (void *) &reuseport, &olen)
            == -1)
        {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_socket_errno,
                          "getsockopt(SO_REUSEPORT) %V failed, ignored",
                          &ls[i].addr_text);

        } else {
            ls[i].reuseport = reuseport ? 1 : 0;
        }
#endif

#endif

        if (ls[i].type != SOCK_STREAM) {
            continue;
        }

#if (NJT_HAVE_TCP_FASTOPEN)

        olen = sizeof(int);

        if (getsockopt(ls[i].fd, IPPROTO_TCP, TCP_FASTOPEN,
                       (void *) &ls[i].fastopen, &olen)
            == -1)
        {
            err = njt_socket_errno;

            if (err != NJT_EOPNOTSUPP && err != NJT_ENOPROTOOPT
                && err != NJT_EINVAL)
            {
                njt_log_error(NJT_LOG_NOTICE, cycle->log, err,
                              "getsockopt(TCP_FASTOPEN) %V failed, ignored",
                              &ls[i].addr_text);
            }

            ls[i].fastopen = -1;
        }

#endif

#if (NJT_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)

        njt_memzero(&af, sizeof(struct accept_filter_arg));
        olen = sizeof(struct accept_filter_arg);

        if (getsockopt(ls[i].fd, SOL_SOCKET, SO_ACCEPTFILTER, &af, &olen)
            == -1)
        {
            err = njt_socket_errno;

            if (err == NJT_EINVAL) {
                continue;
            }

            njt_log_error(NJT_LOG_NOTICE, cycle->log, err,
                          "getsockopt(SO_ACCEPTFILTER) for %V failed, ignored",
                          &ls[i].addr_text);
            continue;
        }

        if (olen < sizeof(struct accept_filter_arg) || af.af_name[0] == '\0') {
            continue;
        }

        ls[i].accept_filter = njt_palloc(cycle->pool, 16);
        if (ls[i].accept_filter == NULL) {
            return NJT_ERROR;
        }

        (void) njt_cpystrn((u_char *) ls[i].accept_filter,
                           (u_char *) af.af_name, 16);
#endif

#if (NJT_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)

        timeout = 0;
        olen = sizeof(int);

        if (getsockopt(ls[i].fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &timeout, &olen)
            == -1)
        {
            err = njt_socket_errno;

            if (err == NJT_EOPNOTSUPP) {
                continue;
            }

            njt_log_error(NJT_LOG_NOTICE, cycle->log, err,
                          "getsockopt(TCP_DEFER_ACCEPT) for %V failed, ignored",
                          &ls[i].addr_text);
            continue;
        }

        if (olen < sizeof(int) || timeout == 0) {
            continue;
        }

        ls[i].deferred_accept = 1;
#endif
    }

    return NJT_OK;
}


njt_int_t
njt_open_listening_sockets(njt_cycle_t *cycle)
{
    int               reuseaddr;
    njt_uint_t        i, tries, failed;
    njt_err_t         err;
    njt_log_t        *log;
    njt_socket_t      s;
    njt_listening_t  *ls;

    reuseaddr = 1;
#if (NJT_SUPPRESS_WARN)
    failed = 0;
#endif

    log = cycle->log;

    /* TODO: configurable try number */

    for (tries = 5; tries; tries--) {
        failed = 0;

        /* for each listening socket */

        ls = cycle->listening.elts;
        for (i = 0; i < cycle->listening.nelts; i++) {

            if (ls[i].ignore) {
                continue;
            }

#if (NJT_HAVE_REUSEPORT)

            if (ls[i].add_reuseport) {

                /*
                 * to allow transition from a socket without SO_REUSEPORT
                 * to multiple sockets with SO_REUSEPORT, we have to set
                 * SO_REUSEPORT on the old socket before opening new ones
                 */

                int  reuseport = 1;

#ifdef SO_REUSEPORT_LB

                if (setsockopt(ls[i].fd, SOL_SOCKET, SO_REUSEPORT_LB,
                               (const void *) &reuseport, sizeof(int))
                    == -1)
                {
                    njt_log_error(NJT_LOG_ALERT, cycle->log, njt_socket_errno,
                                  "setsockopt(SO_REUSEPORT_LB) %V failed, "
                                  "ignored",
                                  &ls[i].addr_text);
                }

#else

                if (setsockopt(ls[i].fd, SOL_SOCKET, SO_REUSEPORT,
                               (const void *) &reuseport, sizeof(int))
                    == -1)
                {
                    njt_log_error(NJT_LOG_ALERT, cycle->log, njt_socket_errno,
                                  "setsockopt(SO_REUSEPORT) %V failed, ignored",
                                  &ls[i].addr_text);
                }
#endif

                ls[i].add_reuseport = 0;
            }
#endif

            if (ls[i].fd != (njt_socket_t) -1) {
                continue;
            }

            if (ls[i].inherited) {

                /* TODO: close on exit */
                /* TODO: nonblocking */
                /* TODO: deferred accept */

                continue;
            }

            s = njt_socket(ls[i].sockaddr->sa_family, ls[i].type, 0);

            if (s == (njt_socket_t) -1) {
                njt_log_error(NJT_LOG_EMERG, log, njt_socket_errno,
                              njt_socket_n " %V failed", &ls[i].addr_text);
                return NJT_ERROR;
            }

            //by clb, used for broadcast and udp traffic hack
            if (ls[i].type == SOCK_DGRAM
                && ls[i].sockaddr->sa_family == AF_INET ) 
            {    
                struct sockaddr_in* sin=(struct sockaddr_in*) ls[i].sockaddr;
                uint32_t address = ntohl(sin->sin_addr.s_addr);
                if ((address & 0xF0000000) == 0xE0000000 ) {
                    njt_log_error(NJT_LOG_INFO, log, njt_socket_errno,
                                    "found multcast address %V ",
                                    &ls[i].addr_text);
                    struct ip_mreq mreq;
                    bzero(&mreq, sizeof(struct ip_mreq));
                    //bcopy((void *)sin->sin_addr.s_addr, &mreq.imr_multiaddr.s_addr, sizeof(struct in_addr));
                    mreq.imr_multiaddr.s_addr=sin->sin_addr.s_addr;
                    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
                    if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq,
                            sizeof(struct ip_mreq)) == -1) {
                            njt_log_error(NJT_LOG_EMERG, log, njt_socket_errno,
                                    "setsockopt(ADD_MEMBERSHIP) %V failed",
                                    &ls[i].addr_text);
                            if (njt_close_socket(s) == -1) {
                                    njt_log_error(NJT_LOG_EMERG, log, njt_socket_errno,
                                            njt_close_socket_n " %V failed",
                                    &ls[i].addr_text);
                            }
                            return NJT_ERROR;
                    }
                }

                // add by clb, used for udp traffic hack, need set IP_TRANSPARENT and IP_RECVORIGDSTADDR
                if(ls[i].mesh){
                    int n = 1;
                    if(0 != setsockopt(s, SOL_IP, IP_TRANSPARENT, &n, sizeof(int))){
                                njt_log_error(NJT_LOG_EMERG, log, njt_socket_errno,
                                        "====================set opt transparent error");
                    }

                    n = 1;
                    if(0 != setsockopt(s, IPPROTO_IP, IP_RECVORIGDSTADDR, &n, sizeof(int))){
                                njt_log_error(NJT_LOG_EMERG, log, njt_socket_errno,
                                        "====================set opt IP_RECVORIGDSTADDR error");
                    }
                }
                //end add by clb
            }
            //end


            if (ls[i].type != SOCK_DGRAM || !njt_test_config) {

                if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                               (const void *) &reuseaddr, sizeof(int))
                    == -1)
                {
                    njt_log_error(NJT_LOG_EMERG, log, njt_socket_errno,
                                  "setsockopt(SO_REUSEADDR) %V failed",
                                  &ls[i].addr_text);

                    if (njt_close_socket(s) == -1) {
                        njt_log_error(NJT_LOG_EMERG, log, njt_socket_errno,
                                      njt_close_socket_n " %V failed",
                                      &ls[i].addr_text);
                    }

                    return NJT_ERROR;
                }
            }

#if (NJT_HAVE_REUSEPORT)

            if (ls[i].reuseport && !njt_test_config) {
                int  reuseport;

                reuseport = 1;

#ifdef SO_REUSEPORT_LB

                if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT_LB,
                               (const void *) &reuseport, sizeof(int))
                    == -1)
                {
                    njt_log_error(NJT_LOG_EMERG, log, njt_socket_errno,
                                  "setsockopt(SO_REUSEPORT_LB) %V failed",
                                  &ls[i].addr_text);

                    if (njt_close_socket(s) == -1) {
                        njt_log_error(NJT_LOG_EMERG, log, njt_socket_errno,
                                      njt_close_socket_n " %V failed",
                                      &ls[i].addr_text);
                    }

                    return NJT_ERROR;
                }

#else

                if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT,
                               (const void *) &reuseport, sizeof(int))
                    == -1)
                {
                    njt_log_error(NJT_LOG_EMERG, log, njt_socket_errno,
                                  "setsockopt(SO_REUSEPORT) %V failed",
                                  &ls[i].addr_text);

                    if (njt_close_socket(s) == -1) {
                        njt_log_error(NJT_LOG_EMERG, log, njt_socket_errno,
                                      njt_close_socket_n " %V failed",
                                      &ls[i].addr_text);
                    }

                    return NJT_ERROR;
                }
#endif
            }
#endif

#if (NJT_HAVE_INET6 && defined IPV6_V6ONLY)

            if (ls[i].sockaddr->sa_family == AF_INET6) {
                int  ipv6only;

                ipv6only = ls[i].ipv6only;

                if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY,
                               (const void *) &ipv6only, sizeof(int))
                    == -1)
                {
                    njt_log_error(NJT_LOG_EMERG, log, njt_socket_errno,
                                  "setsockopt(IPV6_V6ONLY) %V failed, ignored",
                                  &ls[i].addr_text);
                }

                //add by clb, used for udp traffic hack, need set IPV6_TRANSPARENT and IPV6_RECVORIGDSTADDR
                if(ls[i].mesh){
                    int n = 1;
                    if(0 != setsockopt(s, SOL_IPV6, IPV6_TRANSPARENT, &n, sizeof(int))){
                                njt_log_error(NJT_LOG_EMERG, log, njt_socket_errno,
                                        "====================set opt transparent error");
                    }

                    n = 1;
                    if(0 != setsockopt(s, IPPROTO_IPV6, IPV6_RECVORIGDSTADDR, &n, sizeof(int))){
                                njt_log_error(NJT_LOG_EMERG, log, njt_socket_errno,
                                        "====================set opt IP_RECVORIGDSTADDR error");
                    }
                }
                //end add by clb
            }
#endif
            /* TODO: close on exit */

            if (!(njt_event_flags & NJT_USE_IOCP_EVENT)) {
                if (njt_nonblocking(s) == -1) {
                    njt_log_error(NJT_LOG_EMERG, log, njt_socket_errno,
                                  njt_nonblocking_n " %V failed",
                                  &ls[i].addr_text);

                    if (njt_close_socket(s) == -1) {
                        njt_log_error(NJT_LOG_EMERG, log, njt_socket_errno,
                                      njt_close_socket_n " %V failed",
                                      &ls[i].addr_text);
                    }

                    return NJT_ERROR;
                }
            }

            njt_log_debug2(NJT_LOG_DEBUG_CORE, log, 0,
                           "bind() %V #%d ", &ls[i].addr_text, s);

            if (bind(s, ls[i].sockaddr, ls[i].socklen) == -1) {
                err = njt_socket_errno;

                if (err != NJT_EADDRINUSE || !njt_test_config) {
                    njt_log_error(NJT_LOG_EMERG, log, err,
                                  "bind() to %V failed", &ls[i].addr_text);
                }

                if (njt_close_socket(s) == -1) {
                    njt_log_error(NJT_LOG_EMERG, log, njt_socket_errno,
                                  njt_close_socket_n " %V failed",
                                  &ls[i].addr_text);
                }

                if (err != NJT_EADDRINUSE) {
                    return NJT_ERROR;
                }

                if (!njt_test_config) {
                    failed = 1;
                }

                continue;
            }

#if (NJT_HAVE_UNIX_DOMAIN)

            if (ls[i].sockaddr->sa_family == AF_UNIX) {
                mode_t   mode;
                u_char  *name;

                name = ls[i].addr_text.data + sizeof("unix:") - 1;
                mode = (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);

                if (chmod((char *) name, mode) == -1) {
                    njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                                  "chmod() \"%s\" failed", name);
                }

                if (njt_test_config) {
                    if (njt_delete_file(name) == NJT_FILE_ERROR) {
                        njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                                      njt_delete_file_n " %s failed", name);
                    }
                }
            }
#endif

            if (ls[i].type != SOCK_STREAM) {
                ls[i].fd = s;
                continue;
            }

            if (listen(s, ls[i].backlog) == -1) {
                err = njt_socket_errno;

                /*
                 * on OpenVZ after suspend/resume EADDRINUSE
                 * may be returned by listen() instead of bind(), see
                 * hhttps://bugs.openvz.org/browse/OVZ-5587                 */

                if (err != NJT_EADDRINUSE || !njt_test_config) {
                    njt_log_error(NJT_LOG_EMERG, log, err,
                                  "listen() to %V, backlog %d failed",
                                  &ls[i].addr_text, ls[i].backlog);
                }

                if (njt_close_socket(s) == -1) {
                    njt_log_error(NJT_LOG_EMERG, log, njt_socket_errno,
                                  njt_close_socket_n " %V failed",
                                  &ls[i].addr_text);
                }

                if (err != NJT_EADDRINUSE) {
                    return NJT_ERROR;
                }

                if (!njt_test_config) {
                    failed = 1;
                }

                continue;
            }

            ls[i].listen = 1;

            ls[i].fd = s;
        }

        if (!failed) {
            break;
        }

        /* TODO: delay configurable */

        njt_log_error(NJT_LOG_NOTICE, log, 0,
                      "try again to bind() after 500ms");

        njt_msleep(500);
    }

    if (failed) {
        njt_log_error(NJT_LOG_EMERG, log, 0, "still could not bind()");
        return NJT_ERROR;
    }

    return NJT_OK;
}


void
njt_configure_listening_sockets(njt_cycle_t *cycle)
{
    int                        value;
    njt_uint_t                 i;
    njt_listening_t           *ls;

#if (NJT_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    struct accept_filter_arg   af;
#endif

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

        ls[i].log = *ls[i].logp;

        if (ls[i].rcvbuf != -1) {
            if (setsockopt(ls[i].fd, SOL_SOCKET, SO_RCVBUF,
                           (const void *) &ls[i].rcvbuf, sizeof(int))
                == -1)
            {
                njt_log_error(NJT_LOG_ALERT, cycle->log, njt_socket_errno,
                              "setsockopt(SO_RCVBUF, %d) %V failed, ignored",
                              ls[i].rcvbuf, &ls[i].addr_text);
            }
        }

        if (ls[i].sndbuf != -1) {
            if (setsockopt(ls[i].fd, SOL_SOCKET, SO_SNDBUF,
                           (const void *) &ls[i].sndbuf, sizeof(int))
                == -1)
            {
                njt_log_error(NJT_LOG_ALERT, cycle->log, njt_socket_errno,
                              "setsockopt(SO_SNDBUF, %d) %V failed, ignored",
                              ls[i].sndbuf, &ls[i].addr_text);
            }
        }

        if (ls[i].keepalive) {
            value = (ls[i].keepalive == 1) ? 1 : 0;

            if (setsockopt(ls[i].fd, SOL_SOCKET, SO_KEEPALIVE,
                           (const void *) &value, sizeof(int))
                == -1)
            {
                njt_log_error(NJT_LOG_ALERT, cycle->log, njt_socket_errno,
                              "setsockopt(SO_KEEPALIVE, %d) %V failed, ignored",
                              value, &ls[i].addr_text);
            }
        }

#if (NJT_HAVE_KEEPALIVE_TUNABLE)

        if (ls[i].keepidle) {
            value = ls[i].keepidle;

#if (NJT_KEEPALIVE_FACTOR)
            value *= NJT_KEEPALIVE_FACTOR;
#endif

            if (setsockopt(ls[i].fd, IPPROTO_TCP, TCP_KEEPIDLE,
                           (const void *) &value, sizeof(int))
                == -1)
            {
                njt_log_error(NJT_LOG_ALERT, cycle->log, njt_socket_errno,
                              "setsockopt(TCP_KEEPIDLE, %d) %V failed, ignored",
                              value, &ls[i].addr_text);
            }
        }

        if (ls[i].keepintvl) {
            value = ls[i].keepintvl;

#if (NJT_KEEPALIVE_FACTOR)
            value *= NJT_KEEPALIVE_FACTOR;
#endif

            if (setsockopt(ls[i].fd, IPPROTO_TCP, TCP_KEEPINTVL,
                           (const void *) &value, sizeof(int))
                == -1)
            {
                njt_log_error(NJT_LOG_ALERT, cycle->log, njt_socket_errno,
                             "setsockopt(TCP_KEEPINTVL, %d) %V failed, ignored",
                             value, &ls[i].addr_text);
            }
        }

        if (ls[i].keepcnt) {
            if (setsockopt(ls[i].fd, IPPROTO_TCP, TCP_KEEPCNT,
                           (const void *) &ls[i].keepcnt, sizeof(int))
                == -1)
            {
                njt_log_error(NJT_LOG_ALERT, cycle->log, njt_socket_errno,
                              "setsockopt(TCP_KEEPCNT, %d) %V failed, ignored",
                              ls[i].keepcnt, &ls[i].addr_text);
            }
        }

#endif

#if (NJT_HAVE_SETFIB)
        if (ls[i].setfib != -1) {
            if (setsockopt(ls[i].fd, SOL_SOCKET, SO_SETFIB,
                           (const void *) &ls[i].setfib, sizeof(int))
                == -1)
            {
                njt_log_error(NJT_LOG_ALERT, cycle->log, njt_socket_errno,
                              "setsockopt(SO_SETFIB, %d) %V failed, ignored",
                              ls[i].setfib, &ls[i].addr_text);
            }
        }
#endif

#if (NJT_HAVE_TCP_FASTOPEN)
        if (ls[i].fastopen != -1) {
            if (setsockopt(ls[i].fd, IPPROTO_TCP, TCP_FASTOPEN,
                           (const void *) &ls[i].fastopen, sizeof(int))
                == -1)
            {
                njt_log_error(NJT_LOG_ALERT, cycle->log, njt_socket_errno,
                              "setsockopt(TCP_FASTOPEN, %d) %V failed, ignored",
                              ls[i].fastopen, &ls[i].addr_text);
            }
        }
#endif

#if 0
        if (1) {
            int tcp_nodelay = 1;

            if (setsockopt(ls[i].fd, IPPROTO_TCP, TCP_NODELAY,
                       (const void *) &tcp_nodelay, sizeof(int))
                == -1)
            {
                njt_log_error(NJT_LOG_ALERT, cycle->log, njt_socket_errno,
                              "setsockopt(TCP_NODELAY) %V failed, ignored",
                              &ls[i].addr_text);
            }
        }
#endif

        if (ls[i].listen) {

            /* change backlog via listen() */

            if (listen(ls[i].fd, ls[i].backlog) == -1) {
                njt_log_error(NJT_LOG_ALERT, cycle->log, njt_socket_errno,
                              "listen() to %V, backlog %d failed, ignored",
                              &ls[i].addr_text, ls[i].backlog);
            }
        }

        /*
         * setting deferred mode should be last operation on socket,
         * because code may prematurely continue cycle on failure
         */

#if (NJT_HAVE_DEFERRED_ACCEPT)

#ifdef SO_ACCEPTFILTER

        if (ls[i].delete_deferred) {
            if (setsockopt(ls[i].fd, SOL_SOCKET, SO_ACCEPTFILTER, NULL, 0)
                == -1)
            {
                njt_log_error(NJT_LOG_ALERT, cycle->log, njt_socket_errno,
                              "setsockopt(SO_ACCEPTFILTER, NULL) "
                              "for %V failed, ignored",
                              &ls[i].addr_text);

                if (ls[i].accept_filter) {
                    njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                                  "could not change the accept filter "
                                  "to \"%s\" for %V, ignored",
                                  ls[i].accept_filter, &ls[i].addr_text);
                }

                continue;
            }

            ls[i].deferred_accept = 0;
        }

        if (ls[i].add_deferred) {
            njt_memzero(&af, sizeof(struct accept_filter_arg));
            (void) njt_cpystrn((u_char *) af.af_name,
                               (u_char *) ls[i].accept_filter, 16);

            if (setsockopt(ls[i].fd, SOL_SOCKET, SO_ACCEPTFILTER,
                           &af, sizeof(struct accept_filter_arg))
                == -1)
            {
                njt_log_error(NJT_LOG_ALERT, cycle->log, njt_socket_errno,
                              "setsockopt(SO_ACCEPTFILTER, \"%s\") "
                              "for %V failed, ignored",
                              ls[i].accept_filter, &ls[i].addr_text);
                continue;
            }

            ls[i].deferred_accept = 1;
        }

#endif

#ifdef TCP_DEFER_ACCEPT

        if (ls[i].add_deferred || ls[i].delete_deferred) {

            if (ls[i].add_deferred) {
                /*
                 * There is no way to find out how long a connection was
                 * in queue (and a connection may bypass deferred queue at all
                 * if syncookies were used), hence we use 1 second timeout
                 * here.
                 */
                value = 1;

            } else {
                value = 0;
            }

            if (setsockopt(ls[i].fd, IPPROTO_TCP, TCP_DEFER_ACCEPT,
                           &value, sizeof(int))
                == -1)
            {
                njt_log_error(NJT_LOG_ALERT, cycle->log, njt_socket_errno,
                              "setsockopt(TCP_DEFER_ACCEPT, %d) for %V failed, "
                              "ignored",
                              value, &ls[i].addr_text);

                continue;
            }
        }

        if (ls[i].add_deferred) {
            ls[i].deferred_accept = 1;
        }

#endif

#endif /* NJT_HAVE_DEFERRED_ACCEPT */

#if (NJT_HAVE_IP_RECVDSTADDR)

        if (ls[i].wildcard
            && ls[i].type == SOCK_DGRAM
            && ls[i].sockaddr->sa_family == AF_INET)
        {
            value = 1;

            if (setsockopt(ls[i].fd, IPPROTO_IP, IP_RECVDSTADDR,
                           (const void *) &value, sizeof(int))
                == -1)
            {
                njt_log_error(NJT_LOG_ALERT, cycle->log, njt_socket_errno,
                              "setsockopt(IP_RECVDSTADDR) "
                              "for %V failed, ignored",
                              &ls[i].addr_text);
            }
        }

#elif (NJT_HAVE_IP_PKTINFO)

        if (ls[i].wildcard
            && ls[i].type == SOCK_DGRAM
            && ls[i].sockaddr->sa_family == AF_INET)
        {
            value = 1;

            if (setsockopt(ls[i].fd, IPPROTO_IP, IP_PKTINFO,
                           (const void *) &value, sizeof(int))
                == -1)
            {
                njt_log_error(NJT_LOG_ALERT, cycle->log, njt_socket_errno,
                              "setsockopt(IP_PKTINFO) "
                              "for %V failed, ignored",
                              &ls[i].addr_text);
            }
        }

#endif

#if (NJT_HAVE_INET6 && NJT_HAVE_IPV6_RECVPKTINFO)

        if (ls[i].wildcard
            && ls[i].type == SOCK_DGRAM
            && ls[i].sockaddr->sa_family == AF_INET6)
        {
            value = 1;

            if (setsockopt(ls[i].fd, IPPROTO_IPV6, IPV6_RECVPKTINFO,
                           (const void *) &value, sizeof(int))
                == -1)
            {
                njt_log_error(NJT_LOG_ALERT, cycle->log, njt_socket_errno,
                              "setsockopt(IPV6_RECVPKTINFO) "
                              "for %V failed, ignored",
                              &ls[i].addr_text);
            }
        }

#endif

#if (NJT_HAVE_IP_MTU_DISCOVER)

        if (ls[i].quic && ls[i].sockaddr->sa_family == AF_INET) {
            value = IP_PMTUDISC_DO;

            if (setsockopt(ls[i].fd, IPPROTO_IP, IP_MTU_DISCOVER,
                           (const void *) &value, sizeof(int))
                == -1)
            {
                njt_log_error(NJT_LOG_ALERT, cycle->log, njt_socket_errno,
                              "setsockopt(IP_MTU_DISCOVER) "
                              "for %V failed, ignored",
                              &ls[i].addr_text);
            }
        }

#elif (NJT_HAVE_IP_DONTFRAG)

        if (ls[i].quic && ls[i].sockaddr->sa_family == AF_INET) {
            value = 1;

            if (setsockopt(ls[i].fd, IPPROTO_IP, IP_DONTFRAG,
                           (const void *) &value, sizeof(int))
                == -1)
            {
                njt_log_error(NJT_LOG_ALERT, cycle->log, njt_socket_errno,
                              "setsockopt(IP_DONTFRAG) "
                              "for %V failed, ignored",
                              &ls[i].addr_text);
            }
        }

#endif

#if (NJT_HAVE_INET6)

#if (NJT_HAVE_IPV6_MTU_DISCOVER)

        if (ls[i].quic && ls[i].sockaddr->sa_family == AF_INET6) {
            value = IPV6_PMTUDISC_DO;

            if (setsockopt(ls[i].fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER,
                           (const void *) &value, sizeof(int))
                == -1)
            {
                njt_log_error(NJT_LOG_ALERT, cycle->log, njt_socket_errno,
                              "setsockopt(IPV6_MTU_DISCOVER) "
                              "for %V failed, ignored",
                              &ls[i].addr_text);
            }
        }

#elif (NJT_HAVE_IP_DONTFRAG)

        if (ls[i].quic && ls[i].sockaddr->sa_family == AF_INET6) {
            value = 1;

            if (setsockopt(ls[i].fd, IPPROTO_IPV6, IPV6_DONTFRAG,
                           (const void *) &value, sizeof(int))
                == -1)
            {
                njt_log_error(NJT_LOG_ALERT, cycle->log, njt_socket_errno,
                              "setsockopt(IPV6_DONTFRAG) "
                              "for %V failed, ignored",
                              &ls[i].addr_text);
            }
        }

#endif

#endif
    }

    return;
}


void
njt_close_listening_sockets(njt_cycle_t *cycle)
{
    njt_uint_t         i;
    njt_listening_t   *ls;
    njt_connection_t  *c;

    if (njt_event_flags & NJT_USE_IOCP_EVENT) {
        return;
    }

    njt_accept_mutex_held = 0;
    njt_use_accept_mutex = 0;

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {
        // openresty patch
#if (NJT_HAVE_REUSEPORT)
        if (ls[i].fd == (njt_socket_t) -1) {
            continue;
        }
#endif
        // openresty patch end


        c = ls[i].connection;

#if (NJT_QUIC)
        if (ls[i].quic) {
            continue;
        }
#endif

        if (c) {
            if (c->read->active) {
                if (njt_event_flags & NJT_USE_EPOLL_EVENT) {

                    /*
                     * it seems that Linux-2.6.x OpenVZ sends events
                     * for closed shared listening sockets unless
                     * the events was explicitly deleted
                     */

                    njt_del_event(c->read, NJT_READ_EVENT, 0);

                } else {
                    njt_del_event(c->read, NJT_READ_EVENT, NJT_CLOSE_EVENT);
                }
            }

            njt_free_connection(c);

            c->fd = (njt_socket_t) -1;
        }

        njt_log_debug2(NJT_LOG_DEBUG_CORE, cycle->log, 0,
                       "close listening %V #%d ", &ls[i].addr_text, ls[i].fd);

        if (njt_close_socket(ls[i].fd) == -1) {
            njt_log_error(NJT_LOG_EMERG, cycle->log, njt_socket_errno,
                          njt_close_socket_n " %V failed", &ls[i].addr_text);
        }

#if (NJT_HAVE_UNIX_DOMAIN)

        if (ls[i].sockaddr->sa_family == AF_UNIX
            && njt_process <= NJT_PROCESS_MASTER
            && njt_new_binary == 0
            && (!ls[i].inherited || njt_getppid() != njt_parent))
        {
            u_char *name = ls[i].addr_text.data + sizeof("unix:") - 1;

            if (njt_delete_file(name) == NJT_FILE_ERROR) {
                njt_log_error(NJT_LOG_EMERG, cycle->log, njt_socket_errno,
                              njt_delete_file_n " %s failed", name);
            }
        }

#endif

        ls[i].fd = (njt_socket_t) -1;
    }

    cycle->listening.nelts = 0;
}


njt_connection_t *
njt_get_connection(njt_socket_t s, njt_log_t *log)
{
    njt_uint_t         instance;
    njt_event_t       *rev, *wev;
    njt_connection_t  *c;

    /* disable warning: Win32 SOCKET is u_int while UNIX socket is int */

    if (njt_cycle->files && (njt_uint_t) s >= njt_cycle->files_n) {
        njt_log_error(NJT_LOG_ALERT, log, 0,
                      "the new socket has number %d, "
                      "but only %ui files are available",
                      s, njt_cycle->files_n);
        return NULL;
    }

    njt_drain_connections((njt_cycle_t *) njt_cycle);

    c = njt_cycle->free_connections;

    if (c == NULL) {
        njt_log_error(NJT_LOG_ALERT, log, 0,
                      "%ui worker_connections are not enough",
                      njt_cycle->connection_n);

        return NULL;
    }

    njt_cycle->free_connections = c->data;
    njt_cycle->free_connection_n--;
    if (njt_cycle->files && njt_cycle->files[s] == NULL) {
        njt_cycle->files[s] = c;
    }

    rev = c->read;
    wev = c->write;

    njt_memzero(c, sizeof(njt_connection_t));

    c->read = rev;
    c->write = wev;
    c->fd = s;
    c->log = log;
    instance = rev->instance;

    njt_memzero(rev, sizeof(njt_event_t));
    njt_memzero(wev, sizeof(njt_event_t));

    rev->instance = !instance;
    wev->instance = !instance;

    rev->index = NJT_INVALID_INDEX;
    wev->index = NJT_INVALID_INDEX;

    rev->data = c;
    wev->data = c;

    wev->write = 1;

    return c;
}


void
njt_free_connection(njt_connection_t *c)
{
    c->data = njt_cycle->free_connections;
    njt_cycle->free_connections = c;
    njt_cycle->free_connection_n++;

    if (njt_cycle->files && njt_cycle->files[c->fd] == c) {
        njt_cycle->files[c->fd] = NULL;
    }
}


void
njt_close_connection(njt_connection_t *c)
{
    njt_err_t     err;
    njt_uint_t    log_error, level;
    njt_socket_t  fd;

    if (c->fd == (njt_socket_t) -1) {
        njt_log_error(NJT_LOG_ALERT, c->log, 0, "connection already closed");
        return;
    }

    if (c->read->timer_set) {
        njt_del_timer(c->read);
    }

    if (c->write->timer_set) {
        njt_del_timer(c->write);
    }

    if (!c->shared) {
        if (njt_del_conn) {
            njt_del_conn(c, NJT_CLOSE_EVENT);

        } else {
            if (c->read->active || c->read->disabled) {
                njt_del_event(c->read, NJT_READ_EVENT, NJT_CLOSE_EVENT);
            }

            if (c->write->active || c->write->disabled) {
                njt_del_event(c->write, NJT_WRITE_EVENT, NJT_CLOSE_EVENT);
            }
        }
    }

    if (c->read->posted) {
        njt_delete_posted_event(c->read);
    }

    if (c->write->posted) {
        njt_delete_posted_event(c->write);
    }

    log_error = c->log_error;

    if(c->udp && c->udp->real_sock != (njt_socket_t)-1){
        if (njt_close_socket(c->udp->real_sock) == -1) {
            err = njt_socket_errno;
            if (err == NJT_ECONNRESET || err == NJT_ENOTCONN) {
                switch (log_error) {
                case NJT_ERROR_INFO:
                    level = NJT_LOG_INFO;
                    break;
                case NJT_ERROR_ERR:
                    level = NJT_LOG_ERR;
                    break;
                default:
                    level = NJT_LOG_CRIT;
                }
            } else {
                level = NJT_LOG_CRIT;
            }

            c->udp->real_sock = (njt_socket_t)-1;
        }
    }

    c->read->closed = 1;
    c->write->closed = 1;

    njt_reusable_connection(c, 0);

    njt_free_connection(c);

    fd = c->fd;
    c->fd = (njt_socket_t) -1;

    if (c->shared) {
        return;
    }

    if (njt_close_socket(fd) == -1) {

        err = njt_socket_errno;

        if (err == NJT_ECONNRESET || err == NJT_ENOTCONN) {

            switch (log_error) {

            case NJT_ERROR_INFO:
                level = NJT_LOG_INFO;
                break;

            case NJT_ERROR_ERR:
                level = NJT_LOG_ERR;
                break;

            default:
                level = NJT_LOG_CRIT;
            }

        } else {
            level = NJT_LOG_CRIT;
        }

        njt_log_error(level, c->log, err, njt_close_socket_n " %d failed", fd);
    }
}


void
njt_reusable_connection(njt_connection_t *c, njt_uint_t reusable)
{
    njt_log_debug1(NJT_LOG_DEBUG_CORE, c->log, 0,
                   "reusable connection: %ui", reusable);

    if (c->reusable) {
        njt_queue_remove(&c->queue);
        njt_cycle->reusable_connections_n--;

#if (NJT_STAT_STUB)
        (void) njt_atomic_fetch_add(njt_stat_waiting, -1);
#endif
    }

    c->reusable = reusable;

    if (reusable) {
        /* need cast as njt_cycle is volatile */

        njt_queue_insert_head(
            (njt_queue_t *) &njt_cycle->reusable_connections_queue, &c->queue);
        njt_cycle->reusable_connections_n++;

#if (NJT_STAT_STUB)
        (void) njt_atomic_fetch_add(njt_stat_waiting, 1);
#endif
    }
}


static void
njt_drain_connections(njt_cycle_t *cycle)
{
    njt_uint_t         i, n;
    njt_queue_t       *q;
    njt_connection_t  *c;

    if (cycle->free_connection_n > cycle->connection_n / 16
        || cycle->reusable_connections_n == 0)
    {
        return;
    }

    if (cycle->connections_reuse_time != njt_time()) {
        cycle->connections_reuse_time = njt_time();

        njt_log_error(NJT_LOG_WARN, cycle->log, 0,
                      "%ui worker_connections are not enough, "
                      "reusing connections",
                      cycle->connection_n);
    }

    c = NULL;
    n = njt_max(njt_min(32, cycle->reusable_connections_n / 8), 1);

    for (i = 0; i < n; i++) {
        if (njt_queue_empty(&cycle->reusable_connections_queue)) {
            break;
        }

        q = njt_queue_last(&cycle->reusable_connections_queue);
        c = njt_queue_data(q, njt_connection_t, queue);

        njt_log_debug0(NJT_LOG_DEBUG_CORE, c->log, 0,
                       "reusing connection");

        c->close = 1;
        c->read->handler(c->read);
    }

    if (cycle->free_connection_n == 0 && c && c->reusable) {

        /*
         * if no connections were freed, try to reuse the last
         * connection again: this should free it as long as
         * previous reuse moved it to lingering close
         */

        njt_log_debug0(NJT_LOG_DEBUG_CORE, c->log, 0,
                       "reusing connection again");

        c->close = 1;
        c->read->handler(c->read);
    }
}


void
njt_close_idle_connections(njt_cycle_t *cycle)
{
    njt_uint_t         i;
    njt_connection_t  *c;

    c = cycle->connections;

    for (i = 0; i < cycle->connection_n; i++) {

        /* THREAD: lock */

        if (c[i].fd != (njt_socket_t) -1 && c[i].idle) {
            c[i].close = 1;
            c[i].read->handler(c[i].read);
        }
    }
}


njt_int_t
njt_connection_local_sockaddr(njt_connection_t *c, njt_str_t *s,
    njt_uint_t port)
{
    socklen_t             len;
    njt_uint_t            addr;
    njt_sockaddr_t        sa;
    struct sockaddr_in   *sin;
#if (NJT_HAVE_INET6)
    njt_uint_t            i;
    struct sockaddr_in6  *sin6;
#endif

    addr = 0;

    if (c->local_socklen) {
        switch (c->local_sockaddr->sa_family) {

#if (NJT_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) c->local_sockaddr;

            for (i = 0; addr == 0 && i < 16; i++) {
                addr |= sin6->sin6_addr.s6_addr[i];
            }

            break;
#endif

#if (NJT_HAVE_UNIX_DOMAIN)
        case AF_UNIX:
            addr = 1;
            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) c->local_sockaddr;
            addr = sin->sin_addr.s_addr;
            break;
        }
    }

    if (addr == 0) {

        len = sizeof(njt_sockaddr_t);

        if (getsockname(c->fd, &sa.sockaddr, &len) == -1) {
            njt_connection_error(c, njt_socket_errno, "getsockname() failed");
            return NJT_ERROR;
        }

        c->local_sockaddr = njt_palloc(c->pool, len);
        if (c->local_sockaddr == NULL) {
            return NJT_ERROR;
        }

        njt_memcpy(c->local_sockaddr, &sa, len);

        c->local_socklen = len;
    }

    if (s == NULL) {
        return NJT_OK;
    }

    s->len = njt_sock_ntop(c->local_sockaddr, c->local_socklen,
                           s->data, s->len, port);

    return NJT_OK;
}


njt_int_t
njt_tcp_nodelay(njt_connection_t *c)
{
    int  tcp_nodelay;

    if (c->tcp_nodelay != NJT_TCP_NODELAY_UNSET) {
        return NJT_OK;
    }

    njt_log_debug0(NJT_LOG_DEBUG_CORE, c->log, 0, "tcp_nodelay");

    tcp_nodelay = 1;

    if (setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY,
                   (const void *) &tcp_nodelay, sizeof(int))
        == -1)
    {
#if (NJT_SOLARIS)
        if (c->log_error == NJT_ERROR_INFO) {

            /* Solaris returns EINVAL if a socket has been shut down */
            c->log_error = NJT_ERROR_IGNORE_EINVAL;

            njt_connection_error(c, njt_socket_errno,
                                 "setsockopt(TCP_NODELAY) failed");

            c->log_error = NJT_ERROR_INFO;

            return NJT_ERROR;
        }
#endif

        njt_connection_error(c, njt_socket_errno,
                             "setsockopt(TCP_NODELAY) failed");
        return NJT_ERROR;
    }

    c->tcp_nodelay = NJT_TCP_NODELAY_SET;

    return NJT_OK;
}


njt_int_t
njt_connection_error(njt_connection_t *c, njt_err_t err, char *text)
{
    njt_uint_t  level;

    /* Winsock may return NJT_ECONNABORTED instead of NJT_ECONNRESET */

    if ((err == NJT_ECONNRESET
#if (NJT_WIN32)
         || err == NJT_ECONNABORTED
#endif
        ) && c->log_error == NJT_ERROR_IGNORE_ECONNRESET)
    {
        return 0;
    }

#if (NJT_SOLARIS)
    if (err == NJT_EINVAL && c->log_error == NJT_ERROR_IGNORE_EINVAL) {
        return 0;
    }
#endif

    if (err == NJT_EMSGSIZE && c->log_error == NJT_ERROR_IGNORE_EMSGSIZE) {
        return 0;
    }

    if (err == 0
        || err == NJT_ECONNRESET
#if (NJT_WIN32)
        || err == NJT_ECONNABORTED
#else
        || err == NJT_EPIPE
#endif
        || err == NJT_ENOTCONN
        || err == NJT_ETIMEDOUT
        || err == NJT_ECONNREFUSED
        || err == NJT_ENETDOWN
        || err == NJT_ENETUNREACH
        || err == NJT_EHOSTDOWN
        || err == NJT_EHOSTUNREACH)
    {
        switch (c->log_error) {

        case NJT_ERROR_IGNORE_EMSGSIZE:
        case NJT_ERROR_IGNORE_EINVAL:
        case NJT_ERROR_IGNORE_ECONNRESET:
        case NJT_ERROR_INFO:
            level = NJT_LOG_INFO;
            break;

        default:
            level = NJT_LOG_ERR;
        }

    } else {
        level = NJT_LOG_ALERT;
    }

    njt_log_error(level, c->log, err, text);

    return NJT_ERROR;
}
njt_listening_t *
njt_get_listening(njt_conf_t *cf, struct sockaddr *sockaddr,
    socklen_t socklen){
    njt_uint_t         i;
    njt_listening_t   *ls;
    njt_uint_t         worker;
   
    worker = njt_worker;
    if (njt_process == NJT_PROCESS_HELPER && njt_is_privileged_agent) {
	    worker = 0;
    }   
    ls = cf->cycle->listening.elts;
    for (i = 0; i < cf->cycle->listening.nelts; i++) {
	    if (ls[i].reuseport && ls[i].worker != worker) {
		    continue; 
	    }
	if(ls[i].socklen == socklen && njt_memcmp(sockaddr,ls[i].sockaddr,socklen) == 0){
	   return &ls[i];
	}	
    }
    return NULL;	
}
