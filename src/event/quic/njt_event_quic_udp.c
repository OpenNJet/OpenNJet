
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_event_quic_connection.h>


static void njt_quic_close_accepted_connection(njt_connection_t *c);
static njt_connection_t *njt_quic_lookup_connection(njt_listening_t *ls,
    njt_str_t *key, struct sockaddr *local_sockaddr, socklen_t local_socklen);


void
njt_quic_recvmsg(njt_event_t *ev)
{
    ssize_t             n;
    njt_str_t           key;
    njt_buf_t           buf;
    njt_log_t          *log;
    njt_err_t           err;
    socklen_t           socklen, local_socklen;
    njt_event_t        *rev, *wev;
    struct iovec        iov[1];
    struct msghdr       msg;
    njt_sockaddr_t      sa, lsa;
    struct sockaddr    *sockaddr, *local_sockaddr;
    njt_listening_t    *ls;
    njt_event_conf_t   *ecf;
    njt_connection_t   *c, *lc;
    njt_quic_socket_t  *qsock;
    static u_char       buffer[NJT_QUIC_MAX_UDP_PAYLOAD_SIZE];

#if (NJT_HAVE_ADDRINFO_CMSG)
    u_char             msg_control[CMSG_SPACE(sizeof(njt_addrinfo_t))];
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
                   "quic recvmsg on %V, ready: %d",
                   &ls->addr_text, ev->available);

    do {
        njt_memzero(&msg, sizeof(struct msghdr));

        iov[0].iov_base = (void *) buffer;
        iov[0].iov_len = sizeof(buffer);

        msg.msg_name = &sa;
        msg.msg_namelen = sizeof(njt_sockaddr_t);
        msg.msg_iov = iov;
        msg.msg_iovlen = 1;

#if (NJT_HAVE_ADDRINFO_CMSG)
        if (ls->wildcard) {
            msg.msg_control = &msg_control;
            msg.msg_controllen = sizeof(msg_control);

            njt_memzero(&msg_control, sizeof(msg_control));
        }
#endif

        n = recvmsg(lc->fd, &msg, 0);

        if (n == -1) {
            err = njt_socket_errno;

            if (err == NJT_EAGAIN) {
                njt_log_debug0(NJT_LOG_DEBUG_EVENT, ev->log, err,
                               "quic recvmsg() not ready");
                return;
            }

            njt_log_error(NJT_LOG_ALERT, ev->log, err, "quic recvmsg() failed");

            return;
        }

#if (NJT_HAVE_ADDRINFO_CMSG)
        if (msg.msg_flags & (MSG_TRUNC|MSG_CTRUNC)) {
            njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                          "quic recvmsg() truncated data");
            continue;
        }
#endif

        sockaddr = msg.msg_name;
        socklen = msg.msg_namelen;

        if (socklen > (socklen_t) sizeof(njt_sockaddr_t)) {
            socklen = sizeof(njt_sockaddr_t);
        }

#if (NJT_HAVE_UNIX_DOMAIN)

        if (sockaddr->sa_family == AF_UNIX) {
            struct sockaddr_un *saun = (struct sockaddr_un *) sockaddr;

            if (socklen <= (socklen_t) offsetof(struct sockaddr_un, sun_path)
                || saun->sun_path[0] == '\0')
            {
                njt_log_debug0(NJT_LOG_DEBUG_EVENT, njt_cycle->log, 0,
                               "unbound unix socket");
                goto next;
            }
        }

#endif

        local_sockaddr = ls->sockaddr;
        local_socklen = ls->socklen;

#if (NJT_HAVE_ADDRINFO_CMSG)

        if (ls->wildcard) {
            struct cmsghdr  *cmsg;

            njt_memcpy(&lsa, local_sockaddr, local_socklen);
            local_sockaddr = &lsa.sockaddr;

            for (cmsg = CMSG_FIRSTHDR(&msg);
                 cmsg != NULL;
                 cmsg = CMSG_NXTHDR(&msg, cmsg))
            {
                if (njt_get_srcaddr_cmsg(cmsg, local_sockaddr) == NJT_OK) {
                    break;
                }
            }
        }

#endif

        if (njt_quic_get_packet_dcid(ev->log, buffer, n, &key) != NJT_OK) {
            goto next;
        }

        c = njt_quic_lookup_connection(ls, &key, local_sockaddr, local_socklen);

        if (c) {

#if (NJT_DEBUG)
            if (c->log->log_level & NJT_LOG_DEBUG_EVENT) {
                njt_log_handler_pt  handler;

                handler = c->log->handler;
                c->log->handler = NULL;

                njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                               "quic recvmsg: fd:%d n:%z", c->fd, n);

                c->log->handler = handler;
            }
#endif

            njt_memzero(&buf, sizeof(njt_buf_t));

            buf.pos = buffer;
            buf.last = buffer + n;
            buf.start = buf.pos;
            buf.end = buffer + sizeof(buffer);

            qsock = njt_quic_get_socket(c);

            njt_memcpy(&qsock->sockaddr, sockaddr, socklen);
            qsock->socklen = socklen;

            c->udp->buffer = &buf;

            rev = c->read;
            rev->ready = 1;
            rev->active = 0;

            rev->handler(rev);

            if (c->udp) {
                c->udp->buffer = NULL;
            }

            rev->ready = 0;
            rev->active = 1;

            goto next;
        }

#if (NJT_STAT_STUB)
        (void) njt_atomic_fetch_add(njt_stat_accepted, 1);
#endif

        njt_accept_disabled = njt_cycle->connection_n / 8
                              - njt_cycle->free_connection_n;

        c = njt_get_connection(lc->fd, ev->log);
        if (c == NULL) {
            return;
        }

        c->shared = 1;
        c->type = SOCK_DGRAM;
        c->socklen = socklen;

#if (NJT_STAT_STUB)
        (void) njt_atomic_fetch_add(njt_stat_active, 1);
#endif

        c->pool = njt_create_pool(ls->pool_size, ev->log);
        if (c->pool == NULL) {
            njt_quic_close_accepted_connection(c);
            return;
        }

        c->sockaddr = njt_palloc(c->pool, NJT_SOCKADDRLEN);
        if (c->sockaddr == NULL) {
            njt_quic_close_accepted_connection(c);
            return;
        }

        njt_memcpy(c->sockaddr, sockaddr, socklen);

        log = njt_palloc(c->pool, sizeof(njt_log_t));
        if (log == NULL) {
            njt_quic_close_accepted_connection(c);
            return;
        }

        *log = ls->log;

        c->log = log;
        c->pool->log = log;
        c->listening = ls;

        if (local_sockaddr == &lsa.sockaddr) {
            local_sockaddr = njt_palloc(c->pool, local_socklen);
            if (local_sockaddr == NULL) {
                njt_quic_close_accepted_connection(c);
                return;
            }

            njt_memcpy(local_sockaddr, &lsa, local_socklen);
        }

        c->local_sockaddr = local_sockaddr;
        c->local_socklen = local_socklen;

        c->buffer = njt_create_temp_buf(c->pool, n);
        if (c->buffer == NULL) {
            njt_quic_close_accepted_connection(c);
            return;
        }

        c->buffer->last = njt_cpymem(c->buffer->last, buffer, n);

        rev = c->read;
        wev = c->write;

        rev->active = 1;
        wev->ready = 1;

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
                njt_quic_close_accepted_connection(c);
                return;
            }

            c->addr_text.len = njt_sock_ntop(c->sockaddr, c->socklen,
                                             c->addr_text.data,
                                             ls->addr_text_max_len, 0);
            if (c->addr_text.len == 0) {
                njt_quic_close_accepted_connection(c);
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

            njt_log_debug4(NJT_LOG_DEBUG_EVENT, log, 0,
                           "*%uA quic recvmsg: %V fd:%d n:%z",
                           c->number, &addr, c->fd, n);
        }

        }
#endif

        log->data = NULL;
        log->handler = NULL;

        ls->handler(c);

    next:

        if (njt_event_flags & NJT_USE_KQUEUE_EVENT) {
            ev->available -= n;
        }

    } while (ev->available);
}


static void
njt_quic_close_accepted_connection(njt_connection_t *c)
{
    njt_free_connection(c);

    c->fd = (njt_socket_t) -1;

    if (c->pool) {
        njt_destroy_pool(c->pool);
    }

#if (NJT_STAT_STUB)
    (void) njt_atomic_fetch_add(njt_stat_active, -1);
#endif
}


static njt_connection_t *
njt_quic_lookup_connection(njt_listening_t *ls, njt_str_t *key,
    struct sockaddr *local_sockaddr, socklen_t local_socklen)
{
    uint32_t            hash;
    njt_int_t           rc;
    njt_connection_t   *c;
    njt_rbtree_node_t  *node, *sentinel;
    njt_quic_socket_t  *qsock;

    if (key->len == 0) {
        return NULL;
    }

    node = ls->rbtree.root;
    sentinel = ls->rbtree.sentinel;
    hash = njt_crc32_long(key->data, key->len);

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        qsock = (njt_quic_socket_t *) node;

        rc = njt_memn2cmp(key->data, qsock->sid.id, key->len, qsock->sid.len);

        c = qsock->udp.connection;

        if (rc == 0 && ls->wildcard) {
            rc = njt_cmp_sockaddr(local_sockaddr, local_socklen,
                                  c->local_sockaddr, c->local_socklen, 1);
        }

        if (rc == 0) {
            c->udp = &qsock->udp;
            return c;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}
