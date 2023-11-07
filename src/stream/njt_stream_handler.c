
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_stream.h>
#if (NJT_STREAM_FTP_PROXY)
#include <njt_stream_ftp_proxy_module.h>
#endif

static void njt_stream_log_session(njt_stream_session_t *s);
static void njt_stream_close_connection(njt_connection_t *c);
static u_char *njt_stream_log_error(njt_log_t *log, u_char *buf, size_t len);
static void njt_stream_proxy_protocol_handler(njt_event_t *rev);


void
njt_stream_init_connection(njt_connection_t *c)
{
    u_char                        text[NJT_SOCKADDR_STRLEN];
    size_t                        len;
    njt_uint_t                    i;
    njt_time_t                   *tp;
    njt_event_t                  *rev;
    struct sockaddr              *sa;
    njt_stream_port_t            *port;
    struct sockaddr_in           *sin;
    njt_stream_in_addr_t         *addr;
    njt_stream_session_t         *s;
    njt_stream_addr_conf_t       *addr_conf;
#if (NJT_HAVE_INET6)
    struct sockaddr_in6          *sin6;
    njt_stream_in6_addr_t        *addr6;
#endif
    njt_stream_core_srv_conf_t   *cscf;
    njt_stream_core_main_conf_t  *cmcf;

    /* find the server configuration for the address:port */

    port = c->listening->servers;

    if (port->naddrs > 1) {

        /*
         * There are several addresses on this port and one of them
         * is the "*:port" wildcard so getsockname() is needed to determine
         * the server address.
         *
         * AcceptEx() and recvmsg() already gave this address.
         */

        if (njt_connection_local_sockaddr(c, NULL, 0) != NJT_OK) {
            njt_stream_close_connection(c);
            return;
        }

        sa = c->local_sockaddr;

        switch (sa->sa_family) {

#if (NJT_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) sa;

            addr6 = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (njt_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
                    break;
                }
            }

            addr_conf = &addr6[i].conf;

            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) sa;

            addr = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (addr[i].addr == sin->sin_addr.s_addr) {
                    break;
                }
            }

            addr_conf = &addr[i].conf;

            break;
        }

    } else {
        switch (c->local_sockaddr->sa_family) {

#if (NJT_HAVE_INET6)
        case AF_INET6:
            addr6 = port->addrs;
            addr_conf = &addr6[0].conf;
            break;
#endif

        default: /* AF_INET */
            addr = port->addrs;
            addr_conf = &addr[0].conf;
            break;
        }
    }

    s = njt_pcalloc(c->pool, sizeof(njt_stream_session_t));
    if (s == NULL) {
        njt_stream_close_connection(c);
        return;
    }

    s->signature = NJT_STREAM_MODULE;
    s->main_conf = addr_conf->ctx->main_conf;
    s->srv_conf = addr_conf->ctx->srv_conf;

#if (NJT_STREAM_SSL)
    s->ssl = addr_conf->ssl;
#endif

#if (NJT_STREAM_FTP_PROXY)
    njt_queue_init(&s->ftp_port_list);
#endif

    if (c->buffer) {
        s->received += c->buffer->last - c->buffer->pos;
    }

    s->connection = c;
    c->data = s;

    cscf = njt_stream_get_module_srv_conf(s, njt_stream_core_module);

    njt_set_connection_log(c, cscf->error_log);

    len = njt_sock_ntop(c->sockaddr, c->socklen, text, NJT_SOCKADDR_STRLEN, 1);

    njt_log_error(NJT_LOG_INFO, c->log, 0, "*%uA %sclient %*s connected to %V",
                  c->number, c->type == SOCK_DGRAM ? "udp " : "",
                  len, text, &addr_conf->addr_text);

    c->log->connection = c->number;
    c->log->handler = njt_stream_log_error;
    c->log->data = s;
    c->log->action = "initializing session";
    c->log_error = NJT_ERROR_INFO;

    s->ctx = njt_pcalloc(c->pool, sizeof(void *) * njt_stream_max_module);
    if (s->ctx == NULL) {
        njt_stream_close_connection(c);
        return;
    }

    cmcf = njt_stream_get_module_main_conf(s, njt_stream_core_module);

    s->variables = njt_pcalloc(s->connection->pool,
                               cmcf->variables.nelts
                               * sizeof(njt_stream_variable_value_t));

    if (s->variables == NULL) {
        njt_stream_close_connection(c);
        return;
    }

    tp = njt_timeofday();
    s->start_sec = tp->sec;
    s->start_msec = tp->msec;

    rev = c->read;
    rev->handler = njt_stream_session_handler;

    if (addr_conf->proxy_protocol) {
        c->log->action = "reading PROXY protocol";

        rev->handler = njt_stream_proxy_protocol_handler;

        if (!rev->ready) {
            njt_add_timer(rev, cscf->proxy_protocol_timeout);

            if (njt_handle_read_event(rev, 0) != NJT_OK) {
                njt_stream_finalize_session(s,
                                            NJT_STREAM_INTERNAL_SERVER_ERROR);
            }

            return;
        }
    }

    if (njt_use_accept_mutex) {
        njt_post_event(rev, &njt_posted_events);
        return;
    }

    rev->handler(rev);
}


static void
njt_stream_proxy_protocol_handler(njt_event_t *rev)
{
    u_char                      *p, buf[NJT_PROXY_PROTOCOL_MAX_HEADER];
    size_t                       size;
    ssize_t                      n;
    njt_err_t                    err;
    njt_connection_t            *c;
    njt_stream_session_t        *s;
    njt_stream_core_srv_conf_t  *cscf;

    c = rev->data;
    s = c->data;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "stream PROXY protocol handler");

    if (rev->timedout) {
        njt_log_error(NJT_LOG_INFO, c->log, NJT_ETIMEDOUT, "client timed out");
        njt_stream_finalize_session(s, NJT_STREAM_OK);
        return;
    }

    n = recv(c->fd, (char *) buf, sizeof(buf), MSG_PEEK);

    err = njt_socket_errno;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0, "recv(): %z", n);

    if (n == -1) {
        if (err == NJT_EAGAIN) {
            rev->ready = 0;

            if (!rev->timer_set) {
                cscf = njt_stream_get_module_srv_conf(s,
                                                      njt_stream_core_module);

                njt_add_timer(rev, cscf->proxy_protocol_timeout);
            }

            if (njt_handle_read_event(rev, 0) != NJT_OK) {
                njt_stream_finalize_session(s,
                                            NJT_STREAM_INTERNAL_SERVER_ERROR);
            }

            return;
        }

        njt_connection_error(c, err, "recv() failed");

        njt_stream_finalize_session(s, NJT_STREAM_OK);
        return;
    }

    if (rev->timer_set) {
        njt_del_timer(rev);
    }

    p = njt_proxy_protocol_read(c, buf, buf + n);

    if (p == NULL) {
        njt_stream_finalize_session(s, NJT_STREAM_BAD_REQUEST);
        return;
    }

    size = p - buf;

    if (c->recv(c, buf, size) != (ssize_t) size) {
        njt_stream_finalize_session(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    c->log->action = "initializing session";

    njt_stream_session_handler(rev);
}


void
njt_stream_session_handler(njt_event_t *rev)
{
    njt_connection_t      *c;
    njt_stream_session_t  *s;

    c = rev->data;
    s = c->data;

    njt_stream_core_run_phases(s);
}


void
njt_stream_finalize_session(njt_stream_session_t *s, njt_uint_t rc)
{
    njt_log_debug1(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "finalize stream session: %i", rc);

    s->status = rc;

    njt_stream_log_session(s);

    njt_stream_close_connection(s->connection);
}


static void
njt_stream_log_session(njt_stream_session_t *s)
{
    njt_uint_t                    i, n;
    njt_stream_handler_pt        *log_handler;
    njt_stream_core_main_conf_t  *cmcf;

    cmcf = njt_stream_get_module_main_conf(s, njt_stream_core_module);

    log_handler = cmcf->phases[NJT_STREAM_LOG_PHASE].handlers.elts;
    n = cmcf->phases[NJT_STREAM_LOG_PHASE].handlers.nelts;

    for (i = 0; i < n; i++) {
        log_handler[i](s);
    }
}


static void
njt_stream_close_connection(njt_connection_t *c)
{
    njt_pool_t  *pool;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "close stream connection: %d", c->fd);

#if (NJT_STREAM_SSL)

    if (c->ssl) {
        if (njt_ssl_shutdown(c) == NJT_AGAIN) {
            c->ssl->handler = njt_stream_close_connection;
            return;
        }
    }

#endif

#if (NJT_STAT_STUB)
    (void) njt_atomic_fetch_add(njt_stat_active, -1);
#endif

#if (NJT_STREAM_FTP_PROXY)
    //need free all data port map info of current session
    njt_stream_ftp_proxy_cleanup((njt_stream_session_t *)c->data);
#endif

    pool = c->pool;

    njt_close_connection(c);

    njt_destroy_pool(pool);
}


static u_char *
njt_stream_log_error(njt_log_t *log, u_char *buf, size_t len)
{
    u_char                *p;
    njt_stream_session_t  *s;

    if (log->action) {
        p = njt_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    s = log->data;

    p = njt_snprintf(buf, len, ", %sclient: %V, server: %V",
                     s->connection->type == SOCK_DGRAM ? "udp " : "",
                     &s->connection->addr_text,
                     &s->connection->listening->addr_text);
    len -= p - buf;
    buf = p;

    if (s->log_handler) {
        p = s->log_handler(log, buf, len);
    }

    return p;
}
