
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


static void njt_close_posted_connection(njt_connection_t *c);


void
njt_event_acceptex(njt_event_t *rev)
{
    njt_listening_t   *ls;
    njt_connection_t  *c;

    c = rev->data;
    ls = c->listening;

    c->log->handler = njt_accept_log_error;

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0, "AcceptEx: %d", c->fd);

    if (rev->ovlp.error) {
        njt_log_error(NJT_LOG_CRIT, c->log, rev->ovlp.error,
                      "AcceptEx() %V failed", &ls->addr_text);
        return;
    }

    /* SO_UPDATE_ACCEPT_CONTEXT is required for shutdown() to work */

    if (setsockopt(c->fd, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
                   (char *) &ls->fd, sizeof(njt_socket_t))
        == -1)
    {
        njt_log_error(NJT_LOG_CRIT, c->log, njt_socket_errno,
                      "setsockopt(SO_UPDATE_ACCEPT_CONTEXT) failed for %V",
                      &c->addr_text);
        /* TODO: close socket */
        return;
    }

    njt_getacceptexsockaddrs(c->buffer->pos,
                             ls->post_accept_buffer_size,
                             ls->socklen + 16,
                             ls->socklen + 16,
                             &c->local_sockaddr, &c->local_socklen,
                             &c->sockaddr, &c->socklen);

    if (ls->post_accept_buffer_size) {
        c->buffer->last += rev->available;
        c->buffer->end = c->buffer->start + ls->post_accept_buffer_size;

    } else {
        c->buffer = NULL;
    }

    if (ls->addr_ntop) {
        c->addr_text.data = njt_pnalloc(c->pool, ls->addr_text_max_len);
        if (c->addr_text.data == NULL) {
            /* TODO: close socket */
            return;
        }

        c->addr_text.len = njt_sock_ntop(c->sockaddr, c->socklen,
                                         c->addr_text.data,
                                         ls->addr_text_max_len, 0);
        if (c->addr_text.len == 0) {
            /* TODO: close socket */
            return;
        }
    }

    njt_event_post_acceptex(ls, 1);

    c->number = njt_atomic_fetch_add(njt_connection_counter, 1);

    c->start_time = njt_current_msec;

    ls->handler(c);

    return;

}


njt_int_t
njt_event_post_acceptex(njt_listening_t *ls, njt_uint_t n)
{
    u_long             rcvd;
    njt_err_t          err;
    njt_log_t         *log;
    njt_uint_t         i;
    njt_event_t       *rev, *wev;
    njt_socket_t       s;
    njt_connection_t  *c;

    for (i = 0; i < n; i++) {

        /* TODO: look up reused sockets */

        s = njt_socket(ls->sockaddr->sa_family, ls->type, 0);

        njt_log_debug1(NJT_LOG_DEBUG_EVENT, &ls->log, 0,
                       njt_socket_n " s:%d", s);

        if (s == (njt_socket_t) -1) {
            njt_log_error(NJT_LOG_ALERT, &ls->log, njt_socket_errno,
                          njt_socket_n " failed");

            return NJT_ERROR;
        }

        c = njt_get_connection(s, &ls->log);

        if (c == NULL) {
            return NJT_ERROR;
        }

        c->pool = njt_create_pool(ls->pool_size, &ls->log);
        if (c->pool == NULL) {
            njt_close_posted_connection(c);
            return NJT_ERROR;
        }

        log = njt_palloc(c->pool, sizeof(njt_log_t));
        if (log == NULL) {
            njt_close_posted_connection(c);
            return NJT_ERROR;
        }

        c->buffer = njt_create_temp_buf(c->pool, ls->post_accept_buffer_size
                                                 + 2 * (ls->socklen + 16));
        if (c->buffer == NULL) {
            njt_close_posted_connection(c);
            return NJT_ERROR;
        }

        c->local_sockaddr = njt_palloc(c->pool, ls->socklen);
        if (c->local_sockaddr == NULL) {
            njt_close_posted_connection(c);
            return NJT_ERROR;
        }

        c->sockaddr = njt_palloc(c->pool, ls->socklen);
        if (c->sockaddr == NULL) {
            njt_close_posted_connection(c);
            return NJT_ERROR;
        }

        *log = ls->log;
        c->log = log;

        c->recv = njt_recv;
        c->send = njt_send;
        c->recv_chain = njt_recv_chain;
        c->send_chain = njt_send_chain;

        c->listening = ls;

        rev = c->read;
        wev = c->write;

        rev->ovlp.event = rev;
        wev->ovlp.event = wev;
        rev->handler = njt_event_acceptex;

        rev->ready = 1;
        wev->ready = 1;

        rev->log = c->log;
        wev->log = c->log;

        if (njt_add_event(rev, 0, NJT_IOCP_IO) == NJT_ERROR) {
            njt_close_posted_connection(c);
            return NJT_ERROR;
        }

        if (njt_acceptex(ls->fd, s, c->buffer->pos, ls->post_accept_buffer_size,
                         ls->socklen + 16, ls->socklen + 16,
                         &rcvd, (LPOVERLAPPED) &rev->ovlp)
            == 0)
        {
            err = njt_socket_errno;
            if (err != WSA_IO_PENDING) {
                njt_log_error(NJT_LOG_ALERT, &ls->log, err,
                              "AcceptEx() %V failed", &ls->addr_text);

                njt_close_posted_connection(c);
                return NJT_ERROR;
            }
        }
    }

    return NJT_OK;
}


static void
njt_close_posted_connection(njt_connection_t *c)
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
}


u_char *
njt_acceptex_log_error(njt_log_t *log, u_char *buf, size_t len)
{
    return njt_snprintf(buf, len, " while posting AcceptEx() on %V", log->data);
}
