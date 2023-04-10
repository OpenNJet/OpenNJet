
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


#define NJT_WSABUFS  64


njt_chain_t *
njt_wsasend_chain(njt_connection_t *c, njt_chain_t *in, off_t limit)
{
    int           rc;
    u_char       *prev;
    u_long        size, sent, send, prev_send;
    njt_err_t     err;
    njt_event_t  *wev;
    njt_array_t   vec;
    njt_chain_t  *cl;
    LPWSABUF      wsabuf;
    WSABUF        wsabufs[NJT_WSABUFS];

    wev = c->write;

    if (!wev->ready) {
        return in;
    }

    /* the maximum limit size is the maximum u_long value - the page size */

    if (limit == 0 || limit > (off_t) (NJT_MAX_UINT32_VALUE - njt_pagesize)) {
        limit = NJT_MAX_UINT32_VALUE - njt_pagesize;
    }

    send = 0;

    /*
     * WSABUFs must be 4-byte aligned otherwise
     * WSASend() will return undocumented WSAEINVAL error.
     */

    vec.elts = wsabufs;
    vec.size = sizeof(WSABUF);
    vec.nalloc = njt_min(NJT_WSABUFS, njt_max_wsabufs);
    vec.pool = c->pool;

    for ( ;; ) {
        prev = NULL;
        wsabuf = NULL;
        prev_send = send;

        vec.nelts = 0;

        /* create the WSABUF and coalesce the neighbouring bufs */

        for (cl = in; cl && send < limit; cl = cl->next) {

            if (njt_buf_special(cl->buf)) {
                continue;
            }

            size = cl->buf->last - cl->buf->pos;

            if (send + size > limit) {
                size = (u_long) (limit - send);
            }

            if (prev == cl->buf->pos) {
                wsabuf->len += cl->buf->last - cl->buf->pos;

            } else {
                if (vec.nelts == vec.nalloc) {
                    break;
                }

                wsabuf = njt_array_push(&vec);
                if (wsabuf == NULL) {
                    return NJT_CHAIN_ERROR;
                }

                wsabuf->buf = (char *) cl->buf->pos;
                wsabuf->len = cl->buf->last - cl->buf->pos;
            }

            prev = cl->buf->last;
            send += size;
        }

        sent = 0;

        rc = WSASend(c->fd, vec.elts, vec.nelts, &sent, 0, NULL, NULL);

        if (rc == -1) {
            err = njt_errno;

            if (err == WSAEWOULDBLOCK) {
                njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, err,
                               "WSASend() not ready");

            } else {
                wev->error = 1;
                njt_connection_error(c, err, "WSASend() failed");
                return NJT_CHAIN_ERROR;
            }
        }

        njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "WSASend: fd:%d, s:%ul", c->fd, sent);

        c->sent += sent;

        in = njt_chain_update_sent(in, sent);

        if (send - prev_send != sent) {
            wev->ready = 0;
            return in;
        }

        if (send >= limit || in == NULL) {
            return in;
        }
    }
}


njt_chain_t *
njt_overlapped_wsasend_chain(njt_connection_t *c, njt_chain_t *in, off_t limit)
{
    int               rc;
    u_char           *prev;
    u_long            size, send, sent;
    njt_err_t         err;
    njt_event_t      *wev;
    njt_array_t       vec;
    njt_chain_t      *cl;
    LPWSAOVERLAPPED   ovlp;
    LPWSABUF          wsabuf;
    WSABUF            wsabufs[NJT_WSABUFS];

    wev = c->write;

    if (!wev->ready) {
        return in;
    }

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "wev->complete: %d", wev->complete);

    if (!wev->complete) {

        /* post the overlapped WSASend() */

        /* the maximum limit size is the maximum u_long value - the page size */

        if (limit == 0 || limit > (off_t) (NJT_MAX_UINT32_VALUE - njt_pagesize))
        {
            limit = NJT_MAX_UINT32_VALUE - njt_pagesize;
        }

        /*
         * WSABUFs must be 4-byte aligned otherwise
         * WSASend() will return undocumented WSAEINVAL error.
         */

        vec.elts = wsabufs;
        vec.nelts = 0;
        vec.size = sizeof(WSABUF);
        vec.nalloc = njt_min(NJT_WSABUFS, njt_max_wsabufs);
        vec.pool = c->pool;

        send = 0;
        prev = NULL;
        wsabuf = NULL;

        /* create the WSABUF and coalesce the neighbouring bufs */

        for (cl = in; cl && send < limit; cl = cl->next) {

            if (njt_buf_special(cl->buf)) {
                continue;
            }

            size = cl->buf->last - cl->buf->pos;

            if (send + size > limit) {
                size = (u_long) (limit - send);
            }

            if (prev == cl->buf->pos) {
                wsabuf->len += cl->buf->last - cl->buf->pos;

            } else {
                if (vec.nelts == vec.nalloc) {
                    break;
                }

                wsabuf = njt_array_push(&vec);
                if (wsabuf == NULL) {
                    return NJT_CHAIN_ERROR;
                }

                wsabuf->buf = (char *) cl->buf->pos;
                wsabuf->len = cl->buf->last - cl->buf->pos;
            }

            prev = cl->buf->last;
            send += size;
        }

        ovlp = (LPWSAOVERLAPPED) &c->write->ovlp;
        njt_memzero(ovlp, sizeof(WSAOVERLAPPED));

        rc = WSASend(c->fd, vec.elts, vec.nelts, &sent, 0, ovlp, NULL);

        wev->complete = 0;

        if (rc == -1) {
            err = njt_errno;

            if (err == WSA_IO_PENDING) {
                njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, err,
                               "WSASend() posted");
                wev->active = 1;
                return in;

            } else {
                wev->error = 1;
                njt_connection_error(c, err, "WSASend() failed");
                return NJT_CHAIN_ERROR;
            }

        } else if (njt_event_flags & NJT_USE_IOCP_EVENT) {

            /*
             * if a socket was bound with I/O completion port then
             * GetQueuedCompletionStatus() would anyway return its status
             * despite that WSASend() was already complete
             */

            wev->active = 1;
            return in;
        }

        njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "WSASend: fd:%d, s:%ul", c->fd, sent);

    } else {

        /* the overlapped WSASend() complete */

        wev->complete = 0;
        wev->active = 0;

        if (njt_event_flags & NJT_USE_IOCP_EVENT) {
            if (wev->ovlp.error) {
                njt_connection_error(c, wev->ovlp.error, "WSASend() failed");
                return NJT_CHAIN_ERROR;
            }

            sent = wev->available;

        } else {
            if (WSAGetOverlappedResult(c->fd, (LPWSAOVERLAPPED) &wev->ovlp,
                                       &sent, 0, NULL)
                == 0)
            {
                njt_connection_error(c, njt_socket_errno,
                               "WSASend() or WSAGetOverlappedResult() failed");

                return NJT_CHAIN_ERROR;
            }
        }
    }

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "WSASend ovlp: fd:%d, s:%ul", c->fd, sent);

    c->sent += sent;

    in = njt_chain_update_sent(in, sent);

    if (in) {
        wev->ready = 0;

    } else {
        wev->ready = 1;
    }

    return in;
}
