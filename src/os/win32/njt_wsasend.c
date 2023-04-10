
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


ssize_t
njt_wsasend(njt_connection_t *c, u_char *buf, size_t size)
{
    int           n;
    u_long        sent;
    njt_err_t     err;
    njt_event_t  *wev;
    WSABUF        wsabuf;

    wev = c->write;

    if (!wev->ready) {
        return NJT_AGAIN;
    }

    /*
     * WSABUF must be 4-byte aligned otherwise
     * WSASend() will return undocumented WSAEINVAL error.
     */

    wsabuf.buf = (char *) buf;
    wsabuf.len = size;

    sent = 0;

    n = WSASend(c->fd, &wsabuf, 1, &sent, 0, NULL, NULL);

    njt_log_debug4(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "WSASend: fd:%d, %d, %ul of %uz", c->fd, n, sent, size);

    if (n == 0) {
        if (sent < size) {
            wev->ready = 0;
        }

        c->sent += sent;

        return sent;
    }

    err = njt_socket_errno;

    if (err == WSAEWOULDBLOCK) {
        njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, err, "WSASend() not ready");
        wev->ready = 0;
        return NJT_AGAIN;
    }

    wev->error = 1;
    njt_connection_error(c, err, "WSASend() failed");

    return NJT_ERROR;
}


ssize_t
njt_overlapped_wsasend(njt_connection_t *c, u_char *buf, size_t size)
{
    int               n;
    u_long            sent;
    njt_err_t         err;
    njt_event_t      *wev;
    LPWSAOVERLAPPED   ovlp;
    WSABUF            wsabuf;

    wev = c->write;

    if (!wev->ready) {
        return NJT_AGAIN;
    }

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "wev->complete: %d", wev->complete);

    if (!wev->complete) {

        /* post the overlapped WSASend() */

        /*
         * WSABUFs must be 4-byte aligned otherwise
         * WSASend() will return undocumented WSAEINVAL error.
         */

        wsabuf.buf = (char *) buf;
        wsabuf.len = size;

        sent = 0;

        ovlp = (LPWSAOVERLAPPED) &c->write->ovlp;
        njt_memzero(ovlp, sizeof(WSAOVERLAPPED));

        n = WSASend(c->fd, &wsabuf, 1, &sent, 0, ovlp, NULL);

        njt_log_debug4(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "WSASend: fd:%d, %d, %ul of %uz", c->fd, n, sent, size);

        wev->complete = 0;

        if (n == 0) {
            if (njt_event_flags & NJT_USE_IOCP_EVENT) {

                /*
                 * if a socket was bound with I/O completion port then
                 * GetQueuedCompletionStatus() would anyway return its status
                 * despite that WSASend() was already complete
                 */

                wev->active = 1;
                return NJT_AGAIN;
            }

            if (sent < size) {
                wev->ready = 0;
            }

            c->sent += sent;

            return sent;
        }

        err = njt_socket_errno;

        if (err == WSA_IO_PENDING) {
            njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, err,
                           "WSASend() posted");
            wev->active = 1;
            return NJT_AGAIN;
        }

        wev->error = 1;
        njt_connection_error(c, err, "WSASend() failed");

        return NJT_ERROR;
    }

    /* the overlapped WSASend() complete */

    wev->complete = 0;
    wev->active = 0;

    if (njt_event_flags & NJT_USE_IOCP_EVENT) {

        if (wev->ovlp.error) {
            njt_connection_error(c, wev->ovlp.error, "WSASend() failed");
            return NJT_ERROR;
        }

        sent = wev->available;

    } else {
        if (WSAGetOverlappedResult(c->fd, (LPWSAOVERLAPPED) &wev->ovlp,
                                   &sent, 0, NULL)
            == 0)
        {
            njt_connection_error(c, njt_socket_errno,
                           "WSASend() or WSAGetOverlappedResult() failed");

            return NJT_ERROR;
        }
    }

    njt_log_debug3(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "WSAGetOverlappedResult: fd:%d, %ul of %uz",
                   c->fd, sent, size);

    if (sent < size) {
        wev->ready = 0;
    }

    c->sent += sent;

    return sent;
}
