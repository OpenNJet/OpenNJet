
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


ssize_t
njt_udp_wsarecv(njt_connection_t *c, u_char *buf, size_t size)
{
    int           rc;
    u_long        bytes, flags;
    WSABUF        wsabuf[1];
    njt_err_t     err;
    njt_event_t  *rev;

    wsabuf[0].buf = (char *) buf;
    wsabuf[0].len = size;
    flags = 0;
    bytes = 0;

    rc = WSARecv(c->fd, wsabuf, 1, &bytes, &flags, NULL, NULL);

    njt_log_debug4(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "WSARecv: fd:%d rc:%d %ul of %z", c->fd, rc, bytes, size);

    rev = c->read;

    if (rc == -1) {
        rev->ready = 0;
        err = njt_socket_errno;

        if (err == WSAEWOULDBLOCK) {
            njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, err,
                           "WSARecv() not ready");
            return NJT_AGAIN;
        }

        rev->error = 1;
        njt_connection_error(c, err, "WSARecv() failed");

        return NJT_ERROR;
    }

    return bytes;
}


ssize_t
njt_udp_overlapped_wsarecv(njt_connection_t *c, u_char *buf, size_t size)
{
    int               rc;
    u_long            bytes, flags;
    WSABUF            wsabuf[1];
    njt_err_t         err;
    njt_event_t      *rev;
    LPWSAOVERLAPPED   ovlp;

    rev = c->read;

    if (!rev->ready) {
        njt_log_error(NJT_LOG_ALERT, c->log, 0, "second wsa post");
        return NJT_AGAIN;
    }

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "rev->complete: %d", rev->complete);

    if (rev->complete) {
        rev->complete = 0;

        if (njt_event_flags & NJT_USE_IOCP_EVENT) {
            if (rev->ovlp.error) {
                njt_connection_error(c, rev->ovlp.error, "WSARecv() failed");
                return NJT_ERROR;
            }

            njt_log_debug3(NJT_LOG_DEBUG_EVENT, c->log, 0,
                           "WSARecv ovlp: fd:%d %ul of %z",
                           c->fd, rev->available, size);

            return rev->available;
        }

        if (WSAGetOverlappedResult(c->fd, (LPWSAOVERLAPPED) &rev->ovlp,
                                   &bytes, 0, NULL)
            == 0)
        {
            njt_connection_error(c, njt_socket_errno,
                               "WSARecv() or WSAGetOverlappedResult() failed");
            return NJT_ERROR;
        }

        njt_log_debug3(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "WSARecv: fd:%d %ul of %z", c->fd, bytes, size);

        return bytes;
    }

    ovlp = (LPWSAOVERLAPPED) &rev->ovlp;
    njt_memzero(ovlp, sizeof(WSAOVERLAPPED));
    wsabuf[0].buf = (char *) buf;
    wsabuf[0].len = size;
    flags = 0;
    bytes = 0;

    rc = WSARecv(c->fd, wsabuf, 1, &bytes, &flags, ovlp, NULL);

    rev->complete = 0;

    njt_log_debug4(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "WSARecv ovlp: fd:%d rc:%d %ul of %z",
                   c->fd, rc, bytes, size);

    if (rc == -1) {
        err = njt_socket_errno;
        if (err == WSA_IO_PENDING) {
            rev->active = 1;
            njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, err,
                           "WSARecv() posted");
            return NJT_AGAIN;
        }

        rev->error = 1;
        njt_connection_error(c, err, "WSARecv() failed");
        return NJT_ERROR;
    }

    if (njt_event_flags & NJT_USE_IOCP_EVENT) {

        /*
         * if a socket was bound with I/O completion port
         * then GetQueuedCompletionStatus() would anyway return its status
         * despite that WSARecv() was already complete
         */

        rev->active = 1;
        return NJT_AGAIN;
    }

    rev->active = 0;

    return bytes;
}
