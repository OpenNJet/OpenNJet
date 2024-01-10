
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


#define NJT_WSABUFS  64


ssize_t
njt_wsarecv_chain(njt_connection_t *c, njt_chain_t *chain, off_t limit)
{
    int           rc;
    u_char       *prev;
    u_long        bytes, flags;
    size_t        n, size;
    njt_err_t     err;
    njt_array_t   vec;
    njt_event_t  *rev;
    LPWSABUF      wsabuf;
    WSABUF        wsabufs[NJT_WSABUFS];

    prev = NULL;
    wsabuf = NULL;
    flags = 0;
    size = 0;
    bytes = 0;

    vec.elts = wsabufs;
    vec.nelts = 0;
    vec.size = sizeof(WSABUF);
    vec.nalloc = NJT_WSABUFS;
    vec.pool = c->pool;

    /* coalesce the neighbouring bufs */

    while (chain) {
        n = chain->buf->end - chain->buf->last;

        if (limit) {
            if (size >= (size_t) limit) {
                break;
            }

            if (size + n > (size_t) limit) {
                n = (size_t) limit - size;
            }
        }

        if (prev == chain->buf->last) {
            wsabuf->len += n;

        } else {
            if (vec.nelts == vec.nalloc) {
                break;
            }

            wsabuf = njt_array_push(&vec);
            if (wsabuf == NULL) {
                return NJT_ERROR;
            }

            wsabuf->buf = (char *) chain->buf->last;
            wsabuf->len = n;
        }

        size += n;
        prev = chain->buf->end;
        chain = chain->next;
    }

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "WSARecv: %d:%d", vec.nelts, wsabuf->len);


    rc = WSARecv(c->fd, vec.elts, vec.nelts, &bytes, &flags, NULL, NULL);

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

#if (NJT_HAVE_FIONREAD)

    if (rev->available >= 0 && bytes > 0) {
        rev->available -= bytes;

        /*
         * negative rev->available means some additional bytes
         * were received between kernel notification and WSARecv(),
         * and therefore ev->ready can be safely reset even for
         * edge-triggered event methods
         */

        if (rev->available < 0) {
            rev->available = 0;
            rev->ready = 0;
        }

        njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "WSARecv: avail:%d", rev->available);

    } else if (bytes == size) {

        if (njt_socket_nread(c->fd, &rev->available) == -1) {
            rev->ready = 0;
            rev->error = 1;
            njt_connection_error(c, njt_socket_errno,
                                 njt_socket_nread_n " failed");
            return NJT_ERROR;
        }

        njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "WSARecv: avail:%d", rev->available);
    }

#endif

    if (bytes < size) {
        rev->ready = 0;
    }

    if (bytes == 0) {
        rev->ready = 0;
        rev->eof = 1;
    }

    return bytes;
}
