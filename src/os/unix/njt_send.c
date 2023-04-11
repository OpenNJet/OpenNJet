
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


ssize_t
njt_unix_send(njt_connection_t *c, u_char *buf, size_t size)
{
    ssize_t       n;
    njt_err_t     err;
    njt_event_t  *wev;

    wev = c->write;

#if (NJT_HAVE_KQUEUE)

    if ((njt_event_flags & NJT_USE_KQUEUE_EVENT) && wev->pending_eof) {
        (void) njt_connection_error(c, wev->kq_errno,
                               "kevent() reported about an closed connection");
        wev->error = 1;
        return NJT_ERROR;
    }

#endif

    for ( ;; ) {
        n = send(c->fd, buf, size, 0);

        njt_log_debug3(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "send: fd:%d %z of %uz", c->fd, n, size);

        if (n > 0) {
            if (n < (ssize_t) size) {
                wev->ready = 0;
            }

            c->sent += n;

            return n;
        }

        err = njt_socket_errno;

        if (n == 0) {
            njt_log_error(NJT_LOG_ALERT, c->log, err, "send() returned zero");
            wev->ready = 0;
            return n;
        }

        if (err == NJT_EAGAIN || err == NJT_EINTR) {
            wev->ready = 0;

            njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, err,
                           "send() not ready");

            if (err == NJT_EAGAIN) {
                return NJT_AGAIN;
            }

        } else {
            wev->error = 1;
            (void) njt_connection_error(c, err, "send() failed");
            return NJT_ERROR;
        }
    }
}
