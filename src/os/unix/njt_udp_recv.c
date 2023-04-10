
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


ssize_t
njt_udp_unix_recv(njt_connection_t *c, u_char *buf, size_t size)
{
    ssize_t       n;
    njt_err_t     err;
    njt_event_t  *rev;

    rev = c->read;

    do {
        n = recv(c->fd, buf, size, 0);

        njt_log_debug3(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "recv: fd:%d %z of %uz", c->fd, n, size);

        if (n >= 0) {

#if (NJT_HAVE_KQUEUE)

            if (njt_event_flags & NJT_USE_KQUEUE_EVENT) {
                rev->available -= n;

                /*
                 * rev->available may be negative here because some additional
                 * bytes may be received between kevent() and recv()
                 */

                if (rev->available <= 0) {
                    rev->ready = 0;
                    rev->available = 0;
                }
            }

#endif

            return n;
        }

        err = njt_socket_errno;

        if (err == NJT_EAGAIN || err == NJT_EINTR) {
            njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, err,
                           "recv() not ready");
            n = NJT_AGAIN;

        } else {
            n = njt_connection_error(c, err, "recv() failed");
            break;
        }

    } while (err == NJT_EINTR);

    rev->ready = 0;

    if (n == NJT_ERROR) {
        rev->error = 1;
    }

    return n;
}
