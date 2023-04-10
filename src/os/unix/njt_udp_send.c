
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


ssize_t
njt_udp_unix_send(njt_connection_t *c, u_char *buf, size_t size)
{
    ssize_t       n;
    njt_err_t     err;
    njt_event_t  *wev;

    wev = c->write;

    for ( ;; ) {
        n = sendto(c->fd, buf, size, 0, c->sockaddr, c->socklen);

        njt_log_debug4(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "sendto: fd:%d %z of %uz to \"%V\"",
                       c->fd, n, size, &c->addr_text);

        if (n >= 0) {
            if ((size_t) n != size) {
                wev->error = 1;
                (void) njt_connection_error(c, 0, "sendto() incomplete");
                return NJT_ERROR;
            }

            c->sent += n;

            return n;
        }

        err = njt_socket_errno;

        if (err == NJT_EAGAIN) {
            wev->ready = 0;
            njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, NJT_EAGAIN,
                           "sendto() not ready");
            return NJT_AGAIN;
        }

        if (err != NJT_EINTR) {
            wev->error = 1;
            (void) njt_connection_error(c, err, "sendto() failed");
            return NJT_ERROR;
        }
    }
}
