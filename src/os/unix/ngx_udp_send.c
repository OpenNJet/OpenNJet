
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


ssize_t
ngx_udp_unix_send(ngx_connection_t *c, u_char *buf, size_t size)
{
    ssize_t       n;
    ngx_err_t     err;
    ngx_event_t  *wev;

    wev = c->write;

    for ( ;; ) {
        n = sendto(c->fd, buf, size, 0, c->sockaddr, c->socklen);

        ngx_log_debug4(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "sendto: fd:%d %z of %uz to \"%V\"",
                       c->fd, n, size, &c->addr_text);

        if (n >= 0) {
            if ((size_t) n != size) {
                wev->error = 1;
                (void) ngx_connection_error(c, 0, "sendto() incomplete");
                return NJT_ERROR;
            }

            c->sent += n;

            return n;
        }

        err = ngx_socket_errno;

        if (err == NJT_EAGAIN) {
            wev->ready = 0;
            ngx_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, NJT_EAGAIN,
                           "sendto() not ready");
            return NJT_AGAIN;
        }

        if (err != NJT_EINTR) {
            wev->error = 1;
            (void) ngx_connection_error(c, err, "sendto() failed");
            return NJT_ERROR;
        }
    }
}
