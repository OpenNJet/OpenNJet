
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


ssize_t
njt_unix_recv(njt_connection_t *c, u_char *buf, size_t size)
{
    ssize_t       n;
    njt_err_t     err;
    njt_event_t  *rev;

    rev = c->read;

#if (NJT_HAVE_KQUEUE)

    if (njt_event_flags & NJT_USE_KQUEUE_EVENT) {
        njt_log_debug3(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "recv: eof:%d, avail:%d, err:%d",
                       rev->pending_eof, rev->available, rev->kq_errno);

        if (rev->available == 0) {
            if (rev->pending_eof) {
                rev->ready = 0;
                rev->eof = 1;

                if (rev->kq_errno) {
                    rev->error = 1;
                    njt_set_socket_errno(rev->kq_errno);

                    return njt_connection_error(c, rev->kq_errno,
                               "kevent() reported about an closed connection");
                }

                return 0;

            } else {
                rev->ready = 0;
                return NJT_AGAIN;
            }
        }
    }

#endif

#if (NJT_HAVE_EPOLLRDHUP)

    if ((njt_event_flags & NJT_USE_EPOLL_EVENT)
        && njt_use_epoll_rdhup)
    {
        njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "recv: eof:%d, avail:%d",
                       rev->pending_eof, rev->available);

        if (rev->available == 0 && !rev->pending_eof) {
            rev->ready = 0;
            return NJT_AGAIN;
        }
    }

#endif

    do {
        n = recv(c->fd, buf, size, 0);

        njt_log_debug3(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "recv: fd:%d %z of %uz", c->fd, n, size);

        if (n == 0) {
            rev->ready = 0;
            rev->eof = 1;

#if (NJT_HAVE_KQUEUE)

            /*
             * on FreeBSD recv() may return 0 on closed socket
             * even if kqueue reported about available data
             */

            if (njt_event_flags & NJT_USE_KQUEUE_EVENT) {
                rev->available = 0;
            }

#endif

            return 0;
        }

        if (n > 0) {

#if (NJT_HAVE_KQUEUE)

            if (njt_event_flags & NJT_USE_KQUEUE_EVENT) {
                rev->available -= n;

                /*
                 * rev->available may be negative here because some additional
                 * bytes may be received between kevent() and recv()
                 */

                if (rev->available <= 0) {
                    if (!rev->pending_eof) {
                        rev->ready = 0;
                    }

                    rev->available = 0;
                }

                return n;
            }

#endif

#if (NJT_HAVE_FIONREAD)

            if (rev->available >= 0) {
                rev->available -= n;

                /*
                 * negative rev->available means some additional bytes
                 * were received between kernel notification and recv(),
                 * and therefore ev->ready can be safely reset even for
                 * edge-triggered event methods
                 */

                if (rev->available < 0) {
                    rev->available = 0;
                    rev->ready = 0;
                }

                njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                               "recv: avail:%d", rev->available);

            } else if ((size_t) n == size) {

                if (njt_socket_nread(c->fd, &rev->available) == -1) {
                    n = njt_connection_error(c, njt_socket_errno,
                                             njt_socket_nread_n " failed");
                    break;
                }

                njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                               "recv: avail:%d", rev->available);
            }

#endif

#if (NJT_HAVE_EPOLLRDHUP)

            if ((njt_event_flags & NJT_USE_EPOLL_EVENT)
                && njt_use_epoll_rdhup)
            {
                if ((size_t) n < size) {
                    if (!rev->pending_eof) {
                        rev->ready = 0;
                    }

                    rev->available = 0;
                }

                return n;
            }

#endif

            if ((size_t) n < size
                && !(njt_event_flags & NJT_USE_GREEDY_EVENT))
            {
                rev->ready = 0;
            }

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
