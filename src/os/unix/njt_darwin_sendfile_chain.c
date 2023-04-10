
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


/*
 * It seems that Darwin 9.4 (Mac OS X 1.5) sendfile() has the same
 * old bug as early FreeBSD sendfile() syscall:
 * http://bugs.freebsd.org/33771
 *
 * Besides sendfile() has another bug: if one calls sendfile()
 * with both a header and a trailer, then sendfile() ignores a file part
 * at all and sends only the header and the trailer together.
 * For this reason we send a trailer only if there is no a header.
 *
 * Although sendfile() allows to pass a header or a trailer,
 * it may send the header or the trailer and a part of the file
 * in different packets.  And FreeBSD workaround (TCP_NOPUSH option)
 * does not help.
 */


njt_chain_t *
njt_darwin_sendfile_chain(njt_connection_t *c, njt_chain_t *in, off_t limit)
{
    int              rc;
    off_t            send, prev_send, sent;
    off_t            file_size;
    ssize_t          n;
    njt_uint_t       eintr;
    njt_err_t        err;
    njt_buf_t       *file;
    njt_event_t     *wev;
    njt_chain_t     *cl;
    njt_iovec_t      header, trailer;
    struct sf_hdtr   hdtr;
    struct iovec     headers[NJT_IOVS_PREALLOCATE];
    struct iovec     trailers[NJT_IOVS_PREALLOCATE];

    wev = c->write;

    if (!wev->ready) {
        return in;
    }

#if (NJT_HAVE_KQUEUE)

    if ((njt_event_flags & NJT_USE_KQUEUE_EVENT) && wev->pending_eof) {
        (void) njt_connection_error(c, wev->kq_errno,
                               "kevent() reported about an closed connection");
        wev->error = 1;
        return NJT_CHAIN_ERROR;
    }

#endif

    /* the maximum limit size is the maximum size_t value - the page size */

    if (limit == 0 || limit > (off_t) (NJT_MAX_SIZE_T_VALUE - njt_pagesize)) {
        limit = NJT_MAX_SIZE_T_VALUE - njt_pagesize;
    }

    send = 0;

    header.iovs = headers;
    header.nalloc = NJT_IOVS_PREALLOCATE;

    trailer.iovs = trailers;
    trailer.nalloc = NJT_IOVS_PREALLOCATE;

    for ( ;; ) {
        eintr = 0;
        prev_send = send;

        /* create the header iovec and coalesce the neighbouring bufs */

        cl = njt_output_chain_to_iovec(&header, in, limit - send, c->log);

        if (cl == NJT_CHAIN_ERROR) {
            return NJT_CHAIN_ERROR;
        }

        send += header.size;

        if (cl && cl->buf->in_file && send < limit) {
            file = cl->buf;

            /* coalesce the neighbouring file bufs */

            file_size = njt_chain_coalesce_file(&cl, limit - send);

            send += file_size;

            if (header.count == 0 && send < limit) {

                /*
                 * create the trailer iovec and coalesce the neighbouring bufs
                 */

                cl = njt_output_chain_to_iovec(&trailer, cl, limit - send,
                                               c->log);
                if (cl == NJT_CHAIN_ERROR) {
                    return NJT_CHAIN_ERROR;
                }

                send += trailer.size;

            } else {
                trailer.count = 0;
            }

            /*
             * sendfile() returns EINVAL if sf_hdtr's count is 0,
             * but corresponding pointer is not NULL
             */

            hdtr.headers = header.count ? header.iovs : NULL;
            hdtr.hdr_cnt = header.count;
            hdtr.trailers = trailer.count ? trailer.iovs : NULL;
            hdtr.trl_cnt = trailer.count;

            sent = header.size + file_size;

            njt_log_debug3(NJT_LOG_DEBUG_EVENT, c->log, 0,
                           "sendfile: @%O %O h:%uz",
                           file->file_pos, sent, header.size);

            rc = sendfile(file->file->fd, c->fd, file->file_pos,
                          &sent, &hdtr, 0);

            if (rc == -1) {
                err = njt_errno;

                switch (err) {
                case NJT_EAGAIN:
                    break;

                case NJT_EINTR:
                    eintr = 1;
                    break;

                default:
                    wev->error = 1;
                    (void) njt_connection_error(c, err, "sendfile() failed");
                    return NJT_CHAIN_ERROR;
                }

                njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, err,
                               "sendfile() sent only %O bytes", sent);
            }

            if (rc == 0 && sent == 0) {

                /*
                 * if rc and sent equal to zero, then someone
                 * has truncated the file, so the offset became beyond
                 * the end of the file
                 */

                njt_log_error(NJT_LOG_ALERT, c->log, 0,
                              "sendfile() reported that \"%s\" was truncated",
                              file->file->name.data);

                return NJT_CHAIN_ERROR;
            }

            njt_log_debug4(NJT_LOG_DEBUG_EVENT, c->log, 0,
                           "sendfile: %d, @%O %O:%O",
                           rc, file->file_pos, sent, file_size + header.size);

        } else {
            n = njt_writev(c, &header);

            if (n == NJT_ERROR) {
                return NJT_CHAIN_ERROR;
            }

            sent = (n == NJT_AGAIN) ? 0 : n;
        }

        c->sent += sent;

        in = njt_chain_update_sent(in, sent);

        if (eintr) {
            send = prev_send + sent;
            continue;
        }

        if (send - prev_send != sent) {
            wev->ready = 0;
            return in;
        }

        if (send >= limit || in == NULL) {
            return in;
        }
    }
}
