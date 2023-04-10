
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


/*
 * Although FreeBSD sendfile() allows to pass a header and a trailer,
 * it cannot send a header with a part of the file in one packet until
 * FreeBSD 5.3.  Besides, over the fast ethernet connection sendfile()
 * may send the partially filled packets, i.e. the 8 file pages may be sent
 * as the 11 full 1460-bytes packets, then one incomplete 324-bytes packet,
 * and then again the 11 full 1460-bytes packets.
 *
 * Therefore we use the TCP_NOPUSH option (similar to Linux's TCP_CORK)
 * to postpone the sending - it not only sends a header and the first part of
 * the file in one packet, but also sends the file pages in the full packets.
 *
 * But until FreeBSD 4.5 turning TCP_NOPUSH off does not flush a pending
 * data that less than MSS, so that data may be sent with 5 second delay.
 * So we do not use TCP_NOPUSH on FreeBSD prior to 4.5, although it can be used
 * for non-keepalive HTTP connections.
 */


njt_chain_t *
njt_freebsd_sendfile_chain(njt_connection_t *c, njt_chain_t *in, off_t limit)
{
    int              rc, flags;
    off_t            send, prev_send, sent;
    size_t           file_size;
    ssize_t          n;
    njt_err_t        err;
    njt_buf_t       *file;
    njt_uint_t       eintr, eagain;
#if (NJT_HAVE_SENDFILE_NODISKIO)
    njt_uint_t       ebusy;
#endif
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
    eagain = 0;
    flags = 0;

    header.iovs = headers;
    header.nalloc = NJT_IOVS_PREALLOCATE;

    trailer.iovs = trailers;
    trailer.nalloc = NJT_IOVS_PREALLOCATE;

    for ( ;; ) {
        eintr = 0;
#if (NJT_HAVE_SENDFILE_NODISKIO)
        ebusy = 0;
#endif
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

            file_size = (size_t) njt_chain_coalesce_file(&cl, limit - send);

            send += file_size;

            if (send < limit) {

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

            if (njt_freebsd_use_tcp_nopush
                && c->tcp_nopush == NJT_TCP_NOPUSH_UNSET)
            {
                if (njt_tcp_nopush(c->fd) == -1) {
                    err = njt_socket_errno;

                    /*
                     * there is a tiny chance to be interrupted, however,
                     * we continue a processing without the TCP_NOPUSH
                     */

                    if (err != NJT_EINTR) {
                        wev->error = 1;
                        (void) njt_connection_error(c, err,
                                                    njt_tcp_nopush_n " failed");
                        return NJT_CHAIN_ERROR;
                    }

                } else {
                    c->tcp_nopush = NJT_TCP_NOPUSH_SET;

                    njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                                   "tcp_nopush");
                }
            }

            /*
             * sendfile() does unneeded work if sf_hdtr's count is 0,
             * but corresponding pointer is not NULL
             */

            hdtr.headers = header.count ? header.iovs : NULL;
            hdtr.hdr_cnt = header.count;
            hdtr.trailers = trailer.count ? trailer.iovs : NULL;
            hdtr.trl_cnt = trailer.count;

            /*
             * the "nbytes bug" of the old sendfile() syscall:
             * http://bugs.freebsd.org/33771
             */

            if (!njt_freebsd_sendfile_nbytes_bug) {
                header.size = 0;
            }

            sent = 0;

#if (NJT_HAVE_SENDFILE_NODISKIO)

            flags = (c->busy_count <= 2) ? SF_NODISKIO : 0;

            if (file->file->directio) {
                flags |= SF_NOCACHE;
            }

#endif

            rc = sendfile(file->file->fd, c->fd, file->file_pos,
                          file_size + header.size, &hdtr, &sent, flags);

            if (rc == -1) {
                err = njt_errno;

                switch (err) {
                case NJT_EAGAIN:
                    eagain = 1;
                    break;

                case NJT_EINTR:
                    eintr = 1;
                    break;

#if (NJT_HAVE_SENDFILE_NODISKIO)
                case NJT_EBUSY:
                    ebusy = 1;
                    break;
#endif

                default:
                    wev->error = 1;
                    (void) njt_connection_error(c, err, "sendfile() failed");
                    return NJT_CHAIN_ERROR;
                }

                njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, err,
                               "sendfile() sent only %O bytes", sent);

            /*
             * sendfile() in FreeBSD 3.x-4.x may return value >= 0
             * on success, although only 0 is documented
             */

            } else if (rc >= 0 && sent == 0) {

                /*
                 * if rc is OK and sent equal to zero, then someone
                 * has truncated the file, so the offset became beyond
                 * the end of the file
                 */

                njt_log_error(NJT_LOG_ALERT, c->log, 0,
                         "sendfile() reported that \"%s\" was truncated at %O",
                         file->file->name.data, file->file_pos);

                return NJT_CHAIN_ERROR;
            }

            njt_log_debug4(NJT_LOG_DEBUG_EVENT, c->log, 0,
                           "sendfile: %d, @%O %O:%uz",
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

#if (NJT_HAVE_SENDFILE_NODISKIO)

        if (ebusy) {
            if (sent == 0) {
                c->busy_count++;

                njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                               "sendfile() busy, count:%d", c->busy_count);

            } else {
                c->busy_count = 0;
            }

            if (wev->posted) {
                njt_delete_posted_event(wev);
            }

            njt_post_event(wev, &njt_posted_next_events);

            wev->ready = 0;
            return in;
        }

        c->busy_count = 0;

#endif

        if (eagain) {

            /*
             * sendfile() may return EAGAIN, even if it has sent a whole file
             * part, it indicates that the successive sendfile() call would
             * return EAGAIN right away and would not send anything.
             * We use it as a hint.
             */

            wev->ready = 0;
            return in;
        }

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
