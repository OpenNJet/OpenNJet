
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


njt_chain_t *
njt_writev_chain(njt_connection_t *c, njt_chain_t *in, off_t limit)
{
    ssize_t        n, sent;
    off_t          send, prev_send;
    njt_chain_t   *cl;
    njt_event_t   *wev;
    njt_iovec_t    vec;
    struct iovec   iovs[NJT_IOVS_PREALLOCATE];

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

    vec.iovs = iovs;
    vec.nalloc = NJT_IOVS_PREALLOCATE;

    for ( ;; ) {
        prev_send = send;

        /* create the iovec and coalesce the neighbouring bufs */

        cl = njt_output_chain_to_iovec(&vec, in, limit - send, c->log);

        if (cl == NJT_CHAIN_ERROR) {
            return NJT_CHAIN_ERROR;
        }

        if (cl && cl->buf->in_file) {
            njt_log_error(NJT_LOG_ALERT, c->log, 0,
                          "file buf in writev "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            njt_debug_point();

            return NJT_CHAIN_ERROR;
        }

        send += vec.size;

        n = njt_writev(c, &vec);

        if (n == NJT_ERROR) {
            return NJT_CHAIN_ERROR;
        }

        sent = (n == NJT_AGAIN) ? 0 : n;

        c->sent += sent;

        in = njt_chain_update_sent(in, sent);

        if (send - prev_send != sent) {
            wev->ready = 0;
            return in;
        }

        if (send >= limit || in == NULL) {
            return in;
        }
    }
}


njt_chain_t *
njt_output_chain_to_iovec(njt_iovec_t *vec, njt_chain_t *in, size_t limit,
    njt_log_t *log)
{
    size_t         total, size;
    u_char        *prev;
    njt_uint_t     n;
    struct iovec  *iov;

    iov = NULL;
    prev = NULL;
    total = 0;
    n = 0;

    for ( /* void */ ; in && total < limit; in = in->next) {

        if (njt_buf_special(in->buf)) {
            continue;
        }

        if (in->buf->in_file) {
            break;
        }

        if (!njt_buf_in_memory(in->buf)) {
            njt_log_error(NJT_LOG_ALERT, log, 0,
                          "bad buf in output chain "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          in->buf->temporary,
                          in->buf->recycled,
                          in->buf->in_file,
                          in->buf->start,
                          in->buf->pos,
                          in->buf->last,
                          in->buf->file,
                          in->buf->file_pos,
                          in->buf->file_last);

            njt_debug_point();

            return NJT_CHAIN_ERROR;
        }

        size = in->buf->last - in->buf->pos;

        if (size > limit - total) {
            size = limit - total;
        }

        if (prev == in->buf->pos && iov != NULL) {
            iov->iov_len += size;

        } else {
            if (n == vec->nalloc) {
                break;
            }

            iov = &vec->iovs[n++];

            iov->iov_base = (void *) in->buf->pos;
            iov->iov_len = size;
        }

        prev = in->buf->pos + size;
        total += size;
    }

    vec->count = n;
    vec->size = total;

    return in;
}


ssize_t
njt_writev(njt_connection_t *c, njt_iovec_t *vec)
{
    ssize_t    n;
    njt_err_t  err;

eintr:

    n = writev(c->fd, vec->iovs, vec->count);

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "writev: %z of %uz", n, vec->size);

    if (n == -1) {
        err = njt_errno;

        switch (err) {
        case NJT_EAGAIN:
            njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, err,
                           "writev() not ready");
            return NJT_AGAIN;

        case NJT_EINTR:
            njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, err,
                           "writev() was interrupted");
            goto eintr;

        default:
            c->write->error = 1;
            njt_connection_error(c, err, "writev() failed");
            return NJT_ERROR;
        }
    }

    return n;
}
