
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


static ssize_t njt_linux_sendfile(njt_connection_t *c, njt_buf_t *file,
    size_t size);

#if (NJT_THREADS)
#include <njt_thread_pool.h>

#if !(NJT_HAVE_SENDFILE64)
#error sendfile64() is required!
#endif

static ssize_t njt_linux_sendfile_thread(njt_connection_t *c, njt_buf_t *file,
    size_t size);
static void njt_linux_sendfile_thread_handler(void *data, njt_log_t *log);
#endif


/*
 * On Linux up to 2.4.21 sendfile() (syscall #187) works with 32-bit
 * offsets only, and the including <sys/sendfile.h> breaks the compiling,
 * if off_t is 64 bit wide.  So we use own sendfile() definition, where offset
 * parameter is int32_t, and use sendfile() for the file parts below 2G only,
 * see src/os/unix/njt_linux_config.h
 *
 * Linux 2.4.21 has the new sendfile64() syscall #239.
 *
 * On Linux up to 2.6.16 sendfile() does not allow to pass the count parameter
 * more than 2G-1 bytes even on 64-bit platforms: it returns EINVAL,
 * so we limit it to 2G-1 bytes.
 *
 * On Linux 2.6.16 and later, sendfile() silently limits the count parameter
 * to 2G minus the page size, even on 64-bit platforms.
 */

#define NJT_SENDFILE_MAXSIZE  2147483647L


njt_chain_t *
njt_linux_sendfile_chain(njt_connection_t *c, njt_chain_t *in, off_t limit)
{
    int            tcp_nodelay;
    off_t          send, prev_send;
    size_t         file_size, sent;
    ssize_t        n;
    njt_err_t      err;
    njt_buf_t     *file;
    njt_event_t   *wev;
    njt_chain_t   *cl;
    njt_iovec_t    header;
    struct iovec   headers[NJT_IOVS_PREALLOCATE];

    wev = c->write;

    if (!wev->ready) {
        return in;
    }


    /* the maximum limit size is 2G-1 - the page size */

    if (limit == 0 || limit > (off_t) (NJT_SENDFILE_MAXSIZE - njt_pagesize)) {
        limit = NJT_SENDFILE_MAXSIZE - njt_pagesize;
    }


    send = 0;

    header.iovs = headers;
    header.nalloc = NJT_IOVS_PREALLOCATE;

    for ( ;; ) {
        prev_send = send;

        /* create the iovec and coalesce the neighbouring bufs */

        cl = njt_output_chain_to_iovec(&header, in, limit - send, c->log);

        if (cl == NJT_CHAIN_ERROR) {
            return NJT_CHAIN_ERROR;
        }

        send += header.size;

        /* set TCP_CORK if there is a header before a file */

        if (c->tcp_nopush == NJT_TCP_NOPUSH_UNSET
            && header.count != 0
            && cl
            && cl->buf->in_file)
        {
            /* the TCP_CORK and TCP_NODELAY are mutually exclusive */

            if (c->tcp_nodelay == NJT_TCP_NODELAY_SET) {

                tcp_nodelay = 0;

                if (setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY,
                               (const void *) &tcp_nodelay, sizeof(int)) == -1)
                {
                    err = njt_socket_errno;

                    /*
                     * there is a tiny chance to be interrupted, however,
                     * we continue a processing with the TCP_NODELAY
                     * and without the TCP_CORK
                     */

                    if (err != NJT_EINTR) {
                        wev->error = 1;
                        njt_connection_error(c, err,
                                             "setsockopt(TCP_NODELAY) failed");
                        return NJT_CHAIN_ERROR;
                    }

                } else {
                    c->tcp_nodelay = NJT_TCP_NODELAY_UNSET;

                    njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                                   "no tcp_nodelay");
                }
            }

            if (c->tcp_nodelay == NJT_TCP_NODELAY_UNSET) {

                if (njt_tcp_nopush(c->fd) == -1) {
                    err = njt_socket_errno;

                    /*
                     * there is a tiny chance to be interrupted, however,
                     * we continue a processing without the TCP_CORK
                     */

                    if (err != NJT_EINTR) {
                        wev->error = 1;
                        njt_connection_error(c, err,
                                             njt_tcp_nopush_n " failed");
                        return NJT_CHAIN_ERROR;
                    }

                } else {
                    c->tcp_nopush = NJT_TCP_NOPUSH_SET;

                    njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                                   "tcp_nopush");
                }
            }
        }

        /* get the file buf */

        if (header.count == 0 && cl && cl->buf->in_file && send < limit) {
            file = cl->buf;

            /* coalesce the neighbouring file bufs */

            file_size = (size_t) njt_chain_coalesce_file(&cl, limit - send);

            send += file_size;
#if 1
            if (file_size == 0) {
                njt_debug_point();
                return NJT_CHAIN_ERROR;
            }
#endif

            n = njt_linux_sendfile(c, file, file_size);

            if (n == NJT_ERROR) {
                return NJT_CHAIN_ERROR;
            }

            if (n == NJT_DONE) {
                /* thread task posted */
                return in;
            }

            sent = (n == NJT_AGAIN) ? 0 : n;

        } else {
            n = njt_writev(c, &header);

            if (n == NJT_ERROR) {
                return NJT_CHAIN_ERROR;
            }

            sent = (n == NJT_AGAIN) ? 0 : n;
        }

        c->sent += sent;

        in = njt_chain_update_sent(in, sent);

        if (n == NJT_AGAIN) {
            wev->ready = 0;
            return in;
        }

        if ((size_t) (send - prev_send) != sent) {

            /*
             * sendfile() on Linux 4.3+ might be interrupted at any time,
             * and provides no indication if it was interrupted or not,
             * so we have to retry till an explicit EAGAIN
             *
             * sendfile() in threads can also report less bytes written
             * than we are prepared to send now, since it was started in
             * some point in the past, so we again have to retry
             */

            send = prev_send + sent;
        }

        if (send >= limit || in == NULL) {
            return in;
        }
    }
}


static ssize_t
njt_linux_sendfile(njt_connection_t *c, njt_buf_t *file, size_t size)
{
#if (NJT_HAVE_SENDFILE64)
    off_t      offset;
#else
    int32_t    offset;
#endif
    ssize_t    n;
    njt_err_t  err;

#if (NJT_THREADS)

    if (file->file->thread_handler) {
        return njt_linux_sendfile_thread(c, file, size);
    }

#endif

#if (NJT_HAVE_SENDFILE64)
    offset = file->file_pos;
#else
    offset = (int32_t) file->file_pos;
#endif

eintr:

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "sendfile: @%O %uz", file->file_pos, size);

    n = sendfile(c->fd, file->file->fd, &offset, size);

    if (n == -1) {
        err = njt_errno;

        switch (err) {
        case NJT_EAGAIN:
            njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, err,
                           "sendfile() is not ready");
            return NJT_AGAIN;

        case NJT_EINTR:
            njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, err,
                           "sendfile() was interrupted");
            goto eintr;

        default:
            c->write->error = 1;
            njt_connection_error(c, err, "sendfile() failed");
            return NJT_ERROR;
        }
    }

    if (n == 0) {
        /*
         * if sendfile returns zero, then someone has truncated the file,
         * so the offset became beyond the end of the file
         */

        njt_log_error(NJT_LOG_ALERT, c->log, 0,
                      "sendfile() reported that \"%s\" was truncated at %O",
                      file->file->name.data, file->file_pos);

        return NJT_ERROR;
    }

    njt_log_debug3(NJT_LOG_DEBUG_EVENT, c->log, 0, "sendfile: %z of %uz @%O",
                   n, size, file->file_pos);

    return n;
}


#if (NJT_THREADS)

typedef struct {
    njt_buf_t     *file;
    njt_socket_t   socket;
    size_t         size;

    size_t         sent;
    njt_err_t      err;
} njt_linux_sendfile_ctx_t;


static ssize_t
njt_linux_sendfile_thread(njt_connection_t *c, njt_buf_t *file, size_t size)
{
    njt_event_t               *wev;
    njt_thread_task_t         *task;
    njt_linux_sendfile_ctx_t  *ctx;

    njt_log_debug3(NJT_LOG_DEBUG_CORE, c->log, 0,
                   "linux sendfile thread: %d, %uz, %O",
                   file->file->fd, size, file->file_pos);

    task = c->sendfile_task;

    if (task == NULL) {
        task = njt_thread_task_alloc(c->pool, sizeof(njt_linux_sendfile_ctx_t));
        if (task == NULL) {
            return NJT_ERROR;
        }

        task->handler = njt_linux_sendfile_thread_handler;

        c->sendfile_task = task;
    }

    ctx = task->ctx;
    wev = c->write;

    if (task->event.complete) {
        task->event.complete = 0;

        if (ctx->err == NJT_EAGAIN) {
            /*
             * if wev->complete is set, this means that a write event
             * happened while we were waiting for the thread task, so
             * we have to retry sending even on EAGAIN
             */

            if (wev->complete) {
                return 0;
            }

            return NJT_AGAIN;
        }

        if (ctx->err) {
            wev->error = 1;
            njt_connection_error(c, ctx->err, "sendfile() failed");
            return NJT_ERROR;
        }

        if (ctx->sent == 0) {
            /*
             * if sendfile returns zero, then someone has truncated the file,
             * so the offset became beyond the end of the file
             */

            njt_log_error(NJT_LOG_ALERT, c->log, 0,
                          "sendfile() reported that \"%s\" was truncated at %O",
                          file->file->name.data, file->file_pos);

            return NJT_ERROR;
        }

        return ctx->sent;
    }

    ctx->file = file;
    ctx->socket = c->fd;
    ctx->size = size;

    wev->complete = 0;

    if (file->file->thread_handler(task, file->file) != NJT_OK) {
        return NJT_ERROR;
    }

    return NJT_DONE;
}


static void
njt_linux_sendfile_thread_handler(void *data, njt_log_t *log)
{
    njt_linux_sendfile_ctx_t *ctx = data;

    off_t       offset;
    ssize_t     n;
    njt_buf_t  *file;

    njt_log_debug0(NJT_LOG_DEBUG_CORE, log, 0, "linux sendfile thread handler");

    file = ctx->file;
    offset = file->file_pos;

again:

    n = sendfile(ctx->socket, file->file->fd, &offset, ctx->size);

    if (n == -1) {
        ctx->err = njt_errno;

    } else {
        ctx->sent = n;
        ctx->err = 0;
    }

#if 0
    njt_time_update();
#endif

    njt_log_debug4(NJT_LOG_DEBUG_EVENT, log, 0,
                   "sendfile: %z (err: %d) of %uz @%O",
                   n, ctx->err, ctx->size, file->file_pos);

    if (ctx->err == NJT_EINTR) {
        goto again;
    }
}

#endif /* NJT_THREADS */
