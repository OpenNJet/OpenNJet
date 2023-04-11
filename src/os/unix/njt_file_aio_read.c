
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


/*
 * FreeBSD file AIO features and quirks:
 *
 *    if an asked data are already in VM cache, then aio_error() returns 0,
 *    and the data are already copied in buffer;
 *
 *    aio_read() preread in VM cache as minimum 16K (probably BKVASIZE);
 *    the first AIO preload may be up to 128K;
 *
 *    aio_read/aio_error() may return EINPROGRESS for just written data;
 *
 *    kqueue EVFILT_AIO filter is level triggered only: an event repeats
 *    until aio_return() will be called;
 *
 *    aio_cancel() cannot cancel file AIO: it returns AIO_NOTCANCELED always.
 */


extern int  njt_kqueue;


static ssize_t njt_file_aio_result(njt_file_t *file, njt_event_aio_t *aio,
    njt_event_t *ev);
static void njt_file_aio_event_handler(njt_event_t *ev);


njt_int_t
njt_file_aio_init(njt_file_t *file, njt_pool_t *pool)
{
    njt_event_aio_t  *aio;

    aio = njt_pcalloc(pool, sizeof(njt_event_aio_t));
    if (aio == NULL) {
        return NJT_ERROR;
    }

    aio->file = file;
    aio->fd = file->fd;
    aio->event.data = aio;
    aio->event.ready = 1;
    aio->event.log = file->log;

    file->aio = aio;

    return NJT_OK;
}


ssize_t
njt_file_aio_read(njt_file_t *file, u_char *buf, size_t size, off_t offset,
    njt_pool_t *pool)
{
    int               n;
    njt_event_t      *ev;
    njt_event_aio_t  *aio;

    if (!njt_file_aio) {
        return njt_read_file(file, buf, size, offset);
    }

    if (file->aio == NULL && njt_file_aio_init(file, pool) != NJT_OK) {
        return NJT_ERROR;
    }

    aio = file->aio;
    ev = &aio->event;

    if (!ev->ready) {
        njt_log_error(NJT_LOG_ALERT, file->log, 0,
                      "second aio post for \"%V\"", &file->name);
        return NJT_AGAIN;
    }

    njt_log_debug4(NJT_LOG_DEBUG_CORE, file->log, 0,
                   "aio complete:%d @%O:%uz %V",
                   ev->complete, offset, size, &file->name);

    if (ev->complete) {
        ev->complete = 0;
        njt_set_errno(aio->err);

        if (aio->err == 0) {
            return aio->nbytes;
        }

        njt_log_error(NJT_LOG_CRIT, file->log, njt_errno,
                      "aio read \"%s\" failed", file->name.data);

        return NJT_ERROR;
    }

    njt_memzero(&aio->aiocb, sizeof(struct aiocb));

    aio->aiocb.aio_fildes = file->fd;
    aio->aiocb.aio_offset = offset;
    aio->aiocb.aio_buf = buf;
    aio->aiocb.aio_nbytes = size;
#if (NJT_HAVE_KQUEUE)
    aio->aiocb.aio_sigevent.sigev_notify_kqueue = njt_kqueue;
    aio->aiocb.aio_sigevent.sigev_notify = SIGEV_KEVENT;
    aio->aiocb.aio_sigevent.sigev_value.sival_ptr = ev;
#endif
    ev->handler = njt_file_aio_event_handler;

    n = aio_read(&aio->aiocb);

    if (n == -1) {
        n = njt_errno;

        if (n == NJT_EAGAIN) {
            return njt_read_file(file, buf, size, offset);
        }

        njt_log_error(NJT_LOG_CRIT, file->log, n,
                      "aio_read(\"%V\") failed", &file->name);

        if (n == NJT_ENOSYS) {
            njt_file_aio = 0;
            return njt_read_file(file, buf, size, offset);
        }

        return NJT_ERROR;
    }

    njt_log_debug2(NJT_LOG_DEBUG_CORE, file->log, 0,
                   "aio_read: fd:%d %d", file->fd, n);

    ev->active = 1;
    ev->ready = 0;
    ev->complete = 0;

    return njt_file_aio_result(aio->file, aio, ev);
}


static ssize_t
njt_file_aio_result(njt_file_t *file, njt_event_aio_t *aio, njt_event_t *ev)
{
    int        n;
    njt_err_t  err;

    n = aio_error(&aio->aiocb);

    njt_log_debug2(NJT_LOG_DEBUG_CORE, file->log, 0,
                   "aio_error: fd:%d %d", file->fd, n);

    if (n == -1) {
        err = njt_errno;
        aio->err = err;

        njt_log_error(NJT_LOG_ALERT, file->log, err,
                      "aio_error(\"%V\") failed", &file->name);
        return NJT_ERROR;
    }

    if (n == NJT_EINPROGRESS) {
        if (ev->ready) {
            ev->ready = 0;
            njt_log_error(NJT_LOG_ALERT, file->log, n,
                          "aio_read(\"%V\") still in progress",
                          &file->name);
        }

        return NJT_AGAIN;
    }

    n = aio_return(&aio->aiocb);

    if (n == -1) {
        err = njt_errno;
        aio->err = err;
        ev->ready = 1;

        njt_log_error(NJT_LOG_CRIT, file->log, err,
                      "aio_return(\"%V\") failed", &file->name);
        return NJT_ERROR;
    }

    aio->err = 0;
    aio->nbytes = n;
    ev->ready = 1;
    ev->active = 0;

    njt_log_debug2(NJT_LOG_DEBUG_CORE, file->log, 0,
                   "aio_return: fd:%d %d", file->fd, n);

    return n;
}


static void
njt_file_aio_event_handler(njt_event_t *ev)
{
    njt_event_aio_t  *aio;

    aio = ev->data;

    njt_log_debug2(NJT_LOG_DEBUG_CORE, ev->log, 0,
                   "aio event handler fd:%d %V", aio->fd, &aio->file->name);

    if (njt_file_aio_result(aio->file, aio, ev) != NJT_AGAIN) {
        aio->handler(ev);
    }
}
