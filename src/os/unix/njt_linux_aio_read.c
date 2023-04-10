
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


extern int            njt_eventfd;
extern aio_context_t  njt_aio_ctx;


static void njt_file_aio_event_handler(njt_event_t *ev);


static int
io_submit(aio_context_t ctx, long n, struct iocb **paiocb)
{
    return syscall(SYS_io_submit, ctx, n, paiocb);
}


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
    njt_err_t         err;
    struct iocb      *piocb[1];
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
        ev->active = 0;
        ev->complete = 0;

        if (aio->res >= 0) {
            njt_set_errno(0);
            return aio->res;
        }

        njt_set_errno(-aio->res);

        njt_log_error(NJT_LOG_CRIT, file->log, njt_errno,
                      "aio read \"%s\" failed", file->name.data);

        return NJT_ERROR;
    }

    njt_memzero(&aio->aiocb, sizeof(struct iocb));

    aio->aiocb.aio_data = (uint64_t) (uintptr_t) ev;
    aio->aiocb.aio_lio_opcode = IOCB_CMD_PREAD;
    aio->aiocb.aio_fildes = file->fd;
    aio->aiocb.aio_buf = (uint64_t) (uintptr_t) buf;
    aio->aiocb.aio_nbytes = size;
    aio->aiocb.aio_offset = offset;
    aio->aiocb.aio_flags = IOCB_FLAG_RESFD;
    aio->aiocb.aio_resfd = njt_eventfd;

    ev->handler = njt_file_aio_event_handler;

    piocb[0] = &aio->aiocb;

    if (io_submit(njt_aio_ctx, 1, piocb) == 1) {
        ev->active = 1;
        ev->ready = 0;
        ev->complete = 0;

        return NJT_AGAIN;
    }

    err = njt_errno;

    if (err == NJT_EAGAIN) {
        return njt_read_file(file, buf, size, offset);
    }

    njt_log_error(NJT_LOG_CRIT, file->log, err,
                  "io_submit(\"%V\") failed", &file->name);

    if (err == NJT_ENOSYS) {
        njt_file_aio = 0;
        return njt_read_file(file, buf, size, offset);
    }

    return NJT_ERROR;
}


static void
njt_file_aio_event_handler(njt_event_t *ev)
{
    njt_event_aio_t  *aio;

    aio = ev->data;

    njt_log_debug2(NJT_LOG_DEBUG_CORE, ev->log, 0,
                   "aio event handler fd:%d %V", aio->fd, &aio->file->name);

    aio->handler(ev);
}
