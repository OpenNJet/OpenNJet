
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


#if (NJT_TEST_BUILD_SOLARIS_SENDFILEV)

/* Solaris declarations */

typedef struct sendfilevec {
    int     sfv_fd;
    u_int   sfv_flag;
    off_t   sfv_off;
    size_t  sfv_len;
} sendfilevec_t;

#define SFV_FD_SELF  -2

static ssize_t sendfilev(int fd, const struct sendfilevec *vec,
    int sfvcnt, size_t *xferred)
{
    return -1;
}

njt_chain_t *njt_solaris_sendfilev_chain(njt_connection_t *c, njt_chain_t *in,
    off_t limit);

#endif


#define NJT_SENDFILEVECS  NJT_IOVS_PREALLOCATE


njt_chain_t *
njt_solaris_sendfilev_chain(njt_connection_t *c, njt_chain_t *in, off_t limit)
{
    int             fd;
    u_char         *prev;
    off_t           size, send, prev_send, aligned, fprev;
    size_t          sent;
    ssize_t         n;
    njt_int_t       eintr;
    njt_err_t       err;
    njt_buf_t      *file;
    njt_uint_t      nsfv;
    sendfilevec_t  *sfv, sfvs[NJT_SENDFILEVECS];
    njt_event_t    *wev;
    njt_chain_t    *cl;

    wev = c->write;

    if (!wev->ready) {
        return in;
    }

    if (!c->sendfile) {
        return njt_writev_chain(c, in, limit);
    }


    /* the maximum limit size is the maximum size_t value - the page size */

    if (limit == 0 || limit > (off_t) (NJT_MAX_SIZE_T_VALUE - njt_pagesize)) {
        limit = NJT_MAX_SIZE_T_VALUE - njt_pagesize;
    }


    send = 0;

    for ( ;; ) {
        fd = SFV_FD_SELF;
        prev = NULL;
        fprev = 0;
        file = NULL;
        sfv = NULL;
        eintr = 0;
        sent = 0;
        prev_send = send;

        nsfv = 0;

        /* create the sendfilevec and coalesce the neighbouring bufs */

        for (cl = in; cl && send < limit; cl = cl->next) {

            if (njt_buf_special(cl->buf)) {
                continue;
            }

            if (njt_buf_in_memory_only(cl->buf)) {
                fd = SFV_FD_SELF;

                size = cl->buf->last - cl->buf->pos;

                if (send + size > limit) {
                    size = limit - send;
                }

                if (prev == cl->buf->pos) {
                    sfv->sfv_len += (size_t) size;

                } else {
                    if (nsfv == NJT_SENDFILEVECS) {
                        break;
                    }

                    sfv = &sfvs[nsfv++];

                    sfv->sfv_fd = SFV_FD_SELF;
                    sfv->sfv_flag = 0;
                    sfv->sfv_off = (off_t) (uintptr_t) cl->buf->pos;
                    sfv->sfv_len = (size_t) size;
                }

                prev = cl->buf->pos + (size_t) size;
                send += size;

            } else {
                prev = NULL;

                size = cl->buf->file_last - cl->buf->file_pos;

                if (send + size > limit) {
                    size = limit - send;

                    aligned = (cl->buf->file_pos + size + njt_pagesize - 1)
                               & ~((off_t) njt_pagesize - 1);

                    if (aligned <= cl->buf->file_last) {
                        size = aligned - cl->buf->file_pos;
                    }
                }

                if (fd == cl->buf->file->fd && fprev == cl->buf->file_pos) {
                    sfv->sfv_len += (size_t) size;

                } else {
                    if (nsfv == NJT_SENDFILEVECS) {
                        break;
                    }

                    sfv = &sfvs[nsfv++];

                    fd = cl->buf->file->fd;
                    sfv->sfv_fd = fd;
                    sfv->sfv_flag = 0;
                    sfv->sfv_off = cl->buf->file_pos;
                    sfv->sfv_len = (size_t) size;
                }

                file = cl->buf;
                fprev = cl->buf->file_pos + size;
                send += size;
            }
        }

        n = sendfilev(c->fd, sfvs, nsfv, &sent);

        if (n == -1) {
            err = njt_errno;

            switch (err) {
            case NJT_EAGAIN:
                break;

            case NJT_EINTR:
                eintr = 1;
                break;

            default:
                wev->error = 1;
                njt_connection_error(c, err, "sendfilev() failed");
                return NJT_CHAIN_ERROR;
            }

            njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, err,
                          "sendfilev() sent only %uz bytes", sent);

        } else if (n == 0 && sent == 0) {

            /*
             * sendfilev() is documented to return -1 with errno
             * set to EINVAL if svf_len is greater than the file size,
             * but at least Solaris 11 returns 0 instead
             */

            if (file) {
                njt_log_error(NJT_LOG_ALERT, c->log, 0,
                        "sendfilev() reported that \"%s\" was truncated at %O",
                        file->file->name.data, file->file_pos);

            } else {
                njt_log_error(NJT_LOG_ALERT, c->log, 0,
                              "sendfilev() returned 0 with memory buffers");
            }

            return NJT_CHAIN_ERROR;
        }

        njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "sendfilev: %z %z", n, sent);

        c->sent += sent;

        in = njt_chain_update_sent(in, sent);

        if (eintr) {
            send = prev_send + sent;
            continue;
        }

        if (send - prev_send != (off_t) sent) {
            wev->ready = 0;
            return in;
        }

        if (send >= limit || in == NULL) {
            return in;
        }
    }
}
