
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


#if 0
#define NJT_SENDFILE_LIMIT  4096
#endif

/*
 * When DIRECTIO is enabled FreeBSD, Solaris, and MacOSX read directly
 * to an application memory from a device if parameters are aligned
 * to device sector boundary (512 bytes).  They fallback to usual read
 * operation if the parameters are not aligned.
 * Linux allows DIRECTIO only if the parameters are aligned to a filesystem
 * sector boundary, otherwise it returns EINVAL.  The sector size is
 * usually 512 bytes, however, on XFS it may be 4096 bytes.
 */

#define NJT_NONE            1


static njt_inline njt_int_t
    njt_output_chain_as_is(njt_output_chain_ctx_t *ctx, njt_buf_t *buf);
static njt_int_t njt_output_chain_add_copy(njt_pool_t *pool,
    njt_chain_t **chain, njt_chain_t *in);
static njt_int_t njt_output_chain_align_file_buf(njt_output_chain_ctx_t *ctx,
    off_t bsize);
static njt_int_t njt_output_chain_get_buf(njt_output_chain_ctx_t *ctx,
    off_t bsize);
static njt_int_t njt_output_chain_copy_buf(njt_output_chain_ctx_t *ctx);


njt_int_t
njt_output_chain(njt_output_chain_ctx_t *ctx, njt_chain_t *in)
{
    off_t         bsize;
    njt_int_t     rc, last;
    njt_chain_t  *cl, *out, **last_out;

    if (ctx->in == NULL && ctx->busy == NULL
#if (NJT_HAVE_FILE_AIO || NJT_THREADS)
        && !ctx->aio
#endif
       )
    {
        /*
         * the short path for the case when the ctx->in and ctx->busy chains
         * are empty, the incoming chain is empty too or has the single buf
         * that does not require the copy
         */

        if (in == NULL) {
            return ctx->output_filter(ctx->filter_ctx, in);
        }

        if (in->next == NULL
#if (NJT_SENDFILE_LIMIT)
            && !(in->buf->in_file && in->buf->file_last > NJT_SENDFILE_LIMIT)
#endif
            && njt_output_chain_as_is(ctx, in->buf))
        {
            return ctx->output_filter(ctx->filter_ctx, in);
        }
    }

    /* add the incoming buf to the chain ctx->in */

    if (in) {
        if (njt_output_chain_add_copy(ctx->pool, &ctx->in, in) == NJT_ERROR) {
            return NJT_ERROR;
        }
    }

    out = NULL;
    last_out = &out;
    last = NJT_NONE;

    for ( ;; ) {

#if (NJT_HAVE_FILE_AIO || NJT_THREADS)
        if (ctx->aio) {
            return NJT_AGAIN;
        }
#endif

        while (ctx->in) {

            /*
             * cycle while there are the ctx->in bufs
             * and there are the free output bufs to copy in
             */

            bsize = njt_buf_size(ctx->in->buf);

            if (bsize == 0 && !njt_buf_special(ctx->in->buf)) {

                njt_log_error(NJT_LOG_ALERT, ctx->pool->log, 0,
                              "zero size buf in output "
                              "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                              ctx->in->buf->temporary,
                              ctx->in->buf->recycled,
                              ctx->in->buf->in_file,
                              ctx->in->buf->start,
                              ctx->in->buf->pos,
                              ctx->in->buf->last,
                              ctx->in->buf->file,
                              ctx->in->buf->file_pos,
                              ctx->in->buf->file_last);

                njt_debug_point();

                ctx->in = ctx->in->next;

                continue;
            }

            if (bsize < 0) {

                njt_log_error(NJT_LOG_ALERT, ctx->pool->log, 0,
                              "negative size buf in output "
                              "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                              ctx->in->buf->temporary,
                              ctx->in->buf->recycled,
                              ctx->in->buf->in_file,
                              ctx->in->buf->start,
                              ctx->in->buf->pos,
                              ctx->in->buf->last,
                              ctx->in->buf->file,
                              ctx->in->buf->file_pos,
                              ctx->in->buf->file_last);

                njt_debug_point();

                return NJT_ERROR;
            }

            if (njt_output_chain_as_is(ctx, ctx->in->buf)) {

                /* move the chain link to the output chain */

                cl = ctx->in;
                ctx->in = cl->next;

                *last_out = cl;
                last_out = &cl->next;
                cl->next = NULL;

                continue;
            }

            if (ctx->buf == NULL) {

                rc = njt_output_chain_align_file_buf(ctx, bsize);

                if (rc == NJT_ERROR) {
                    return NJT_ERROR;
                }

                if (rc != NJT_OK) {

                    if (ctx->free) {

                        /* get the free buf */

                        cl = ctx->free;
                        ctx->buf = cl->buf;
                        ctx->free = cl->next;

                        njt_free_chain(ctx->pool, cl);

                    } else if (out || ctx->allocated == ctx->bufs.num) {

                        break;

                    } else if (njt_output_chain_get_buf(ctx, bsize) != NJT_OK) {
                        return NJT_ERROR;
                    }
                }
            }

            rc = njt_output_chain_copy_buf(ctx);

            if (rc == NJT_ERROR) {
                return rc;
            }

            if (rc == NJT_AGAIN) {
                if (out) {
                    break;
                }

                return rc;
            }

            /* delete the completed buf from the ctx->in chain */

            if (njt_buf_size(ctx->in->buf) == 0) {
                ctx->in = ctx->in->next;
            }

            cl = njt_alloc_chain_link(ctx->pool);
            if (cl == NULL) {
                return NJT_ERROR;
            }

            cl->buf = ctx->buf;
            cl->next = NULL;
            *last_out = cl;
            last_out = &cl->next;
            ctx->buf = NULL;
        }

        if (out == NULL && last != NJT_NONE) {

            if (ctx->in) {
                return NJT_AGAIN;
            }

            return last;
        }

        last = ctx->output_filter(ctx->filter_ctx, out);

        if (last == NJT_ERROR || last == NJT_DONE) {
            return last;
        }

        njt_chain_update_chains(ctx->pool, &ctx->free, &ctx->busy, &out,
                                ctx->tag);
        last_out = &out;
    }
}


static njt_inline njt_int_t
njt_output_chain_as_is(njt_output_chain_ctx_t *ctx, njt_buf_t *buf)
{
    njt_uint_t  sendfile;

    if (njt_buf_special(buf)) {
        return 1;
    }

#if (NJT_THREADS)
    if (buf->in_file) {
        buf->file->thread_handler = ctx->thread_handler;
        buf->file->thread_ctx = ctx->filter_ctx;
    }
#endif

    sendfile = ctx->sendfile;

#if (NJT_SENDFILE_LIMIT)

    if (buf->in_file && buf->file_pos >= NJT_SENDFILE_LIMIT) {
        sendfile = 0;
    }

#endif

#if !(NJT_HAVE_SENDFILE_NODISKIO)

    /*
     * With DIRECTIO, disable sendfile() unless sendfile(SF_NOCACHE)
     * is available.
     */

    if (buf->in_file && buf->file->directio) {
        sendfile = 0;
    }

#endif

    if (!sendfile) {

        if (!njt_buf_in_memory(buf)) {
            return 0;
        }

        buf->in_file = 0;
    }

    if (ctx->need_in_memory && !njt_buf_in_memory(buf)) {
        return 0;
    }

    if (ctx->need_in_temp && (buf->memory || buf->mmap)) {
        return 0;
    }

    return 1;
}


static njt_int_t
njt_output_chain_add_copy(njt_pool_t *pool, njt_chain_t **chain,
    njt_chain_t *in)
{
    njt_chain_t  *cl, **ll;
#if (NJT_SENDFILE_LIMIT)
    njt_buf_t    *b, *buf;
#endif

    ll = chain;

    for (cl = *chain; cl; cl = cl->next) {
        ll = &cl->next;
    }

    while (in) {

        cl = njt_alloc_chain_link(pool);
        if (cl == NULL) {
            return NJT_ERROR;
        }

#if (NJT_SENDFILE_LIMIT)

        buf = in->buf;

        if (buf->in_file
            && buf->file_pos < NJT_SENDFILE_LIMIT
            && buf->file_last > NJT_SENDFILE_LIMIT)
        {
            /* split a file buf on two bufs by the sendfile limit */

            b = njt_calloc_buf(pool);
            if (b == NULL) {
                return NJT_ERROR;
            }

            njt_memcpy(b, buf, sizeof(njt_buf_t));

            if (njt_buf_in_memory(buf)) {
                buf->pos += (ssize_t) (NJT_SENDFILE_LIMIT - buf->file_pos);
                b->last = buf->pos;
            }

            buf->file_pos = NJT_SENDFILE_LIMIT;
            b->file_last = NJT_SENDFILE_LIMIT;

            cl->buf = b;

        } else {
            cl->buf = buf;
            in = in->next;
        }

#else
        cl->buf = in->buf;
        in = in->next;

#endif

        cl->next = NULL;
        *ll = cl;
        ll = &cl->next;
    }

    return NJT_OK;
}


static njt_int_t
njt_output_chain_align_file_buf(njt_output_chain_ctx_t *ctx, off_t bsize)
{
    size_t      size;
    njt_buf_t  *in;

    in = ctx->in->buf;

    if (in->file == NULL || !in->file->directio) {
        return NJT_DECLINED;
    }

    ctx->directio = 1;

    size = (size_t) (in->file_pos - (in->file_pos & ~(ctx->alignment - 1)));

    if (size == 0) {

        if (bsize >= (off_t) ctx->bufs.size) {
            return NJT_DECLINED;
        }

        size = (size_t) bsize;

    } else {
        size = (size_t) ctx->alignment - size;

        if ((off_t) size > bsize) {
            size = (size_t) bsize;
        }
    }

    ctx->buf = njt_create_temp_buf(ctx->pool, size);
    if (ctx->buf == NULL) {
        return NJT_ERROR;
    }

    /*
     * we do not set ctx->buf->tag, because we do not want
     * to reuse the buf via ctx->free list
     */

#if (NJT_HAVE_ALIGNED_DIRECTIO)
    ctx->unaligned = 1;
#endif

    return NJT_OK;
}


static njt_int_t
njt_output_chain_get_buf(njt_output_chain_ctx_t *ctx, off_t bsize)
{
    size_t       size;
    njt_buf_t   *b, *in;
    njt_uint_t   recycled;

    in = ctx->in->buf;
    size = ctx->bufs.size;
    recycled = 1;

    if (in->last_in_chain) {

        if (bsize < (off_t) size) {

            /*
             * allocate a small temp buf for a small last buf
             * or its small last part
             */

            size = (size_t) bsize;
            recycled = 0;

        } else if (!ctx->directio
                   && ctx->bufs.num == 1
                   && (bsize < (off_t) (size + size / 4)))
        {
            /*
             * allocate a temp buf that equals to a last buf,
             * if there is no directio, the last buf size is lesser
             * than 1.25 of bufs.size and the temp buf is single
             */

            size = (size_t) bsize;
            recycled = 0;
        }
    }

    b = njt_calloc_buf(ctx->pool);
    if (b == NULL) {
        return NJT_ERROR;
    }

    if (ctx->directio) {

        /*
         * allocate block aligned to a disk sector size to enable
         * userland buffer direct usage conjunctly with directio
         */

        b->start = njt_pmemalign(ctx->pool, size, (size_t) ctx->alignment);
        if (b->start == NULL) {
            return NJT_ERROR;
        }

    } else {
        b->start = njt_palloc(ctx->pool, size);
        if (b->start == NULL) {
            return NJT_ERROR;
        }
    }

    b->pos = b->start;
    b->last = b->start;
    b->end = b->last + size;
    b->temporary = 1;
    b->tag = ctx->tag;
    b->recycled = recycled;

    ctx->buf = b;
    ctx->allocated++;

    return NJT_OK;
}


static njt_int_t
njt_output_chain_copy_buf(njt_output_chain_ctx_t *ctx)
{
    off_t        size;
    ssize_t      n;
    njt_buf_t   *src, *dst;
    njt_uint_t   sendfile;

    src = ctx->in->buf;
    dst = ctx->buf;

    size = njt_buf_size(src);
    size = njt_min(size, dst->end - dst->pos);

    sendfile = ctx->sendfile && !ctx->directio;

#if (NJT_SENDFILE_LIMIT)

    if (src->in_file && src->file_pos >= NJT_SENDFILE_LIMIT) {
        sendfile = 0;
    }

#endif

    if (njt_buf_in_memory(src)) {
        njt_memcpy(dst->pos, src->pos, (size_t) size);
        src->pos += (size_t) size;
        dst->last += (size_t) size;

        if (src->in_file) {

            if (sendfile) {
                dst->in_file = 1;
                dst->file = src->file;
                dst->file_pos = src->file_pos;
                dst->file_last = src->file_pos + size;

            } else {
                dst->in_file = 0;
            }

            src->file_pos += size;

        } else {
            dst->in_file = 0;
        }

        if (src->pos == src->last) {
            dst->flush = src->flush;
            dst->last_buf = src->last_buf;
            dst->last_in_chain = src->last_in_chain;
        }

    } else {

#if (NJT_HAVE_ALIGNED_DIRECTIO)

        if (ctx->unaligned) {
            if (njt_directio_off(src->file->fd) == NJT_FILE_ERROR) {
                njt_log_error(NJT_LOG_ALERT, ctx->pool->log, njt_errno,
                              njt_directio_off_n " \"%s\" failed",
                              src->file->name.data);
            }
        }

#endif

#if (NJT_HAVE_FILE_AIO)
        if (ctx->aio_handler) {
            n = njt_file_aio_read(src->file, dst->pos, (size_t) size,
                                  src->file_pos, ctx->pool);
            if (n == NJT_AGAIN) {
                ctx->aio_handler(ctx, src->file);
                return NJT_AGAIN;
            }

        } else
#endif
#if (NJT_THREADS)
        if (ctx->thread_handler) {
            src->file->thread_task = ctx->thread_task;
            src->file->thread_handler = ctx->thread_handler;
            src->file->thread_ctx = ctx->filter_ctx;

            n = njt_thread_read(src->file, dst->pos, (size_t) size,
                                src->file_pos, ctx->pool);
            if (n == NJT_AGAIN) {
                ctx->thread_task = src->file->thread_task;
                return NJT_AGAIN;
            }

        } else
#endif
        {
            n = njt_read_file(src->file, dst->pos, (size_t) size,
                              src->file_pos);
        }

#if (NJT_HAVE_ALIGNED_DIRECTIO)

        if (ctx->unaligned) {
            njt_err_t  err;

            err = njt_errno;

            if (njt_directio_on(src->file->fd) == NJT_FILE_ERROR) {
                njt_log_error(NJT_LOG_ALERT, ctx->pool->log, njt_errno,
                              njt_directio_on_n " \"%s\" failed",
                              src->file->name.data);
            }

            njt_set_errno(err);

            ctx->unaligned = 0;
        }

#endif

        if (n == NJT_ERROR) {
            return (njt_int_t) n;
        }

        if (n != size) {
            njt_log_error(NJT_LOG_ALERT, ctx->pool->log, 0,
                          njt_read_file_n " read only %z of %O from \"%s\"",
                          n, size, src->file->name.data);
            return NJT_ERROR;
        }

        dst->last += n;

        if (sendfile) {
            dst->in_file = 1;
            dst->file = src->file;
            dst->file_pos = src->file_pos;
            dst->file_last = src->file_pos + n;

        } else {
            dst->in_file = 0;
        }

        src->file_pos += n;

        if (src->file_pos == src->file_last) {
            dst->flush = src->flush;
            dst->last_buf = src->last_buf;
            dst->last_in_chain = src->last_in_chain;
        }
    }

    return NJT_OK;
}


njt_int_t
njt_chain_writer(void *data, njt_chain_t *in)
{
    njt_chain_writer_ctx_t *ctx = data;

    off_t              size;
    njt_chain_t       *cl, *ln, *chain;
    njt_connection_t  *c;

    c = ctx->connection;

    for (size = 0; in; in = in->next) {

        if (njt_buf_size(in->buf) == 0 && !njt_buf_special(in->buf)) {

            njt_log_error(NJT_LOG_ALERT, ctx->pool->log, 0,
                          "zero size buf in chain writer "
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

            continue;
        }

        if (njt_buf_size(in->buf) < 0) {

            njt_log_error(NJT_LOG_ALERT, ctx->pool->log, 0,
                          "negative size buf in chain writer "
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

            return NJT_ERROR;
        }

        size += njt_buf_size(in->buf);

        njt_log_debug2(NJT_LOG_DEBUG_CORE, c->log, 0,
                       "chain writer buf fl:%d s:%uO",
                       in->buf->flush, njt_buf_size(in->buf));

        cl = njt_alloc_chain_link(ctx->pool);
        if (cl == NULL) {
            return NJT_ERROR;
        }

        cl->buf = in->buf;
        cl->next = NULL;
        *ctx->last = cl;
        ctx->last = &cl->next;
    }

    njt_log_debug1(NJT_LOG_DEBUG_CORE, c->log, 0,
                   "chain writer in: %p", ctx->out);

    for (cl = ctx->out; cl; cl = cl->next) {

        if (njt_buf_size(cl->buf) == 0 && !njt_buf_special(cl->buf)) {

            njt_log_error(NJT_LOG_ALERT, ctx->pool->log, 0,
                          "zero size buf in chain writer "
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

            continue;
        }

        if (njt_buf_size(cl->buf) < 0) {

            njt_log_error(NJT_LOG_ALERT, ctx->pool->log, 0,
                          "negative size buf in chain writer "
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

            return NJT_ERROR;
        }

        size += njt_buf_size(cl->buf);
    }

    if (size == 0 && !c->buffered) {
        return NJT_OK;
    }

    chain = c->send_chain(c, ctx->out, ctx->limit);

    njt_log_debug1(NJT_LOG_DEBUG_CORE, c->log, 0,
                   "chain writer out: %p", chain);

    if (chain == NJT_CHAIN_ERROR) {
        return NJT_ERROR;
    }

    if (chain && c->write->ready) {
        njt_post_event(c->write, &njt_posted_next_events);
    }

    for (cl = ctx->out; cl && cl != chain; /* void */) {
        ln = cl;
        cl = cl->next;
        njt_free_chain(ctx->pool, ln);
    }

    ctx->out = chain;

    if (ctx->out == NULL) {
        ctx->last = &ctx->out;

        if (!c->buffered) {
            return NJT_OK;
        }
    }

    return NJT_AGAIN;
}
