
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_event_pipe.h>


static njt_int_t njt_event_pipe_read_upstream(njt_event_pipe_t *p);
static njt_int_t njt_event_pipe_write_to_downstream(njt_event_pipe_t *p);

static njt_int_t njt_event_pipe_write_chain_to_temp_file(njt_event_pipe_t *p);
static njt_inline void njt_event_pipe_remove_shadow_links(njt_buf_t *buf);
static njt_int_t njt_event_pipe_drain_chains(njt_event_pipe_t *p);


njt_int_t
njt_event_pipe(njt_event_pipe_t *p, njt_int_t do_write)
{
    njt_int_t     rc;
    njt_uint_t    flags;
    njt_event_t  *rev, *wev;

    for ( ;; ) {
        if (do_write) {
            p->log->action = "sending to client";

            rc = njt_event_pipe_write_to_downstream(p);

            if (rc == NJT_ABORT) {
                return NJT_ABORT;
            }

            if (rc == NJT_BUSY) {
                return NJT_OK;
            }
        }

        p->read = 0;
        p->upstream_blocked = 0;

        p->log->action = "reading upstream";

        if (njt_event_pipe_read_upstream(p) == NJT_ABORT) {
            return NJT_ABORT;
        }

        if (!p->read && !p->upstream_blocked) {
            break;
        }

        do_write = 1;
    }

    if (p->upstream->fd != (njt_socket_t) -1) {
        rev = p->upstream->read;

        flags = (rev->eof || rev->error) ? NJT_CLOSE_EVENT : 0;

        if (njt_handle_read_event(rev, flags) != NJT_OK) {
            return NJT_ABORT;
        }

        if (!rev->delayed) {
            if (rev->active && !rev->ready) {
                njt_add_timer(rev, p->read_timeout);

            } else if (rev->timer_set) {
                njt_del_timer(rev);
            }
        }
    }

    if (p->downstream->fd != (njt_socket_t) -1
        && p->downstream->data == p->output_ctx)
    {
        wev = p->downstream->write;
        if (njt_handle_write_event(wev, p->send_lowat) != NJT_OK) {
            return NJT_ABORT;
        }

        if (!wev->delayed) {
            if (wev->active && !wev->ready) {
                njt_add_timer(wev, p->send_timeout);

            } else if (wev->timer_set) {
                njt_del_timer(wev);
            }
        }
    }

    return NJT_OK;
}


static njt_int_t
njt_event_pipe_read_upstream(njt_event_pipe_t *p)
{
    off_t         limit;
    ssize_t       n, size;
    njt_int_t     rc;
    njt_buf_t    *b;
    njt_msec_t    delay;
    njt_chain_t  *chain, *cl, *ln;

    if (p->upstream_eof || p->upstream_error || p->upstream_done) {
        return NJT_OK;
    }

#if (NJT_THREADS)

    if (p->aio) {
        njt_log_debug0(NJT_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe read upstream: aio");
        return NJT_AGAIN;
    }

    if (p->writing) {
        njt_log_debug0(NJT_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe read upstream: writing");

        rc = njt_event_pipe_write_chain_to_temp_file(p);

        if (rc != NJT_OK) {
            return rc;
        }
    }

#endif

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, p->log, 0,
                   "pipe read upstream: %d", p->upstream->read->ready);

    for ( ;; ) {

        if (p->upstream_eof || p->upstream_error || p->upstream_done) {
            break;
        }

        if (p->preread_bufs == NULL && !p->upstream->read->ready) {
            break;
        }

        if (p->preread_bufs) {

            /* use the pre-read bufs if they exist */

            chain = p->preread_bufs;
            p->preread_bufs = NULL;
            n = p->preread_size;

            njt_log_debug1(NJT_LOG_DEBUG_EVENT, p->log, 0,
                           "pipe preread: %z", n);

            if (n) {
                p->read = 1;
            }

        } else {

#if (NJT_HAVE_KQUEUE)

            /*
             * kqueue notifies about the end of file or a pending error.
             * This test allows not to allocate a buf on these conditions
             * and not to call c->recv_chain().
             */

            if (p->upstream->read->available == 0
                && p->upstream->read->pending_eof
#if (NJT_SSL)
                && !p->upstream->ssl
#endif
                )
            {
                p->upstream->read->ready = 0;
                p->upstream->read->eof = 1;
                p->upstream_eof = 1;
                p->read = 1;

                if (p->upstream->read->kq_errno) {
                    p->upstream->read->error = 1;
                    p->upstream_error = 1;
                    p->upstream_eof = 0;

                    njt_log_error(NJT_LOG_ERR, p->log,
                                  p->upstream->read->kq_errno,
                                  "kevent() reported that upstream "
                                  "closed connection");
                }

                break;
            }
#endif

            if (p->limit_rate) {
                if (p->upstream->read->delayed) {
                    break;
                }

                limit = (off_t) p->limit_rate * (njt_time() - p->start_sec + 1)
                        - p->read_length;

                if (limit <= 0) {
                    p->upstream->read->delayed = 1;
                    delay = (njt_msec_t) (- limit * 1000 / p->limit_rate + 1);
                    njt_add_timer(p->upstream->read, delay);
                    break;
                }

            } else {
                limit = 0;
            }

            if (p->free_raw_bufs) {

                /* use the free bufs if they exist */

                chain = p->free_raw_bufs;
                if (p->single_buf) {
                    p->free_raw_bufs = p->free_raw_bufs->next;
                    chain->next = NULL;
                } else {
                    p->free_raw_bufs = NULL;
                }

            } else if (p->allocated < p->bufs.num) {

                /* allocate a new buf if it's still allowed */

                b = njt_create_temp_buf(p->pool, p->bufs.size);
                if (b == NULL) {
                    return NJT_ABORT;
                }

                p->allocated++;

                chain = njt_alloc_chain_link(p->pool);
                if (chain == NULL) {
                    return NJT_ABORT;
                }

                chain->buf = b;
                chain->next = NULL;

            } else if (!p->cacheable
                       && p->downstream->data == p->output_ctx
                       && p->downstream->write->ready
                       && !p->downstream->write->delayed)
            {
                /*
                 * if the bufs are not needed to be saved in a cache and
                 * a downstream is ready then write the bufs to a downstream
                 */

                p->upstream_blocked = 1;

                njt_log_debug0(NJT_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe downstream ready");

                break;

            } else if (p->cacheable
                       || p->temp_file->offset < p->max_temp_file_size)
            {

                /*
                 * if it is allowed, then save some bufs from p->in
                 * to a temporary file, and add them to a p->out chain
                 */

                rc = njt_event_pipe_write_chain_to_temp_file(p);

                njt_log_debug1(NJT_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe temp offset: %O", p->temp_file->offset);

                if (rc == NJT_BUSY) {
                    break;
                }

                if (rc != NJT_OK) {
                    return rc;
                }

                chain = p->free_raw_bufs;
                if (p->single_buf && p->free_raw_bufs != NULL) {
                    p->free_raw_bufs = p->free_raw_bufs->next;
                    chain->next = NULL;
                } else {
                    p->free_raw_bufs = NULL;
                }

            } else {

                /* there are no bufs to read in */

                njt_log_debug0(NJT_LOG_DEBUG_EVENT, p->log, 0,
                               "no pipe bufs to read in");

                break;
            }

            n = p->upstream->recv_chain(p->upstream, chain, limit);

            njt_log_debug1(NJT_LOG_DEBUG_EVENT, p->log, 0,
                           "pipe recv chain: %z", n);

            if (p->free_raw_bufs) {
                chain->next = p->free_raw_bufs;
            }
            p->free_raw_bufs = chain;

            if (n == NJT_ERROR) {
                p->upstream_error = 1;
                break;
            }

            if (n == NJT_AGAIN) {
                if (p->single_buf) {
		    if(chain != NULL) {
                    	njt_event_pipe_remove_shadow_links(chain->buf);
		    } else {
			njt_log_error(NJT_LOG_ERR, p->log,0,"njt_event_pipe_remove_shadow_links  chain is null");
		    }
                }

                break;
            }

            p->read = 1;

            if (n == 0) {
                p->upstream_eof = 1;
                break;
            }
        }

        delay = p->limit_rate ? (njt_msec_t) n * 1000 / p->limit_rate : 0;

        p->read_length += n;
        cl = chain;
        p->free_raw_bufs = NULL;

        while (cl && n > 0) {

            njt_event_pipe_remove_shadow_links(cl->buf);

            size = cl->buf->end - cl->buf->last;

            if (n >= size) {
                cl->buf->last = cl->buf->end;

                /* STUB */ cl->buf->num = p->num++;

                if (p->input_filter(p, cl->buf) == NJT_ERROR) {
                    return NJT_ABORT;
                }

                n -= size;
                ln = cl;
                cl = cl->next;
                njt_free_chain(p->pool, ln);

            } else {
                cl->buf->last += n;
                n = 0;
            }
        }

        if (cl) {
            for (ln = cl; ln->next; ln = ln->next) { /* void */ }

            ln->next = p->free_raw_bufs;
            p->free_raw_bufs = cl;
        }

        if (delay > 0) {
            p->upstream->read->delayed = 1;
            njt_add_timer(p->upstream->read, delay);
            break;
        }
    }

#if (NJT_DEBUG)

    for (cl = p->busy; cl; cl = cl->next) {
        njt_log_debug8(NJT_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe buf busy s:%d t:%d f:%d "
                       "%p, pos %p, size: %z "
                       "file: %O, size: %O",
                       (cl->buf->shadow ? 1 : 0),
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    for (cl = p->out; cl; cl = cl->next) {
        njt_log_debug8(NJT_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe buf out  s:%d t:%d f:%d "
                       "%p, pos %p, size: %z "
                       "file: %O, size: %O",
                       (cl->buf->shadow ? 1 : 0),
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    for (cl = p->in; cl; cl = cl->next) {
        njt_log_debug8(NJT_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe buf in   s:%d t:%d f:%d "
                       "%p, pos %p, size: %z "
                       "file: %O, size: %O",
                       (cl->buf->shadow ? 1 : 0),
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    for (cl = p->free_raw_bufs; cl; cl = cl->next) {
        njt_log_debug8(NJT_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe buf free s:%d t:%d f:%d "
                       "%p, pos %p, size: %z "
                       "file: %O, size: %O",
                       (cl->buf->shadow ? 1 : 0),
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, p->log, 0,
                   "pipe length: %O", p->length);

#endif

    if (p->free_raw_bufs && p->length != -1) {
        cl = p->free_raw_bufs;

        if (cl->buf->last - cl->buf->pos >= p->length) {

            p->free_raw_bufs = cl->next;

            /* STUB */ cl->buf->num = p->num++;

            if (p->input_filter(p, cl->buf) == NJT_ERROR) {
                return NJT_ABORT;
            }

            njt_free_chain(p->pool, cl);
        }
    }

    if (p->length == 0) {
        p->upstream_done = 1;
        p->read = 1;
    }

    if ((p->upstream_eof || p->upstream_error) && p->free_raw_bufs) {

        /* STUB */ p->free_raw_bufs->buf->num = p->num++;

        if (p->input_filter(p, p->free_raw_bufs->buf) == NJT_ERROR) {
            return NJT_ABORT;
        }

        p->free_raw_bufs = p->free_raw_bufs->next;

        if (p->free_bufs && p->buf_to_file == NULL) {
            for (cl = p->free_raw_bufs; cl; cl = cl->next) {
                if (cl->buf->shadow == NULL) {
                    njt_pfree(p->pool, cl->buf->start);
                }
            }
        }
    }

    if (p->cacheable && (p->in || p->buf_to_file)) {

        njt_log_debug0(NJT_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe write chain");

        rc = njt_event_pipe_write_chain_to_temp_file(p);

        if (rc != NJT_OK) {
            return rc;
        }
    }

    return NJT_OK;
}


static njt_int_t
njt_event_pipe_write_to_downstream(njt_event_pipe_t *p)
{
    u_char            *prev;
    size_t             bsize;
    njt_int_t          rc;
    njt_uint_t         flush, flushed, prev_last_shadow;
    njt_chain_t       *out, **ll, *cl;
    njt_connection_t  *downstream;

    downstream = p->downstream;

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, p->log, 0,
                   "pipe write downstream: %d", downstream->write->ready);

#if (NJT_THREADS)

    if (p->writing) {
        rc = njt_event_pipe_write_chain_to_temp_file(p);

        if (rc == NJT_ABORT) {
            return NJT_ABORT;
        }
    }

#endif

    flushed = 0;

    for ( ;; ) {
        if (p->downstream_error) {
            return njt_event_pipe_drain_chains(p);
        }

        if (p->upstream_eof || p->upstream_error || p->upstream_done) {

            /* pass the p->out and p->in chains to the output filter */

            for (cl = p->busy; cl; cl = cl->next) {
                cl->buf->recycled = 0;
            }

            if (p->out) {
                njt_log_debug0(NJT_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe write downstream flush out");

                for (cl = p->out; cl; cl = cl->next) {
                    cl->buf->recycled = 0;
                }

                rc = p->output_filter(p->output_ctx, p->out);

                if (rc == NJT_ERROR) {
                    p->downstream_error = 1;
                    return njt_event_pipe_drain_chains(p);
                }

                p->out = NULL;
            }

            if (p->writing) {
                break;
            }

            if (p->in) {
                njt_log_debug0(NJT_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe write downstream flush in");

                for (cl = p->in; cl; cl = cl->next) {
                    cl->buf->recycled = 0;
                }

                rc = p->output_filter(p->output_ctx, p->in);

                if (rc == NJT_ERROR) {
                    p->downstream_error = 1;
                    return njt_event_pipe_drain_chains(p);
                }

                p->in = NULL;
            }

            njt_log_debug0(NJT_LOG_DEBUG_EVENT, p->log, 0,
                           "pipe write downstream done");

            /* TODO: free unused bufs */

            p->downstream_done = 1;
            break;
        }

        if (downstream->data != p->output_ctx
            || !downstream->write->ready
            || downstream->write->delayed)
        {
            break;
        }

        /* bsize is the size of the busy recycled bufs */

        prev = NULL;
        bsize = 0;

        for (cl = p->busy; cl; cl = cl->next) {

            if (cl->buf->recycled) {
                if (prev == cl->buf->start) {
                    continue;
                }

                bsize += cl->buf->end - cl->buf->start;
                prev = cl->buf->start;
            }
        }

        njt_log_debug1(NJT_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe write busy: %uz", bsize);

        out = NULL;

        if (bsize >= (size_t) p->busy_size) {
            flush = 1;
            goto flush;
        }

        flush = 0;
        ll = NULL;
        prev_last_shadow = 1;

        for ( ;; ) {
            if (p->out) {
                cl = p->out;

                if (cl->buf->recycled) {
                    njt_log_error(NJT_LOG_ALERT, p->log, 0,
                                  "recycled buffer in pipe out chain");
                }

                p->out = p->out->next;

            } else if (!p->cacheable && !p->writing && p->in) {
                cl = p->in;

                njt_log_debug3(NJT_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe write buf ls:%d %p %z",
                               cl->buf->last_shadow,
                               cl->buf->pos,
                               cl->buf->last - cl->buf->pos);

                if (cl->buf->recycled && prev_last_shadow) {
                    if (bsize + cl->buf->end - cl->buf->start > p->busy_size) {
                        flush = 1;
                        break;
                    }

                    bsize += cl->buf->end - cl->buf->start;
                }

                prev_last_shadow = cl->buf->last_shadow;

                p->in = p->in->next;

            } else {
                break;
            }

            cl->next = NULL;

            if (out) {
                *ll = cl;
            } else {
                out = cl;
            }
            ll = &cl->next;
        }

    flush:

        njt_log_debug2(NJT_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe write: out:%p, f:%ui", out, flush);

        if (out == NULL) {

            if (!flush) {
                break;
            }

            /* a workaround for AIO */
            if (flushed++ > 10) {
                return NJT_BUSY;
            }
        }

        rc = p->output_filter(p->output_ctx, out);

        njt_chain_update_chains(p->pool, &p->free, &p->busy, &out, p->tag);

        if (rc == NJT_ERROR) {
            p->downstream_error = 1;
            return njt_event_pipe_drain_chains(p);
        }

        for (cl = p->free; cl; cl = cl->next) {

            if (cl->buf->temp_file) {
                if (p->cacheable || !p->cyclic_temp_file) {
                    continue;
                }

                /* reset p->temp_offset if all bufs had been sent */

                if (cl->buf->file_last == p->temp_file->offset) {
                    p->temp_file->offset = 0;
                }
            }

            /* TODO: free buf if p->free_bufs && upstream done */

            /* add the free shadow raw buf to p->free_raw_bufs */

            if (cl->buf->last_shadow) {
                if (njt_event_pipe_add_free_buf(p, cl->buf->shadow) != NJT_OK) {
                    return NJT_ABORT;
                }

                cl->buf->last_shadow = 0;
            }

            cl->buf->shadow = NULL;
        }
    }

    return NJT_OK;
}


static njt_int_t
njt_event_pipe_write_chain_to_temp_file(njt_event_pipe_t *p)
{
    ssize_t       size, bsize, n;
    njt_buf_t    *b;
    njt_uint_t    prev_last_shadow;
    njt_chain_t  *cl, *tl, *next, *out, **ll, **last_out, **last_free;

#if (NJT_THREADS)

    if (p->writing) {

        if (p->aio) {
            return NJT_AGAIN;
        }

        out = p->writing;
        p->writing = NULL;

        n = njt_write_chain_to_temp_file(p->temp_file, NULL);

        if (n == NJT_ERROR) {
            return NJT_ABORT;
        }

        goto done;
    }

#endif

    if (p->buf_to_file) {
        out = njt_alloc_chain_link(p->pool);
        if (out == NULL) {
            return NJT_ABORT;
        }

        out->buf = p->buf_to_file;
        out->next = p->in;

    } else {
        out = p->in;
    }

    if (!p->cacheable) {

        size = 0;
        cl = out;
        ll = NULL;
        prev_last_shadow = 1;

        njt_log_debug1(NJT_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe offset: %O", p->temp_file->offset);

        do {
            bsize = cl->buf->last - cl->buf->pos;

            njt_log_debug4(NJT_LOG_DEBUG_EVENT, p->log, 0,
                           "pipe buf ls:%d %p, pos %p, size: %z",
                           cl->buf->last_shadow, cl->buf->start,
                           cl->buf->pos, bsize);

            if (prev_last_shadow
                && ((size + bsize > p->temp_file_write_size)
                    || (p->temp_file->offset + size + bsize
                        > p->max_temp_file_size)))
            {
                break;
            }

            prev_last_shadow = cl->buf->last_shadow;

            size += bsize;
            ll = &cl->next;
            cl = cl->next;

        } while (cl);

        njt_log_debug1(NJT_LOG_DEBUG_EVENT, p->log, 0, "size: %z", size);

        if (ll == NULL) {
            return NJT_BUSY;
        }

        if (cl) {
            p->in = cl;
            *ll = NULL;

        } else {
            p->in = NULL;
            p->last_in = &p->in;
        }

    } else {
        p->in = NULL;
        p->last_in = &p->in;
    }

#if (NJT_THREADS)
    if (p->thread_handler) {
        p->temp_file->thread_write = 1;
        p->temp_file->file.thread_task = p->thread_task;
        p->temp_file->file.thread_handler = p->thread_handler;
        p->temp_file->file.thread_ctx = p->thread_ctx;
    }
#endif

    n = njt_write_chain_to_temp_file(p->temp_file, out);

    if (n == NJT_ERROR) {
        return NJT_ABORT;
    }

#if (NJT_THREADS)

    if (n == NJT_AGAIN) {
        p->writing = out;
        p->thread_task = p->temp_file->file.thread_task;
        return NJT_AGAIN;
    }

done:

#endif

    if (p->buf_to_file) {
        p->temp_file->offset = p->buf_to_file->last - p->buf_to_file->pos;
        n -= p->buf_to_file->last - p->buf_to_file->pos;
        p->buf_to_file = NULL;
        out = out->next;
    }

    if (n > 0) {
        /* update previous buffer or add new buffer */

        if (p->out) {
            for (cl = p->out; cl->next; cl = cl->next) { /* void */ }

            b = cl->buf;

            if (b->file_last == p->temp_file->offset) {
                p->temp_file->offset += n;
                b->file_last = p->temp_file->offset;
                goto free;
            }

            last_out = &cl->next;

        } else {
            last_out = &p->out;
        }

        cl = njt_chain_get_free_buf(p->pool, &p->free);
        if (cl == NULL) {
            return NJT_ABORT;
        }

        b = cl->buf;

        njt_memzero(b, sizeof(njt_buf_t));

        b->tag = p->tag;

        b->file = &p->temp_file->file;
        b->file_pos = p->temp_file->offset;
        p->temp_file->offset += n;
        b->file_last = p->temp_file->offset;

        b->in_file = 1;
        b->temp_file = 1;

        *last_out = cl;
    }

free:

    for (last_free = &p->free_raw_bufs;
         *last_free != NULL;
         last_free = &(*last_free)->next)
    {
        /* void */
    }

    for (cl = out; cl; cl = next) {
        next = cl->next;

        cl->next = p->free;
        p->free = cl;

        b = cl->buf;

        if (b->last_shadow) {

            tl = njt_alloc_chain_link(p->pool);
            if (tl == NULL) {
                return NJT_ABORT;
            }

            tl->buf = b->shadow;
            tl->next = NULL;

            *last_free = tl;
            last_free = &tl->next;

            b->shadow->pos = b->shadow->start;
            b->shadow->last = b->shadow->start;

            njt_event_pipe_remove_shadow_links(b->shadow);
        }
    }

    return NJT_OK;
}


/* the copy input filter */

njt_int_t
njt_event_pipe_copy_input_filter(njt_event_pipe_t *p, njt_buf_t *buf)
{
    njt_buf_t    *b;
    njt_chain_t  *cl;

    if (buf->pos == buf->last) {
        return NJT_OK;
    }

    if (p->upstream_done) {
        njt_log_debug0(NJT_LOG_DEBUG_EVENT, p->log, 0,
                       "input data after close");
        return NJT_OK;
    }

    if (p->length == 0) {
        p->upstream_done = 1;

        njt_log_error(NJT_LOG_WARN, p->log, 0,
                      "upstream sent more data than specified in "
                      "\"Content-Length\" header");

        return NJT_OK;
    }

    cl = njt_chain_get_free_buf(p->pool, &p->free);
    if (cl == NULL) {
        return NJT_ERROR;
    }

    b = cl->buf;

    njt_memcpy(b, buf, sizeof(njt_buf_t));
    b->shadow = buf;
    b->tag = p->tag;
    b->last_shadow = 1;
    b->recycled = 1;
    buf->shadow = b;

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, p->log, 0, "input buf #%d", b->num);

    if (p->in) {
        *p->last_in = cl;
    } else {
        p->in = cl;
    }
    p->last_in = &cl->next;

    if (p->length == -1) {
        return NJT_OK;
    }

    if (b->last - b->pos > p->length) {

        njt_log_error(NJT_LOG_WARN, p->log, 0,
                      "upstream sent more data than specified in "
                      "\"Content-Length\" header");

        b->last = b->pos + p->length;
        p->upstream_done = 1;

        return NJT_OK;
    }

    p->length -= b->last - b->pos;

    return NJT_OK;
}


static njt_inline void
njt_event_pipe_remove_shadow_links(njt_buf_t *buf)
{
    njt_buf_t  *b, *next;

    b = buf->shadow;

    if (b == NULL) {
        return;
    }

    while (!b->last_shadow) {
        next = b->shadow;

        b->temporary = 0;
        b->recycled = 0;

        b->shadow = NULL;
        b = next;
    }

    b->temporary = 0;
    b->recycled = 0;
    b->last_shadow = 0;

    b->shadow = NULL;

    buf->shadow = NULL;
}


njt_int_t
njt_event_pipe_add_free_buf(njt_event_pipe_t *p, njt_buf_t *b)
{
    njt_chain_t  *cl;

    cl = njt_alloc_chain_link(p->pool);
    if (cl == NULL) {
        return NJT_ERROR;
    }

    if (p->buf_to_file && b->start == p->buf_to_file->start) {
        b->pos = p->buf_to_file->last;
        b->last = p->buf_to_file->last;

    } else {
        b->pos = b->start;
        b->last = b->start;
    }

    b->shadow = NULL;

    cl->buf = b;

    if (p->free_raw_bufs == NULL) {
        p->free_raw_bufs = cl;
        cl->next = NULL;

        return NJT_OK;
    }

    if (p->free_raw_bufs->buf->pos == p->free_raw_bufs->buf->last) {

        /* add the free buf to the list start */

        cl->next = p->free_raw_bufs;
        p->free_raw_bufs = cl;

        return NJT_OK;
    }

    /* the first free buf is partially filled, thus add the free buf after it */

    cl->next = p->free_raw_bufs->next;
    p->free_raw_bufs->next = cl;

    return NJT_OK;
}


static njt_int_t
njt_event_pipe_drain_chains(njt_event_pipe_t *p)
{
    njt_chain_t  *cl, *tl;

    for ( ;; ) {
        if (p->busy) {
            cl = p->busy;
            p->busy = NULL;

        } else if (p->out) {
            cl = p->out;
            p->out = NULL;

        } else if (p->in) {
            cl = p->in;
            p->in = NULL;

        } else {
            return NJT_OK;
        }

        while (cl) {
            if (cl->buf->last_shadow) {
                if (njt_event_pipe_add_free_buf(p, cl->buf->shadow) != NJT_OK) {
                    return NJT_ABORT;
                }

                cl->buf->last_shadow = 0;
            }

            cl->buf->shadow = NULL;
            tl = cl->next;
            cl->next = p->free;
            p->free = cl;
            cl = tl;
        }
    }
}
