
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>


typedef struct {
    njt_chain_t  *from_upstream;
    njt_chain_t  *from_downstream;
} njt_stream_write_filter_ctx_t;


static njt_int_t njt_stream_write_filter(njt_stream_session_t *s,
    njt_chain_t *in, njt_uint_t from_upstream);
static njt_int_t njt_stream_write_filter_init(njt_conf_t *cf);


static njt_stream_module_t  njt_stream_write_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_stream_write_filter_init,          /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL                                   /* merge server configuration */
};


njt_module_t  njt_stream_write_filter_module = {
    NJT_MODULE_V1,
    &njt_stream_write_filter_module_ctx,   /* module context */
    NULL,                                  /* module directives */
    NJT_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_int_t
njt_stream_write_filter(njt_stream_session_t *s, njt_chain_t *in,
    njt_uint_t from_upstream)
{
    off_t                           size;
    njt_uint_t                      last, flush, sync;
    njt_chain_t                    *cl, *ln, **ll, **out, *chain;
    njt_connection_t               *c;
    njt_stream_write_filter_ctx_t  *ctx;

    ctx = njt_stream_get_module_ctx(s, njt_stream_write_filter_module);

    if (ctx == NULL) {
        ctx = njt_pcalloc(s->connection->pool,
                          sizeof(njt_stream_write_filter_ctx_t));
        if (ctx == NULL) {
            return NJT_ERROR;
        }

        njt_stream_set_ctx(s, ctx, njt_stream_write_filter_module);
    }

    if (from_upstream) {
        c = s->connection;
        out = &ctx->from_upstream;

    } else {
        c = s->upstream->peer.connection;
        out = &ctx->from_downstream;
    }

    if (c->error) {
        return NJT_ERROR;
    }

    size = 0;
    flush = 0;
    sync = 0;
    last = 0;
    ll = out;

    /* find the size, the flush point and the last link of the saved chain */

    for (cl = *out; cl; cl = cl->next) {
        ll = &cl->next;

        njt_log_debug7(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "write old buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

        if (njt_buf_size(cl->buf) == 0 && !njt_buf_special(cl->buf)) {
            njt_log_error(NJT_LOG_ALERT, c->log, 0,
                          "zero size buf in writer "
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

        if (njt_buf_size(cl->buf) < 0) {
            njt_log_error(NJT_LOG_ALERT, c->log, 0,
                          "negative size buf in writer "
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

        if (cl->buf->flush || cl->buf->recycled) {
            flush = 1;
        }

        if (cl->buf->sync) {
            sync = 1;
        }

        if (cl->buf->last_buf) {
            last = 1;
        }
    }

    /* add the new chain to the existent one */

    for (ln = in; ln; ln = ln->next) {
        cl = njt_alloc_chain_link(c->pool);
        if (cl == NULL) {
            return NJT_ERROR;
        }

        cl->buf = ln->buf;
        *ll = cl;
        ll = &cl->next;

        njt_log_debug7(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "write new buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

        if (njt_buf_size(cl->buf) == 0 && !njt_buf_special(cl->buf)) {
            njt_log_error(NJT_LOG_ALERT, c->log, 0,
                          "zero size buf in writer "
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

        if (njt_buf_size(cl->buf) < 0) {
            njt_log_error(NJT_LOG_ALERT, c->log, 0,
                          "negative size buf in writer "
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

        if (cl->buf->flush || cl->buf->recycled) {
            flush = 1;
        }

        if (cl->buf->sync) {
            sync = 1;
        }

        if (cl->buf->last_buf) {
            last = 1;
        }
    }

    *ll = NULL;

    njt_log_debug3(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "stream write filter: l:%ui f:%ui s:%O", last, flush, size);

    if (size == 0
        && !(c->buffered & NJT_LOWLEVEL_BUFFERED)
        && !(last && c->need_last_buf)
        && !(flush && c->need_flush_buf))
    {
        if (last || flush || sync) {
            for (cl = *out; cl; /* void */) {
                ln = cl;
                cl = cl->next;
                njt_free_chain(c->pool, ln);
            }

            *out = NULL;
            c->buffered &= ~NJT_STREAM_WRITE_BUFFERED;

            return NJT_OK;
        }

        njt_log_error(NJT_LOG_ALERT, c->log, 0,
                      "the stream output chain is empty");

        njt_debug_point();

        return NJT_ERROR;
    }

    chain = c->send_chain(c, *out, 0);

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "stream write filter %p", chain);

    if (chain == NJT_CHAIN_ERROR) {
        c->error = 1;
        return NJT_ERROR;
    }

    for (cl = *out; cl && cl != chain; /* void */) {
        ln = cl;
        cl = cl->next;
        njt_free_chain(c->pool, ln);
    }

    *out = chain;

    if (chain) {
        if (c->shared) {
            njt_log_error(NJT_LOG_ALERT, c->log, 0,
                          "shared connection is busy");
            return NJT_ERROR;
        }

        c->buffered |= NJT_STREAM_WRITE_BUFFERED;
        return NJT_AGAIN;
    }

    c->buffered &= ~NJT_STREAM_WRITE_BUFFERED;

    if (c->buffered & NJT_LOWLEVEL_BUFFERED) {
        return NJT_AGAIN;
    }

    return NJT_OK;
}


static njt_int_t
njt_stream_write_filter_init(njt_conf_t *cf)
{
    njt_stream_top_filter = njt_stream_write_filter;

    return NJT_OK;
}
