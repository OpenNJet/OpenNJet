
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>

#include <zlib.h>


typedef struct {
    njt_flag_t           enable;
    njt_bufs_t           bufs;
} njt_http_gunzip_conf_t;


typedef struct {
    njt_chain_t         *in;
    njt_chain_t         *free;
    njt_chain_t         *busy;
    njt_chain_t         *out;
    njt_chain_t        **last_out;

    njt_buf_t           *in_buf;
    njt_buf_t           *out_buf;
    njt_int_t            bufs;

    unsigned             started:1;
    unsigned             flush:4;
    unsigned             redo:1;
    unsigned             done:1;
    unsigned             nomem:1;

    z_stream             zstream;
    njt_http_request_t  *request;
} njt_http_gunzip_ctx_t;


static njt_int_t njt_http_gunzip_filter_inflate_start(njt_http_request_t *r,
    njt_http_gunzip_ctx_t *ctx);
static njt_int_t njt_http_gunzip_filter_add_data(njt_http_request_t *r,
    njt_http_gunzip_ctx_t *ctx);
static njt_int_t njt_http_gunzip_filter_get_buf(njt_http_request_t *r,
    njt_http_gunzip_ctx_t *ctx);
static njt_int_t njt_http_gunzip_filter_inflate(njt_http_request_t *r,
    njt_http_gunzip_ctx_t *ctx);
static njt_int_t njt_http_gunzip_filter_inflate_end(njt_http_request_t *r,
    njt_http_gunzip_ctx_t *ctx);

static void *njt_http_gunzip_filter_alloc(void *opaque, u_int items,
    u_int size);
static void njt_http_gunzip_filter_free(void *opaque, void *address);

static njt_int_t njt_http_gunzip_filter_init(njt_conf_t *cf);
static void *njt_http_gunzip_create_conf(njt_conf_t *cf);
static char *njt_http_gunzip_merge_conf(njt_conf_t *cf,
    void *parent, void *child);


static njt_command_t  njt_http_gunzip_filter_commands[] = {

    { njt_string("gunzip"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_gunzip_conf_t, enable),
      NULL },

    { njt_string("gunzip_buffers"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE2,
      njt_conf_set_bufs_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_gunzip_conf_t, bufs),
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_gunzip_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_http_gunzip_filter_init,           /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_gunzip_create_conf,           /* create location configuration */
    njt_http_gunzip_merge_conf             /* merge location configuration */
};


njt_module_t  njt_http_gunzip_filter_module = {
    NJT_MODULE_V1,
    &njt_http_gunzip_filter_module_ctx,    /* module context */
    njt_http_gunzip_filter_commands,       /* module directives */
    NJT_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_http_output_header_filter_pt  njt_http_next_header_filter;
static njt_http_output_body_filter_pt    njt_http_next_body_filter;


static njt_int_t
njt_http_gunzip_header_filter(njt_http_request_t *r)
{
    njt_http_gunzip_ctx_t   *ctx;
    njt_http_gunzip_conf_t  *conf;

    conf = njt_http_get_module_loc_conf(r, njt_http_gunzip_filter_module);

    /* TODO support multiple content-codings */
    /* TODO always gunzip - due to configuration or module request */
    /* TODO ignore content encoding? */

    if (!conf->enable
        || r->headers_out.content_encoding == NULL
        || r->headers_out.content_encoding->value.len != 4
        || njt_strncasecmp(r->headers_out.content_encoding->value.data,
                           (u_char *) "gzip", 4) != 0)
    {
        return njt_http_next_header_filter(r);
    }

    r->gzip_vary = 1;

    if (!r->gzip_tested) {
        if (njt_http_gzip_ok(r) == NJT_OK) {
            return njt_http_next_header_filter(r);
        }

    } else if (r->gzip_ok) {
        return njt_http_next_header_filter(r);
    }

    ctx = njt_pcalloc(r->pool, sizeof(njt_http_gunzip_ctx_t));
    if (ctx == NULL) {
        return NJT_ERROR;
    }

    njt_http_set_ctx(r, ctx, njt_http_gunzip_filter_module);

    ctx->request = r;

    r->filter_need_in_memory = 1;

    r->headers_out.content_encoding->hash = 0;
    r->headers_out.content_encoding = NULL;

    njt_http_clear_content_length(r);
    njt_http_clear_accept_ranges(r);
    njt_http_weak_etag(r);

    return njt_http_next_header_filter(r);
}


static njt_int_t
njt_http_gunzip_body_filter(njt_http_request_t *r, njt_chain_t *in)
{
    int                     rc;
    njt_uint_t              flush;
    njt_chain_t            *cl;
    njt_http_gunzip_ctx_t  *ctx;

    ctx = njt_http_get_module_ctx(r, njt_http_gunzip_filter_module);

    if (ctx == NULL || ctx->done) {
        return njt_http_next_body_filter(r, in);
    }

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http gunzip filter");

    if (!ctx->started) {
        if (njt_http_gunzip_filter_inflate_start(r, ctx) != NJT_OK) {
            goto failed;
        }
    }

    if (in) {
        if (njt_chain_add_copy(r->pool, &ctx->in, in) != NJT_OK) {
            goto failed;
        }
    }

    if (ctx->nomem) {

        /* flush busy buffers */

        if (njt_http_next_body_filter(r, NULL) == NJT_ERROR) {
            goto failed;
        }

        cl = NULL;

        njt_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &cl,
                                (njt_buf_tag_t) &njt_http_gunzip_filter_module);
        ctx->nomem = 0;
        flush = 0;

    } else {
        flush = ctx->busy ? 1 : 0;
    }

    for ( ;; ) {

        /* cycle while we can write to a client */

        for ( ;; ) {

            /* cycle while there is data to feed zlib and ... */

            rc = njt_http_gunzip_filter_add_data(r, ctx);

            if (rc == NJT_DECLINED) {
                break;
            }

            if (rc == NJT_AGAIN) {
                continue;
            }


            /* ... there are buffers to write zlib output */

            rc = njt_http_gunzip_filter_get_buf(r, ctx);

            if (rc == NJT_DECLINED) {
                break;
            }

            if (rc == NJT_ERROR) {
                goto failed;
            }

            rc = njt_http_gunzip_filter_inflate(r, ctx);

            if (rc == NJT_OK) {
                break;
            }

            if (rc == NJT_ERROR) {
                goto failed;
            }

            /* rc == NJT_AGAIN */
        }

        if (ctx->out == NULL && !flush) {
            return ctx->busy ? NJT_AGAIN : NJT_OK;
        }

        rc = njt_http_next_body_filter(r, ctx->out);

        if (rc == NJT_ERROR) {
            goto failed;
        }

        njt_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &ctx->out,
                                (njt_buf_tag_t) &njt_http_gunzip_filter_module);
        ctx->last_out = &ctx->out;

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "gunzip out: %p", ctx->out);

        ctx->nomem = 0;
        flush = 0;

        if (ctx->done) {
            return rc;
        }
    }

    /* unreachable */

failed:

    ctx->done = 1;

    return NJT_ERROR;
}


static njt_int_t
njt_http_gunzip_filter_inflate_start(njt_http_request_t *r,
    njt_http_gunzip_ctx_t *ctx)
{
    int  rc;

    ctx->zstream.next_in = Z_NULL;
    ctx->zstream.avail_in = 0;

    ctx->zstream.zalloc = njt_http_gunzip_filter_alloc;
    ctx->zstream.zfree = njt_http_gunzip_filter_free;
    ctx->zstream.opaque = ctx;

    /* windowBits +16 to decode gzip, zlib 1.2.0.4+ */
    rc = inflateInit2(&ctx->zstream, MAX_WBITS + 16);

    if (rc != Z_OK) {
        njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
                      "inflateInit2() failed: %d", rc);
        return NJT_ERROR;
    }

    ctx->started = 1;

    ctx->last_out = &ctx->out;
    ctx->flush = Z_NO_FLUSH;

    return NJT_OK;
}


static njt_int_t
njt_http_gunzip_filter_add_data(njt_http_request_t *r,
    njt_http_gunzip_ctx_t *ctx)
{
    if (ctx->zstream.avail_in || ctx->flush != Z_NO_FLUSH || ctx->redo) {
        return NJT_OK;
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "gunzip in: %p", ctx->in);

    if (ctx->in == NULL) {
        return NJT_DECLINED;
    }

    ctx->in_buf = ctx->in->buf;
    ctx->in = ctx->in->next;

    ctx->zstream.next_in = ctx->in_buf->pos;
    ctx->zstream.avail_in = ctx->in_buf->last - ctx->in_buf->pos;

    njt_log_debug3(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "gunzip in_buf:%p ni:%p ai:%ud",
                   ctx->in_buf,
                   ctx->zstream.next_in, ctx->zstream.avail_in);

    if (ctx->in_buf->last_buf || ctx->in_buf->last_in_chain) {
        ctx->flush = Z_FINISH;

    } else if (ctx->in_buf->flush) {
        ctx->flush = Z_SYNC_FLUSH;

    } else if (ctx->zstream.avail_in == 0) {
        /* ctx->flush == Z_NO_FLUSH */
        return NJT_AGAIN;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_gunzip_filter_get_buf(njt_http_request_t *r,
    njt_http_gunzip_ctx_t *ctx)
{
    njt_http_gunzip_conf_t  *conf;

    if (ctx->zstream.avail_out) {
        return NJT_OK;
    }

    conf = njt_http_get_module_loc_conf(r, njt_http_gunzip_filter_module);

    if (ctx->free) {
        ctx->out_buf = ctx->free->buf;
        ctx->free = ctx->free->next;

        ctx->out_buf->flush = 0;

    } else if (ctx->bufs < conf->bufs.num) {

        ctx->out_buf = njt_create_temp_buf(r->pool, conf->bufs.size);
        if (ctx->out_buf == NULL) {
            return NJT_ERROR;
        }

        ctx->out_buf->tag = (njt_buf_tag_t) &njt_http_gunzip_filter_module;
        ctx->out_buf->recycled = 1;
        ctx->bufs++;

    } else {
        ctx->nomem = 1;
        return NJT_DECLINED;
    }

    ctx->zstream.next_out = ctx->out_buf->pos;
    ctx->zstream.avail_out = conf->bufs.size;

    return NJT_OK;
}


static njt_int_t
njt_http_gunzip_filter_inflate(njt_http_request_t *r,
    njt_http_gunzip_ctx_t *ctx)
{
    int           rc;
    njt_buf_t    *b;
    njt_chain_t  *cl;

    njt_log_debug6(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "inflate in: ni:%p no:%p ai:%ud ao:%ud fl:%d redo:%d",
                   ctx->zstream.next_in, ctx->zstream.next_out,
                   ctx->zstream.avail_in, ctx->zstream.avail_out,
                   ctx->flush, ctx->redo);

    rc = inflate(&ctx->zstream, ctx->flush);

    if (rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "inflate() failed: %d, %d", ctx->flush, rc);
        return NJT_ERROR;
    }

    njt_log_debug5(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "inflate out: ni:%p no:%p ai:%ud ao:%ud rc:%d",
                   ctx->zstream.next_in, ctx->zstream.next_out,
                   ctx->zstream.avail_in, ctx->zstream.avail_out,
                   rc);

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "gunzip in_buf:%p pos:%p",
                   ctx->in_buf, ctx->in_buf->pos);

    if (ctx->zstream.next_in) {
        ctx->in_buf->pos = ctx->zstream.next_in;

        if (ctx->zstream.avail_in == 0) {
            ctx->zstream.next_in = NULL;
        }
    }

    ctx->out_buf->last = ctx->zstream.next_out;

    if (ctx->zstream.avail_out == 0) {

        /* zlib wants to output some more data */

        cl = njt_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NJT_ERROR;
        }

        cl->buf = ctx->out_buf;
        cl->next = NULL;
        *ctx->last_out = cl;
        ctx->last_out = &cl->next;

        ctx->redo = 1;

        return NJT_AGAIN;
    }

    ctx->redo = 0;

    if (ctx->flush == Z_SYNC_FLUSH) {

        ctx->flush = Z_NO_FLUSH;

        cl = njt_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NJT_ERROR;
        }

        b = ctx->out_buf;

        if (njt_buf_size(b) == 0) {

            b = njt_calloc_buf(ctx->request->pool);
            if (b == NULL) {
                return NJT_ERROR;
            }

        } else {
            ctx->zstream.avail_out = 0;
        }

        b->flush = 1;

        cl->buf = b;
        cl->next = NULL;
        *ctx->last_out = cl;
        ctx->last_out = &cl->next;

        return NJT_OK;
    }

    if (ctx->flush == Z_FINISH && ctx->zstream.avail_in == 0) {

        if (rc != Z_STREAM_END) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "inflate() returned %d on response end", rc);
            return NJT_ERROR;
        }

        if (njt_http_gunzip_filter_inflate_end(r, ctx) != NJT_OK) {
            return NJT_ERROR;
        }

        return NJT_OK;
    }

    if (rc == Z_STREAM_END && ctx->zstream.avail_in > 0) {

        rc = inflateReset(&ctx->zstream);

        if (rc != Z_OK) {
            njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
                          "inflateReset() failed: %d", rc);
            return NJT_ERROR;
        }

        ctx->redo = 1;

        return NJT_AGAIN;
    }

    if (ctx->in == NULL) {

        b = ctx->out_buf;

        if (njt_buf_size(b) == 0) {
            return NJT_OK;
        }

        cl = njt_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NJT_ERROR;
        }

        ctx->zstream.avail_out = 0;

        cl->buf = b;
        cl->next = NULL;
        *ctx->last_out = cl;
        ctx->last_out = &cl->next;

        return NJT_OK;
    }

    return NJT_AGAIN;
}


static njt_int_t
njt_http_gunzip_filter_inflate_end(njt_http_request_t *r,
    njt_http_gunzip_ctx_t *ctx)
{
    int           rc;
    njt_buf_t    *b;
    njt_chain_t  *cl;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "gunzip inflate end");

    rc = inflateEnd(&ctx->zstream);

    if (rc != Z_OK) {
        njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
                      "inflateEnd() failed: %d", rc);
        return NJT_ERROR;
    }

    b = ctx->out_buf;

    if (njt_buf_size(b) == 0) {

        b = njt_calloc_buf(ctx->request->pool);
        if (b == NULL) {
            return NJT_ERROR;
        }
    }

    cl = njt_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NJT_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;
    *ctx->last_out = cl;
    ctx->last_out = &cl->next;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;
    b->sync = 1;

    ctx->done = 1;

    return NJT_OK;
}


static void *
njt_http_gunzip_filter_alloc(void *opaque, u_int items, u_int size)
{
    njt_http_gunzip_ctx_t *ctx = opaque;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "gunzip alloc: n:%ud s:%ud",
                   items, size);

    return njt_palloc(ctx->request->pool, items * size);
}


static void
njt_http_gunzip_filter_free(void *opaque, void *address)
{
#if 0
    njt_http_gunzip_ctx_t *ctx = opaque;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "gunzip free: %p", address);
#endif
}


static void *
njt_http_gunzip_create_conf(njt_conf_t *cf)
{
    njt_http_gunzip_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_gunzip_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->bufs.num = 0;
     */

    conf->enable = NJT_CONF_UNSET;

    return conf;
}


static char *
njt_http_gunzip_merge_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_gunzip_conf_t *prev = parent;
    njt_http_gunzip_conf_t *conf = child;

    njt_conf_merge_value(conf->enable, prev->enable, 0);

    njt_conf_merge_bufs_value(conf->bufs, prev->bufs,
                              (128 * 1024) / njt_pagesize, njt_pagesize);

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_gunzip_filter_init(njt_conf_t *cf)
{
    njt_http_next_header_filter = njt_http_top_header_filter;
    njt_http_top_header_filter = njt_http_gunzip_header_filter;

    njt_http_next_body_filter = njt_http_top_body_filter;
    njt_http_top_body_filter = njt_http_gunzip_body_filter;

    return NJT_OK;
}
