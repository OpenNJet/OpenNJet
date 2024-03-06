
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>

#include <zlib.h>


typedef struct {
    njt_flag_t           enable;
    njt_flag_t           no_buffer;

    njt_hash_t           types;

    njt_bufs_t           bufs;

    size_t               postpone_gzipping;
    njt_int_t            level;
    size_t               wbits;
    size_t               memlevel;
    ssize_t              min_length;

    njt_array_t         *types_keys;
} njt_http_gzip_conf_t;


typedef struct {
    njt_chain_t         *in;
    njt_chain_t         *free;
    njt_chain_t         *busy;
    njt_chain_t         *out;
    njt_chain_t        **last_out;

    njt_chain_t         *copied;
    njt_chain_t         *copy_buf;

    njt_buf_t           *in_buf;
    njt_buf_t           *out_buf;
    njt_int_t            bufs;

    void                *preallocated;
    char                *free_mem;
    njt_uint_t           allocated;

    int                  wbits;
    int                  memlevel;

    unsigned             flush:4;
    unsigned             redo:1;
    unsigned             done:1;
    unsigned             nomem:1;
    unsigned             buffering:1;
    unsigned             zlib_ng:1;
    unsigned             state_allocated:1;

    size_t               zin;
    size_t               zout;

    z_stream             zstream;
    njt_http_request_t  *request;
} njt_http_gzip_ctx_t;


static void njt_http_gzip_filter_memory(njt_http_request_t *r,
    njt_http_gzip_ctx_t *ctx);
static njt_int_t njt_http_gzip_filter_buffer(njt_http_gzip_ctx_t *ctx,
    njt_chain_t *in);
static njt_int_t njt_http_gzip_filter_deflate_start(njt_http_request_t *r,
    njt_http_gzip_ctx_t *ctx);
static njt_int_t njt_http_gzip_filter_add_data(njt_http_request_t *r,
    njt_http_gzip_ctx_t *ctx);
static njt_int_t njt_http_gzip_filter_get_buf(njt_http_request_t *r,
    njt_http_gzip_ctx_t *ctx);
static njt_int_t njt_http_gzip_filter_deflate(njt_http_request_t *r,
    njt_http_gzip_ctx_t *ctx);
static njt_int_t njt_http_gzip_filter_deflate_end(njt_http_request_t *r,
    njt_http_gzip_ctx_t *ctx);

static void *njt_http_gzip_filter_alloc(void *opaque, u_int items,
    u_int size);
static void njt_http_gzip_filter_free(void *opaque, void *address);
static void njt_http_gzip_filter_free_copy_buf(njt_http_request_t *r,
    njt_http_gzip_ctx_t *ctx);

static njt_int_t njt_http_gzip_add_variables(njt_conf_t *cf);
static njt_int_t njt_http_gzip_ratio_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);

static njt_int_t njt_http_gzip_filter_init(njt_conf_t *cf);
static void *njt_http_gzip_create_conf(njt_conf_t *cf);
static char *njt_http_gzip_merge_conf(njt_conf_t *cf,
    void *parent, void *child);
static char *njt_http_gzip_window(njt_conf_t *cf, void *post, void *data);
static char *njt_http_gzip_hash(njt_conf_t *cf, void *post, void *data);


static njt_conf_num_bounds_t  njt_http_gzip_comp_level_bounds = {
    njt_conf_check_num_bounds, 1, 9
};

static njt_conf_post_handler_pt  njt_http_gzip_window_p = njt_http_gzip_window;
static njt_conf_post_handler_pt  njt_http_gzip_hash_p = njt_http_gzip_hash;


static njt_command_t  njt_http_gzip_filter_commands[] = {

    { njt_string("gzip"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_gzip_conf_t, enable),
      NULL },

    { njt_string("gzip_buffers"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE2,
      njt_conf_set_bufs_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_gzip_conf_t, bufs),
      NULL },

    { njt_string("gzip_types"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_http_types_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_gzip_conf_t, types_keys),
      &njt_http_html_default_types[0] },

    { njt_string("gzip_comp_level"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_gzip_conf_t, level),
      &njt_http_gzip_comp_level_bounds },

    { njt_string("gzip_window"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_gzip_conf_t, wbits),
      &njt_http_gzip_window_p },

    { njt_string("gzip_hash"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_gzip_conf_t, memlevel),
      &njt_http_gzip_hash_p },

    { njt_string("postpone_gzipping"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_gzip_conf_t, postpone_gzipping),
      NULL },

    { njt_string("gzip_no_buffer"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_gzip_conf_t, no_buffer),
      NULL },

    { njt_string("gzip_min_length"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_gzip_conf_t, min_length),
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_gzip_filter_module_ctx = {
    njt_http_gzip_add_variables,           /* preconfiguration */
    njt_http_gzip_filter_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_gzip_create_conf,             /* create location configuration */
    njt_http_gzip_merge_conf               /* merge location configuration */
};


njt_module_t  njt_http_gzip_filter_module = {
    NJT_MODULE_V1,
    &njt_http_gzip_filter_module_ctx,      /* module context */
    njt_http_gzip_filter_commands,         /* module directives */
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


static njt_str_t  njt_http_gzip_ratio = njt_string("gzip_ratio");

static njt_http_output_header_filter_pt  njt_http_next_header_filter;
static njt_http_output_body_filter_pt    njt_http_next_body_filter;

static njt_uint_t  njt_http_gzip_assume_zlib_ng;


static njt_int_t
njt_http_gzip_header_filter(njt_http_request_t *r)
{
    njt_table_elt_t       *h;
    njt_http_gzip_ctx_t   *ctx;
    njt_http_gzip_conf_t  *conf;

    conf = njt_http_get_module_loc_conf(r, njt_http_gzip_filter_module);

    if (!conf->enable
        || (r->headers_out.status != NJT_HTTP_OK
            && r->headers_out.status != NJT_HTTP_FORBIDDEN
            && r->headers_out.status != NJT_HTTP_NOT_FOUND)
        || (r->headers_out.content_encoding
            && r->headers_out.content_encoding->value.len)
        || (r->headers_out.content_length_n != -1
            && r->headers_out.content_length_n < conf->min_length)
        || njt_http_test_content_type(r, &conf->types) == NULL
        || r->header_only)
    {
        return njt_http_next_header_filter(r);
    }

    r->gzip_vary = 1;

#if (NJT_HTTP_DEGRADATION)
    {
    njt_http_core_loc_conf_t  *clcf;

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    if (clcf->gzip_disable_degradation && njt_http_degraded(r)) {
        return njt_http_next_header_filter(r);
    }
    }
#endif

    if (!r->gzip_tested) {
        if (njt_http_gzip_ok(r) != NJT_OK) {
            return njt_http_next_header_filter(r);
        }

    } else if (!r->gzip_ok) {
        return njt_http_next_header_filter(r);
    }

    ctx = njt_pcalloc(r->pool, sizeof(njt_http_gzip_ctx_t));
    if (ctx == NULL) {
        return NJT_ERROR;
    }

    njt_http_set_ctx(r, ctx, njt_http_gzip_filter_module);

    ctx->request = r;
    ctx->buffering = (conf->postpone_gzipping != 0);

    njt_http_gzip_filter_memory(r, ctx);

    h = njt_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    h->hash = 1;
    h->next = NULL;
    njt_str_set(&h->key, "Content-Encoding");
    njt_str_set(&h->value, "gzip");
    r->headers_out.content_encoding = h;

    r->main_filter_need_in_memory = 1;

    njt_http_clear_content_length(r);
    njt_http_clear_accept_ranges(r);
    njt_http_weak_etag(r);

    return njt_http_next_header_filter(r);
}


static njt_int_t
njt_http_gzip_body_filter(njt_http_request_t *r, njt_chain_t *in)
{
    int                   rc;
    njt_uint_t            flush;
    njt_chain_t          *cl;
    njt_http_gzip_ctx_t  *ctx;

    ctx = njt_http_get_module_ctx(r, njt_http_gzip_filter_module);

    if (ctx == NULL || ctx->done || r->header_only) {
        return njt_http_next_body_filter(r, in);
    }

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http gzip filter");

    if (ctx->buffering) {

        /*
         * With default memory settings zlib starts to output gzipped data
         * only after it has got about 90K, so it makes sense to allocate
         * zlib memory (200-400K) only after we have enough data to compress.
         * Although we copy buffers, nevertheless for not big responses
         * this allows to allocate zlib memory, to compress and to output
         * the response in one step using hot CPU cache.
         */

        if (in) {
            switch (njt_http_gzip_filter_buffer(ctx, in)) {

            case NJT_OK:
                return NJT_OK;

            case NJT_DONE:
                in = NULL;
                break;

            default:  /* NJT_ERROR */
                goto failed;
            }

        } else {
            ctx->buffering = 0;
        }
    }

    if (ctx->preallocated == NULL) {
        if (njt_http_gzip_filter_deflate_start(r, ctx) != NJT_OK) {
            goto failed;
        }
    }

    if (in) {
        if (njt_chain_add_copy(r->pool, &ctx->in, in) != NJT_OK) {
            goto failed;
        }

        r->connection->buffered |= NJT_HTTP_GZIP_BUFFERED;
    }

    if (ctx->nomem) {

        /* flush busy buffers */

        if (njt_http_next_body_filter(r, NULL) == NJT_ERROR) {
            goto failed;
        }

        cl = NULL;

        njt_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &cl,
                                (njt_buf_tag_t) &njt_http_gzip_filter_module);
        ctx->nomem = 0;
        flush = 0;

    } else {
        flush = ctx->busy ? 1 : 0;
    }

    for ( ;; ) {

        /* cycle while we can write to a client */

        for ( ;; ) {

            /* cycle while there is data to feed zlib and ... */

            rc = njt_http_gzip_filter_add_data(r, ctx);

            if (rc == NJT_DECLINED) {
                break;
            }

            if (rc == NJT_AGAIN) {
                continue;
            }


            /* ... there are buffers to write zlib output */

            rc = njt_http_gzip_filter_get_buf(r, ctx);

            if (rc == NJT_DECLINED) {
                break;
            }

            if (rc == NJT_ERROR) {
                goto failed;
            }


            rc = njt_http_gzip_filter_deflate(r, ctx);

            if (rc == NJT_OK) {
                break;
            }

            if (rc == NJT_ERROR) {
                goto failed;
            }

            /* rc == NJT_AGAIN */
        }

        if (ctx->out == NULL && !flush) {
            njt_http_gzip_filter_free_copy_buf(r, ctx);

            return ctx->busy ? NJT_AGAIN : NJT_OK;
        }

        rc = njt_http_next_body_filter(r, ctx->out);

        if (rc == NJT_ERROR) {
            goto failed;
        }

        njt_http_gzip_filter_free_copy_buf(r, ctx);

        njt_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &ctx->out,
                                (njt_buf_tag_t) &njt_http_gzip_filter_module);
        ctx->last_out = &ctx->out;

        ctx->nomem = 0;
        flush = 0;

        if (ctx->done) {
            return rc;
        }
    }

    /* unreachable */

failed:

    ctx->done = 1;

    if (ctx->preallocated) {
        deflateEnd(&ctx->zstream);

        njt_pfree(r->pool, ctx->preallocated);
    }

    njt_http_gzip_filter_free_copy_buf(r, ctx);

    return NJT_ERROR;
}


static void
njt_http_gzip_filter_memory(njt_http_request_t *r, njt_http_gzip_ctx_t *ctx)
{
    int                    wbits, memlevel;
    njt_http_gzip_conf_t  *conf;

    conf = njt_http_get_module_loc_conf(r, njt_http_gzip_filter_module);

    wbits = conf->wbits;
    memlevel = conf->memlevel;

    if (r->headers_out.content_length_n > 0) {

        /* the actual zlib window size is smaller by 262 bytes */

        while (r->headers_out.content_length_n < ((1 << (wbits - 1)) - 262)) {
            wbits--;
            memlevel--;
        }

        if (memlevel < 1) {
            memlevel = 1;
        }
    }

    ctx->wbits = wbits;
    ctx->memlevel = memlevel;

    /*
     * We preallocate a memory for zlib in one buffer (200K-400K), this
     * decreases a number of malloc() and free() calls and also probably
     * decreases a number of syscalls (sbrk()/mmap() and so on).
     * Besides we free the memory as soon as a gzipping will complete
     * and do not wait while a whole response will be sent to a client.
     *
     * 8K is for zlib deflate_state, it takes
     *  *) 5816 bytes on i386 and sparc64 (32-bit mode)
     *  *) 5920 bytes on amd64 and sparc64
     *
     * A zlib variant from Intel (https://github.com/jtkukunas/zlib)
     * uses additional 16-byte padding in one of window-sized buffers.
     */

    if (!njt_http_gzip_assume_zlib_ng) {
        ctx->allocated = 8192 + 16 + (1 << (wbits + 2))
                         + (1 << (memlevel + 9));

    } else {
        /*
         * Another zlib variant, https://github.com/zlib-ng/zlib-ng.
         * It used to force window bits to 13 for fast compression level,
         * uses (64 + sizeof(void*)) additional space on all allocations
         * for alignment, 16-byte padding in one of window-sized buffers,
         * and 128K hash.
         */

        if (conf->level == 1) {
            wbits = njt_max(wbits, 13);
        }

        ctx->allocated = 8192 + 16 + (1 << (wbits + 2))
                         + 131072 + (1 << (memlevel + 8))
                         + 4 * (64 + sizeof(void*));
        ctx->zlib_ng = 1;
    }
}


static njt_int_t
njt_http_gzip_filter_buffer(njt_http_gzip_ctx_t *ctx, njt_chain_t *in)
{
    size_t                 size, buffered;
    njt_buf_t             *b, *buf;
    njt_chain_t           *cl, **ll;
    njt_http_request_t    *r;
    njt_http_gzip_conf_t  *conf;

    r = ctx->request;

    r->connection->buffered |= NJT_HTTP_GZIP_BUFFERED;

    buffered = 0;
    ll = &ctx->in;

    for (cl = ctx->in; cl; cl = cl->next) {
        buffered += cl->buf->last - cl->buf->pos;
        ll = &cl->next;
    }

    conf = njt_http_get_module_loc_conf(r, njt_http_gzip_filter_module);

    while (in) {
        cl = njt_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NJT_ERROR;
        }

        b = in->buf;

        size = b->last - b->pos;
        buffered += size;

        if (b->flush || b->last_buf || buffered > conf->postpone_gzipping) {
            ctx->buffering = 0;
        }

        if (ctx->buffering && size) {

            buf = njt_create_temp_buf(r->pool, size);
            if (buf == NULL) {
                return NJT_ERROR;
            }

            buf->last = njt_cpymem(buf->pos, b->pos, size);
            b->pos = b->last;

            buf->last_buf = b->last_buf;
            buf->tag = (njt_buf_tag_t) &njt_http_gzip_filter_module;

            cl->buf = buf;

        } else {
            cl->buf = b;
        }

        *ll = cl;
        ll = &cl->next;
        in = in->next;
    }

    *ll = NULL;

    return ctx->buffering ? NJT_OK : NJT_DONE;
}


static njt_int_t
njt_http_gzip_filter_deflate_start(njt_http_request_t *r,
    njt_http_gzip_ctx_t *ctx)
{
    int                    rc;
    njt_http_gzip_conf_t  *conf;

    conf = njt_http_get_module_loc_conf(r, njt_http_gzip_filter_module);

    ctx->preallocated = njt_palloc(r->pool, ctx->allocated);
    if (ctx->preallocated == NULL) {
        return NJT_ERROR;
    }

    ctx->free_mem = ctx->preallocated;

    ctx->zstream.zalloc = njt_http_gzip_filter_alloc;
    ctx->zstream.zfree = njt_http_gzip_filter_free;
    ctx->zstream.opaque = ctx;

    rc = deflateInit2(&ctx->zstream, (int) conf->level, Z_DEFLATED,
                      ctx->wbits + 16, ctx->memlevel, Z_DEFAULT_STRATEGY);

    if (rc != Z_OK) {
        njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
                      "deflateInit2() failed: %d", rc);
        return NJT_ERROR;
    }

    ctx->last_out = &ctx->out;
    ctx->flush = Z_NO_FLUSH;

    return NJT_OK;
}


static njt_int_t
njt_http_gzip_filter_add_data(njt_http_request_t *r, njt_http_gzip_ctx_t *ctx)
{
    njt_chain_t  *cl;

    if (ctx->zstream.avail_in || ctx->flush != Z_NO_FLUSH || ctx->redo) {
        return NJT_OK;
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "gzip in: %p", ctx->in);

    if (ctx->in == NULL) {
        return NJT_DECLINED;
    }

    if (ctx->copy_buf) {

        /*
         * to avoid CPU cache trashing we do not free() just quit buf,
         * but postpone free()ing after zlib compressing and data output
         */

        ctx->copy_buf->next = ctx->copied;
        ctx->copied = ctx->copy_buf;
        ctx->copy_buf = NULL;
    }

    cl = ctx->in;
    ctx->in_buf = cl->buf;
    ctx->in = cl->next;

    if (ctx->in_buf->tag == (njt_buf_tag_t) &njt_http_gzip_filter_module) {
        ctx->copy_buf = cl;

    } else {
        njt_free_chain(r->pool, cl);
    }

    ctx->zstream.next_in = ctx->in_buf->pos;
    ctx->zstream.avail_in = ctx->in_buf->last - ctx->in_buf->pos;

    njt_log_debug3(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "gzip in_buf:%p ni:%p ai:%ud",
                   ctx->in_buf,
                   ctx->zstream.next_in, ctx->zstream.avail_in);

    if (ctx->in_buf->last_buf) {
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
njt_http_gzip_filter_get_buf(njt_http_request_t *r, njt_http_gzip_ctx_t *ctx)
{
    njt_chain_t           *cl;
    njt_http_gzip_conf_t  *conf;

    if (ctx->zstream.avail_out) {
        return NJT_OK;
    }

    conf = njt_http_get_module_loc_conf(r, njt_http_gzip_filter_module);

    if (ctx->free) {

        cl = ctx->free;
        ctx->out_buf = cl->buf;
        ctx->free = cl->next;

        njt_free_chain(r->pool, cl);

    } else if (ctx->bufs < conf->bufs.num) {

        ctx->out_buf = njt_create_temp_buf(r->pool, conf->bufs.size);
        if (ctx->out_buf == NULL) {
            return NJT_ERROR;
        }

        ctx->out_buf->tag = (njt_buf_tag_t) &njt_http_gzip_filter_module;
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
njt_http_gzip_filter_deflate(njt_http_request_t *r, njt_http_gzip_ctx_t *ctx)
{
    int                    rc;
    njt_buf_t             *b;
    njt_chain_t           *cl;
    njt_http_gzip_conf_t  *conf;

    njt_log_debug6(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "deflate in: ni:%p no:%p ai:%ud ao:%ud fl:%d redo:%d",
                 ctx->zstream.next_in, ctx->zstream.next_out,
                 ctx->zstream.avail_in, ctx->zstream.avail_out,
                 ctx->flush, ctx->redo);

    rc = deflate(&ctx->zstream, ctx->flush);

    if (rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
        njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
                      "deflate() failed: %d, %d", ctx->flush, rc);
        return NJT_ERROR;
    }

    njt_log_debug5(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "deflate out: ni:%p no:%p ai:%ud ao:%ud rc:%d",
                   ctx->zstream.next_in, ctx->zstream.next_out,
                   ctx->zstream.avail_in, ctx->zstream.avail_out,
                   rc);

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "gzip in_buf:%p pos:%p",
                   ctx->in_buf, ctx->in_buf->pos);

    if (ctx->zstream.next_in) {
        ctx->in_buf->pos = ctx->zstream.next_in;

        if (ctx->zstream.avail_in == 0) {
            ctx->zstream.next_in = NULL;
        }
    }

    ctx->out_buf->last = ctx->zstream.next_out;

    if (ctx->zstream.avail_out == 0 && rc != Z_STREAM_END) {

        /* zlib wants to output some more gzipped data */

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

        r->connection->buffered &= ~NJT_HTTP_GZIP_BUFFERED;

        return NJT_OK;
    }

    if (rc == Z_STREAM_END) {

        if (njt_http_gzip_filter_deflate_end(r, ctx) != NJT_OK) {
            return NJT_ERROR;
        }

        return NJT_OK;
    }

    conf = njt_http_get_module_loc_conf(r, njt_http_gzip_filter_module);

    if (conf->no_buffer && ctx->in == NULL) {

        cl = njt_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NJT_ERROR;
        }

        cl->buf = ctx->out_buf;
        cl->next = NULL;
        *ctx->last_out = cl;
        ctx->last_out = &cl->next;

        return NJT_OK;
    }

    return NJT_AGAIN;
}


static njt_int_t
njt_http_gzip_filter_deflate_end(njt_http_request_t *r,
    njt_http_gzip_ctx_t *ctx)
{
    int           rc;
    njt_buf_t    *b;
    njt_chain_t  *cl;

    ctx->zin = ctx->zstream.total_in;
    ctx->zout = ctx->zstream.total_out;

    rc = deflateEnd(&ctx->zstream);

    if (rc != Z_OK) {
        njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
                      "deflateEnd() failed: %d", rc);
        return NJT_ERROR;
    }

    njt_pfree(r->pool, ctx->preallocated);

    cl = njt_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NJT_ERROR;
    }

    b = ctx->out_buf;

    if (njt_buf_size(b) == 0) {
        b->temporary = 0;
    }

    b->last_buf = 1;

    cl->buf = b;
    cl->next = NULL;
    *ctx->last_out = cl;
    ctx->last_out = &cl->next;

    ctx->zstream.avail_in = 0;
    ctx->zstream.avail_out = 0;

    ctx->done = 1;

    r->connection->buffered &= ~NJT_HTTP_GZIP_BUFFERED;

    return NJT_OK;
}


static void *
njt_http_gzip_filter_alloc(void *opaque, u_int items, u_int size)
{
    njt_http_gzip_ctx_t *ctx = opaque;

    void        *p;
    njt_uint_t   alloc;

    alloc = items * size;

    if (items == 1 && alloc % 512 != 0 && alloc < 8192
        && !ctx->state_allocated)
    {

        /*
         * The zlib deflate_state allocation, it takes about 6K,
         * we allocate 8K.  Other allocations are divisible by 512.
         */

        ctx->state_allocated = 1;

        alloc = 8192;
    }

    if (alloc <= ctx->allocated) {
        p = ctx->free_mem;
        ctx->free_mem += alloc;
        ctx->allocated -= alloc;

        njt_log_debug4(NJT_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                       "gzip alloc: n:%ud s:%ud a:%ui p:%p",
                       items, size, alloc, p);

        return p;
    }

    if (ctx->zlib_ng) {
        njt_log_error(NJT_LOG_ALERT, ctx->request->connection->log, 0,
                      "gzip filter failed to use preallocated memory: "
                      "%ud of %ui", items * size, ctx->allocated);

    } else {
        njt_http_gzip_assume_zlib_ng = 1;
    }

    p = njt_palloc(ctx->request->pool, items * size);

    return p;
}


static void
njt_http_gzip_filter_free(void *opaque, void *address)
{
#if 0
    njt_http_gzip_ctx_t *ctx = opaque;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "gzip free: %p", address);
#endif
}


static void
njt_http_gzip_filter_free_copy_buf(njt_http_request_t *r,
    njt_http_gzip_ctx_t *ctx)
{
    njt_chain_t  *cl;

    for (cl = ctx->copied; cl; cl = cl->next) {
        njt_pfree(r->pool, cl->buf->start);
    }

    ctx->copied = NULL;
}


static njt_int_t
njt_http_gzip_add_variables(njt_conf_t *cf)
{
    njt_http_variable_t  *var;

    var = njt_http_add_variable(cf, &njt_http_gzip_ratio, NJT_HTTP_VAR_NOHASH);
    if (var == NULL) {
        return NJT_ERROR;
    }

    var->get_handler = njt_http_gzip_ratio_variable;

    return NJT_OK;
}


static njt_int_t
njt_http_gzip_ratio_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_uint_t            zint, zfrac;
    njt_http_gzip_ctx_t  *ctx;

    ctx = njt_http_get_module_ctx(r, njt_http_gzip_filter_module);

    if (ctx == NULL || ctx->zout == 0) {
        v->not_found = 1;
        return NJT_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = njt_pnalloc(r->pool, NJT_INT32_LEN + 3);
    if (v->data == NULL) {
        return NJT_ERROR;
    }

    zint = (njt_uint_t) (ctx->zin / ctx->zout);
    zfrac = (njt_uint_t) ((ctx->zin * 100 / ctx->zout) % 100);

    if ((ctx->zin * 1000 / ctx->zout) % 10 > 4) {

        /* the rounding, e.g., 2.125 to 2.13 */

        zfrac++;

        if (zfrac > 99) {
            zint++;
            zfrac = 0;
        }
    }

    v->len = njt_sprintf(v->data, "%ui.%02ui", zint, zfrac) - v->data;

    return NJT_OK;
}


static void *
njt_http_gzip_create_conf(njt_conf_t *cf)
{
    njt_http_gzip_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_gzip_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->bufs.num = 0;
     *     conf->types = { NULL };
     *     conf->types_keys = NULL;
     */

    conf->enable = NJT_CONF_UNSET;
    conf->no_buffer = NJT_CONF_UNSET;

    conf->postpone_gzipping = NJT_CONF_UNSET_SIZE;
    conf->level = NJT_CONF_UNSET;
    conf->wbits = NJT_CONF_UNSET_SIZE;
    conf->memlevel = NJT_CONF_UNSET_SIZE;
    conf->min_length = NJT_CONF_UNSET;

    return conf;
}


static char *
njt_http_gzip_merge_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_gzip_conf_t *prev = parent;
    njt_http_gzip_conf_t *conf = child;

    njt_conf_merge_value(conf->enable, prev->enable, 0);
    njt_conf_merge_value(conf->no_buffer, prev->no_buffer, 0);

    njt_conf_merge_bufs_value(conf->bufs, prev->bufs,
                              (128 * 1024) / njt_pagesize, njt_pagesize);

    njt_conf_merge_size_value(conf->postpone_gzipping, prev->postpone_gzipping,
                              0);
    njt_conf_merge_value(conf->level, prev->level, 1);
    njt_conf_merge_size_value(conf->wbits, prev->wbits, MAX_WBITS);
    njt_conf_merge_size_value(conf->memlevel, prev->memlevel,
                              MAX_MEM_LEVEL - 1);
    njt_conf_merge_value(conf->min_length, prev->min_length, 20);

    if (njt_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             njt_http_html_default_types)
        != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_gzip_filter_init(njt_conf_t *cf)
{
    njt_http_next_header_filter = njt_http_top_header_filter;
    njt_http_top_header_filter = njt_http_gzip_header_filter;

    njt_http_next_body_filter = njt_http_top_body_filter;
    njt_http_top_body_filter = njt_http_gzip_body_filter;

    return NJT_OK;
}


static char *
njt_http_gzip_window(njt_conf_t *cf, void *post, void *data)
{
    size_t *np = data;

    size_t  wbits, wsize;

    wbits = 15;

    for (wsize = 32 * 1024; wsize > 256; wsize >>= 1) {

        if (wsize == *np) {
            *np = wbits;

            return NJT_CONF_OK;
        }

        wbits--;
    }

    return "must be 512, 1k, 2k, 4k, 8k, 16k, or 32k";
}


static char *
njt_http_gzip_hash(njt_conf_t *cf, void *post, void *data)
{
    size_t *np = data;

    size_t  memlevel, hsize;

    memlevel = 9;

    for (hsize = 128 * 1024; hsize > 256; hsize >>= 1) {

        if (hsize == *np) {
            *np = memlevel;

            return NJT_CONF_OK;
        }

        memlevel--;
    }

    return "must be 512, 1k, 2k, 4k, 8k, 16k, 32k, 64k, or 128k";
}
