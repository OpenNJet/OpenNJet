
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


typedef struct {
    njt_chain_t         *free;
    njt_chain_t         *busy;
} njt_http_chunked_filter_ctx_t;


static njt_int_t njt_http_chunked_filter_init(njt_conf_t *cf);
static njt_chain_t *njt_http_chunked_create_trailers(njt_http_request_t *r,
    njt_http_chunked_filter_ctx_t *ctx);


static njt_http_module_t  njt_http_chunked_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_http_chunked_filter_init,          /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


njt_module_t  njt_http_chunked_filter_module = {
    NJT_MODULE_V1,
    &njt_http_chunked_filter_module_ctx,   /* module context */
    NULL,                                  /* module directives */
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
njt_http_chunked_header_filter(njt_http_request_t *r)
{
    njt_http_core_loc_conf_t       *clcf;
    njt_http_chunked_filter_ctx_t  *ctx;

    if (r->headers_out.status == NJT_HTTP_NOT_MODIFIED
        || r->headers_out.status == NJT_HTTP_NO_CONTENT
        || r->headers_out.status < NJT_HTTP_OK
        || r != r->main
        || r->method == NJT_HTTP_HEAD)
    {
        return njt_http_next_header_filter(r);
    }

    if (r->headers_out.content_length_n == -1
        || r->expect_trailers)
    {
        clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

        if (r->http_version >= NJT_HTTP_VERSION_11
            && clcf->chunked_transfer_encoding)
        {
            if (r->expect_trailers) {
                njt_http_clear_content_length(r);
            }

            r->chunked = 1;

            ctx = njt_pcalloc(r->pool, sizeof(njt_http_chunked_filter_ctx_t));
            if (ctx == NULL) {
                return NJT_ERROR;
            }

            njt_http_set_ctx(r, ctx, njt_http_chunked_filter_module);

        } else if (r->headers_out.content_length_n == -1) {
            r->keepalive = 0;
        }
    }

    return njt_http_next_header_filter(r);
}


static njt_int_t
njt_http_chunked_body_filter(njt_http_request_t *r, njt_chain_t *in)
{
    u_char                         *chunk;
    off_t                           size;
    njt_int_t                       rc;
    njt_buf_t                      *b;
    njt_chain_t                    *out, *cl, *tl, **ll;
    njt_http_chunked_filter_ctx_t  *ctx;

    if (in == NULL || !r->chunked || r->header_only) {
        return njt_http_next_body_filter(r, in);
    }

    ctx = njt_http_get_module_ctx(r, njt_http_chunked_filter_module);

    out = NULL;
    ll = &out;

    size = 0;
    cl = in;

    for ( ;; ) {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http chunk: %O", njt_buf_size(cl->buf));

        size += njt_buf_size(cl->buf);

        if (cl->buf->flush
            || cl->buf->sync
            || njt_buf_in_memory(cl->buf)
            || cl->buf->in_file)
        {
            tl = njt_alloc_chain_link(r->pool);
            if (tl == NULL) {
                return NJT_ERROR;
            }

            tl->buf = cl->buf;
            *ll = tl;
            ll = &tl->next;
        }

        if (cl->next == NULL) {
            break;
        }

        cl = cl->next;
    }

    if (size) {
        tl = njt_chain_get_free_buf(r->pool, &ctx->free);
        if (tl == NULL) {
            return NJT_ERROR;
        }

        b = tl->buf;
        chunk = b->start;

        if (chunk == NULL) {
            /* the "0000000000000000" is 64-bit hexadecimal string */

            chunk = njt_palloc(r->pool, sizeof("0000000000000000" CRLF) - 1);
            if (chunk == NULL) {
                return NJT_ERROR;
            }

            b->start = chunk;
            b->end = chunk + sizeof("0000000000000000" CRLF) - 1;
        }

        b->tag = (njt_buf_tag_t) &njt_http_chunked_filter_module;
        b->memory = 0;
        b->temporary = 1;
        b->pos = chunk;
        b->last = njt_sprintf(chunk, "%xO" CRLF, size);

        tl->next = out;
        out = tl;
    }

    if (cl->buf->last_buf) {
        tl = njt_http_chunked_create_trailers(r, ctx);
        if (tl == NULL) {
            return NJT_ERROR;
        }

        cl->buf->last_buf = 0;

        *ll = tl;

        if (size == 0) {
            tl->buf->pos += 2;
        }

    } else if (size > 0) {
        tl = njt_chain_get_free_buf(r->pool, &ctx->free);
        if (tl == NULL) {
            return NJT_ERROR;
        }

        b = tl->buf;

        b->tag = (njt_buf_tag_t) &njt_http_chunked_filter_module;
        b->temporary = 0;
        b->memory = 1;
        b->pos = (u_char *) CRLF;
        b->last = b->pos + 2;

        *ll = tl;

    } else {
        *ll = NULL;
    }

    rc = njt_http_next_body_filter(r, out);

    njt_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
                            (njt_buf_tag_t) &njt_http_chunked_filter_module);

    return rc;
}


static njt_chain_t *
njt_http_chunked_create_trailers(njt_http_request_t *r,
    njt_http_chunked_filter_ctx_t *ctx)
{
    size_t            len;
    njt_buf_t        *b;
    njt_uint_t        i;
    njt_chain_t      *cl;
    njt_list_part_t  *part;
    njt_table_elt_t  *header;

    len = 0;

    part = &r->headers_out.trailers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        len += header[i].key.len + sizeof(": ") - 1
               + header[i].value.len + sizeof(CRLF) - 1;
    }

    cl = njt_chain_get_free_buf(r->pool, &ctx->free);
    if (cl == NULL) {
        return NULL;
    }

    b = cl->buf;

    b->tag = (njt_buf_tag_t) &njt_http_chunked_filter_module;
    b->temporary = 0;
    b->memory = 1;
    b->last_buf = 1;

    if (len == 0) {
        b->pos = (u_char *) CRLF "0" CRLF CRLF;
        b->last = b->pos + sizeof(CRLF "0" CRLF CRLF) - 1;
        return cl;
    }

    len += sizeof(CRLF "0" CRLF CRLF) - 1;

    b->pos = njt_palloc(r->pool, len);
    if (b->pos == NULL) {
        return NULL;
    }

    b->last = b->pos;

    *b->last++ = CR; *b->last++ = LF;
    *b->last++ = '0';
    *b->last++ = CR; *b->last++ = LF;

    part = &r->headers_out.trailers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http trailer: \"%V: %V\"",
                       &header[i].key, &header[i].value);

        b->last = njt_copy(b->last, header[i].key.data, header[i].key.len);
        *b->last++ = ':'; *b->last++ = ' ';

        b->last = njt_copy(b->last, header[i].value.data, header[i].value.len);
        *b->last++ = CR; *b->last++ = LF;
    }

    *b->last++ = CR; *b->last++ = LF;

    return cl;
}


static njt_int_t
njt_http_chunked_filter_init(njt_conf_t *cf)
{
    njt_http_next_header_filter = njt_http_top_header_filter;
    njt_http_top_header_filter = njt_http_chunked_header_filter;

    njt_http_next_body_filter = njt_http_top_body_filter;
    njt_http_top_body_filter = njt_http_chunked_body_filter;

    return NJT_OK;
}
