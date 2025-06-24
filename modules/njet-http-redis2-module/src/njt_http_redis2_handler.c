
#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"

#include "njt_http_redis2_handler.h"
#include "njt_http_redis2_reply.h"
#include "njt_http_redis2_util.h"


static njt_int_t njt_http_redis2_create_request(njt_http_request_t *r);
static njt_int_t njt_http_redis2_reinit_request(njt_http_request_t *r);
static njt_int_t njt_http_redis2_process_header(njt_http_request_t *r);
static njt_int_t njt_http_redis2_filter_init(void *data);
static njt_int_t njt_http_redis2_filter(void *data, ssize_t bytes);
static void njt_http_redis2_abort_request(njt_http_request_t *r);
static void njt_http_redis2_finalize_request(njt_http_request_t *r,
    njt_int_t rc);


njt_int_t
njt_http_redis2_handler(njt_http_request_t *r)
{
    njt_int_t                        rc;
    njt_http_upstream_t             *u;
    njt_http_redis2_ctx_t           *ctx;
    njt_http_redis2_loc_conf_t      *rlcf;
    njt_str_t                        target;
    njt_url_t                        url;

    if (njt_http_set_content_type(r) != NJT_OK) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (njt_http_upstream_create(r) != NJT_OK) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    u = r->upstream;

    rlcf = njt_http_get_module_loc_conf(r, njt_http_redis2_module);

    if (rlcf->complex_target) {
        /* variables used in the redis2_pass directive */

        if (njt_http_complex_value(r, rlcf->complex_target, &target)
            != NJT_OK)
        {
            return NJT_ERROR;
        }

        if (target.len == 0) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "handler: empty \"redis2_pass\" target");
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        url.host = target;
        url.port = 0;
        url.no_resolve = 1;

        rlcf->upstream.upstream = njt_http_redis2_upstream_add(r, &url);

        if (rlcf->upstream.upstream == NULL) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "redis2: upstream \"%V\" not found", &target);

            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    njt_str_set(&u->schema, "redis2://");
    u->output.tag = (njt_buf_tag_t) &njt_http_redis2_module;

    u->conf = &rlcf->upstream;

    u->create_request = njt_http_redis2_create_request;
    u->reinit_request = njt_http_redis2_reinit_request;
    u->process_header = njt_http_redis2_process_header;
    u->abort_request = njt_http_redis2_abort_request;
    u->finalize_request = njt_http_redis2_finalize_request;

    ctx = njt_pcalloc(r->pool, sizeof(njt_http_redis2_ctx_t));
    if (ctx == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->request = r;
    ctx->state = NJT_ERROR;

    njt_http_set_ctx(r, ctx, njt_http_redis2_module);

    u->input_filter_init = njt_http_redis2_filter_init;
    u->input_filter = njt_http_redis2_filter;
    u->input_filter_ctx = ctx;

    rc = njt_http_read_client_request_body(r, njt_http_upstream_init);

    if (rc >= NJT_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NJT_DONE;
}


static njt_int_t
njt_http_redis2_create_request(njt_http_request_t *r)
{
    njt_buf_t                       *b;
    njt_chain_t                     *cl;
    njt_http_redis2_loc_conf_t      *rlcf;
    njt_str_t                        query;
    njt_str_t                        query_count;
    njt_int_t                        rc;
    njt_http_redis2_ctx_t           *ctx;
    njt_int_t                        n;

    ctx = njt_http_get_module_ctx(r, njt_http_redis2_module);

    rlcf = njt_http_get_module_loc_conf(r, njt_http_redis2_module);

    if (rlcf->queries) {
        ctx->query_count = rlcf->queries->nelts;

        rc = njt_http_redis2_build_query(r, rlcf->queries, &b);
        if (rc != NJT_OK) {
            return rc;
        }

    } else if (rlcf->literal_query.len == 0) {
        if (rlcf->complex_query == NULL) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "no redis2 query specified or the query is empty");

            return NJT_ERROR;
        }

        if (njt_http_complex_value(r, rlcf->complex_query, &query)
            != NJT_OK)
        {
            return NJT_ERROR;
        }

        if (query.len == 0) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "the redis query is empty");

            return NJT_ERROR;
        }

        if (rlcf->complex_query_count == NULL) {
            ctx->query_count = 1;

        } else {
            if (njt_http_complex_value(r, rlcf->complex_query_count,
                                       &query_count)
                != NJT_OK)
            {
                return NJT_ERROR;
            }

            if (query_count.len == 0) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "the N argument to redis2_raw_queries is empty");

                return NJT_ERROR;
            }

            n = njt_atoi(query_count.data, query_count.len);
            if (n == NJT_ERROR || n == 0) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "the N argument to redis2_raw_queries is "
                              "invalid");

                return NJT_ERROR;
            }

            ctx->query_count = n;
        }

        b = njt_create_temp_buf(r->pool, query.len);
        if (b == NULL) {
            return NJT_ERROR;
        }

        b->last = njt_copy(b->pos, query.data, query.len);

    } else {
        ctx->query_count = 1;

        b = njt_calloc_buf(r->pool);
        if (b == NULL) {
            return NJT_ERROR;
        }

        b->pos = rlcf->literal_query.data;
        b->last = b->pos + rlcf->literal_query.len;
        b->memory = 1;
    }

    cl = njt_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NJT_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    r->upstream->request_bufs = cl;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http redis2 request: \"%V\"", &rlcf->literal_query);

    return NJT_OK;
}


static njt_int_t
njt_http_redis2_reinit_request(njt_http_request_t *r)
{
    return NJT_OK;
}


static njt_int_t
njt_http_redis2_process_header(njt_http_request_t *r)
{
    njt_http_upstream_t         *u;
    njt_http_redis2_ctx_t       *ctx;
    njt_buf_t                   *b;
    u_char                       chr;
    njt_str_t                    buf;

    u = r->upstream;
    b = &u->buffer;

    if (b->last - b->pos < (ssize_t) sizeof(u_char)) {
        return NJT_AGAIN;
    }

    ctx = njt_http_get_module_ctx(r, njt_http_redis2_module);

    /* the first char is the response header */

    chr = *b->pos;

    dd("response header: %c (ascii %d)", chr, chr);

    switch (chr) {
        case '+':
        case '-':
        case ':':
        case '$':
        case '*':
            ctx->filter = njt_http_redis2_process_reply;
            break;

        default:
            buf.data = b->pos;
            buf.len = b->last - b->pos;

            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "redis2 sent invalid response: \"%V\"", &buf);

            return NJT_HTTP_UPSTREAM_INVALID_HEADER;
    }

    u->headers_in.status_n = NJT_HTTP_OK;
    u->state->status = NJT_HTTP_OK;

    return NJT_OK;
}


static njt_int_t
njt_http_redis2_filter_init(void *data)
{
#if 0
    njt_http_redis2_ctx_t  *ctx = data;

    njt_http_upstream_t  *u;

    u = ctx->request->upstream;
#endif

    return NJT_OK;
}


static njt_int_t
njt_http_redis2_filter(void *data, ssize_t bytes)
{
    njt_http_redis2_ctx_t  *ctx = data;

    return ctx->filter(ctx, bytes);
}


static void
njt_http_redis2_abort_request(njt_http_request_t *r)
{
    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http redis2 request");
    return;
}


static void
njt_http_redis2_finalize_request(njt_http_request_t *r, njt_int_t rc)
{
    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http redis2 request");

    if (rc >= NJT_HTTP_SPECIAL_RESPONSE) {
        r->headers_out.status = rc;
    }

    return;
}
