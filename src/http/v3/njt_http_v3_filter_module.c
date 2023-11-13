
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


/* static table indices */
#define NJT_HTTP_V3_HEADER_AUTHORITY                 0
#define NJT_HTTP_V3_HEADER_PATH_ROOT                 1
#define NJT_HTTP_V3_HEADER_CONTENT_LENGTH_ZERO       4
#define NJT_HTTP_V3_HEADER_DATE                      6
#define NJT_HTTP_V3_HEADER_LAST_MODIFIED             10
#define NJT_HTTP_V3_HEADER_LOCATION                  12
#define NJT_HTTP_V3_HEADER_METHOD_GET                17
#define NJT_HTTP_V3_HEADER_SCHEME_HTTP               22
#define NJT_HTTP_V3_HEADER_SCHEME_HTTPS              23
#define NJT_HTTP_V3_HEADER_STATUS_200                25
#define NJT_HTTP_V3_HEADER_ACCEPT_ENCODING           31
#define NJT_HTTP_V3_HEADER_CONTENT_TYPE_TEXT_PLAIN   53
#define NJT_HTTP_V3_HEADER_VARY_ACCEPT_ENCODING      59
#define NJT_HTTP_V3_HEADER_ACCEPT_LANGUAGE           72
#define NJT_HTTP_V3_HEADER_SERVER                    92
#define NJT_HTTP_V3_HEADER_USER_AGENT                95


typedef struct {
    njt_chain_t         *free;
    njt_chain_t         *busy;
} njt_http_v3_filter_ctx_t;


static njt_int_t njt_http_v3_header_filter(njt_http_request_t *r);
static njt_int_t njt_http_v3_body_filter(njt_http_request_t *r,
    njt_chain_t *in);
static njt_chain_t *njt_http_v3_create_trailers(njt_http_request_t *r,
    njt_http_v3_filter_ctx_t *ctx);
static njt_int_t njt_http_v3_filter_init(njt_conf_t *cf);


static njt_http_module_t  njt_http_v3_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_http_v3_filter_init,               /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


njt_module_t  njt_http_v3_filter_module = {
    NJT_MODULE_V1,
    &njt_http_v3_filter_module_ctx,        /* module context */
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
njt_http_v3_header_filter(njt_http_request_t *r)
{
    u_char                    *p;
    size_t                     len, n;
    njt_buf_t                 *b;
    njt_str_t                  host, location;
    njt_uint_t                 i, port;
    njt_chain_t               *out, *hl, *cl, **ll;
    njt_list_part_t           *part;
    njt_table_elt_t           *header;
    njt_connection_t          *c;
    njt_http_v3_session_t     *h3c;
    njt_http_v3_filter_ctx_t  *ctx;
    njt_http_core_loc_conf_t  *clcf;
    njt_http_core_srv_conf_t  *cscf;
    u_char                     addr[NJT_SOCKADDR_STRLEN];

    if (r->http_version != NJT_HTTP_VERSION_30) {
        return njt_http_next_header_filter(r);
    }

    if (r->header_sent) {
        return NJT_OK;
    }

    r->header_sent = 1;

    if (r != r->main) {
        return NJT_OK;
    }

    h3c = njt_http_v3_get_session(r->connection);

    if (r->method == NJT_HTTP_HEAD) {
        r->header_only = 1;
    }

    if (r->headers_out.last_modified_time != -1) {
        if (r->headers_out.status != NJT_HTTP_OK
            && r->headers_out.status != NJT_HTTP_PARTIAL_CONTENT
            && r->headers_out.status != NJT_HTTP_NOT_MODIFIED)
        {
            r->headers_out.last_modified_time = -1;
            r->headers_out.last_modified = NULL;
        }
    }

    if (r->headers_out.status == NJT_HTTP_NO_CONTENT) {
        r->header_only = 1;
        njt_str_null(&r->headers_out.content_type);
        r->headers_out.last_modified_time = -1;
        r->headers_out.last_modified = NULL;
        r->headers_out.content_length = NULL;
        r->headers_out.content_length_n = -1;
    }

    if (r->headers_out.status == NJT_HTTP_NOT_MODIFIED) {
        r->header_only = 1;
    }

    c = r->connection;

    out = NULL;
    ll = &out;

    len = njt_http_v3_encode_field_section_prefix(NULL, 0, 0, 0);

    if (r->headers_out.status == NJT_HTTP_OK) {
        len += njt_http_v3_encode_field_ri(NULL, 0,
                                           NJT_HTTP_V3_HEADER_STATUS_200);

    } else {
        len += njt_http_v3_encode_field_lri(NULL, 0,
                                            NJT_HTTP_V3_HEADER_STATUS_200,
                                            NULL, 3);
    }

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    if (r->headers_out.server == NULL) {
        if (clcf->server_tokens == NJT_HTTP_SERVER_TOKENS_ON) {
            n = sizeof(NJT_VER) - 1;

        } else if (clcf->server_tokens == NJT_HTTP_SERVER_TOKENS_BUILD) {
            n = sizeof(NJT_VER_BUILD) - 1;

        } else {
            n = sizeof("njet") - 1;
        }

        len += njt_http_v3_encode_field_lri(NULL, 0,
                                            NJT_HTTP_V3_HEADER_SERVER,
                                            NULL, n);
    }

    if (r->headers_out.date == NULL) {
        len += njt_http_v3_encode_field_lri(NULL, 0, NJT_HTTP_V3_HEADER_DATE,
                                            NULL, njt_cached_http_time.len);
    }

    if (r->headers_out.content_type.len) {
        n = r->headers_out.content_type.len;

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            n += sizeof("; charset=") - 1 + r->headers_out.charset.len;
        }

        len += njt_http_v3_encode_field_lri(NULL, 0,
                                    NJT_HTTP_V3_HEADER_CONTENT_TYPE_TEXT_PLAIN,
                                    NULL, n);
    }

    if (r->headers_out.content_length == NULL) {
        if (r->headers_out.content_length_n > 0) {
            len += njt_http_v3_encode_field_lri(NULL, 0,
                                        NJT_HTTP_V3_HEADER_CONTENT_LENGTH_ZERO,
                                        NULL, NJT_OFF_T_LEN);

        } else if (r->headers_out.content_length_n == 0) {
            len += njt_http_v3_encode_field_ri(NULL, 0,
                                       NJT_HTTP_V3_HEADER_CONTENT_LENGTH_ZERO);
        }
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        len += njt_http_v3_encode_field_lri(NULL, 0,
                                  NJT_HTTP_V3_HEADER_LAST_MODIFIED, NULL,
                                  sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1);
    }

    if (r->headers_out.location && r->headers_out.location->value.len) {

        if (r->headers_out.location->value.data[0] == '/'
            && clcf->absolute_redirect)
        {
            if (clcf->server_name_in_redirect) {
                cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);
                host = cscf->server_name;

            } else if (r->headers_in.server.len) {
                host = r->headers_in.server;

            } else {
                host.len = NJT_SOCKADDR_STRLEN;
                host.data = addr;

                if (njt_connection_local_sockaddr(c, &host, 0) != NJT_OK) {
                    return NJT_ERROR;
                }
            }

            port = njt_inet_get_port(c->local_sockaddr);

            location.len = sizeof("https://") - 1 + host.len
                           + r->headers_out.location->value.len;

            if (clcf->port_in_redirect) {
                port = (port == 443) ? 0 : port;

            } else {
                port = 0;
            }

            if (port) {
                location.len += sizeof(":65535") - 1;
            }

            location.data = njt_pnalloc(r->pool, location.len);
            if (location.data == NULL) {
                return NJT_ERROR;
            }

            p = njt_cpymem(location.data, "https://", sizeof("https://") - 1);
            p = njt_cpymem(p, host.data, host.len);

            if (port) {
                p = njt_sprintf(p, ":%ui", port);
            }

            p = njt_cpymem(p, r->headers_out.location->value.data,
                              r->headers_out.location->value.len);

            /* update r->headers_out.location->value for possible logging */

            r->headers_out.location->value.len = p - location.data;
            r->headers_out.location->value.data = location.data;
            njt_str_set(&r->headers_out.location->key, "Location");
        }

        r->headers_out.location->hash = 0;

        len += njt_http_v3_encode_field_lri(NULL, 0,
                                           NJT_HTTP_V3_HEADER_LOCATION, NULL,
                                           r->headers_out.location->value.len);
    }

#if (NJT_HTTP_GZIP)
    if (r->gzip_vary) {
        if (clcf->gzip_vary) {
            len += njt_http_v3_encode_field_ri(NULL, 0,
                                      NJT_HTTP_V3_HEADER_VARY_ACCEPT_ENCODING);

        } else {
            r->gzip_vary = 0;
        }
    }
#endif

    part = &r->headers_out.headers.part;
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

        len += njt_http_v3_encode_field_l(NULL, &header[i].key,
                                          &header[i].value);
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0, "http3 header len:%uz", len);

    b = njt_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NJT_ERROR;
    }

    b->last = (u_char *) njt_http_v3_encode_field_section_prefix(b->last,
                                                                 0, 0, 0);

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 output header: \":status: %03ui\"",
                   r->headers_out.status);

    if (r->headers_out.status == NJT_HTTP_OK) {
        b->last = (u_char *) njt_http_v3_encode_field_ri(b->last, 0,
                                                NJT_HTTP_V3_HEADER_STATUS_200);

    } else {
        b->last = (u_char *) njt_http_v3_encode_field_lri(b->last, 0,
                                                 NJT_HTTP_V3_HEADER_STATUS_200,
                                                 NULL, 3);
        b->last = njt_sprintf(b->last, "%03ui", r->headers_out.status);
    }

    if (r->headers_out.server == NULL) {
        if (clcf->server_tokens == NJT_HTTP_SERVER_TOKENS_ON) {
            p = (u_char *) NJT_VER;
            n = sizeof(NJT_VER) - 1;

        } else if (clcf->server_tokens == NJT_HTTP_SERVER_TOKENS_BUILD) {
            p = (u_char *) NJT_VER_BUILD;
            n = sizeof(NJT_VER_BUILD) - 1;

        } else {
            p = (u_char *) "njet";
            n = sizeof("njet") - 1;
        }

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 output header: \"server: %*s\"", n, p);

        b->last = (u_char *) njt_http_v3_encode_field_lri(b->last, 0,
                                                     NJT_HTTP_V3_HEADER_SERVER,
                                                     p, n);
    }

    if (r->headers_out.date == NULL) {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 output header: \"date: %V\"",
                       &njt_cached_http_time);

        b->last = (u_char *) njt_http_v3_encode_field_lri(b->last, 0,
                                                     NJT_HTTP_V3_HEADER_DATE,
                                                     njt_cached_http_time.data,
                                                     njt_cached_http_time.len);
    }

    if (r->headers_out.content_type.len) {
        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            n = r->headers_out.content_type.len + sizeof("; charset=") - 1
                + r->headers_out.charset.len;

            p = njt_pnalloc(r->pool, n);
            if (p == NULL) {
                return NJT_ERROR;
            }

            p = njt_cpymem(p, r->headers_out.content_type.data,
                           r->headers_out.content_type.len);

            p = njt_cpymem(p, "; charset=", sizeof("; charset=") - 1);

            p = njt_cpymem(p, r->headers_out.charset.data,
                           r->headers_out.charset.len);

            /* updated r->headers_out.content_type is also needed for logging */

            r->headers_out.content_type.len = n;
            r->headers_out.content_type.data = p - n;
        }

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 output header: \"content-type: %V\"",
                       &r->headers_out.content_type);

        b->last = (u_char *) njt_http_v3_encode_field_lri(b->last, 0,
                                    NJT_HTTP_V3_HEADER_CONTENT_TYPE_TEXT_PLAIN,
                                    r->headers_out.content_type.data,
                                    r->headers_out.content_type.len);
    }

    if (r->headers_out.content_length == NULL
        && r->headers_out.content_length_n >= 0)
    {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 output header: \"content-length: %O\"",
                       r->headers_out.content_length_n);

        if (r->headers_out.content_length_n > 0) {
            p = njt_sprintf(b->last, "%O", r->headers_out.content_length_n);
            n = p - b->last;

            b->last = (u_char *) njt_http_v3_encode_field_lri(b->last, 0,
                                        NJT_HTTP_V3_HEADER_CONTENT_LENGTH_ZERO,
                                        NULL, n);

            b->last = njt_sprintf(b->last, "%O",
                                  r->headers_out.content_length_n);

        } else {
            b->last = (u_char *) njt_http_v3_encode_field_ri(b->last, 0,
                                       NJT_HTTP_V3_HEADER_CONTENT_LENGTH_ZERO);
        }
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        n = sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1;

        p = njt_pnalloc(r->pool, n);
        if (p == NULL) {
            return NJT_ERROR;
        }

        njt_http_time(p, r->headers_out.last_modified_time);

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 output header: \"last-modified: %*s\"", n, p);

        b->last = (u_char *) njt_http_v3_encode_field_lri(b->last, 0,
                                              NJT_HTTP_V3_HEADER_LAST_MODIFIED,
                                              p, n);
    }

    if (r->headers_out.location && r->headers_out.location->value.len) {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 output header: \"location: %V\"",
                       &r->headers_out.location->value);

        b->last = (u_char *) njt_http_v3_encode_field_lri(b->last, 0,
                                           NJT_HTTP_V3_HEADER_LOCATION,
                                           r->headers_out.location->value.data,
                                           r->headers_out.location->value.len);
    }

#if (NJT_HTTP_GZIP)
    if (r->gzip_vary) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 output header: \"vary: Accept-Encoding\"");

        b->last = (u_char *) njt_http_v3_encode_field_ri(b->last, 0,
                                      NJT_HTTP_V3_HEADER_VARY_ACCEPT_ENCODING);
    }
#endif

    part = &r->headers_out.headers.part;
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

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 output header: \"%V: %V\"",
                       &header[i].key, &header[i].value);

        b->last = (u_char *) njt_http_v3_encode_field_l(b->last,
                                                        &header[i].key,
                                                        &header[i].value);
    }

    if (r->header_only) {
        b->last_buf = 1;
    }

    cl = njt_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NJT_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    n = b->last - b->pos;

    h3c->payload_bytes += n;

    len = njt_http_v3_encode_varlen_int(NULL, NJT_HTTP_V3_FRAME_HEADERS)
          + njt_http_v3_encode_varlen_int(NULL, n);

    b = njt_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NJT_ERROR;
    }

    b->last = (u_char *) njt_http_v3_encode_varlen_int(b->last,
                                                    NJT_HTTP_V3_FRAME_HEADERS);
    b->last = (u_char *) njt_http_v3_encode_varlen_int(b->last, n);

    hl = njt_alloc_chain_link(r->pool);
    if (hl == NULL) {
        return NJT_ERROR;
    }

    hl->buf = b;
    hl->next = cl;

    *ll = hl;
    ll = &cl->next;

    if (r->headers_out.content_length_n >= 0
        && !r->header_only && !r->expect_trailers)
    {
        len = njt_http_v3_encode_varlen_int(NULL, NJT_HTTP_V3_FRAME_DATA)
              + njt_http_v3_encode_varlen_int(NULL,
                                              r->headers_out.content_length_n);

        b = njt_create_temp_buf(r->pool, len);
        if (b == NULL) {
            return NJT_ERROR;
        }

        b->last = (u_char *) njt_http_v3_encode_varlen_int(b->last,
                                                       NJT_HTTP_V3_FRAME_DATA);
        b->last = (u_char *) njt_http_v3_encode_varlen_int(b->last,
                                              r->headers_out.content_length_n);

        h3c->payload_bytes += r->headers_out.content_length_n;
        h3c->total_bytes += r->headers_out.content_length_n;

        cl = njt_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NJT_ERROR;
        }

        cl->buf = b;
        cl->next = NULL;

        *ll = cl;

    } else {
        ctx = njt_pcalloc(r->pool, sizeof(njt_http_v3_filter_ctx_t));
        if (ctx == NULL) {
            return NJT_ERROR;
        }

        njt_http_set_ctx(r, ctx, njt_http_v3_filter_module);
    }

    for (cl = out; cl; cl = cl->next) {
        h3c->total_bytes += cl->buf->last - cl->buf->pos;
        r->header_size += cl->buf->last - cl->buf->pos;
    }

    return njt_http_write_filter(r, out);
}


static njt_int_t
njt_http_v3_body_filter(njt_http_request_t *r, njt_chain_t *in)
{
    u_char                    *chunk;
    off_t                      size;
    njt_int_t                  rc;
    njt_buf_t                 *b;
    njt_chain_t               *out, *cl, *tl, **ll;
    njt_http_v3_session_t     *h3c;
    njt_http_v3_filter_ctx_t  *ctx;

    if (in == NULL) {
        return njt_http_next_body_filter(r, in);
    }

    ctx = njt_http_get_module_ctx(r, njt_http_v3_filter_module);
    if (ctx == NULL) {
        return njt_http_next_body_filter(r, in);
    }

    h3c = njt_http_v3_get_session(r->connection);

    out = NULL;
    ll = &out;

    size = 0;
    cl = in;

    for ( ;; ) {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http3 chunk: %O", njt_buf_size(cl->buf));

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
            chunk = njt_palloc(r->pool, NJT_HTTP_V3_VARLEN_INT_LEN * 2);
            if (chunk == NULL) {
                return NJT_ERROR;
            }

            b->start = chunk;
            b->end = chunk + NJT_HTTP_V3_VARLEN_INT_LEN * 2;
        }

        b->tag = (njt_buf_tag_t) &njt_http_v3_filter_module;
        b->memory = 0;
        b->temporary = 1;
        b->pos = chunk;

        b->last = (u_char *) njt_http_v3_encode_varlen_int(chunk,
                                                       NJT_HTTP_V3_FRAME_DATA);
        b->last = (u_char *) njt_http_v3_encode_varlen_int(b->last, size);

        tl->next = out;
        out = tl;

        h3c->payload_bytes += size;
    }

    if (cl->buf->last_buf) {
        tl = njt_http_v3_create_trailers(r, ctx);
        if (tl == NULL) {
            return NJT_ERROR;
        }

        cl->buf->last_buf = 0;

        *ll = tl;

    } else {
        *ll = NULL;
    }

    for (cl = out; cl; cl = cl->next) {
        h3c->total_bytes += cl->buf->last - cl->buf->pos;
    }

    rc = njt_http_next_body_filter(r, out);

    njt_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
                            (njt_buf_tag_t) &njt_http_v3_filter_module);

    return rc;
}


static njt_chain_t *
njt_http_v3_create_trailers(njt_http_request_t *r,
    njt_http_v3_filter_ctx_t *ctx)
{
    size_t                  len, n;
    u_char                 *p;
    njt_buf_t              *b;
    njt_uint_t              i;
    njt_chain_t            *cl, *hl;
    njt_list_part_t        *part;
    njt_table_elt_t        *header;
    njt_http_v3_session_t  *h3c;

    h3c = njt_http_v3_get_session(r->connection);

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

        len += njt_http_v3_encode_field_l(NULL, &header[i].key,
                                          &header[i].value);
    }

    cl = njt_chain_get_free_buf(r->pool, &ctx->free);
    if (cl == NULL) {
        return NULL;
    }

    b = cl->buf;

    b->tag = (njt_buf_tag_t) &njt_http_v3_filter_module;
    b->memory = 0;
    b->last_buf = 1;

    if (len == 0) {
        b->temporary = 0;
        b->pos = b->last = NULL;
        return cl;
    }

    b->temporary = 1;

    len += njt_http_v3_encode_field_section_prefix(NULL, 0, 0, 0);

    b->pos = njt_palloc(r->pool, len);
    if (b->pos == NULL) {
        return NULL;
    }

    b->last = (u_char *) njt_http_v3_encode_field_section_prefix(b->pos,
                                                                 0, 0, 0);

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
                       "http3 output trailer: \"%V: %V\"",
                       &header[i].key, &header[i].value);

        b->last = (u_char *) njt_http_v3_encode_field_l(b->last,
                                                        &header[i].key,
                                                        &header[i].value);
    }

    n = b->last - b->pos;

    h3c->payload_bytes += n;

    hl = njt_chain_get_free_buf(r->pool, &ctx->free);
    if (hl == NULL) {
        return NULL;
    }

    b = hl->buf;
    p = b->start;

    if (p == NULL) {
        p = njt_palloc(r->pool, NJT_HTTP_V3_VARLEN_INT_LEN * 2);
        if (p == NULL) {
            return NULL;
        }

        b->start = p;
        b->end = p + NJT_HTTP_V3_VARLEN_INT_LEN * 2;
    }

    b->tag = (njt_buf_tag_t) &njt_http_v3_filter_module;
    b->memory = 0;
    b->temporary = 1;
    b->pos = p;

    b->last = (u_char *) njt_http_v3_encode_varlen_int(p,
                                                    NJT_HTTP_V3_FRAME_HEADERS);
    b->last = (u_char *) njt_http_v3_encode_varlen_int(b->last, n);

    hl->next = cl;

    return hl;
}


static njt_int_t
njt_http_v3_filter_init(njt_conf_t *cf)
{
    njt_http_next_header_filter = njt_http_top_header_filter;
    njt_http_top_header_filter = njt_http_v3_header_filter;

    njt_http_next_body_filter = njt_http_top_body_filter;
    njt_http_top_body_filter = njt_http_v3_body_filter;

    return NJT_OK;
}
