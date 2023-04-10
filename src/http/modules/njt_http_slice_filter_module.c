
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>

//by chengxu
#if (NJT_HTTP_CACHE_PURGE)
#else
typedef struct {
    size_t               size;
} njt_http_slice_loc_conf_t;
#endif
// end



typedef struct {
    off_t                start;
    off_t                end;
    njt_str_t            range;
    njt_str_t            etag;
    unsigned             last:1;
    unsigned             active:1;
    njt_http_request_t  *sr;
} njt_http_slice_ctx_t;


typedef struct {
    off_t                start;
    off_t                end;
    off_t                complete_length;
} njt_http_slice_content_range_t;


static njt_int_t njt_http_slice_header_filter(njt_http_request_t *r);
static njt_int_t njt_http_slice_body_filter(njt_http_request_t *r,
    njt_chain_t *in);
static njt_int_t njt_http_slice_parse_content_range(njt_http_request_t *r,
    njt_http_slice_content_range_t *cr);
static njt_int_t njt_http_slice_range_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static off_t njt_http_slice_get_start(njt_http_request_t *r);
static void *njt_http_slice_create_loc_conf(njt_conf_t *cf);
static char *njt_http_slice_merge_loc_conf(njt_conf_t *cf, void *parent,
    void *child);
static njt_int_t njt_http_slice_add_variables(njt_conf_t *cf);
static njt_int_t njt_http_slice_init(njt_conf_t *cf);


static njt_command_t  njt_http_slice_filter_commands[] = {

    { njt_string("slice"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_slice_loc_conf_t, size),
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_slice_filter_module_ctx = {
    njt_http_slice_add_variables,          /* preconfiguration */
    njt_http_slice_init,                   /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_slice_create_loc_conf,        /* create location configuration */
    njt_http_slice_merge_loc_conf          /* merge location configuration */
};


njt_module_t  njt_http_slice_filter_module = {
    NJT_MODULE_V1,
    &njt_http_slice_filter_module_ctx,     /* module context */
    njt_http_slice_filter_commands,        /* module directives */
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


static njt_str_t  njt_http_slice_range_name = njt_string("slice_range");

static njt_http_output_header_filter_pt  njt_http_next_header_filter;
static njt_http_output_body_filter_pt    njt_http_next_body_filter;


static njt_int_t
njt_http_slice_header_filter(njt_http_request_t *r)
{
    off_t                            end;
    njt_int_t                        rc;
    njt_table_elt_t                 *h;
    njt_http_slice_ctx_t            *ctx;
    njt_http_slice_loc_conf_t       *slcf;
    njt_http_slice_content_range_t   cr;

    ctx = njt_http_get_module_ctx(r, njt_http_slice_filter_module);
    if (ctx == NULL) {
        return njt_http_next_header_filter(r);
    }

    if (r->headers_out.status != NJT_HTTP_PARTIAL_CONTENT) {
        if (r == r->main) {
            njt_http_set_ctx(r, NULL, njt_http_slice_filter_module);
            return njt_http_next_header_filter(r);
        }

        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "unexpected status code %ui in slice response",
                      r->headers_out.status);
        return NJT_ERROR;
    }

    h = r->headers_out.etag;

    if (ctx->etag.len) {
        if (h == NULL
            || h->value.len != ctx->etag.len
            || njt_strncmp(h->value.data, ctx->etag.data, ctx->etag.len)
               != 0)
        {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "etag mismatch in slice response");
            return NJT_ERROR;
        }
    }

    if (h) {
        ctx->etag = h->value;
    }

    if (njt_http_slice_parse_content_range(r, &cr) != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "invalid range in slice response");
        return NJT_ERROR;
    }

    if (cr.complete_length == -1) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "no complete length in slice response");
        return NJT_ERROR;
    }

    njt_log_debug3(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http slice response range: %O-%O/%O",
                   cr.start, cr.end, cr.complete_length);

    slcf = njt_http_get_module_loc_conf(r, njt_http_slice_filter_module);

    end = njt_min(cr.start + (off_t) slcf->size, cr.complete_length);

    if (cr.start != ctx->start || cr.end != end) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "unexpected range in slice response: %O-%O",
                      cr.start, cr.end);
        return NJT_ERROR;
    }

    ctx->start = end;
    ctx->active = 1;

    r->headers_out.status = NJT_HTTP_OK;
    r->headers_out.status_line.len = 0;
    r->headers_out.content_length_n = cr.complete_length;
    r->headers_out.content_offset = cr.start;
    r->headers_out.content_range->hash = 0;
    r->headers_out.content_range = NULL;

    if (r->headers_out.accept_ranges) {
        r->headers_out.accept_ranges->hash = 0;
        r->headers_out.accept_ranges = NULL;
    }

    r->allow_ranges = 1;
    r->subrequest_ranges = 1;
    r->single_range = 1;

    rc = njt_http_next_header_filter(r);

    if (r != r->main) {
        return rc;
    }

    r->preserve_body = 1;

    if (r->headers_out.status == NJT_HTTP_PARTIAL_CONTENT) {
        if (ctx->start + (off_t) slcf->size <= r->headers_out.content_offset) {
            ctx->start = slcf->size
                         * (r->headers_out.content_offset / slcf->size);
        }

        ctx->end = r->headers_out.content_offset
                   + r->headers_out.content_length_n;

    } else {
        ctx->end = cr.complete_length;
    }

    return rc;
}


static njt_int_t
njt_http_slice_body_filter(njt_http_request_t *r, njt_chain_t *in)
{
    njt_int_t                   rc;
    njt_chain_t                *cl;
    njt_http_slice_ctx_t       *ctx;
    njt_http_slice_loc_conf_t  *slcf;

    ctx = njt_http_get_module_ctx(r, njt_http_slice_filter_module);

    if (ctx == NULL || r != r->main) {
        return njt_http_next_body_filter(r, in);
    }

    for (cl = in; cl; cl = cl->next) {
        if (cl->buf->last_buf) {
            cl->buf->last_buf = 0;
            cl->buf->last_in_chain = 1;
            cl->buf->sync = 1;
            ctx->last = 1;
        }
    }

    rc = njt_http_next_body_filter(r, in);

    if (rc == NJT_ERROR || !ctx->last) {
        return rc;
    }

    if (ctx->sr && !ctx->sr->done) {
        return rc;
    }

    if (!ctx->active) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "missing slice response");
        return NJT_ERROR;
    }

    if (ctx->start >= ctx->end) {
        njt_http_set_ctx(r, NULL, njt_http_slice_filter_module);
        njt_http_send_special(r, NJT_HTTP_LAST);
        return rc;
    }

    if (r->buffered) {
        return rc;
    }

    if (njt_http_subrequest(r, &r->uri, &r->args, &ctx->sr, NULL,
                            NJT_HTTP_SUBREQUEST_CLONE)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    njt_http_set_ctx(ctx->sr, ctx, njt_http_slice_filter_module);

    slcf = njt_http_get_module_loc_conf(r, njt_http_slice_filter_module);

    ctx->range.len = njt_sprintf(ctx->range.data, "bytes=%O-%O", ctx->start,
                                 ctx->start + (off_t) slcf->size - 1)
                     - ctx->range.data;

    ctx->active = 0;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http slice subrequest: \"%V\"", &ctx->range);

    return rc;
}


static njt_int_t
njt_http_slice_parse_content_range(njt_http_request_t *r,
    njt_http_slice_content_range_t *cr)
{
    off_t             start, end, complete_length, cutoff, cutlim;
    u_char           *p;
    njt_table_elt_t  *h;

    h = r->headers_out.content_range;

    if (h == NULL
        || h->value.len < 7
        || njt_strncmp(h->value.data, "bytes ", 6) != 0)
    {
        return NJT_ERROR;
    }

    p = h->value.data + 6;

    cutoff = NJT_MAX_OFF_T_VALUE / 10;
    cutlim = NJT_MAX_OFF_T_VALUE % 10;

    start = 0;
    end = 0;
    complete_length = 0;

    while (*p == ' ') { p++; }

    if (*p < '0' || *p > '9') {
        return NJT_ERROR;
    }

    while (*p >= '0' && *p <= '9') {
        if (start >= cutoff && (start > cutoff || *p - '0' > cutlim)) {
            return NJT_ERROR;
        }

        start = start * 10 + (*p++ - '0');
    }

    while (*p == ' ') { p++; }

    if (*p++ != '-') {
        return NJT_ERROR;
    }

    while (*p == ' ') { p++; }

    if (*p < '0' || *p > '9') {
        return NJT_ERROR;
    }

    while (*p >= '0' && *p <= '9') {
        if (end >= cutoff && (end > cutoff || *p - '0' > cutlim)) {
            return NJT_ERROR;
        }

        end = end * 10 + (*p++ - '0');
    }

    end++;

    while (*p == ' ') { p++; }

    if (*p++ != '/') {
        return NJT_ERROR;
    }

    while (*p == ' ') { p++; }

    if (*p != '*') {
        if (*p < '0' || *p > '9') {
            return NJT_ERROR;
        }

        while (*p >= '0' && *p <= '9') {
            if (complete_length >= cutoff
                && (complete_length > cutoff || *p - '0' > cutlim))
            {
                return NJT_ERROR;
            }

            complete_length = complete_length * 10 + (*p++ - '0');
        }

    } else {
        complete_length = -1;
        p++;
    }

    while (*p == ' ') { p++; }

    if (*p != '\0') {
        return NJT_ERROR;
    }

    cr->start = start;
    cr->end = end;
    cr->complete_length = complete_length;

    return NJT_OK;
}


static njt_int_t
njt_http_slice_range_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    njt_http_slice_ctx_t       *ctx;
    njt_http_slice_loc_conf_t  *slcf;

    ctx = njt_http_get_module_ctx(r, njt_http_slice_filter_module);

    if (ctx == NULL) {
        if (r != r->main || r->headers_out.status) {
            v->not_found = 1;
            return NJT_OK;
        }

        slcf = njt_http_get_module_loc_conf(r, njt_http_slice_filter_module);

        if (slcf->size == 0) {
            v->not_found = 1;
            return NJT_OK;
        }

        ctx = njt_pcalloc(r->pool, sizeof(njt_http_slice_ctx_t));
        if (ctx == NULL) {
            return NJT_ERROR;
        }

        njt_http_set_ctx(r, ctx, njt_http_slice_filter_module);

        p = njt_pnalloc(r->pool, sizeof("bytes=-") - 1 + 2 * NJT_OFF_T_LEN);
        if (p == NULL) {
            return NJT_ERROR;
        }

        ctx->start = slcf->size * (njt_http_slice_get_start(r) / slcf->size);

        ctx->range.data = p;
        ctx->range.len = njt_sprintf(p, "bytes=%O-%O", ctx->start,
                                     ctx->start + (off_t) slcf->size - 1)
                         - p;
    }

    v->data = ctx->range.data;
    v->valid = 1;
    v->not_found = 0;
    v->no_cacheable = 1;
    v->len = ctx->range.len;

    return NJT_OK;
}


static off_t
njt_http_slice_get_start(njt_http_request_t *r)
{
    off_t             start, cutoff, cutlim;
    u_char           *p;
    njt_table_elt_t  *h;

    if (r->headers_in.if_range) {
        return 0;
    }

    h = r->headers_in.range;

    if (h == NULL
        || h->value.len < 7
        || njt_strncasecmp(h->value.data, (u_char *) "bytes=", 6) != 0)
    {
        return 0;
    }

    p = h->value.data + 6;

    if (njt_strchr(p, ',')) {
        return 0;
    }

    while (*p == ' ') { p++; }

    if (*p == '-') {
        return 0;
    }

    cutoff = NJT_MAX_OFF_T_VALUE / 10;
    cutlim = NJT_MAX_OFF_T_VALUE % 10;

    start = 0;

    while (*p >= '0' && *p <= '9') {
        if (start >= cutoff && (start > cutoff || *p - '0' > cutlim)) {
            return 0;
        }

        start = start * 10 + (*p++ - '0');
    }

    return start;
}


static void *
njt_http_slice_create_loc_conf(njt_conf_t *cf)
{
    njt_http_slice_loc_conf_t  *slcf;

    slcf = njt_palloc(cf->pool, sizeof(njt_http_slice_loc_conf_t));
    if (slcf == NULL) {
        return NULL;
    }

    slcf->size = NJT_CONF_UNSET_SIZE;

    return slcf;
}


static char *
njt_http_slice_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_slice_loc_conf_t *prev = parent;
    njt_http_slice_loc_conf_t *conf = child;

    njt_conf_merge_size_value(conf->size, prev->size, 0);

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_slice_add_variables(njt_conf_t *cf)
{
    njt_http_variable_t  *var;

    var = njt_http_add_variable(cf, &njt_http_slice_range_name, 0);
    if (var == NULL) {
        return NJT_ERROR;
    }

    var->get_handler = njt_http_slice_range_variable;

    return NJT_OK;
}


static njt_int_t
njt_http_slice_init(njt_conf_t *cf)
{
    njt_http_next_header_filter = njt_http_top_header_filter;
    njt_http_top_header_filter = njt_http_slice_header_filter;

    njt_http_next_body_filter = njt_http_top_body_filter;
    njt_http_top_body_filter = njt_http_slice_body_filter;

    return NJT_OK;
}
