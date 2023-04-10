
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


static njt_int_t njt_http_postpone_filter_add(njt_http_request_t *r,
    njt_chain_t *in);
static njt_int_t njt_http_postpone_filter_in_memory(njt_http_request_t *r,
    njt_chain_t *in);
static njt_int_t njt_http_postpone_filter_init(njt_conf_t *cf);


static njt_http_module_t  njt_http_postpone_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_http_postpone_filter_init,         /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


njt_module_t  njt_http_postpone_filter_module = {
    NJT_MODULE_V1,
    &njt_http_postpone_filter_module_ctx,  /* module context */
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


static njt_http_output_body_filter_pt    njt_http_next_body_filter;


static njt_int_t
njt_http_postpone_filter(njt_http_request_t *r, njt_chain_t *in)
{
    njt_connection_t              *c;
    njt_http_postponed_request_t  *pr;

    c = r->connection;

    njt_log_debug3(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http postpone filter \"%V?%V\" %p", &r->uri, &r->args, in);

    if (r->subrequest_in_memory) {
        return njt_http_postpone_filter_in_memory(r, in);
    }

    if (r != c->data) {

        if (in) {
            if (njt_http_postpone_filter_add(r, in) != NJT_OK) {
                return NJT_ERROR;
            }

            return NJT_OK;
        }

#if 0
        /* TODO: SSI may pass NULL */
        njt_log_error(NJT_LOG_ALERT, c->log, 0,
                      "http postpone filter NULL inactive request");
#endif

        return NJT_OK;
    }

    if (r->postponed == NULL) {

        if (in || c->buffered) {
            return njt_http_next_body_filter(r->main, in);
        }

        return NJT_OK;
    }

    if (in) {
        if (njt_http_postpone_filter_add(r, in) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    do {
        pr = r->postponed;

        if (pr->request) {

            njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                           "http postpone filter wake \"%V?%V\"",
                           &pr->request->uri, &pr->request->args);

            r->postponed = pr->next;

            c->data = pr->request;

            return njt_http_post_request(pr->request, NULL);
        }

        if (pr->out == NULL) {
            njt_log_error(NJT_LOG_ALERT, c->log, 0,
                          "http postpone filter NULL output");

        } else {
            njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                           "http postpone filter output \"%V?%V\"",
                           &r->uri, &r->args);

            if (njt_http_next_body_filter(r->main, pr->out) == NJT_ERROR) {
                return NJT_ERROR;
            }
        }

        r->postponed = pr->next;

    } while (r->postponed);

    return NJT_OK;
}


static njt_int_t
njt_http_postpone_filter_add(njt_http_request_t *r, njt_chain_t *in)
{
    njt_http_postponed_request_t  *pr, **ppr;

    if (r->postponed) {
        for (pr = r->postponed; pr->next; pr = pr->next) { /* void */ }

        if (pr->request == NULL) {
            goto found;
        }

        ppr = &pr->next;

    } else {
        ppr = &r->postponed;
    }

    pr = njt_palloc(r->pool, sizeof(njt_http_postponed_request_t));
    if (pr == NULL) {
        return NJT_ERROR;
    }

    *ppr = pr;

    pr->request = NULL;
    pr->out = NULL;
    pr->next = NULL;

found:

    if (njt_chain_add_copy(r->pool, &pr->out, in) == NJT_OK) {
        return NJT_OK;
    }

    return NJT_ERROR;
}


static njt_int_t
njt_http_postpone_filter_in_memory(njt_http_request_t *r, njt_chain_t *in)
{
    size_t                     len;
    njt_buf_t                 *b;
    njt_connection_t          *c;
    njt_http_core_loc_conf_t  *clcf;

    c = r->connection;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http postpone filter in memory");

    if (r->out == NULL) {
        clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

        if (r->headers_out.content_length_n != -1) {
            len = r->headers_out.content_length_n;

            if (len > clcf->subrequest_output_buffer_size) {
                njt_log_error(NJT_LOG_ERR, c->log, 0,
                              "too big subrequest response: %uz", len);
                return NJT_ERROR;
            }

        } else {
            len = clcf->subrequest_output_buffer_size;
        }

        b = njt_create_temp_buf(r->pool, len);
        if (b == NULL) {
            return NJT_ERROR;
        }

        b->last_buf = 1;

        r->out = njt_alloc_chain_link(r->pool);
        if (r->out == NULL) {
            return NJT_ERROR;
        }

        r->out->buf = b;
        r->out->next = NULL;
    }

    b = r->out->buf;

    for ( /* void */ ; in; in = in->next) {

        if (njt_buf_special(in->buf)) {
            continue;
        }

        len = in->buf->last - in->buf->pos;

        if (len > (size_t) (b->end - b->last)) {
            njt_log_error(NJT_LOG_ERR, c->log, 0,
                          "too big subrequest response");
            return NJT_ERROR;
        }

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http postpone filter in memory %uz bytes", len);

        b->last = njt_cpymem(b->last, in->buf->pos, len);
        in->buf->pos = in->buf->last;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_postpone_filter_init(njt_conf_t *cf)
{
    njt_http_next_body_filter = njt_http_top_body_filter;
    njt_http_top_body_filter = njt_http_postpone_filter;

    return NJT_OK;
}
