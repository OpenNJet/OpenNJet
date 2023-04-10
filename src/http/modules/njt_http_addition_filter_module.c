
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


typedef struct {
    njt_str_t     before_body;
    njt_str_t     after_body;

    njt_hash_t    types;
    njt_array_t  *types_keys;
} njt_http_addition_conf_t;


typedef struct {
    njt_uint_t    before_body_sent;
} njt_http_addition_ctx_t;


static void *njt_http_addition_create_conf(njt_conf_t *cf);
static char *njt_http_addition_merge_conf(njt_conf_t *cf, void *parent,
    void *child);
static njt_int_t njt_http_addition_filter_init(njt_conf_t *cf);


static njt_command_t  njt_http_addition_commands[] = {

    { njt_string("add_before_body"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_addition_conf_t, before_body),
      NULL },

    { njt_string("add_after_body"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_addition_conf_t, after_body),
      NULL },

    { njt_string("addition_types"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_http_types_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_addition_conf_t, types_keys),
      &njt_http_html_default_types[0] },

      njt_null_command
};


static njt_http_module_t  njt_http_addition_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_http_addition_filter_init,         /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_addition_create_conf,         /* create location configuration */
    njt_http_addition_merge_conf           /* merge location configuration */
};


njt_module_t  njt_http_addition_filter_module = {
    NJT_MODULE_V1,
    &njt_http_addition_filter_module_ctx,  /* module context */
    njt_http_addition_commands,            /* module directives */
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
njt_http_addition_header_filter(njt_http_request_t *r)
{
    njt_http_addition_ctx_t   *ctx;
    njt_http_addition_conf_t  *conf;

    if (r->headers_out.status != NJT_HTTP_OK || r != r->main) {
        return njt_http_next_header_filter(r);
    }

    conf = njt_http_get_module_loc_conf(r, njt_http_addition_filter_module);

    if (conf->before_body.len == 0 && conf->after_body.len == 0) {
        return njt_http_next_header_filter(r);
    }

    if (njt_http_test_content_type(r, &conf->types) == NULL) {
        return njt_http_next_header_filter(r);
    }

    ctx = njt_pcalloc(r->pool, sizeof(njt_http_addition_ctx_t));
    if (ctx == NULL) {
        return NJT_ERROR;
    }

    njt_http_set_ctx(r, ctx, njt_http_addition_filter_module);

    njt_http_clear_content_length(r);
    njt_http_clear_accept_ranges(r);
    njt_http_weak_etag(r);

    r->preserve_body = 1;

    return njt_http_next_header_filter(r);
}


static njt_int_t
njt_http_addition_body_filter(njt_http_request_t *r, njt_chain_t *in)
{
    njt_int_t                  rc;
    njt_uint_t                 last;
    njt_chain_t               *cl;
    njt_http_request_t        *sr;
    njt_http_addition_ctx_t   *ctx;
    njt_http_addition_conf_t  *conf;

    if (in == NULL || r->header_only) {
        return njt_http_next_body_filter(r, in);
    }

    ctx = njt_http_get_module_ctx(r, njt_http_addition_filter_module);

    if (ctx == NULL) {
        return njt_http_next_body_filter(r, in);
    }

    conf = njt_http_get_module_loc_conf(r, njt_http_addition_filter_module);

    if (!ctx->before_body_sent) {
        ctx->before_body_sent = 1;

        if (conf->before_body.len) {
            if (njt_http_subrequest(r, &conf->before_body, NULL, &sr, NULL, 0)
                != NJT_OK)
            {
                return NJT_ERROR;
            }
        }
    }

    if (conf->after_body.len == 0) {
        njt_http_set_ctx(r, NULL, njt_http_addition_filter_module);
        return njt_http_next_body_filter(r, in);
    }

    last = 0;

    for (cl = in; cl; cl = cl->next) {
        if (cl->buf->last_buf) {
            cl->buf->last_buf = 0;
            cl->buf->last_in_chain = 1;
            cl->buf->sync = 1;
            last = 1;
        }
    }

    rc = njt_http_next_body_filter(r, in);

    if (rc == NJT_ERROR || !last || conf->after_body.len == 0) {
        return rc;
    }

    if (njt_http_subrequest(r, &conf->after_body, NULL, &sr, NULL, 0)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    njt_http_set_ctx(r, NULL, njt_http_addition_filter_module);

    return njt_http_send_special(r, NJT_HTTP_LAST);
}


static njt_int_t
njt_http_addition_filter_init(njt_conf_t *cf)
{
    njt_http_next_header_filter = njt_http_top_header_filter;
    njt_http_top_header_filter = njt_http_addition_header_filter;

    njt_http_next_body_filter = njt_http_top_body_filter;
    njt_http_top_body_filter = njt_http_addition_body_filter;

    return NJT_OK;
}


static void *
njt_http_addition_create_conf(njt_conf_t *cf)
{
    njt_http_addition_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_addition_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->before_body = { 0, NULL };
     *     conf->after_body = { 0, NULL };
     *     conf->types = { NULL };
     *     conf->types_keys = NULL;
     */

    return conf;
}


static char *
njt_http_addition_merge_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_addition_conf_t *prev = parent;
    njt_http_addition_conf_t *conf = child;

    njt_conf_merge_str_value(conf->before_body, prev->before_body, "");
    njt_conf_merge_str_value(conf->after_body, prev->after_body, "");

    if (njt_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             njt_http_html_default_types)
        != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}
