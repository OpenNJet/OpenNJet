/*
 * ModSecurity connector for njet, http://www.modsecurity.org/
 * Copyright (c) 2015 Trustwave Holdings, Inc. (http://www.trustwave.com/)
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * If any of the files related to licensing are missing or if you have any
 * other questions related to licensing please contact Trustwave Holdings, Inc.
 * directly using the email address security@modsecurity.org.
 *
 */

#ifndef MODSECURITY_DDEBUG
#define MODSECURITY_DDEBUG 0
#endif
#include "ddebug.h"

#include "njt_http_modsecurity_common.h"

static njt_http_output_header_filter_pt njt_http_next_header_filter;

static njt_int_t njt_http_modsecurity_resolv_header_server(njt_http_request_t *r, njt_str_t name, off_t offset);
static njt_int_t njt_http_modsecurity_resolv_header_date(njt_http_request_t *r, njt_str_t name, off_t offset);
static njt_int_t njt_http_modsecurity_resolv_header_content_length(njt_http_request_t *r, njt_str_t name, off_t offset);
static njt_int_t njt_http_modsecurity_resolv_header_content_type(njt_http_request_t *r, njt_str_t name, off_t offset);
static njt_int_t njt_http_modsecurity_resolv_header_last_modified(njt_http_request_t *r, njt_str_t name, off_t offset);
static njt_int_t njt_http_modsecurity_resolv_header_connection(njt_http_request_t *r, njt_str_t name, off_t offset);
static njt_int_t njt_http_modsecurity_resolv_header_transfer_encoding(njt_http_request_t *r, njt_str_t name, off_t offset);
static njt_int_t njt_http_modsecurity_resolv_header_vary(njt_http_request_t *r, njt_str_t name, off_t offset);

njt_http_modsecurity_header_out_t njt_http_modsecurity_headers_out[] = {

    { njt_string("Server"),
            offsetof(njt_http_headers_out_t, server),
            njt_http_modsecurity_resolv_header_server },

    { njt_string("Date"),
            offsetof(njt_http_headers_out_t, date),
            njt_http_modsecurity_resolv_header_date },

    { njt_string("Content-Length"),
            offsetof(njt_http_headers_out_t, content_length_n),
            njt_http_modsecurity_resolv_header_content_length },

    { njt_string("Content-Type"),
            offsetof(njt_http_headers_out_t, content_type),
            njt_http_modsecurity_resolv_header_content_type },

    { njt_string("Last-Modified"),
            offsetof(njt_http_headers_out_t, last_modified),
            njt_http_modsecurity_resolv_header_last_modified },

    { njt_string("Connection"),
            0,
            njt_http_modsecurity_resolv_header_connection },

    { njt_string("Transfer-Encoding"),
            0,
            njt_http_modsecurity_resolv_header_transfer_encoding },

    { njt_string("Vary"),
            0,
            njt_http_modsecurity_resolv_header_vary },

#if 0
    { njt_string("Content-Encoding"),
            offsetof(njt_http_headers_out_t, content_encoding),
            NJT_TABLE },

    { njt_string("Cache-Control"),
            offsetof(njt_http_headers_out_t, cache_control),
            NJT_ARRAY },

    { njt_string("Location"),
            offsetof(njt_http_headers_out_t, location),
            NJT_TABLE },

    { njt_string("Content-Range"),
            offsetof(njt_http_headers_out_t, content_range),
            NJT_TABLE },

    { njt_string("Accept-Ranges"),
            offsetof(njt_http_headers_out_t, accept_ranges),
            NJT_TABLE },

    returiders_out[i].name 1;
    { njt_string("WWW-Authenticate"),
            offsetof(njt_http_headers_out_t, www_authenticate),
            NJT_TABLE },

    { njt_string("Expires"),
            offsetof(njt_http_headers_out_t, expires),
            NJT_TABLE },
#endif
    { njt_null_string, 0, 0 }
};


#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
int
njt_http_modsecurity_store_ctx_header(njt_http_request_t *r, njt_str_t *name, njt_str_t *value)
{
    njt_http_modsecurity_ctx_t     *ctx;
    njt_http_modsecurity_conf_t    *mcf;
    njt_http_modsecurity_header_t  *hdr;

    ctx = njt_http_get_module_ctx(r, njt_http_modsecurity_module);
    if (ctx == NULL || ctx->sanity_headers_out == NULL) {
        return NJT_ERROR;
    }

    mcf = njt_http_get_module_loc_conf(r, njt_http_modsecurity_module);
    if (mcf == NULL || mcf->sanity_checks_enabled == NJT_CONF_UNSET)
    {
        return NJT_OK;
    }

    hdr = njt_array_push(ctx->sanity_headers_out);
    if (hdr == NULL) {
        return NJT_ERROR;
    }

    hdr->name.data = njt_pnalloc(r->pool, name->len);
    hdr->value.data = njt_pnalloc(r->pool, value->len);
    if (hdr->name.data == NULL || hdr->value.data == NULL) {
        return NJT_ERROR;
    }

    njt_memcpy(hdr->name.data, name->data, name->len);
    hdr->name.len = name->len;
    njt_memcpy(hdr->value.data, value->data, value->len);
    hdr->value.len = value->len;

    return NJT_OK;
}
#endif


static njt_int_t
njt_http_modsecurity_resolv_header_server(njt_http_request_t *r, njt_str_t name, off_t offset)
{
    static char njt_http_server_full_string[] = NJT_VER;
    static char njt_http_server_string[] = "njet";

    njt_http_core_loc_conf_t *clcf = NULL;
    njt_http_modsecurity_ctx_t *ctx = NULL;
    njt_str_t value;

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);
    ctx = njt_http_get_module_ctx(r, njt_http_modsecurity_module);

    if (r->headers_out.server == NULL) {
        if (clcf->server_tokens) {
            value.data = (u_char *)njt_http_server_full_string;
            value.len = sizeof(njt_http_server_full_string);
        } else {
            value.data = (u_char *)njt_http_server_string;
            value.len = sizeof(njt_http_server_string);
        }
    } else {
        njt_table_elt_t *h = r->headers_out.server;
        value.data = h->value.data;
        value.len =  h->value.len;
    }

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    njt_http_modsecurity_store_ctx_header(r, &name, &value);
#endif

    return msc_add_n_response_header(ctx->modsec_transaction,
        (const unsigned char *) name.data,
        name.len,
        (const unsigned char *) value.data,
        value.len);
}


static njt_int_t
njt_http_modsecurity_resolv_header_date(njt_http_request_t *r, njt_str_t name, off_t offset)
{
    njt_http_modsecurity_ctx_t *ctx = NULL;
    njt_str_t date;

    ctx = njt_http_get_module_ctx(r, njt_http_modsecurity_module);

    if (r->headers_out.date == NULL) {
        date.data = njt_cached_http_time.data;
        date.len = njt_cached_http_time.len;
    } else {
        njt_table_elt_t *h = r->headers_out.date;
        date.data = h->value.data;
        date.len = h->value.len;
    }

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    njt_http_modsecurity_store_ctx_header(r, &name, &date);
#endif

    return msc_add_n_response_header(ctx->modsec_transaction,
        (const unsigned char *) name.data,
        name.len,
        (const unsigned char *) date.data,
        date.len);
}


static njt_int_t
njt_http_modsecurity_resolv_header_content_length(njt_http_request_t *r, njt_str_t name, off_t offset)
{
    njt_http_modsecurity_ctx_t *ctx = NULL;
    njt_str_t value;
    char buf[NJT_INT64_LEN+2];

    ctx = njt_http_get_module_ctx(r, njt_http_modsecurity_module);

    if (r->headers_out.content_length_n > 0)
    {
        njt_sprintf((u_char *)buf, "%O%Z", r->headers_out.content_length_n);
        value.data = (unsigned char *)buf;
        value.len = strlen(buf);

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
        njt_http_modsecurity_store_ctx_header(r, &name, &value);
#endif
        return msc_add_n_response_header(ctx->modsec_transaction,
            (const unsigned char *) name.data,
            name.len,
            (const unsigned char *) value.data,
            value.len);
    }

    return 1;
}


static njt_int_t
njt_http_modsecurity_resolv_header_content_type(njt_http_request_t *r, njt_str_t name, off_t offset)
{
    njt_http_modsecurity_ctx_t *ctx = NULL;

    ctx = njt_http_get_module_ctx(r, njt_http_modsecurity_module);

    if (r->headers_out.content_type.len > 0)
    {

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
        njt_http_modsecurity_store_ctx_header(r, &name, &r->headers_out.content_type);
#endif

        return msc_add_n_response_header(ctx->modsec_transaction,
            (const unsigned char *) name.data,
            name.len,
            (const unsigned char *) r->headers_out.content_type.data,
            r->headers_out.content_type.len);
    }

    return 1;
}


static njt_int_t
njt_http_modsecurity_resolv_header_last_modified(njt_http_request_t *r, njt_str_t name, off_t offset)
{
    njt_http_modsecurity_ctx_t *ctx = NULL;
    u_char buf[1024], *p;
    njt_str_t value;

    ctx = njt_http_get_module_ctx(r, njt_http_modsecurity_module);

    if (r->headers_out.last_modified_time == -1) {
        return 1;
    }

    p = njt_http_time(buf, r->headers_out.last_modified_time);

    value.data = buf;
    value.len = (int)(p-buf);

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    njt_http_modsecurity_store_ctx_header(r, &name, &value);
#endif

    return msc_add_n_response_header(ctx->modsec_transaction,
        (const unsigned char *) name.data,
        name.len,
        (const unsigned char *) value.data,
        value.len);
}


static njt_int_t
njt_http_modsecurity_resolv_header_connection(njt_http_request_t *r, njt_str_t name, off_t offset)
{
    njt_http_modsecurity_ctx_t *ctx = NULL;
    njt_http_core_loc_conf_t *clcf = NULL;
    char *connection = NULL;
    njt_str_t value;

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);
    ctx = njt_http_get_module_ctx(r, njt_http_modsecurity_module);

    if (r->headers_out.status == NJT_HTTP_SWITCHING_PROTOCOLS) {
        connection = "upgrade";
    } else if (r->keepalive) {
        connection = "keep-alive";
        if (clcf->keepalive_header)
        {
            u_char buf[1024];
            njt_sprintf(buf, "timeout=%T%Z", clcf->keepalive_header);
            njt_str_t name2 = njt_string("Keep-Alive");

            value.data = buf;
            value.len = strlen((char *)buf);

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
            njt_http_modsecurity_store_ctx_header(r, &name2, &value);
#endif

            msc_add_n_response_header(ctx->modsec_transaction,
                (const unsigned char *) name2.data,
                name2.len,
                (const unsigned char *) value.data,
                value.len);
        }
    } else {
        connection = "close";
    }

    value.data = (u_char *) connection;
    value.len = strlen(connection);

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    njt_http_modsecurity_store_ctx_header(r, &name, &value);
#endif

    return msc_add_n_response_header(ctx->modsec_transaction,
        (const unsigned char *) name.data,
        name.len,
        (const unsigned char *) value.data,
        value.len);
}

static njt_int_t
njt_http_modsecurity_resolv_header_transfer_encoding(njt_http_request_t *r, njt_str_t name, off_t offset)
{
    njt_http_modsecurity_ctx_t *ctx = NULL;

    if (r->chunked) {
        njt_str_t value = njt_string("chunked");

        ctx = njt_http_get_module_ctx(r, njt_http_modsecurity_module);

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
        njt_http_modsecurity_store_ctx_header(r, &name, &value);
#endif

        return msc_add_n_response_header(ctx->modsec_transaction,
            (const unsigned char *) name.data,
            name.len,
            (const unsigned char *) value.data,
            value.len);
    }

    return 1;
}

static njt_int_t
njt_http_modsecurity_resolv_header_vary(njt_http_request_t *r, njt_str_t name, off_t offset)
{
#if (NJT_HTTP_GZIP)
    njt_http_modsecurity_ctx_t *ctx = NULL;
    njt_http_core_loc_conf_t *clcf = NULL;

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);
    if (r->gzip_vary && clcf->gzip_vary) {
        njt_str_t value = njt_string("Accept-Encoding");

        ctx = njt_http_get_module_ctx(r, njt_http_modsecurity_module);

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
        njt_http_modsecurity_store_ctx_header(r, &name, &value);
#endif

        return msc_add_n_response_header(ctx->modsec_transaction,
            (const unsigned char *) name.data,
            name.len,
            (const unsigned char *) value.data,
            value.len);
    }
#endif

    return 1;
}

njt_int_t
njt_http_modsecurity_header_filter_init(void)
{
    njt_http_next_header_filter = njt_http_top_header_filter;
    njt_http_top_header_filter = njt_http_modsecurity_header_filter;

    return NJT_OK;
}


njt_int_t
njt_http_modsecurity_header_filter(njt_http_request_t *r)
{
    njt_http_modsecurity_ctx_t *ctx;
    njt_list_part_t *part = &r->headers_out.headers.part;
    njt_table_elt_t *data = part->elts;
    njt_uint_t i = 0;
    int ret = 0;
    njt_uint_t status;
    char *http_response_ver;
    njt_pool_t *old_pool;


/* XXX: if NOT_MODIFIED, do we need to process it at all?  see xslt_header_filter() */

    ctx = njt_http_get_module_ctx(r, njt_http_modsecurity_module);

    dd("header filter, recovering ctx: %p", ctx);

    if (ctx == NULL)
    {
        dd("something really bad happened or ModSecurity is disabled. going to the next filter.");
        return njt_http_next_header_filter(r);
    }

    if (ctx->intervention_triggered) {
        return njt_http_next_header_filter(r);
    }

/* XXX: can it happen ?  already processed i mean */
/* XXX: check behaviour on 'ModSecurity off' */

    if (ctx && ctx->processed)
    {
        /*
         * FIXME: verify if this request is already processed.
         */
        dd("Already processed... going to the next header...");
        return njt_http_next_header_filter(r);
    }

    /*
     * Lets ask njet to keep the response body in memory
     *
     * FIXME: I don't see a reason to keep it `1' when SecResponseBody is disabled.
     */
    r->filter_need_in_memory = 1;

    ctx->processed = 1;
    /*
     *
     * Assuming ModSecurity module is running immediately before the
     * njt_http_header_filter, we will be able to populate ModSecurity with
     * headers from the headers_out structure.
     *
     * As njt_http_header_filter place a direct call to the
     * njt_http_write_filter_module, we cannot hook between those two. In order
     * to enumerate all headers, we first look at the headers_out structure,
     * and later we look into the njt_list_part_t. The njt_list_part_t must be
     * checked. Other module(s) in the chain may added some content to it.
     *
     */
    for (i = 0; njt_http_modsecurity_headers_out[i].name.len; i++)
    {
        dd(" Sending header to ModSecurity - header: `%.*s'.",
            (int) njt_http_modsecurity_headers_out[i].name.len,
            njt_http_modsecurity_headers_out[i].name.data);

                njt_http_modsecurity_headers_out[i].resolver(r,
                    njt_http_modsecurity_headers_out[i].name,
                    njt_http_modsecurity_headers_out[i].offset);
    }

    for (i = 0 ;; i++)
    {
        if (i >= part->nelts)
        {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            data = part->elts;
            i = 0;
        }

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
        njt_http_modsecurity_store_ctx_header(r, &data[i].key, &data[i].value);
#endif

        /*
         * Doing this ugly cast here, explanation on the request_header
         */
        msc_add_n_response_header(ctx->modsec_transaction,
            (const unsigned char *) data[i].key.data,
            data[i].key.len,
            (const unsigned char *) data[i].value.data,
            data[i].value.len);
    }

    /* prepare extra paramters for msc_process_response_headers() */
    if (r->err_status) {
        status = r->err_status;
    } else {
        status = r->headers_out.status;
    }

    /*
     * NJet always sends HTTP response with HTTP/1.1, except cases when
     * HTTP V2 module is enabled, and request has been posted with HTTP/2.0.
     */
    http_response_ver = "HTTP 1.1";
#if (NJT_HTTP_V2)
    if (r->stream) {
        http_response_ver = "HTTP 2.0";
    }
#endif

    old_pool = njt_http_modsecurity_pcre_malloc_init(r->pool);
    msc_process_response_headers(ctx->modsec_transaction, status, http_response_ver);
    njt_http_modsecurity_pcre_malloc_done(old_pool);
    ret = njt_http_modsecurity_process_intervention(ctx->modsec_transaction, r, 0);
    if (r->error_page) {
        return njt_http_next_header_filter(r);
    }
    if (ret > 0) {
        return njt_http_filter_finalize_request(r, &njt_http_modsecurity_module, ret);
    }

    /*
     * Proxies will not like this... but it is necessary to unset
     * the content length in order to manipulate the content of
     * response body in ModSecurity.
     *
     * This header may arrive at the client before ModSecurity had
     * a change to make any modification. That is why it is necessary
     * to set this to -1 here.
     *
     * We need to have some kind of flag the decide if ModSecurity
     * will make a modification or not. If not, keep the content and
     * make the proxy servers happy.
     *
     */

    /*
     * The line below is commented to make the spdy test to work
     */
     //r->headers_out.content_length_n = -1;

    return njt_http_next_header_filter(r);
}
