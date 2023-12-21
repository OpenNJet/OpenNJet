
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


static void njt_http_v3_init_request_stream(njt_connection_t *c);
static void njt_http_v3_wait_request_handler(njt_event_t *rev);
static void njt_http_v3_cleanup_connection(void *data);
static void njt_http_v3_cleanup_request(void *data);
static void njt_http_v3_process_request(njt_event_t *rev);
static njt_int_t njt_http_v3_process_header(njt_http_request_t *r,
    njt_str_t *name, njt_str_t *value);
static njt_int_t njt_http_v3_validate_header(njt_http_request_t *r,
    njt_str_t *name, njt_str_t *value);
static njt_int_t njt_http_v3_process_pseudo_header(njt_http_request_t *r,
    njt_str_t *name, njt_str_t *value);
static njt_int_t njt_http_v3_init_pseudo_headers(njt_http_request_t *r);
static njt_int_t njt_http_v3_process_request_header(njt_http_request_t *r);
static njt_int_t njt_http_v3_cookie(njt_http_request_t *r, njt_str_t *value);
static njt_int_t njt_http_v3_construct_cookie_header(njt_http_request_t *r);
static void njt_http_v3_read_client_request_body_handler(njt_http_request_t *r);
static njt_int_t njt_http_v3_do_read_client_request_body(njt_http_request_t *r);
static njt_int_t njt_http_v3_request_body_filter(njt_http_request_t *r,
    njt_chain_t *in);


static const struct {
    njt_str_t   name;
    njt_uint_t  method;
} njt_http_v3_methods[] = {

    { njt_string("GET"),       NJT_HTTP_GET },
    { njt_string("POST"),      NJT_HTTP_POST },
    { njt_string("HEAD"),      NJT_HTTP_HEAD },
    { njt_string("OPTIONS"),   NJT_HTTP_OPTIONS },
    { njt_string("PROPFIND"),  NJT_HTTP_PROPFIND },
    { njt_string("PUT"),       NJT_HTTP_PUT },
    { njt_string("MKCOL"),     NJT_HTTP_MKCOL },
    { njt_string("DELETE"),    NJT_HTTP_DELETE },
    { njt_string("COPY"),      NJT_HTTP_COPY },
    { njt_string("MOVE"),      NJT_HTTP_MOVE },
    { njt_string("PROPPATCH"), NJT_HTTP_PROPPATCH },
    { njt_string("LOCK"),      NJT_HTTP_LOCK },
    { njt_string("UNLOCK"),    NJT_HTTP_UNLOCK },
    { njt_string("PATCH"),     NJT_HTTP_PATCH },
    { njt_string("TRACE"),     NJT_HTTP_TRACE },
    { njt_string("CONNECT"),   NJT_HTTP_CONNECT }
};


void
njt_http_v3_init_stream(njt_connection_t *c)
{
    njt_http_connection_t     *hc, *phc;
    njt_http_v3_srv_conf_t    *h3scf;
    njt_http_core_loc_conf_t  *clcf;

    hc = c->data;

    hc->ssl = 1;

    clcf = njt_http_get_module_loc_conf(hc->conf_ctx, njt_http_core_module);

    if (c->quic == NULL) {
        h3scf = njt_http_get_module_srv_conf(hc->conf_ctx, njt_http_v3_module);
        h3scf->quic.idle_timeout = clcf->keepalive_timeout;

        njt_quic_run(c, &h3scf->quic);
        return;
    }

    phc = njt_http_quic_get_connection(c);

    if (phc->ssl_servername) {
        hc->ssl_servername = phc->ssl_servername;
#if (NJT_PCRE)
        hc->ssl_servername_regex = phc->ssl_servername_regex;
#endif
        hc->conf_ctx = phc->conf_ctx;

        njt_set_connection_log(c, clcf->error_log);
    }

    if (c->quic->id & NJT_QUIC_STREAM_UNIDIRECTIONAL) {
        njt_http_v3_init_uni_stream(c);

    } else  {
        njt_http_v3_init_request_stream(c);
    }
}


njt_int_t
njt_http_v3_init(njt_connection_t *c)
{
    unsigned int               len;
    const unsigned char       *data;
    njt_http_v3_session_t     *h3c;
    njt_http_v3_srv_conf_t    *h3scf;
    njt_http_core_loc_conf_t  *clcf;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0, "http3 init");

    if (njt_http_v3_init_session(c) != NJT_OK) {
        return NJT_ERROR;
    }

    h3c = njt_http_v3_get_session(c);
    clcf = njt_http_v3_get_module_loc_conf(c, njt_http_core_module);
    njt_add_timer(&h3c->keepalive, clcf->keepalive_timeout);

    h3scf = njt_http_v3_get_module_srv_conf(c, njt_http_v3_module);

    if (h3scf->enable_hq) {
        if (!h3scf->enable) {
            h3c->hq = 1;
            return NJT_OK;
        }

        SSL_get0_alpn_selected(c->ssl->connection, &data, &len);

        if (len == sizeof(NJT_HTTP_V3_HQ_PROTO) - 1
            && njt_strncmp(data, NJT_HTTP_V3_HQ_PROTO, len) == 0)
        {
            h3c->hq = 1;
            return NJT_OK;
        }
    }

    return njt_http_v3_send_settings(c);
}


void
njt_http_v3_shutdown(njt_connection_t *c)
{
    njt_http_v3_session_t  *h3c;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0, "http3 shutdown");

    h3c = njt_http_v3_get_session(c);

    if (h3c == NULL) {
        njt_quic_finalize_connection(c, NJT_HTTP_V3_ERR_NO_ERROR,
                                     "connection shutdown");
        return;
    }

    if (!h3c->goaway) {
        h3c->goaway = 1;

        if (!h3c->hq) {
            (void) njt_http_v3_send_goaway(c, h3c->next_request_id);
        }

        njt_http_v3_shutdown_connection(c, NJT_HTTP_V3_ERR_NO_ERROR,
                                        "connection shutdown");
    }
}


static void
njt_http_v3_init_request_stream(njt_connection_t *c)
{
    uint64_t                   n;
    njt_event_t               *rev;
    njt_pool_cleanup_t        *cln;
    njt_http_connection_t     *hc;
    njt_http_v3_session_t     *h3c;
    njt_http_core_loc_conf_t  *clcf;
    njt_http_core_srv_conf_t  *cscf;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0, "http3 init request stream");

#if (NJT_STAT_STUB)
    (void) njt_atomic_fetch_add(njt_stat_active, 1);
#endif

    hc = c->data;

    clcf = njt_http_get_module_loc_conf(hc->conf_ctx, njt_http_core_module);

    n = c->quic->id >> 2;

    if (n >= clcf->keepalive_requests * 2) {
        njt_http_v3_finalize_connection(c, NJT_HTTP_V3_ERR_EXCESSIVE_LOAD,
                                        "too many requests per connection");
        njt_http_close_connection(c);
        return;
    }

    h3c = njt_http_v3_get_session(c);

    if (h3c->goaway) {
        c->close = 1;
        njt_http_close_connection(c);
        return;
    }

    h3c->next_request_id = c->quic->id + 0x04;

    if (n + 1 == clcf->keepalive_requests
        || njt_current_msec - c->start_time > clcf->keepalive_time)
    {
        h3c->goaway = 1;

        if (!h3c->hq) {
            if (njt_http_v3_send_goaway(c, h3c->next_request_id) != NJT_OK) {
                njt_http_close_connection(c);
                return;
            }
        }

        njt_http_v3_shutdown_connection(c, NJT_HTTP_V3_ERR_NO_ERROR,
                                        "reached maximum number of requests");
    }

    cln = njt_pool_cleanup_add(c->pool, 0);
    if (cln == NULL) {
        njt_http_close_connection(c);
        return;
    }

    cln->handler = njt_http_v3_cleanup_connection;
    cln->data = c;

    h3c->nrequests++;

    if (h3c->keepalive.timer_set) {
        njt_del_timer(&h3c->keepalive);
    }

    rev = c->read;

    if (!h3c->hq) {
        rev->handler = njt_http_v3_wait_request_handler;
        c->write->handler = njt_http_empty_handler;
    }

    if (rev->ready) {
        rev->handler(rev);
        return;
    }

    cscf = njt_http_get_module_srv_conf(hc->conf_ctx, njt_http_core_module);

    njt_add_timer(rev, cscf->client_header_timeout);
    njt_reusable_connection(c, 1);

    if (njt_handle_read_event(rev, 0) != NJT_OK) {
        njt_http_close_connection(c);
        return;
    }
}


static void
njt_http_v3_wait_request_handler(njt_event_t *rev)
{
    size_t                     size;
    ssize_t                    n;
    njt_buf_t                 *b;
    njt_connection_t          *c;
    njt_pool_cleanup_t        *cln;
    njt_http_request_t        *r;
    njt_http_connection_t     *hc;
    njt_http_core_srv_conf_t  *cscf;

    c = rev->data;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0, "http3 wait request handler");

    if (rev->timedout) {
        njt_log_error(NJT_LOG_INFO, c->log, NJT_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        njt_http_close_connection(c);
        return;
    }

    if (c->close) {
        njt_http_close_connection(c);
        return;
    }

    hc = c->data;
    cscf = njt_http_get_module_srv_conf(hc->conf_ctx, njt_http_core_module);

    size = cscf->client_header_buffer_size;

    b = c->buffer;

    if (b == NULL) {
        b = njt_create_temp_buf(c->pool, size);
        if (b == NULL) {
            njt_http_close_connection(c);
            return;
        }

        c->buffer = b;

    } else if (b->start == NULL) {

        b->start = njt_palloc(c->pool, size);
        if (b->start == NULL) {
            njt_http_close_connection(c);
            return;
        }

        b->pos = b->start;
        b->last = b->start;
        b->end = b->last + size;
    }

    n = c->recv(c, b->last, size);

    if (n == NJT_AGAIN) {

        if (!rev->timer_set) {
            njt_add_timer(rev, cscf->client_header_timeout);
            njt_reusable_connection(c, 1);
        }

        if (njt_handle_read_event(rev, 0) != NJT_OK) {
            njt_http_close_connection(c);
            return;
        }

        /*
         * We are trying to not hold c->buffer's memory for an idle connection.
         */

        if (njt_pfree(c->pool, b->start) == NJT_OK) {
            b->start = NULL;
        }

        return;
    }

    if (n == NJT_ERROR) {
        njt_http_close_connection(c);
        return;
    }

    if (n == 0) {
        njt_log_error(NJT_LOG_INFO, c->log, 0,
                      "client closed connection");
        njt_http_close_connection(c);
        return;
    }

    b->last += n;

    c->log->action = "reading client request";

    njt_reusable_connection(c, 0);

    r = njt_http_create_request(c);
    if (r == NULL) {
        njt_http_close_connection(c);
        return;
    }

    r->http_version = NJT_HTTP_VERSION_30;

    r->v3_parse = njt_pcalloc(r->pool, sizeof(njt_http_v3_parse_t));
    if (r->v3_parse == NULL) {
        njt_http_close_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    r->v3_parse->header_limit = cscf->large_client_header_buffers.size
                                * cscf->large_client_header_buffers.num;

    c->data = r;
    c->requests = (c->quic->id >> 2) + 1;

    cln = njt_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        njt_http_close_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    cln->handler = njt_http_v3_cleanup_request;
    cln->data = r;

    rev->handler = njt_http_v3_process_request;
    njt_http_v3_process_request(rev);
}


void
njt_http_v3_reset_stream(njt_connection_t *c)
{
    njt_http_v3_session_t   *h3c;
    njt_http_v3_srv_conf_t  *h3scf;

    h3scf = njt_http_v3_get_module_srv_conf(c, njt_http_v3_module);

    h3c = njt_http_v3_get_session(c);

    if (h3scf->max_table_capacity > 0 && !c->read->eof && !h3c->hq
        && (c->quic->id & NJT_QUIC_STREAM_UNIDIRECTIONAL) == 0)
    {
        (void) njt_http_v3_send_cancel_stream(c, c->quic->id);
    }

    if (c->timedout) {
        njt_quic_reset_stream(c, NJT_HTTP_V3_ERR_GENERAL_PROTOCOL_ERROR);

    } else if (c->close) {
        njt_quic_reset_stream(c, NJT_HTTP_V3_ERR_REQUEST_REJECTED);

    } else if (c->requests == 0 || c->error) {
        njt_quic_reset_stream(c, NJT_HTTP_V3_ERR_INTERNAL_ERROR);
    }
}


static void
njt_http_v3_cleanup_connection(void *data)
{
    njt_connection_t  *c = data;

    njt_http_v3_session_t     *h3c;
    njt_http_core_loc_conf_t  *clcf;

    h3c = njt_http_v3_get_session(c);

    if (--h3c->nrequests == 0) {
        clcf = njt_http_v3_get_module_loc_conf(c, njt_http_core_module);
        njt_add_timer(&h3c->keepalive, clcf->keepalive_timeout);
    }
}


static void
njt_http_v3_cleanup_request(void *data)
{
    njt_http_request_t  *r = data;

    if (!r->response_sent) {
        r->connection->error = 1;
    }
}


static void
njt_http_v3_process_request(njt_event_t *rev)
{
    u_char                       *p;
    ssize_t                       n;
    njt_buf_t                    *b;
    njt_int_t                     rc;
    njt_connection_t             *c;
    njt_http_request_t           *r;
    njt_http_v3_session_t        *h3c;
    njt_http_core_srv_conf_t     *cscf;
    njt_http_v3_parse_headers_t  *st;

    c = rev->data;
    r = c->data;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, rev->log, 0, "http3 process request");

    if (rev->timedout) {
        njt_log_error(NJT_LOG_INFO, c->log, NJT_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        njt_http_close_request(r, NJT_HTTP_REQUEST_TIME_OUT);
        return;
    }

    h3c = njt_http_v3_get_session(c);

    st = &r->v3_parse->headers;

    b = r->header_in;

    for ( ;; ) {

        if (b->pos == b->last) {

            if (rev->ready) {
                n = c->recv(c, b->start, b->end - b->start);

            } else {
                n = NJT_AGAIN;
            }

            if (n == NJT_AGAIN) {
                if (!rev->timer_set) {
                    cscf = njt_http_get_module_srv_conf(r,
                                                        njt_http_core_module);
                    njt_add_timer(rev, cscf->client_header_timeout);
                }

                if (njt_handle_read_event(rev, 0) != NJT_OK) {
                    njt_http_close_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
                }

                break;
            }

            if (n == 0) {
                njt_log_error(NJT_LOG_INFO, c->log, 0,
                              "client prematurely closed connection");
            }

            if (n == 0 || n == NJT_ERROR) {
                c->error = 1;
                c->log->action = "reading client request";

                njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);
                break;
            }

            b->pos = b->start;
            b->last = b->start + n;
        }

        p = b->pos;

        rc = njt_http_v3_parse_headers(c, st, b);

        if (rc > 0) {
            njt_quic_reset_stream(c, rc);
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "client sent invalid header");
            njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);
            break;
        }

        if (rc == NJT_ERROR) {
            njt_http_close_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
            break;
        }

        r->request_length += b->pos - p;
        h3c->total_bytes += b->pos - p;

        if (njt_http_v3_check_flood(c) != NJT_OK) {
            njt_http_close_request(r, NJT_HTTP_CLOSE);
            break;
        }

        if (rc == NJT_BUSY) {
            if (rev->error) {
                njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);
                break;
            }

            if (!rev->timer_set) {
                cscf = njt_http_get_module_srv_conf(r,
                                                    njt_http_core_module);
                njt_add_timer(rev, cscf->client_header_timeout);
            }

            if (njt_handle_read_event(rev, 0) != NJT_OK) {
                njt_http_close_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
            }

            break;
        }

        if (rc == NJT_AGAIN) {
            continue;
        }

        /* rc == NJT_OK || rc == NJT_DONE */

        h3c->payload_bytes += njt_http_v3_encode_field_l(NULL,
                                                   &st->field_rep.field.name,
                                                   &st->field_rep.field.value);

        if (njt_http_v3_process_header(r, &st->field_rep.field.name,
                                       &st->field_rep.field.value)
            != NJT_OK)
        {
            break;
        }

        if (rc == NJT_DONE) {
            if (njt_http_v3_process_request_header(r) != NJT_OK) {
                break;
            }

            njt_http_process_request(r);
            break;
        }
    }

    njt_http_run_posted_requests(c);

    return;
}


static njt_int_t
njt_http_v3_process_header(njt_http_request_t *r, njt_str_t *name,
    njt_str_t *value)
{
    size_t                      len;
    njt_table_elt_t            *h;
    njt_http_header_t          *hh;
    njt_http_core_srv_conf_t   *cscf;
    njt_http_core_main_conf_t  *cmcf;

    static njt_str_t cookie = njt_string("cookie");

    len = name->len + value->len;

    if (len > r->v3_parse->header_limit) {
        njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                      "client sent too large header");
        njt_http_finalize_request(r, NJT_HTTP_REQUEST_HEADER_TOO_LARGE);
        return NJT_ERROR;
    }

    r->v3_parse->header_limit -= len;

    if (njt_http_v3_validate_header(r, name, value) != NJT_OK) {
        njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);
        return NJT_ERROR;
    }

    if (r->invalid_header) {
        cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);

        if (cscf->ignore_invalid_headers) {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "client sent invalid header: \"%V\"", name);

            return NJT_OK;
        }
    }

    if (name->len && name->data[0] == ':') {
        return njt_http_v3_process_pseudo_header(r, name, value);
    }

    if (njt_http_v3_init_pseudo_headers(r) != NJT_OK) {
        return NJT_ERROR;
    }

    if (name->len == cookie.len
        && njt_memcmp(name->data, cookie.data, cookie.len) == 0)
    {
        if (njt_http_v3_cookie(r, value) != NJT_OK) {
            njt_http_close_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
            return NJT_ERROR;
        }

    } else {
        h = njt_list_push(&r->headers_in.headers);
        if (h == NULL) {
            njt_http_close_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
            return NJT_ERROR;
        }

        h->key = *name;
        h->value = *value;
        h->lowcase_key = h->key.data;
        h->hash = njt_hash_key(h->key.data, h->key.len);

        cmcf = njt_http_get_module_main_conf(r, njt_http_core_module);

        hh = njt_hash_find(&cmcf->headers_in_hash, h->hash,
                           h->lowcase_key, h->key.len);

        if (hh && hh->handler(r, h, hh->offset) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http3 header: \"%V: %V\"", name, value);
    return NJT_OK;
}


static njt_int_t
njt_http_v3_validate_header(njt_http_request_t *r, njt_str_t *name,
    njt_str_t *value)
{
    u_char                     ch;
    njt_uint_t                 i;
    njt_http_core_srv_conf_t  *cscf;

    r->invalid_header = 0;

    cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);

    for (i = (name->data[0] == ':'); i != name->len; i++) {
        ch = name->data[i];

        if ((ch >= 'a' && ch <= 'z')
            || (ch == '-')
            || (ch >= '0' && ch <= '9')
            || (ch == '_' && cscf->underscores_in_headers))
        {
            continue;
        }

        if (ch <= 0x20 || ch == 0x7f || ch == ':'
            || (ch >= 'A' && ch <= 'Z'))
        {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "client sent invalid header name: \"%V\"", name);

            return NJT_ERROR;
        }

        r->invalid_header = 1;
    }

    for (i = 0; i != value->len; i++) {
        ch = value->data[i];

        if (ch == '\0' || ch == LF || ch == CR) {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "client sent header \"%V\" with "
                          "invalid value: \"%V\"", name, value);

            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


static njt_int_t
njt_http_v3_process_pseudo_header(njt_http_request_t *r, njt_str_t *name,
    njt_str_t *value)
{
    u_char      ch, c;
    njt_uint_t  i;

    if (r->request_line.len) {
        njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                      "client sent out of order pseudo-headers");
        goto failed;
    }

    if (name->len == 7 && njt_strncmp(name->data, ":method", 7) == 0) {

        if (r->method_name.len) {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "client sent duplicate \":method\" header");
            goto failed;
        }

        if (value->len == 0) {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "client sent empty \":method\" header");
            goto failed;
        }

        r->method_name = *value;

        for (i = 0; i < sizeof(njt_http_v3_methods)
                        / sizeof(njt_http_v3_methods[0]); i++)
        {
            if (value->len == njt_http_v3_methods[i].name.len
                && njt_strncmp(value->data,
                               njt_http_v3_methods[i].name.data, value->len)
                   == 0)
            {
                r->method = njt_http_v3_methods[i].method;
                break;
            }
        }

        for (i = 0; i < value->len; i++) {
            ch = value->data[i];

            if ((ch < 'A' || ch > 'Z') && ch != '_' && ch != '-') {
                njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                              "client sent invalid method: \"%V\"", value);
                goto failed;
            }
        }

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http3 method \"%V\" %ui", value, r->method);
        return NJT_OK;
    }

    if (name->len == 5 && njt_strncmp(name->data, ":path", 5) == 0) {

        if (r->uri_start) {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "client sent duplicate \":path\" header");
            goto failed;
        }

        if (value->len == 0) {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "client sent empty \":path\" header");
            goto failed;
        }

        r->uri_start = value->data;
        r->uri_end = value->data + value->len;

        if (njt_http_parse_uri(r) != NJT_OK) {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "client sent invalid \":path\" header: \"%V\"",
                          value);
            goto failed;
        }

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http3 path \"%V\"", value);
        return NJT_OK;
    }

    if (name->len == 7 && njt_strncmp(name->data, ":scheme", 7) == 0) {

        if (r->schema.len) {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "client sent duplicate \":scheme\" header");
            goto failed;
        }

        if (value->len == 0) {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "client sent empty \":scheme\" header");
            goto failed;
        }

        for (i = 0; i < value->len; i++) {
            ch = value->data[i];

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                continue;
            }

            if (((ch >= '0' && ch <= '9')
                 || ch == '+' || ch == '-' || ch == '.')
                && i > 0)
            {
                continue;
            }

            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "client sent invalid \":scheme\" header: \"%V\"",
                          value);
            goto failed;
        }

        r->schema = *value;

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http3 schema \"%V\"", value);
        return NJT_OK;
    }

    if (name->len == 10 && njt_strncmp(name->data, ":authority", 10) == 0) {

        if (r->host_start) {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "client sent duplicate \":authority\" header");
            goto failed;
        }

        r->host_start = value->data;
        r->host_end = value->data + value->len;

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http3 authority \"%V\"", value);
        return NJT_OK;
    }

    njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                  "client sent unknown pseudo-header \"%V\"", name);

failed:

    njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);
    return NJT_ERROR;
}


static njt_int_t
njt_http_v3_init_pseudo_headers(njt_http_request_t *r)
{
    size_t      len;
    u_char     *p;
    njt_int_t   rc;
    njt_str_t   host;

    if (r->request_line.len) {
        return NJT_OK;
    }

    if (r->method_name.len == 0) {
        njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                      "client sent no \":method\" header");
        goto failed;
    }

    if (r->schema.len == 0) {
        njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                      "client sent no \":scheme\" header");
        goto failed;
    }

    if (r->uri_start == NULL) {
        njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                      "client sent no \":path\" header");
        goto failed;
    }

    len = r->method_name.len + 1
          + (r->uri_end - r->uri_start) + 1
          + sizeof("HTTP/3.0") - 1;

    p = njt_pnalloc(r->pool, len);
    if (p == NULL) {
        njt_http_close_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return NJT_ERROR;
    }

    r->request_line.data = p;

    p = njt_cpymem(p, r->method_name.data, r->method_name.len);
    *p++ = ' ';
    p = njt_cpymem(p, r->uri_start, r->uri_end - r->uri_start);
    *p++ = ' ';
    p = njt_cpymem(p, "HTTP/3.0", sizeof("HTTP/3.0") - 1);

    r->request_line.len = p - r->request_line.data;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http3 request line: \"%V\"", &r->request_line);

    njt_str_set(&r->http_protocol, "HTTP/3.0");

    if (njt_http_process_request_uri(r) != NJT_OK) {
        return NJT_ERROR;
    }

    if (r->host_end) {

        host.len = r->host_end - r->host_start;
        host.data = r->host_start;

        rc = njt_http_validate_host(&host, r->pool, 0);

        if (rc == NJT_DECLINED) {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "client sent invalid host in request line");
            goto failed;
        }

        if (rc == NJT_ERROR) {
            njt_http_close_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
            return NJT_ERROR;
        }

        if (njt_http_set_virtual_server(r, &host) == NJT_ERROR) {
            return NJT_ERROR;
        }

        r->headers_in.server = host;
    }

    if (njt_list_init(&r->headers_in.headers, r->pool, 20,
                      sizeof(njt_table_elt_t))
        != NJT_OK)
    {
        njt_http_close_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return NJT_ERROR;
    }

    return NJT_OK;

failed:

    njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);
    return NJT_ERROR;
}


static njt_int_t
njt_http_v3_process_request_header(njt_http_request_t *r)
{
    ssize_t                  n;
    njt_buf_t               *b;
    njt_connection_t        *c;
    njt_http_v3_session_t   *h3c;
    njt_http_v3_srv_conf_t  *h3scf;

    c = r->connection;

    if (njt_http_v3_init_pseudo_headers(r) != NJT_OK) {
        return NJT_ERROR;
    }

    h3c = njt_http_v3_get_session(c);
    h3scf = njt_http_get_module_srv_conf(r, njt_http_v3_module);

    if ((h3c->hq && !h3scf->enable_hq) || (!h3c->hq && !h3scf->enable)) {
        njt_log_error(NJT_LOG_INFO, c->log, 0,
                      "client attempted to request the server name "
                      "for which the negotiated protocol is disabled");
        njt_http_finalize_request(r, NJT_HTTP_MISDIRECTED_REQUEST);
        return NJT_ERROR;
    }

    if (njt_http_v3_construct_cookie_header(r) != NJT_OK) {
        return NJT_ERROR;
    }

    if (r->headers_in.server.len == 0) {
        njt_log_error(NJT_LOG_INFO, c->log, 0,
                      "client sent neither \":authority\" nor \"Host\" header");
        goto failed;
    }

    if (r->headers_in.host) {
        if (r->headers_in.host->value.len != r->headers_in.server.len
            || njt_memcmp(r->headers_in.host->value.data,
                          r->headers_in.server.data,
                          r->headers_in.server.len)
               != 0)
        {
            njt_log_error(NJT_LOG_INFO, c->log, 0,
                          "client sent \":authority\" and \"Host\" headers "
                          "with different values");
            goto failed;
        }
    }

    if (r->headers_in.content_length) {
        r->headers_in.content_length_n =
                            njt_atoof(r->headers_in.content_length->value.data,
                                      r->headers_in.content_length->value.len);

        if (r->headers_in.content_length_n == NJT_ERROR) {
            njt_log_error(NJT_LOG_INFO, c->log, 0,
                          "client sent invalid \"Content-Length\" header");
            goto failed;
        }

    } else {
        b = r->header_in;
        n = b->last - b->pos;

        if (n == 0) {
            n = c->recv(c, b->start, b->end - b->start);

            if (n == NJT_ERROR) {
                njt_http_close_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
                return NJT_ERROR;
            }

            if (n > 0) {
                b->pos = b->start;
                b->last = b->start + n;
            }
        }

        if (n != 0) {
            r->headers_in.chunked = 1;
        }
    }

    if (r->method == NJT_HTTP_CONNECT) {
        njt_log_error(NJT_LOG_INFO, c->log, 0, "client sent CONNECT method");
        njt_http_finalize_request(r, NJT_HTTP_NOT_ALLOWED);
        return NJT_ERROR;
    }

    if (r->method == NJT_HTTP_TRACE) {
        njt_log_error(NJT_LOG_INFO, c->log, 0, "client sent TRACE method");
        njt_http_finalize_request(r, NJT_HTTP_NOT_ALLOWED);
        return NJT_ERROR;
    }

    return NJT_OK;

failed:

    njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);
    return NJT_ERROR;
}


static njt_int_t
njt_http_v3_cookie(njt_http_request_t *r, njt_str_t *value)
{
    njt_str_t    *val;
    njt_array_t  *cookies;

    cookies = r->v3_parse->cookies;

    if (cookies == NULL) {
        cookies = njt_array_create(r->pool, 2, sizeof(njt_str_t));
        if (cookies == NULL) {
            return NJT_ERROR;
        }

        r->v3_parse->cookies = cookies;
    }

    val = njt_array_push(cookies);
    if (val == NULL) {
        return NJT_ERROR;
    }

    *val = *value;

    return NJT_OK;
}


static njt_int_t
njt_http_v3_construct_cookie_header(njt_http_request_t *r)
{
    u_char                     *buf, *p, *end;
    size_t                      len;
    njt_str_t                  *vals;
    njt_uint_t                  i;
    njt_array_t                *cookies;
    njt_table_elt_t            *h;
    njt_http_header_t          *hh;
    njt_http_core_main_conf_t  *cmcf;

    static njt_str_t cookie = njt_string("cookie");

    cookies = r->v3_parse->cookies;

    if (cookies == NULL) {
        return NJT_OK;
    }

    vals = cookies->elts;

    i = 0;
    len = 0;

    do {
        len += vals[i].len + 2;
    } while (++i != cookies->nelts);

    len -= 2;

    buf = njt_pnalloc(r->pool, len + 1);
    if (buf == NULL) {
        njt_http_close_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return NJT_ERROR;
    }

    p = buf;
    end = buf + len;

    for (i = 0; /* void */ ; i++) {

        p = njt_cpymem(p, vals[i].data, vals[i].len);

        if (p == end) {
            *p = '\0';
            break;
        }

        *p++ = ';'; *p++ = ' ';
    }

    h = njt_list_push(&r->headers_in.headers);
    if (h == NULL) {
        njt_http_close_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return NJT_ERROR;
    }

    h->hash = njt_hash(njt_hash(njt_hash(njt_hash(
                                    njt_hash('c', 'o'), 'o'), 'k'), 'i'), 'e');

    h->key.len = cookie.len;
    h->key.data = cookie.data;

    h->value.len = len;
    h->value.data = buf;

    h->lowcase_key = cookie.data;

    cmcf = njt_http_get_module_main_conf(r, njt_http_core_module);

    hh = njt_hash_find(&cmcf->headers_in_hash, h->hash,
                       h->lowcase_key, h->key.len);

    if (hh == NULL) {
        njt_http_close_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return NJT_ERROR;
    }

    if (hh->handler(r, h, hh->offset) != NJT_OK) {
        /*
         * request has been finalized already
         * in njt_http_process_multi_header_lines()
         */
        return NJT_ERROR;
    }

    return NJT_OK;
}


njt_int_t
njt_http_v3_read_request_body(njt_http_request_t *r)
{
    size_t                     preread;
    njt_int_t                  rc;
    njt_chain_t               *cl, out;
    njt_http_request_body_t   *rb;
    njt_http_core_loc_conf_t  *clcf;

    rb = r->request_body;

    preread = r->header_in->last - r->header_in->pos;

    if (preread) {

        /* there is the pre-read part of the request body */

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http3 client request body preread %uz", preread);

        out.buf = r->header_in;
        out.next = NULL;
        cl = &out;

    } else {
        cl = NULL;
    }

    rc = njt_http_v3_request_body_filter(r, cl);
    if (rc != NJT_OK) {
        return rc;
    }

    if (rb->rest == 0 && rb->last_saved) {
        /* the whole request body was pre-read */
        r->request_body_no_buffering = 0;
        rb->post_handler(r);
        return NJT_OK;
    }

    if (rb->rest < 0) {
        njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
                      "negative request body rest");
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    rb->buf = njt_create_temp_buf(r->pool, clcf->client_body_buffer_size);
    if (rb->buf == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->read_event_handler = njt_http_v3_read_client_request_body_handler;
    r->write_event_handler = njt_http_request_empty_handler;

    return njt_http_v3_do_read_client_request_body(r);
}


static void
njt_http_v3_read_client_request_body_handler(njt_http_request_t *r)
{
    njt_int_t  rc;

    if (r->connection->read->timedout) {
        r->connection->timedout = 1;
        njt_http_finalize_request(r, NJT_HTTP_REQUEST_TIME_OUT);
        return;
    }

    rc = njt_http_v3_do_read_client_request_body(r);

    if (rc >= NJT_HTTP_SPECIAL_RESPONSE) {
        njt_http_finalize_request(r, rc);
    }
}


njt_int_t
njt_http_v3_read_unbuffered_request_body(njt_http_request_t *r)
{
    njt_int_t  rc;

    if (r->connection->read->timedout) {
        r->connection->timedout = 1;
        return NJT_HTTP_REQUEST_TIME_OUT;
    }

    rc = njt_http_v3_do_read_client_request_body(r);

    if (rc == NJT_OK) {
        r->reading_body = 0;
    }

    return rc;
}


static njt_int_t
njt_http_v3_do_read_client_request_body(njt_http_request_t *r)
{
    off_t                      rest;
    size_t                     size;
    ssize_t                    n;
    njt_int_t                  rc;
    njt_uint_t                 flush;
    njt_chain_t                out;
    njt_connection_t          *c;
    njt_http_request_body_t   *rb;
    njt_http_core_loc_conf_t  *clcf;

    c = r->connection;
    rb = r->request_body;
    flush = 1;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 read client request body");

    for ( ;; ) {
        for ( ;; ) {
            if (rb->rest == 0) {
                break;
            }

            if (rb->buf->last == rb->buf->end) {

                /* update chains */

                rc = njt_http_v3_request_body_filter(r, NULL);

                if (rc != NJT_OK) {
                    return rc;
                }

                if (rb->busy != NULL) {
                    if (r->request_body_no_buffering) {
                        if (c->read->timer_set) {
                            njt_del_timer(c->read);
                        }

                        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
                            return NJT_HTTP_INTERNAL_SERVER_ERROR;
                        }

                        return NJT_AGAIN;
                    }

                    if (rb->filter_need_buffering) {
                        clcf = njt_http_get_module_loc_conf(r,
                                                         njt_http_core_module);
                        njt_add_timer(c->read, clcf->client_body_timeout);

                        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
                            return NJT_HTTP_INTERNAL_SERVER_ERROR;
                        }

                        return NJT_AGAIN;
                    }

                    njt_log_error(NJT_LOG_ALERT, c->log, 0,
                                  "busy buffers after request body flush");

                    return NJT_HTTP_INTERNAL_SERVER_ERROR;
                }

                flush = 0;
                rb->buf->pos = rb->buf->start;
                rb->buf->last = rb->buf->start;
            }

            size = rb->buf->end - rb->buf->last;
            rest = rb->rest - (rb->buf->last - rb->buf->pos);

            if ((off_t) size > rest) {
                size = (size_t) rest;
            }

            if (size == 0) {
                break;
            }

            n = c->recv(c, rb->buf->last, size);

            njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 client request body recv %z", n);

            if (n == NJT_AGAIN) {
                break;
            }

            if (n == 0) {
                rb->buf->last_buf = 1;
            }

            if (n == NJT_ERROR) {
                c->error = 1;
                return NJT_HTTP_BAD_REQUEST;
            }

            rb->buf->last += n;

            /* pass buffer to request body filter chain */

            flush = 0;
            out.buf = rb->buf;
            out.next = NULL;

            rc = njt_http_v3_request_body_filter(r, &out);

            if (rc != NJT_OK) {
                return rc;
            }

            if (rb->rest == 0) {
                break;
            }

            if (rb->buf->last < rb->buf->end) {
                break;
            }
        }

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 client request body rest %O", rb->rest);

        if (flush) {
            rc = njt_http_v3_request_body_filter(r, NULL);

            if (rc != NJT_OK) {
                return rc;
            }
        }

        if (rb->rest == 0 && rb->last_saved) {
            break;
        }

        if (!c->read->ready || rb->rest == 0) {

            clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);
            njt_add_timer(c->read, clcf->client_body_timeout);

            if (njt_handle_read_event(c->read, 0) != NJT_OK) {
                return NJT_HTTP_INTERNAL_SERVER_ERROR;
            }

            return NJT_AGAIN;
        }
    }

    if (c->read->timer_set) {
        njt_del_timer(c->read);
    }

    if (!r->request_body_no_buffering) {
        r->read_event_handler = njt_http_block_reading;
        rb->post_handler(r);
    }

    return NJT_OK;
}


static njt_int_t
njt_http_v3_request_body_filter(njt_http_request_t *r, njt_chain_t *in)
{
    off_t                      max;
    size_t                     size;
    u_char                    *p;
    njt_int_t                  rc;
    njt_buf_t                 *b;
    njt_uint_t                 last;
    njt_chain_t               *cl, *out, *tl, **ll;
    njt_http_v3_session_t     *h3c;
    njt_http_request_body_t   *rb;
    njt_http_core_loc_conf_t  *clcf;
    njt_http_core_srv_conf_t  *cscf;
    njt_http_v3_parse_data_t  *st;

    rb = r->request_body;
    st = &r->v3_parse->body;

    h3c = njt_http_v3_get_session(r->connection);

    if (rb->rest == -1) {

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http3 request body filter");

        cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);

        rb->rest = cscf->large_client_header_buffers.size;
    }

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    max = r->headers_in.content_length_n;

    if (max == -1 && clcf->client_max_body_size) {
        max = clcf->client_max_body_size;
    }

    out = NULL;
    ll = &out;
    last = 0;

    for (cl = in; cl; cl = cl->next) {

        njt_log_debug7(NJT_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "http3 body buf "
                       "t:%d f:%d %p, pos %p, size: %z file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

        if (cl->buf->last_buf) {
            last = 1;
        }

        b = NULL;

        while (cl->buf->pos < cl->buf->last) {

            if (st->length == 0) {
                p = cl->buf->pos;

                rc = njt_http_v3_parse_data(r->connection, st, cl->buf);

                r->request_length += cl->buf->pos - p;
                h3c->total_bytes += cl->buf->pos - p;

                if (njt_http_v3_check_flood(r->connection) != NJT_OK) {
                    return NJT_HTTP_CLOSE;
                }

                if (rc == NJT_AGAIN) {
                    continue;
                }

                if (rc == NJT_DONE) {
                    last = 1;
                    goto done;
                }

                if (rc > 0) {
                    njt_quic_reset_stream(r->connection, rc);
                    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                  "client sent invalid body");
                    return NJT_HTTP_BAD_REQUEST;
                }

                if (rc == NJT_ERROR) {
                    return NJT_HTTP_INTERNAL_SERVER_ERROR;
                }

                /* rc == NJT_OK */

                if (max != -1 && (uint64_t) (max - rb->received) < st->length) {
                    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                  "client intended to send too large "
                                  "body: %O+%ui bytes",
                                  rb->received, st->length);

                    return NJT_HTTP_REQUEST_ENTITY_TOO_LARGE;
                }

                continue;
            }

            if (b
                && st->length <= 128
                && (uint64_t) (cl->buf->last - cl->buf->pos) >= st->length)
            {
                rb->received += st->length;
                r->request_length += st->length;
                h3c->total_bytes += st->length;
                h3c->payload_bytes += st->length;

                if (st->length < 8) {

                    while (st->length) {
                        *b->last++ = *cl->buf->pos++;
                        st->length--;
                    }

                } else {
                    njt_memmove(b->last, cl->buf->pos, st->length);
                    b->last += st->length;
                    cl->buf->pos += st->length;
                    st->length = 0;
                }

                continue;
            }

            tl = njt_chain_get_free_buf(r->pool, &rb->free);
            if (tl == NULL) {
                return NJT_HTTP_INTERNAL_SERVER_ERROR;
            }

            b = tl->buf;

            njt_memzero(b, sizeof(njt_buf_t));

            b->temporary = 1;
            b->tag = (njt_buf_tag_t) &njt_http_read_client_request_body;
            b->start = cl->buf->pos;
            b->pos = cl->buf->pos;
            b->last = cl->buf->last;
            b->end = cl->buf->end;
            b->flush = r->request_body_no_buffering;

            *ll = tl;
            ll = &tl->next;

            size = cl->buf->last - cl->buf->pos;

            if (size > st->length) {
                cl->buf->pos += (size_t) st->length;
                rb->received += st->length;
                r->request_length += st->length;
                h3c->total_bytes += st->length;
                h3c->payload_bytes += st->length;
                st->length = 0;

            } else {
                st->length -= size;
                rb->received += size;
                r->request_length += size;
                h3c->total_bytes += size;
                h3c->payload_bytes += size;
                cl->buf->pos = cl->buf->last;
            }

            b->last = cl->buf->pos;
        }
    }

done:

    if (last) {

        if (st->length > 0) {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "client prematurely closed stream");
            r->connection->error = 1;
            return NJT_HTTP_BAD_REQUEST;
        }

        if (r->headers_in.content_length_n == -1) {
            r->headers_in.content_length_n = rb->received;

        } else if (r->headers_in.content_length_n != rb->received) {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "client sent less body data than expected: "
                          "%O out of %O bytes of request body received",
                          rb->received, r->headers_in.content_length_n);
            return NJT_HTTP_BAD_REQUEST;
        }

        rb->rest = 0;

        tl = njt_chain_get_free_buf(r->pool, &rb->free);
        if (tl == NULL) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        b = tl->buf;

        njt_memzero(b, sizeof(njt_buf_t));

        b->last_buf = 1;

        *ll = tl;

    } else {

        /* set rb->rest, amount of data we want to see next time */

        cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);

        rb->rest = (off_t) cscf->large_client_header_buffers.size;
    }

    rc = njt_http_top_request_body_filter(r, out);

    njt_chain_update_chains(r->pool, &rb->free, &rb->busy, &out,
                            (njt_buf_tag_t) &njt_http_read_client_request_body);

    return rc;
}
