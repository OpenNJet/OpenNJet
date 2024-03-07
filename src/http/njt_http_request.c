
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


static void njt_http_wait_request_handler(njt_event_t *ev);
static njt_http_request_t *njt_http_alloc_request(njt_connection_t *c);
static void njt_http_process_request_line(njt_event_t *rev);
static void njt_http_process_request_headers(njt_event_t *rev);
static ssize_t njt_http_read_request_header(njt_http_request_t *r);
static njt_int_t njt_http_alloc_large_header_buffer(njt_http_request_t *r,
    njt_uint_t request_line);

static njt_int_t njt_http_process_header_line(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset);
static njt_int_t njt_http_process_unique_header_line(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset);
static njt_int_t njt_http_process_host(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset);
static njt_int_t njt_http_process_connection(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset);
static njt_int_t njt_http_process_user_agent(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset);

static njt_int_t njt_http_find_virtual_server(njt_connection_t *c,
    njt_http_virtual_names_t *virtual_names, njt_str_t *host,
    njt_http_request_t *r, njt_http_core_srv_conf_t **cscfp);

static void njt_http_request_handler(njt_event_t *ev);
static void njt_http_terminate_request(njt_http_request_t *r, njt_int_t rc);
static void njt_http_terminate_handler(njt_http_request_t *r);
static void njt_http_finalize_connection(njt_http_request_t *r);
static njt_int_t njt_http_set_write_handler(njt_http_request_t *r);
static void njt_http_writer(njt_http_request_t *r);
static void njt_http_request_finalizer(njt_http_request_t *r);

static void njt_http_set_keepalive(njt_http_request_t *r);
static void njt_http_keepalive_handler(njt_event_t *ev);
static void njt_http_set_lingering_close(njt_connection_t *c);
static void njt_http_lingering_close_handler(njt_event_t *ev);
static njt_int_t njt_http_post_action(njt_http_request_t *r);
static void njt_http_log_request(njt_http_request_t *r);

static u_char *njt_http_log_error(njt_log_t *log, u_char *buf, size_t len);
static u_char *njt_http_log_error_handler(njt_http_request_t *r,
    njt_http_request_t *sr, u_char *buf, size_t len);

#if (NJT_HTTP_SSL)
static void njt_http_ssl_handshake(njt_event_t *rev);
static void njt_http_ssl_handshake_handler(njt_connection_t *c);
#endif


static char *njt_http_client_errors[] = {

    /* NJT_HTTP_PARSE_INVALID_METHOD */
    "client sent invalid method",

    /* NJT_HTTP_PARSE_INVALID_REQUEST */
    "client sent invalid request",

    /* NJT_HTTP_PARSE_INVALID_VERSION */
    "client sent invalid version",

    /* NJT_HTTP_PARSE_INVALID_09_METHOD */
    "client sent invalid method in HTTP/0.9 request"
};


njt_http_header_t  njt_http_headers_in[] = {
    { njt_string("Host"), offsetof(njt_http_headers_in_t, host),
                 njt_http_process_host },

    { njt_string("Connection"), offsetof(njt_http_headers_in_t, connection),
                 njt_http_process_connection },

    { njt_string("If-Modified-Since"),
                 offsetof(njt_http_headers_in_t, if_modified_since),
                 njt_http_process_unique_header_line },

    { njt_string("If-Unmodified-Since"),
                 offsetof(njt_http_headers_in_t, if_unmodified_since),
                 njt_http_process_unique_header_line },

    { njt_string("If-Match"),
                 offsetof(njt_http_headers_in_t, if_match),
                 njt_http_process_unique_header_line },

    { njt_string("If-None-Match"),
                 offsetof(njt_http_headers_in_t, if_none_match),
                 njt_http_process_unique_header_line },

    { njt_string("User-Agent"), offsetof(njt_http_headers_in_t, user_agent),
                 njt_http_process_user_agent },

    { njt_string("Referer"), offsetof(njt_http_headers_in_t, referer),
                 njt_http_process_header_line },

    { njt_string("Content-Length"),
                 offsetof(njt_http_headers_in_t, content_length),
                 njt_http_process_unique_header_line },

    { njt_string("Content-Range"),
                 offsetof(njt_http_headers_in_t, content_range),
                 njt_http_process_unique_header_line },

    { njt_string("Content-Type"),
                 offsetof(njt_http_headers_in_t, content_type),
                 njt_http_process_header_line },

    { njt_string("Range"), offsetof(njt_http_headers_in_t, range),
                 njt_http_process_header_line },

    { njt_string("If-Range"),
                 offsetof(njt_http_headers_in_t, if_range),
                 njt_http_process_unique_header_line },

    { njt_string("Transfer-Encoding"),
                 offsetof(njt_http_headers_in_t, transfer_encoding),
                 njt_http_process_unique_header_line },

    { njt_string("TE"),
                 offsetof(njt_http_headers_in_t, te),
                 njt_http_process_header_line },

    { njt_string("Expect"),
                 offsetof(njt_http_headers_in_t, expect),
                 njt_http_process_unique_header_line },

    { njt_string("Upgrade"),
                 offsetof(njt_http_headers_in_t, upgrade),
                 njt_http_process_header_line },

#if (NJT_HTTP_GZIP || NJT_HTTP_HEADERS)
    { njt_string("Accept-Encoding"),
                 offsetof(njt_http_headers_in_t, accept_encoding),
                 njt_http_process_header_line },

    { njt_string("Via"), offsetof(njt_http_headers_in_t, via),
                 njt_http_process_header_line },
#endif

    { njt_string("Authorization"),
                 offsetof(njt_http_headers_in_t, authorization),
                 njt_http_process_unique_header_line },

    { njt_string("Keep-Alive"), offsetof(njt_http_headers_in_t, keep_alive),
                 njt_http_process_header_line },

#if (NJT_HTTP_X_FORWARDED_FOR)
    { njt_string("X-Forwarded-For"),
                 offsetof(njt_http_headers_in_t, x_forwarded_for),
                 njt_http_process_header_line },
#endif

#if (NJT_HTTP_REALIP)
    { njt_string("X-Real-IP"),
                 offsetof(njt_http_headers_in_t, x_real_ip),
                 njt_http_process_header_line },
#endif

#if (NJT_HTTP_HEADERS)
    { njt_string("Accept"), offsetof(njt_http_headers_in_t, accept),
                 njt_http_process_header_line },

    { njt_string("Accept-Language"),
                 offsetof(njt_http_headers_in_t, accept_language),
                 njt_http_process_header_line },
#endif

#if (NJT_HTTP_DAV)
    { njt_string("Depth"), offsetof(njt_http_headers_in_t, depth),
                 njt_http_process_header_line },

    { njt_string("Destination"), offsetof(njt_http_headers_in_t, destination),
                 njt_http_process_header_line },

    { njt_string("Overwrite"), offsetof(njt_http_headers_in_t, overwrite),
                 njt_http_process_header_line },

    { njt_string("Date"), offsetof(njt_http_headers_in_t, date),
                 njt_http_process_header_line },
#endif

    { njt_string("Cookie"), offsetof(njt_http_headers_in_t, cookie),
                 njt_http_process_header_line },

    { njt_null_string, 0, NULL }
};


void
njt_http_init_connection(njt_connection_t *c)
{
    njt_uint_t                 i;
    njt_event_t               *rev;
    struct sockaddr_in        *sin;
    njt_http_port_t           *port;
    njt_http_in_addr_t        *addr;
    njt_http_log_ctx_t        *ctx;
    njt_http_connection_t     *hc;
    njt_http_core_srv_conf_t  *cscf;
#if (NJT_HAVE_INET6)
    struct sockaddr_in6       *sin6;
    njt_http_in6_addr_t       *addr6;
#endif

    hc = njt_pcalloc(c->pool, sizeof(njt_http_connection_t));
    if (hc == NULL) {
        njt_http_close_connection(c);
        return;
    }

    c->data = hc;

    /* find the server configuration for the address:port */

    port = c->listening->servers;

    if (port->naddrs > 1) {

        /*
         * there are several addresses on this port and one of them
         * is an "*:port" wildcard so getsockname() in njt_http_server_addr()
         * is required to determine a server address
         */

        if (njt_connection_local_sockaddr(c, NULL, 0) != NJT_OK) {
            njt_http_close_connection(c);
            return;
        }

        switch (c->local_sockaddr->sa_family) {

#if (NJT_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) c->local_sockaddr;

            addr6 = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (njt_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
                    break;
                }
            }

            hc->addr_conf = &addr6[i].conf;

            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) c->local_sockaddr;

            addr = port->addrs;
            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (addr[i].addr == sin->sin_addr.s_addr) {
                    break;
                }
            }

            hc->addr_conf = &addr[i].conf;
	     njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0,"njt_http_init_connection listening=%p, port=%p, addr=%p,servers=%p,addr_conf=%p",c->listening,port,addr,c->listening->servers,hc->addr_conf);	

            break;
        }

    } else {

        switch (c->local_sockaddr->sa_family) {

#if (NJT_HAVE_INET6)
        case AF_INET6:
            addr6 = port->addrs;
            hc->addr_conf = &addr6[0].conf;
            break;
#endif

        default: /* AF_INET */
            addr = port->addrs;
            hc->addr_conf = &addr[0].conf;
            break;
        }
    }

    /* the default server configuration for the address:port */
    hc->conf_ctx = hc->addr_conf->default_server->ctx;

    ctx = njt_palloc(c->pool, sizeof(njt_http_log_ctx_t));
    if (ctx == NULL) {
        njt_http_close_connection(c);
        return;
    }

    ctx->connection = c;
    ctx->request = NULL;
    ctx->current_request = NULL;

    c->log->connection = c->number;
    c->log->handler = njt_http_log_error;
    c->log->data = ctx;
    c->log->action = "waiting for request";

    c->log_error = NJT_ERROR_INFO;

    rev = c->read;
    rev->handler = njt_http_wait_request_handler;
    c->write->handler = njt_http_empty_handler;

#if (NJT_HTTP_V3)
    if (hc->addr_conf->quic) {
        njt_http_v3_init_stream(c);
        return;
    }
#endif

#if (NJT_HTTP_SSL)
    if (hc->addr_conf->ssl) {
        hc->ssl = 1;
        c->log->action = "SSL handshaking";
        rev->handler = njt_http_ssl_handshake;
    }
#endif

    if (hc->addr_conf->proxy_protocol) {
        hc->proxy_protocol = 1;
        c->log->action = "reading PROXY protocol";
    }

    if (rev->ready) {
        /* the deferred accept(), iocp */

        if (njt_use_accept_mutex) {
            njt_post_event(rev, &njt_posted_events);
            return;
        }

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
njt_http_wait_request_handler(njt_event_t *rev)
{
    u_char                    *p;
    size_t                     size;
    ssize_t                    n;
    njt_buf_t                 *b;
    njt_connection_t          *c;
    njt_http_connection_t     *hc;
#if (NJT_HTTP_V2)
    njt_http_v2_srv_conf_t    *h2scf;
#endif
    njt_http_core_srv_conf_t  *cscf;

    c = rev->data;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0, "http wait request handler");

    if (rev->timedout) {
        njt_log_error(NJT_LOG_INFO, c->log, NJT_ETIMEDOUT, "client timed out");
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

    size = b->end - b->last;

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

        if (b->pos == b->last) {

            /*
            * We are trying to not hold c->buffer's memory for an
            * idle connection.
            */

            if (njt_pfree(c->pool, b->start) == NJT_OK) {
                b->start = NULL;
            }
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

    if (hc->proxy_protocol) {
        hc->proxy_protocol = 0;

        p = njt_proxy_protocol_read(c, b->pos, b->last);

        if (p == NULL) {
            njt_http_close_connection(c);
            return;
        }

        b->pos = p;

        if (b->pos == b->last) {
            c->log->action = "waiting for request";
            b->pos = b->start;
            b->last = b->start;
            njt_post_event(rev, &njt_posted_events);
            return;
        }
    }

#if (NJT_HTTP_V2)

    h2scf = njt_http_get_module_srv_conf(hc->conf_ctx, njt_http_v2_module);

    if (!hc->ssl && (h2scf->enable || hc->addr_conf->http2)) {

        size = njt_min(sizeof(NJT_HTTP_V2_PREFACE) - 1,
                       (size_t) (b->last - b->pos));

        if (njt_memcmp(b->pos, NJT_HTTP_V2_PREFACE, size) == 0) {

            if (size == sizeof(NJT_HTTP_V2_PREFACE) - 1) {
                njt_http_v2_init(rev);
                return;
            }

            njt_post_event(rev, &njt_posted_events);
            return;
        }
    }

#endif

    c->log->action = "reading client request line";

    njt_reusable_connection(c, 0);

    c->data = njt_http_create_request(c);
    if (c->data == NULL) {
        njt_http_close_connection(c);
        return;
    }

    rev->handler = njt_http_process_request_line;
    njt_http_process_request_line(rev);
}


njt_http_request_t *
njt_http_create_request(njt_connection_t *c)
{
    njt_http_request_t        *r;
    njt_http_log_ctx_t        *ctx;
    njt_http_core_loc_conf_t  *clcf;

    r = njt_http_alloc_request(c);
    if (r == NULL) {
        return NULL;
    }

    c->requests++;

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    njt_set_connection_log(c, clcf->error_log);

    ctx = c->log->data;
    ctx->request = r;
    ctx->current_request = r;

#if (NJT_STAT_STUB)
    (void) njt_atomic_fetch_add(njt_stat_reading, 1);
    r->stat_reading = 1;
    (void) njt_atomic_fetch_add(njt_stat_requests, 1);
#endif

    return r;
}


static njt_http_request_t *
njt_http_alloc_request(njt_connection_t *c)
{
    njt_pool_t                 *pool;
    njt_time_t                 *tp;
    njt_http_request_t         *r;
    njt_http_connection_t      *hc;
    njt_http_core_srv_conf_t   *cscf;
    njt_http_core_main_conf_t  *cmcf;

    hc = c->data;

    cscf = njt_http_get_module_srv_conf(hc->conf_ctx, njt_http_core_module);

    pool = njt_create_pool(cscf->request_pool_size, c->log);
    if (pool == NULL) {
        return NULL;
    }

    r = njt_pcalloc(pool, sizeof(njt_http_request_t));
    if (r == NULL) {
        njt_destroy_pool(pool);
        return NULL;
    }

    r->pool = pool;

    r->http_connection = hc;
    r->signature = NJT_HTTP_MODULE;
    r->connection = c;

    r->main_conf = hc->conf_ctx->main_conf;
    r->srv_conf = hc->conf_ctx->srv_conf;
    r->loc_conf = hc->conf_ctx->loc_conf;

    r->read_event_handler = njt_http_block_reading;

    r->header_in = hc->busy ? hc->busy->buf : c->buffer;

    if (njt_list_init(&r->headers_out.headers, r->pool, 20,
                      sizeof(njt_table_elt_t))
        != NJT_OK)
    {
        njt_destroy_pool(r->pool);
        return NULL;
    }

    if (njt_list_init(&r->headers_out.trailers, r->pool, 4,
                      sizeof(njt_table_elt_t))
        != NJT_OK)
    {
        njt_destroy_pool(r->pool);
        return NULL;
    }

    r->ctx = njt_pcalloc(r->pool, sizeof(void *) * njt_http_max_module);
    if (r->ctx == NULL) {
        njt_destroy_pool(r->pool);
        return NULL;
    }

    cmcf = njt_http_get_module_main_conf(r, njt_http_core_module);

    r->variables = njt_pcalloc(r->pool, cmcf->variables.nelts
                                        * sizeof(njt_http_variable_value_t));
    if (r->variables == NULL) {
        njt_destroy_pool(r->pool);
        return NULL;
    }

#if (NJT_HTTP_SSL)
    if (c->ssl && !c->ssl->sendfile) {
        r->main_filter_need_in_memory = 1;
    }
#endif

    r->main = r;
    r->count = 1;

    tp = njt_timeofday();
    r->start_sec = tp->sec;
    r->start_msec = tp->msec;

    r->method = NJT_HTTP_UNKNOWN;
    r->http_version = NJT_HTTP_VERSION_10;

    r->headers_in.content_length_n = -1;
    r->headers_in.keep_alive_n = -1;
    r->headers_out.content_length_n = -1;
    r->headers_out.last_modified_time = -1;

    r->uri_changes = NJT_HTTP_MAX_URI_CHANGES + 1;
    r->subrequests = NJT_HTTP_MAX_SUBREQUESTS + 1;

    r->http_state = NJT_HTTP_READING_REQUEST_STATE;

    r->log_handler = njt_http_log_error_handler;

    return r;
}


#if (NJT_HTTP_SSL)

static void
njt_http_ssl_handshake(njt_event_t *rev)
{
    u_char                    *p, buf[NJT_PROXY_PROTOCOL_MAX_HEADER + 1];
    size_t                     size;
    ssize_t                    n;
    njt_err_t                  err;
    njt_int_t                  rc;
    njt_connection_t          *c;
    njt_http_connection_t     *hc;
    njt_http_ssl_srv_conf_t   *sscf;
    njt_http_core_loc_conf_t  *clcf;
    njt_http_core_srv_conf_t  *cscf;

    c = rev->data;
    hc = c->data;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, rev->log, 0,
                   "http check ssl handshake");

    if (rev->timedout) {
        njt_log_error(NJT_LOG_INFO, c->log, NJT_ETIMEDOUT, "client timed out");
        njt_http_close_connection(c);
        return;
    }

    if (c->close) {
        njt_http_close_connection(c);
        return;
    }

    size = hc->proxy_protocol ? sizeof(buf) : 1;

    n = recv(c->fd, (char *) buf, size, MSG_PEEK);

    err = njt_socket_errno;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, rev->log, 0, "http recv(): %z", n);

    if (n == -1) {
        if (err == NJT_EAGAIN) {
            rev->ready = 0;

            if (!rev->timer_set) {
                cscf = njt_http_get_module_srv_conf(hc->conf_ctx,
                                                    njt_http_core_module);
                njt_add_timer(rev, cscf->client_header_timeout);
                njt_reusable_connection(c, 1);
            }

            if (njt_handle_read_event(rev, 0) != NJT_OK) {
                njt_http_close_connection(c);
            }

            return;
        }

        njt_connection_error(c, err, "recv() failed");
        njt_http_close_connection(c);

        return;
    }

    if (hc->proxy_protocol) {
        hc->proxy_protocol = 0;

        p = njt_proxy_protocol_read(c, buf, buf + n);

        if (p == NULL) {
            njt_http_close_connection(c);
            return;
        }

        size = p - buf;

        if (c->recv(c, buf, size) != (ssize_t) size) {
            njt_http_close_connection(c);
            return;
        }

        c->log->action = "SSL handshaking";

        if (n == (ssize_t) size) {
            njt_post_event(rev, &njt_posted_events);
            return;
        }

        n = 1;
        buf[0] = *p;
    }

    if (n == 1) {
        if (buf[0] & 0x80 /* SSLv2 */ || buf[0] == 0x16 /* SSLv3/TLSv1 */) {
            njt_log_debug1(NJT_LOG_DEBUG_HTTP, rev->log, 0,
                           "https ssl handshake: 0x%02Xd", buf[0]);

            clcf = njt_http_get_module_loc_conf(hc->conf_ctx,
                                                njt_http_core_module);

            if (clcf->tcp_nodelay && njt_tcp_nodelay(c) != NJT_OK) {
                njt_http_close_connection(c);
                return;
            }

            sscf = njt_http_get_module_srv_conf(hc->conf_ctx,
                                                njt_http_ssl_module);

            if (njt_ssl_create_connection(&sscf->ssl, c, NJT_SSL_BUFFER)
                != NJT_OK)
            {
                njt_http_close_connection(c);
                return;
            }

#if (NJT_HAVE_NTLS)
            if (sscf->ntls) {
                SSL_enable_ntls(c->ssl->connection);
            }
#endif

            njt_reusable_connection(c, 0);

            rc = njt_ssl_handshake(c);

            if (rc == NJT_AGAIN) {

                if (!rev->timer_set) {
                    cscf = njt_http_get_module_srv_conf(hc->conf_ctx,
                                                        njt_http_core_module);
                    njt_add_timer(rev, cscf->client_header_timeout);
                }

                c->ssl->handler = njt_http_ssl_handshake_handler;
                return;
            }

            njt_http_ssl_handshake_handler(c);

            return;
        }

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, rev->log, 0, "plain http");

        c->log->action = "waiting for request";

        rev->handler = njt_http_wait_request_handler;
        njt_http_wait_request_handler(rev);

        return;
    }

    njt_log_error(NJT_LOG_INFO, c->log, 0, "client closed connection");
    njt_http_close_connection(c);
}


static void
njt_http_ssl_handshake_handler(njt_connection_t *c)
{
    if (c->ssl->handshaked) {

        /*
         * The majority of browsers do not send the "close notify" alert.
         * Among them are MSIE, old Mozilla, Netscape 4, Konqueror,
         * and Links.  And what is more, MSIE ignores the server's alert.
         *
         * Opera and recent Mozilla send the alert.
         */

        c->ssl->no_wait_shutdown = 1;

#if (NJT_HTTP_V2                                                              \
     && defined TLSEXT_TYPE_application_layer_protocol_negotiation)
        {
        unsigned int             len;
        const unsigned char     *data;
        njt_http_connection_t   *hc;
        njt_http_v2_srv_conf_t  *h2scf;

        hc = c->data;

        h2scf = njt_http_get_module_srv_conf(hc->conf_ctx, njt_http_v2_module);

        if (h2scf->enable || hc->addr_conf->http2) {

            SSL_get0_alpn_selected(c->ssl->connection, &data, &len);

            if (len == 2 && data[0] == 'h' && data[1] == '2') {
                njt_http_v2_init(c->read);
                return;
            }
        }
        }
#endif

        c->log->action = "waiting for request";

        c->read->handler = njt_http_wait_request_handler;
        /* STUB: epoll edge */ c->write->handler = njt_http_empty_handler;

        njt_reusable_connection(c, 1);

        njt_http_wait_request_handler(c->read);

        return;
    }

    if (c->read->timedout) {
        njt_log_error(NJT_LOG_INFO, c->log, NJT_ETIMEDOUT, "client timed out");
    }

    njt_http_close_connection(c);
}


#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

int
njt_http_ssl_servername(njt_ssl_conn_t *ssl_conn, int *ad, void *arg)
{
    njt_int_t                  rc;
    njt_str_t                  host;
    const char                *servername;
    njt_connection_t          *c;
    njt_http_connection_t     *hc;
    njt_http_ssl_srv_conf_t   *sscf;
    njt_http_core_loc_conf_t  *clcf;
    njt_http_core_srv_conf_t  *cscf;

    c = njt_ssl_get_connection(ssl_conn);

    if (c->ssl->handshaked) {
        *ad = SSL_AD_NO_RENEGOTIATION;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    hc = c->data;

    servername = SSL_get_servername(ssl_conn, TLSEXT_NAMETYPE_host_name);

    if (servername == NULL) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "SSL server name: null");
        goto done;
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "SSL server name: \"%s\"", servername);

    host.len = njt_strlen(servername);

    if (host.len == 0) {
        goto done;
    }

    host.data = (u_char *) servername;

    rc = njt_http_validate_host(&host, c->pool, 1);

    if (rc == NJT_ERROR) {
        goto error;
    }

    if (rc == NJT_DECLINED) {
        goto done;
    }

    rc = njt_http_find_virtual_server(c, hc->addr_conf->virtual_names, &host,
                                      NULL, &cscf);

    if (rc == NJT_ERROR) {
        goto error;
    }

    if (rc == NJT_DECLINED) {
        goto done;
    }

    hc->ssl_servername = njt_palloc(c->pool, sizeof(njt_str_t));
    if (hc->ssl_servername == NULL) {
        goto error;
    }

    *hc->ssl_servername = host;

    hc->conf_ctx = cscf->ctx;

    clcf = njt_http_get_module_loc_conf(hc->conf_ctx, njt_http_core_module);

    njt_set_connection_log(c, clcf->error_log);

    sscf = njt_http_get_module_srv_conf(hc->conf_ctx, njt_http_ssl_module);

    c->ssl->buffer_size = sscf->buffer_size;

    if (sscf->ssl.ctx) {
        if (SSL_set_SSL_CTX(ssl_conn, sscf->ssl.ctx) == NULL) {
            goto error;
        }

        /*
         * SSL_set_SSL_CTX() only changes certs as of 1.0.0d
         * adjust other things we care about
         */

        SSL_set_verify(ssl_conn, SSL_CTX_get_verify_mode(sscf->ssl.ctx),
                       SSL_CTX_get_verify_callback(sscf->ssl.ctx));

        SSL_set_verify_depth(ssl_conn, SSL_CTX_get_verify_depth(sscf->ssl.ctx));

#if OPENSSL_VERSION_NUMBER >= 0x009080dfL
        /* only in 0.9.8m+ */
        SSL_clear_options(ssl_conn, SSL_get_options(ssl_conn) &
                                    ~SSL_CTX_get_options(sscf->ssl.ctx));
#endif

        SSL_set_options(ssl_conn, SSL_CTX_get_options(sscf->ssl.ctx));

#ifdef SSL_OP_NO_RENEGOTIATION
        SSL_set_options(ssl_conn, SSL_OP_NO_RENEGOTIATION);
#endif
    }

#ifdef SSL_OP_ENABLE_MIDDLEBOX_COMPAT
#if (NJT_HTTP_V3)
        if (c->listening->quic) {
            SSL_clear_options(ssl_conn, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
        }
#endif
#endif

done:

    sscf = njt_http_get_module_srv_conf(hc->conf_ctx, njt_http_ssl_module);

    if (sscf->reject_handshake) {
        c->ssl->handshake_rejected = 1;
        *ad = SSL_AD_UNRECOGNIZED_NAME;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    return SSL_TLSEXT_ERR_OK;

error:

    *ad = SSL_AD_INTERNAL_ERROR;
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

#endif


#ifdef SSL_R_CERT_CB_ERROR

int
njt_http_ssl_certificate(njt_ssl_conn_t *ssl_conn, void *arg)
{
    njt_str_t                  cert, key;
    njt_uint_t                 i, nelts;
    njt_connection_t          *c;
    njt_http_request_t        *r;
    njt_http_ssl_srv_conf_t   *sscf;
    njt_http_complex_value_t  *certs, *keys;

    c = njt_ssl_get_connection(ssl_conn);

    if (c->ssl->handshaked) {
        return 0;
    }

    r = njt_http_alloc_request(c);
    if (r == NULL) {
        return 0;
    }

    r->logged = 1;

    sscf = arg;

    nelts = sscf->certificate_values->nelts;
    certs = sscf->certificate_values->elts;
    keys = sscf->certificate_key_values->elts;

    for (i = 0; i < nelts; i++) {

        if (njt_http_complex_value(r, &certs[i], &cert) != NJT_OK) {
            goto failed;
        }

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "ssl cert: \"%s\"", cert.data);

        if (njt_http_complex_value(r, &keys[i], &key) != NJT_OK) {
            goto failed;
        }

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "ssl key: \"%s\"", key.data);

        if (njt_ssl_connection_certificate(c, r->pool, &cert, &key,
                                           sscf->passwords)
            != NJT_OK)
        {
            goto failed;
        }
    }

    njt_http_free_request(r, 0);
    c->log->action = "SSL handshaking";
    c->destroyed = 0;
    return 1;

failed:

    njt_http_free_request(r, 0);
    c->log->action = "SSL handshaking";
    c->destroyed = 0;
    return 0;
}

#endif

#endif


static void
njt_http_process_request_line(njt_event_t *rev)
{
    ssize_t              n;
    njt_int_t            rc, rv;
    njt_str_t            host;
    njt_connection_t    *c;
    njt_http_request_t  *r;

    c = rev->data;
    r = c->data;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, rev->log, 0,
                   "http process request line");

    if (rev->timedout) {
        njt_log_error(NJT_LOG_INFO, c->log, NJT_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        njt_http_close_request(r, NJT_HTTP_REQUEST_TIME_OUT);
        return;
    }

    rc = NJT_AGAIN;

    for ( ;; ) {

        if (rc == NJT_AGAIN) {
            n = njt_http_read_request_header(r);

            if (n == NJT_AGAIN || n == NJT_ERROR) {
                break;
            }
        }

        rc = njt_http_parse_request_line(r, r->header_in);

        if (rc == NJT_OK) {

            /* the request line has been parsed successfully */

            r->request_line.len = r->request_end - r->request_start;
            r->request_line.data = r->request_start;
            r->request_length = r->header_in->pos - r->request_start;

            njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                           "http request line: \"%V\"", &r->request_line);

            r->method_name.len = r->method_end - r->request_start + 1;
            r->method_name.data = r->request_line.data;

            if (r->http_protocol.data) {
                r->http_protocol.len = r->request_end - r->http_protocol.data;
            }

//add by clb
#if (NJT_HTTP_PROXY_CONNECT)

            if (r->connect_host_start && r->connect_host_end) {

                host.len = r->connect_host_end - r->connect_host_start;
                host.data = r->connect_host_start;
                rc = njt_http_validate_host(&host, r->pool, 0);

                if (rc == NJT_DECLINED) {
                    njt_log_error(NJT_LOG_INFO, c->log, 0,
                                  "client sent invalid host in request line");
                    njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);
                    return;
                }

                if (rc == NJT_ERROR) {
                    njt_http_close_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
                    return;
                }

                r->connect_host = host;

                if (!r->connect_port_end) {
                   njt_log_error(NJT_LOG_INFO, c->log, 0,
                                  "client sent no port in request line");
                    njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);
                    return;
                }

                r->connect_port.data = r->connect_host_end + 1;
                r->connect_port.len = r->connect_port_end
                                      - r->connect_host_end - 1;

                njt_int_t port;

                port = njt_atoi(r->connect_port.data, r->connect_port.len);
                if (port == NJT_ERROR || port < 1 || port > 65535) {
                    njt_log_error(NJT_LOG_INFO, c->log, 0,
                                  "client sent invalid port in request line");
                    njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);
                    return;
                }

                r->connect_port_n = port;

                /* skip processing request uri */
            } else
#endif

            if (njt_http_process_request_uri(r) != NJT_OK) {
                break;
            }

            if (r->schema_end) {
                r->schema.len = r->schema_end - r->schema_start;
                r->schema.data = r->schema_start;
            }

            if (r->host_end) {

                host.len = r->host_end - r->host_start;
                host.data = r->host_start;

                rc = njt_http_validate_host(&host, r->pool, 0);

                if (rc == NJT_DECLINED) {
                    njt_log_error(NJT_LOG_INFO, c->log, 0,
                                  "client sent invalid host in request line");
                    njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);
                    break;
                }

                if (rc == NJT_ERROR) {
                    njt_http_close_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
                    break;
                }

                if (njt_http_set_virtual_server(r, &host) == NJT_ERROR) {
                    break;
                }

                r->headers_in.server = host;
            }

            if (r->http_version < NJT_HTTP_VERSION_10) {

                if (r->headers_in.server.len == 0
                    && njt_http_set_virtual_server(r, &r->headers_in.server)
                       == NJT_ERROR)
                {
                    break;
                }

                njt_http_process_request(r);
                break;
            }


            if (njt_list_init(&r->headers_in.headers, r->pool, 20,
                              sizeof(njt_table_elt_t))
                != NJT_OK)
            {
                njt_http_close_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
                break;
            }

            c->log->action = "reading client request headers";

            rev->handler = njt_http_process_request_headers;
            njt_http_process_request_headers(rev);

            break;
        }

        if (rc != NJT_AGAIN) {

            /* there was error while a request line parsing */

            njt_log_error(NJT_LOG_INFO, c->log, 0,
                          njt_http_client_errors[rc - NJT_HTTP_CLIENT_ERROR]);

            if (rc == NJT_HTTP_PARSE_INVALID_VERSION) {
                njt_http_finalize_request(r, NJT_HTTP_VERSION_NOT_SUPPORTED);

            } else {
                njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);
            }

            break;
        }

        /* NJT_AGAIN: a request line parsing is still incomplete */

        if (r->header_in->pos == r->header_in->end) {

            rv = njt_http_alloc_large_header_buffer(r, 1);

            if (rv == NJT_ERROR) {
                njt_http_close_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
                break;
            }

            if (rv == NJT_DECLINED) {
                r->request_line.len = r->header_in->end - r->request_start;
                r->request_line.data = r->request_start;

                njt_log_error(NJT_LOG_INFO, c->log, 0,
                              "client sent too long URI");
                njt_http_finalize_request(r, NJT_HTTP_REQUEST_URI_TOO_LARGE);
                break;
            }
        }
    }

    njt_http_run_posted_requests(c);
}


njt_int_t
njt_http_process_request_uri(njt_http_request_t *r)
{
    njt_http_core_srv_conf_t  *cscf;

    if (r->args_start) {
        r->uri.len = r->args_start - 1 - r->uri_start;
    } else {
        r->uri.len = r->uri_end - r->uri_start;
    }

    if (r->complex_uri || r->quoted_uri || r->empty_path_in_uri) {

        if (r->empty_path_in_uri) {
            r->uri.len++;
        }

        r->uri.data = njt_pnalloc(r->pool, r->uri.len);
        if (r->uri.data == NULL) {
            njt_http_close_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
            return NJT_ERROR;
        }

        cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);

        if (njt_http_parse_complex_uri(r, cscf->merge_slashes) != NJT_OK) {
            r->uri.len = 0;

            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "client sent invalid request");
            njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);
            return NJT_ERROR;
        }

    } else {
        r->uri.data = r->uri_start;
    }

    r->unparsed_uri.len = r->uri_end - r->uri_start;
    r->unparsed_uri.data = r->uri_start;

    r->valid_unparsed_uri = r->empty_path_in_uri ? 0 : 1;

    if (r->uri_ext) {
        if (r->args_start) {
            r->exten.len = r->args_start - 1 - r->uri_ext;
        } else {
            r->exten.len = r->uri_end - r->uri_ext;
        }

        r->exten.data = r->uri_ext;
    }

    if (r->args_start && r->uri_end > r->args_start) {
        r->args.len = r->uri_end - r->args_start;
        r->args.data = r->args_start;
    }

#if (NJT_WIN32)
    {
    u_char  *p, *last;

    p = r->uri.data;
    last = r->uri.data + r->uri.len;

    while (p < last) {

        if (*p++ == ':') {

            /*
             * this check covers "::$data", "::$index_allocation" and
             * ":$i30:$index_allocation"
             */

            if (p < last && *p == '$') {
                njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                              "client sent unsafe win32 URI");
                njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);
                return NJT_ERROR;
            }
        }
    }

    p = r->uri.data + r->uri.len - 1;

    while (p > r->uri.data) {

        if (*p == ' ') {
            p--;
            continue;
        }

        if (*p == '.') {
            p--;
            continue;
        }

        break;
    }

    if (p != r->uri.data + r->uri.len - 1) {
        r->uri.len = p + 1 - r->uri.data;
        njt_http_set_exten(r);
    }

    }
#endif

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http uri: \"%V\"", &r->uri);

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http args: \"%V\"", &r->args);

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http exten: \"%V\"", &r->exten);

    return NJT_OK;
}


static void
njt_http_process_request_headers(njt_event_t *rev)
{
    u_char                     *p;
    size_t                      len;
    ssize_t                     n;
    njt_int_t                   rc, rv;
    njt_table_elt_t            *h;
    njt_connection_t           *c;
    njt_http_header_t          *hh;
    njt_http_request_t         *r;
    njt_http_core_srv_conf_t   *cscf;
    njt_http_core_main_conf_t  *cmcf;

    c = rev->data;
    r = c->data;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, rev->log, 0,
                   "http process request header line");

    if (rev->timedout) {
        njt_log_error(NJT_LOG_INFO, c->log, NJT_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        njt_http_close_request(r, NJT_HTTP_REQUEST_TIME_OUT);
        return;
    }

    cmcf = njt_http_get_module_main_conf(r, njt_http_core_module);

    rc = NJT_AGAIN;

    for ( ;; ) {

        if (rc == NJT_AGAIN) {

            if (r->header_in->pos == r->header_in->end) {

                rv = njt_http_alloc_large_header_buffer(r, 0);

                if (rv == NJT_ERROR) {
                    njt_http_close_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
                    break;
                }

                if (rv == NJT_DECLINED) {
                    p = r->header_name_start;

                    r->lingering_close = 1;

                    if (p == NULL) {
                        njt_log_error(NJT_LOG_INFO, c->log, 0,
                                      "client sent too large request");
                        njt_http_finalize_request(r,
                                            NJT_HTTP_REQUEST_HEADER_TOO_LARGE);
                        break;
                    }

                    len = r->header_in->end - p;

                    if (len > NJT_MAX_ERROR_STR - 300) {
                        len = NJT_MAX_ERROR_STR - 300;
                    }

                    njt_log_error(NJT_LOG_INFO, c->log, 0,
                                "client sent too long header line: \"%*s...\"",
                                len, r->header_name_start);

                    njt_http_finalize_request(r,
                                            NJT_HTTP_REQUEST_HEADER_TOO_LARGE);
                    break;
                }
            }

            n = njt_http_read_request_header(r);

            if (n == NJT_AGAIN || n == NJT_ERROR) {
                break;
            }
        }

        /* the host header could change the server configuration context */
        cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);

        rc = njt_http_parse_header_line(r, r->header_in,
                                        cscf->underscores_in_headers);

        if (rc == NJT_OK) {

            r->request_length += r->header_in->pos - r->header_name_start;

            if (r->invalid_header && cscf->ignore_invalid_headers) {

                /* there was error while a header line parsing */

                njt_log_error(NJT_LOG_INFO, c->log, 0,
                              "client sent invalid header line: \"%*s\"",
                              r->header_end - r->header_name_start,
                              r->header_name_start);
                continue;
            }

            /* a header line has been parsed successfully */

            h = njt_list_push(&r->headers_in.headers);
            if (h == NULL) {
                njt_http_close_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
                break;
            }

            h->hash = r->header_hash;

            h->key.len = r->header_name_end - r->header_name_start;
            h->key.data = r->header_name_start;
            h->key.data[h->key.len] = '\0';

            h->value.len = r->header_end - r->header_start;
            h->value.data = r->header_start;
            h->value.data[h->value.len] = '\0';

            h->lowcase_key = njt_pnalloc(r->pool, h->key.len);
            if (h->lowcase_key == NULL) {
                njt_http_close_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
                break;
            }

            if (h->key.len == r->lowcase_index) {
                njt_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

            } else {
                njt_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            hh = njt_hash_find(&cmcf->headers_in_hash, h->hash,
                               h->lowcase_key, h->key.len);

            if (hh && hh->handler(r, h, hh->offset) != NJT_OK) {
                break;
            }

            njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http header: \"%V: %V\"",
                           &h->key, &h->value);

            continue;
        }

        if (rc == NJT_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http header done");

            r->request_length += r->header_in->pos - r->header_name_start;

            r->http_state = NJT_HTTP_PROCESS_REQUEST_STATE;

            rc = njt_http_process_request_header(r);

            if (rc != NJT_OK) {
                break;
            }

            njt_http_process_request(r);

            break;
        }

        if (rc == NJT_AGAIN) {

            /* a header line parsing is still not complete */

            continue;
        }

        /* rc == NJT_HTTP_PARSE_INVALID_HEADER */

        njt_log_error(NJT_LOG_INFO, c->log, 0,
                      "client sent invalid header line: \"%*s\\x%02xd...\"",
                      r->header_end - r->header_name_start,
                      r->header_name_start, *r->header_end);

        njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);
        break;
    }

    njt_http_run_posted_requests(c);
}


static ssize_t
njt_http_read_request_header(njt_http_request_t *r)
{
    ssize_t                    n;
    njt_event_t               *rev;
    njt_connection_t          *c;
    njt_http_core_srv_conf_t  *cscf;

    c = r->connection;
    rev = c->read;

    n = r->header_in->last - r->header_in->pos;

    if (n > 0) {
        return n;
    }

    if (rev->ready) {
        n = c->recv(c, r->header_in->last,
                    r->header_in->end - r->header_in->last);
    } else {
        n = NJT_AGAIN;
    }

    if (n == NJT_AGAIN) {
        if (!rev->timer_set) {
            cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);
            njt_add_timer(rev, cscf->client_header_timeout);
        }

        if (njt_handle_read_event(rev, 0) != NJT_OK) {
            njt_http_close_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
            return NJT_ERROR;
        }

        return NJT_AGAIN;
    }

    if (n == 0) {
        njt_log_error(NJT_LOG_INFO, c->log, 0,
                      "client prematurely closed connection");
    }

    if (n == 0 || n == NJT_ERROR) {
        c->error = 1;
        c->log->action = "reading client request headers";

        njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);
        return NJT_ERROR;
    }

    r->header_in->last += n;

    return n;
}


static njt_int_t
njt_http_alloc_large_header_buffer(njt_http_request_t *r,
    njt_uint_t request_line)
{
    u_char                    *old, *new;
    njt_buf_t                 *b;
    njt_chain_t               *cl;
    njt_http_connection_t     *hc;
    njt_http_core_srv_conf_t  *cscf;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http alloc large header buffer");

    if (request_line && r->state == 0) {

        /* the client fills up the buffer with "\r\n" */

        r->header_in->pos = r->header_in->start;
        r->header_in->last = r->header_in->start;

        return NJT_OK;
    }

    old = request_line ? r->request_start : r->header_name_start;

    cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);

    if (r->state != 0
        && (size_t) (r->header_in->pos - old)
                                     >= cscf->large_client_header_buffers.size)
    {
        return NJT_DECLINED;
    }

    hc = r->http_connection;

    if (hc->free) {
        cl = hc->free;
        hc->free = cl->next;

        b = cl->buf;

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http large header free: %p %uz",
                       b->pos, b->end - b->last);

    } else if (hc->nbusy < cscf->large_client_header_buffers.num) {

        b = njt_create_temp_buf(r->connection->pool,
                                cscf->large_client_header_buffers.size);
        if (b == NULL) {
            return NJT_ERROR;
        }

        cl = njt_alloc_chain_link(r->connection->pool);
        if (cl == NULL) {
            return NJT_ERROR;
        }

        cl->buf = b;

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http large header alloc: %p %uz",
                       b->pos, b->end - b->last);

    } else {
        return NJT_DECLINED;
    }

    cl->next = hc->busy;
    hc->busy = cl;
    hc->nbusy++;

    if (r->state == 0) {
        /*
         * r->state == 0 means that a header line was parsed successfully
         * and we do not need to copy incomplete header line and
         * to relocate the parser header pointers
         */

        r->header_in = b;

        return NJT_OK;
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http large header copy: %uz", r->header_in->pos - old);

    if (r->header_in->pos - old > b->end - b->start) {
        njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
                      "too large header to copy");
        return NJT_ERROR;
    }

    new = b->start;

    njt_memcpy(new, old, r->header_in->pos - old);

    b->pos = new + (r->header_in->pos - old);
    b->last = new + (r->header_in->pos - old);

    if (request_line) {
        r->request_start = new;

        if (r->request_end) {
            r->request_end = new + (r->request_end - old);
        }

        r->method_end = new + (r->method_end - old);

        r->uri_start = new + (r->uri_start - old);
        r->uri_end = new + (r->uri_end - old);

        if (r->schema_start) {
            r->schema_start = new + (r->schema_start - old);
            r->schema_end = new + (r->schema_end - old);
        }

//add by clb
#if (NJT_HTTP_PROXY_CONNECT)
        if (r->connect_host_start) {
            r->connect_host_start = new + (r->connect_host_start - old);
            if (r->connect_host_end) {
                r->connect_host_end = new + (r->connect_host_end - old);
            }

            if (r->connect_port_end) {
                r->connect_port_end = new + (r->connect_port_end - old);
            }
        }
#endif

        if (r->host_start) {
            r->host_start = new + (r->host_start - old);
            if (r->host_end) {
                r->host_end = new + (r->host_end - old);
            }
        }

        if (r->port_start) {
            r->port_start = new + (r->port_start - old);
            r->port_end = new + (r->port_end - old);
        }

        if (r->uri_ext) {
            r->uri_ext = new + (r->uri_ext - old);
        }

        if (r->args_start) {
            r->args_start = new + (r->args_start - old);
        }

        if (r->http_protocol.data) {
            r->http_protocol.data = new + (r->http_protocol.data - old);
        }

    } else {
        r->header_name_start = new;
        r->header_name_end = new + (r->header_name_end - old);
        r->header_start = new + (r->header_start - old);
        r->header_end = new + (r->header_end - old);
    }

    r->header_in = b;

    return NJT_OK;
}


static njt_int_t
njt_http_process_header_line(njt_http_request_t *r, njt_table_elt_t *h,
    njt_uint_t offset)
{
    njt_table_elt_t  **ph;

    ph = (njt_table_elt_t **) ((char *) &r->headers_in + offset);

    while (*ph) { ph = &(*ph)->next; }

    *ph = h;
    h->next = NULL;

    return NJT_OK;
}


static njt_int_t
njt_http_process_unique_header_line(njt_http_request_t *r, njt_table_elt_t *h,
    njt_uint_t offset)
{
    njt_table_elt_t  **ph;

    ph = (njt_table_elt_t **) ((char *) &r->headers_in + offset);

    if (*ph == NULL) {
        *ph = h;
        h->next = NULL;
        return NJT_OK;
    }

    njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                  "client sent duplicate header line: \"%V: %V\", "
                  "previous value: \"%V: %V\"",
                  &h->key, &h->value, &(*ph)->key, &(*ph)->value);

    njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);

    return NJT_ERROR;
}


static njt_int_t
njt_http_process_host(njt_http_request_t *r, njt_table_elt_t *h,
    njt_uint_t offset)
{
    njt_int_t  rc;
    njt_str_t  host;

    if (r->headers_in.host) {
        njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                      "client sent duplicate host header: \"%V: %V\", "
                      "previous value: \"%V: %V\"",
                      &h->key, &h->value, &r->headers_in.host->key,
                      &r->headers_in.host->value);
        njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);
        return NJT_ERROR;
    }

    r->headers_in.host = h;
    h->next = NULL;

    host = h->value;

    rc = njt_http_validate_host(&host, r->pool, 0);

    if (rc == NJT_DECLINED) {
        njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                      "client sent invalid host header");
        njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);
        return NJT_ERROR;
    }

    if (rc == NJT_ERROR) {
        njt_http_close_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return NJT_ERROR;
    }

    if (r->headers_in.server.len) {
        return NJT_OK;
    }

    if (njt_http_set_virtual_server(r, &host) == NJT_ERROR) {
        return NJT_ERROR;
    }

    r->headers_in.server = host;

    return NJT_OK;
}


static njt_int_t
njt_http_process_connection(njt_http_request_t *r, njt_table_elt_t *h,
    njt_uint_t offset)
{
    if (njt_http_process_header_line(r, h, offset) != NJT_OK) {
        return NJT_ERROR;
    }

    if (njt_strcasestrn(h->value.data, "close", 5 - 1)) {
        r->headers_in.connection_type = NJT_HTTP_CONNECTION_CLOSE;

    } else if (njt_strcasestrn(h->value.data, "keep-alive", 10 - 1)) {
        r->headers_in.connection_type = NJT_HTTP_CONNECTION_KEEP_ALIVE;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_process_user_agent(njt_http_request_t *r, njt_table_elt_t *h,
    njt_uint_t offset)
{
    u_char  *user_agent, *msie;

    if (njt_http_process_header_line(r, h, offset) != NJT_OK) {
        return NJT_ERROR;
    }

    /* check some widespread browsers while the header is in CPU cache */

    user_agent = h->value.data;

    msie = njt_strstrn(user_agent, "MSIE ", 5 - 1);

    if (msie && msie + 7 < user_agent + h->value.len) {

        r->headers_in.msie = 1;

        if (msie[6] == '.') {

            switch (msie[5]) {
            case '4':
            case '5':
                r->headers_in.msie6 = 1;
                break;
            case '6':
                if (njt_strstrn(msie + 8, "SV1", 3 - 1) == NULL) {
                    r->headers_in.msie6 = 1;
                }
                break;
            }
        }

#if 0
        /* MSIE ignores the SSL "close notify" alert */
        if (c->ssl) {
            c->ssl->no_send_shutdown = 1;
        }
#endif
    }

    if (njt_strstrn(user_agent, "Opera", 5 - 1)) {
        r->headers_in.opera = 1;
        r->headers_in.msie = 0;
        r->headers_in.msie6 = 0;
    }

    if (!r->headers_in.msie && !r->headers_in.opera) {

        if (njt_strstrn(user_agent, "Gecko/", 6 - 1)) {
            r->headers_in.gecko = 1;

        } else if (njt_strstrn(user_agent, "Chrome/", 7 - 1)) {
            r->headers_in.chrome = 1;

        } else if (njt_strstrn(user_agent, "Safari/", 7 - 1)
                   && njt_strstrn(user_agent, "Mac OS X", 8 - 1))
        {
            r->headers_in.safari = 1;

        } else if (njt_strstrn(user_agent, "Konqueror", 9 - 1)) {
            r->headers_in.konqueror = 1;
        }
    }

    return NJT_OK;
}


njt_int_t
njt_http_process_request_header(njt_http_request_t *r)
{
    if (r->headers_in.server.len == 0
        && njt_http_set_virtual_server(r, &r->headers_in.server)
           == NJT_ERROR)
    {
        return NJT_ERROR;
    }

    if (r->headers_in.host == NULL && r->http_version > NJT_HTTP_VERSION_10) {
        njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                   "client sent HTTP/1.1 request without \"Host\" header");
        njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);
        return NJT_ERROR;
    }

    if (r->headers_in.content_length) {
        r->headers_in.content_length_n =
                            njt_atoof(r->headers_in.content_length->value.data,
                                      r->headers_in.content_length->value.len);

        if (r->headers_in.content_length_n == NJT_ERROR) {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "client sent invalid \"Content-Length\" header");
            njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);
            return NJT_ERROR;
        }
    }

    if (r->headers_in.transfer_encoding) {
        if (r->http_version < NJT_HTTP_VERSION_11) {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "client sent HTTP/1.0 request with "
                          "\"Transfer-Encoding\" header");
            njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);
            return NJT_ERROR;
        }

        if (r->headers_in.transfer_encoding->value.len == 7
            && njt_strncasecmp(r->headers_in.transfer_encoding->value.data,
                               (u_char *) "chunked", 7) == 0)
        {
            if (r->headers_in.content_length) {
                njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                              "client sent \"Content-Length\" and "
                              "\"Transfer-Encoding\" headers "
                              "at the same time");
                njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);
                return NJT_ERROR;
            }

            r->headers_in.chunked = 1;

        } else {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "client sent unknown \"Transfer-Encoding\": \"%V\"",
                          &r->headers_in.transfer_encoding->value);
            njt_http_finalize_request(r, NJT_HTTP_NOT_IMPLEMENTED);
            return NJT_ERROR;
        }
    }

    if (r->headers_in.connection_type == NJT_HTTP_CONNECTION_KEEP_ALIVE) {
        if (r->headers_in.keep_alive) {
            r->headers_in.keep_alive_n =
                            njt_atotm(r->headers_in.keep_alive->value.data,
                                      r->headers_in.keep_alive->value.len);
        }
    }

//mod by clb, for add proxy_connect
#if (NJT_HTTP_PROXY_CONNECT)

#else
    if (r->method == NJT_HTTP_CONNECT) {
        njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                      "client sent CONNECT method");
        njt_http_finalize_request(r, NJT_HTTP_NOT_ALLOWED);
        return NJT_ERROR;
    }
#endif

    if (r->method == NJT_HTTP_TRACE) {
        njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                      "client sent TRACE method");
        njt_http_finalize_request(r, NJT_HTTP_NOT_ALLOWED);
        return NJT_ERROR;
    }

    return NJT_OK;
}


void
njt_http_process_request(njt_http_request_t *r)
{
    njt_connection_t  *c;

    c = r->connection;

#if (NJT_HTTP_SSL)

    if (r->http_connection->ssl) {
        long                      rc;
        X509                     *cert;
        const char               *s;
        njt_http_ssl_srv_conf_t  *sscf;

        if (c->ssl == NULL) {
            njt_log_error(NJT_LOG_INFO, c->log, 0,
                          "client sent plain HTTP request to HTTPS port");
            njt_http_finalize_request(r, NJT_HTTP_TO_HTTPS);
            return;
        }

        sscf = njt_http_get_module_srv_conf(r, njt_http_ssl_module);

        if (sscf->verify) {
            rc = SSL_get_verify_result(c->ssl->connection);

            if (rc != X509_V_OK
                && (sscf->verify != 3 || !njt_ssl_verify_error_optional(rc)))
            {
                njt_log_error(NJT_LOG_INFO, c->log, 0,
                              "client SSL certificate verify error: (%l:%s)",
                              rc, X509_verify_cert_error_string(rc));

                njt_ssl_remove_cached_session(c->ssl->session_ctx,
                                       (SSL_get0_session(c->ssl->connection)));

                njt_http_finalize_request(r, NJT_HTTPS_CERT_ERROR);
                return;
            }

            if (sscf->verify == 1) {
                cert = SSL_get_peer_certificate(c->ssl->connection);

                if (cert == NULL) {
                    njt_log_error(NJT_LOG_INFO, c->log, 0,
                                  "client sent no required SSL certificate");

                    njt_ssl_remove_cached_session(c->ssl->session_ctx,
                                       (SSL_get0_session(c->ssl->connection)));

                    njt_http_finalize_request(r, NJT_HTTPS_NO_CERT);
                    return;
                }

                X509_free(cert);
            }

            if (njt_ssl_ocsp_get_status(c, &s) != NJT_OK) {
                njt_log_error(NJT_LOG_INFO, c->log, 0,
                              "client SSL certificate verify error: %s", s);

                njt_ssl_remove_cached_session(c->ssl->session_ctx,
                                       (SSL_get0_session(c->ssl->connection)));

                njt_http_finalize_request(r, NJT_HTTPS_CERT_ERROR);
                return;
            }
        }
    }

#endif

    if (c->read->timer_set) {
        njt_del_timer(c->read);
    }

#if (NJT_STAT_STUB)
    (void) njt_atomic_fetch_add(njt_stat_reading, -1);
    r->stat_reading = 0;
    (void) njt_atomic_fetch_add(njt_stat_writing, 1);
    r->stat_writing = 1;
#endif

    c->read->handler = njt_http_request_handler;
    c->write->handler = njt_http_request_handler;
    r->read_event_handler = njt_http_block_reading;

    njt_http_handler(r);
}


njt_int_t
njt_http_validate_host(njt_str_t *host, njt_pool_t *pool, njt_uint_t alloc)
{
    u_char  *h, ch;
    size_t   i, dot_pos, host_len;

    enum {
        sw_usual = 0,
        sw_literal,
        sw_rest
    } state;

    dot_pos = host->len;
    host_len = host->len;

    h = host->data;

    state = sw_usual;

    for (i = 0; i < host->len; i++) {
        ch = h[i];

        switch (ch) {

        case '.':
            if (dot_pos == i - 1) {
                return NJT_DECLINED;
            }
            dot_pos = i;
            break;

        case ':':
            if (state == sw_usual) {
                host_len = i;
                state = sw_rest;
            }
            break;

        case '[':
            if (i == 0) {
                state = sw_literal;
            }
            break;

        case ']':
            if (state == sw_literal) {
                host_len = i + 1;
                state = sw_rest;
            }
            break;

        default:

            if (njt_path_separator(ch)) {
                return NJT_DECLINED;
            }

            if (ch <= 0x20 || ch == 0x7f) {
                return NJT_DECLINED;
            }

            if (ch >= 'A' && ch <= 'Z') {
                alloc = 1;
            }

            break;
        }
    }

    if (dot_pos == host_len - 1) {
        host_len--;
    }

    if (host_len == 0) {
        return NJT_DECLINED;
    }

    if (alloc) {
        host->data = njt_pnalloc(pool, host_len);
        if (host->data == NULL) {
            return NJT_ERROR;
        }

        njt_strlow(host->data, h, host_len);
    }

    host->len = host_len;

    return NJT_OK;
}



njt_int_t
njt_http_set_virtual_server(njt_http_request_t *r, njt_str_t *host)
{
    njt_int_t                  rc;
    njt_http_connection_t     *hc;
    njt_http_core_loc_conf_t  *clcf;
    njt_http_core_srv_conf_t  *cscf;

#if (NJT_SUPPRESS_WARN)
    cscf = NULL;
#endif

    hc = r->http_connection;

#if (NJT_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)

    if (hc->ssl_servername) {
        if (hc->ssl_servername->len == host->len
            && njt_strncmp(hc->ssl_servername->data,
                           host->data, host->len) == 0)
        {
#if (NJT_PCRE)
            if (hc->ssl_servername_regex
                && njt_http_regex_exec(r, hc->ssl_servername_regex,
                                          hc->ssl_servername) != NJT_OK)
            {
                njt_http_close_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
                return NJT_ERROR;
            }
#endif
            return NJT_OK;
        }
    }

#endif
   //njt_log_error(NJT_LOG_INFO, r->connection->log, 0,"hc->addr_conf->virtual_names=%p,addr_conf=%p",hc->addr_conf->virtual_names,hc->addr_conf);
    rc = njt_http_find_virtual_server(r->connection,
                                      hc->addr_conf->virtual_names,
                                      host, r, &cscf);

    if (rc == NJT_ERROR) {
        njt_http_close_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return NJT_ERROR;
    }

#if (NJT_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)

    if (hc->ssl_servername) {
        njt_http_ssl_srv_conf_t  *sscf;

        if (rc == NJT_DECLINED) {
            cscf = hc->addr_conf->default_server;
            rc = NJT_OK;
        }

        sscf = njt_http_get_module_srv_conf(cscf->ctx, njt_http_ssl_module);

        if (sscf->verify) {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "client attempted to request the server name "
                          "different from the one that was negotiated");
            njt_http_finalize_request(r, NJT_HTTP_MISDIRECTED_REQUEST);
            return NJT_ERROR;
        }
    }

#endif

    if (rc == NJT_DECLINED) {
        return NJT_OK;
    }

    r->srv_conf = cscf->ctx->srv_conf;
    r->loc_conf = cscf->ctx->loc_conf;

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    njt_set_connection_log(r->connection, clcf->error_log);

#if (NJT_HTTP_DYNAMIC_SERVER)
     njt_pool_cleanup_t   *cln;
     u_char *pt;
    cln = njt_pool_cleanup_add(r->main->pool,sizeof(njt_http_core_srv_conf_t *) + sizeof(njt_http_request_t *));
     if (cln == NULL) {
             njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
             return NJT_OK;
    }
    cln->handler = njt_http_core_free_srv_ctx;
    pt = cln->data;
    njt_memcpy(pt,&cscf,sizeof(njt_http_core_srv_conf_t *));
    njt_memcpy(pt+sizeof(njt_http_core_srv_conf_t *),&r->main,sizeof(njt_http_request_t *));
    cscf->ref_count ++;

#endif 

    return NJT_OK;
}


static njt_int_t
njt_http_find_virtual_server(njt_connection_t *c,
    njt_http_virtual_names_t *virtual_names, njt_str_t *host,
    njt_http_request_t *r, njt_http_core_srv_conf_t **cscfp)
{
    njt_http_core_srv_conf_t  *cscf;

    if (virtual_names == NULL) {
        return NJT_DECLINED;
    }

    cscf = njt_hash_find_combined(&virtual_names->names,
                                  njt_hash_key(host->data, host->len),
                                  host->data, host->len);

    if (cscf) {
        *cscfp = cscf;
        return NJT_OK;
    }

#if (NJT_PCRE)

    if (host->len && virtual_names->nregex) {
        njt_int_t                n;
        njt_uint_t               i;
        njt_http_server_name_t  *sn;

        sn = virtual_names->regex;

#if (NJT_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)

        if (r == NULL) {
            njt_http_connection_t  *hc;

            for (i = 0; i < virtual_names->nregex; i++) {

                n = njt_regex_exec(sn[i].regex->regex, host, NULL, 0);

                if (n == NJT_REGEX_NO_MATCHED) {
                    continue;
                }

                if (n >= 0) {
                    hc = c->data;
                    hc->ssl_servername_regex = sn[i].regex;

                    *cscfp = sn[i].server;
                    return NJT_OK;
                }

                njt_log_error(NJT_LOG_ALERT, c->log, 0,
                              njt_regex_exec_n " failed: %i "
                              "on \"%V\" using \"%V\"",
                              n, host, &sn[i].regex->name);

                return NJT_ERROR;
            }

            return NJT_DECLINED;
        }

#endif /* NJT_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME */

        for (i = 0; i < virtual_names->nregex; i++) {

            n = njt_http_regex_exec(r, sn[i].regex, host);

            if (n == NJT_DECLINED) {
                continue;
            }

            if (n == NJT_OK) {
                *cscfp = sn[i].server;
                return NJT_OK;
            }

            return NJT_ERROR;
        }
    }

#endif /* NJT_PCRE */

    return NJT_DECLINED;
}


static void
njt_http_request_handler(njt_event_t *ev)
{
    njt_connection_t    *c;
    njt_http_request_t  *r;

    c = ev->data;
    r = c->data;

    njt_http_set_log_request(c->log, r);

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http run request: \"%V?%V\"", &r->uri, &r->args);

    if (c->close) {
        r->main->count++;
        njt_http_terminate_request(r, 0);
        njt_http_run_posted_requests(c);
        return;
    }

    if (ev->delayed && ev->timedout) {
        ev->delayed = 0;
        ev->timedout = 0;
    }

    if (ev->write) {
        r->write_event_handler(r);

    } else {
        r->read_event_handler(r);
    }

    njt_http_run_posted_requests(c);
}


void
njt_http_run_posted_requests(njt_connection_t *c)
{
    njt_http_request_t         *r;
    njt_http_posted_request_t  *pr;

    for ( ;; ) {

        if (c->destroyed) {
            return;
        }

        r = c->data;
        pr = r->main->posted_requests;

        if (pr == NULL) {
            return;
        }

        r->main->posted_requests = pr->next;

        r = pr->request;

        njt_http_set_log_request(c->log, r);

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http posted request: \"%V?%V\"", &r->uri, &r->args);

        r->write_event_handler(r);
    }
}


njt_int_t
njt_http_post_request(njt_http_request_t *r, njt_http_posted_request_t *pr)
{
    njt_http_posted_request_t  **p;

    if (pr == NULL) {
        pr = njt_palloc(r->pool, sizeof(njt_http_posted_request_t));
        if (pr == NULL) {
            return NJT_ERROR;
        }
    }

    pr->request = r;
    pr->next = NULL;

    for (p = &r->main->posted_requests; *p; p = &(*p)->next) { /* void */ }

    *p = pr;

    return NJT_OK;
}


void
njt_http_finalize_request(njt_http_request_t *r, njt_int_t rc)
{
    njt_connection_t          *c;
    njt_http_request_t        *pr;
    njt_http_core_loc_conf_t  *clcf;

    c = r->connection;

    njt_log_debug5(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http finalize request: %i, \"%V?%V\" a:%d, c:%d",
                   rc, &r->uri, &r->args, r == c->data, r->main->count);
  
#if (NJT_HTTP_FAULT_INJECT)
    if(r->abort_flag > 0){
        r->abort_flag = 0;
        if (r == r->main) {
            if (c->read->timer_set) {
                njt_del_timer(c->read);
            }

            if (c->write->timer_set) {
                njt_del_timer(c->write);
            }
        }

        c->read->handler = njt_http_request_handler;
        c->write->handler = njt_http_request_handler;

        njt_http_finalize_request(r, njt_http_special_response_handler(r, rc));
        return;         
    }
#endif  

    if (rc == NJT_DONE) {
        njt_http_finalize_connection(r);
        return;
    }

    if (rc == NJT_OK && r->filter_finalize) {
        c->error = 1;
    }

    if (rc == NJT_DECLINED) {
        r->content_handler = NULL;
        r->write_event_handler = njt_http_core_run_phases;
        njt_http_core_run_phases(r);
        return;
    }

    if (r != r->main && r->post_subrequest) {
        rc = r->post_subrequest->handler(r, r->post_subrequest->data, rc);
    }

    if (rc == NJT_ERROR
        || rc == NJT_HTTP_REQUEST_TIME_OUT
        || rc == NJT_HTTP_CLIENT_CLOSED_REQUEST
        || c->error)
    {
        if (njt_http_post_action(r) == NJT_OK) {
            return;
        }

        njt_http_terminate_request(r, rc);
        return;
    }

    if (rc >= NJT_HTTP_SPECIAL_RESPONSE
        || rc == NJT_HTTP_CREATED
        || rc == NJT_HTTP_NO_CONTENT)
    {
        if (rc == NJT_HTTP_CLOSE) {
            c->timedout = 1;
            njt_http_terminate_request(r, rc);
            return;
        }

        if (r == r->main) {
            if (c->read->timer_set) {
                njt_del_timer(c->read);
            }

            if (c->write->timer_set) {
                njt_del_timer(c->write);
            }
        }

        c->read->handler = njt_http_request_handler;
        c->write->handler = njt_http_request_handler;

        njt_http_finalize_request(r, njt_http_special_response_handler(r, rc));
        return;
    }

    if (r != r->main) {

        if (r->buffered || r->postponed) {

            if (njt_http_set_write_handler(r) != NJT_OK) {
                njt_http_terminate_request(r, 0);
            }

            return;
        }

        pr = r->parent;

        if (r == c->data || r->background) {

            if (!r->logged) {

                clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

                if (clcf->log_subrequest) {
                    njt_http_log_request(r);
                }

                r->logged = 1;

            } else {
                njt_log_error(NJT_LOG_ALERT, c->log, 0,
                              "subrequest: \"%V?%V\" logged again",
                              &r->uri, &r->args);
            }

            r->done = 1;

            if (r->background) {
                njt_http_finalize_connection(r);
                return;
            }

            r->main->count--;

            if (pr->postponed && pr->postponed->request == r) {
                pr->postponed = pr->postponed->next;
            }

            c->data = pr;

        } else {

            njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                           "http finalize non-active request: \"%V?%V\"",
                           &r->uri, &r->args);

            r->write_event_handler = njt_http_request_finalizer;

            if (r->waited) {
                r->done = 1;
            }
        }

        if (njt_http_post_request(pr, NULL) != NJT_OK) {
            r->main->count++;
            njt_http_terminate_request(r, 0);
            return;
        }

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http wake parent request: \"%V?%V\"",
                       &pr->uri, &pr->args);

        return;
    }

    if (r->buffered || c->buffered || r->postponed) {

        if (njt_http_set_write_handler(r) != NJT_OK) {
            njt_http_terminate_request(r, 0);
        }

        return;
    }

    if (r != c->data) {
        njt_log_error(NJT_LOG_ALERT, c->log, 0,
                      "http finalize non-active request: \"%V?%V\"",
                      &r->uri, &r->args);
        return;
    }

    r->done = 1;

    r->read_event_handler = njt_http_block_reading;
    r->write_event_handler = njt_http_request_empty_handler;

    if (!r->post_action) {
        r->request_complete = 1;
    }

    if (njt_http_post_action(r) == NJT_OK) {
        return;
    }

    if (c->read->timer_set) {
        njt_del_timer(c->read);
    }

    if (c->write->timer_set) {
        c->write->delayed = 0;
        njt_del_timer(c->write);
    }

    njt_http_finalize_connection(r);
}


static void
njt_http_terminate_request(njt_http_request_t *r, njt_int_t rc)
{
    njt_http_cleanup_t    *cln;
    njt_http_request_t    *mr;
    njt_http_ephemeral_t  *e;
    mr = r->main;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http terminate request count:%d", mr->count);

    if (rc > 0 && (mr->headers_out.status == 0 || mr->connection->sent == 0)) {
        mr->headers_out.status = rc;
    }

    cln = mr->cleanup;
    mr->cleanup = NULL;

    while (cln) {
        if (cln->handler) {
            cln->handler(cln->data);
        }

        cln = cln->next;
    }

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http terminate cleanup count:%d blk:%d",
                   mr->count, mr->blocked);

    if (mr->write_event_handler) {

        if (mr->blocked) {
            r->connection->error = 1;
            r->write_event_handler = njt_http_request_finalizer;
            return;
        }

        e = njt_http_ephemeral(mr);
        mr->posted_requests = NULL;
        mr->write_event_handler = njt_http_terminate_handler;
        (void) njt_http_post_request(mr, &e->terminal_posted_request);
        return;
    }

    njt_http_close_request(mr, rc);
}


static void
njt_http_terminate_handler(njt_http_request_t *r)
{
    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http terminate handler count:%d", r->count);

    r->count = 1;

    njt_http_close_request(r, 0);
}


static void
njt_http_finalize_connection(njt_http_request_t *r)
{
    njt_http_core_loc_conf_t  *clcf;

#if (NJT_HTTP_V2)
    if (r->stream) {
        njt_http_close_request(r, 0);
        return;
    }
#endif

#if (NJT_HTTP_V3)
    if (r->connection->quic) {
        njt_http_close_request(r, 0);
        return;
    }
#endif

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    if (r->main->count != 1) {

        if (r->discard_body) {
            r->read_event_handler = njt_http_discarded_request_body_handler;
            njt_add_timer(r->connection->read, clcf->lingering_timeout);

            if (r->lingering_time == 0) {
                r->lingering_time = njt_time()
                                      + (time_t) (clcf->lingering_time / 1000);
            }
        }

        njt_http_close_request(r, 0);
        return;
    }

    r = r->main;

    if (r->connection->read->eof) {
        njt_http_close_request(r, 0);
        return;
    }

    if (r->reading_body) {
        r->keepalive = 0;
        r->lingering_close = 1;
    }

    if (!njt_terminate
         && !njt_exiting
         && r->keepalive
         && clcf->keepalive_timeout > 0)
    {
        njt_http_set_keepalive(r);
        return;
    }

    if (clcf->lingering_close == NJT_HTTP_LINGERING_ALWAYS
        || (clcf->lingering_close == NJT_HTTP_LINGERING_ON
            && (r->lingering_close
                || r->header_in->pos < r->header_in->last
                || r->connection->read->ready
                || r->connection->pipeline)))
    {
        njt_http_set_lingering_close(r->connection);
        return;
    }

    njt_http_close_request(r, 0);
}


static njt_int_t
njt_http_set_write_handler(njt_http_request_t *r)
{
    njt_event_t               *wev;
    njt_http_core_loc_conf_t  *clcf;

    r->http_state = NJT_HTTP_WRITING_REQUEST_STATE;

    r->read_event_handler = r->discard_body ?
                                njt_http_discarded_request_body_handler:
                                njt_http_test_reading;
    r->write_event_handler = njt_http_writer;

    wev = r->connection->write;

    if (wev->ready && wev->delayed) {
        return NJT_OK;
    }

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);
    if (!wev->delayed) {
        njt_add_timer(wev, clcf->send_timeout);
    }

    if (njt_handle_write_event(wev, clcf->send_lowat) != NJT_OK) {
        njt_http_close_request(r, 0);
        return NJT_ERROR;
    }

    return NJT_OK;
}


static void
njt_http_writer(njt_http_request_t *r)
{
    njt_int_t                  rc;
    njt_event_t               *wev;
    njt_connection_t          *c;
    njt_http_core_loc_conf_t  *clcf;

    c = r->connection;
    wev = c->write;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, wev->log, 0,
                   "http writer handler: \"%V?%V\"", &r->uri, &r->args);

    clcf = njt_http_get_module_loc_conf(r->main, njt_http_core_module);

    if (wev->timedout) {
        njt_log_error(NJT_LOG_INFO, c->log, NJT_ETIMEDOUT,
                      "client timed out");
        c->timedout = 1;

        njt_http_finalize_request(r, NJT_HTTP_REQUEST_TIME_OUT);
        return;
    }

    if (wev->delayed || r->aio) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, wev->log, 0,
                       "http writer delayed");

        if (!wev->delayed) {
            njt_add_timer(wev, clcf->send_timeout);
        }

        if (njt_handle_write_event(wev, clcf->send_lowat) != NJT_OK) {
            njt_http_close_request(r, 0);
        }

        return;
    }

    rc = njt_http_output_filter(r, NULL);

    njt_log_debug3(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http writer output filter: %i, \"%V?%V\"",
                   rc, &r->uri, &r->args);

    if (rc == NJT_ERROR) {
        njt_http_finalize_request(r, rc);
        return;
    }

    if (r->buffered || r->postponed || (r == r->main && c->buffered)) {

        if (!wev->delayed) {
            njt_add_timer(wev, clcf->send_timeout);
        }

        if (njt_handle_write_event(wev, clcf->send_lowat) != NJT_OK) {
            njt_http_close_request(r, 0);
        }

        return;
    }

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, wev->log, 0,
                   "http writer done: \"%V?%V\"", &r->uri, &r->args);

    r->write_event_handler = njt_http_request_empty_handler;

    njt_http_finalize_request(r, rc);
}


static void
njt_http_request_finalizer(njt_http_request_t *r)
{
    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http finalizer done: \"%V?%V\"", &r->uri, &r->args);

    njt_http_finalize_request(r, 0);
}


void
njt_http_block_reading(njt_http_request_t *r)
{
    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http reading blocked");

    /* aio does not call this handler */

    if ((njt_event_flags & NJT_USE_LEVEL_EVENT)
        && r->connection->read->active)
    {
        if (njt_del_event(r->connection->read, NJT_READ_EVENT, 0) != NJT_OK) {
            njt_http_close_request(r, 0);
        }
    }
}


void
njt_http_test_reading(njt_http_request_t *r)
{
    int                n;
    char               buf[1];
    njt_err_t          err;
    njt_event_t       *rev;
    njt_connection_t  *c;

    c = r->connection;
    rev = c->read;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0, "http test reading");

#if (NJT_HTTP_V2)

    if (r->stream) {
        if (c->error) {
            err = 0;
            goto closed;
        }

        return;
    }

#endif

#if (NJT_HTTP_V3)

    if (c->quic) {
        if (rev->error) {
            c->error = 1;
            err = 0;
            goto closed;
        }

        return;
    }

#endif

#if (NJT_HAVE_KQUEUE)

    if (njt_event_flags & NJT_USE_KQUEUE_EVENT) {

        if (!rev->pending_eof) {
            return;
        }

        rev->eof = 1;
        c->error = 1;
        err = rev->kq_errno;

        goto closed;
    }

#endif

#if (NJT_HAVE_EPOLLRDHUP)

    if ((njt_event_flags & NJT_USE_EPOLL_EVENT) && njt_use_epoll_rdhup) {
        socklen_t  len;

        if (!rev->pending_eof) {
            return;
        }

        rev->eof = 1;
        c->error = 1;

        err = 0;
        len = sizeof(njt_err_t);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = njt_socket_errno;
        }

        goto closed;
    }

#endif

    n = recv(c->fd, buf, 1, MSG_PEEK);

    if (n == 0) {
        rev->eof = 1;
        c->error = 1;
        err = 0;

        goto closed;

    } else if (n == -1) {
        err = njt_socket_errno;

        if (err != NJT_EAGAIN) {
            rev->eof = 1;
            c->error = 1;

            goto closed;
        }
    }

    /* aio does not call this handler */

    if ((njt_event_flags & NJT_USE_LEVEL_EVENT) && rev->active) {

        if (njt_del_event(rev, NJT_READ_EVENT, 0) != NJT_OK) {
            njt_http_close_request(r, 0);
        }
    }

    return;

closed:

    if (err) {
        rev->error = 1;
    }

#if (NJT_HTTP_SSL)
    if (c->ssl) {
        c->ssl->no_send_shutdown = 1;
    }
#endif

    njt_log_error(NJT_LOG_INFO, c->log, err,
                  "client prematurely closed connection");

    njt_http_finalize_request(r, NJT_HTTP_CLIENT_CLOSED_REQUEST);
}


static void
njt_http_set_keepalive(njt_http_request_t *r)
{
    int                        tcp_nodelay;
    njt_buf_t                 *b, *f;
    njt_chain_t               *cl, *ln;
    njt_event_t               *rev, *wev;
    njt_connection_t          *c;
    njt_http_connection_t     *hc;
    njt_http_core_loc_conf_t  *clcf;

    c = r->connection;
    rev = c->read;

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0, "set http keepalive handler");

    c->log->action = "closing request";

    hc = r->http_connection;
    b = r->header_in;

    if (b->pos < b->last) {

        /* the pipelined request */

        if (b != c->buffer) {

            /*
             * If the large header buffers were allocated while the previous
             * request processing then we do not use c->buffer for
             * the pipelined request (see njt_http_create_request()).
             *
             * Now we would move the large header buffers to the free list.
             */

            for (cl = hc->busy; cl; /* void */) {
                ln = cl;
                cl = cl->next;

                if (ln->buf == b) {
                    njt_free_chain(c->pool, ln);
                    continue;
                }

                f = ln->buf;
                f->pos = f->start;
                f->last = f->start;

                ln->next = hc->free;
                hc->free = ln;
            }

            cl = njt_alloc_chain_link(c->pool);
            if (cl == NULL) {
                njt_http_close_request(r, 0);
                return;
            }

            cl->buf = b;
            cl->next = NULL;

            hc->busy = cl;
            hc->nbusy = 1;
        }
    }

    /* guard against recursive call from njt_http_finalize_connection() */
    r->keepalive = 0;

    njt_http_free_request(r, 0);

    c->data = hc;

    if (njt_handle_read_event(rev, 0) != NJT_OK) {
        njt_http_close_connection(c);
        return;
    }

    wev = c->write;
    wev->handler = njt_http_empty_handler;

    if (b->pos < b->last) {

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0, "pipelined request");

        c->log->action = "reading client pipelined request line";

        r = njt_http_create_request(c);
        if (r == NULL) {
            njt_http_close_connection(c);
            return;
        }

        r->pipeline = 1;

        c->data = r;

        c->sent = 0;
        c->destroyed = 0;
        c->pipeline = 1;

        if (rev->timer_set) {
            njt_del_timer(rev);
        }

        rev->handler = njt_http_process_request_line;
        njt_post_event(rev, &njt_posted_events);
        return;
    }

    /*
     * To keep a memory footprint as small as possible for an idle keepalive
     * connection we try to free c->buffer's memory if it was allocated outside
     * the c->pool.  The large header buffers are always allocated outside the
     * c->pool and are freed too.
     */

    b = c->buffer;

    if (njt_pfree(c->pool, b->start) == NJT_OK) {

        /*
         * the special note for njt_http_keepalive_handler() that
         * c->buffer's memory was freed
         */

        b->pos = NULL;

    } else {
        b->pos = b->start;
        b->last = b->start;
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0, "hc free: %p",
                   hc->free);

    if (hc->free) {
        for (cl = hc->free; cl; /* void */) {
            ln = cl;
            cl = cl->next;
            njt_pfree(c->pool, ln->buf->start);
            njt_free_chain(c->pool, ln);
        }

        hc->free = NULL;
    }

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0, "hc busy: %p %i",
                   hc->busy, hc->nbusy);

    if (hc->busy) {
        for (cl = hc->busy; cl; /* void */) {
            ln = cl;
            cl = cl->next;
            njt_pfree(c->pool, ln->buf->start);
            njt_free_chain(c->pool, ln);
        }

        hc->busy = NULL;
        hc->nbusy = 0;
    }

#if (NJT_HTTP_SSL)
    if (c->ssl) {
        njt_ssl_free_buffer(c);
    }
#endif

    rev->handler = njt_http_keepalive_handler;

    if (wev->active && (njt_event_flags & NJT_USE_LEVEL_EVENT)) {
        if (njt_del_event(wev, NJT_WRITE_EVENT, 0) != NJT_OK) {
            njt_http_close_connection(c);
            return;
        }
    }

    c->log->action = "keepalive";

    if (c->tcp_nopush == NJT_TCP_NOPUSH_SET) {
        if (njt_tcp_push(c->fd) == -1) {
            njt_connection_error(c, njt_socket_errno, njt_tcp_push_n " failed");
            njt_http_close_connection(c);
            return;
        }

        c->tcp_nopush = NJT_TCP_NOPUSH_UNSET;
        tcp_nodelay = njt_tcp_nodelay_and_tcp_nopush ? 1 : 0;

    } else {
        tcp_nodelay = 1;
    }

    if (tcp_nodelay && clcf->tcp_nodelay && njt_tcp_nodelay(c) != NJT_OK) {
        njt_http_close_connection(c);
        return;
    }

#if 0
    /* if njt_http_request_t was freed then we need some other place */
    r->http_state = NJT_HTTP_KEEPALIVE_STATE;
#endif

    c->idle = 1;
    njt_reusable_connection(c, 1);

    njt_add_timer(rev, clcf->keepalive_timeout);

    if (rev->ready) {
        njt_post_event(rev, &njt_posted_events);
    }
}


static void
njt_http_keepalive_handler(njt_event_t *rev)
{
    size_t             size;
    ssize_t            n;
    njt_buf_t         *b;
    njt_connection_t  *c;

    c = rev->data;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0, "http keepalive handler");

    if (rev->timedout || c->close) {
        njt_http_close_connection(c);
        return;
    }

#if (NJT_HAVE_KQUEUE)

    if (njt_event_flags & NJT_USE_KQUEUE_EVENT) {
        if (rev->pending_eof) {
            c->log->handler = NULL;
            njt_log_error(NJT_LOG_INFO, c->log, rev->kq_errno,
                          "kevent() reported that client %V closed "
                          "keepalive connection", &c->addr_text);
#if (NJT_HTTP_SSL)
            if (c->ssl) {
                c->ssl->no_send_shutdown = 1;
            }
#endif
            njt_http_close_connection(c);
            return;
        }
    }

#endif

    b = c->buffer;
    size = b->end - b->start;

    if (b->pos == NULL) {

        /*
         * The c->buffer's memory was freed by njt_http_set_keepalive().
         * However, the c->buffer->start and c->buffer->end were not changed
         * to keep the buffer size.
         */

        b->pos = njt_palloc(c->pool, size);
        if (b->pos == NULL) {
            njt_http_close_connection(c);
            return;
        }

        b->start = b->pos;
        b->last = b->pos;
        b->end = b->pos + size;
    }

    /*
     * MSIE closes a keepalive connection with RST flag
     * so we ignore ECONNRESET here.
     */

    c->log_error = NJT_ERROR_IGNORE_ECONNRESET;
    njt_set_socket_errno(0);

    n = c->recv(c, b->last, size);
    c->log_error = NJT_ERROR_INFO;

    if (n == NJT_AGAIN) {
        if (njt_handle_read_event(rev, 0) != NJT_OK) {
            njt_http_close_connection(c);
            return;
        }

        /*
         * Like njt_http_set_keepalive() we are trying to not hold
         * c->buffer's memory for a keepalive connection.
         */

        if (njt_pfree(c->pool, b->start) == NJT_OK) {

            /*
             * the special note that c->buffer's memory was freed
             */

            b->pos = NULL;
        }

        return;
    }

    if (n == NJT_ERROR) {
        njt_http_close_connection(c);
        return;
    }

    c->log->handler = NULL;

    if (n == 0) {
        njt_log_error(NJT_LOG_INFO, c->log, njt_socket_errno,
                      "client %V closed keepalive connection", &c->addr_text);
        njt_http_close_connection(c);
        return;
    }

    b->last += n;

    c->log->handler = njt_http_log_error;
    c->log->action = "reading client request line";

    c->idle = 0;
    njt_reusable_connection(c, 0);

    c->data = njt_http_create_request(c);
    if (c->data == NULL) {
        njt_http_close_connection(c);
        return;
    }

    c->sent = 0;
    c->destroyed = 0;

    njt_del_timer(rev);

    rev->handler = njt_http_process_request_line;
    njt_http_process_request_line(rev);
}


static void
njt_http_set_lingering_close(njt_connection_t *c)
{
    njt_event_t               *rev, *wev;
    njt_http_request_t        *r;
    njt_http_core_loc_conf_t  *clcf;

    r = c->data;

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    if (r->lingering_time == 0) {
        r->lingering_time = njt_time() + (time_t) (clcf->lingering_time / 1000);
    }

#if (NJT_HTTP_SSL)
    if (c->ssl) {
        njt_int_t  rc;

        c->ssl->shutdown_without_free = 1;

        rc = njt_ssl_shutdown(c);

        if (rc == NJT_ERROR) {
            njt_http_close_request(r, 0);
            return;
        }

        if (rc == NJT_AGAIN) {
            c->ssl->handler = njt_http_set_lingering_close;
            return;
        }
    }
#endif

    rev = c->read;
    rev->handler = njt_http_lingering_close_handler;

    if (njt_handle_read_event(rev, 0) != NJT_OK) {
        njt_http_close_request(r, 0);
        return;
    }

    wev = c->write;
    wev->handler = njt_http_empty_handler;

    if (wev->active && (njt_event_flags & NJT_USE_LEVEL_EVENT)) {
        if (njt_del_event(wev, NJT_WRITE_EVENT, 0) != NJT_OK) {
            njt_http_close_request(r, 0);
            return;
        }
    }

    if (njt_shutdown_socket(c->fd, NJT_WRITE_SHUTDOWN) == -1) {
        njt_connection_error(c, njt_socket_errno,
                             njt_shutdown_socket_n " failed");
        njt_http_close_request(r, 0);
        return;
    }

    c->close = 0;
    njt_reusable_connection(c, 1);

    njt_add_timer(rev, clcf->lingering_timeout);

    if (rev->ready) {
        njt_http_lingering_close_handler(rev);
    }
}


static void
njt_http_lingering_close_handler(njt_event_t *rev)
{
    ssize_t                    n;
    njt_msec_t                 timer;
    njt_connection_t          *c;
    njt_http_request_t        *r;
    njt_http_core_loc_conf_t  *clcf;
    u_char                     buffer[NJT_HTTP_LINGERING_BUFFER_SIZE];

    c = rev->data;
    r = c->data;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http lingering close handler");

    if (rev->timedout || c->close) {
        njt_http_close_request(r, 0);
        return;
    }

    timer = (njt_msec_t) r->lingering_time - (njt_msec_t) njt_time();
    if ((njt_msec_int_t) timer <= 0) {
        njt_http_close_request(r, 0);
        return;
    }

    do {
        n = c->recv(c, buffer, NJT_HTTP_LINGERING_BUFFER_SIZE);

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0, "lingering read: %z", n);

        if (n == NJT_AGAIN) {
            break;
        }

        if (n == NJT_ERROR || n == 0) {
            njt_http_close_request(r, 0);
            return;
        }

    } while (rev->ready);

    if (njt_handle_read_event(rev, 0) != NJT_OK) {
        njt_http_close_request(r, 0);
        return;
    }

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    timer *= 1000;

    if (timer > clcf->lingering_timeout) {
        timer = clcf->lingering_timeout;
    }

    njt_add_timer(rev, timer);
}


void
njt_http_empty_handler(njt_event_t *wev)
{
    njt_log_debug0(NJT_LOG_DEBUG_HTTP, wev->log, 0, "http empty handler");

    return;
}


void
njt_http_request_empty_handler(njt_http_request_t *r)
{
    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http request empty handler");

    return;
}


njt_int_t
njt_http_send_special(njt_http_request_t *r, njt_uint_t flags)
{
    njt_buf_t    *b;
    njt_chain_t   out;

    b = njt_calloc_buf(r->pool);
    if (b == NULL) {
        return NJT_ERROR;
    }

    if (flags & NJT_HTTP_LAST) {

        if (r == r->main && !r->post_action) {
            b->last_buf = 1;

        } else {
            b->sync = 1;
            b->last_in_chain = 1;
        }
    }

    if (flags & NJT_HTTP_FLUSH) {
        b->flush = 1;
    }

    out.buf = b;
    out.next = NULL;

    return njt_http_output_filter(r, &out);
}


static njt_int_t
njt_http_post_action(njt_http_request_t *r)
{
    njt_http_core_loc_conf_t  *clcf;

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    if (clcf->post_action.data == NULL) {
        return NJT_DECLINED;
    }

    if (r->post_action && r->uri_changes == 0) {
        return NJT_DECLINED;
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "post action: \"%V\"", &clcf->post_action);

    r->main->count--;
    r->http_version = NJT_HTTP_VERSION_9;
    r->header_only = 1;
    r->post_action = 1;

    r->read_event_handler = njt_http_block_reading;

    if (clcf->post_action.data[0] == '/') {
        njt_http_internal_redirect(r, &clcf->post_action, NULL);

    } else {
        njt_http_named_location(r, &clcf->post_action);
    }

    return NJT_OK;
}


void
njt_http_close_request(njt_http_request_t *r, njt_int_t rc)
{
    njt_connection_t  *c;

    r = r->main;
    c = r->connection;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http request count:%d blk:%d", r->count, r->blocked);

    if (r->count == 0) {
        njt_log_error(NJT_LOG_ALERT, c->log, 0, "http request count is zero");
    }

    r->count--;
    if (r->count || r->blocked) {
        return;
    }

#if (NJT_HTTP_V2)
    if (r->stream) {
        njt_http_v2_close_stream(r->stream, rc);
        return;
    }
#endif



    njt_http_free_request(r, rc);
    njt_http_close_connection(c);
}


void
njt_http_free_request(njt_http_request_t *r, njt_int_t rc)
{
    njt_log_t                 *log;
    njt_pool_t                *pool;
    struct linger              linger;
    njt_http_cleanup_t        *cln;
    njt_http_log_ctx_t        *ctx;
    njt_http_core_loc_conf_t  *clcf;
    //njt_http_core_srv_conf_t  *cscf;

    log = r->connection->log;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, log, 0, "http close request");

    if (r->pool == NULL) {
        njt_log_error(NJT_LOG_ALERT, log, 0, "http request already closed");
        return;
    }

    cln = r->cleanup;
    r->cleanup = NULL;

    while (cln) {
        if (cln->handler) {
            cln->handler(cln->data);
        }

        cln = cln->next;
    }

#if (NJT_STAT_STUB)

    if (r->stat_reading) {
        (void) njt_atomic_fetch_add(njt_stat_reading, -1);
    }

    if (r->stat_writing) {
        (void) njt_atomic_fetch_add(njt_stat_writing, -1);
    }

#endif

    if (rc > 0 && (r->headers_out.status == 0 || r->connection->sent == 0)) {
        r->headers_out.status = rc;
    }

    if (!r->logged) {
        log->action = "logging request";

        njt_http_log_request(r);
    }

    log->action = "closing request";

    if (r->connection->timedout
#if (NJT_HTTP_V3)
        && r->connection->quic == NULL
#endif
       )
    {
        clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

        if (clcf->reset_timedout_connection) {
            linger.l_onoff = 1;
            linger.l_linger = 0;

            if (setsockopt(r->connection->fd, SOL_SOCKET, SO_LINGER,
                           (const void *) &linger, sizeof(struct linger)) == -1)
            {
                njt_log_error(NJT_LOG_ALERT, log, njt_socket_errno,
                              "setsockopt(SO_LINGER) failed");
            }
        }
    }

    /* the various request strings were allocated from r->pool */
    ctx = log->data;
    ctx->request = NULL;

    r->request_line.len = 0;

    r->connection->destroyed = 1;

    /*
     * Setting r->pool to NULL will increase probability to catch double close
     * of request since the request object is allocated from its own pool.
     */
    // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);
#endif
    //end
    pool = r->pool;
    r->pool = NULL;
    njt_destroy_pool(pool);
    //end
}


static void
njt_http_log_request(njt_http_request_t *r)
{
    njt_uint_t                  i, n;
    njt_http_handler_pt        *log_handler;
    njt_http_core_main_conf_t  *cmcf;

    cmcf = njt_http_get_module_main_conf(r, njt_http_core_module);

    log_handler = cmcf->phases[NJT_HTTP_LOG_PHASE].handlers.elts;
    n = cmcf->phases[NJT_HTTP_LOG_PHASE].handlers.nelts;

    for (i = 0; i < n; i++) {
        log_handler[i](r);
    }
}


void
njt_http_close_connection(njt_connection_t *c)
{
    njt_pool_t  *pool;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "close http connection: %d", c->fd);

#if (NJT_HTTP_SSL)

    if (c->ssl) {
        if (njt_ssl_shutdown(c) == NJT_AGAIN) {
            c->ssl->handler = njt_http_close_connection;
            return;
        }
    }

#endif

#if (NJT_HTTP_V3)
    if (c->quic) {
        njt_http_v3_reset_stream(c);
    }
#endif

#if (NJT_STAT_STUB)
    (void) njt_atomic_fetch_add(njt_stat_active, -1);
#endif

    c->destroyed = 1;

    pool = c->pool;

    njt_close_connection(c);

    njt_destroy_pool(pool);
}


static u_char *
njt_http_log_error(njt_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;
    njt_http_request_t  *r;
    njt_http_log_ctx_t  *ctx;

    if (log->action) {
        p = njt_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    ctx = log->data;

    p = njt_snprintf(buf, len, ", client: %V", &ctx->connection->addr_text);
    len -= p - buf;

    r = ctx->request;

    if (r) {
        return r->log_handler(r, ctx->current_request, p, len);

    } else {
        p = njt_snprintf(p, len, ", server: %V",
                         &ctx->connection->listening->addr_text);
    }

    return p;
}


static u_char *
njt_http_log_error_handler(njt_http_request_t *r, njt_http_request_t *sr,
    u_char *buf, size_t len)
{
    char                      *uri_separator;
    u_char                    *p;
    njt_http_upstream_t       *u;
    njt_http_core_srv_conf_t  *cscf;

    cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);

    p = njt_snprintf(buf, len, ", server: %V", &cscf->server_name);
    len -= p - buf;
    buf = p;

    if (r->request_line.data == NULL && r->request_start) {
        for (p = r->request_start; p < r->header_in->last; p++) {
            if (*p == CR || *p == LF) {
                break;
            }
        }

        r->request_line.len = p - r->request_start;
        r->request_line.data = r->request_start;
    }

    if (r->request_line.len) {
        p = njt_snprintf(buf, len, ", request: \"%V\"", &r->request_line);
        len -= p - buf;
        buf = p;
    }

    if (r != sr) {
        p = njt_snprintf(buf, len, ", subrequest: \"%V\"", &sr->uri);
        len -= p - buf;
        buf = p;
    }

    u = sr->upstream;

    if (u && u->peer.name) {

        uri_separator = "";

#if (NJT_HAVE_UNIX_DOMAIN)
        if (u->peer.sockaddr && u->peer.sockaddr->sa_family == AF_UNIX) {
            uri_separator = ":";
        }
#endif

        p = njt_snprintf(buf, len, ", upstream: \"%V%V%s%V\"",
                         &u->schema, u->peer.name,
                         uri_separator, &u->uri);
        len -= p - buf;
        buf = p;
    }

    if (r->headers_in.host) {
        p = njt_snprintf(buf, len, ", host: \"%V\"",
                         &r->headers_in.host->value);
        len -= p - buf;
        buf = p;
    }

    if (r->headers_in.referer) {
        p = njt_snprintf(buf, len, ", referrer: \"%V\"",
                         &r->headers_in.referer->value);
        buf = p;
    }

    return buf;
}
