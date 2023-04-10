
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njet.h>


static njt_int_t njt_http_header_filter_init(njt_conf_t *cf);
static njt_int_t njt_http_header_filter(njt_http_request_t *r);


static njt_http_module_t  njt_http_header_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_http_header_filter_init,           /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL,                                  /* merge location configuration */
};


njt_module_t  njt_http_header_filter_module = {
    NJT_MODULE_V1,
    &njt_http_header_filter_module_ctx,    /* module context */
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


static u_char njt_http_server_string[] = "Server: njet" CRLF;
static u_char njt_http_server_full_string[] = "Server: " NJT_VER CRLF;
static u_char njt_http_server_build_string[] = "Server: " NJT_VER_BUILD CRLF;


static njt_str_t njt_http_status_lines[] = {

    njt_string("200 OK"),
    njt_string("201 Created"),
    njt_string("202 Accepted"),
    njt_null_string,  /* "203 Non-Authoritative Information" */
    njt_string("204 No Content"),
    njt_null_string,  /* "205 Reset Content" */
    njt_string("206 Partial Content"),

    /* njt_null_string, */  /* "207 Multi-Status" */

#define NJT_HTTP_LAST_2XX  207
#define NJT_HTTP_OFF_3XX   (NJT_HTTP_LAST_2XX - 200)

    /* njt_null_string, */  /* "300 Multiple Choices" */

    njt_string("301 Moved Permanently"),
    njt_string("302 Moved Temporarily"),
    njt_string("303 See Other"),
    njt_string("304 Not Modified"),
    njt_null_string,  /* "305 Use Proxy" */
    njt_null_string,  /* "306 unused" */
    njt_string("307 Temporary Redirect"),
    njt_string("308 Permanent Redirect"),

#define NJT_HTTP_LAST_3XX  309
#define NJT_HTTP_OFF_4XX   (NJT_HTTP_LAST_3XX - 301 + NJT_HTTP_OFF_3XX)

    njt_string("400 Bad Request"),
    njt_string("401 Unauthorized"),
    njt_string("402 Payment Required"),
    njt_string("403 Forbidden"),
    njt_string("404 Not Found"),
    njt_string("405 Not Allowed"),
    njt_string("406 Not Acceptable"),
    njt_null_string,  /* "407 Proxy Authentication Required" */
    njt_string("408 Request Time-out"),
    njt_string("409 Conflict"),
    njt_string("410 Gone"),
    njt_string("411 Length Required"),
    njt_string("412 Precondition Failed"),
    njt_string("413 Request Entity Too Large"),
    njt_string("414 Request-URI Too Large"),
    njt_string("415 Unsupported Media Type"),
    njt_string("416 Requested Range Not Satisfiable"),
    njt_null_string,  /* "417 Expectation Failed" */
    njt_null_string,  /* "418 unused" */
    njt_null_string,  /* "419 unused" */
    njt_null_string,  /* "420 unused" */
    njt_string("421 Misdirected Request"),
    njt_null_string,  /* "422 Unprocessable Entity" */
    njt_null_string,  /* "423 Locked" */
    njt_null_string,  /* "424 Failed Dependency" */
    njt_null_string,  /* "425 unused" */
    njt_null_string,  /* "426 Upgrade Required" */
    njt_null_string,  /* "427 unused" */
    njt_null_string,  /* "428 Precondition Required" */
    njt_string("429 Too Many Requests"),

#define NJT_HTTP_LAST_4XX  430
#define NJT_HTTP_OFF_5XX   (NJT_HTTP_LAST_4XX - 400 + NJT_HTTP_OFF_4XX)

    njt_string("500 Internal Server Error"),
    njt_string("501 Not Implemented"),
    njt_string("502 Bad Gateway"),
    njt_string("503 Service Temporarily Unavailable"),
    njt_string("504 Gateway Time-out"),
    njt_string("505 HTTP Version Not Supported"),
    njt_null_string,        /* "506 Variant Also Negotiates" */
    njt_string("507 Insufficient Storage"),

    /* njt_null_string, */  /* "508 unused" */
    /* njt_null_string, */  /* "509 unused" */
    /* njt_null_string, */  /* "510 Not Extended" */

#define NJT_HTTP_LAST_5XX  508

};


njt_http_header_out_t  njt_http_headers_out[] = {
    { njt_string("Server"), offsetof(njt_http_headers_out_t, server) },
    { njt_string("Date"), offsetof(njt_http_headers_out_t, date) },
    { njt_string("Content-Length"),
                 offsetof(njt_http_headers_out_t, content_length) },
    { njt_string("Content-Encoding"),
                 offsetof(njt_http_headers_out_t, content_encoding) },
    { njt_string("Location"), offsetof(njt_http_headers_out_t, location) },
    { njt_string("Last-Modified"),
                 offsetof(njt_http_headers_out_t, last_modified) },
    { njt_string("Accept-Ranges"),
                 offsetof(njt_http_headers_out_t, accept_ranges) },
    { njt_string("Expires"), offsetof(njt_http_headers_out_t, expires) },
    { njt_string("Cache-Control"),
                 offsetof(njt_http_headers_out_t, cache_control) },
    { njt_string("ETag"), offsetof(njt_http_headers_out_t, etag) },

    { njt_null_string, 0 }
};


static njt_int_t
njt_http_header_filter(njt_http_request_t *r)
{
    u_char                    *p;
    size_t                     len;
    njt_str_t                  host, *status_line;
    njt_buf_t                 *b;
    njt_uint_t                 status, i, port;
    njt_chain_t                out;
    njt_list_part_t           *part;
    njt_table_elt_t           *header;
    njt_connection_t          *c;
    njt_http_core_loc_conf_t  *clcf;
    njt_http_core_srv_conf_t  *cscf;
    u_char                     addr[NJT_SOCKADDR_STRLEN];

    if (r->header_sent) {
        return NJT_OK;
    }

    r->header_sent = 1;

    if (r != r->main) {
        return NJT_OK;
    }

    if (r->http_version < NJT_HTTP_VERSION_10) {
        return NJT_OK;
    }

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

    if (r->keepalive && (njt_terminate || njt_exiting)) {
        r->keepalive = 0;
    }

    len = sizeof("HTTP/1.x ") - 1 + sizeof(CRLF) - 1
          /* the end of the header */
          + sizeof(CRLF) - 1;

    /* status line */

    if (r->headers_out.status_line.len) {
        len += r->headers_out.status_line.len;
        status_line = &r->headers_out.status_line;
#if (NJT_SUPPRESS_WARN)
        status = 0;
#endif

    } else {

        status = r->headers_out.status;

        if (status >= NJT_HTTP_OK
            && status < NJT_HTTP_LAST_2XX)
        {
            /* 2XX */

            if (status == NJT_HTTP_NO_CONTENT) {
                r->header_only = 1;
                njt_str_null(&r->headers_out.content_type);
                r->headers_out.last_modified_time = -1;
                r->headers_out.last_modified = NULL;
                r->headers_out.content_length = NULL;
                r->headers_out.content_length_n = -1;
            }

            status -= NJT_HTTP_OK;
            status_line = &njt_http_status_lines[status];
            len += njt_http_status_lines[status].len;

        } else if (status >= NJT_HTTP_MOVED_PERMANENTLY
                   && status < NJT_HTTP_LAST_3XX)
        {
            /* 3XX */

            if (status == NJT_HTTP_NOT_MODIFIED) {
                r->header_only = 1;
            }

            status = status - NJT_HTTP_MOVED_PERMANENTLY + NJT_HTTP_OFF_3XX;
            status_line = &njt_http_status_lines[status];
            len += njt_http_status_lines[status].len;

        } else if (status >= NJT_HTTP_BAD_REQUEST
                   && status < NJT_HTTP_LAST_4XX)
        {
            /* 4XX */
            status = status - NJT_HTTP_BAD_REQUEST
                            + NJT_HTTP_OFF_4XX;

            status_line = &njt_http_status_lines[status];
            len += njt_http_status_lines[status].len;

        } else if (status >= NJT_HTTP_INTERNAL_SERVER_ERROR
                   && status < NJT_HTTP_LAST_5XX)
        {
            /* 5XX */
            status = status - NJT_HTTP_INTERNAL_SERVER_ERROR
                            + NJT_HTTP_OFF_5XX;

            status_line = &njt_http_status_lines[status];
            len += njt_http_status_lines[status].len;

        } else {
            len += NJT_INT_T_LEN + 1 /* SP */;
            status_line = NULL;
        }

        if (status_line && status_line->len == 0) {
            status = r->headers_out.status;
            len += NJT_INT_T_LEN + 1 /* SP */;
            status_line = NULL;
        }
    }

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    if (r->headers_out.server == NULL) {
        if (clcf->server_tokens == NJT_HTTP_SERVER_TOKENS_ON) {
            len += sizeof(njt_http_server_full_string) - 1;

        } else if (clcf->server_tokens == NJT_HTTP_SERVER_TOKENS_BUILD) {
            len += sizeof(njt_http_server_build_string) - 1;

        } else {
            len += sizeof(njt_http_server_string) - 1;
        }
    }

    if (r->headers_out.date == NULL) {
        len += sizeof("Date: Mon, 28 Sep 1970 06:00:00 GMT" CRLF) - 1;
    }

    if (r->headers_out.content_type.len) {
        len += sizeof("Content-Type: ") - 1
               + r->headers_out.content_type.len + 2;

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            len += sizeof("; charset=") - 1 + r->headers_out.charset.len;
        }
    }

    if (r->headers_out.content_length == NULL
        && r->headers_out.content_length_n >= 0)
    {
        len += sizeof("Content-Length: ") - 1 + NJT_OFF_T_LEN + 2;
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        len += sizeof("Last-Modified: Mon, 28 Sep 1970 06:00:00 GMT" CRLF) - 1;
    }

    c = r->connection;

    if (r->headers_out.location
        && r->headers_out.location->value.len
        && r->headers_out.location->value.data[0] == '/'
        && clcf->absolute_redirect)
    {
        r->headers_out.location->hash = 0;

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

        len += sizeof("Location: https://") - 1
               + host.len
               + r->headers_out.location->value.len + 2;

        if (clcf->port_in_redirect) {

#if (NJT_HTTP_SSL)
            if (c->ssl)
                port = (port == 443) ? 0 : port;
            else
#endif
                port = (port == 80) ? 0 : port;

        } else {
            port = 0;
        }

        if (port) {
            len += sizeof(":65535") - 1;
        }

    } else {
        njt_str_null(&host);
        port = 0;
    }

    if (r->chunked) {
        len += sizeof("Transfer-Encoding: chunked" CRLF) - 1;
    }

    if (r->headers_out.status == NJT_HTTP_SWITCHING_PROTOCOLS) {
        len += sizeof("Connection: upgrade" CRLF) - 1;

    } else if (r->keepalive) {
        len += sizeof("Connection: keep-alive" CRLF) - 1;

        /*
         * MSIE and Opera ignore the "Keep-Alive: timeout=<N>" header.
         * MSIE keeps the connection alive for about 60-65 seconds.
         * Opera keeps the connection alive very long.
         * Mozilla keeps the connection alive for N plus about 1-10 seconds.
         * Konqueror keeps the connection alive for about N seconds.
         */

        if (clcf->keepalive_header) {
            len += sizeof("Keep-Alive: timeout=") - 1 + NJT_TIME_T_LEN + 2;
        }

    } else {
        len += sizeof("Connection: close" CRLF) - 1;
    }

#if (NJT_HTTP_GZIP)
    if (r->gzip_vary) {
        if (clcf->gzip_vary) {
            len += sizeof("Vary: Accept-Encoding" CRLF) - 1;

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

        len += header[i].key.len + sizeof(": ") - 1 + header[i].value.len
               + sizeof(CRLF) - 1;
    }

    b = njt_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NJT_ERROR;
    }

    /* "HTTP/1.x " */
    b->last = njt_cpymem(b->last, "HTTP/1.1 ", sizeof("HTTP/1.x ") - 1);

    /* status line */
    if (status_line) {
        b->last = njt_copy(b->last, status_line->data, status_line->len);

    } else {
        b->last = njt_sprintf(b->last, "%03ui ", status);
    }
    *b->last++ = CR; *b->last++ = LF;

    if (r->headers_out.server == NULL) {
        if (clcf->server_tokens == NJT_HTTP_SERVER_TOKENS_ON) {
            p = njt_http_server_full_string;
            len = sizeof(njt_http_server_full_string) - 1;

        } else if (clcf->server_tokens == NJT_HTTP_SERVER_TOKENS_BUILD) {
            p = njt_http_server_build_string;
            len = sizeof(njt_http_server_build_string) - 1;

        } else {
            p = njt_http_server_string;
            len = sizeof(njt_http_server_string) - 1;
        }

        b->last = njt_cpymem(b->last, p, len);
    }

    if (r->headers_out.date == NULL) {
        b->last = njt_cpymem(b->last, "Date: ", sizeof("Date: ") - 1);
        b->last = njt_cpymem(b->last, njt_cached_http_time.data,
                             njt_cached_http_time.len);

        *b->last++ = CR; *b->last++ = LF;
    }

    if (r->headers_out.content_type.len) {
        b->last = njt_cpymem(b->last, "Content-Type: ",
                             sizeof("Content-Type: ") - 1);
        p = b->last;
        b->last = njt_copy(b->last, r->headers_out.content_type.data,
                           r->headers_out.content_type.len);

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            b->last = njt_cpymem(b->last, "; charset=",
                                 sizeof("; charset=") - 1);
            b->last = njt_copy(b->last, r->headers_out.charset.data,
                               r->headers_out.charset.len);

            /* update r->headers_out.content_type for possible logging */

            r->headers_out.content_type.len = b->last - p;
            r->headers_out.content_type.data = p;
        }

        *b->last++ = CR; *b->last++ = LF;
    }

    if (r->headers_out.content_length == NULL
        && r->headers_out.content_length_n >= 0)
    {
        b->last = njt_sprintf(b->last, "Content-Length: %O" CRLF,
                              r->headers_out.content_length_n);
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        b->last = njt_cpymem(b->last, "Last-Modified: ",
                             sizeof("Last-Modified: ") - 1);
        b->last = njt_http_time(b->last, r->headers_out.last_modified_time);

        *b->last++ = CR; *b->last++ = LF;
    }

    if (host.data) {

        p = b->last + sizeof("Location: ") - 1;

        b->last = njt_cpymem(b->last, "Location: http",
                             sizeof("Location: http") - 1);

#if (NJT_HTTP_SSL)
        if (c->ssl) {
            *b->last++ ='s';
        }
#endif

        *b->last++ = ':'; *b->last++ = '/'; *b->last++ = '/';
        b->last = njt_copy(b->last, host.data, host.len);

        if (port) {
            b->last = njt_sprintf(b->last, ":%ui", port);
        }

        b->last = njt_copy(b->last, r->headers_out.location->value.data,
                           r->headers_out.location->value.len);

        /* update r->headers_out.location->value for possible logging */

        r->headers_out.location->value.len = b->last - p;
        r->headers_out.location->value.data = p;
        njt_str_set(&r->headers_out.location->key, "Location");

        *b->last++ = CR; *b->last++ = LF;
    }

    if (r->chunked) {
        b->last = njt_cpymem(b->last, "Transfer-Encoding: chunked" CRLF,
                             sizeof("Transfer-Encoding: chunked" CRLF) - 1);
    }

    if (r->headers_out.status == NJT_HTTP_SWITCHING_PROTOCOLS) {
        b->last = njt_cpymem(b->last, "Connection: upgrade" CRLF,
                             sizeof("Connection: upgrade" CRLF) - 1);

    } else if (r->keepalive) {
        b->last = njt_cpymem(b->last, "Connection: keep-alive" CRLF,
                             sizeof("Connection: keep-alive" CRLF) - 1);

        if (clcf->keepalive_header) {
            b->last = njt_sprintf(b->last, "Keep-Alive: timeout=%T" CRLF,
                                  clcf->keepalive_header);
        }

    } else {
        b->last = njt_cpymem(b->last, "Connection: close" CRLF,
                             sizeof("Connection: close" CRLF) - 1);
    }

#if (NJT_HTTP_GZIP)
    if (r->gzip_vary) {
        b->last = njt_cpymem(b->last, "Vary: Accept-Encoding" CRLF,
                             sizeof("Vary: Accept-Encoding" CRLF) - 1);
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

        b->last = njt_copy(b->last, header[i].key.data, header[i].key.len);
        *b->last++ = ':'; *b->last++ = ' ';

        b->last = njt_copy(b->last, header[i].value.data, header[i].value.len);
        *b->last++ = CR; *b->last++ = LF;
    }

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "%*s", (size_t) (b->last - b->pos), b->pos);

    /* the end of HTTP header */
    *b->last++ = CR; *b->last++ = LF;

    r->header_size = b->last - b->pos;

    if (r->header_only) {
        b->last_buf = 1;
    }

    out.buf = b;
    out.next = NULL;

    return njt_http_write_filter(r, &out);
}


static njt_int_t
njt_http_header_filter_init(njt_conf_t *cf)
{
    njt_http_top_header_filter = njt_http_header_filter;

    return NJT_OK;
}
