
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) Ruslan Ermilov
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njet.h>
#include <njt_http_v2_module.h>


/*
 * This returns precise number of octets for values in range 0..253
 * and estimate number for the rest, but not smaller than required.
 */

#define njt_http_v2_integer_octets(v)  (1 + (v) / 127)

#define njt_http_v2_literal_size(h)                                           \
    (njt_http_v2_integer_octets(sizeof(h) - 1) + sizeof(h) - 1)


#define NJT_HTTP_V2_NO_TRAILERS           (njt_http_v2_out_frame_t *) -1


static njt_http_v2_out_frame_t *njt_http_v2_create_headers_frame(
    njt_http_request_t *r, u_char *pos, u_char *end, njt_uint_t fin);
static njt_http_v2_out_frame_t *njt_http_v2_create_trailers_frame(
    njt_http_request_t *r);

static njt_chain_t *njt_http_v2_send_chain(njt_connection_t *fc,
    njt_chain_t *in, off_t limit);

static njt_chain_t *njt_http_v2_filter_get_shadow(
    njt_http_v2_stream_t *stream, njt_buf_t *buf, off_t offset, off_t size);
static njt_http_v2_out_frame_t *njt_http_v2_filter_get_data_frame(
    njt_http_v2_stream_t *stream, size_t len, njt_chain_t *first,
    njt_chain_t *last);

static njt_inline njt_int_t njt_http_v2_flow_control(
    njt_http_v2_connection_t *h2c, njt_http_v2_stream_t *stream);
static void njt_http_v2_waiting_queue(njt_http_v2_connection_t *h2c,
    njt_http_v2_stream_t *stream);

static njt_inline njt_int_t njt_http_v2_filter_send(
    njt_connection_t *fc, njt_http_v2_stream_t *stream);

static njt_int_t njt_http_v2_headers_frame_handler(
    njt_http_v2_connection_t *h2c, njt_http_v2_out_frame_t *frame);
static njt_int_t njt_http_v2_data_frame_handler(
    njt_http_v2_connection_t *h2c, njt_http_v2_out_frame_t *frame);
static njt_inline void njt_http_v2_handle_frame(
    njt_http_v2_stream_t *stream, njt_http_v2_out_frame_t *frame);
static njt_inline void njt_http_v2_handle_stream(
    njt_http_v2_connection_t *h2c, njt_http_v2_stream_t *stream);

static void njt_http_v2_filter_cleanup(void *data);

static njt_int_t njt_http_v2_filter_init(njt_conf_t *cf);


static njt_http_module_t  njt_http_v2_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_http_v2_filter_init,               /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


njt_module_t  njt_http_v2_filter_module = {
    NJT_MODULE_V1,
    &njt_http_v2_filter_module_ctx,        /* module context */
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


static njt_int_t
njt_http_v2_header_filter(njt_http_request_t *r)
{
    u_char                     status, *pos, *start, *p, *tmp;
    size_t                     len, tmp_len;
    njt_str_t                  host, location;
    njt_uint_t                 i, port, fin;
    njt_list_part_t           *part;
    njt_table_elt_t           *header;
    njt_connection_t          *fc;
    njt_http_cleanup_t        *cln;
    njt_http_v2_stream_t      *stream;
    njt_http_v2_out_frame_t   *frame;
    njt_http_v2_connection_t  *h2c;
    njt_http_core_loc_conf_t  *clcf;
    njt_http_core_srv_conf_t  *cscf;
    u_char                     addr[NJT_SOCKADDR_STRLEN];

    static const u_char njet[5] = "\x84\xaa\x63\x55\xe7";
#if (NJT_HTTP_GZIP)
    static const u_char accept_encoding[12] =
        "\x8b\x84\x84\x2d\x69\x5b\x05\x44\x3c\x86\xaa\x6f";
#endif

    static size_t njet_ver_len = njt_http_v2_literal_size(NJT_VER);
    static u_char njet_ver[njt_http_v2_literal_size(NJT_VER)];

    static size_t njet_ver_build_len =
                                  njt_http_v2_literal_size(NJT_VER_BUILD);
    static u_char njet_ver_build[njt_http_v2_literal_size(NJT_VER_BUILD)];

    stream = r->stream;

    if (!stream) {
        return njt_http_next_header_filter(r);
    }

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http2 header filter");

    if (r->header_sent) {
        return NJT_OK;
    }

    r->header_sent = 1;

    if (r != r->main) {
        return NJT_OK;
    }

    fc = r->connection;

    if (fc->error) {
        return NJT_ERROR;
    }

    if (r->method == NJT_HTTP_HEAD) {
        r->header_only = 1;
    }

    switch (r->headers_out.status) {

    case NJT_HTTP_OK:
        status = njt_http_v2_indexed(NJT_HTTP_V2_STATUS_200_INDEX);
        break;

    case NJT_HTTP_NO_CONTENT:
        r->header_only = 1;

        njt_str_null(&r->headers_out.content_type);

        r->headers_out.content_length = NULL;
        r->headers_out.content_length_n = -1;

        r->headers_out.last_modified_time = -1;
        r->headers_out.last_modified = NULL;

        status = njt_http_v2_indexed(NJT_HTTP_V2_STATUS_204_INDEX);
        break;

    case NJT_HTTP_PARTIAL_CONTENT:
        status = njt_http_v2_indexed(NJT_HTTP_V2_STATUS_206_INDEX);
        break;

    case NJT_HTTP_NOT_MODIFIED:
        r->header_only = 1;
        status = njt_http_v2_indexed(NJT_HTTP_V2_STATUS_304_INDEX);
        break;

    default:
        r->headers_out.last_modified_time = -1;
        r->headers_out.last_modified = NULL;

        switch (r->headers_out.status) {

        case NJT_HTTP_BAD_REQUEST:
            status = njt_http_v2_indexed(NJT_HTTP_V2_STATUS_400_INDEX);
            break;

        case NJT_HTTP_NOT_FOUND:
            status = njt_http_v2_indexed(NJT_HTTP_V2_STATUS_404_INDEX);
            break;

        case NJT_HTTP_INTERNAL_SERVER_ERROR:
            status = njt_http_v2_indexed(NJT_HTTP_V2_STATUS_500_INDEX);
            break;

        default:
            status = 0;
        }
    }

    h2c = stream->connection;

    len = h2c->table_update ? 1 : 0;

    len += status ? 1 : 1 + njt_http_v2_literal_size("418");

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    if (r->headers_out.server == NULL) {

        if (clcf->server_tokens == NJT_HTTP_SERVER_TOKENS_ON) {
            len += 1 + njet_ver_len;

        } else if (clcf->server_tokens == NJT_HTTP_SERVER_TOKENS_BUILD) {
            len += 1 + njet_ver_build_len;

        } else {
            len += 1 + sizeof(njet);
        }
    }

    if (r->headers_out.date == NULL) {
        len += 1 + njt_http_v2_literal_size("Wed, 31 Dec 1986 18:00:00 GMT");
    }

    if (r->headers_out.content_type.len) {
        len += 1 + NJT_HTTP_V2_INT_OCTETS + r->headers_out.content_type.len;

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            len += sizeof("; charset=") - 1 + r->headers_out.charset.len;
        }
    }

    if (r->headers_out.content_length == NULL
        && r->headers_out.content_length_n >= 0)
    {
        len += 1 + njt_http_v2_integer_octets(NJT_OFF_T_LEN) + NJT_OFF_T_LEN;
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        len += 1 + njt_http_v2_literal_size("Wed, 31 Dec 1986 18:00:00 GMT");
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

                if (njt_connection_local_sockaddr(fc, &host, 0) != NJT_OK) {
                    return NJT_ERROR;
                }
            }

            port = njt_inet_get_port(fc->local_sockaddr);

            location.len = sizeof("https://") - 1 + host.len
                           + r->headers_out.location->value.len;

            if (clcf->port_in_redirect) {

#if (NJT_HTTP_SSL)
                if (fc->ssl)
                    port = (port == 443) ? 0 : port;
                else
#endif
                    port = (port == 80) ? 0 : port;

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

            p = njt_cpymem(location.data, "http", sizeof("http") - 1);

#if (NJT_HTTP_SSL)
            if (fc->ssl) {
                *p++ = 's';
            }
#endif

            *p++ = ':'; *p++ = '/'; *p++ = '/';
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

        len += 1 + NJT_HTTP_V2_INT_OCTETS + r->headers_out.location->value.len;
    }

    tmp_len = len;

#if (NJT_HTTP_GZIP)
    if (r->gzip_vary) {
        if (clcf->gzip_vary) {
            len += 1 + sizeof(accept_encoding);

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

        if (header[i].key.len > NJT_HTTP_V2_MAX_FIELD) {
            njt_log_error(NJT_LOG_CRIT, fc->log, 0,
                          "too long response header name: \"%V\"",
                          &header[i].key);
            return NJT_ERROR;
        }

        if (header[i].value.len > NJT_HTTP_V2_MAX_FIELD) {
            njt_log_error(NJT_LOG_CRIT, fc->log, 0,
                          "too long response header value: \"%V: %V\"",
                          &header[i].key, &header[i].value);
            return NJT_ERROR;
        }

        len += 1 + NJT_HTTP_V2_INT_OCTETS + header[i].key.len
                 + NJT_HTTP_V2_INT_OCTETS + header[i].value.len;

        if (header[i].key.len > tmp_len) {
            tmp_len = header[i].key.len;
        }

        if (header[i].value.len > tmp_len) {
            tmp_len = header[i].value.len;
        }
    }

    tmp = njt_palloc(r->pool, tmp_len);
    pos = njt_pnalloc(r->pool, len);

    if (pos == NULL || tmp == NULL) {
        return NJT_ERROR;
    }

    start = pos;

    if (h2c->table_update) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, fc->log, 0,
                       "http2 table size update: 0");
        *pos++ = (1 << 5) | 0;
        h2c->table_update = 0;
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, fc->log, 0,
                   "http2 output header: \":status: %03ui\"",
                   r->headers_out.status);

    if (status) {
        *pos++ = status;

    } else {
        *pos++ = njt_http_v2_inc_indexed(NJT_HTTP_V2_STATUS_INDEX);
        *pos++ = NJT_HTTP_V2_ENCODE_RAW | 3;
        pos = njt_sprintf(pos, "%03ui", r->headers_out.status);
    }

    if (r->headers_out.server == NULL) {

        if (clcf->server_tokens == NJT_HTTP_SERVER_TOKENS_ON) {
            njt_log_debug1(NJT_LOG_DEBUG_HTTP, fc->log, 0,
                           "http2 output header: \"server: %s\"",
                           NJT_VER);

        } else if (clcf->server_tokens == NJT_HTTP_SERVER_TOKENS_BUILD) {
            njt_log_debug1(NJT_LOG_DEBUG_HTTP, fc->log, 0,
                           "http2 output header: \"server: %s\"",
                           NJT_VER_BUILD);

        } else {
            njt_log_debug0(NJT_LOG_DEBUG_HTTP, fc->log, 0,
                           "http2 output header: \"server: njet\"");
        }

        *pos++ = njt_http_v2_inc_indexed(NJT_HTTP_V2_SERVER_INDEX);

        if (clcf->server_tokens == NJT_HTTP_SERVER_TOKENS_ON) {
            if (njet_ver[0] == '\0') {
                p = njt_http_v2_write_value(njet_ver, (u_char *) NJT_VER,
                                            sizeof(NJT_VER) - 1, tmp);
                njet_ver_len = p - njet_ver;
            }

            pos = njt_cpymem(pos, njet_ver, njet_ver_len);

        } else if (clcf->server_tokens == NJT_HTTP_SERVER_TOKENS_BUILD) {
            if (njet_ver_build[0] == '\0') {
                p = njt_http_v2_write_value(njet_ver_build,
                                            (u_char *) NJT_VER_BUILD,
                                            sizeof(NJT_VER_BUILD) - 1, tmp);
                njet_ver_build_len = p - njet_ver_build;
            }

            pos = njt_cpymem(pos, njet_ver_build, njet_ver_build_len);

        } else {
            pos = njt_cpymem(pos, njet, sizeof(njet));
        }
    }

    if (r->headers_out.date == NULL) {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, fc->log, 0,
                       "http2 output header: \"date: %V\"",
                       &njt_cached_http_time);

        *pos++ = njt_http_v2_inc_indexed(NJT_HTTP_V2_DATE_INDEX);
        pos = njt_http_v2_write_value(pos, njt_cached_http_time.data,
                                      njt_cached_http_time.len, tmp);
    }

    if (r->headers_out.content_type.len) {
        *pos++ = njt_http_v2_inc_indexed(NJT_HTTP_V2_CONTENT_TYPE_INDEX);

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            len = r->headers_out.content_type.len + sizeof("; charset=") - 1
                  + r->headers_out.charset.len;

            p = njt_pnalloc(r->pool, len);
            if (p == NULL) {
                return NJT_ERROR;
            }

            p = njt_cpymem(p, r->headers_out.content_type.data,
                           r->headers_out.content_type.len);

            p = njt_cpymem(p, "; charset=", sizeof("; charset=") - 1);

            p = njt_cpymem(p, r->headers_out.charset.data,
                           r->headers_out.charset.len);

            /* updated r->headers_out.content_type is also needed for logging */

            r->headers_out.content_type.len = len;
            r->headers_out.content_type.data = p - len;
        }

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, fc->log, 0,
                       "http2 output header: \"content-type: %V\"",
                       &r->headers_out.content_type);

        pos = njt_http_v2_write_value(pos, r->headers_out.content_type.data,
                                      r->headers_out.content_type.len, tmp);
    }

    if (r->headers_out.content_length == NULL
        && r->headers_out.content_length_n >= 0)
    {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, fc->log, 0,
                       "http2 output header: \"content-length: %O\"",
                       r->headers_out.content_length_n);

        *pos++ = njt_http_v2_inc_indexed(NJT_HTTP_V2_CONTENT_LENGTH_INDEX);

        p = pos;
        pos = njt_sprintf(pos + 1, "%O", r->headers_out.content_length_n);
        *p = NJT_HTTP_V2_ENCODE_RAW | (u_char) (pos - p - 1);
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        *pos++ = njt_http_v2_inc_indexed(NJT_HTTP_V2_LAST_MODIFIED_INDEX);

        njt_http_time(pos, r->headers_out.last_modified_time);
        len = sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1;

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, fc->log, 0,
                       "http2 output header: \"last-modified: %*s\"",
                       len, pos);

        /*
         * Date will always be encoded using huffman in the temporary buffer,
         * so it's safe here to use src and dst pointing to the same address.
         */
        pos = njt_http_v2_write_value(pos, pos, len, tmp);
    }

    if (r->headers_out.location && r->headers_out.location->value.len) {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, fc->log, 0,
                       "http2 output header: \"location: %V\"",
                       &r->headers_out.location->value);

        *pos++ = njt_http_v2_inc_indexed(NJT_HTTP_V2_LOCATION_INDEX);
        pos = njt_http_v2_write_value(pos, r->headers_out.location->value.data,
                                      r->headers_out.location->value.len, tmp);
    }

#if (NJT_HTTP_GZIP)
    if (r->gzip_vary) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, fc->log, 0,
                       "http2 output header: \"vary: Accept-Encoding\"");

        *pos++ = njt_http_v2_inc_indexed(NJT_HTTP_V2_VARY_INDEX);
        pos = njt_cpymem(pos, accept_encoding, sizeof(accept_encoding));
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

#if (NJT_DEBUG)
        if (fc->log->log_level & NJT_LOG_DEBUG_HTTP) {
            njt_strlow(tmp, header[i].key.data, header[i].key.len);

            njt_log_debug3(NJT_LOG_DEBUG_HTTP, fc->log, 0,
                           "http2 output header: \"%*s: %V\"",
                           header[i].key.len, tmp, &header[i].value);
        }
#endif

        *pos++ = 0;

        pos = njt_http_v2_write_name(pos, header[i].key.data,
                                     header[i].key.len, tmp);

        pos = njt_http_v2_write_value(pos, header[i].value.data,
                                      header[i].value.len, tmp);
    }

    fin = r->header_only
          || (r->headers_out.content_length_n == 0 && !r->expect_trailers);

    frame = njt_http_v2_create_headers_frame(r, start, pos, fin);
    if (frame == NULL) {
        return NJT_ERROR;
    }

    njt_http_v2_queue_blocked_frame(h2c, frame);

    stream->queued = 1;

    cln = njt_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return NJT_ERROR;
    }

    cln->handler = njt_http_v2_filter_cleanup;
    cln->data = stream;

    fc->send_chain = njt_http_v2_send_chain;
    fc->need_last_buf = 1;
    fc->need_flush_buf = 1;

    return njt_http_v2_filter_send(fc, stream);
}


static njt_http_v2_out_frame_t *
njt_http_v2_create_headers_frame(njt_http_request_t *r, u_char *pos,
    u_char *end, njt_uint_t fin)
{
    u_char                    type, flags;
    size_t                    rest, frame_size;
    njt_buf_t                *b;
    njt_chain_t              *cl, **ll;
    njt_http_v2_stream_t     *stream;
    njt_http_v2_out_frame_t  *frame;

    stream = r->stream;
    rest = end - pos;

    frame = njt_palloc(r->pool, sizeof(njt_http_v2_out_frame_t));
    if (frame == NULL) {
        return NULL;
    }

    frame->handler = njt_http_v2_headers_frame_handler;
    frame->stream = stream;
    frame->length = rest;
    frame->blocked = 1;
    frame->fin = fin;

    ll = &frame->first;

    type = NJT_HTTP_V2_HEADERS_FRAME;
    flags = fin ? NJT_HTTP_V2_END_STREAM_FLAG : NJT_HTTP_V2_NO_FLAG;
    frame_size = stream->connection->frame_size;

    for ( ;; ) {
        if (rest <= frame_size) {
            frame_size = rest;
            flags |= NJT_HTTP_V2_END_HEADERS_FLAG;
        }

        b = njt_create_temp_buf(r->pool, NJT_HTTP_V2_FRAME_HEADER_SIZE);
        if (b == NULL) {
            return NULL;
        }

        b->last = njt_http_v2_write_len_and_type(b->last, frame_size, type);
        *b->last++ = flags;
        b->last = njt_http_v2_write_sid(b->last, stream->node->id);

        b->tag = (njt_buf_tag_t) &njt_http_v2_module;

        cl = njt_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NULL;
        }

        cl->buf = b;

        *ll = cl;
        ll = &cl->next;

        b = njt_calloc_buf(r->pool);
        if (b == NULL) {
            return NULL;
        }

        b->pos = pos;

        pos += frame_size;

        b->last = pos;
        b->start = b->pos;
        b->end = b->last;
        b->temporary = 1;

        cl = njt_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NULL;
        }

        cl->buf = b;

        *ll = cl;
        ll = &cl->next;

        rest -= frame_size;

        if (rest) {
            frame->length += NJT_HTTP_V2_FRAME_HEADER_SIZE;

            type = NJT_HTTP_V2_CONTINUATION_FRAME;
            flags = NJT_HTTP_V2_NO_FLAG;
            continue;
        }

        b->last_buf = fin;
        cl->next = NULL;
        frame->last = cl;

        njt_log_debug4(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http2:%ui create HEADERS frame %p: len:%uz fin:%ui",
                       stream->node->id, frame, frame->length, fin);

        return frame;
    }
}


static njt_http_v2_out_frame_t *
njt_http_v2_create_trailers_frame(njt_http_request_t *r)
{
    u_char            *pos, *start, *tmp;
    size_t             len, tmp_len;
    njt_uint_t         i;
    njt_list_part_t   *part;
    njt_table_elt_t   *header;
    njt_connection_t  *fc;

    fc = r->connection;
    len = 0;
    tmp_len = 0;

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

        if (header[i].key.len > NJT_HTTP_V2_MAX_FIELD) {
            njt_log_error(NJT_LOG_CRIT, fc->log, 0,
                          "too long response trailer name: \"%V\"",
                          &header[i].key);
            return NULL;
        }

        if (header[i].value.len > NJT_HTTP_V2_MAX_FIELD) {
            njt_log_error(NJT_LOG_CRIT, fc->log, 0,
                          "too long response trailer value: \"%V: %V\"",
                          &header[i].key, &header[i].value);
            return NULL;
        }

        len += 1 + NJT_HTTP_V2_INT_OCTETS + header[i].key.len
                 + NJT_HTTP_V2_INT_OCTETS + header[i].value.len;

        if (header[i].key.len > tmp_len) {
            tmp_len = header[i].key.len;
        }

        if (header[i].value.len > tmp_len) {
            tmp_len = header[i].value.len;
        }
    }

    if (len == 0) {
        return NJT_HTTP_V2_NO_TRAILERS;
    }

    tmp = njt_palloc(r->pool, tmp_len);
    pos = njt_pnalloc(r->pool, len);

    if (pos == NULL || tmp == NULL) {
        return NULL;
    }

    start = pos;

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

#if (NJT_DEBUG)
        if (fc->log->log_level & NJT_LOG_DEBUG_HTTP) {
            njt_strlow(tmp, header[i].key.data, header[i].key.len);

            njt_log_debug3(NJT_LOG_DEBUG_HTTP, fc->log, 0,
                           "http2 output trailer: \"%*s: %V\"",
                           header[i].key.len, tmp, &header[i].value);
        }
#endif

        *pos++ = 0;

        pos = njt_http_v2_write_name(pos, header[i].key.data,
                                     header[i].key.len, tmp);

        pos = njt_http_v2_write_value(pos, header[i].value.data,
                                      header[i].value.len, tmp);
    }

    return njt_http_v2_create_headers_frame(r, start, pos, 1);
}


static njt_chain_t *
njt_http_v2_send_chain(njt_connection_t *fc, njt_chain_t *in, off_t limit)
{
    off_t                      size, offset;
    size_t                     rest, frame_size;
    njt_chain_t               *cl, *out, **ln;
    njt_http_request_t        *r;
    njt_http_v2_stream_t      *stream;
    njt_http_v2_loc_conf_t    *h2lcf;
    njt_http_v2_out_frame_t   *frame, *trailers;
    njt_http_v2_connection_t  *h2c;

    r = fc->data;
    stream = r->stream;

#if (NJT_SUPPRESS_WARN)
    size = 0;
#endif

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, fc->log, 0,
                   "http2 send chain: %p", in);

    while (in) {
        size = njt_buf_size(in->buf);

        if (size || in->buf->last_buf) {
            break;
        }

        in = in->next;
    }

    if (in == NULL || stream->out_closed) {

        if (size) {
            njt_log_error(NJT_LOG_ERR, fc->log, 0,
                          "output on closed stream");
            return NJT_CHAIN_ERROR;
        }

        if (njt_http_v2_filter_send(fc, stream) == NJT_ERROR) {
            return NJT_CHAIN_ERROR;
        }

        return NULL;
    }

    h2c = stream->connection;

    if (size && njt_http_v2_flow_control(h2c, stream) == NJT_DECLINED) {

        if (njt_http_v2_filter_send(fc, stream) == NJT_ERROR) {
            return NJT_CHAIN_ERROR;
        }

        if (njt_http_v2_flow_control(h2c, stream) == NJT_DECLINED) {
            fc->write->active = 1;
            fc->write->ready = 0;
            return in;
        }
    }

    if (in->buf->tag == (njt_buf_tag_t) &njt_http_v2_filter_get_shadow) {
        cl = njt_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NJT_CHAIN_ERROR;
        }

        cl->buf = in->buf;
        in->buf = cl->buf->shadow;

        offset = njt_buf_in_memory(in->buf)
                 ? (cl->buf->pos - in->buf->pos)
                 : (cl->buf->file_pos - in->buf->file_pos);

        cl->next = stream->free_bufs;
        stream->free_bufs = cl;

    } else {
        offset = 0;
    }

    if (limit == 0 || limit > (off_t) h2c->send_window) {
        limit = h2c->send_window;
    }

    if (limit > stream->send_window) {
        limit = (stream->send_window > 0) ? stream->send_window : 0;
    }

    h2lcf = njt_http_get_module_loc_conf(r, njt_http_v2_module);

    frame_size = (h2lcf->chunk_size < h2c->frame_size)
                 ? h2lcf->chunk_size : h2c->frame_size;

    trailers = NJT_HTTP_V2_NO_TRAILERS;

#if (NJT_SUPPRESS_WARN)
    cl = NULL;
#endif

    for ( ;; ) {
        if ((off_t) frame_size > limit) {
            frame_size = (size_t) limit;
        }

        ln = &out;
        rest = frame_size;

        while ((off_t) rest >= size) {

            if (offset) {
                cl = njt_http_v2_filter_get_shadow(stream, in->buf,
                                                   offset, size);
                if (cl == NULL) {
                    return NJT_CHAIN_ERROR;
                }

                offset = 0;

            } else {
                cl = njt_alloc_chain_link(r->pool);
                if (cl == NULL) {
                    return NJT_CHAIN_ERROR;
                }

                cl->buf = in->buf;
            }

            *ln = cl;
            ln = &cl->next;

            rest -= (size_t) size;
            in = in->next;

            if (in == NULL) {
                frame_size -= rest;
                rest = 0;
                break;
            }

            size = njt_buf_size(in->buf);
        }

        if (rest) {
            cl = njt_http_v2_filter_get_shadow(stream, in->buf, offset, rest);
            if (cl == NULL) {
                return NJT_CHAIN_ERROR;
            }

            cl->buf->flush = 0;
            cl->buf->last_buf = 0;

            *ln = cl;

            offset += rest;
            size -= rest;
        }

        if (cl->buf->last_buf) {
            trailers = njt_http_v2_create_trailers_frame(r);
            if (trailers == NULL) {
                return NJT_CHAIN_ERROR;
            }

            if (trailers != NJT_HTTP_V2_NO_TRAILERS) {
                cl->buf->last_buf = 0;
            }
        }

        if (frame_size || cl->buf->last_buf) {
            frame = njt_http_v2_filter_get_data_frame(stream, frame_size,
                                                      out, cl);
            if (frame == NULL) {
                return NJT_CHAIN_ERROR;
            }

            njt_http_v2_queue_frame(h2c, frame);

            h2c->send_window -= frame_size;

            stream->send_window -= frame_size;
            stream->queued++;
        }

        if (in == NULL) {

            if (trailers != NJT_HTTP_V2_NO_TRAILERS) {
                njt_http_v2_queue_frame(h2c, trailers);
                stream->queued++;
            }

            break;
        }

        limit -= frame_size;

        if (limit == 0) {
            break;
        }
    }

    if (offset) {
        cl = njt_http_v2_filter_get_shadow(stream, in->buf, offset, size);
        if (cl == NULL) {
            return NJT_CHAIN_ERROR;
        }

        in->buf = cl->buf;
        njt_free_chain(r->pool, cl);
    }

    if (njt_http_v2_filter_send(fc, stream) == NJT_ERROR) {
        return NJT_CHAIN_ERROR;
    }

    if (in && njt_http_v2_flow_control(h2c, stream) == NJT_DECLINED) {
        fc->write->active = 1;
        fc->write->ready = 0;
    }

    return in;
}


static njt_chain_t *
njt_http_v2_filter_get_shadow(njt_http_v2_stream_t *stream, njt_buf_t *buf,
    off_t offset, off_t size)
{
    njt_buf_t    *chunk;
    njt_chain_t  *cl;

    cl = njt_chain_get_free_buf(stream->request->pool, &stream->free_bufs);
    if (cl == NULL) {
        return NULL;
    }

    chunk = cl->buf;

    njt_memcpy(chunk, buf, sizeof(njt_buf_t));

    chunk->tag = (njt_buf_tag_t) &njt_http_v2_filter_get_shadow;
    chunk->shadow = buf;

    if (njt_buf_in_memory(chunk)) {
        chunk->pos += offset;
        chunk->last = chunk->pos + size;
    }

    if (chunk->in_file) {
        chunk->file_pos += offset;
        chunk->file_last = chunk->file_pos + size;
    }

    return cl;
}


static njt_http_v2_out_frame_t *
njt_http_v2_filter_get_data_frame(njt_http_v2_stream_t *stream,
    size_t len, njt_chain_t *first, njt_chain_t *last)
{
    u_char                     flags;
    njt_buf_t                 *buf;
    njt_chain_t               *cl;
    njt_http_v2_out_frame_t   *frame;
    njt_http_v2_connection_t  *h2c;

    frame = stream->free_frames;
    h2c = stream->connection;

    if (frame) {
        stream->free_frames = frame->next;

    } else if (h2c->frames < 10000) {
        frame = njt_palloc(stream->request->pool,
                           sizeof(njt_http_v2_out_frame_t));
        if (frame == NULL) {
            return NULL;
        }

        stream->frames++;
        h2c->frames++;

    } else {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "http2 flood detected");

        h2c->connection->error = 1;
        return NULL;
    }

    flags = last->buf->last_buf ? NJT_HTTP_V2_END_STREAM_FLAG : 0;

    njt_log_debug4(NJT_LOG_DEBUG_HTTP, stream->request->connection->log, 0,
                   "http2:%ui create DATA frame %p: len:%uz flags:%ui",
                   stream->node->id, frame, len, (njt_uint_t) flags);

    cl = njt_chain_get_free_buf(stream->request->pool,
                                &stream->free_frame_headers);
    if (cl == NULL) {
        return NULL;
    }

    buf = cl->buf;

    if (buf->start == NULL) {
        buf->start = njt_palloc(stream->request->pool,
                                NJT_HTTP_V2_FRAME_HEADER_SIZE);
        if (buf->start == NULL) {
            return NULL;
        }

        buf->end = buf->start + NJT_HTTP_V2_FRAME_HEADER_SIZE;
        buf->last = buf->end;

        buf->tag = (njt_buf_tag_t) &njt_http_v2_module;
        buf->memory = 1;
    }

    buf->pos = buf->start;
    buf->last = buf->pos;

    buf->last = njt_http_v2_write_len_and_type(buf->last, len,
                                               NJT_HTTP_V2_DATA_FRAME);
    *buf->last++ = flags;

    buf->last = njt_http_v2_write_sid(buf->last, stream->node->id);

    cl->next = first;
    first = cl;

    last->buf->flush = 1;

    frame->first = first;
    frame->last = last;
    frame->handler = njt_http_v2_data_frame_handler;
    frame->stream = stream;
    frame->length = len;
    frame->blocked = 0;
    frame->fin = last->buf->last_buf;

    return frame;
}


static njt_inline njt_int_t
njt_http_v2_flow_control(njt_http_v2_connection_t *h2c,
    njt_http_v2_stream_t *stream)
{
    njt_log_debug3(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2:%ui windows: conn:%uz stream:%z",
                   stream->node->id, h2c->send_window, stream->send_window);

    if (stream->send_window <= 0) {
        stream->exhausted = 1;
        return NJT_DECLINED;
    }

    if (h2c->send_window == 0) {
        njt_http_v2_waiting_queue(h2c, stream);
        return NJT_DECLINED;
    }

    return NJT_OK;
}


static void
njt_http_v2_waiting_queue(njt_http_v2_connection_t *h2c,
    njt_http_v2_stream_t *stream)
{
    njt_queue_t           *q;
    njt_http_v2_stream_t  *s;

    if (stream->waiting) {
        return;
    }

    stream->waiting = 1;

    for (q = njt_queue_last(&h2c->waiting);
         q != njt_queue_sentinel(&h2c->waiting);
         q = njt_queue_prev(q))
    {
        s = njt_queue_data(q, njt_http_v2_stream_t, queue);

        if (s->node->rank < stream->node->rank
            || (s->node->rank == stream->node->rank
                && s->node->rel_weight >= stream->node->rel_weight))
        {
            break;
        }
    }

    njt_queue_insert_after(q, &stream->queue);
}


static njt_inline njt_int_t
njt_http_v2_filter_send(njt_connection_t *fc, njt_http_v2_stream_t *stream)
{
    njt_connection_t  *c;

    c = stream->connection->connection;

    if (stream->queued == 0 && !c->buffered) {
        fc->buffered &= ~NJT_HTTP_V2_BUFFERED;
        return NJT_OK;
    }

    stream->blocked = 1;

    if (njt_http_v2_send_output_queue(stream->connection) == NJT_ERROR) {
        fc->error = 1;
        return NJT_ERROR;
    }

    stream->blocked = 0;

    if (stream->queued) {
        fc->buffered |= NJT_HTTP_V2_BUFFERED;
        fc->write->active = 1;
        fc->write->ready = 0;
        return NJT_AGAIN;
    }

    fc->buffered &= ~NJT_HTTP_V2_BUFFERED;

    return NJT_OK;
}


static njt_int_t
njt_http_v2_headers_frame_handler(njt_http_v2_connection_t *h2c,
    njt_http_v2_out_frame_t *frame)
{
    njt_chain_t           *cl, *ln;
    njt_http_v2_stream_t  *stream;

    stream = frame->stream;
    cl = frame->first;

    for ( ;; ) {
        if (cl->buf->pos != cl->buf->last) {
            frame->first = cl;

            njt_log_debug2(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                           "http2:%ui HEADERS frame %p was sent partially",
                           stream->node->id, frame);

            return NJT_AGAIN;
        }

        ln = cl->next;

        if (cl->buf->tag == (njt_buf_tag_t) &njt_http_v2_module) {
            cl->next = stream->free_frame_headers;
            stream->free_frame_headers = cl;

        } else {
            cl->next = stream->free_bufs;
            stream->free_bufs = cl;
        }

        if (cl == frame->last) {
            break;
        }

        cl = ln;
    }

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2:%ui HEADERS frame %p was sent",
                   stream->node->id, frame);

    stream->request->header_size += NJT_HTTP_V2_FRAME_HEADER_SIZE
                                    + frame->length;

    h2c->payload_bytes += frame->length;

    njt_http_v2_handle_frame(stream, frame);

    njt_http_v2_handle_stream(h2c, stream);

    return NJT_OK;
}


static njt_int_t
njt_http_v2_data_frame_handler(njt_http_v2_connection_t *h2c,
    njt_http_v2_out_frame_t *frame)
{
    njt_buf_t             *buf;
    njt_chain_t           *cl, *ln;
    njt_http_v2_stream_t  *stream;

    stream = frame->stream;
    cl = frame->first;

    if (cl->buf->tag == (njt_buf_tag_t) &njt_http_v2_module) {

        if (cl->buf->pos != cl->buf->last) {
            njt_log_debug2(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                           "http2:%ui DATA frame %p was sent partially",
                           stream->node->id, frame);

            return NJT_AGAIN;
        }

        ln = cl->next;

        cl->next = stream->free_frame_headers;
        stream->free_frame_headers = cl;

        if (cl == frame->last) {
            goto done;
        }

        cl = ln;
    }

    for ( ;; ) {
        if (cl->buf->tag == (njt_buf_tag_t) &njt_http_v2_filter_get_shadow) {
            buf = cl->buf->shadow;

            if (njt_buf_in_memory(buf)) {
                buf->pos = cl->buf->pos;
            }

            if (buf->in_file) {
                buf->file_pos = cl->buf->file_pos;
            }
        }

        if (njt_buf_size(cl->buf) != 0) {

            if (cl != frame->first) {
                frame->first = cl;
                njt_http_v2_handle_stream(h2c, stream);
            }

            njt_log_debug2(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                           "http2:%ui DATA frame %p was sent partially",
                           stream->node->id, frame);

            return NJT_AGAIN;
        }

        ln = cl->next;

        if (cl->buf->tag == (njt_buf_tag_t) &njt_http_v2_filter_get_shadow) {
            cl->next = stream->free_bufs;
            stream->free_bufs = cl;

        } else {
            njt_free_chain(stream->request->pool, cl);
        }

        if (cl == frame->last) {
            goto done;
        }

        cl = ln;
    }

done:

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2:%ui DATA frame %p was sent",
                   stream->node->id, frame);

    stream->request->header_size += NJT_HTTP_V2_FRAME_HEADER_SIZE;

    h2c->payload_bytes += frame->length;

    njt_http_v2_handle_frame(stream, frame);

    njt_http_v2_handle_stream(h2c, stream);

    return NJT_OK;
}


static njt_inline void
njt_http_v2_handle_frame(njt_http_v2_stream_t *stream,
    njt_http_v2_out_frame_t *frame)
{
    njt_http_request_t        *r;
    njt_http_v2_connection_t  *h2c;

    r = stream->request;

    r->connection->sent += NJT_HTTP_V2_FRAME_HEADER_SIZE + frame->length;

    h2c = stream->connection;

    h2c->total_bytes += NJT_HTTP_V2_FRAME_HEADER_SIZE + frame->length;

    if (frame->fin) {
        stream->out_closed = 1;
    }

    frame->next = stream->free_frames;
    stream->free_frames = frame;

    stream->queued--;
}


static njt_inline void
njt_http_v2_handle_stream(njt_http_v2_connection_t *h2c,
    njt_http_v2_stream_t *stream)
{
    njt_event_t       *wev;
    njt_connection_t  *fc;

    if (stream->waiting || stream->blocked) {
        return;
    }

    fc = stream->request->connection;

    if (!fc->error && stream->exhausted) {
        return;
    }

    wev = fc->write;

    wev->active = 0;
    wev->ready = 1;

    if (!fc->error && wev->delayed) {
        return;
    }

    njt_post_event(wev, &njt_posted_events);
}


static void
njt_http_v2_filter_cleanup(void *data)
{
    njt_http_v2_stream_t *stream = data;

    size_t                     window;
    njt_event_t               *wev;
    njt_queue_t               *q;
    njt_http_v2_out_frame_t   *frame, **fn;
    njt_http_v2_connection_t  *h2c;

    if (stream->waiting) {
        stream->waiting = 0;
        njt_queue_remove(&stream->queue);
    }

    if (stream->queued == 0) {
        return;
    }

    window = 0;
    h2c = stream->connection;
    fn = &h2c->last_out;

    for ( ;; ) {
        frame = *fn;

        if (frame == NULL) {
            break;
        }

        if (frame->stream == stream && !frame->blocked) {
            *fn = frame->next;

            window += frame->length;

            if (--stream->queued == 0) {
                break;
            }

            continue;
        }

        fn = &frame->next;
    }

    if (h2c->send_window == 0 && window) {

        while (!njt_queue_empty(&h2c->waiting)) {
            q = njt_queue_head(&h2c->waiting);

            njt_queue_remove(q);

            stream = njt_queue_data(q, njt_http_v2_stream_t, queue);

            stream->waiting = 0;

            wev = stream->request->connection->write;

            wev->active = 0;
            wev->ready = 1;

            if (!wev->delayed) {
                njt_post_event(wev, &njt_posted_events);
            }
        }
    }

    h2c->send_window += window;
}


static njt_int_t
njt_http_v2_filter_init(njt_conf_t *cf)
{
    njt_http_next_header_filter = njt_http_top_header_filter;
    njt_http_top_header_filter = njt_http_v2_header_filter;

    return NJT_OK;
}
