
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


typedef struct {
    njt_http_v3_parse_uni_t         parse;
    njt_int_t                       index;
} njt_http_v3_uni_stream_t;




static void njt_http_v3_close_uni_stream(njt_connection_t *c);
static void njt_http_v3_uni_read_handler(njt_event_t *rev);
static void njt_http_v3_uni_dummy_read_handler(njt_event_t *wev);
static void njt_http_v3_uni_dummy_write_handler(njt_event_t *wev);
static njt_connection_t *njt_http_v3_get_uni_stream(njt_connection_t *c,
    njt_uint_t type);


void
njt_http_v3_init_uni_stream(njt_connection_t *c)
{
    uint64_t                   n;
    njt_http_v3_session_t     *h3c;
    njt_http_v3_uni_stream_t  *us;

    h3c = njt_http_v3_get_session(c);
    if (h3c->hq) {
        njt_http_v3_finalize_connection(c,
                                        NJT_HTTP_V3_ERR_STREAM_CREATION_ERROR,
                                        "uni stream in hq mode");
        c->data = NULL;
        njt_http_v3_close_uni_stream(c);
        return;
    }

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0, "http3 init uni stream");

    n = c->quic->id >> 2;

    if (n >= NJT_HTTP_V3_MAX_UNI_STREAMS) {
        njt_http_v3_finalize_connection(c,
                                      NJT_HTTP_V3_ERR_STREAM_CREATION_ERROR,
                                      "reached maximum number of uni streams");
        c->data = NULL;
        njt_http_v3_close_uni_stream(c);
        return;
    }

    njt_quic_cancelable_stream(c);

    us = njt_pcalloc(c->pool, sizeof(njt_http_v3_uni_stream_t));
    if (us == NULL) {
        njt_http_v3_finalize_connection(c,
                                        NJT_HTTP_V3_ERR_INTERNAL_ERROR,
                                        "memory allocation error");
        c->data = NULL;
        njt_http_v3_close_uni_stream(c);
        return;
    }

    us->index = -1;

    c->data = us;

    c->read->handler = njt_http_v3_uni_read_handler;
    c->write->handler = njt_http_v3_uni_dummy_write_handler;

    njt_http_v3_uni_read_handler(c->read);
}


static void
njt_http_v3_close_uni_stream(njt_connection_t *c)
{
    njt_pool_t                *pool;
    njt_http_v3_session_t     *h3c;
    njt_http_v3_uni_stream_t  *us;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0, "http3 close stream");

    us = c->data;

    if (us && us->index >= 0) {
        h3c = njt_http_v3_get_session(c);
        h3c->known_streams[us->index] = NULL;
    }

    c->destroyed = 1;

    pool = c->pool;

    njt_close_connection(c);

    njt_destroy_pool(pool);
}


njt_int_t
njt_http_v3_register_uni_stream(njt_connection_t *c, uint64_t type)
{
    njt_int_t                  index;
    njt_http_v3_session_t     *h3c;
    njt_http_v3_uni_stream_t  *us;

    h3c = njt_http_v3_get_session(c);

    switch (type) {

    case NJT_HTTP_V3_STREAM_ENCODER:

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 encoder stream");
        index = NJT_HTTP_V3_STREAM_CLIENT_ENCODER;
        break;

    case NJT_HTTP_V3_STREAM_DECODER:

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 decoder stream");
        index = NJT_HTTP_V3_STREAM_CLIENT_DECODER;
        break;

    case NJT_HTTP_V3_STREAM_CONTROL:

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 control stream");
        index = NJT_HTTP_V3_STREAM_CLIENT_CONTROL;

        break;

    default:

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 stream 0x%02xL", type);

        if (h3c->known_streams[NJT_HTTP_V3_STREAM_CLIENT_ENCODER] == NULL
            || h3c->known_streams[NJT_HTTP_V3_STREAM_CLIENT_DECODER] == NULL
            || h3c->known_streams[NJT_HTTP_V3_STREAM_CLIENT_CONTROL] == NULL)
        {
            njt_log_error(NJT_LOG_INFO, c->log, 0, "missing mandatory stream");
            return NJT_HTTP_V3_ERR_STREAM_CREATION_ERROR;
        }

        index = -1;
    }

    if (index >= 0) {
        if (h3c->known_streams[index]) {
            njt_log_error(NJT_LOG_INFO, c->log, 0, "stream exists");
            return NJT_HTTP_V3_ERR_STREAM_CREATION_ERROR;
        }

        h3c->known_streams[index] = c;

        us = c->data;
        us->index = index;
    }

    return NJT_OK;
}


static void
njt_http_v3_uni_read_handler(njt_event_t *rev)
{
    u_char                     buf[128];
    ssize_t                    n;
    njt_buf_t                  b;
    njt_int_t                  rc;
    njt_connection_t          *c;
    njt_http_v3_session_t     *h3c;
    njt_http_v3_uni_stream_t  *us;

    c = rev->data;
    us = c->data;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0, "http3 read handler");

    if (c->close) {
        njt_http_v3_close_uni_stream(c);
        return;
    }

    njt_memzero(&b, sizeof(njt_buf_t));

    while (rev->ready) {

        n = c->recv(c, buf, sizeof(buf));

        if (n == NJT_ERROR) {
            rc = NJT_HTTP_V3_ERR_INTERNAL_ERROR;
            goto failed;
        }

        if (n == 0) {
            if (us->index >= 0) {
                rc = NJT_HTTP_V3_ERR_CLOSED_CRITICAL_STREAM;
                goto failed;
            }

            njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0, "http3 read eof");
            njt_http_v3_close_uni_stream(c);
            return;
        }

        if (n == NJT_AGAIN) {
            break;
        }

        b.pos = buf;
        b.last = buf + n;

        h3c = njt_http_v3_get_session(c);
        h3c->total_bytes += n;

        if (njt_http_v3_check_flood(c) != NJT_OK) {
            njt_http_v3_close_uni_stream(c);
            return;
        }

        rc = njt_http_v3_parse_uni(c, &us->parse, &b);

        if (rc == NJT_DONE) {
            njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 read done");
            njt_http_v3_close_uni_stream(c);
            return;
        }

        if (rc > 0) {
            goto failed;
        }

        if (rc != NJT_AGAIN) {
            rc = NJT_HTTP_V3_ERR_GENERAL_PROTOCOL_ERROR;
            goto failed;
        }
    }

    if (njt_handle_read_event(rev, 0) != NJT_OK) {
        rc = NJT_HTTP_V3_ERR_INTERNAL_ERROR;
        goto failed;
    }

    return;

failed:

    njt_http_v3_finalize_connection(c, rc, "stream error");
    njt_http_v3_close_uni_stream(c);
}


static void
njt_http_v3_uni_dummy_read_handler(njt_event_t *rev)
{
    u_char             ch;
    njt_connection_t  *c;

    c = rev->data;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0, "http3 dummy read handler");

    if (c->close) {
        njt_http_v3_close_uni_stream(c);
        return;
    }

    if (rev->ready) {
        if (c->recv(c, &ch, 1) != 0) {
            njt_http_v3_finalize_connection(c, NJT_HTTP_V3_ERR_NO_ERROR, NULL);
            njt_http_v3_close_uni_stream(c);
            return;
        }
    }

    if (njt_handle_read_event(rev, 0) != NJT_OK) {
        njt_http_v3_finalize_connection(c, NJT_HTTP_V3_ERR_INTERNAL_ERROR,
                                        NULL);
        njt_http_v3_close_uni_stream(c);
    }
}


static void
njt_http_v3_uni_dummy_write_handler(njt_event_t *wev)
{
    njt_connection_t  *c;

    c = wev->data;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0, "http3 dummy write handler");

    if (njt_handle_write_event(wev, 0) != NJT_OK) {
        njt_http_v3_finalize_connection(c, NJT_HTTP_V3_ERR_INTERNAL_ERROR,
                                        NULL);
        njt_http_v3_close_uni_stream(c);
    }
}


static njt_connection_t *
njt_http_v3_get_uni_stream(njt_connection_t *c, njt_uint_t type)
{
    u_char                     buf[NJT_HTTP_V3_VARLEN_INT_LEN];
    size_t                     n;
    njt_int_t                  index;
    njt_connection_t          *sc;
    njt_http_v3_session_t     *h3c;
    njt_http_v3_uni_stream_t  *us;

    switch (type) {
    case NJT_HTTP_V3_STREAM_ENCODER:
        index = NJT_HTTP_V3_STREAM_SERVER_ENCODER;
        break;
    case NJT_HTTP_V3_STREAM_DECODER:
        index = NJT_HTTP_V3_STREAM_SERVER_DECODER;
        break;
    case NJT_HTTP_V3_STREAM_CONTROL:
        index = NJT_HTTP_V3_STREAM_SERVER_CONTROL;
        break;
    default:
        index = -1;
    }

    h3c = njt_http_v3_get_session(c);

    if (index >= 0) {
        if (h3c->known_streams[index]) {
            return h3c->known_streams[index];
        }
    }

    sc = njt_quic_open_stream(c, 0);
    if (sc == NULL) {
        goto failed;
    }

    njt_quic_cancelable_stream(sc);

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 create uni stream, type:%ui", type);

    us = njt_pcalloc(sc->pool, sizeof(njt_http_v3_uni_stream_t));
    if (us == NULL) {
        goto failed;
    }

    us->index = index;

    sc->data = us;

    sc->read->handler = njt_http_v3_uni_dummy_read_handler;
    sc->write->handler = njt_http_v3_uni_dummy_write_handler;

    if (index >= 0) {
        h3c->known_streams[index] = sc;
    }

    n = (u_char *) njt_http_v3_encode_varlen_int(buf, type) - buf;

    h3c = njt_http_v3_get_session(c);
    h3c->total_bytes += n;

    if (sc->send(sc, buf, n) != (ssize_t) n) {
        goto failed;
    }

    njt_post_event(sc->read, &njt_posted_events);

    return sc;

failed:

    njt_log_error(NJT_LOG_ERR, c->log, 0, "failed to create server stream");

    njt_http_v3_finalize_connection(c, NJT_HTTP_V3_ERR_STREAM_CREATION_ERROR,
                                    "failed to create server stream");
    if (sc) {
        njt_http_v3_close_uni_stream(sc);
    }

    return NULL;
}


njt_int_t
njt_http_v3_send_settings(njt_connection_t *c)
{
    u_char                  *p, buf[NJT_HTTP_V3_VARLEN_INT_LEN * 6];
    size_t                   n;
    njt_connection_t        *cc;
    njt_http_v3_session_t   *h3c;
    njt_http_v3_srv_conf_t  *h3scf;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0, "http3 send settings");

    cc = njt_http_v3_get_uni_stream(c, NJT_HTTP_V3_STREAM_CONTROL);
    if (cc == NULL) {
        return NJT_ERROR;
    }

    h3scf = njt_http_v3_get_module_srv_conf(c, njt_http_v3_module);

    n = njt_http_v3_encode_varlen_int(NULL,
                                      NJT_HTTP_V3_PARAM_MAX_TABLE_CAPACITY);
    n += njt_http_v3_encode_varlen_int(NULL, h3scf->max_table_capacity);
    n += njt_http_v3_encode_varlen_int(NULL, NJT_HTTP_V3_PARAM_BLOCKED_STREAMS);
    n += njt_http_v3_encode_varlen_int(NULL, h3scf->max_blocked_streams);

    p = (u_char *) njt_http_v3_encode_varlen_int(buf,
                                                 NJT_HTTP_V3_FRAME_SETTINGS);
    p = (u_char *) njt_http_v3_encode_varlen_int(p, n);
    p = (u_char *) njt_http_v3_encode_varlen_int(p,
                                         NJT_HTTP_V3_PARAM_MAX_TABLE_CAPACITY);
    p = (u_char *) njt_http_v3_encode_varlen_int(p, h3scf->max_table_capacity);
    p = (u_char *) njt_http_v3_encode_varlen_int(p,
                                            NJT_HTTP_V3_PARAM_BLOCKED_STREAMS);
    p = (u_char *) njt_http_v3_encode_varlen_int(p, h3scf->max_blocked_streams);
    n = p - buf;

    h3c = njt_http_v3_get_session(c);
    h3c->total_bytes += n;

    if (cc->send(cc, buf, n) != (ssize_t) n) {
        goto failed;
    }

    return NJT_OK;

failed:

    njt_log_error(NJT_LOG_ERR, c->log, 0, "failed to send settings");

    njt_http_v3_finalize_connection(c, NJT_HTTP_V3_ERR_EXCESSIVE_LOAD,
                                    "failed to send settings");
    njt_http_v3_close_uni_stream(cc);

    return NJT_ERROR;
}


njt_int_t
njt_http_v3_send_goaway(njt_connection_t *c, uint64_t id)
{
    u_char                 *p, buf[NJT_HTTP_V3_VARLEN_INT_LEN * 3];
    size_t                  n;
    njt_connection_t       *cc;
    njt_http_v3_session_t  *h3c;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0, "http3 send goaway %uL", id);

    cc = njt_http_v3_get_uni_stream(c, NJT_HTTP_V3_STREAM_CONTROL);
    if (cc == NULL) {
        return NJT_ERROR;
    }

    n = njt_http_v3_encode_varlen_int(NULL, id);
    p = (u_char *) njt_http_v3_encode_varlen_int(buf, NJT_HTTP_V3_FRAME_GOAWAY);
    p = (u_char *) njt_http_v3_encode_varlen_int(p, n);
    p = (u_char *) njt_http_v3_encode_varlen_int(p, id);
    n = p - buf;

    h3c = njt_http_v3_get_session(c);
    h3c->total_bytes += n;

    if (cc->send(cc, buf, n) != (ssize_t) n) {
        goto failed;
    }

    return NJT_OK;

failed:

    njt_log_error(NJT_LOG_ERR, c->log, 0, "failed to send goaway");

    njt_http_v3_finalize_connection(c, NJT_HTTP_V3_ERR_EXCESSIVE_LOAD,
                                    "failed to send goaway");
    njt_http_v3_close_uni_stream(cc);

    return NJT_ERROR;
}


njt_int_t
njt_http_v3_send_ack_section(njt_connection_t *c, njt_uint_t stream_id)
{
    u_char                  buf[NJT_HTTP_V3_PREFIX_INT_LEN];
    size_t                  n;
    njt_connection_t       *dc;
    njt_http_v3_session_t  *h3c;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 send section acknowledgement %ui", stream_id);

    dc = njt_http_v3_get_uni_stream(c, NJT_HTTP_V3_STREAM_DECODER);
    if (dc == NULL) {
        return NJT_ERROR;
    }

    buf[0] = 0x80;
    n = (u_char *) njt_http_v3_encode_prefix_int(buf, stream_id, 7) - buf;

    h3c = njt_http_v3_get_session(c);
    h3c->total_bytes += n;

    if (dc->send(dc, buf, n) != (ssize_t) n) {
        goto failed;
    }

    return NJT_OK;

failed:

    njt_log_error(NJT_LOG_ERR, c->log, 0,
                  "failed to send section acknowledgement");

    njt_http_v3_finalize_connection(c, NJT_HTTP_V3_ERR_EXCESSIVE_LOAD,
                                    "failed to send section acknowledgement");
    njt_http_v3_close_uni_stream(dc);

    return NJT_ERROR;
}


njt_int_t
njt_http_v3_send_cancel_stream(njt_connection_t *c, njt_uint_t stream_id)
{
    u_char                  buf[NJT_HTTP_V3_PREFIX_INT_LEN];
    size_t                  n;
    njt_connection_t       *dc;
    njt_http_v3_session_t  *h3c;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 send stream cancellation %ui", stream_id);

    dc = njt_http_v3_get_uni_stream(c, NJT_HTTP_V3_STREAM_DECODER);
    if (dc == NULL) {
        return NJT_ERROR;
    }

    buf[0] = 0x40;
    n = (u_char *) njt_http_v3_encode_prefix_int(buf, stream_id, 6) - buf;

    h3c = njt_http_v3_get_session(c);
    h3c->total_bytes += n;

    if (dc->send(dc, buf, n) != (ssize_t) n) {
        goto failed;
    }

    return NJT_OK;

failed:

    njt_log_error(NJT_LOG_ERR, c->log, 0, "failed to send stream cancellation");

    njt_http_v3_finalize_connection(c, NJT_HTTP_V3_ERR_EXCESSIVE_LOAD,
                                    "failed to send stream cancellation");
    njt_http_v3_close_uni_stream(dc);

    return NJT_ERROR;
}


njt_int_t
njt_http_v3_send_inc_insert_count(njt_connection_t *c, njt_uint_t inc)
{
    u_char                  buf[NJT_HTTP_V3_PREFIX_INT_LEN];
    size_t                  n;
    njt_connection_t       *dc;
    njt_http_v3_session_t  *h3c;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 send insert count increment %ui", inc);

    dc = njt_http_v3_get_uni_stream(c, NJT_HTTP_V3_STREAM_DECODER);
    if (dc == NULL) {
        return NJT_ERROR;
    }

    buf[0] = 0;
    n = (u_char *) njt_http_v3_encode_prefix_int(buf, inc, 6) - buf;

    h3c = njt_http_v3_get_session(c);
    h3c->total_bytes += n;

    if (dc->send(dc, buf, n) != (ssize_t) n) {
        goto failed;
    }

    return NJT_OK;

failed:

    njt_log_error(NJT_LOG_ERR, c->log, 0,
                  "failed to send insert count increment");

    njt_http_v3_finalize_connection(c, NJT_HTTP_V3_ERR_EXCESSIVE_LOAD,
                                    "failed to send insert count increment");
    njt_http_v3_close_uni_stream(dc);

    return NJT_ERROR;
}


njt_int_t
njt_http_v3_cancel_stream(njt_connection_t *c, njt_uint_t stream_id)
{
    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 cancel stream %ui", stream_id);

    /* we do not use dynamic tables */

    return NJT_OK;
}
