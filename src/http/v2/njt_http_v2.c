
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 * Copyright (C) Valentin V. Bartenev
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_http_v2_module.h>


/* errors */
#define NJT_HTTP_V2_NO_ERROR                     0x0
#define NJT_HTTP_V2_PROTOCOL_ERROR               0x1
#define NJT_HTTP_V2_INTERNAL_ERROR               0x2
#define NJT_HTTP_V2_FLOW_CTRL_ERROR              0x3
#define NJT_HTTP_V2_SETTINGS_TIMEOUT             0x4
#define NJT_HTTP_V2_STREAM_CLOSED                0x5
#define NJT_HTTP_V2_SIZE_ERROR                   0x6
#define NJT_HTTP_V2_REFUSED_STREAM               0x7
#define NJT_HTTP_V2_CANCEL                       0x8
#define NJT_HTTP_V2_COMP_ERROR                   0x9
#define NJT_HTTP_V2_CONNECT_ERROR                0xa
#define NJT_HTTP_V2_ENHANCE_YOUR_CALM            0xb
#define NJT_HTTP_V2_INADEQUATE_SECURITY          0xc
#define NJT_HTTP_V2_HTTP_1_1_REQUIRED            0xd

/* frame sizes */
#define NJT_HTTP_V2_SETTINGS_ACK_SIZE            0
#define NJT_HTTP_V2_RST_STREAM_SIZE              4
#define NJT_HTTP_V2_PRIORITY_SIZE                5
#define NJT_HTTP_V2_PING_SIZE                    8
#define NJT_HTTP_V2_GOAWAY_SIZE                  8
#define NJT_HTTP_V2_WINDOW_UPDATE_SIZE           4

#define NJT_HTTP_V2_SETTINGS_PARAM_SIZE          6

/* settings fields */
#define NJT_HTTP_V2_HEADER_TABLE_SIZE_SETTING    0x1
#define NJT_HTTP_V2_ENABLE_PUSH_SETTING          0x2
#define NJT_HTTP_V2_MAX_STREAMS_SETTING          0x3
#define NJT_HTTP_V2_INIT_WINDOW_SIZE_SETTING     0x4
#define NJT_HTTP_V2_MAX_FRAME_SIZE_SETTING       0x5

#define NJT_HTTP_V2_FRAME_BUFFER_SIZE            24

#define NJT_HTTP_V2_ROOT                         (void *) -1


static void njt_http_v2_read_handler(njt_event_t *rev);
static void njt_http_v2_write_handler(njt_event_t *wev);
static void njt_http_v2_handle_connection(njt_http_v2_connection_t *h2c);
static void njt_http_v2_lingering_close(njt_connection_t *c);
static void njt_http_v2_lingering_close_handler(njt_event_t *rev);

static u_char *njt_http_v2_state_preface(njt_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *njt_http_v2_state_preface_end(njt_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *njt_http_v2_state_head(njt_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *njt_http_v2_state_data(njt_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *njt_http_v2_state_read_data(njt_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *njt_http_v2_state_headers(njt_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *njt_http_v2_state_header_block(njt_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *njt_http_v2_state_field_len(njt_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *njt_http_v2_state_field_huff(njt_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *njt_http_v2_state_field_raw(njt_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *njt_http_v2_state_field_skip(njt_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *njt_http_v2_state_process_header(njt_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *njt_http_v2_state_header_complete(njt_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *njt_http_v2_handle_continuation(njt_http_v2_connection_t *h2c,
    u_char *pos, u_char *end, njt_http_v2_handler_pt handler);
static u_char *njt_http_v2_state_priority(njt_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *njt_http_v2_state_rst_stream(njt_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *njt_http_v2_state_settings(njt_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *njt_http_v2_state_settings_params(njt_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *njt_http_v2_state_push_promise(njt_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *njt_http_v2_state_ping(njt_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *njt_http_v2_state_goaway(njt_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *njt_http_v2_state_window_update(njt_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *njt_http_v2_state_continuation(njt_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *njt_http_v2_state_complete(njt_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *njt_http_v2_state_skip_padded(njt_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *njt_http_v2_state_skip(njt_http_v2_connection_t *h2c,
    u_char *pos, u_char *end);
static u_char *njt_http_v2_state_save(njt_http_v2_connection_t *h2c,
    u_char *pos, u_char *end, njt_http_v2_handler_pt handler);
static u_char *njt_http_v2_state_headers_save(njt_http_v2_connection_t *h2c,
    u_char *pos, u_char *end, njt_http_v2_handler_pt handler);
static u_char *njt_http_v2_connection_error(njt_http_v2_connection_t *h2c,
    njt_uint_t err);

static njt_int_t njt_http_v2_parse_int(njt_http_v2_connection_t *h2c,
    u_char **pos, u_char *end, njt_uint_t prefix);

static njt_http_v2_stream_t *njt_http_v2_create_stream(
    njt_http_v2_connection_t *h2c);
static njt_http_v2_node_t *njt_http_v2_get_node_by_id(
    njt_http_v2_connection_t *h2c, njt_uint_t sid, njt_uint_t alloc);
static njt_http_v2_node_t *njt_http_v2_get_closed_node(
    njt_http_v2_connection_t *h2c);
#define njt_http_v2_index_size(h2scf)  (h2scf->streams_index_mask + 1)
#define njt_http_v2_index(h2scf, sid)  ((sid >> 1) & h2scf->streams_index_mask)

static njt_int_t njt_http_v2_send_settings(njt_http_v2_connection_t *h2c);
static njt_int_t njt_http_v2_settings_frame_handler(
    njt_http_v2_connection_t *h2c, njt_http_v2_out_frame_t *frame);
static njt_int_t njt_http_v2_send_window_update(njt_http_v2_connection_t *h2c,
    njt_uint_t sid, size_t window);
static njt_int_t njt_http_v2_send_rst_stream(njt_http_v2_connection_t *h2c,
    njt_uint_t sid, njt_uint_t status);
static njt_int_t njt_http_v2_send_goaway(njt_http_v2_connection_t *h2c,
    njt_uint_t status);

static njt_http_v2_out_frame_t *njt_http_v2_get_frame(
    njt_http_v2_connection_t *h2c, size_t length, njt_uint_t type,
    u_char flags, njt_uint_t sid);
static njt_int_t njt_http_v2_frame_handler(njt_http_v2_connection_t *h2c,
    njt_http_v2_out_frame_t *frame);

static njt_int_t njt_http_v2_validate_header(njt_http_request_t *r,
    njt_http_v2_header_t *header);
static njt_int_t njt_http_v2_pseudo_header(njt_http_request_t *r,
    njt_http_v2_header_t *header);
static njt_int_t njt_http_v2_parse_path(njt_http_request_t *r,
    njt_str_t *value);
static njt_int_t njt_http_v2_parse_method(njt_http_request_t *r,
    njt_str_t *value);
static njt_int_t njt_http_v2_parse_scheme(njt_http_request_t *r,
    njt_str_t *value);
static njt_int_t njt_http_v2_parse_authority(njt_http_request_t *r,
    njt_str_t *value);
static njt_int_t njt_http_v2_construct_request_line(njt_http_request_t *r);
static njt_int_t njt_http_v2_cookie(njt_http_request_t *r,
    njt_http_v2_header_t *header);
static njt_int_t njt_http_v2_construct_cookie_header(njt_http_request_t *r);
static void njt_http_v2_run_request(njt_http_request_t *r);
static njt_int_t njt_http_v2_process_request_body(njt_http_request_t *r,
    u_char *pos, size_t size, njt_uint_t last, njt_uint_t flush);
static njt_int_t njt_http_v2_filter_request_body(njt_http_request_t *r);
static void njt_http_v2_read_client_request_body_handler(njt_http_request_t *r);

static njt_int_t njt_http_v2_terminate_stream(njt_http_v2_connection_t *h2c,
    njt_http_v2_stream_t *stream, njt_uint_t status);
static void njt_http_v2_close_stream_handler(njt_event_t *ev);
static void njt_http_v2_retry_close_stream_handler(njt_event_t *ev);
static void njt_http_v2_handle_connection_handler(njt_event_t *rev);
static void njt_http_v2_idle_handler(njt_event_t *rev);
static void njt_http_v2_finalize_connection(njt_http_v2_connection_t *h2c,
    njt_uint_t status);

static njt_int_t njt_http_v2_adjust_windows(njt_http_v2_connection_t *h2c,
    ssize_t delta);
static void njt_http_v2_set_dependency(njt_http_v2_connection_t *h2c,
    njt_http_v2_node_t *node, njt_uint_t depend, njt_uint_t exclusive);
static void njt_http_v2_node_children_update(njt_http_v2_node_t *node);

static void njt_http_v2_pool_cleanup(void *data);


static njt_http_v2_handler_pt njt_http_v2_frame_states[] = {
    njt_http_v2_state_data,               /* NJT_HTTP_V2_DATA_FRAME */
    njt_http_v2_state_headers,            /* NJT_HTTP_V2_HEADERS_FRAME */
    njt_http_v2_state_priority,           /* NJT_HTTP_V2_PRIORITY_FRAME */
    njt_http_v2_state_rst_stream,         /* NJT_HTTP_V2_RST_STREAM_FRAME */
    njt_http_v2_state_settings,           /* NJT_HTTP_V2_SETTINGS_FRAME */
    njt_http_v2_state_push_promise,       /* NJT_HTTP_V2_PUSH_PROMISE_FRAME */
    njt_http_v2_state_ping,               /* NJT_HTTP_V2_PING_FRAME */
    njt_http_v2_state_goaway,             /* NJT_HTTP_V2_GOAWAY_FRAME */
    njt_http_v2_state_window_update,      /* NJT_HTTP_V2_WINDOW_UPDATE_FRAME */
    njt_http_v2_state_continuation        /* NJT_HTTP_V2_CONTINUATION_FRAME */
};

#define NJT_HTTP_V2_FRAME_STATES                                              \
    (sizeof(njt_http_v2_frame_states) / sizeof(njt_http_v2_handler_pt))


void
njt_http_v2_init(njt_event_t *rev)
{
    u_char                    *p, *end;
    njt_connection_t          *c;
    njt_pool_cleanup_t        *cln;
    njt_http_connection_t     *hc;
    njt_http_v2_srv_conf_t    *h2scf;
    njt_http_v2_main_conf_t   *h2mcf;
    njt_http_v2_connection_t  *h2c;
    njt_http_core_srv_conf_t  *cscf;

    c = rev->data;
    hc = c->data;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0, "init http2 connection");

    c->log->action = "processing HTTP/2 connection";

    h2mcf = njt_http_get_module_main_conf(hc->conf_ctx, njt_http_v2_module);

    if (h2mcf->recv_buffer == NULL) {
        h2mcf->recv_buffer = njt_palloc(njt_cycle->pool,
                                        h2mcf->recv_buffer_size);
        if (h2mcf->recv_buffer == NULL) {
            njt_http_close_connection(c);
            return;
        }
    }

    h2c = njt_pcalloc(c->pool, sizeof(njt_http_v2_connection_t));
    if (h2c == NULL) {
        njt_http_close_connection(c);
        return;
    }

    h2c->connection = c;
    h2c->http_connection = hc;

    h2c->send_window = NJT_HTTP_V2_DEFAULT_WINDOW;
    h2c->recv_window = NJT_HTTP_V2_MAX_WINDOW;

    h2c->init_window = NJT_HTTP_V2_DEFAULT_WINDOW;

    h2c->frame_size = NJT_HTTP_V2_DEFAULT_FRAME_SIZE;

    h2scf = njt_http_get_module_srv_conf(hc->conf_ctx, njt_http_v2_module);

    h2c->priority_limit = njt_max(h2scf->concurrent_streams, 100);

    h2c->pool = njt_create_pool(h2scf->pool_size, h2c->connection->log);
    if (h2c->pool == NULL) {
        njt_http_close_connection(c);
        return;
    }

    cln = njt_pool_cleanup_add(c->pool, 0);
    if (cln == NULL) {
        njt_http_close_connection(c);
        return;
    }

    cln->handler = njt_http_v2_pool_cleanup;
    cln->data = h2c;

    h2c->streams_index = njt_pcalloc(c->pool, njt_http_v2_index_size(h2scf)
                                              * sizeof(njt_http_v2_node_t *));
    if (h2c->streams_index == NULL) {
        njt_http_close_connection(c);
        return;
    }

    if (njt_http_v2_send_settings(h2c) == NJT_ERROR) {
        njt_http_close_connection(c);
        return;
    }

    if (njt_http_v2_send_window_update(h2c, 0, NJT_HTTP_V2_MAX_WINDOW
                                               - NJT_HTTP_V2_DEFAULT_WINDOW)
        == NJT_ERROR)
    {
        njt_http_close_connection(c);
        return;
    }

    h2c->state.handler = njt_http_v2_state_preface;

    njt_queue_init(&h2c->waiting);
    njt_queue_init(&h2c->dependencies);
    njt_queue_init(&h2c->closed);

    c->data = h2c;

    rev->handler = njt_http_v2_read_handler;
    c->write->handler = njt_http_v2_write_handler;

    if (!rev->timer_set) {
        cscf = njt_http_get_module_srv_conf(hc->conf_ctx,
                                            njt_http_core_module);
        njt_add_timer(rev, cscf->client_header_timeout);
    }

    c->idle = 1;
    njt_reusable_connection(c, 0);

    if (c->buffer) {
        p = c->buffer->pos;
        end = c->buffer->last;

        do {
            p = h2c->state.handler(h2c, p, end);

            if (p == NULL) {
                return;
            }

        } while (p != end);

        h2c->total_bytes += p - c->buffer->pos;
        c->buffer->pos = p;
    }

    njt_http_v2_read_handler(rev);
}


static void
njt_http_v2_read_handler(njt_event_t *rev)
{
    u_char                    *p, *end;
    size_t                     available;
    ssize_t                    n;
    njt_connection_t          *c;
    njt_http_v2_main_conf_t   *h2mcf;
    njt_http_v2_connection_t  *h2c;

    c = rev->data;
    h2c = c->data;

    if (rev->timedout) {
        njt_log_error(NJT_LOG_INFO, c->log, NJT_ETIMEDOUT, "client timed out");
        njt_http_v2_finalize_connection(h2c, NJT_HTTP_V2_PROTOCOL_ERROR);
        return;
    }

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0, "http2 read handler");

    h2c->blocked = 1;
    h2c->new_streams = 0;

    if (c->close) {
        c->close = 0;

        if (c->error) {
            njt_http_v2_finalize_connection(h2c, 0);
            return;
        }

        if (!h2c->processing) {
            njt_http_v2_finalize_connection(h2c, NJT_HTTP_V2_NO_ERROR);
            return;
        }

        if (!h2c->goaway) {
            h2c->goaway = 1;

            if (njt_http_v2_send_goaway(h2c, NJT_HTTP_V2_NO_ERROR)
                == NJT_ERROR)
            {
                njt_http_v2_finalize_connection(h2c, 0);
                return;
            }

            if (njt_http_v2_send_output_queue(h2c) == NJT_ERROR) {
                njt_http_v2_finalize_connection(h2c, 0);
                return;
            }
        }

        h2c->blocked = 0;

        return;
    }

    h2mcf = njt_http_get_module_main_conf(h2c->http_connection->conf_ctx,
                                          njt_http_v2_module);

    available = h2mcf->recv_buffer_size - NJT_HTTP_V2_STATE_BUFFER_SIZE;

    do {
        p = h2mcf->recv_buffer;
        end = njt_cpymem(p, h2c->state.buffer, h2c->state.buffer_used);

        n = c->recv(c, end, available);

        if (n == NJT_AGAIN) {
            break;
        }

        if (n == 0 && (h2c->state.incomplete || h2c->processing)) {
            njt_log_error(NJT_LOG_INFO, c->log, 0,
                          "client prematurely closed connection");
        }

        if (n == 0 || n == NJT_ERROR) {
            c->error = 1;
            njt_http_v2_finalize_connection(h2c, 0);
            return;
        }

        end += n;

        h2c->state.buffer_used = 0;
        h2c->state.incomplete = 0;

        do {
            p = h2c->state.handler(h2c, p, end);

            if (p == NULL) {
                return;
            }

        } while (p != end);

        h2c->total_bytes += n;

        if (h2c->total_bytes / 8 > h2c->payload_bytes + 1048576) {
            njt_log_error(NJT_LOG_INFO, c->log, 0, "http2 flood detected");
            njt_http_v2_finalize_connection(h2c, NJT_HTTP_V2_NO_ERROR);
            return;
        }

    } while (rev->ready);

    if (njt_handle_read_event(rev, 0) != NJT_OK) {
        njt_http_v2_finalize_connection(h2c, NJT_HTTP_V2_INTERNAL_ERROR);
        return;
    }

    if (h2c->last_out && njt_http_v2_send_output_queue(h2c) == NJT_ERROR) {
        njt_http_v2_finalize_connection(h2c, 0);
        return;
    }

    h2c->blocked = 0;

    njt_http_v2_handle_connection(h2c);
}


static void
njt_http_v2_write_handler(njt_event_t *wev)
{
    njt_int_t                  rc;
    njt_connection_t          *c;
    njt_http_v2_connection_t  *h2c;

    c = wev->data;
    h2c = c->data;

    if (wev->timedout) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http2 write event timed out");
        c->error = 1;
        c->timedout = 1;
        njt_http_v2_finalize_connection(h2c, 0);
        return;
    }

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0, "http2 write handler");

    if (h2c->last_out == NULL && !c->buffered) {

        if (wev->timer_set) {
            njt_del_timer(wev);
        }

        njt_http_v2_handle_connection(h2c);
        return;
    }

    h2c->blocked = 1;

    rc = njt_http_v2_send_output_queue(h2c);

    if (rc == NJT_ERROR) {
        njt_http_v2_finalize_connection(h2c, 0);
        return;
    }

    h2c->blocked = 0;

    if (rc == NJT_AGAIN) {
        return;
    }

    njt_http_v2_handle_connection(h2c);
}


njt_int_t
njt_http_v2_send_output_queue(njt_http_v2_connection_t *h2c)
{
    int                        tcp_nodelay;
    njt_chain_t               *cl;
    njt_event_t               *wev;
    njt_connection_t          *c;
    njt_http_v2_out_frame_t   *out, *frame, *fn;
    njt_http_core_loc_conf_t  *clcf;

    c = h2c->connection;
    wev = c->write;

    if (c->error) {
        goto error;
    }

    if (!wev->ready) {
        return NJT_AGAIN;
    }

    cl = NULL;
    out = NULL;

    for (frame = h2c->last_out; frame; frame = fn) {
        frame->last->next = cl;
        cl = frame->first;

        fn = frame->next;
        frame->next = out;
        out = frame;

        njt_log_debug4(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http2 frame out: %p sid:%ui bl:%d len:%uz",
                       out, out->stream ? out->stream->node->id : 0,
                       out->blocked, out->length);
    }

    cl = c->send_chain(c, cl, 0);

    if (cl == NJT_CHAIN_ERROR) {
        goto error;
    }

    clcf = njt_http_get_module_loc_conf(h2c->http_connection->conf_ctx,
                                        njt_http_core_module);

    if (njt_handle_write_event(wev, clcf->send_lowat) != NJT_OK) {
        goto error;
    }

    if (c->tcp_nopush == NJT_TCP_NOPUSH_SET) {
        if (njt_tcp_push(c->fd) == -1) {
            njt_connection_error(c, njt_socket_errno, njt_tcp_push_n " failed");
            goto error;
        }

        c->tcp_nopush = NJT_TCP_NOPUSH_UNSET;
        tcp_nodelay = njt_tcp_nodelay_and_tcp_nopush ? 1 : 0;

    } else {
        tcp_nodelay = 1;
    }

    if (tcp_nodelay && clcf->tcp_nodelay && njt_tcp_nodelay(c) != NJT_OK) {
        goto error;
    }

    for ( /* void */ ; out; out = fn) {
        fn = out->next;

        if (out->handler(h2c, out) != NJT_OK) {
            out->blocked = 1;
            break;
        }

        njt_log_debug4(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http2 frame sent: %p sid:%ui bl:%d len:%uz",
                       out, out->stream ? out->stream->node->id : 0,
                       out->blocked, out->length);
    }

    frame = NULL;

    for ( /* void */ ; out; out = fn) {
        fn = out->next;
        out->next = frame;
        frame = out;
    }

    h2c->last_out = frame;

    if (!wev->ready) {
        njt_add_timer(wev, clcf->send_timeout);
        return NJT_AGAIN;
    }

    if (wev->timer_set) {
        njt_del_timer(wev);
    }

    return NJT_OK;

error:

    c->error = 1;

    if (!h2c->blocked) {
        njt_post_event(wev, &njt_posted_events);
    }

    return NJT_ERROR;
}


static void
njt_http_v2_handle_connection(njt_http_v2_connection_t *h2c)
{
    njt_int_t                  rc;
    njt_connection_t          *c;
    njt_http_core_loc_conf_t  *clcf;

    if (h2c->last_out || h2c->processing) {
        return;
    }

    c = h2c->connection;

    if (c->error) {
        njt_http_close_connection(c);
        return;
    }

    if (c->buffered) {
        h2c->blocked = 1;

        rc = njt_http_v2_send_output_queue(h2c);

        h2c->blocked = 0;

        if (rc == NJT_ERROR) {
            njt_http_close_connection(c);
            return;
        }

        if (rc == NJT_AGAIN) {
            return;
        }

        /* rc == NJT_OK */
    }

    if (h2c->goaway) {
        njt_http_v2_lingering_close(c);
        return;
    }

    clcf = njt_http_get_module_loc_conf(h2c->http_connection->conf_ctx,
                                        njt_http_core_module);

    if (!c->read->timer_set) {
        njt_add_timer(c->read, clcf->keepalive_timeout);
    }

    njt_reusable_connection(c, 1);

    if (h2c->state.incomplete) {
        return;
    }

    njt_destroy_pool(h2c->pool);

    h2c->pool = NULL;
    h2c->free_frames = NULL;
    h2c->frames = 0;
    h2c->free_fake_connections = NULL;

#if (NJT_HTTP_SSL)
    if (c->ssl) {
        njt_ssl_free_buffer(c);
    }
#endif

    c->destroyed = 1;

    c->write->handler = njt_http_empty_handler;
    c->read->handler = njt_http_v2_idle_handler;

    if (c->write->timer_set) {
        njt_del_timer(c->write);
    }
}


static void
njt_http_v2_lingering_close(njt_connection_t *c)
{
    njt_event_t               *rev, *wev;
    njt_http_v2_connection_t  *h2c;
    njt_http_core_loc_conf_t  *clcf;

    h2c = c->data;

    clcf = njt_http_get_module_loc_conf(h2c->http_connection->conf_ctx,
                                        njt_http_core_module);

    if (clcf->lingering_close == NJT_HTTP_LINGERING_OFF) {
        njt_http_close_connection(c);
        return;
    }

    if (h2c->lingering_time == 0) {
        h2c->lingering_time = njt_time()
                              + (time_t) (clcf->lingering_time / 1000);
    }

#if (NJT_HTTP_SSL)
    if (c->ssl) {
        njt_int_t  rc;

        rc = njt_ssl_shutdown(c);

        if (rc == NJT_ERROR) {
            njt_http_close_connection(c);
            return;
        }

        if (rc == NJT_AGAIN) {
            c->ssl->handler = njt_http_v2_lingering_close;
            return;
        }
    }
#endif

    rev = c->read;
    rev->handler = njt_http_v2_lingering_close_handler;

    if (njt_handle_read_event(rev, 0) != NJT_OK) {
        njt_http_close_connection(c);
        return;
    }

    wev = c->write;
    wev->handler = njt_http_empty_handler;

    if (wev->active && (njt_event_flags & NJT_USE_LEVEL_EVENT)) {
        if (njt_del_event(wev, NJT_WRITE_EVENT, 0) != NJT_OK) {
            njt_http_close_connection(c);
            return;
        }
    }

    if (njt_shutdown_socket(c->fd, NJT_WRITE_SHUTDOWN) == -1) {
        njt_connection_error(c, njt_socket_errno,
                             njt_shutdown_socket_n " failed");
        njt_http_close_connection(c);
        return;
    }

    c->close = 0;
    njt_reusable_connection(c, 1);

    njt_add_timer(rev, clcf->lingering_timeout);

    if (rev->ready) {
        njt_http_v2_lingering_close_handler(rev);
    }
}


static void
njt_http_v2_lingering_close_handler(njt_event_t *rev)
{
    ssize_t                    n;
    njt_msec_t                 timer;
    njt_connection_t          *c;
    njt_http_core_loc_conf_t  *clcf;
    njt_http_v2_connection_t  *h2c;
    u_char                     buffer[NJT_HTTP_LINGERING_BUFFER_SIZE];

    c = rev->data;
    h2c = c->data;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http2 lingering close handler");

    if (rev->timedout || c->close) {
        njt_http_close_connection(c);
        return;
    }

    timer = (njt_msec_t) h2c->lingering_time - (njt_msec_t) njt_time();
    if ((njt_msec_int_t) timer <= 0) {
        njt_http_close_connection(c);
        return;
    }

    do {
        n = c->recv(c, buffer, NJT_HTTP_LINGERING_BUFFER_SIZE);

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0, "lingering read: %z", n);

        if (n == NJT_AGAIN) {
            break;
        }

        if (n == NJT_ERROR || n == 0) {
            njt_http_close_connection(c);
            return;
        }

    } while (rev->ready);

    if (njt_handle_read_event(rev, 0) != NJT_OK) {
        njt_http_close_connection(c);
        return;
    }

    clcf = njt_http_get_module_loc_conf(h2c->http_connection->conf_ctx,
                                        njt_http_core_module);
    timer *= 1000;

    if (timer > clcf->lingering_timeout) {
        timer = clcf->lingering_timeout;
    }

    njt_add_timer(rev, timer);
}


static u_char *
njt_http_v2_state_preface(njt_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    static const u_char preface[] = NJT_HTTP_V2_PREFACE_START;

    if ((size_t) (end - pos) < sizeof(preface) - 1) {
        return njt_http_v2_state_save(h2c, pos, end, njt_http_v2_state_preface);
    }

    if (njt_memcmp(pos, preface, sizeof(preface) - 1) != 0) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "invalid connection preface");

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_PROTOCOL_ERROR);
    }

    return njt_http_v2_state_preface_end(h2c, pos + sizeof(preface) - 1, end);
}


static u_char *
njt_http_v2_state_preface_end(njt_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    static const u_char preface[] = NJT_HTTP_V2_PREFACE_END;

    if ((size_t) (end - pos) < sizeof(preface) - 1) {
        return njt_http_v2_state_save(h2c, pos, end,
                                      njt_http_v2_state_preface_end);
    }

    if (njt_memcmp(pos, preface, sizeof(preface) - 1) != 0) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "invalid connection preface");

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_PROTOCOL_ERROR);
    }

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 preface verified");

    return njt_http_v2_state_head(h2c, pos + sizeof(preface) - 1, end);
}


static u_char *
njt_http_v2_state_head(njt_http_v2_connection_t *h2c, u_char *pos, u_char *end)
{
    uint32_t    head;
    njt_uint_t  type;

    if (end - pos < NJT_HTTP_V2_FRAME_HEADER_SIZE) {
        return njt_http_v2_state_save(h2c, pos, end, njt_http_v2_state_head);
    }

    head = njt_http_v2_parse_uint32(pos);

    h2c->state.length = njt_http_v2_parse_length(head);
    h2c->state.flags = pos[4];

    h2c->state.sid = njt_http_v2_parse_sid(&pos[5]);

    pos += NJT_HTTP_V2_FRAME_HEADER_SIZE;

    type = njt_http_v2_parse_type(head);

    njt_log_debug4(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 frame type:%ui f:%Xd l:%uz sid:%ui",
                   type, h2c->state.flags, h2c->state.length, h2c->state.sid);

    if (type >= NJT_HTTP_V2_FRAME_STATES) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent frame with unknown type %ui", type);
        return njt_http_v2_state_skip(h2c, pos, end);
    }

    return njt_http_v2_frame_states[type](h2c, pos, end);
}


static u_char *
njt_http_v2_state_data(njt_http_v2_connection_t *h2c, u_char *pos, u_char *end)
{
    size_t                 size;
    njt_http_v2_node_t    *node;
    njt_http_v2_stream_t  *stream;

    size = h2c->state.length;

    if (h2c->state.flags & NJT_HTTP_V2_PADDED_FLAG) {

        if (h2c->state.length == 0) {
            njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                          "client sent padded DATA frame "
                          "with incorrect length: 0");

            return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_SIZE_ERROR);
        }

        if (end - pos == 0) {
            return njt_http_v2_state_save(h2c, pos, end,
                                          njt_http_v2_state_data);
        }

        h2c->state.padding = *pos++;

        if (h2c->state.padding >= size) {
            njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                          "client sent padded DATA frame "
                          "with incorrect length: %uz, padding: %uz",
                          size, h2c->state.padding);

            return njt_http_v2_connection_error(h2c,
                                                NJT_HTTP_V2_PROTOCOL_ERROR);
        }

        h2c->state.length -= 1 + h2c->state.padding;
    }

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 DATA frame");

    if (h2c->state.sid == 0) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent DATA frame with incorrect identifier");

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_PROTOCOL_ERROR);
    }

    if (size > h2c->recv_window) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client violated connection flow control: "
                      "received DATA frame length %uz, available window %uz",
                      size, h2c->recv_window);

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_FLOW_CTRL_ERROR);
    }

    h2c->recv_window -= size;

    if (h2c->recv_window < NJT_HTTP_V2_MAX_WINDOW / 4) {

        if (njt_http_v2_send_window_update(h2c, 0, NJT_HTTP_V2_MAX_WINDOW
                                                   - h2c->recv_window)
            == NJT_ERROR)
        {
            return njt_http_v2_connection_error(h2c,
                                                NJT_HTTP_V2_INTERNAL_ERROR);
        }

        h2c->recv_window = NJT_HTTP_V2_MAX_WINDOW;
    }

    node = njt_http_v2_get_node_by_id(h2c, h2c->state.sid, 0);

    if (node == NULL || node->stream == NULL) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "unknown http2 stream");

        return njt_http_v2_state_skip_padded(h2c, pos, end);
    }

    stream = node->stream;

    if (size > stream->recv_window) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client violated flow control for stream %ui: "
                      "received DATA frame length %uz, available window %uz",
                      node->id, size, stream->recv_window);

        if (njt_http_v2_terminate_stream(h2c, stream,
                                         NJT_HTTP_V2_FLOW_CTRL_ERROR)
            == NJT_ERROR)
        {
            return njt_http_v2_connection_error(h2c,
                                                NJT_HTTP_V2_INTERNAL_ERROR);
        }

        return njt_http_v2_state_skip_padded(h2c, pos, end);
    }

    stream->recv_window -= size;

    if (stream->no_flow_control
        && stream->recv_window < NJT_HTTP_V2_MAX_WINDOW / 4)
    {
        if (njt_http_v2_send_window_update(h2c, node->id,
                                           NJT_HTTP_V2_MAX_WINDOW
                                           - stream->recv_window)
            == NJT_ERROR)
        {
            return njt_http_v2_connection_error(h2c,
                                                NJT_HTTP_V2_INTERNAL_ERROR);
        }

        stream->recv_window = NJT_HTTP_V2_MAX_WINDOW;
    }

    if (stream->in_closed) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent DATA frame for half-closed stream %ui",
                      node->id);

        if (njt_http_v2_terminate_stream(h2c, stream,
                                         NJT_HTTP_V2_STREAM_CLOSED)
            == NJT_ERROR)
        {
            return njt_http_v2_connection_error(h2c,
                                                NJT_HTTP_V2_INTERNAL_ERROR);
        }

        return njt_http_v2_state_skip_padded(h2c, pos, end);
    }

    h2c->state.stream = stream;

    return njt_http_v2_state_read_data(h2c, pos, end);
}


static u_char *
njt_http_v2_state_read_data(njt_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    size_t                   size;
    njt_buf_t               *buf;
    njt_int_t                rc;
    njt_connection_t        *fc;
    njt_http_request_t      *r;
    njt_http_v2_stream_t    *stream;
    njt_http_v2_srv_conf_t  *h2scf;

    stream = h2c->state.stream;

    if (stream == NULL) {
        return njt_http_v2_state_skip_padded(h2c, pos, end);
    }

    if (stream->skip_data) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "skipping http2 DATA frame");

        return njt_http_v2_state_skip_padded(h2c, pos, end);
    }

    r = stream->request;
    fc = r->connection;

    if (r->reading_body && !r->request_body_no_buffering) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "skipping http2 DATA frame");

        return njt_http_v2_state_skip_padded(h2c, pos, end);
    }

    if (r->headers_in.content_length_n < 0 && !r->headers_in.chunked) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "skipping http2 DATA frame");

        return njt_http_v2_state_skip_padded(h2c, pos, end);
    }

    size = end - pos;

    if (size >= h2c->state.length) {
        size = h2c->state.length;
        stream->in_closed = h2c->state.flags & NJT_HTTP_V2_END_STREAM_FLAG;
    }

    h2c->payload_bytes += size;

    if (r->request_body) {
        rc = njt_http_v2_process_request_body(r, pos, size,
                                              stream->in_closed, 0);

        if (rc != NJT_OK && rc != NJT_AGAIN) {
            stream->skip_data = 1;
            njt_http_finalize_request(r, rc);
        }

        njt_http_run_posted_requests(fc);

    } else if (size) {
        buf = stream->preread;

        if (buf == NULL) {
            h2scf = njt_http_get_module_srv_conf(r, njt_http_v2_module);

            buf = njt_create_temp_buf(r->pool, h2scf->preread_size);
            if (buf == NULL) {
                return njt_http_v2_connection_error(h2c,
                                                    NJT_HTTP_V2_INTERNAL_ERROR);
            }

            stream->preread = buf;
        }

        if (size > (size_t) (buf->end - buf->last)) {
            njt_log_error(NJT_LOG_ALERT, h2c->connection->log, 0,
                          "http2 preread buffer overflow");
            return njt_http_v2_connection_error(h2c,
                                                NJT_HTTP_V2_INTERNAL_ERROR);
        }

        buf->last = njt_cpymem(buf->last, pos, size);
    }

    pos += size;
    h2c->state.length -= size;

    if (h2c->state.length) {
        return njt_http_v2_state_save(h2c, pos, end,
                                      njt_http_v2_state_read_data);
    }

    if (h2c->state.padding) {
        return njt_http_v2_state_skip_padded(h2c, pos, end);
    }

    return njt_http_v2_state_complete(h2c, pos, end);
}


static u_char *
njt_http_v2_state_headers(njt_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    size_t                     size;
    njt_uint_t                 padded, priority, depend, dependency, excl,
                               weight;
    njt_uint_t                 status;
    njt_http_v2_node_t        *node;
    njt_http_v2_stream_t      *stream;
    njt_http_v2_srv_conf_t    *h2scf;
    njt_http_core_srv_conf_t  *cscf;
    njt_http_core_loc_conf_t  *clcf;

    padded = h2c->state.flags & NJT_HTTP_V2_PADDED_FLAG;
    priority = h2c->state.flags & NJT_HTTP_V2_PRIORITY_FLAG;

    size = 0;

    if (padded) {
        size++;
    }

    if (priority) {
        size += sizeof(uint32_t) + 1;
    }

    if (h2c->state.length < size) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent HEADERS frame with incorrect length %uz",
                      h2c->state.length);

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_SIZE_ERROR);
    }

    if (h2c->state.length == size) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent HEADERS frame with empty header block");

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_SIZE_ERROR);
    }

    if (h2c->goaway) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "skipping http2 HEADERS frame");
        return njt_http_v2_state_skip(h2c, pos, end);
    }

    if ((size_t) (end - pos) < size) {
        return njt_http_v2_state_save(h2c, pos, end,
                                      njt_http_v2_state_headers);
    }

    h2c->state.length -= size;

    if (padded) {
        h2c->state.padding = *pos++;

        if (h2c->state.padding > h2c->state.length) {
            njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                          "client sent padded HEADERS frame "
                          "with incorrect length: %uz, padding: %uz",
                          h2c->state.length, h2c->state.padding);

            return njt_http_v2_connection_error(h2c,
                                                NJT_HTTP_V2_PROTOCOL_ERROR);
        }

        h2c->state.length -= h2c->state.padding;
    }

    depend = 0;
    excl = 0;
    weight = NJT_HTTP_V2_DEFAULT_WEIGHT;

    if (priority) {
        dependency = njt_http_v2_parse_uint32(pos);

        depend = dependency & 0x7fffffff;
        excl = dependency >> 31;
        weight = pos[4] + 1;

        pos += sizeof(uint32_t) + 1;
    }

    njt_log_debug4(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 HEADERS frame sid:%ui "
                   "depends on %ui excl:%ui weight:%ui",
                   h2c->state.sid, depend, excl, weight);

    if (h2c->state.sid % 2 == 0 || h2c->state.sid <= h2c->last_sid) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent HEADERS frame with incorrect identifier "
                      "%ui, the last was %ui", h2c->state.sid, h2c->last_sid);

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_PROTOCOL_ERROR);
    }

    if (depend == h2c->state.sid) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent HEADERS frame for stream %ui "
                      "with incorrect dependency", h2c->state.sid);

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_PROTOCOL_ERROR);
    }

    h2c->last_sid = h2c->state.sid;

    h2c->state.pool = njt_create_pool(1024, h2c->connection->log);
    if (h2c->state.pool == NULL) {
        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_INTERNAL_ERROR);
    }

    cscf = njt_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                        njt_http_core_module);

    h2c->state.header_limit = cscf->large_client_header_buffers.size
                              * cscf->large_client_header_buffers.num;

    h2scf = njt_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         njt_http_v2_module);

    if (h2c->processing >= h2scf->concurrent_streams) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "concurrent streams exceeded %ui", h2c->processing);

        status = NJT_HTTP_V2_REFUSED_STREAM;
        goto rst_stream;
    }

    if (h2c->new_streams++ >= 2 * h2scf->concurrent_streams) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent too many streams at once");

        status = NJT_HTTP_V2_REFUSED_STREAM;
        goto rst_stream;
    }

    if (!h2c->settings_ack
        && !(h2c->state.flags & NJT_HTTP_V2_END_STREAM_FLAG)
        && h2scf->preread_size < NJT_HTTP_V2_DEFAULT_WINDOW)
    {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent stream with data "
                      "before settings were acknowledged");

        status = NJT_HTTP_V2_REFUSED_STREAM;
        goto rst_stream;
    }

    node = njt_http_v2_get_node_by_id(h2c, h2c->state.sid, 1);

    if (node == NULL) {
        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_INTERNAL_ERROR);
    }

    if (node->parent) {
        njt_queue_remove(&node->reuse);
        h2c->closed_nodes--;
    }

    stream = njt_http_v2_create_stream(h2c);
    if (stream == NULL) {
        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_INTERNAL_ERROR);
    }

    h2c->state.stream = stream;

    stream->pool = h2c->state.pool;
    h2c->state.keep_pool = 1;

    stream->request->request_length = h2c->state.length;

    stream->in_closed = h2c->state.flags & NJT_HTTP_V2_END_STREAM_FLAG;
    stream->node = node;

    node->stream = stream;

    if (priority || node->parent == NULL) {
        node->weight = weight;
        njt_http_v2_set_dependency(h2c, node, depend, excl);
    }

    clcf = njt_http_get_module_loc_conf(h2c->http_connection->conf_ctx,
                                        njt_http_core_module);

    if (clcf->keepalive_timeout == 0
        || h2c->connection->requests >= clcf->keepalive_requests
        || njt_current_msec - h2c->connection->start_time
           > clcf->keepalive_time)
    {
        h2c->goaway = 1;

        if (njt_http_v2_send_goaway(h2c, NJT_HTTP_V2_NO_ERROR) == NJT_ERROR) {
            return njt_http_v2_connection_error(h2c,
                                                NJT_HTTP_V2_INTERNAL_ERROR);
        }
    }

    return njt_http_v2_state_header_block(h2c, pos, end);

rst_stream:

    if (h2c->refused_streams++ > njt_max(h2scf->concurrent_streams, 100)) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent too many refused streams");
        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_NO_ERROR);
    }

    if (njt_http_v2_send_rst_stream(h2c, h2c->state.sid, status) != NJT_OK) {
        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_INTERNAL_ERROR);
    }

    return njt_http_v2_state_header_block(h2c, pos, end);
}


static u_char *
njt_http_v2_state_header_block(njt_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    u_char      ch;
    njt_int_t   value;
    njt_uint_t  indexed, size_update, prefix;

    if (end - pos < 1) {
        return njt_http_v2_state_headers_save(h2c, pos, end,
                                              njt_http_v2_state_header_block);
    }

    if (!(h2c->state.flags & NJT_HTTP_V2_END_HEADERS_FLAG)
        && h2c->state.length < NJT_HTTP_V2_INT_OCTETS)
    {
        return njt_http_v2_handle_continuation(h2c, pos, end,
                                               njt_http_v2_state_header_block);
    }

    size_update = 0;
    indexed = 0;

    ch = *pos;

    if (ch >= (1 << 7)) {
        /* indexed header field */
        indexed = 1;
        prefix = njt_http_v2_prefix(7);

    } else if (ch >= (1 << 6)) {
        /* literal header field with incremental indexing */
        h2c->state.index = 1;
        prefix = njt_http_v2_prefix(6);

    } else if (ch >= (1 << 5)) {
        /* dynamic table size update */
        size_update = 1;
        prefix = njt_http_v2_prefix(5);

    } else if (ch >= (1 << 4)) {
        /* literal header field never indexed */
        prefix = njt_http_v2_prefix(4);

    } else {
        /* literal header field without indexing */
        prefix = njt_http_v2_prefix(4);
    }

    value = njt_http_v2_parse_int(h2c, &pos, end, prefix);

    if (value < 0) {
        if (value == NJT_AGAIN) {
            return njt_http_v2_state_headers_save(h2c, pos, end,
                                               njt_http_v2_state_header_block);
        }

        if (value == NJT_DECLINED) {
            njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                          "client sent header block with too long %s value",
                          size_update ? "size update" : "header index");

            return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_COMP_ERROR);
        }

        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent header block with incorrect length");

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_SIZE_ERROR);
    }

    if (indexed) {
        if (njt_http_v2_get_indexed_header(h2c, value, 0) != NJT_OK) {
            return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_COMP_ERROR);
        }

        return njt_http_v2_state_process_header(h2c, pos, end);
    }

    if (size_update) {
        if (njt_http_v2_table_size(h2c, value) != NJT_OK) {
            return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_COMP_ERROR);
        }

        return njt_http_v2_state_header_complete(h2c, pos, end);
    }

    if (value == 0) {
        h2c->state.parse_name = 1;

    } else if (njt_http_v2_get_indexed_header(h2c, value, 1) != NJT_OK) {
        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_COMP_ERROR);
    }

    h2c->state.parse_value = 1;

    return njt_http_v2_state_field_len(h2c, pos, end);
}


static u_char *
njt_http_v2_state_field_len(njt_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    size_t                     alloc;
    njt_int_t                  len;
    njt_uint_t                 huff;
    njt_http_core_srv_conf_t  *cscf;

    if (!(h2c->state.flags & NJT_HTTP_V2_END_HEADERS_FLAG)
        && h2c->state.length < NJT_HTTP_V2_INT_OCTETS)
    {
        return njt_http_v2_handle_continuation(h2c, pos, end,
                                               njt_http_v2_state_field_len);
    }

    if (h2c->state.length < 1) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent header block with incorrect length");

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_SIZE_ERROR);
    }

    if (end - pos < 1) {
        return njt_http_v2_state_headers_save(h2c, pos, end,
                                              njt_http_v2_state_field_len);
    }

    huff = *pos >> 7;
    len = njt_http_v2_parse_int(h2c, &pos, end, njt_http_v2_prefix(7));

    if (len < 0) {
        if (len == NJT_AGAIN) {
            return njt_http_v2_state_headers_save(h2c, pos, end,
                                                  njt_http_v2_state_field_len);
        }

        if (len == NJT_DECLINED) {
            njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                        "client sent header field with too long length value");

            return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_COMP_ERROR);
        }

        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent header block with incorrect length");

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_SIZE_ERROR);
    }

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 %s string, len:%i",
                   huff ? "encoded" : "raw", len);

    cscf = njt_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                        njt_http_core_module);

    if ((size_t) len > cscf->large_client_header_buffers.size) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent too large header field");

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_ENHANCE_YOUR_CALM);
    }

    h2c->state.field_rest = len;

    if (h2c->state.stream == NULL && !h2c->state.index) {
        return njt_http_v2_state_field_skip(h2c, pos, end);
    }

    alloc = (huff ? len * 8 / 5 : len) + 1;

    h2c->state.field_start = njt_pnalloc(h2c->state.pool, alloc);
    if (h2c->state.field_start == NULL) {
        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_INTERNAL_ERROR);
    }

    h2c->state.field_end = h2c->state.field_start;

    if (huff) {
        return njt_http_v2_state_field_huff(h2c, pos, end);
    }

    return njt_http_v2_state_field_raw(h2c, pos, end);
}


static u_char *
njt_http_v2_state_field_huff(njt_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    size_t  size;

    size = end - pos;

    if (size > h2c->state.field_rest) {
        size = h2c->state.field_rest;
    }

    if (size > h2c->state.length) {
        size = h2c->state.length;
    }

    h2c->state.length -= size;
    h2c->state.field_rest -= size;

    if (njt_http_huff_decode(&h2c->state.field_state, pos, size,
                             &h2c->state.field_end,
                             h2c->state.field_rest == 0,
                             h2c->connection->log)
        != NJT_OK)
    {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent invalid encoded header field");

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_COMP_ERROR);
    }

    pos += size;

    if (h2c->state.field_rest == 0) {
        *h2c->state.field_end = '\0';
        return njt_http_v2_state_process_header(h2c, pos, end);
    }

    if (h2c->state.length) {
        return njt_http_v2_state_headers_save(h2c, pos, end,
                                              njt_http_v2_state_field_huff);
    }

    if (h2c->state.flags & NJT_HTTP_V2_END_HEADERS_FLAG) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent header field with incorrect length");

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_SIZE_ERROR);
    }

    return njt_http_v2_handle_continuation(h2c, pos, end,
                                           njt_http_v2_state_field_huff);
}


static u_char *
njt_http_v2_state_field_raw(njt_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    size_t  size;

    size = end - pos;

    if (size > h2c->state.field_rest) {
        size = h2c->state.field_rest;
    }

    if (size > h2c->state.length) {
        size = h2c->state.length;
    }

    h2c->state.length -= size;
    h2c->state.field_rest -= size;

    h2c->state.field_end = njt_cpymem(h2c->state.field_end, pos, size);

    pos += size;

    if (h2c->state.field_rest == 0) {
        *h2c->state.field_end = '\0';
        return njt_http_v2_state_process_header(h2c, pos, end);
    }

    if (h2c->state.length) {
        return njt_http_v2_state_headers_save(h2c, pos, end,
                                              njt_http_v2_state_field_raw);
    }

    if (h2c->state.flags & NJT_HTTP_V2_END_HEADERS_FLAG) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent header field with incorrect length");

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_SIZE_ERROR);
    }

    return njt_http_v2_handle_continuation(h2c, pos, end,
                                           njt_http_v2_state_field_raw);
}


static u_char *
njt_http_v2_state_field_skip(njt_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    size_t  size;

    size = end - pos;

    if (size > h2c->state.field_rest) {
        size = h2c->state.field_rest;
    }

    if (size > h2c->state.length) {
        size = h2c->state.length;
    }

    h2c->state.length -= size;
    h2c->state.field_rest -= size;

    pos += size;

    if (h2c->state.field_rest == 0) {
        return njt_http_v2_state_process_header(h2c, pos, end);
    }

    if (h2c->state.length) {
        return njt_http_v2_state_save(h2c, pos, end,
                                      njt_http_v2_state_field_skip);
    }

    if (h2c->state.flags & NJT_HTTP_V2_END_HEADERS_FLAG) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent header field with incorrect length");

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_SIZE_ERROR);
    }

    return njt_http_v2_handle_continuation(h2c, pos, end,
                                           njt_http_v2_state_field_skip);
}


static u_char *
njt_http_v2_state_process_header(njt_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    size_t                      len;
    njt_int_t                   rc;
    njt_table_elt_t            *h;
    njt_connection_t           *fc;
    njt_http_header_t          *hh;
    njt_http_request_t         *r;
    njt_http_v2_header_t       *header;
    njt_http_core_srv_conf_t   *cscf;
    njt_http_core_main_conf_t  *cmcf;

    static njt_str_t cookie = njt_string("cookie");

    header = &h2c->state.header;

    if (h2c->state.parse_name) {
        h2c->state.parse_name = 0;

        header->name.len = h2c->state.field_end - h2c->state.field_start;
        header->name.data = h2c->state.field_start;

        if (header->name.len == 0) {
            njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                          "client sent zero header name length");

            return njt_http_v2_connection_error(h2c,
                                                NJT_HTTP_V2_PROTOCOL_ERROR);
        }

        return njt_http_v2_state_field_len(h2c, pos, end);
    }

    if (h2c->state.parse_value) {
        h2c->state.parse_value = 0;

        header->value.len = h2c->state.field_end - h2c->state.field_start;
        header->value.data = h2c->state.field_start;
    }

    len = header->name.len + header->value.len;

    if (len > h2c->state.header_limit) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent too large header");

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_ENHANCE_YOUR_CALM);
    }

    h2c->state.header_limit -= len;

    if (h2c->state.index) {
        if (njt_http_v2_add_header(h2c, header) != NJT_OK) {
            return njt_http_v2_connection_error(h2c,
                                                NJT_HTTP_V2_INTERNAL_ERROR);
        }

        h2c->state.index = 0;
    }

    if (h2c->state.stream == NULL) {
        return njt_http_v2_state_header_complete(h2c, pos, end);
    }

    r = h2c->state.stream->request;
    fc = r->connection;

    /* TODO Optimization: validate headers while parsing. */
    if (njt_http_v2_validate_header(r, header) != NJT_OK) {
        njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);
        goto error;
    }

    if (header->name.data[0] == ':') {
        rc = njt_http_v2_pseudo_header(r, header);

        if (rc == NJT_OK) {
            njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http2 header: \":%V: %V\"",
                           &header->name, &header->value);

            return njt_http_v2_state_header_complete(h2c, pos, end);
        }

        if (rc == NJT_ABORT) {
            goto error;
        }

        if (rc == NJT_DECLINED) {
            njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);
            goto error;
        }

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_INTERNAL_ERROR);
    }

    if (r->invalid_header) {
        cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);

        if (cscf->ignore_invalid_headers) {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "client sent invalid header: \"%V\"", &header->name);

            return njt_http_v2_state_header_complete(h2c, pos, end);
        }
    }

    if (header->name.len == cookie.len
        && njt_memcmp(header->name.data, cookie.data, cookie.len) == 0)
    {
        if (njt_http_v2_cookie(r, header) != NJT_OK) {
            return njt_http_v2_connection_error(h2c,
                                                NJT_HTTP_V2_INTERNAL_ERROR);
        }

    } else {
        h = njt_list_push(&r->headers_in.headers);
        if (h == NULL) {
            return njt_http_v2_connection_error(h2c,
                                                NJT_HTTP_V2_INTERNAL_ERROR);
        }

        h->key.len = header->name.len;
        h->key.data = header->name.data;

        /*
         * TODO Optimization: precalculate hash
         * and handler for indexed headers.
         */
        h->hash = njt_hash_key(h->key.data, h->key.len);

        h->value.len = header->value.len;
        h->value.data = header->value.data;

        h->lowcase_key = h->key.data;

        cmcf = njt_http_get_module_main_conf(r, njt_http_core_module);

        hh = njt_hash_find(&cmcf->headers_in_hash, h->hash,
                           h->lowcase_key, h->key.len);

        if (hh && hh->handler(r, h, hh->offset) != NJT_OK) {
            goto error;
        }
    }

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http2 header: \"%V: %V\"",
                   &header->name, &header->value);

    return njt_http_v2_state_header_complete(h2c, pos, end);

error:

    h2c->state.stream = NULL;

    njt_http_run_posted_requests(fc);

    return njt_http_v2_state_header_complete(h2c, pos, end);
}


static u_char *
njt_http_v2_state_header_complete(njt_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    njt_http_v2_stream_t  *stream;

    if (h2c->state.length) {
        if (end - pos > 0) {
            h2c->state.handler = njt_http_v2_state_header_block;
            return pos;
        }

        return njt_http_v2_state_headers_save(h2c, pos, end,
                                              njt_http_v2_state_header_block);
    }

    if (!(h2c->state.flags & NJT_HTTP_V2_END_HEADERS_FLAG)) {
        return njt_http_v2_handle_continuation(h2c, pos, end,
                                             njt_http_v2_state_header_complete);
    }

    stream = h2c->state.stream;

    if (stream) {
        njt_http_v2_run_request(stream->request);
    }

    if (!h2c->state.keep_pool) {
        njt_destroy_pool(h2c->state.pool);
    }

    h2c->state.pool = NULL;
    h2c->state.keep_pool = 0;

    if (h2c->state.padding) {
        return njt_http_v2_state_skip_padded(h2c, pos, end);
    }

    return njt_http_v2_state_complete(h2c, pos, end);
}


static u_char *
njt_http_v2_handle_continuation(njt_http_v2_connection_t *h2c, u_char *pos,
    u_char *end, njt_http_v2_handler_pt handler)
{
    u_char    *p;
    size_t     len, skip;
    uint32_t   head;

    len = h2c->state.length;

    if (h2c->state.padding && (size_t) (end - pos) > len) {
        skip = njt_min(h2c->state.padding, (end - pos) - len);

        h2c->state.padding -= skip;

        p = pos;
        pos += skip;
        njt_memmove(pos, p, len);
    }

    if ((size_t) (end - pos) < len + NJT_HTTP_V2_FRAME_HEADER_SIZE) {
        return njt_http_v2_state_headers_save(h2c, pos, end, handler);
    }

    p = pos + len;

    head = njt_http_v2_parse_uint32(p);

    if (njt_http_v2_parse_type(head) != NJT_HTTP_V2_CONTINUATION_FRAME) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
             "client sent inappropriate frame while CONTINUATION was expected");

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_PROTOCOL_ERROR);
    }

    h2c->state.flags |= p[4];

    if (h2c->state.sid != njt_http_v2_parse_sid(&p[5])) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                    "client sent CONTINUATION frame with incorrect identifier");

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_PROTOCOL_ERROR);
    }

    p = pos;
    pos += NJT_HTTP_V2_FRAME_HEADER_SIZE;

    njt_memcpy(pos, p, len);

    len = njt_http_v2_parse_length(head);

    h2c->state.length += len;

    if (h2c->state.stream) {
        h2c->state.stream->request->request_length += len;
    }

    h2c->state.handler = handler;
    return pos;
}


static u_char *
njt_http_v2_state_priority(njt_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    njt_uint_t           depend, dependency, excl, weight;
    njt_http_v2_node_t  *node;

    if (h2c->state.length != NJT_HTTP_V2_PRIORITY_SIZE) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent PRIORITY frame with incorrect length %uz",
                      h2c->state.length);

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_SIZE_ERROR);
    }

    if (--h2c->priority_limit == 0) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent too many PRIORITY frames");

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_ENHANCE_YOUR_CALM);
    }

    if (end - pos < NJT_HTTP_V2_PRIORITY_SIZE) {
        return njt_http_v2_state_save(h2c, pos, end,
                                      njt_http_v2_state_priority);
    }

    dependency = njt_http_v2_parse_uint32(pos);

    depend = dependency & 0x7fffffff;
    excl = dependency >> 31;
    weight = pos[4] + 1;

    pos += NJT_HTTP_V2_PRIORITY_SIZE;

    njt_log_debug4(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 PRIORITY frame sid:%ui "
                   "depends on %ui excl:%ui weight:%ui",
                   h2c->state.sid, depend, excl, weight);

    if (h2c->state.sid == 0) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent PRIORITY frame with incorrect identifier");

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_PROTOCOL_ERROR);
    }

    if (depend == h2c->state.sid) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent PRIORITY frame for stream %ui "
                      "with incorrect dependency", h2c->state.sid);

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_PROTOCOL_ERROR);
    }

    node = njt_http_v2_get_node_by_id(h2c, h2c->state.sid, 1);

    if (node == NULL) {
        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_INTERNAL_ERROR);
    }

    node->weight = weight;

    if (node->stream == NULL) {
        if (node->parent == NULL) {
            h2c->closed_nodes++;

        } else {
            njt_queue_remove(&node->reuse);
        }

        njt_queue_insert_tail(&h2c->closed, &node->reuse);
    }

    njt_http_v2_set_dependency(h2c, node, depend, excl);

    return njt_http_v2_state_complete(h2c, pos, end);
}


static u_char *
njt_http_v2_state_rst_stream(njt_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    njt_uint_t             status;
    njt_event_t           *ev;
    njt_connection_t      *fc;
    njt_http_v2_node_t    *node;
    njt_http_v2_stream_t  *stream;

    if (h2c->state.length != NJT_HTTP_V2_RST_STREAM_SIZE) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent RST_STREAM frame with incorrect length %uz",
                      h2c->state.length);

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_SIZE_ERROR);
    }

    if (end - pos < NJT_HTTP_V2_RST_STREAM_SIZE) {
        return njt_http_v2_state_save(h2c, pos, end,
                                      njt_http_v2_state_rst_stream);
    }

    status = njt_http_v2_parse_uint32(pos);

    pos += NJT_HTTP_V2_RST_STREAM_SIZE;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 RST_STREAM frame, sid:%ui status:%ui",
                   h2c->state.sid, status);

    if (h2c->state.sid == 0) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent RST_STREAM frame with incorrect identifier");

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_PROTOCOL_ERROR);
    }

    node = njt_http_v2_get_node_by_id(h2c, h2c->state.sid, 0);

    if (node == NULL || node->stream == NULL) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "unknown http2 stream");

        return njt_http_v2_state_complete(h2c, pos, end);
    }

    stream = node->stream;

    stream->in_closed = 1;
    stream->out_closed = 1;

    fc = stream->request->connection;
    fc->error = 1;

    switch (status) {

    case NJT_HTTP_V2_CANCEL:
        njt_log_error(NJT_LOG_INFO, fc->log, 0,
                      "client canceled stream %ui", h2c->state.sid);
        break;

    case NJT_HTTP_V2_INTERNAL_ERROR:
        njt_log_error(NJT_LOG_INFO, fc->log, 0,
                      "client terminated stream %ui due to internal error",
                      h2c->state.sid);
        break;

    default:
        njt_log_error(NJT_LOG_INFO, fc->log, 0,
                      "client terminated stream %ui with status %ui",
                      h2c->state.sid, status);
        break;
    }

    ev = fc->read;
    ev->handler(ev);

    return njt_http_v2_state_complete(h2c, pos, end);
}


static u_char *
njt_http_v2_state_settings(njt_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    njt_log_debug0(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 SETTINGS frame");

    if (h2c->state.sid) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent SETTINGS frame with incorrect identifier");

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_PROTOCOL_ERROR);
    }

    if (h2c->state.flags == NJT_HTTP_V2_ACK_FLAG) {

        if (h2c->state.length != 0) {
            njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                          "client sent SETTINGS frame with the ACK flag "
                          "and nonzero length");

            return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_SIZE_ERROR);
        }

        h2c->settings_ack = 1;

        return njt_http_v2_state_complete(h2c, pos, end);
    }

    if (h2c->state.length % NJT_HTTP_V2_SETTINGS_PARAM_SIZE) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent SETTINGS frame with incorrect length %uz",
                      h2c->state.length);

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_SIZE_ERROR);
    }

    return njt_http_v2_state_settings_params(h2c, pos, end);
}


static u_char *
njt_http_v2_state_settings_params(njt_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    ssize_t                   window_delta;
    njt_uint_t                id, value;
    njt_http_v2_out_frame_t  *frame;

    window_delta = 0;

    while (h2c->state.length) {
        if (end - pos < NJT_HTTP_V2_SETTINGS_PARAM_SIZE) {
            return njt_http_v2_state_save(h2c, pos, end,
                                          njt_http_v2_state_settings_params);
        }

        h2c->state.length -= NJT_HTTP_V2_SETTINGS_PARAM_SIZE;

        id = njt_http_v2_parse_uint16(pos);
        value = njt_http_v2_parse_uint32(&pos[2]);

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "http2 setting %ui:%ui", id, value);

        switch (id) {

        case NJT_HTTP_V2_INIT_WINDOW_SIZE_SETTING:

            if (value > NJT_HTTP_V2_MAX_WINDOW) {
                njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                              "client sent SETTINGS frame with incorrect "
                              "INITIAL_WINDOW_SIZE value %ui", value);

                return njt_http_v2_connection_error(h2c,
                                                  NJT_HTTP_V2_FLOW_CTRL_ERROR);
            }

            window_delta = value - h2c->init_window;
            break;

        case NJT_HTTP_V2_MAX_FRAME_SIZE_SETTING:

            if (value > NJT_HTTP_V2_MAX_FRAME_SIZE
                || value < NJT_HTTP_V2_DEFAULT_FRAME_SIZE)
            {
                njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                              "client sent SETTINGS frame with incorrect "
                              "MAX_FRAME_SIZE value %ui", value);

                return njt_http_v2_connection_error(h2c,
                                                    NJT_HTTP_V2_PROTOCOL_ERROR);
            }

            h2c->frame_size = value;
            break;

        case NJT_HTTP_V2_ENABLE_PUSH_SETTING:

            if (value > 1) {
                njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                              "client sent SETTINGS frame with incorrect "
                              "ENABLE_PUSH value %ui", value);

                return njt_http_v2_connection_error(h2c,
                                                    NJT_HTTP_V2_PROTOCOL_ERROR);
            }

            break;

        case NJT_HTTP_V2_HEADER_TABLE_SIZE_SETTING:

            h2c->table_update = 1;
            break;

        default:
            break;
        }

        pos += NJT_HTTP_V2_SETTINGS_PARAM_SIZE;
    }

    frame = njt_http_v2_get_frame(h2c, NJT_HTTP_V2_SETTINGS_ACK_SIZE,
                                  NJT_HTTP_V2_SETTINGS_FRAME,
                                  NJT_HTTP_V2_ACK_FLAG, 0);
    if (frame == NULL) {
        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_INTERNAL_ERROR);
    }

    njt_http_v2_queue_ordered_frame(h2c, frame);

    if (window_delta) {
        h2c->init_window += window_delta;

        if (njt_http_v2_adjust_windows(h2c, window_delta) != NJT_OK) {
            return njt_http_v2_connection_error(h2c,
                                                NJT_HTTP_V2_INTERNAL_ERROR);
        }
    }

    return njt_http_v2_state_complete(h2c, pos, end);
}


static u_char *
njt_http_v2_state_push_promise(njt_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                  "client sent PUSH_PROMISE frame");

    return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_PROTOCOL_ERROR);
}


static u_char *
njt_http_v2_state_ping(njt_http_v2_connection_t *h2c, u_char *pos, u_char *end)
{
    njt_buf_t                *buf;
    njt_http_v2_out_frame_t  *frame;

    if (h2c->state.length != NJT_HTTP_V2_PING_SIZE) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent PING frame with incorrect length %uz",
                      h2c->state.length);

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_SIZE_ERROR);
    }

    if (end - pos < NJT_HTTP_V2_PING_SIZE) {
        return njt_http_v2_state_save(h2c, pos, end, njt_http_v2_state_ping);
    }

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 PING frame");

    if (h2c->state.sid) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent PING frame with incorrect identifier");

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_PROTOCOL_ERROR);
    }

    if (h2c->state.flags & NJT_HTTP_V2_ACK_FLAG) {
        return njt_http_v2_state_skip(h2c, pos, end);
    }

    frame = njt_http_v2_get_frame(h2c, NJT_HTTP_V2_PING_SIZE,
                                  NJT_HTTP_V2_PING_FRAME,
                                  NJT_HTTP_V2_ACK_FLAG, 0);
    if (frame == NULL) {
        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_INTERNAL_ERROR);
    }

    buf = frame->first->buf;

    buf->last = njt_cpymem(buf->last, pos, NJT_HTTP_V2_PING_SIZE);

    njt_http_v2_queue_blocked_frame(h2c, frame);

    return njt_http_v2_state_complete(h2c, pos + NJT_HTTP_V2_PING_SIZE, end);
}


static u_char *
njt_http_v2_state_goaway(njt_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
#if (NJT_DEBUG)
    njt_uint_t  last_sid, error;
#endif

    if (h2c->state.length < NJT_HTTP_V2_GOAWAY_SIZE) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent GOAWAY frame "
                      "with incorrect length %uz", h2c->state.length);

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_SIZE_ERROR);
    }

    if (end - pos < NJT_HTTP_V2_GOAWAY_SIZE) {
        return njt_http_v2_state_save(h2c, pos, end, njt_http_v2_state_goaway);
    }

    if (h2c->state.sid) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent GOAWAY frame with incorrect identifier");

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_PROTOCOL_ERROR);
    }

#if (NJT_DEBUG)
    h2c->state.length -= NJT_HTTP_V2_GOAWAY_SIZE;

    last_sid = njt_http_v2_parse_sid(pos);
    error = njt_http_v2_parse_uint32(&pos[4]);

    pos += NJT_HTTP_V2_GOAWAY_SIZE;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 GOAWAY frame: last sid %ui, error %ui",
                   last_sid, error);
#endif

    return njt_http_v2_state_skip(h2c, pos, end);
}


static u_char *
njt_http_v2_state_window_update(njt_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    size_t                 window;
    njt_event_t           *wev;
    njt_queue_t           *q;
    njt_http_v2_node_t    *node;
    njt_http_v2_stream_t  *stream;

    if (h2c->state.length != NJT_HTTP_V2_WINDOW_UPDATE_SIZE) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent WINDOW_UPDATE frame "
                      "with incorrect length %uz", h2c->state.length);

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_SIZE_ERROR);
    }

    if (end - pos < NJT_HTTP_V2_WINDOW_UPDATE_SIZE) {
        return njt_http_v2_state_save(h2c, pos, end,
                                      njt_http_v2_state_window_update);
    }

    window = njt_http_v2_parse_window(pos);

    pos += NJT_HTTP_V2_WINDOW_UPDATE_SIZE;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 WINDOW_UPDATE frame sid:%ui window:%uz",
                   h2c->state.sid, window);

    if (window == 0) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent WINDOW_UPDATE frame "
                      "with incorrect window increment 0");

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_PROTOCOL_ERROR);
    }

    if (h2c->state.sid) {
        node = njt_http_v2_get_node_by_id(h2c, h2c->state.sid, 0);

        if (node == NULL || node->stream == NULL) {
            njt_log_debug0(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                           "unknown http2 stream");

            return njt_http_v2_state_complete(h2c, pos, end);
        }

        stream = node->stream;

        if (window > (size_t) (NJT_HTTP_V2_MAX_WINDOW - stream->send_window)) {

            njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                          "client violated flow control for stream %ui: "
                          "received WINDOW_UPDATE frame "
                          "with window increment %uz "
                          "not allowed for window %z",
                          h2c->state.sid, window, stream->send_window);

            if (njt_http_v2_terminate_stream(h2c, stream,
                                             NJT_HTTP_V2_FLOW_CTRL_ERROR)
                == NJT_ERROR)
            {
                return njt_http_v2_connection_error(h2c,
                                                    NJT_HTTP_V2_INTERNAL_ERROR);
            }

            return njt_http_v2_state_complete(h2c, pos, end);
        }

        stream->send_window += window;

        if (stream->exhausted) {
            stream->exhausted = 0;

            wev = stream->request->connection->write;

            wev->active = 0;
            wev->ready = 1;

            if (!wev->delayed) {
                wev->handler(wev);
            }
        }

        return njt_http_v2_state_complete(h2c, pos, end);
    }

    if (window > NJT_HTTP_V2_MAX_WINDOW - h2c->send_window) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client violated connection flow control: "
                      "received WINDOW_UPDATE frame "
                      "with window increment %uz "
                      "not allowed for window %uz",
                      window, h2c->send_window);

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_FLOW_CTRL_ERROR);
    }

    h2c->send_window += window;

    while (!njt_queue_empty(&h2c->waiting)) {
        q = njt_queue_head(&h2c->waiting);

        njt_queue_remove(q);

        stream = njt_queue_data(q, njt_http_v2_stream_t, queue);

        stream->waiting = 0;

        wev = stream->request->connection->write;

        wev->active = 0;
        wev->ready = 1;

        if (!wev->delayed) {
            wev->handler(wev);

            if (h2c->send_window == 0) {
                break;
            }
        }
    }

    return njt_http_v2_state_complete(h2c, pos, end);
}


static u_char *
njt_http_v2_state_continuation(njt_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                  "client sent unexpected CONTINUATION frame");

    return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_PROTOCOL_ERROR);
}


static u_char *
njt_http_v2_state_complete(njt_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    njt_log_debug2(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 frame complete pos:%p end:%p", pos, end);

    if (pos > end) {
        njt_log_error(NJT_LOG_ALERT, h2c->connection->log, 0,
                      "receive buffer overrun");

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_INTERNAL_ERROR);
    }

    h2c->state.stream = NULL;
    h2c->state.handler = njt_http_v2_state_head;

    return pos;
}


static u_char *
njt_http_v2_state_skip_padded(njt_http_v2_connection_t *h2c, u_char *pos,
    u_char *end)
{
    h2c->state.length += h2c->state.padding;
    h2c->state.padding = 0;

    return njt_http_v2_state_skip(h2c, pos, end);
}


static u_char *
njt_http_v2_state_skip(njt_http_v2_connection_t *h2c, u_char *pos, u_char *end)
{
    size_t  size;

    size = end - pos;

    if (size < h2c->state.length) {
        njt_log_debug2(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "http2 frame skip %uz of %uz", size, h2c->state.length);

        h2c->state.length -= size;
        return njt_http_v2_state_save(h2c, end, end, njt_http_v2_state_skip);
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 frame skip %uz", h2c->state.length);

    return njt_http_v2_state_complete(h2c, pos + h2c->state.length, end);
}


static u_char *
njt_http_v2_state_save(njt_http_v2_connection_t *h2c, u_char *pos, u_char *end,
    njt_http_v2_handler_pt handler)
{
    size_t  size;

    njt_log_debug3(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 frame state save pos:%p end:%p handler:%p",
                   pos, end, handler);

    size = end - pos;

    if (size > NJT_HTTP_V2_STATE_BUFFER_SIZE) {
        njt_log_error(NJT_LOG_ALERT, h2c->connection->log, 0,
                      "state buffer overflow: %uz bytes required", size);

        return njt_http_v2_connection_error(h2c, NJT_HTTP_V2_INTERNAL_ERROR);
    }

    njt_memcpy(h2c->state.buffer, pos, size);

    h2c->state.buffer_used = size;
    h2c->state.handler = handler;
    h2c->state.incomplete = 1;

    return end;
}


static u_char *
njt_http_v2_state_headers_save(njt_http_v2_connection_t *h2c, u_char *pos,
    u_char *end, njt_http_v2_handler_pt handler)
{
    njt_event_t               *rev;
    njt_http_request_t        *r;
    njt_http_core_srv_conf_t  *cscf;

    if (h2c->state.stream) {
        r = h2c->state.stream->request;
        rev = r->connection->read;

        if (!rev->timer_set) {
            cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);
            njt_add_timer(rev, cscf->client_header_timeout);
        }
    }

    return njt_http_v2_state_save(h2c, pos, end, handler);
}


static u_char *
njt_http_v2_connection_error(njt_http_v2_connection_t *h2c,
    njt_uint_t err)
{
    njt_log_debug0(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 state connection error");

    njt_http_v2_finalize_connection(h2c, err);

    return NULL;
}


static njt_int_t
njt_http_v2_parse_int(njt_http_v2_connection_t *h2c, u_char **pos, u_char *end,
    njt_uint_t prefix)
{
    u_char      *start, *p;
    njt_uint_t   value, octet, shift;

    start = *pos;
    p = start;

    value = *p++ & prefix;

    if (value != prefix) {
        if (h2c->state.length == 0) {
            return NJT_ERROR;
        }

        h2c->state.length--;

        *pos = p;
        return value;
    }

    if (end - start > NJT_HTTP_V2_INT_OCTETS) {
        end = start + NJT_HTTP_V2_INT_OCTETS;
    }

    for (shift = 0; p != end; shift += 7) {
        octet = *p++;

        value += (octet & 0x7f) << shift;

        if (octet < 128) {
            if ((size_t) (p - start) > h2c->state.length) {
                return NJT_ERROR;
            }

            h2c->state.length -= p - start;

            *pos = p;
            return value;
        }
    }

    if ((size_t) (end - start) >= h2c->state.length) {
        return NJT_ERROR;
    }

    if (end == start + NJT_HTTP_V2_INT_OCTETS) {
        return NJT_DECLINED;
    }

    return NJT_AGAIN;
}


static njt_int_t
njt_http_v2_send_settings(njt_http_v2_connection_t *h2c)
{
    size_t                    len;
    njt_buf_t                *buf;
    njt_chain_t              *cl;
    njt_http_v2_srv_conf_t   *h2scf;
    njt_http_v2_out_frame_t  *frame;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 send SETTINGS frame");

    frame = njt_palloc(h2c->pool, sizeof(njt_http_v2_out_frame_t));
    if (frame == NULL) {
        return NJT_ERROR;
    }

    cl = njt_alloc_chain_link(h2c->pool);
    if (cl == NULL) {
        return NJT_ERROR;
    }

    len = NJT_HTTP_V2_SETTINGS_PARAM_SIZE * 3;

    buf = njt_create_temp_buf(h2c->pool, NJT_HTTP_V2_FRAME_HEADER_SIZE + len);
    if (buf == NULL) {
        return NJT_ERROR;
    }

    buf->last_buf = 1;

    cl->buf = buf;
    cl->next = NULL;

    frame->first = cl;
    frame->last = cl;
    frame->handler = njt_http_v2_settings_frame_handler;
    frame->stream = NULL;
#if (NJT_DEBUG)
    frame->length = len;
#endif
    frame->blocked = 0;

    buf->last = njt_http_v2_write_len_and_type(buf->last, len,
                                               NJT_HTTP_V2_SETTINGS_FRAME);

    *buf->last++ = NJT_HTTP_V2_NO_FLAG;

    buf->last = njt_http_v2_write_sid(buf->last, 0);

    h2scf = njt_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         njt_http_v2_module);

    buf->last = njt_http_v2_write_uint16(buf->last,
                                         NJT_HTTP_V2_MAX_STREAMS_SETTING);
    buf->last = njt_http_v2_write_uint32(buf->last,
                                         h2scf->concurrent_streams);

    buf->last = njt_http_v2_write_uint16(buf->last,
                                         NJT_HTTP_V2_INIT_WINDOW_SIZE_SETTING);
    buf->last = njt_http_v2_write_uint32(buf->last, h2scf->preread_size);

    buf->last = njt_http_v2_write_uint16(buf->last,
                                         NJT_HTTP_V2_MAX_FRAME_SIZE_SETTING);
    buf->last = njt_http_v2_write_uint32(buf->last,
                                         NJT_HTTP_V2_MAX_FRAME_SIZE);

    njt_http_v2_queue_blocked_frame(h2c, frame);

    return NJT_OK;
}


static njt_int_t
njt_http_v2_settings_frame_handler(njt_http_v2_connection_t *h2c,
    njt_http_v2_out_frame_t *frame)
{
    njt_buf_t  *buf;

    buf = frame->first->buf;

    if (buf->pos != buf->last) {
        return NJT_AGAIN;
    }

    njt_free_chain(h2c->pool, frame->first);

    return NJT_OK;
}


static njt_int_t
njt_http_v2_send_window_update(njt_http_v2_connection_t *h2c, njt_uint_t sid,
    size_t window)
{
    njt_buf_t                *buf;
    njt_http_v2_out_frame_t  *frame;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 send WINDOW_UPDATE frame sid:%ui, window:%uz",
                   sid, window);

    frame = njt_http_v2_get_frame(h2c, NJT_HTTP_V2_WINDOW_UPDATE_SIZE,
                                  NJT_HTTP_V2_WINDOW_UPDATE_FRAME,
                                  NJT_HTTP_V2_NO_FLAG, sid);
    if (frame == NULL) {
        return NJT_ERROR;
    }

    buf = frame->first->buf;

    buf->last = njt_http_v2_write_uint32(buf->last, window);

    njt_http_v2_queue_blocked_frame(h2c, frame);

    return NJT_OK;
}


static njt_int_t
njt_http_v2_send_rst_stream(njt_http_v2_connection_t *h2c, njt_uint_t sid,
    njt_uint_t status)
{
    njt_buf_t                *buf;
    njt_http_v2_out_frame_t  *frame;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 send RST_STREAM frame sid:%ui, status:%ui",
                   sid, status);

    frame = njt_http_v2_get_frame(h2c, NJT_HTTP_V2_RST_STREAM_SIZE,
                                  NJT_HTTP_V2_RST_STREAM_FRAME,
                                  NJT_HTTP_V2_NO_FLAG, sid);
    if (frame == NULL) {
        return NJT_ERROR;
    }

    buf = frame->first->buf;

    buf->last = njt_http_v2_write_uint32(buf->last, status);

    njt_http_v2_queue_blocked_frame(h2c, frame);

    return NJT_OK;
}


static njt_int_t
njt_http_v2_send_goaway(njt_http_v2_connection_t *h2c, njt_uint_t status)
{
    njt_buf_t                *buf;
    njt_http_v2_out_frame_t  *frame;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 send GOAWAY frame: last sid %ui, error %ui",
                   h2c->last_sid, status);

    frame = njt_http_v2_get_frame(h2c, NJT_HTTP_V2_GOAWAY_SIZE,
                                  NJT_HTTP_V2_GOAWAY_FRAME,
                                  NJT_HTTP_V2_NO_FLAG, 0);
    if (frame == NULL) {
        return NJT_ERROR;
    }

    buf = frame->first->buf;

    buf->last = njt_http_v2_write_sid(buf->last, h2c->last_sid);
    buf->last = njt_http_v2_write_uint32(buf->last, status);

    njt_http_v2_queue_blocked_frame(h2c, frame);

    return NJT_OK;
}


static njt_http_v2_out_frame_t *
njt_http_v2_get_frame(njt_http_v2_connection_t *h2c, size_t length,
    njt_uint_t type, u_char flags, njt_uint_t sid)
{
    njt_buf_t                *buf;
    njt_pool_t               *pool;
    njt_http_v2_out_frame_t  *frame;

    frame = h2c->free_frames;

    if (frame) {
        h2c->free_frames = frame->next;

        buf = frame->first->buf;
        buf->pos = buf->start;

        frame->blocked = 0;

    } else if (h2c->frames < 10000) {
        pool = h2c->pool ? h2c->pool : h2c->connection->pool;

        frame = njt_pcalloc(pool, sizeof(njt_http_v2_out_frame_t));
        if (frame == NULL) {
            return NULL;
        }

        frame->first = njt_alloc_chain_link(pool);
        if (frame->first == NULL) {
            return NULL;
        }

        buf = njt_create_temp_buf(pool, NJT_HTTP_V2_FRAME_BUFFER_SIZE);
        if (buf == NULL) {
            return NULL;
        }

        buf->last_buf = 1;

        frame->first->buf = buf;
        frame->last = frame->first;

        frame->handler = njt_http_v2_frame_handler;

        h2c->frames++;

    } else {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "http2 flood detected");

        h2c->connection->error = 1;
        return NULL;
    }

#if (NJT_DEBUG)
    if (length > NJT_HTTP_V2_FRAME_BUFFER_SIZE - NJT_HTTP_V2_FRAME_HEADER_SIZE)
    {
        njt_log_error(NJT_LOG_ALERT, h2c->connection->log, 0,
                      "requested control frame is too large: %uz", length);
        return NULL;
    }
#endif

    frame->length = length;

    buf->last = njt_http_v2_write_len_and_type(buf->pos, length, type);

    *buf->last++ = flags;

    buf->last = njt_http_v2_write_sid(buf->last, sid);

    return frame;
}


static njt_int_t
njt_http_v2_frame_handler(njt_http_v2_connection_t *h2c,
    njt_http_v2_out_frame_t *frame)
{
    njt_buf_t  *buf;

    buf = frame->first->buf;

    if (buf->pos != buf->last) {
        return NJT_AGAIN;
    }

    frame->next = h2c->free_frames;
    h2c->free_frames = frame;

    h2c->total_bytes += NJT_HTTP_V2_FRAME_HEADER_SIZE + frame->length;

    return NJT_OK;
}


static njt_http_v2_stream_t *
njt_http_v2_create_stream(njt_http_v2_connection_t *h2c)
{
    njt_log_t                 *log;
    njt_event_t               *rev, *wev;
    njt_connection_t          *fc;
    njt_http_log_ctx_t        *ctx;
    njt_http_request_t        *r;
    njt_http_v2_stream_t      *stream;
    njt_http_v2_srv_conf_t    *h2scf;
    njt_http_core_srv_conf_t  *cscf;

    fc = h2c->free_fake_connections;

    if (fc) {
        h2c->free_fake_connections = fc->data;

        rev = fc->read;
        wev = fc->write;
        log = fc->log;
        ctx = log->data;

    } else {
        fc = njt_palloc(h2c->pool, sizeof(njt_connection_t));
        if (fc == NULL) {
            return NULL;
        }

        rev = njt_palloc(h2c->pool, sizeof(njt_event_t));
        if (rev == NULL) {
            return NULL;
        }

        wev = njt_palloc(h2c->pool, sizeof(njt_event_t));
        if (wev == NULL) {
            return NULL;
        }

        log = njt_palloc(h2c->pool, sizeof(njt_log_t));
        if (log == NULL) {
            return NULL;
        }

        ctx = njt_palloc(h2c->pool, sizeof(njt_http_log_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }

        ctx->connection = fc;
        ctx->request = NULL;
        ctx->current_request = NULL;
    }

    njt_memcpy(log, h2c->connection->log, sizeof(njt_log_t));

    log->data = ctx;
    log->action = "reading client request headers";

    njt_memzero(rev, sizeof(njt_event_t));

    rev->data = fc;
    rev->ready = 1;
    rev->handler = njt_http_v2_close_stream_handler;
    rev->log = log;

    njt_memcpy(wev, rev, sizeof(njt_event_t));

    wev->write = 1;

    njt_memcpy(fc, h2c->connection, sizeof(njt_connection_t));

    fc->data = h2c->http_connection;
    fc->read = rev;
    fc->write = wev;
    fc->sent = 0;
    fc->log = log;
    fc->buffered = 0;
    fc->sndlowat = 1;
    fc->tcp_nodelay = NJT_TCP_NODELAY_DISABLED;

    r = njt_http_create_request(fc);
    if (r == NULL) {
        return NULL;
    }

    njt_str_set(&r->http_protocol, "HTTP/2.0");

    r->http_version = NJT_HTTP_VERSION_20;
    r->valid_location = 1;

    fc->data = r;
    h2c->connection->requests++;

    cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);

    r->header_in = njt_create_temp_buf(r->pool,
                                       cscf->client_header_buffer_size);
    if (r->header_in == NULL) {
        njt_http_free_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    if (njt_list_init(&r->headers_in.headers, r->pool, 20,
                      sizeof(njt_table_elt_t))
        != NJT_OK)
    {
        njt_http_free_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    r->headers_in.connection_type = NJT_HTTP_CONNECTION_CLOSE;

    stream = njt_pcalloc(r->pool, sizeof(njt_http_v2_stream_t));
    if (stream == NULL) {
        njt_http_free_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    r->stream = stream;

    stream->request = r;
    stream->connection = h2c;

    h2scf = njt_http_get_module_srv_conf(r, njt_http_v2_module);

    stream->send_window = h2c->init_window;
    stream->recv_window = h2scf->preread_size;

    h2c->processing++;

    h2c->priority_limit += h2scf->concurrent_streams;

    if (h2c->connection->read->timer_set) {
        njt_del_timer(h2c->connection->read);
    }

    return stream;
}


static njt_http_v2_node_t *
njt_http_v2_get_node_by_id(njt_http_v2_connection_t *h2c, njt_uint_t sid,
    njt_uint_t alloc)
{
    njt_uint_t               index;
    njt_http_v2_node_t      *node;
    njt_http_v2_srv_conf_t  *h2scf;

    h2scf = njt_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         njt_http_v2_module);

    index = njt_http_v2_index(h2scf, sid);

    for (node = h2c->streams_index[index]; node; node = node->index) {

        if (node->id == sid) {
            return node;
        }
    }

    if (!alloc) {
        return NULL;
    }

    if (h2c->closed_nodes < 32) {
        node = njt_pcalloc(h2c->connection->pool, sizeof(njt_http_v2_node_t));
        if (node == NULL) {
            return NULL;
        }

    } else {
        node = njt_http_v2_get_closed_node(h2c);
    }

    node->id = sid;

    njt_queue_init(&node->children);

    node->index = h2c->streams_index[index];
    h2c->streams_index[index] = node;

    return node;
}


static njt_http_v2_node_t *
njt_http_v2_get_closed_node(njt_http_v2_connection_t *h2c)
{
    njt_uint_t               weight;
    njt_queue_t             *q, *children;
    njt_http_v2_node_t      *node, **next, *n, *parent, *child;
    njt_http_v2_srv_conf_t  *h2scf;

    h2scf = njt_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         njt_http_v2_module);

    h2c->closed_nodes--;

    q = njt_queue_head(&h2c->closed);

    njt_queue_remove(q);

    node = njt_queue_data(q, njt_http_v2_node_t, reuse);

    next = &h2c->streams_index[njt_http_v2_index(h2scf, node->id)];

    for ( ;; ) {
        n = *next;

        if (n == node) {
            *next = n->index;
            break;
        }

        next = &n->index;
    }

    njt_queue_remove(&node->queue);

    weight = 0;

    for (q = njt_queue_head(&node->children);
         q != njt_queue_sentinel(&node->children);
         q = njt_queue_next(q))
    {
        child = njt_queue_data(q, njt_http_v2_node_t, queue);
        weight += child->weight;
    }

    parent = node->parent;
    weight = (weight != 0?weight:1); //by zyg
    for (q = njt_queue_head(&node->children);
         q != njt_queue_sentinel(&node->children);
         q = njt_queue_next(q))
    {
        child = njt_queue_data(q, njt_http_v2_node_t, queue);
        child->parent = parent;
        child->weight = node->weight * child->weight / weight;

        if (child->weight == 0) {
            child->weight = 1;
        }
    }

    if (parent == NJT_HTTP_V2_ROOT) {
        node->rank = 0;
        node->rel_weight = 1.0;

        children = &h2c->dependencies;

    } else {
        node->rank = parent->rank;
        node->rel_weight = parent->rel_weight;

        children = &parent->children;
    }

    njt_http_v2_node_children_update(node);
    njt_queue_add(children, &node->children);

    njt_memzero(node, sizeof(njt_http_v2_node_t));

    return node;
}


static njt_int_t
njt_http_v2_validate_header(njt_http_request_t *r, njt_http_v2_header_t *header)
{
    u_char                     ch;
    njt_uint_t                 i;
    njt_http_core_srv_conf_t  *cscf;

    r->invalid_header = 0;

    cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);

    for (i = (header->name.data[0] == ':'); i != header->name.len; i++) {
        ch = header->name.data[i];

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
                          "client sent invalid header name: \"%V\"",
                          &header->name);

            return NJT_ERROR;
        }

        r->invalid_header = 1;
    }

    for (i = 0; i != header->value.len; i++) {
        ch = header->value.data[i];

        if (ch == '\0' || ch == LF || ch == CR) {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "client sent header \"%V\" with "
                          "invalid value: \"%V\"",
                          &header->name, &header->value);

            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


static njt_int_t
njt_http_v2_pseudo_header(njt_http_request_t *r, njt_http_v2_header_t *header)
{
    header->name.len--;
    header->name.data++;

    switch (header->name.len) {
    case 4:
        if (njt_memcmp(header->name.data, "path", sizeof("path") - 1)
            == 0)
        {
            return njt_http_v2_parse_path(r, &header->value);
        }

        break;

    case 6:
        if (njt_memcmp(header->name.data, "method", sizeof("method") - 1)
            == 0)
        {
            return njt_http_v2_parse_method(r, &header->value);
        }

        if (njt_memcmp(header->name.data, "scheme", sizeof("scheme") - 1)
            == 0)
        {
            return njt_http_v2_parse_scheme(r, &header->value);
        }

        break;

    case 9:
        if (njt_memcmp(header->name.data, "authority", sizeof("authority") - 1)
            == 0)
        {
            return njt_http_v2_parse_authority(r, &header->value);
        }

        break;
    }

    njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                  "client sent unknown pseudo-header \":%V\"",
                  &header->name);

    return NJT_DECLINED;
}


static njt_int_t
njt_http_v2_parse_path(njt_http_request_t *r, njt_str_t *value)
{
    if (r->unparsed_uri.len) {
        njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                      "client sent duplicate :path header");

        return NJT_DECLINED;
    }

    if (value->len == 0) {
        njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                      "client sent empty :path header");

        return NJT_DECLINED;
    }

    r->uri_start = value->data;
    r->uri_end = value->data + value->len;

    if (njt_http_parse_uri(r) != NJT_OK) {
        njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                      "client sent invalid :path header: \"%V\"", value);

        return NJT_DECLINED;
    }

    if (njt_http_process_request_uri(r) != NJT_OK) {
        /*
         * request has been finalized already
         * in njt_http_process_request_uri()
         */
        return NJT_ABORT;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_v2_parse_method(njt_http_request_t *r, njt_str_t *value)
{
    size_t         k, len;
    njt_uint_t     n;
    const u_char  *p, *m;

    /*
     * This array takes less than 256 sequential bytes,
     * and if typical CPU cache line size is 64 bytes,
     * it is prefetched for 4 load operations.
     */
    static const struct {
        u_char            len;
        const u_char      method[11];
        uint32_t          value;
    } tests[] = {
        { 3, "GET",       NJT_HTTP_GET },
        { 4, "POST",      NJT_HTTP_POST },
        { 4, "HEAD",      NJT_HTTP_HEAD },
        { 7, "OPTIONS",   NJT_HTTP_OPTIONS },
        { 8, "PROPFIND",  NJT_HTTP_PROPFIND },
        { 3, "PUT",       NJT_HTTP_PUT },
        { 5, "MKCOL",     NJT_HTTP_MKCOL },
        { 6, "DELETE",    NJT_HTTP_DELETE },
        { 4, "COPY",      NJT_HTTP_COPY },
        { 4, "MOVE",      NJT_HTTP_MOVE },
        { 9, "PROPPATCH", NJT_HTTP_PROPPATCH },
        { 4, "LOCK",      NJT_HTTP_LOCK },
        { 6, "UNLOCK",    NJT_HTTP_UNLOCK },
        { 5, "PATCH",     NJT_HTTP_PATCH },
        { 5, "TRACE",     NJT_HTTP_TRACE },
        { 7, "CONNECT",   NJT_HTTP_CONNECT }
    }, *test;

    if (r->method_name.len) {
        njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                      "client sent duplicate :method header");

        return NJT_DECLINED;
    }

    if (value->len == 0) {
        njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                      "client sent empty :method header");

        return NJT_DECLINED;
    }

    r->method_name.len = value->len;
    r->method_name.data = value->data;

    len = r->method_name.len;
    n = sizeof(tests) / sizeof(tests[0]);
    test = tests;

    do {
        if (len == test->len) {
            p = r->method_name.data;
            m = test->method;
            k = len;

            do {
                if (*p++ != *m++) {
                    goto next;
                }
            } while (--k);

            r->method = test->value;
            return NJT_OK;
        }

    next:
        test++;

    } while (--n);

    p = r->method_name.data;

    do {
        if ((*p < 'A' || *p > 'Z') && *p != '_' && *p != '-') {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "client sent invalid method: \"%V\"",
                          &r->method_name);

            return NJT_DECLINED;
        }

        p++;

    } while (--len);

    return NJT_OK;
}


static njt_int_t
njt_http_v2_parse_scheme(njt_http_request_t *r, njt_str_t *value)
{
    u_char      c, ch;
    njt_uint_t  i;

    if (r->schema.len) {
        njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                      "client sent duplicate :scheme header");

        return NJT_DECLINED;
    }

    if (value->len == 0) {
        njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                      "client sent empty :scheme header");

        return NJT_DECLINED;
    }

    for (i = 0; i < value->len; i++) {
        ch = value->data[i];

        c = (u_char) (ch | 0x20);
        if (c >= 'a' && c <= 'z') {
            continue;
        }

        if (((ch >= '0' && ch <= '9') || ch == '+' || ch == '-' || ch == '.')
            && i > 0)
        {
            continue;
        }

        njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                      "client sent invalid :scheme header: \"%V\"", value);

        return NJT_DECLINED;
    }

    r->schema = *value;

    return NJT_OK;
}


static njt_int_t
njt_http_v2_parse_authority(njt_http_request_t *r, njt_str_t *value)
{
    njt_table_elt_t            *h;
    njt_http_header_t          *hh;
    njt_http_core_main_conf_t  *cmcf;

    static njt_str_t host = njt_string("host");

    h = njt_list_push(&r->headers_in.headers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    h->hash = njt_hash(njt_hash(njt_hash('h', 'o'), 's'), 't');

    h->key.len = host.len;
    h->key.data = host.data;

    h->value.len = value->len;
    h->value.data = value->data;

    h->lowcase_key = host.data;

    cmcf = njt_http_get_module_main_conf(r, njt_http_core_module);

    hh = njt_hash_find(&cmcf->headers_in_hash, h->hash,
                       h->lowcase_key, h->key.len);

    if (hh == NULL) {
        return NJT_ERROR;
    }

    if (hh->handler(r, h, hh->offset) != NJT_OK) {
        /*
         * request has been finalized already
         * in ngx_http_process_host()
         */
        return NJT_ABORT;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_v2_construct_request_line(njt_http_request_t *r)
{
    u_char  *p;

    static const u_char ending[] = " HTTP/2.0";

    if (r->method_name.len == 0
        || r->schema.len == 0
        || r->unparsed_uri.len == 0)
    {
        if (r->method_name.len == 0) {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "client sent no :method header");

        } else if (r->schema.len == 0) {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "client sent no :scheme header");

        } else {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "client sent no :path header");
        }

        njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);
        return NJT_ERROR;
    }

    r->request_line.len = r->method_name.len + 1
                          + r->unparsed_uri.len
                          + sizeof(ending) - 1;

    p = njt_pnalloc(r->pool, r->request_line.len + 1);
    if (p == NULL) {
        njt_http_v2_close_stream(r->stream, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return NJT_ERROR;
    }

    r->request_line.data = p;

    p = njt_cpymem(p, r->method_name.data, r->method_name.len);

    *p++ = ' ';

    p = njt_cpymem(p, r->unparsed_uri.data, r->unparsed_uri.len);

    njt_memcpy(p, ending, sizeof(ending));

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http2 request line: \"%V\"", &r->request_line);

    return NJT_OK;
}


static njt_int_t
njt_http_v2_cookie(njt_http_request_t *r, njt_http_v2_header_t *header)
{
    njt_str_t    *val;
    njt_array_t  *cookies;

    cookies = r->stream->cookies;

    if (cookies == NULL) {
        cookies = njt_array_create(r->pool, 2, sizeof(njt_str_t));
        if (cookies == NULL) {
            return NJT_ERROR;
        }

        r->stream->cookies = cookies;
    }

    val = njt_array_push(cookies);
    if (val == NULL) {
        return NJT_ERROR;
    }

    val->len = header->value.len;
    val->data = header->value.data;

    return NJT_OK;
}


static njt_int_t
njt_http_v2_construct_cookie_header(njt_http_request_t *r)
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

    cookies = r->stream->cookies;

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
        njt_http_v2_close_stream(r->stream, NJT_HTTP_INTERNAL_SERVER_ERROR);
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
        njt_http_v2_close_stream(r->stream, NJT_HTTP_INTERNAL_SERVER_ERROR);
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
        njt_http_v2_close_stream(r->stream, NJT_HTTP_INTERNAL_SERVER_ERROR);
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


static void
njt_http_v2_run_request(njt_http_request_t *r)
{
    njt_connection_t          *fc;
    njt_http_v2_srv_conf_t    *h2scf;
    njt_http_v2_connection_t  *h2c;

    fc = r->connection;

    h2scf = njt_http_get_module_srv_conf(r, njt_http_v2_module);

    if (!h2scf->enable && !r->http_connection->addr_conf->http2) {
        njt_log_error(NJT_LOG_INFO, fc->log, 0,
                      "client attempted to request the server name "
                      "for which the negotiated protocol is disabled");

        njt_http_finalize_request(r, NJT_HTTP_MISDIRECTED_REQUEST);
        goto failed;
    }

    if (njt_http_v2_construct_request_line(r) != NJT_OK) {
        goto failed;
    }

    if (njt_http_v2_construct_cookie_header(r) != NJT_OK) {
        goto failed;
    }

    r->http_state = NJT_HTTP_PROCESS_REQUEST_STATE;

    if (njt_http_process_request_header(r) != NJT_OK) {
        goto failed;
    }

    if (r->headers_in.content_length_n > 0 && r->stream->in_closed) {
        njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                      "client prematurely closed stream");

        r->stream->skip_data = 1;

        njt_http_finalize_request(r, NJT_HTTP_BAD_REQUEST);
        goto failed;
    }

    if (r->headers_in.content_length_n == -1 && !r->stream->in_closed) {
        r->headers_in.chunked = 1;
    }

    h2c = r->stream->connection;

    h2c->payload_bytes += r->request_length;

    njt_http_process_request(r);

failed:

    njt_http_run_posted_requests(fc);
}


njt_int_t
njt_http_v2_read_request_body(njt_http_request_t *r)
{
    off_t                      len;
    size_t                     size;
    njt_buf_t                 *buf;
    njt_int_t                  rc;
    njt_http_v2_stream_t      *stream;
    njt_http_v2_srv_conf_t    *h2scf;
    njt_http_request_body_t   *rb;
    njt_http_core_loc_conf_t  *clcf;
    njt_http_v2_connection_t  *h2c;

    stream = r->stream;
    rb = r->request_body;

    if (stream->skip_data) {
        r->request_body_no_buffering = 0;
        rb->post_handler(r);
        return NJT_OK;
    }

    rb->rest = 1;

    /* set rb->filter_need_buffering */

    rc = njt_http_top_request_body_filter(r, NULL);

    if (rc != NJT_OK) {
        stream->skip_data = 1;
        return rc;
    }

    h2scf = njt_http_get_module_srv_conf(r, njt_http_v2_module);
    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    len = r->headers_in.content_length_n;

    if (len < 0 || len > (off_t) clcf->client_body_buffer_size) {
        len = clcf->client_body_buffer_size;

    } else {
        len++;
    }

    if (r->request_body_no_buffering || rb->filter_need_buffering) {

        /*
         * We need a room to store data up to the stream's initial window size,
         * at least until this window will be exhausted.
         */

        if (len < (off_t) h2scf->preread_size) {
            len = h2scf->preread_size;
        }

        if (len > NJT_HTTP_V2_MAX_WINDOW) {
            len = NJT_HTTP_V2_MAX_WINDOW;
        }
    }

    rb->buf = njt_create_temp_buf(r->pool, (size_t) len);

    if (rb->buf == NULL) {
        stream->skip_data = 1;
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    buf = stream->preread;

    if (stream->in_closed) {
        if (!rb->filter_need_buffering) {
            r->request_body_no_buffering = 0;
        }

        if (buf) {
            rc = njt_http_v2_process_request_body(r, buf->pos,
                                                  buf->last - buf->pos, 1, 0);
            njt_pfree(r->pool, buf->start);

        } else {
            rc = njt_http_v2_process_request_body(r, NULL, 0, 1, 0);
        }

        if (rc != NJT_AGAIN) {
            return rc;
        }

        r->read_event_handler = njt_http_v2_read_client_request_body_handler;
        r->write_event_handler = njt_http_request_empty_handler;

        return NJT_AGAIN;
    }

    if (buf) {
        rc = njt_http_v2_process_request_body(r, buf->pos,
                                              buf->last - buf->pos, 0, 0);

        njt_pfree(r->pool, buf->start);

        if (rc != NJT_OK && rc != NJT_AGAIN) {
            stream->skip_data = 1;
            return rc;
        }
    }

    if (r->request_body_no_buffering || rb->filter_need_buffering) {
        size = (size_t) len - h2scf->preread_size;

    } else {
        stream->no_flow_control = 1;
        size = NJT_HTTP_V2_MAX_WINDOW - stream->recv_window;
    }

    if (size) {
        if (njt_http_v2_send_window_update(stream->connection,
                                           stream->node->id, size)
            == NJT_ERROR)
        {
            stream->skip_data = 1;
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        h2c = stream->connection;

        if (!h2c->blocked) {
            if (njt_http_v2_send_output_queue(h2c) == NJT_ERROR) {
                stream->skip_data = 1;
                return NJT_HTTP_INTERNAL_SERVER_ERROR;
            }
        }

        stream->recv_window += size;
    }

    if (!buf) {
        njt_add_timer(r->connection->read, clcf->client_body_timeout);
    }

    r->read_event_handler = njt_http_v2_read_client_request_body_handler;
    r->write_event_handler = njt_http_request_empty_handler;

    return NJT_AGAIN;
}


static njt_int_t
njt_http_v2_process_request_body(njt_http_request_t *r, u_char *pos,
    size_t size, njt_uint_t last, njt_uint_t flush)
{
    size_t                     n;
    njt_int_t                  rc;
    njt_connection_t          *fc;
    njt_http_request_body_t   *rb;
    njt_http_core_loc_conf_t  *clcf;

    fc = r->connection;
    rb = r->request_body;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, fc->log, 0,
                   "http2 process request body");

    if (size == 0 && !last && !flush) {
        return NJT_AGAIN;
    }

    for ( ;; ) {
        for ( ;; ) {
            if (rb->buf->last == rb->buf->end && size) {

                if (r->request_body_no_buffering) {

                    /* should never happen due to flow control */

                    njt_log_error(NJT_LOG_ALERT, fc->log, 0,
                                  "no space in http2 body buffer");

                    return NJT_HTTP_INTERNAL_SERVER_ERROR;
                }

                /* update chains */

                njt_log_debug0(NJT_LOG_DEBUG_HTTP, fc->log, 0,
                               "http2 body update chains");

                rc = njt_http_v2_filter_request_body(r);

                if (rc != NJT_OK) {
                    return rc;
                }

                if (rb->busy != NULL) {
                    njt_log_error(NJT_LOG_ALERT, fc->log, 0,
                                  "busy buffers after request body flush");
                    return NJT_HTTP_INTERNAL_SERVER_ERROR;
                }

                rb->buf->pos = rb->buf->start;
                rb->buf->last = rb->buf->start;
            }

            /* copy body data to the buffer */

            n = rb->buf->end - rb->buf->last;

            if (n > size) {
                n = size;
            }

            if (n > 0) {
                rb->buf->last = njt_cpymem(rb->buf->last, pos, n);
            }

            njt_log_debug1(NJT_LOG_DEBUG_HTTP, fc->log, 0,
                           "http2 request body recv %uz", n);

            pos += n;
            size -= n;

            if (size == 0 && last) {
                rb->rest = 0;
            }

            if (size == 0) {
                break;
            }
        }

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, fc->log, 0,
                       "http2 request body rest %O", rb->rest);

        if (flush) {
            rc = njt_http_v2_filter_request_body(r);

            if (rc != NJT_OK) {
                return rc;
            }
        }

        if (rb->rest == 0 && rb->last_saved) {
            break;
        }

        if (size == 0) {
            clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);
            njt_add_timer(fc->read, clcf->client_body_timeout);

            if (!flush) {
                njt_post_event(fc->read, &njt_posted_events);
            }

            return NJT_AGAIN;
        }
    }

    if (fc->read->timer_set) {
        njt_del_timer(fc->read);
    }

    if (r->request_body_no_buffering) {
        if (!flush) {
            njt_post_event(fc->read, &njt_posted_events);
        }

        return NJT_OK;
    }

    if (r->headers_in.chunked) {
        r->headers_in.content_length_n = rb->received;
    }

    r->read_event_handler = njt_http_block_reading;
    rb->post_handler(r);

    return NJT_OK;
}


static njt_int_t
njt_http_v2_filter_request_body(njt_http_request_t *r)
{
    njt_buf_t                 *b, *buf;
    njt_int_t                  rc;
    njt_chain_t               *cl;
    njt_http_request_body_t   *rb;
    njt_http_core_loc_conf_t  *clcf;

    rb = r->request_body;
    buf = rb->buf;

    if (buf->pos == buf->last && (rb->rest || rb->last_sent)) {
        cl = NULL;
        goto update;
    }

    cl = njt_chain_get_free_buf(r->pool, &rb->free);
    if (cl == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    b = cl->buf;

    njt_memzero(b, sizeof(njt_buf_t));

    if (buf->pos != buf->last) {
        r->request_length += buf->last - buf->pos;
        rb->received += buf->last - buf->pos;

        if (r->headers_in.content_length_n != -1) {
            if (rb->received > r->headers_in.content_length_n) {
                njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                              "client intended to send body data "
                              "larger than declared");

                return NJT_HTTP_BAD_REQUEST;
            }

        } else {
            clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

            if (clcf->client_max_body_size
                && rb->received > clcf->client_max_body_size)
            {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "client intended to send too large chunked body: "
                              "%O bytes", rb->received);

                return NJT_HTTP_REQUEST_ENTITY_TOO_LARGE;
            }
        }

        b->temporary = 1;
        b->pos = buf->pos;
        b->last = buf->last;
        b->start = b->pos;
        b->end = b->last;

        buf->pos = buf->last;
    }

    if (!rb->rest) {
        if (r->headers_in.content_length_n != -1
            && r->headers_in.content_length_n != rb->received)
        {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "client prematurely closed stream: "
                          "only %O out of %O bytes of request body received",
                          rb->received, r->headers_in.content_length_n);

            return NJT_HTTP_BAD_REQUEST;
        }

        b->last_buf = 1;
        rb->last_sent = 1;
    }

    b->tag = (njt_buf_tag_t) &njt_http_v2_filter_request_body;
    b->flush = r->request_body_no_buffering;

update:

    rc = njt_http_top_request_body_filter(r, cl);

    njt_chain_update_chains(r->pool, &rb->free, &rb->busy, &cl,
                            (njt_buf_tag_t) &njt_http_v2_filter_request_body);

    return rc;
}


static void
njt_http_v2_read_client_request_body_handler(njt_http_request_t *r)
{
    size_t                     window;
    njt_buf_t                 *buf;
    njt_int_t                  rc;
    njt_connection_t          *fc;
    njt_http_v2_stream_t      *stream;
    njt_http_v2_connection_t  *h2c;

    fc = r->connection;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, fc->log, 0,
                   "http2 read client request body handler");

    if (fc->read->timedout) {
        njt_log_error(NJT_LOG_INFO, fc->log, NJT_ETIMEDOUT, "client timed out");

        fc->timedout = 1;
        r->stream->skip_data = 1;

        njt_http_finalize_request(r, NJT_HTTP_REQUEST_TIME_OUT);
        return;
    }

    if (fc->error) {
        njt_log_error(NJT_LOG_INFO, fc->log, 0,
                      "client prematurely closed stream");

        r->stream->skip_data = 1;

        njt_http_finalize_request(r, NJT_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }

    rc = njt_http_v2_process_request_body(r, NULL, 0, r->stream->in_closed, 1);

    if (rc != NJT_OK && rc != NJT_AGAIN) {
        r->stream->skip_data = 1;
        njt_http_finalize_request(r, rc);
        return;
    }

    if (rc == NJT_OK) {
        return;
    }

    if (r->stream->no_flow_control) {
        return;
    }

    if (r->request_body->rest == 0) {
        return;
    }

    if (r->request_body->busy != NULL) {
        return;
    }

    stream = r->stream;
    h2c = stream->connection;

    buf = r->request_body->buf;

    buf->pos = buf->start;
    buf->last = buf->start;

    window = buf->end - buf->start;

    if (h2c->state.stream == stream) {
        window -= h2c->state.length;
    }

    if (window <= stream->recv_window) {
        if (window < stream->recv_window) {
            njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
                          "http2 negative window update");

            stream->skip_data = 1;

            njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        return;
    }

    if (njt_http_v2_send_window_update(h2c, stream->node->id,
                                       window - stream->recv_window)
        == NJT_ERROR)
    {
        stream->skip_data = 1;
        njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    stream->recv_window = window;

    if (njt_http_v2_send_output_queue(h2c) == NJT_ERROR) {
        stream->skip_data = 1;
        njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
}


njt_int_t
njt_http_v2_read_unbuffered_request_body(njt_http_request_t *r)
{
    size_t                     window;
    njt_buf_t                 *buf;
    njt_int_t                  rc;
    njt_connection_t          *fc;
    njt_http_v2_stream_t      *stream;
    njt_http_v2_connection_t  *h2c;

    stream = r->stream;
    fc = r->connection;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, fc->log, 0,
                   "http2 read unbuffered request body");

    if (fc->read->timedout) {
        if (stream->recv_window) {
            stream->skip_data = 1;
            fc->timedout = 1;

            return NJT_HTTP_REQUEST_TIME_OUT;
        }

        fc->read->timedout = 0;
    }

    if (fc->error) {
        stream->skip_data = 1;
        return NJT_HTTP_BAD_REQUEST;
    }

    rc = njt_http_v2_process_request_body(r, NULL, 0, r->stream->in_closed, 1);

    if (rc != NJT_OK && rc != NJT_AGAIN) {
        stream->skip_data = 1;
        return rc;
    }

    if (rc == NJT_OK) {
        return NJT_OK;
    }

    if (r->request_body->rest == 0) {
        return NJT_AGAIN;
    }

    if (r->request_body->busy != NULL) {
        return NJT_AGAIN;
    }

    buf = r->request_body->buf;

    buf->pos = buf->start;
    buf->last = buf->start;

    window = buf->end - buf->start;
    h2c = stream->connection;

    if (h2c->state.stream == stream) {
        window -= h2c->state.length;
    }

    if (window <= stream->recv_window) {
        if (window < stream->recv_window) {
            njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
                          "http2 negative window update");
            stream->skip_data = 1;
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        return NJT_AGAIN;
    }

    if (njt_http_v2_send_window_update(h2c, stream->node->id,
                                       window - stream->recv_window)
        == NJT_ERROR)
    {
        stream->skip_data = 1;
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (njt_http_v2_send_output_queue(h2c) == NJT_ERROR) {
        stream->skip_data = 1;
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    stream->recv_window = window;

    return NJT_AGAIN;
}


static njt_int_t
njt_http_v2_terminate_stream(njt_http_v2_connection_t *h2c,
    njt_http_v2_stream_t *stream, njt_uint_t status)
{
    njt_event_t       *rev;
    njt_connection_t  *fc;

    if (stream->rst_sent) {
        return NJT_OK;
    }

    if (njt_http_v2_send_rst_stream(h2c, stream->node->id, status)
        == NJT_ERROR)
    {
        return NJT_ERROR;
    }

    stream->rst_sent = 1;
    stream->skip_data = 1;

    fc = stream->request->connection;
    fc->error = 1;

    rev = fc->read;
    rev->handler(rev);

    return NJT_OK;
}


void
njt_http_v2_close_stream(njt_http_v2_stream_t *stream, njt_int_t rc)
{
    njt_pool_t                *pool;
    njt_event_t               *ev;
    njt_connection_t          *fc;
    njt_http_v2_node_t        *node;
    njt_http_v2_connection_t  *h2c;

    h2c = stream->connection;
    node = stream->node;

    njt_log_debug3(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 close stream %ui, queued %ui, processing %ui",
                   node->id, stream->queued, h2c->processing);

    fc = stream->request->connection;

    if (stream->queued) {
        fc->error = 1;
        fc->write->handler = njt_http_v2_retry_close_stream_handler;
        fc->read->handler = njt_http_v2_retry_close_stream_handler;
        return;
    }

    if (!stream->rst_sent && !h2c->connection->error) {

        if (!stream->out_closed) {
            if (njt_http_v2_send_rst_stream(h2c, node->id,
                                      fc->timedout ? NJT_HTTP_V2_PROTOCOL_ERROR
                                                   : NJT_HTTP_V2_INTERNAL_ERROR)
                != NJT_OK)
            {
                h2c->connection->error = 1;
            }

        } else if (!stream->in_closed) {
            if (njt_http_v2_send_rst_stream(h2c, node->id, NJT_HTTP_V2_NO_ERROR)
                != NJT_OK)
            {
                h2c->connection->error = 1;
            }
        }
    }

    if (h2c->state.stream == stream) {
        h2c->state.stream = NULL;
    }

    node->stream = NULL;

    njt_queue_insert_tail(&h2c->closed, &node->reuse);
    h2c->closed_nodes++;

    /*
     * This pool keeps decoded request headers which can be used by log phase
     * handlers in njt_http_free_request().
     *
     * The pointer is stored into local variable because the stream object
     * will be destroyed after a call to njt_http_free_request().
     */
    pool = stream->pool;

    h2c->frames -= stream->frames;

    njt_http_free_request(stream->request, rc);

    if (pool != h2c->state.pool) {
        njt_destroy_pool(pool);

    } else {
        /* pool will be destroyed when the complete header is parsed */
        h2c->state.keep_pool = 0;
    }

    ev = fc->read;

    if (ev->timer_set) {
        njt_del_timer(ev);
    }

    if (ev->posted) {
        njt_delete_posted_event(ev);
    }

    ev = fc->write;

    if (ev->timer_set) {
        njt_del_timer(ev);
    }

    if (ev->posted) {
        njt_delete_posted_event(ev);
    }

    fc->data = h2c->free_fake_connections;
    h2c->free_fake_connections = fc;

    h2c->processing--;

    if (h2c->processing || h2c->blocked) {
        return;
    }

    ev = h2c->connection->read;

    ev->handler = njt_http_v2_handle_connection_handler;
    njt_post_event(ev, &njt_posted_events);
}


static void
njt_http_v2_close_stream_handler(njt_event_t *ev)
{
    njt_connection_t    *fc;
    njt_http_request_t  *r;

    fc = ev->data;
    r = fc->data;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, fc->log, 0,
                   "http2 close stream handler");

    if (ev->timedout) {
        njt_log_error(NJT_LOG_INFO, fc->log, NJT_ETIMEDOUT, "client timed out");

        fc->timedout = 1;

        njt_http_v2_close_stream(r->stream, NJT_HTTP_REQUEST_TIME_OUT);
        return;
    }

    njt_http_v2_close_stream(r->stream, 0);
}


static void
njt_http_v2_retry_close_stream_handler(njt_event_t *ev)
{
    njt_connection_t    *fc;
    njt_http_request_t  *r;

    fc = ev->data;
    r = fc->data;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, fc->log, 0,
                   "http2 retry close stream handler");

    njt_http_v2_close_stream(r->stream, 0);
}


static void
njt_http_v2_handle_connection_handler(njt_event_t *rev)
{
    njt_connection_t          *c;
    njt_http_v2_connection_t  *h2c;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, rev->log, 0,
                   "http2 handle connection handler");

    c = rev->data;
    h2c = c->data;

    if (c->error) {
        njt_http_v2_finalize_connection(h2c, 0);
        return;
    }

    rev->handler = njt_http_v2_read_handler;

    if (rev->ready) {
        njt_http_v2_read_handler(rev);
        return;
    }

    if (h2c->last_out && njt_http_v2_send_output_queue(h2c) == NJT_ERROR) {
        njt_http_v2_finalize_connection(h2c, 0);
        return;
    }

    njt_http_v2_handle_connection(c->data);
}


static void
njt_http_v2_idle_handler(njt_event_t *rev)
{
    njt_connection_t          *c;
    njt_http_v2_srv_conf_t    *h2scf;
    njt_http_v2_connection_t  *h2c;
    njt_http_core_loc_conf_t  *clcf;

    c = rev->data;
    h2c = c->data;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0, "http2 idle handler");

    if (rev->timedout || c->close) {
        njt_http_v2_finalize_connection(h2c, NJT_HTTP_V2_NO_ERROR);
        return;
    }

#if (NJT_HAVE_KQUEUE)

    if (njt_event_flags & NJT_USE_KQUEUE_EVENT) {
        if (rev->pending_eof) {
            c->log->handler = NULL;
            njt_log_error(NJT_LOG_INFO, c->log, rev->kq_errno,
                          "kevent() reported that client %V closed "
                          "idle connection", &c->addr_text);
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

    clcf = njt_http_get_module_loc_conf(h2c->http_connection->conf_ctx,
                                        njt_http_core_module);

    if (h2c->idle++ > 10 * clcf->keepalive_requests) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "http2 flood detected");
        njt_http_v2_finalize_connection(h2c, NJT_HTTP_V2_NO_ERROR);
        return;
    }

    c->destroyed = 0;
    njt_reusable_connection(c, 0);

    h2scf = njt_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         njt_http_v2_module);

    h2c->pool = njt_create_pool(h2scf->pool_size, h2c->connection->log);
    if (h2c->pool == NULL) {
        njt_http_v2_finalize_connection(h2c, NJT_HTTP_V2_INTERNAL_ERROR);
        return;
    }

    c->write->handler = njt_http_v2_write_handler;

    rev->handler = njt_http_v2_read_handler;
    njt_http_v2_read_handler(rev);
}


static void
njt_http_v2_finalize_connection(njt_http_v2_connection_t *h2c,
    njt_uint_t status)
{
    njt_uint_t               i, size;
    njt_event_t             *ev;
    njt_connection_t        *c, *fc;
    njt_http_request_t      *r;
    njt_http_v2_node_t      *node;
    njt_http_v2_stream_t    *stream;
    njt_http_v2_srv_conf_t  *h2scf;

    c = h2c->connection;

    h2c->blocked = 1;

    if (!c->error && !h2c->goaway) {
        h2c->goaway = 1;

        if (njt_http_v2_send_goaway(h2c, status) != NJT_ERROR) {
            (void) njt_http_v2_send_output_queue(h2c);
        }
    }

    if (!h2c->processing) {
        goto done;
    }

    c->read->handler = njt_http_empty_handler;
    c->write->handler = njt_http_empty_handler;

    h2c->last_out = NULL;

    h2scf = njt_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         njt_http_v2_module);

    size = njt_http_v2_index_size(h2scf);

    for (i = 0; i < size; i++) {

        for (node = h2c->streams_index[i]; node; node = node->index) {
            stream = node->stream;

            if (stream == NULL) {
                continue;
            }

            stream->waiting = 0;

            r = stream->request;
            fc = r->connection;

            fc->error = 1;

            if (stream->queued) {
                stream->queued = 0;

                ev = fc->write;
                ev->active = 0;
                ev->ready = 1;

            } else {
                ev = fc->read;
            }

            ev->eof = 1;
            ev->handler(ev);
        }
    }

    h2c->blocked = 0;

    if (h2c->processing) {
        c->error = 1;
        return;
    }

done:

    if (c->error) {
        njt_http_close_connection(c);
        return;
    }

    njt_http_v2_lingering_close(c);
}


static njt_int_t
njt_http_v2_adjust_windows(njt_http_v2_connection_t *h2c, ssize_t delta)
{
    njt_uint_t               i, size;
    njt_event_t             *wev;
    njt_http_v2_node_t      *node;
    njt_http_v2_stream_t    *stream;
    njt_http_v2_srv_conf_t  *h2scf;

    h2scf = njt_http_get_module_srv_conf(h2c->http_connection->conf_ctx,
                                         njt_http_v2_module);

    size = njt_http_v2_index_size(h2scf);

    for (i = 0; i < size; i++) {

        for (node = h2c->streams_index[i]; node; node = node->index) {
            stream = node->stream;

            if (stream == NULL) {
                continue;
            }

            if (delta > 0
                && stream->send_window
                      > (ssize_t) (NJT_HTTP_V2_MAX_WINDOW - delta))
            {
                if (njt_http_v2_terminate_stream(h2c, stream,
                                                 NJT_HTTP_V2_FLOW_CTRL_ERROR)
                    == NJT_ERROR)
                {
                    return NJT_ERROR;
                }

                continue;
            }

            stream->send_window += delta;

            njt_log_debug2(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                           "http2:%ui adjusted window: %z",
                           node->id, stream->send_window);

            if (stream->send_window > 0 && stream->exhausted) {
                stream->exhausted = 0;

                wev = stream->request->connection->write;

                wev->active = 0;
                wev->ready = 1;

                if (!wev->delayed) {
                    wev->handler(wev);
                }
            }
        }
    }

    return NJT_OK;
}


static void
njt_http_v2_set_dependency(njt_http_v2_connection_t *h2c,
    njt_http_v2_node_t *node, njt_uint_t depend, njt_uint_t exclusive)
{
    njt_queue_t         *children, *q;
    njt_http_v2_node_t  *parent, *child, *next;

    parent = depend ? njt_http_v2_get_node_by_id(h2c, depend, 0) : NULL;

    if (parent == NULL) {
        parent = NJT_HTTP_V2_ROOT;

        if (depend != 0) {
            exclusive = 0;
        }

        node->rank = 1;
        node->rel_weight = (1.0 / 256) * node->weight;

        children = &h2c->dependencies;

    } else {
        if (node->parent != NULL) {

            for (next = parent->parent;
                 next != NJT_HTTP_V2_ROOT && next->rank >= node->rank;
                 next = next->parent)
            {
                if (next != node) {
                    continue;
                }

                njt_queue_remove(&parent->queue);
                njt_queue_insert_after(&node->queue, &parent->queue);

                parent->parent = node->parent;

                if (node->parent == NJT_HTTP_V2_ROOT) {
                    parent->rank = 1;
                    parent->rel_weight = (1.0 / 256) * parent->weight;

                } else {
                    parent->rank = node->parent->rank + 1;
                    parent->rel_weight = (node->parent->rel_weight / 256)
                                         * parent->weight;
                }

                if (!exclusive) {
                    njt_http_v2_node_children_update(parent);
                }

                break;
            }
        }

        node->rank = parent->rank + 1;
        node->rel_weight = (parent->rel_weight / 256) * node->weight;

        if (parent->stream == NULL) {
            njt_queue_remove(&parent->reuse);
            njt_queue_insert_tail(&h2c->closed, &parent->reuse);
        }

        children = &parent->children;
    }

    if (exclusive) {
        for (q = njt_queue_head(children);
             q != njt_queue_sentinel(children);
             q = njt_queue_next(q))
        {
            child = njt_queue_data(q, njt_http_v2_node_t, queue);
            child->parent = node;
        }

        njt_queue_add(&node->children, children);
        njt_queue_init(children);
    }

    if (node->parent != NULL) {
        njt_queue_remove(&node->queue);
    }

    njt_queue_insert_tail(children, &node->queue);

    node->parent = parent;

    njt_http_v2_node_children_update(node);
}


static void
njt_http_v2_node_children_update(njt_http_v2_node_t *node)
{
    njt_queue_t         *q;
    njt_http_v2_node_t  *child;

    for (q = njt_queue_head(&node->children);
         q != njt_queue_sentinel(&node->children);
         q = njt_queue_next(q))
    {
        child = njt_queue_data(q, njt_http_v2_node_t, queue);

        child->rank = node->rank + 1;
        child->rel_weight = (node->rel_weight / 256) * child->weight;

        njt_http_v2_node_children_update(child);
    }
}


static void
njt_http_v2_pool_cleanup(void *data)
{
    njt_http_v2_connection_t  *h2c = data;

    if (h2c->state.pool) {
        njt_destroy_pool(h2c->state.pool);
    }

    if (h2c->pool) {
        njt_destroy_pool(h2c->pool);
    }
}
