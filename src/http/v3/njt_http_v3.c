
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


static void njt_http_v3_keepalive_handler(njt_event_t *ev);
static void njt_http_v3_cleanup_session(void *data);


njt_int_t
njt_http_v3_init_session(njt_connection_t *c)
{
    njt_pool_cleanup_t     *cln;
    njt_http_connection_t  *hc;
    njt_http_v3_session_t  *h3c;

    hc = c->data;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0, "http3 init session");

    h3c = njt_pcalloc(c->pool, sizeof(njt_http_v3_session_t));
    if (h3c == NULL) {
        goto failed;
    }

    h3c->http_connection = hc;

    njt_queue_init(&h3c->blocked);

    h3c->keepalive.log = c->log;
    h3c->keepalive.data = c;
    h3c->keepalive.handler = njt_http_v3_keepalive_handler;

    h3c->table.send_insert_count.log = c->log;
    h3c->table.send_insert_count.data = c;
    h3c->table.send_insert_count.handler = njt_http_v3_inc_insert_count_handler;

    cln = njt_pool_cleanup_add(c->pool, 0);
    if (cln == NULL) {
        goto failed;
    }

    cln->handler = njt_http_v3_cleanup_session;
    cln->data = h3c;

    c->data = h3c;

    return NJT_OK;

failed:

    njt_log_error(NJT_LOG_ERR, c->log, 0, "failed to create http3 session");

    return NJT_ERROR;
}


static void
njt_http_v3_keepalive_handler(njt_event_t *ev)
{
    njt_connection_t  *c;

    c = ev->data;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0, "http3 keepalive handler");

    njt_http_v3_finalize_connection(c, NJT_HTTP_V3_ERR_NO_ERROR,
                                    "keepalive timeout");
}


static void
njt_http_v3_cleanup_session(void *data)
{
    njt_http_v3_session_t  *h3c = data;

    njt_http_v3_cleanup_table(h3c);

    if (h3c->keepalive.timer_set) {
        njt_del_timer(&h3c->keepalive);
    }

    if (h3c->table.send_insert_count.posted) {
        njt_delete_posted_event(&h3c->table.send_insert_count);
    }
}


njt_int_t
njt_http_v3_check_flood(njt_connection_t *c)
{
    njt_http_v3_session_t  *h3c;

    h3c = njt_http_v3_get_session(c);

    if (h3c->total_bytes / 8 > h3c->payload_bytes + 1048576) {
        njt_log_error(NJT_LOG_INFO, c->log, 0, "http3 flood detected");

        njt_http_v3_finalize_connection(c, NJT_HTTP_V3_ERR_NO_ERROR,
                                        "HTTP/3 flood detected");
        return NJT_ERROR;
    }

    return NJT_OK;
}
