/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */


#include "njt_http_mqtt_handler.h"
#include "njt_http_mqtt_module.h"
#include "njt_http_mqtt_processor.h"
#include "njt_http_mqtt_util.h"


#define MQTT_ERR_NO_DATA "no_message\n"
#define MQTT_ERR_BODY_TO_LARGE "body_too_large\n"
#define MQTT_ERR_PUBLISH "mqtt_publish_error\n"


njt_int_t
njt_http_mqtt_handler(njt_http_request_t *r)
{
    njt_http_mqtt_loc_conf_t   *mqttlcf;
    njt_http_mqtt_ctx_t        *mqttctx;
    njt_http_core_loc_conf_t  *clcf;
    njt_http_upstream_t       *u;
    njt_str_t                  host;
    njt_url_t                  url;
    njt_int_t                  rc;


    if (!(r->method & NJT_HTTP_POST)) {
        return NJT_HTTP_NOT_ALLOWED;
    }

    if (r->subrequest_in_memory) {
        /* TODO: add support for subrequest in memory by
         * emitting output into u->buffer instead */

        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "mqtt: njt_http_mqtt module does not support"
                      " subrequests in memory");

        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    mqttlcf = njt_http_get_module_loc_conf(r, njt_http_mqtt_module);

    if(mqttlcf->topic.len == 0){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "mqtt topic should be set");
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (njt_http_upstream_create(r) != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "mqtt upstream create error");
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    u = r->upstream;

    if (mqttlcf->upstream_cv) {
        /* use complex value */
        if (njt_http_complex_value(r, mqttlcf->upstream_cv, &host) != NJT_OK) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "mqtt upstream variable complex value error");
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (host.len == 0) {
            clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "mqtt: empty \"mqtt_pass\" (was: \"%V\")"
                          " in location \"%V\"", &mqttlcf->upstream_cv->value,
                          &clcf->name);

            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        njt_memzero(&url, sizeof(njt_url_t));

        url.host = host;
        url.no_resolve = 1;

        mqttlcf->upstream.upstream = njt_http_mqtt_find_upstream(r, &url);
        if (mqttlcf->upstream.upstream == NULL) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "mqtt: upstream name \"%V\" not found", &host);

            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    mqttctx = njt_pcalloc(r->pool, sizeof(njt_http_mqtt_ctx_t));
    if (mqttctx == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    njt_http_set_ctx(r, mqttctx, njt_http_mqtt_module);

    u->schema.len = sizeof("mqtt://") - 1;
    u->schema.data = (u_char *) "mqtt://";

    u->output.tag = (njt_buf_tag_t) &njt_http_mqtt_module;

    u->conf = &mqttlcf->upstream;

    u->create_request = njt_http_mqtt_create_request;
    u->reinit_request = njt_http_mqtt_reinit_request;
    u->process_header = njt_http_mqtt_process_header;
    u->abort_request = njt_http_mqtt_abort_request;
    u->finalize_request = njt_http_mqtt_finalize_request;

    /* we bypass the upstream input filter mechanism in
     * njt_http_upstream_process_headers */

    u->input_filter_init = njt_http_mqtt_input_filter_init;
    u->input_filter = njt_http_mqtt_input_filter;
    u->input_filter_ctx = NULL;

    rc = njt_http_read_client_request_body(r, njt_http_mqtt_internal_upstream_init);
    if (rc >= NJT_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NJT_DONE;
}


void
njt_http_mqtt_internal_upstream_init(njt_http_request_t *r){
    njt_http_upstream_init(r);

    /* override the read/write event handler to our own */
    r->upstream->write_event_handler = njt_http_mqtt_wev_handler;
    r->upstream->read_event_handler = njt_http_mqtt_rev_handler;
}


void
njt_http_mqtt_wev_handler(njt_http_request_t *r, njt_http_upstream_t *u)
{
    njt_connection_t                    *mqttxc;
    njt_http_mqtt_upstream_peer_data_t  *mqttdt;

    /* just to ensure u->reinit_request always gets called for
     * upstream_next */
    mqttxc = u->peer.connection;

    if (mqttxc->write->timedout) {
        // return;
    }

    if (njt_http_mqtt_upstream_test_connect(mqttxc) != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "mqtt connection is broken");

        mqttdt = u->peer.data;
        if(mqttdt->state == state_mqtt_connect){
            njt_http_mqtt_upstream_next(r, u, NJT_HTTP_UPSTREAM_FT_ERROR);
        }else{
            njt_http_mqtt_upstream_finalize_request(r, u, NJT_HTTP_INTERNAL_SERVER_ERROR);
        }
        
        return;
    }

    njt_http_mqtt_process_events(r);

    return;
}

void
njt_http_mqtt_rev_handler(njt_http_request_t *r, njt_http_upstream_t *u)
{
    njt_connection_t                    *mqttxc;
    njt_http_mqtt_upstream_peer_data_t  *mqttdt;

    /* just to ensure u->reinit_request always gets called for
     * upstream_next */
    mqttxc = u->peer.connection;

    if (mqttxc->read->timedout) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "mqtt connection read timeout");

        // njt_http_mqtt_upstream_next(r, u, NJT_HTTP_UPSTREAM_FT_TIMEOUT);
        njt_http_mqtt_upstream_next(r, u, NJT_HTTP_UPSTREAM_FT_TIMEOUT);
        return;
    }

    if (njt_http_mqtt_upstream_test_connect(mqttxc) != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "mqtt connection is broken");

        mqttdt = u->peer.data;
        if(mqttdt->state == state_mqtt_connect){
            njt_http_mqtt_upstream_next(r, u, NJT_HTTP_UPSTREAM_FT_ERROR);
        }else{
            njt_http_mqtt_upstream_finalize_request(r, u, NJT_HTTP_INTERNAL_SERVER_ERROR);
        }

        return;
    }

    if (mqttxc->read->timer_set) {
            njt_del_timer(mqttxc->read);
    }

    njt_http_mqtt_process_events(r);
}

njt_int_t
njt_http_mqtt_create_request(njt_http_request_t *r)
{
    r->upstream->request_bufs = NULL;

    return NJT_OK;
}

njt_int_t
njt_http_mqtt_reinit_request(njt_http_request_t *r)
{
    njt_http_upstream_t  *u;

    u = r->upstream;

    /* override the read/write event handler to our own */
    u->write_event_handler = njt_http_mqtt_wev_handler;
    u->read_event_handler = njt_http_mqtt_rev_handler;

    return NJT_OK;
}

void
njt_http_mqtt_abort_request(njt_http_request_t *r)
{
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "mqtt entering & returning (dummy function) abort request");
}

void
njt_http_mqtt_finalize_request(njt_http_request_t *r, njt_int_t rc)
{
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "mqtt finalize request code:%d", rc);
    r->headers_out.status = rc ? rc : NJT_HTTP_OK;
    njt_http_send_header(r);
}

njt_int_t
njt_http_mqtt_process_header(njt_http_request_t *r)
{
    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                  "mqtt: njt_http_mqtt_process_header should not"
                  " be called by the upstream");

    return NJT_ERROR;
}

njt_int_t
njt_http_mqtt_input_filter_init(void *data)
{
    njt_http_request_t  *r = data;

    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                  "mqtt: njt_http_mqtt_input_filter_init should not"
                  " be called by the upstream");
    return NJT_ERROR;
}

njt_int_t
njt_http_mqtt_input_filter(void *data, ssize_t bytes)
{
    njt_http_request_t  *r = data;

    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                  "mqtt: njt_http_mqtt_input_filter should not"
                  " be called by the upstream");

    return NJT_ERROR;
}


void
njt_http_mqtt_upstream_next(njt_http_request_t *r,
    njt_http_upstream_t *u, njt_int_t ft_type)
{
    // njt_uint_t          status, state;
    // njt_int_t           rc;
    njt_peer_connection_t  *pc = &u->peer;
    njt_http_mqtt_upstream_peer_data_t  *mqttdt = (njt_http_mqtt_upstream_peer_data_t  *)pc->data;
    njt_http_mqtt_upstream_srv_conf_t   *mqttscf = mqttdt->srv_conf;

    njt_log_error(NJT_LOG_DEBUG, r->connection->log, 0, "mqtt entering njt_http_mqtt_upstream_next");

    // if (ft_type == NJT_HTTP_UPSTREAM_FT_HTTP_404) {
    //     state = NJT_PEER_NEXT;
    // } else {
    //     state = NJT_PEER_FAILED;
    // }

    // if (ft_type != NJT_HTTP_UPSTREAM_FT_NOLIVE) {
    //     u->peer.free(&u->peer, u->peer.data, state);
    // }

    // if (ft_type == NJT_HTTP_UPSTREAM_FT_TIMEOUT) {
    //     njt_log_error(NJT_LOG_ERR, r->connection->log, NJT_ETIMEDOUT,
    //                   "upstream timed out");
    // }

    // if (u->peer.cached && ft_type == NJT_HTTP_UPSTREAM_FT_ERROR) {
    //     status = 0;

    // } else {
    //     switch(ft_type) {

    //     case NJT_HTTP_UPSTREAM_FT_TIMEOUT:
    //         status = NJT_HTTP_GATEWAY_TIME_OUT;
    //         break;

    //     case NJT_HTTP_UPSTREAM_FT_HTTP_500:
    //         status = NJT_HTTP_INTERNAL_SERVER_ERROR;
    //         break;

    //     case NJT_HTTP_UPSTREAM_FT_HTTP_404:
    //         status = NJT_HTTP_NOT_FOUND;
    //         break;

    //     /*
    //      * NJT_HTTP_UPSTREAM_FT_BUSY_LOCK and NJT_HTTP_UPSTREAM_FT_MAX_WAITING
    //      * never reach here
    //      */

    //     default:
    //         status = NJT_HTTP_BAD_GATEWAY;
    //     }
    // }

    if (r->connection->error) {
        njt_http_mqtt_upstream_finalize_request(r, u,
                                               NJT_HTTP_CLIENT_CLOSED_REQUEST);

        return;
    }

    // if (status) {
    //     u->state->status = status;

    //     if (u->peer.tries == 0 || !(u->conf->next_upstream & ft_type)) {
    //         njt_http_mqtt_upstream_finalize_request(r, u, status);

    //         return;
    //     }
    // }

//     if (u->peer.connection) {
//         njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
//                        "close http upstream connection: %d",
//                        u->peer.connection->fd);

// #if 0 /* we don't support SSL at this time, was: (NJT_HTTP_SSL) */

//         if (u->peer.connection->ssl) {
//             u->peer.connection->ssl->no_wait_shutdown = 1;
//             u->peer.connection->ssl->no_send_shutdown = 1;

//             (void) njt_ssl_shutdown(u->peer.connection);
//         }
// #endif

//         if (u->peer.connection->pool) {
//             njt_destroy_pool(u->peer.connection->pool);
//         }

//         njt_close_connection(u->peer.connection);
//     }


    // njt_http_mqtt_upstream_finalize_request(r, u, NJT_HTTP_INTERNAL_SERVER_ERROR);
    //free current connection
    njt_http_mqtt_upstream_free_connection(pc->log, pc->connection,
                                          mqttdt->mqtt_conn, mqttscf);

    pc->connection = NULL;

    //if has more than max retry times, just return
    mqttdt->get_peer_times++;
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,"mqtt getpeertimes:%d     config retry times:%d", mqttdt->get_peer_times , mqttdt->max_retry_times);

    if(mqttdt->get_peer_times > mqttdt->max_retry_times){
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0,"mqtt connect more than max retry times");
        // njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        njt_http_mqtt_upstream_finalize_request(r, u, NJT_HTTP_INTERNAL_SERVER_ERROR);
    }else{
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0,"mqtt connect retry");
        //connect new connection
        njt_http_upstream_connect(r, u);

        /* override the read/write event handler to our own */
        u->write_event_handler = njt_http_mqtt_wev_handler;
        u->read_event_handler = njt_http_mqtt_rev_handler;
    }

    return;
}
