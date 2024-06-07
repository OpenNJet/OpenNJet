/*
 * Copyright (c) 2010, FRiCKLE Piotr Sikora <info@frickle.com>
 * Copyright (c) 2009-2010, Xiaozhe Wang <chaoslawful@gmail.com>
 * Copyright (c) 2009-2010, Yichun Zhang <agentzh@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */



#include "njt_http_mqtt_processor.h"
#include "njt_http_mqtt_util.h"

#define MQTT_ERR_NO_DATA "no_message\n"
#define MQTT_ERR_BODY_TO_LARGE "body_too_large\n"
#define MQTT_ERR_PUBLISH "mqtt_publish_error\n"


void
njt_http_mqtt_process_events(njt_http_request_t *r)
{
    njt_http_mqtt_upstream_peer_data_t  *mqttdt;
    njt_connection_t                   *mqttxc;
    njt_http_upstream_t                *u;
    njt_int_t                           rc;

    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"entering njt_http_mqtt_process_events");

    u = r->upstream;
    mqttxc = u->peer.connection;
    mqttdt = u->peer.data;

    if (!njt_http_mqtt_upstream_is_my_peer(&u->peer)) {
        njt_log_error(NJT_LOG_ERR, mqttxc->log, 0,
                      "http_mqtt: trying to connect to something that"
                      " is not mqtt database");

        goto failed;
    }

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, mqttxc->log, 0,
                   "http_mqtt: process events");

    switch (mqttdt->state) {
    case state_mqtt_connect:
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"state_mqtt_connect");
        rc = njt_http_mqtt_upstream_connect(r, mqttxc, mqttdt);
        break;
    case state_mqtt_publish:
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"state_mqtt_publish");
        rc = njt_http_mqtt_upstream_publish(r, mqttxc, mqttdt);
        break;
    case state_mqtt_get_result:
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"state_mqtt_get_result");
        rc = njt_http_mqtt_upstream_get_result(r, mqttxc, mqttdt);
        break;

    case state_mqtt_idle:
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"state_mqtt_idle, re-using keepalive connection");
        rc = njt_http_mqtt_upstream_get_result(r, mqttxc, mqttdt);
        break;
    default:
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"unknown state:%d", mqttdt->state);
        njt_log_error(NJT_LOG_ERR, mqttxc->log, 0,
                      "http_mqtt: unknown state:%d", mqttdt->state);

        goto failed;
    }

    if (rc >= NJT_HTTP_SPECIAL_RESPONSE) {
        njt_http_mqtt_upstream_finalize_request(r, u, rc);
    } else if (rc == NJT_ERROR) {
        goto failed;
    }

    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"returning njt_http_mqtt_process_events");
    return;

failed:

    // njt_http_mqtt_upstream_next(r, u, NJT_HTTP_UPSTREAM_FT_ERROR);
    // njt_http_upstream_next(r, u, NJT_HTTP_UPSTREAM_FT_ERROR);

    // njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"mqtt next upstream");

    return;
}


static void njt_http_mqtt_broker_ping_timer_handler(njt_event_t *ev){
    struct mqtt_client *client = (struct mqtt_client *)ev->data;
    ssize_t             rv;

    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"===========enter ping timer handler");

    //send ping packet
    /* check for keep-alive */
    // {
        // mqtt_pal_time_t keep_alive_timeout = client->time_of_last_send + (mqtt_pal_time_t)((float)(client->keep_alive));
        // if (MQTT_PAL_TIME() > keep_alive_timeout) {
            MQTT_PAL_MUTEX_LOCK(&client->mutex);
            rv = __mqtt_ping(client);
            if (rv != MQTT_OK) {
                MQTT_PAL_MUTEX_UNLOCK(&client->mutex);
                if(rv == MQTT_ERROR_SEND_BUFFER_IS_FULL){
                    if (ev->timedout && !njt_exiting)
                    {
                        njt_add_timer(ev, client->ping_time);
                        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                            "===========ping msg add to queue, buffer is full, readd ping timer handler");

                        return;
                    }
                }

                //if has error, timer just return
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                    "===========ping msg add to queue error:%d, exit ping timer", rv);
                return ;
            }

            MQTT_PAL_MUTEX_UNLOCK(&client->mutex);
            rv = __mqtt_send(client);
            if(rv != MQTT_OK){
                if(rv == MQTT_ERROR_SEND_BUFFER_IS_FULL){
                    if (ev->timedout && !njt_exiting)
                    {
                        njt_add_timer(ev, client->ping_time);
                        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                            "===========buffer is full, readd ping timer handler");
                        return;
                    }
                }

                //if has error, timer just return
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                    "===========ping send error:%d, exit ping timer", rv);

                return ;
            }
    //     }
    // }

    if (ev->timedout && !njt_exiting)
    {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"===========readd ping timer handler");
		njt_add_timer(ev, client->ping_time);
        // //need start read timeout
        njt_add_timer(client->connection->read, client->read_timeout);
	}

    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"===========exit ping timer handler");
}

void njt_http_mqtt_publish_callback(njt_http_request_t *r, void** unused, struct mqtt_response_publish *published)
{

njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "============njt_http_mqtt_publish_callback");

    /* not used in this example */
    if(r != NULL){
        //close http request
        njt_http_mqtt_upstream_finalize_request(r, r->upstream, NJT_OK);
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "mqtt response publish result");
    }
}


njt_int_t
njt_http_mqtt_upstream_connect(njt_http_request_t *r, njt_connection_t *c,
    njt_http_mqtt_upstream_peer_data_t *mqttdt)
{
    njt_peer_connection_t               *pc = &r->upstream->peer;
    const char                          *client_id = NULL;
    uint8_t                             connect_flags = MQTT_CONNECT_CLEAN_SESSION;
    njt_event_t                         *rev, *wev;
    njt_int_t                           rc;
    njt_int_t                           event;
    njt_err_t                           err;
    njt_uint_t                          level;
    njt_http_mqtt_upstream_srv_conf_t   *mqttscf;
    njt_pool_t                          *pool;


    mqttscf = mqttdt->srv_conf;

    rev = c->read;
    wev = c->write;

    // if (njt_add_conn) {
    //     if (njt_add_conn(c) == NJT_ERROR) {
    //         goto failed;
    //     }
    // }


    rc = connect(c->fd, pc->sockaddr, pc->socklen);
    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                   "connect to %V, fd:%d #%uA   return:%d", pc->name, c->fd, c->number, rc);
    if (rc == -1) {
        err = njt_socket_errno;


        if (err != NJT_EINPROGRESS
#if (NJT_WIN32)
            /* Winsock returns WSAEWOULDBLOCK (NJT_EAGAIN) */
            && err != NJT_EAGAIN
#endif
            )
        {
            if (err == NJT_ECONNREFUSED
#if (NJT_LINUX)
                /*
                 * Linux returns EAGAIN instead of ECONNREFUSED
                 * for unix sockets if listen queue is full
                 */
                || err == NJT_EAGAIN
#endif
                || err == NJT_ECONNRESET
                || err == NJT_ENETDOWN
                || err == NJT_ENETUNREACH
                || err == NJT_EHOSTDOWN
                || err == NJT_EHOSTUNREACH)
            {
                level = NJT_LOG_ERR;

            } else {
                level = NJT_LOG_CRIT;
            }

            njt_log_error(level, c->log, err, "connect() to %V failed",
                          pc->name);

            goto failed;
        }
    }

    if (njt_add_conn) {
        if (rc == -1) {

            /* NJT_EINPROGRESS */
            njt_log_error(NJT_LOG_INFO, c->log, 0, "connect() to %V again",
                pc->name);

            return NJT_AGAIN;
        }

        wev->ready = 1;

        goto done;
    }

    if (njt_event_flags & NJT_USE_IOCP_EVENT) {

        njt_log_debug1(NJT_LOG_DEBUG_EVENT, pc->log, njt_socket_errno,
                       "connect(): %d", rc);

        if (njt_blocking(c->fd) == -1) {
            njt_log_error(NJT_LOG_ALERT, pc->log, njt_socket_errno,
                          njt_blocking_n " failed");

            njt_log_error(NJT_LOG_INFO, c->log, 0, "mqtt connected %V failed", pc->name);
            goto failed;
        }

        /*
         * FreeBSD's aio allows to post an operation on non-connected socket.
         * NT does not support it.
         *
         * TODO: check in Win32, etc. As workaround we can use NJT_ONESHOT_EVENT
         */

        rev->ready = 1;
        wev->ready = 1;

        goto done;
    }

    if (njt_event_flags & NJT_USE_CLEAR_EVENT) {

        /* kqueue */

        event = NJT_CLEAR_EVENT;

    } else {

        /* select, poll, /dev/poll */

        event = NJT_LEVEL_EVENT;
    }

    if (njt_add_event(rev, NJT_READ_EVENT, event) != NJT_OK) {
        goto failed;
    }

    if (rc == -1) {

        /* NJT_EINPROGRESS */

        if (njt_add_event(wev, NJT_WRITE_EVENT, event) != NJT_OK) {
            goto failed;
        }

        njt_log_error(NJT_LOG_INFO, c->log, 0, "mqtt connected %V again", pc->name);
        return NJT_AGAIN;
    }

done:
    njt_log_error(NJT_LOG_INFO, c->log, 0, "mqtt connected %V success", pc->name);
    wev->ready = 1;

    /* remove connection timeout from new connection */
    if (c->write->timer_set) {
        njt_del_timer(c->write);
    }

    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"connected successfully");

    //create pool
    pool = njt_create_pool(njt_pagesize, njt_cycle->log);
    if(pool == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "mqtt client pool malloc error");

        goto failed;
    }

    mqttdt->mqtt_conn = njt_pcalloc(pool, sizeof(struct mqtt_client));
    if(mqttdt->mqtt_conn == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "mqtt client malloc error");

        goto failed;
    }

    mqttdt->mqtt_conn->pool = pool;

    if(MQTT_OK != mqtt_init(mqttdt->mqtt_conn, c->fd, 
        mqttscf->send_buffer_size, mqttscf->recv_buffer_size, 
        mqttscf->ping_time, njt_http_mqtt_publish_callback)){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                      "mqtt init error");

        goto failed;
    }

    /* Send connection request to the broker. */
    if(mqttdt->user.len > 0){
        if(MQTT_OK != mqtt_connect(mqttdt->mqtt_conn, client_id,
                NULL, NULL, 0, (char *)mqttdt->user.data,
                (char *)mqttdt->password.data, connect_flags, 400)){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "mqtt connect error");

            goto failed;
        }
    
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                      "=========mqtt connect user user:%V password:%V", &mqttdt->user, &mqttdt->password);
    }else{
        if(MQTT_OK != mqtt_connect(mqttdt->mqtt_conn, client_id,
                NULL, NULL, 0, NULL, NULL, connect_flags, 400)){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                        "mqtt connect error");

            goto failed;
        }

        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                      "=========mqtt connect no user");
    }  

    //config ping timer, but start ping when idle
    mqttdt->mqtt_conn->ping_timer =  njt_pcalloc(mqttdt->mqtt_conn->pool, sizeof(njt_event_t));
    if(mqttdt->mqtt_conn->ping_timer == NULL){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                      "mqtt pint timer event malloc error");

        goto failed;
    }
    mqttdt->mqtt_conn->ping_timer->handler = njt_http_mqtt_broker_ping_timer_handler;
    mqttdt->mqtt_conn->ping_timer->log = njt_cycle->log;
    mqttdt->mqtt_conn->ping_timer->data = mqttdt->mqtt_conn;
    mqttdt->mqtt_conn->ping_timer->cancelable = 1;

    mqttdt->mqtt_conn->connection = pc->connection;
    mqttdt->mqtt_conn->read_timeout = mqttscf->read_timeout;
    njt_add_timer(mqttdt->mqtt_conn->ping_timer, mqttscf->ping_time);

    //set current request
    mqttdt->mqtt_conn->cur_r = mqttdt->request;

    c->log->action = "sending publish to mqtt database";
    mqttdt->state = state_mqtt_publish;

    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"returning njt_http_mqtt_upstream_connect");
    return njt_http_mqtt_upstream_publish(r, c, mqttdt);

failed:
    mqtt_exit(mqttdt->mqtt_conn);
    njt_close_connection(c);
    pc->connection = NULL;

    njt_log_error(NJT_LOG_INFO, c->log, 0, "mqtt connected %V failed", pc->name);
    return NJT_ERROR;
}

njt_int_t njt_http_mqtt_publish_msg(njt_http_request_t *r){
    njt_http_mqtt_upstream_peer_data_t  *mqttdt;
    // njt_connection_t                    *mqttxc;
    njt_http_mqtt_loc_conf_t            *mqttlcf;
    njt_http_mqtt_upstream_srv_conf_t   *mqttscf;
    njt_http_upstream_t                 *u;
    int                                  nbufs;
    u_char                              *msg;
    njt_str_t                            tmp_msg;
    // u_char                              *err_msg;
    // size_t                              len, err_msg_size;
    size_t                              len;
    // njt_buf_t                           *buf;
    // njt_chain_t                         out;
    njt_chain_t                         *cl, *in;
    njt_http_request_body_t             *body;


    mqttlcf = njt_http_get_module_loc_conf(r, njt_http_mqtt_module);
    u = r->upstream;
    mqttdt = u->peer.data;
    mqttscf = mqttdt->srv_conf;

    // err_msg = NULL;
    // err_msg_size = 0;

    /* get body */
    body = r->request_body;
    if (body == NULL || body->bufs == NULL) {
        // err_msg = (u_char *)MQTT_ERR_NO_DATA;
        // err_msg_size = sizeof(MQTT_ERR_NO_DATA);
        // r->headers_out.status = NJT_HTTP_OK;
        return NJT_HTTP_NO_CONTENT;
    }

    /* calc len and bufs */
    len = 0;
    nbufs = 0;
    in = body->bufs;
    for (cl = in; cl != NULL; cl = cl->next) {
        nbufs++;
        len += (size_t)(cl->buf->last - cl->buf->pos);
    }

    /* get msg */
    if (nbufs == 0) {
        // err_msg = (u_char *)MQTT_ERR_NO_DATA;
        // err_msg_size = sizeof(MQTT_ERR_NO_DATA);
        // r->headers_out.status = NJT_HTTP_OK;
        return NJT_HTTP_NO_CONTENT;
    }

    if (nbufs == 1 && njt_buf_in_memory(in->buf)) {

        msg = in->buf->pos;

    } else {
        if ((msg = njt_pnalloc(r->pool, len)) == NULL) {
            // njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        for (cl = in; cl != NULL; cl = cl->next) {
            if (njt_buf_in_memory(cl->buf)) {
                msg = njt_copy(msg, cl->buf->pos, cl->buf->last - cl->buf->pos);
            } else {
                /* TODO: handle buf in file */
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                        "njt_http_mqtt_handler cannot handle in-file-post-buf");

                // err_msg = (u_char *)MQTT_ERR_BODY_TO_LARGE;
                // err_msg_size = sizeof(MQTT_ERR_BODY_TO_LARGE);
                // r->headers_out.status = NJT_HTTP_INTERNAL_SERVER_ERROR;

                // goto end;
                return NJT_HTTP_REQUEST_ENTITY_TOO_LARGE;
            }
        }
        msg -= len;

    }

    tmp_msg.data = msg;
    tmp_msg.len = len;

    if(MQTT_OK != mqtt_publish(mqttdt->mqtt_conn, (char *)mqttlcf->topic.data, 
            msg, len, MQTT_PUBLISH_QOS_0)){

        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "mqtt publish msg publish error, topic:%V msg:%V", &mqttlcf->topic, &tmp_msg);

        // err_msg = (u_char *)MQTT_ERR_PUBLISH;
        // err_msg_size = sizeof(MQTT_ERR_PUBLISH);
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }


    if(MQTT_OK != (enum MQTTErrors)__mqtt_send(mqttdt->mqtt_conn)){
        //close connection

        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "mqtt publish msg send error, topic:%V msg:%V", &mqttlcf->topic, &tmp_msg);
        // client->status
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    // /* set result timeout */
    // mqttxc = u->peer.connection;
    njt_add_timer(u->peer.connection->read, mqttscf->read_timeout);

        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "mqtt publish msg ok, topic:%V msg:%V", &mqttlcf->topic, &tmp_msg);

    return NJT_OK;
}


njt_int_t
njt_http_mqtt_upstream_publish(njt_http_request_t *r, njt_connection_t *mqttxc,
    njt_http_mqtt_upstream_peer_data_t *mqttdt)
{
    // njt_http_mqtt_loc_conf_t  *mqttlcf;
    njt_int_t               rc;

    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"entering njt_http_mqtt_upstream_publish");

    // mqttlcf = njt_http_get_module_loc_conf(r, njt_http_mqtt_module);

    r->upstream->headers_in.status_n = NJT_HTTP_OK;

    //publish msg
    if(r->upstream->request_sent != 1){
        r->upstream->request_sent = 1;
        //send data to mqtt
        rc = njt_http_mqtt_publish_msg(r);
        if(NJT_OK != rc){
            
            njt_http_mqtt_upstream_finalize_request(r, r->upstream, rc);

            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"publish msg error");
            return NJT_ERROR;
        }
    }

    //just finalize
    // njt_http_mqtt_upstream_finalize_request(r, r->upstream, NJT_OK);

    // /* set result timeout */
    njt_add_timer(mqttxc->read, r->upstream->conf->read_timeout);

    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"publish successfully");

    mqttxc->log->action = "waiting for result from mqtt database";
    mqttdt->state = state_mqtt_get_result;

    return NJT_DONE;
}


njt_int_t
njt_http_mqtt_upstream_get_result(njt_http_request_t *r, njt_connection_t *mqttxc,
    njt_http_mqtt_upstream_peer_data_t *mqttdt)
{
    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"entering njt_http_mqtt_upstream_get_result");

    if(MQTT_OK != __mqtt_recv(mqttdt->mqtt_conn)){
        njt_log_error(NJT_LOG_ERR, mqttxc->log, 0,
                      "mqtt sync error:%d",mqttdt->mqtt_conn->error); 

        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    mqttxc->log->action = "being idle on mqtt database";
    mqttdt->state = state_mqtt_idle;

    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"returning njt_http_mqtt_upstream_get_result");

    return njt_http_mqtt_upstream_done(r, r->upstream, mqttdt);
}

njt_int_t
njt_http_mqtt_upstream_done(njt_http_request_t *r, njt_http_upstream_t *u,
    njt_http_mqtt_upstream_peer_data_t *mqttdt)
{
    njt_http_mqtt_ctx_t  *mqttctx;

    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"entering njt_http_mqtt_upstream_done");

    mqttctx = njt_http_get_module_ctx(r, njt_http_mqtt_module);
    if (mqttctx->status >= NJT_HTTP_SPECIAL_RESPONSE) {
        njt_http_mqtt_upstream_finalize_request(r, u, mqttctx->status);
    } else {

        njt_http_mqtt_upstream_finalize_request(r, u, NJT_OK);
    }

    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,"returning NJT_DONE njt_http_mqtt_upstream_done");
    return NJT_DONE;
}
