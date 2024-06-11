/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */


#include "njt_http_mqtt_keepalive.h"


njt_int_t
njt_http_mqtt_keepalive_init(njt_pool_t *pool,
    njt_http_mqtt_upstream_srv_conf_t *mqttscf)
{
    njt_http_mqtt_keepalive_cache_t  *cached;
    njt_uint_t                       i;

    cached = njt_pcalloc(pool,
                 sizeof(njt_http_mqtt_keepalive_cache_t) * mqttscf->max_cached);
    if (cached == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "mqtt malloc cached queue error");
        return NJT_ERROR;
    }

    njt_queue_init(&mqttscf->cache);
    njt_queue_init(&mqttscf->free);

    for (i = 0; i < mqttscf->max_cached; i++) {
        njt_queue_insert_head(&mqttscf->free, &cached[i].queue);
        cached[i].srv_conf = mqttscf;
    }

    return NJT_OK;
}

njt_int_t
njt_http_mqtt_keepalive_get_peer_single(njt_peer_connection_t *pc,
    njt_http_mqtt_upstream_peer_data_t *mqttp,
    njt_http_mqtt_upstream_srv_conf_t *mqttscf)
{
    njt_http_mqtt_keepalive_cache_t  *item;
    njt_queue_t                     *q;
    njt_connection_t                *c;


    if (!njt_queue_empty(&mqttscf->cache)) {
        q = njt_queue_head(&mqttscf->cache);
        njt_queue_remove(q);

        item = njt_queue_data(q, njt_http_mqtt_keepalive_cache_t, queue);
        c = item->connection;

        njt_queue_insert_head(&mqttscf->free, q);

        c->idle = 0;
        c->log = pc->log;
        c->pool->log = pc->log;
        c->read->log = pc->log;
        c->write->log = pc->log;

        mqttp->name.data = item->name.data;
        mqttp->name.len = item->name.len;

        mqttp->sockaddr = item->sockaddr;

        mqttp->mqtt_conn = item->mqtt_conn;

        pc->connection = c;
        pc->cached = 1;

        pc->name = &mqttp->name;

        pc->sockaddr = &mqttp->sockaddr;
        pc->socklen = item->socklen;

        return NJT_DONE;
    }

    return NJT_DECLINED;
}

njt_int_t
njt_http_mqtt_keepalive_get_peer_multi(njt_peer_connection_t *pc,
    njt_http_mqtt_upstream_peer_data_t *mqttp,
    njt_http_mqtt_upstream_srv_conf_t *mqttscf)
{
    njt_http_mqtt_keepalive_cache_t  *item;
    njt_queue_t                     *q, *cache;
    njt_connection_t                *c;

    cache = &mqttscf->cache;

    for (q = njt_queue_head(cache);
         q != njt_queue_sentinel(cache);
         q = njt_queue_next(q))
    {
        item = njt_queue_data(q, njt_http_mqtt_keepalive_cache_t, queue);
        c = item->connection;

        if (njt_memn2cmp((u_char *) &item->sockaddr, (u_char *) pc->sockaddr,
                item->socklen, pc->socklen) == 0)
        {
            njt_queue_remove(q);
            njt_queue_insert_head(&mqttscf->free, q);

            c->idle = 0;
            c->log = pc->log;
            c->pool->log = pc->log;
            c->read->log = pc->log;
            c->write->log = pc->log;

            pc->connection = c;
            pc->cached = 1;

            /* we do not need to resume the peer name
             * because we already take the right value outside */

            mqttp->mqtt_conn = item->mqtt_conn;

            return NJT_DONE;
        }
    }
    return NJT_DECLINED;
}

void
njt_http_mqtt_keepalive_free_peer(njt_peer_connection_t *pc,
    njt_http_mqtt_upstream_peer_data_t *mqttp,
    njt_http_mqtt_upstream_srv_conf_t *mqttscf, njt_uint_t  state)
{
    njt_http_mqtt_keepalive_cache_t  *item;
    njt_queue_t                     *q;
    njt_connection_t                *c;
    njt_http_upstream_t             *u;

    // if (state & NJT_PEER_FAILED) {
    //     mqttp->failed = 1;
    // }

    u = mqttp->upstream;

    if ( (pc->connection != NULL)
        && (u->headers_in.status_n == NJT_HTTP_OK))
    {
        c = pc->connection;

        if (c->read->timer_set) {
            njt_del_timer(c->read);
        }

        if (c->write->timer_set) {
            njt_del_timer(c->write);
        }

        if (c->write->active && (njt_event_flags & NJT_USE_LEVEL_EVENT)) {
            if (njt_del_event(c->write, NJT_WRITE_EVENT, 0) != NJT_OK) {
                return;
            }
        }

        pc->connection = NULL;

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, pc->log, 0,
                       "mqtt: free keepalive peer: saving connection %p",
                       c);

        if (njt_queue_empty(&mqttscf->free)) {
            /* connection pool is already full */

            q = njt_queue_last(&mqttscf->cache);
            njt_queue_remove(q);

            item = njt_queue_data(q, njt_http_mqtt_keepalive_cache_t,
                                  queue);

            njt_http_mqtt_upstream_free_connection(pc->log, item->connection,
                                                  item->mqtt_conn, mqttscf);

        } else {
            q = njt_queue_head(&mqttscf->free);
            njt_queue_remove(q);

            item = njt_queue_data(q, njt_http_mqtt_keepalive_cache_t,
                                  queue);
        }

        item->connection = c;
        njt_queue_insert_head(&mqttscf->cache, q);

        c->write->handler = njt_http_mqtt_keepalive_dummy_handler;
        c->read->handler = njt_http_mqtt_keepalive_default_read_handler;

        c->data = item;
        c->idle = 1;
        c->log = njt_cycle->log;
        c->pool->log = njt_cycle->log;
        c->read->log = njt_cycle->log;
        c->write->log = njt_cycle->log;

        item->socklen = pc->socklen;
        njt_memcpy(&item->sockaddr, pc->sockaddr, pc->socklen);

        item->mqtt_conn = mqttp->mqtt_conn;
        item->mqtt_conn->cur_r = NULL;

        item->name.data = mqttp->name.data;
        item->name.len = mqttp->name.len;

        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, " save connection to cache ");
    }

}

void
njt_http_mqtt_keepalive_dummy_handler(njt_event_t *ev)
{
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "mqtt entering & returning (dummy handler)");
}

void
njt_http_mqtt_keepalive_default_read_handler(njt_event_t *ev)
{
    njt_http_mqtt_upstream_srv_conf_t  *mqttscf;
    njt_http_mqtt_keepalive_cache_t    *item;
    njt_connection_t                  *c;

    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "mqtt entering njt_http_mqtt_keepalive_default_read_handler");
    c = ev->data;
    item = c->data;

    if (c->close) {
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, " mqtt broker connection close");
        goto close;
    }

    if(ev->timedout){
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, " mqtt broker read timeout close");
        goto close;
    }

    if(MQTT_OK != __mqtt_recv(item->mqtt_conn)){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                      "mqtt sync error:%d", item->mqtt_conn->error);
    
        goto close;
    }


    if (ev->timer_set) {
        njt_del_timer(ev);
    }

    return;

close:
    njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "mqtt colse keepalive connection");
    mqttscf = item->srv_conf;

    njt_http_mqtt_upstream_free_connection(ev->log, c, item->mqtt_conn, mqttscf);

    njt_queue_remove(&item->queue);
    njt_queue_insert_head(&mqttscf->free, &item->queue);
}

void
njt_http_mqtt_keepalive_cleanup(void *data)
{
    njt_http_mqtt_upstream_srv_conf_t  *mqttscf = data;
    njt_http_mqtt_keepalive_cache_t    *item;
    njt_queue_t                       *q;

    /* njt_queue_empty is broken when used on unitialized queue */
    if (mqttscf->cache.prev == NULL) {
        return;
    }

    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "mqtt enter njt_http_mqtt_keepalive_cleanup");
    /* just to be on the safe-side */
    mqttscf->max_cached = 0;

    while (!njt_queue_empty(&mqttscf->cache)) {
        q = njt_queue_head(&mqttscf->cache);
        njt_queue_remove(q);

        item = njt_queue_data(q, njt_http_mqtt_keepalive_cache_t,
                              queue);

        njt_http_mqtt_upstream_free_connection(item->connection->log,
                                              item->connection,
                                              item->mqtt_conn, mqttscf);
    }
}
