/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */

#ifndef _NJT_MQTT_KEEPALIVE_H_
#define _NJT_MQTT_KEEPALIVE_H_

#include <njt_core.h>
#include <njt_http.h>
#include "njt_http_mqtt_module.h"
#include "njt_http_mqtt_upstream.h"


typedef struct {
    njt_queue_t                         queue;
    njt_http_mqtt_upstream_srv_conf_t   *srv_conf;
    njt_connection_t                    *connection;
    struct mqtt_client                  *mqtt_conn;
    struct sockaddr                     sockaddr;
    socklen_t                           socklen;
    njt_str_t                           name;
} njt_http_mqtt_keepalive_cache_t;


njt_int_t   njt_http_mqtt_keepalive_init(njt_pool_t *,
                njt_http_mqtt_upstream_srv_conf_t *);
njt_int_t   njt_http_mqtt_keepalive_get_peer_single(njt_peer_connection_t *,
                njt_http_mqtt_upstream_peer_data_t *,
                njt_http_mqtt_upstream_srv_conf_t *);
njt_int_t   njt_http_mqtt_keepalive_get_peer_multi(njt_peer_connection_t *,
                njt_http_mqtt_upstream_peer_data_t *,
                njt_http_mqtt_upstream_srv_conf_t *);
void        njt_http_mqtt_keepalive_free_peer(njt_peer_connection_t *,
                njt_http_mqtt_upstream_peer_data_t *,
                njt_http_mqtt_upstream_srv_conf_t *, njt_uint_t);
void        njt_http_mqtt_keepalive_dummy_handler(njt_event_t *);
void        njt_http_mqtt_keepalive_default_read_handler(njt_event_t *);
void        njt_http_mqtt_keepalive_cleanup(void *);

#endif /* _NJT_MQTT_KEEPALIVE_H_ */
