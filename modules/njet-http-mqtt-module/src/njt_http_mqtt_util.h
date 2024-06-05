/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */

#ifndef _NJT_MQTT_UTIL_H_
#define _NJT_MQTT_UTIL_H_

#include <njt_core.h>
#include <njt_http.h>



void       njt_http_mqtt_upstream_finalize_request(njt_http_request_t *,
               njt_http_upstream_t *, njt_int_t);
void       njt_http_mqtt_upstream_next(njt_http_request_t *,
               njt_http_upstream_t *, njt_int_t);
njt_int_t  njt_http_mqtt_upstream_test_connect(njt_connection_t *);
int njt_http_mqtt_open_nb_socket(njt_peer_connection_t *pc);

#endif /* _NJT_MQTT_UTIL_H_ */
