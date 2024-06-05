/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */

#ifndef _NJT_MQTT_HANDLER_H_
#define _NJT_MQTT_HANDLER_H_

#include <njt_core.h>
#include <njt_http.h>


njt_int_t  njt_http_mqtt_handler(njt_http_request_t *);
void       njt_http_mqtt_wev_handler(njt_http_request_t *,
               njt_http_upstream_t *);
void       njt_http_mqtt_rev_handler(njt_http_request_t *,
               njt_http_upstream_t *);
njt_int_t  njt_http_mqtt_create_request(njt_http_request_t *);
njt_int_t  njt_http_mqtt_reinit_request(njt_http_request_t *);
void       njt_http_mqtt_abort_request(njt_http_request_t *);
void       njt_http_mqtt_finalize_request(njt_http_request_t *, njt_int_t);
njt_int_t  njt_http_mqtt_process_header(njt_http_request_t *);
njt_int_t  njt_http_mqtt_input_filter_init(void *);
njt_int_t  njt_http_mqtt_input_filter(void *, ssize_t);

#endif /* _NJT_MQTT_HANDLER_H_ */
