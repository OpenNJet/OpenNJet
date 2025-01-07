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

#ifndef _NJT_HTTP_MQTT_PROCESSOR_H_
#define _NJT_HTTP_MQTT_PROCESSOR_H_

#include <njt_core.h>
#include <njt_http.h>


#include "njt_http_mqtt_upstream.h"


void       njt_http_mqtt_process_events(njt_http_request_t *);
njt_int_t  njt_http_mqtt_upstream_connect(njt_http_request_t *,
               njt_connection_t *, njt_http_mqtt_upstream_peer_data_t *);
njt_int_t  njt_http_mqtt_upstream_publish(njt_http_request_t *,
               njt_connection_t *, njt_http_mqtt_upstream_peer_data_t *);
njt_int_t  njt_http_mqtt_upstream_get_result(njt_http_request_t *,
               njt_connection_t *, njt_http_mqtt_upstream_peer_data_t *);
// njt_int_t  njt_http_mqtt_process_response(njt_http_request_t *, PGresult *);
njt_int_t  njt_http_mqtt_upstream_get_ack(njt_http_request_t *,
               njt_connection_t *, njt_http_mqtt_upstream_peer_data_t *);
njt_int_t  njt_http_mqtt_upstream_done(njt_http_request_t *,
               njt_http_upstream_t *, njt_http_mqtt_upstream_peer_data_t *);
njt_int_t
njt_http_mqtt_upstream_internal_publish(njt_http_request_t *r, njt_connection_t *mqttxc,
    njt_http_mqtt_upstream_peer_data_t *mqttdt);

#endif /* _NJT_HTTP_MQTT_PROCESSOR_H_ */
