/*
Copyright (c) 2009-2020 Roger Light <roger@atchoo.org>
Copyright (C), 2021-2023, TMLake(Beijing) Technology Co., Ltd.

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include "config.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define WITH_BROKER
#ifdef WITH_BROKER
#include "njet_iot_internal.h"
#endif

#include "mosquitto.h"
// #include "logging_mosq.h"
#include "memory_mosq.h"
#include "messages_mosq.h"
#include "mqtt_protocol.h"
#include "njet_iot_net_mosq.h"
#include "njet_iot_packet_mosq.h"
#include "njet_iot_read_handle.h"
#include "njet_iot_send_mosq.h"
#include "njet_iot_util_mosq.h"

int iot_handle__pingreq(struct mosq_iot *mosq)
{
	assert(mosq);

	if (iot_mqtt__get_state(mosq) != mosq_cs_active)
	{
		return MOSQ_ERR_PROTOCOL;
	}

#ifdef WITH_BROKER
	iot_log__printf(NULL, MOSQ_LOG_DEBUG, "Received PINGREQ from %s", mosq->id);
#else
	log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s received PINGREQ", mosq->id);
#endif
	return iot_send__pingresp(mosq);
}

int iot_handle__pingresp(struct mosq_iot *mosq)
{
	assert(mosq);

	if (iot_mqtt__get_state(mosq) != mosq_cs_active)
	{
		return MOSQ_ERR_PROTOCOL;
	}

	mosq->ping_t = 0; /* No longer waiting for a PINGRESP. */
#ifdef WITH_BROKER
	iot_log__printf(NULL, MOSQ_LOG_DEBUG, "Received PINGRESP from %s", mosq->id);
#else
	log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s received PINGRESP", mosq->id);
#endif
	return MOSQ_ERR_SUCCESS;
}
