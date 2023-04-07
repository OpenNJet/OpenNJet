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
#include "logging_mosq.h"
#include "memory_mosq.h"
#include "messages_mosq.h"
#include "mqtt_protocol.h"
#include "njet_iot_net_mosq.h"
#include "njet_iot_packet_mosq.h"
#include "property_mosq.h"
#include "njet_iot_read_handle.h"
#include "njet_iot_send_mosq.h"
#include "njet_iot_util_mosq.h"

int iot_handle__unsuback(struct mosq_iot *mosq)
{
	uint16_t mid;
	int rc;
	mosquitto_property *properties = NULL;

	assert(mosq);

	if (iot_mqtt__get_state(mosq) != mosq_cs_active)
	{
		return MOSQ_ERR_PROTOCOL;
	}

#ifdef WITH_BROKER
	iot_log__printf(NULL, MOSQ_LOG_DEBUG, "Received UNSUBACK from %s", mosq->id);
#else
	iot_log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s received UNSUBACK", mosq->id);
#endif
	rc = packet__read_uint16(&mosq->in_packet, &mid);
	if (rc)
		return rc;
	if (mid == 0)
		return MOSQ_ERR_PROTOCOL;

	if (mosq->protocol == mosq_p_mqtt5)
	{
		rc = property__read_all(CMD_UNSUBACK, &mosq->in_packet, &properties);
		if (rc)
			return rc;
	}

#ifdef WITH_BROKER
	/* Immediately free, we don't do anything with Reason String or User Property at the moment */
	mosquitto_property_free_all(&properties);
#else
	pthread_mutex_lock(&mosq->callback_mutex);
	if (mosq->on_unsubscribe)
	{
		mosq->in_callback = true;
		mosq->on_unsubscribe(mosq, mosq->userdata, mid);
		mosq->in_callback = false;
	}
	if (mosq->on_unsubscribe_v5)
	{
		mosq->in_callback = true;
		mosq->on_unsubscribe_v5(mosq, mosq->userdata, mid, properties);
		mosq->in_callback = false;
	}
	pthread_mutex_unlock(&mosq->callback_mutex);
	mosquitto_property_free_all(&properties);
#endif

	return MOSQ_ERR_SUCCESS;
}
