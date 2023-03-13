/*
Copyright (c) 2009-2020 Roger Light <roger@atchoo.org>
Copyright (C) TMLake, Inc.

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
#include "njet_iot_internal.h"

#include "mosquitto.h"
#include "logging_mosq.h"
#include "memory_mosq.h"
#include "messages_mosq.h"
#include "mqtt_protocol.h"
#include "njet_iot_net_mosq.h"
#include "njet_iot_packet_mosq.h"
#include "njet_iot_read_handle.h"
#include "njet_iot_send_mosq.h"
#include "njet_iot_util_mosq.h"

int iot_handle__pubrec(struct mosq_iot *mosq)
{
	uint8_t reason_code = 0;
	uint16_t mid;
	int rc;
	mosquitto_property *properties = NULL;

	assert(mosq);

	if (iot_mqtt__get_state(mosq) != mosq_cs_active)
	{
		return MOSQ_ERR_PROTOCOL;
	}

	rc = packet__read_uint16(&mosq->in_packet, &mid);
	if (rc)
		return rc;
	if (mid == 0)
		return MOSQ_ERR_PROTOCOL;

	if (mosq->protocol == mosq_p_mqtt5 && mosq->in_packet.remaining_length > 2)
	{
		rc = packet__read_byte(&mosq->in_packet, &reason_code);
		if (rc)
			return rc;

		if (mosq->in_packet.remaining_length > 3)
		{
			rc = property__read_all(CMD_PUBREC, &mosq->in_packet, &properties);
			if (rc)
				return rc;
			/* Immediately free, we don't do anything with Reason String or User Property at the moment */
			mosquitto_property_free_all(&properties);
		}
	}

#ifdef WITH_BROKER
	iot_log__printf(NULL, MOSQ_LOG_DEBUG, "Received PUBREC from %s (Mid: %d)", mosq->id, mid);

	if (reason_code < 0x80)
	{
		rc = db__message_update_outgoing(mosq, mid, mosq_ms_wait_for_pubcomp, 2);
	}
	else
	{
		return db__message_delete_outgoing(mosq, mid, mosq_ms_wait_for_pubrec, 2);
	}
#else

	iot_log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s received PUBREC (Mid: %d)", mosq->id, mid);

	if (reason_code < 0x80 || mosq->protocol != mosq_p_mqtt5)
	{
		rc = iot_message__out_update(mosq, mid, mosq_ms_wait_for_pubcomp, 2);
	}
	else
	{
		if (!iot_message__delete(mosq, mid, mosq_md_out, 2))
		{
			/* Only inform the client the message has been sent once. */
			pthread_mutex_lock(&mosq->callback_mutex);
			if (mosq->on_publish_v5)
			{
				mosq->in_callback = true;
				mosq->on_publish_v5(mosq, mosq->userdata, mid, reason_code, properties);
				mosq->in_callback = false;
			}
			pthread_mutex_unlock(&mosq->callback_mutex);
		}
		iot_util__increment_send_quota(mosq);
		pthread_mutex_lock(&mosq->msgs_out.mutex);
		iot_message__release_to_inflight(mosq, mosq_md_out);
		pthread_mutex_unlock(&mosq->msgs_out.mutex);
		return MOSQ_ERR_SUCCESS;
	}
#endif
	if (rc == MOSQ_ERR_NOT_FOUND)
	{
		iot_log__printf(mosq, MOSQ_LOG_WARNING, "Warning: Received PUBREC from %s for an unknown packet identifier %d.", mosq->id, mid);
	}
	else if (rc != MOSQ_ERR_SUCCESS)
	{
		return rc;
	}
	rc = iot_send__pubrel(mosq, mid, NULL);
	if (rc)
		return rc;

	return MOSQ_ERR_SUCCESS;
}
