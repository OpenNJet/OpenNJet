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

int iot_handle__pubrel(struct mosq_iot *mosq)
{
	uint8_t reason_code;
	uint16_t mid;
#ifndef WITH_BROKER
	struct mosquitto_message_all *message = NULL;
#endif
	int rc;
	mosquitto_property *properties = NULL;

	assert(mosq);

	if (iot_mqtt__get_state(mosq) != mosq_cs_active)
	{
		return MOSQ_ERR_PROTOCOL;
	}

	if (mosq->protocol != mosq_p_mqtt31)
	{
		if ((mosq->in_packet.command & 0x0F) != 0x02)
		{
			return MOSQ_ERR_PROTOCOL;
		}
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
			rc = property__read_all(CMD_PUBREL, &mosq->in_packet, &properties);
			if (rc)
				return rc;
		}
	}

#ifdef WITH_BROKER
	iot_log__printf(NULL, MOSQ_LOG_DEBUG, "Received PUBREL from %s (Mid: %d)", mosq->id, mid);

	/* Immediately free, we don't do anything with Reason String or User Property at the moment */
	mosquitto_property_free_all(&properties);

	rc = db__message_release_incoming(mosq, mid);
	if (rc == MOSQ_ERR_NOT_FOUND)
	{
		/* Message not found. Still send a PUBCOMP anyway because this could be
		 * due to a repeated PUBREL after a client has reconnected. */
	}
	else if (rc != MOSQ_ERR_SUCCESS)
	{
		return rc;
	}

	rc = iot_send__pubcomp(mosq, mid, NULL);
	if (rc)
		return rc;
#else
	iot_log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s received PUBREL (Mid: %d)", mosq->id, mid);

	rc = send__pubcomp(mosq, mid, NULL);
	if (rc)
	{
		message__remove(mosq, mid, mosq_md_in, &message, 2);
		return rc;
	}

	rc = iot_message__remove(mosq, mid, mosq_md_in, &message, 2);
	if (rc == MOSQ_ERR_SUCCESS)
	{
		/* Only pass the message on if we have removed it from the queue - this
		 * prevents multiple callbacks for the same message. */
		pthread_mutex_lock(&mosq->callback_mutex);
		if (mosq->on_message)
		{
			mosq->in_callback = true;
			mosq->on_message(mosq, mosq->userdata, &message->msg);
			mosq->in_callback = false;
		}
		if (mosq->on_message_v5)
		{
			mosq->in_callback = true;
			mosq->on_message_v5(mosq, mosq->userdata, &message->msg, message->properties);
			mosq->in_callback = false;
		}
		pthread_mutex_unlock(&mosq->callback_mutex);
		mosquitto_property_free_all(&properties);
		message__cleanup(&message);
	}
	else if (rc == MOSQ_ERR_NOT_FOUND)
	{
		return MOSQ_ERR_SUCCESS;
	}
	else
	{
		return rc;
	}
#endif

	return MOSQ_ERR_SUCCESS;
}
