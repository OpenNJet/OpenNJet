/*
Copyright (c) 2009-2020 Roger Light <roger@atchoo.org>
Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.

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

#include "njet_iot_internal.h"
#include "mqtt_protocol.h"
#include "memory_mosq.h"
#include "njet_iot_packet_mosq.h"
#include "property_mosq.h"
#include "njet_iot_util_mosq.h"

int iot_send__connack(struct mosq_iot *context, uint8_t ack, uint8_t reason_code, const mosquitto_property *properties)
{
	struct mosquitto__packet *packet = NULL;
	int rc;
	mosquitto_property *connack_props = NULL;
	uint32_t remaining_length;

	rc = mosquitto_property_copy_all(&connack_props, properties);
	if (rc)
	{
		return rc;
	}

	if (context->id)
	{
		iot_log__printf(NULL, MOSQ_LOG_DEBUG, "Sending CONNACK to %s (%d, %d)", context->id, ack, reason_code);
	}
	else
	{
		iot_log__printf(NULL, MOSQ_LOG_DEBUG, "Sending CONNACK to %s (%d, %d)", context->address, ack, reason_code);
	}

	remaining_length = 2;

	if (context->protocol == mosq_p_mqtt5)
	{
		if (reason_code < 128 && db.config->retain_available == false)
		{
			rc = mosquitto_property_add_byte(&connack_props, MQTT_PROP_RETAIN_AVAILABLE, 0);
			if (rc)
			{
				mosquitto_property_free_all(&connack_props);
				return rc;
			}
		}
		if (reason_code < 128 && db.config->max_packet_size > 0)
		{
			rc = mosquitto_property_add_int32(&connack_props, MQTT_PROP_MAXIMUM_PACKET_SIZE, db.config->max_packet_size);
			if (rc)
			{
				mosquitto_property_free_all(&connack_props);
				return rc;
			}
		}
		if (reason_code < 128 && db.config->max_inflight_messages > 0)
		{
			rc = mosquitto_property_add_int16(&connack_props, MQTT_PROP_RECEIVE_MAXIMUM, db.config->max_inflight_messages);
			if (rc)
			{
				mosquitto_property_free_all(&connack_props);
				return rc;
			}
		}
		if (context->listener->max_qos != 2)
		{
			rc = mosquitto_property_add_byte(&connack_props, MQTT_PROP_MAXIMUM_QOS, context->listener->max_qos);
			if (rc)
			{
				mosquitto_property_free_all(&connack_props);
				return rc;
			}
		}

		remaining_length += property__get_remaining_length(connack_props);
	}

	if (iot_packet__check_oversize(context, remaining_length))
	{
		mosquitto_property_free_all(&connack_props);
		return MOSQ_ERR_OVERSIZE_PACKET;
	}

	packet = mosquitto__calloc(1, sizeof(struct mosquitto__packet));
	if (!packet)
	{
		mosquitto_property_free_all(&connack_props);
		return MOSQ_ERR_NOMEM;
	}

	packet->command = CMD_CONNACK;
	packet->remaining_length = remaining_length;

	rc = packet__alloc(packet);
	if (rc)
	{
		mosquitto_property_free_all(&connack_props);
		mosquitto__free(packet);
		return rc;
	}
	packet__write_byte(packet, ack);
	packet__write_byte(packet, reason_code);
	if (context->protocol == mosq_p_mqtt5)
	{
		property__write_all(packet, connack_props, true);
	}
	mosquitto_property_free_all(&connack_props);

	return iot_packet__queue(context, packet);
}
