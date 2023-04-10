/*
Copyright (c) 2019-2020 Roger Light <roger@atchoo.org>
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

int iot_send__auth(struct mosq_iot *context, uint8_t reason_code, const void *auth_data, uint16_t auth_data_len)
{
	struct mosquitto__packet *packet = NULL;
	int rc;
	mosquitto_property *properties = NULL;
	uint32_t remaining_length;

	if (context->auth_method == NULL)
		return MOSQ_ERR_INVAL;
	if (context->protocol != mosq_p_mqtt5)
		return MOSQ_ERR_PROTOCOL;

	iot_log__printf(NULL, MOSQ_LOG_DEBUG, "Sending AUTH to %s (rc%d, %s)", context->id, reason_code, context->auth_method);

	remaining_length = 1;

	rc = mosquitto_property_add_string(&properties, MQTT_PROP_AUTHENTICATION_METHOD, context->auth_method);
	if (rc)
	{
		mosquitto_property_free_all(&properties);
		return rc;
	}

	if (auth_data != NULL && auth_data_len > 0)
	{
		rc = mosquitto_property_add_binary(&properties, MQTT_PROP_AUTHENTICATION_DATA, auth_data, auth_data_len);
		if (rc)
		{
			mosquitto_property_free_all(&properties);
			return rc;
		}
	}

	remaining_length += property__get_remaining_length(properties);

	if (iot_packet__check_oversize(context, remaining_length))
	{
		mosquitto_property_free_all(&properties);
		mosquitto__free(packet);
		return MOSQ_ERR_OVERSIZE_PACKET;
	}

	packet = mosquitto__calloc(1, sizeof(struct mosquitto__packet));
	if (!packet)
		return MOSQ_ERR_NOMEM;

	packet->command = CMD_AUTH;
	packet->remaining_length = remaining_length;

	rc = packet__alloc(packet);
	if (rc)
	{
		mosquitto_property_free_all(&properties);
		mosquitto__free(packet);
		return rc;
	}
	packet__write_byte(packet, reason_code);
	property__write_all(packet, properties, true);
	mosquitto_property_free_all(&properties);

	return iot_packet__queue(context, packet);
}
