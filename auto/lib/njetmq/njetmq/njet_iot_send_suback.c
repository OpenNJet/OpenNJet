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

#include "njet_iot_internal.h"
#include "mqtt_protocol.h"
#include "memory_mosq.h"
#include "njet_iot_packet_mosq.h"
#include "property_mosq.h"
#include "njet_iot_util_mosq.h"

int iot_send__suback(struct mosq_iot *context, uint16_t mid, uint32_t payloadlen, const void *payload)
{
	struct mosquitto__packet *packet = NULL;
	int rc;
	mosquitto_property *properties = NULL;

	iot_log__printf(NULL, MOSQ_LOG_DEBUG, "Sending SUBACK to %s", context->id);

	packet = mosquitto__calloc(1, sizeof(struct mosquitto__packet));
	if (!packet)
		return MOSQ_ERR_NOMEM;

	packet->command = CMD_SUBACK;
	packet->remaining_length = 2 + payloadlen;
	if (context->protocol == mosq_p_mqtt5)
	{
		packet->remaining_length += property__get_remaining_length(properties);
	}
	rc = packet__alloc(packet);
	if (rc)
	{
		mosquitto__free(packet);
		return rc;
	}
	packet__write_uint16(packet, mid);

	if (context->protocol == mosq_p_mqtt5)
	{
		/* We don't use Reason String or User Property yet. */
		property__write_all(packet, properties, true);
	}

	if (payloadlen)
	{
		packet__write_bytes(packet, payload, payloadlen);
	}

	return iot_packet__queue(context, packet);
}
