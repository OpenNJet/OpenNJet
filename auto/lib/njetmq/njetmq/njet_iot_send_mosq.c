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
#include "sys_tree.h"
#else
#define G_PUB_BYTES_SENT_INC(A)
#endif

#include "mosquitto.h"
#include "mosquitto_internal.h"
#include "mqtt_protocol.h"
#include "memory_mosq.h"
#include "njet_iot_net_mosq.h"
#include "njet_iot_packet_mosq.h"
#include "property_mosq.h"
#include "njet_iot_send_mosq.h"
#include "time_mosq.h"
#include "njet_iot_util_mosq.h"

int iot_send__pingreq(struct mosq_iot *mosq)
{
	int rc;
	assert(mosq);
#ifdef WITH_BROKER
	iot_log__printf(NULL, MOSQ_LOG_DEBUG, "Sending PINGREQ to %s", mosq->id);
#else
	log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s broker_sending PINGREQ", mosq->id);
#endif
	rc = iot_send__simple_command(mosq, CMD_PINGREQ);
	if (rc == MOSQ_ERR_SUCCESS)
	{
		mosq->ping_t = mosquitto_time();
	}
	return rc;
}

int iot_send__pingresp(struct mosq_iot *mosq)
{
#ifdef WITH_BROKER
	iot_log__printf(NULL, MOSQ_LOG_DEBUG, "Sending PINGRESP to %s", mosq->id);
#else
	log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s broker_sending PINGRESP", mosq->id);
#endif
	return iot_send__simple_command(mosq, CMD_PINGRESP);
}

int iot_send__puback(struct mosq_iot *mosq, uint16_t mid, uint8_t reason_code, const mosquitto_property *properties)
{
#ifdef WITH_BROKER
	iot_log__printf(NULL, MOSQ_LOG_DEBUG, "Sending PUBACK to %s (m%d, rc%d)", mosq->id, mid, reason_code);
#else
	log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s broker_sending PUBACK (m%d, rc%d)", mosq->id, mid, reason_code);
#endif
	iot_util__increment_receive_quota(mosq);
	/* We don't use Reason String or User Property yet. */
	return iot_send__command_with_mid(mosq, CMD_PUBACK, mid, false, reason_code, properties);
}

int iot_send__pubcomp(struct mosq_iot *mosq, uint16_t mid, const mosquitto_property *properties)
{
#ifdef WITH_BROKER
	iot_log__printf(NULL, MOSQ_LOG_DEBUG, "Sending PUBCOMP to %s (m%d)", mosq->id, mid);
#else
	log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s broker_sending PUBCOMP (m%d)", mosq->id, mid);
#endif
	iot_util__increment_receive_quota(mosq);
	/* We don't use Reason String or User Property yet. */
	return iot_send__command_with_mid(mosq, CMD_PUBCOMP, mid, false, 0, properties);
}

int iot_send__pubrec(struct mosq_iot *mosq, uint16_t mid, uint8_t reason_code, const mosquitto_property *properties)
{
#ifdef WITH_BROKER
	iot_log__printf(NULL, MOSQ_LOG_DEBUG, "Sending PUBREC to %s (m%d, rc%d)", mosq->id, mid, reason_code);
#else
	log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s broker_sending PUBREC (m%d, rc%d)", mosq->id, mid, reason_code);
#endif
	if (reason_code >= 0x80 && mosq->protocol == mosq_p_mqtt5)
	{
		iot_util__increment_receive_quota(mosq);
	}
	/* We don't use Reason String or User Property yet. */
	return iot_send__command_with_mid(mosq, CMD_PUBREC, mid, false, reason_code, properties);
}

int iot_send__pubrel(struct mosq_iot *mosq, uint16_t mid, const mosquitto_property *properties)
{
#ifdef WITH_BROKER
	iot_log__printf(NULL, MOSQ_LOG_DEBUG, "Sending PUBREL to %s (m%d)", mosq->id, mid);
#else
	log__printf(mosq, MOSQ_LOG_DEBUG, "Client %s broker_sending PUBREL (m%d)", mosq->id, mid);
#endif
	/* We don't use Reason String or User Property yet. */
	return iot_send__command_with_mid(mosq, CMD_PUBREL | 2, mid, false, 0, properties);
}

/* For PUBACK, PUBCOMP, PUBREC, and PUBREL */
int iot_send__command_with_mid(struct mosq_iot *mosq, uint8_t command, uint16_t mid, bool dup, uint8_t reason_code, const mosquitto_property *properties)
{
	struct mosquitto__packet *packet = NULL;
	int rc;

	assert(mosq);
	packet = mosquitto__calloc(1, sizeof(struct mosquitto__packet));
	if (!packet)
		return MOSQ_ERR_NOMEM;

	packet->command = command;
	if (dup)
	{
		packet->command |= 8;
	}
	packet->remaining_length = 2;

	if (mosq->protocol == mosq_p_mqtt5)
	{
		if (reason_code != 0 || properties)
		{
			packet->remaining_length += 1;
		}

		if (properties)
		{
			packet->remaining_length += property__get_remaining_length(properties);
		}
	}

	rc = packet__alloc(packet);
	if (rc)
	{
		mosquitto__free(packet);
		return rc;
	}

	packet__write_uint16(packet, mid);

	if (mosq->protocol == mosq_p_mqtt5)
	{
		if (reason_code != 0 || properties)
		{
			packet__write_byte(packet, reason_code);
		}
		if (properties)
		{
			property__write_all(packet, properties, true);
		}
	}

	return iot_packet__queue(mosq, packet);
}

/* For DISCONNECT, PINGREQ and PINGRESP */
int iot_send__simple_command(struct mosq_iot *mosq, uint8_t command)
{
	struct mosquitto__packet *packet = NULL;
	int rc;

	assert(mosq);
	packet = mosquitto__calloc(1, sizeof(struct mosquitto__packet));
	if (!packet)
		return MOSQ_ERR_NOMEM;

	packet->command = command;
	packet->remaining_length = 0;

	rc = packet__alloc(packet);
	if (rc)
	{
		mosquitto__free(packet);
		return rc;
	}

	return iot_packet__queue(mosq, packet);
}
