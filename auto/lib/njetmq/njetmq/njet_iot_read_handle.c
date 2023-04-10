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

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "njet_iot_internal.h"
#include "mqtt_protocol.h"
#include "memory_mosq.h"
#include "njet_iot_packet_mosq.h"
#include "njet_iot_read_handle.h"
#include "njet_iot_send_mosq.h"
#include "sys_tree.h"
#include "njet_iot_util_mosq.h"

int iot_handle__packet(struct mosq_iot *context)
{
	int rc = MOSQ_ERR_INVAL;

	if (!context)
		return MOSQ_ERR_INVAL;

	switch ((context->in_packet.command) & 0xF0)
	{
	case CMD_PINGREQ:
		return iot_handle__pingreq(context);
	case CMD_PINGRESP:
		return iot_handle__pingresp(context);
	case CMD_PUBACK:
		return iot_handle__pubackcomp(context, "PUBACK");
	case CMD_PUBCOMP:
		return iot_handle__pubackcomp(context, "PUBCOMP");
	case CMD_PUBLISH:
		rc = iot_handle__publish(context);
		break;
	case CMD_PUBREC:
		return iot_handle__pubrec(context);
	case CMD_PUBREL:
		return iot_handle__pubrel(context);
	case CMD_CONNECT:
		return iot_handle__connect(context);
	case CMD_DISCONNECT:
		return iot_handle__disconnect(context);
	case CMD_SUBSCRIBE:
		rc = iot_handle__subscribe(context);
		break;
	case CMD_UNSUBSCRIBE:
		rc = iot_handle__unsubscribe(context);
		break;
#ifdef WITH_BRIDGE
	case CMD_CONNACK:
		return iot_handle__connack(context);
	case CMD_SUBACK:
		return iot_handle__suback(context);
	case CMD_UNSUBACK:
		return iot_handle__unsuback(context);
#endif
	case CMD_AUTH:
		return iot_handle__auth(context);
	default:
		rc = MOSQ_ERR_PROTOCOL;
	}

	if (context->protocol == mosq_p_mqtt5)
	{
		if (rc == MOSQ_ERR_PROTOCOL)
		{
			iot_send__disconnect(context, MQTT_RC_PROTOCOL_ERROR, NULL);
		}
		else if (rc == MOSQ_ERR_MALFORMED_PACKET)
		{
			iot_send__disconnect(context, MQTT_RC_MALFORMED_PACKET, NULL);
		}
		else if (rc == MOSQ_ERR_QOS_NOT_SUPPORTED)
		{
			iot_send__disconnect(context, MQTT_RC_QOS_NOT_SUPPORTED, NULL);
		}
		else if (rc == MOSQ_ERR_RETAIN_NOT_SUPPORTED)
		{
			iot_send__disconnect(context, MQTT_RC_RETAIN_NOT_SUPPORTED, NULL);
		}
		else if (rc == MOSQ_ERR_TOPIC_ALIAS_INVALID)
		{
			iot_send__disconnect(context, MQTT_RC_TOPIC_ALIAS_INVALID, NULL);
		}
		else if (rc == MOSQ_ERR_UNKNOWN || rc == MOSQ_ERR_NOMEM)
		{
			iot_send__disconnect(context, MQTT_RC_UNSPECIFIED, NULL);
		}
	}
	return rc;
}
