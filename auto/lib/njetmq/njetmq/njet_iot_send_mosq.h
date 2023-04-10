/*
Copyright (c) 2010-2020 Roger Light <roger@atchoo.org>
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
#ifndef BROKER_SEND_MOSQ_H
#define BROKER_SEND_MOSQ_H

#include "mosquitto.h"
#include "property_mosq.h"

int iot_send__simple_command(struct mosq_iot *mosq, uint8_t command);
int iot_send__command_with_mid(struct mosq_iot *mosq, uint8_t command, uint16_t mid, bool dup, uint8_t reason_code, const mosquitto_property *properties);
int iot_send__real_publish(struct mosq_iot *mosq, uint16_t mid, const char *topic, uint32_t payloadlen, const void *payload, uint8_t qos, bool retain, bool dup, const mosquitto_property *cmsg_props, const mosquitto_property *store_props, uint32_t expiry_interval);

int iot_send__connect(struct mosq_iot *mosq, uint16_t keepalive, bool clean_session, const mosquitto_property *properties);
int iot_send__disconnect(struct mosq_iot *mosq, uint8_t reason_code, const mosquitto_property *properties);
int iot_send__pingreq(struct mosq_iot *mosq);
int iot_send__pingresp(struct mosq_iot *mosq);
int iot_send__puback(struct mosq_iot *mosq, uint16_t mid, uint8_t reason_code, const mosquitto_property *properties);
int iot_send__pubcomp(struct mosq_iot *mosq, uint16_t mid, const mosquitto_property *properties);
int iot_send__publish(struct mosq_iot *mosq, uint16_t mid, const char *topic, uint32_t payloadlen, const void *payload, uint8_t qos, bool retain, bool dup, const mosquitto_property *cmsg_props, const mosquitto_property *store_props, uint32_t expiry_interval);
int iot_send__pubrec(struct mosq_iot *mosq, uint16_t mid, uint8_t reason_code, const mosquitto_property *properties);
int iot_send__pubrel(struct mosq_iot *mosq, uint16_t mid, const mosquitto_property *properties);
int iot_send__subscribe(struct mosq_iot *mosq, int *mid, int topic_count, char *const *const topic, int topic_qos, const mosquitto_property *properties);
int iot_send__unsubscribe(struct mosq_iot *mosq, int *mid, int topic_count, char *const *const topic, const mosquitto_property *properties);

#endif
