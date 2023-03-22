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
#ifndef BROKER_UTIL_MOSQ_H
#define BROKER_UTIL_MOSQ_H

#include <stdio.h>

#include "tls_mosq.h"
#include "mosquitto.h"
#include "njet_iot_internal.h"
#include "util_mosq.h"

int iot_mqtt__check_keepalive(struct mosq_iot *mosq);
uint16_t iot_mqtt__mid_generate(struct mosq_iot *mosq);

int iot_mqtt__set_state(struct mosq_iot *mosq, enum mosquitto_client_state state);
enum mosquitto_client_state iot_mqtt__get_state(struct mosq_iot *mosq);

void iot_util__increment_receive_quota(struct mosq_iot *mosq);
void iot_util__increment_send_quota(struct mosq_iot *mosq);
void iot_util__decrement_receive_quota(struct mosq_iot *mosq);
void iot_util__decrement_send_quota(struct mosq_iot *mosq);

#endif
