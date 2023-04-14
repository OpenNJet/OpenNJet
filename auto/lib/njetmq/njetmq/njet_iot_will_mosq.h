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

#ifndef BROKER_WILL_MOSQ_H
#define BROKER_WILL_MOSQ_H

#include "mosquitto.h"
#include "njet_iot_internal.h"

int iot_will__set(struct mosq_iot *mosq, const char *topic, int payloadlen, const void *payload, int qos, bool retain, mosquitto_property *properties);
int iot_will__clear(struct mosq_iot *mosq);

#endif
