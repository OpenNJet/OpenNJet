/*
Copyright (c) 2019-2020 Roger Light <roger@atchoo.org>
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

#ifndef BROKER_ALIAS_MOSQ_H
#define BROKER_ALIAS_MOSQ_H

#include "mosquitto_internal.h"
#include "njet_iot_internal.h"

int iot_alias__add(struct mosq_iot *mosq, const char *topic, uint16_t alias);
int iot_alias__find(struct mosq_iot *mosq, char **topic, uint16_t alias);
void iot_alias__free_all(struct mosq_iot *mosq);

#endif
