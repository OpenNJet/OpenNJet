/*
Copyright (c) 2010-2020 Roger Light <roger@atchoo.org>
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
#ifndef BROKER_READ_HANDLE_H
#define BROKER_READ_HANDLE_H

#include "mosquitto.h"
struct mosquitto_db;

int iot_handle__pingreq(struct mosq_iot *mosq);
int iot_handle__pingresp(struct mosq_iot *mosq);
int iot_handle__packet(struct mosq_iot *mosq);
int iot_handle__connack(struct mosq_iot *mosq);
int iot_handle__disconnect(struct mosq_iot *mosq);
int iot_handle__pubackcomp(struct mosq_iot *mosq, const char *type);
int iot_handle__publish(struct mosq_iot *mosq);
int iot_handle__auth(struct mosq_iot *mosq);
int iot_handle__pubrec(struct mosq_iot *mosq);
int iot_handle__pubrel(struct mosq_iot *mosq);
int iot_handle__suback(struct mosq_iot *mosq);
int iot_handle__unsuback(struct mosq_iot *mosq);

#endif
