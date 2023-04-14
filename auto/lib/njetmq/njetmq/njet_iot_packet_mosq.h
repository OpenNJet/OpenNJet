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
#ifndef BROKER_PACKET_MOSQ_H
#define BROKER_PACKET_MOSQ_H

#include "mosquitto_internal.h"
#include "mosquitto.h"
#include "packet_mosq.h"

void iot_packet__cleanup_all(struct mosq_iot *mosq);
void iot_packet__cleanup_all_no_locks(struct mosq_iot *mosq);

int iot_packet__queue(struct mosq_iot *mosq, struct mosquitto__packet *packet);

int iot_packet__check_oversize(struct mosq_iot *mosq, uint32_t remaining_length);

int iot_packet__write(struct mosq_iot *mosq);
int iot_packet__read(struct mosq_iot *mosq);

#endif
