/*
Copyright (c) 2020 Roger Light <roger@atchoo.org>
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

#ifndef BROKER_MUX_H
#define BROKER_MUX_H

#include "njet_iot_internal.h"

int iot_mux_epoll__init(struct mosquitto__listener_sock *listensock, int listensock_count);
int iot_mux_epoll__add_out(struct mosq_iot *context);
int iot_mux_epoll__remove_out(struct mosq_iot *context);
int iot_mux_epoll__add_in(struct mosq_iot *context);
int iot_mux_epoll__delete(struct mosq_iot *context);
int iot_mux_epoll__handle(void);
int iot_mux_epoll__cleanup(void);

#endif
