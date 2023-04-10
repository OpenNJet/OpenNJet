/*
Copyright (c) 2009-2019 Roger Light <roger@atchoo.org>
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
   Tatsuzo Osawa - Add epoll.
*/

#include "njet_iot_mux.h"

int iot_mux__add_out(struct mosq_iot *context)
{
   return iot_mux_epoll__add_out(context);
}

int iot_mux__remove_out(struct mosq_iot *context)
{
   return iot_mux_epoll__remove_out(context);
}

int iot_mux__add_in(struct mosq_iot *context)
{
   return iot_mux_epoll__add_in(context);
}

int iot_mux__delete(struct mosq_iot *context)
{
   return iot_mux_epoll__delete(context);
}

int iot_mux__init(struct mosquitto__listener_sock *listensock, int listensock_count)
{
   return iot_mux_epoll__init(listensock, listensock_count);
}
int iot_mux__cleanup(void)
{
   return iot_mux_epoll__cleanup();
}
int iot_mux__handle(struct mosquitto__listener_sock *listensock, int listensock_count)
{
   UNUSED(listensock);
   UNUSED(listensock_count);
   return iot_mux_epoll__handle();
}
