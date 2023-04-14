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
#ifndef BROKER_NET_MOSQ_H
#define BROKER_NET_MOSQ_H

#include "njet_iot_internal.h"

#include "net_mosq.h"

int iot_net__socket_connect(struct mosq_iot *mosq, const char *host, uint16_t port, const char *bind_address, bool blocking);
int iot_net__socket_close(struct mosq_iot *mosq);
int iot_net__try_connect_step1(struct mosq_iot *mosq, const char *host);
int iot_net__try_connect_step2(struct mosq_iot *mosq, uint16_t port, mosq_sock_t *sock);
int iot_net__socket_connect_step3(struct mosq_iot *mosq, const char *host);

ssize_t iot_net__read(struct mosq_iot *mosq, void *buf, size_t count);
ssize_t iot_net__write(struct mosq_iot *mosq, const void *buf, size_t count);

#ifdef WITH_TLS
void iot_net__print_ssl_error(struct mosq_iot *mosq);
int iot_net__socket_apply_tls(struct mosq_iot *mosq);
int iot_net__socket_connect_tls(struct mosq_iot *mosq);
int iot_mqtt__verify_ocsp_status_cb(SSL *ssl, void *arg);
#endif

#endif
