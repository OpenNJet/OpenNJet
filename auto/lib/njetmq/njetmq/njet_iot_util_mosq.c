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
#include <ctype.h>
#include <string.h>

#define WITH_BROKER
#ifdef WIN32
#include <winsock2.h>
#include <aclapi.h>
#include <io.h>
#include <lmcons.h>
#else
#include <sys/stat.h>
#endif

#if !defined(WITH_TLS) && defined(__linux__) && defined(__GLIBC__)
#if __GLIBC_PREREQ(2, 25)
#include <sys/random.h>
#define HAVE_GETRANDOM 1
#endif
#endif

#ifdef WITH_TLS
#include <openssl/bn.h>
#include <openssl/rand.h>
#endif

#include "njet_iot_internal.h"

#include "mosquitto.h"
#include "memory_mosq.h"
#include "njet_iot_util_mosq.h"
#include "time_mosq.h"
#include "tls_mosq.h"

#include "njet_iot_net_mosq.h"
#include "njet_iot_send_mosq.h"

int iot_mqtt__check_keepalive(struct mosq_iot *mosq)
{
	time_t next_msg_out;
	time_t last_msg_in;
	time_t now;
#ifndef WITH_BROKER
	int rc;
#endif
	enum mosquitto_client_state state;

	assert(mosq);
#ifdef WITH_BROKER
	now = db.now_s;
#else
	now = mosquitto_time();
#endif

#if defined(WITH_BROKER) && defined(WITH_BRIDGE)
	/* Check if a lazy bridge should be timed out due to idle. */
	if (mosq->bridge && mosq->bridge->start_type == bst_lazy && mosq->sock != INVALID_SOCKET && now - mosq->next_msg_out - mosq->keepalive >= mosq->bridge->idle_timeout)
	{

		iot_log__printf(NULL, MOSQ_LOG_NOTICE, "Bridge connection %s has exceeded idle timeout, disconnecting.", mosq->id);
		iot_net__socket_close(mosq);
		return MOSQ_ERR_SUCCESS;
	}
#endif
	pthread_mutex_lock(&mosq->msgtime_mutex);
	next_msg_out = mosq->next_msg_out;
	last_msg_in = mosq->last_msg_in;
	pthread_mutex_unlock(&mosq->msgtime_mutex);
	if (mosq->keepalive && mosq->sock != INVALID_SOCKET &&
		(now >= next_msg_out || now - last_msg_in >= mosq->keepalive))
	{

		state = iot_mqtt__get_state(mosq);
		if (state == mosq_cs_active && mosq->ping_t == 0)
		{
			iot_send__pingreq(mosq);
			/* Reset last msg times to give the server time to send a pingresp */
			pthread_mutex_lock(&mosq->msgtime_mutex);
			mosq->last_msg_in = now;
			mosq->next_msg_out = now + mosq->keepalive;
			pthread_mutex_unlock(&mosq->msgtime_mutex);
		}
		else
		{
#ifdef WITH_BROKER
			iot_net__socket_close(mosq);
#else
			iot_net__socket_close(mosq);
			state = iot_mqtt__get_state(mosq);
			if (state == mosq_cs_disconnecting)
			{
				rc = MOSQ_ERR_SUCCESS;
			}
			else
			{
				rc = MOSQ_ERR_KEEPALIVE;
			}
			pthread_mutex_lock(&mosq->callback_mutex);
			if (mosq->on_disconnect)
			{
				mosq->in_callback = true;
				mosq->on_disconnect(mosq, mosq->userdata, rc);
				mosq->in_callback = false;
			}
			if (mosq->on_disconnect_v5)
			{
				mosq->in_callback = true;
				mosq->on_disconnect_v5(mosq, mosq->userdata, rc, NULL);
				mosq->in_callback = false;
			}
			pthread_mutex_unlock(&mosq->callback_mutex);

			return rc;
#endif
		}
	}
	return MOSQ_ERR_SUCCESS;
}

uint16_t iot_mqtt__mid_generate(struct mosq_iot *mosq)
{
	/* FIXME - this would be better with atomic increment, but this is safer
	 * for now for a bug fix release.
	 *
	 * If this is changed to use atomic increment, callers of this function
	 * will have to be aware that they may receive a 0 result, which may not be
	 * used as a mid.
	 */
	uint16_t mid;
	assert(mosq);

	pthread_mutex_lock(&mosq->mid_mutex);
	mosq->last_mid++;
	if (mosq->last_mid == 0)
		mosq->last_mid++;
	mid = mosq->last_mid;
	pthread_mutex_unlock(&mosq->mid_mutex);

	return mid;
}

void iot_util__increment_receive_quota(struct mosq_iot *mosq)
{
	if (mosq->msgs_in.inflight_quota < mosq->msgs_in.inflight_maximum)
	{
		mosq->msgs_in.inflight_quota++;
	}
}

void iot_util__increment_send_quota(struct mosq_iot *mosq)
{
	if (mosq->msgs_out.inflight_quota < mosq->msgs_out.inflight_maximum)
	{
		mosq->msgs_out.inflight_quota++;
	}
}

void iot_util__decrement_receive_quota(struct mosq_iot *mosq)
{
	if (mosq->msgs_in.inflight_quota > 0)
	{
		mosq->msgs_in.inflight_quota--;
	}
}

void iot_util__decrement_send_quota(struct mosq_iot *mosq)
{
	if (mosq->msgs_out.inflight_quota > 0)
	{
		mosq->msgs_out.inflight_quota--;
	}
}

int iot_mqtt__set_state(struct mosq_iot *mosq, enum mosquitto_client_state state)
{
	pthread_mutex_lock(&mosq->state_mutex);
#ifdef WITH_BROKER
	if (mosq->state != mosq_cs_disused)
#endif
	{
		mosq->state = state;
	}
	pthread_mutex_unlock(&mosq->state_mutex);

	return MOSQ_ERR_SUCCESS;
}

enum mosquitto_client_state iot_mqtt__get_state(struct mosq_iot *mosq)
{
	enum mosquitto_client_state state;

	pthread_mutex_lock(&mosq->state_mutex);
	state = mosq->state;
	pthread_mutex_unlock(&mosq->state_mutex);

	return state;
}
