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
#include <errno.h>
#include <string.h>

#define WITH_BROKER

#ifdef WITH_BROKER
#include "njet_iot_internal.h"
#else
#include "read_handle.h"
#endif

#include "memory_mosq.h"
#include "mqtt_protocol.h"
#include "njet_iot_net_mosq.h"
#include "njet_iot_packet_mosq.h"
#include "njet_iot_read_handle.h"
#include "njet_iot_util_mosq.h"
#ifdef WITH_BROKER
#include "sys_tree.h"
#include "njet_iot_send_mosq.h"
#else
#define G_BYTES_RECEIVED_INC(A)
#define G_BYTES_SENT_INC(A)
#define G_MSGS_SENT_INC(A)
#define G_PUB_MSGS_SENT_INC(A)
#endif

void iot_packet__cleanup_all_no_locks(struct mosq_iot *mosq)
{
	struct mosquitto__packet *packet;

	/* Out packet cleanup */
	if (mosq->out_packet && !mosq->current_out_packet)
	{
		mosq->current_out_packet = mosq->out_packet;
		mosq->out_packet = mosq->out_packet->next;
	}
	while (mosq->current_out_packet)
	{
		packet = mosq->current_out_packet;
		/* Free data and reset values */
		mosq->current_out_packet = mosq->out_packet;
		if (mosq->out_packet)
		{
			mosq->out_packet = mosq->out_packet->next;
		}

		packet__cleanup(packet);
		mosquitto__free(packet);
	}
	mosq->out_packet_count = 0;

	packet__cleanup(&mosq->in_packet);
}

void iot_packet__cleanup_all(struct mosq_iot *mosq)
{
	pthread_mutex_lock(&mosq->current_out_packet_mutex);
	pthread_mutex_lock(&mosq->out_packet_mutex);

	iot_packet__cleanup_all_no_locks(mosq);

	pthread_mutex_unlock(&mosq->out_packet_mutex);
	pthread_mutex_unlock(&mosq->current_out_packet_mutex);
}

int iot_packet__queue(struct mosq_iot *mosq, struct mosquitto__packet *packet)
{
#ifndef WITH_BROKER
	char sockpair_data = 0;
#endif
	assert(mosq);
	assert(packet);

	packet->pos = 0;
	packet->to_process = packet->packet_length;

	packet->next = NULL;
	pthread_mutex_lock(&mosq->out_packet_mutex);

#ifdef WITH_BROKER
	if(mosq->out_packet_count >= db.config->max_queued_messages){
		mosquitto__free(packet);
		if(mosq->is_dropping == false){
			mosq->is_dropping = true;
			log__printf(NULL, MOSQ_LOG_NOTICE,
					"Outgoing messages are being dropped for client %s.",
					mosq->id);
		}
		G_MSGS_DROPPED_INC();
		return MOSQ_ERR_SUCCESS;
	}
#endif

	if (mosq->out_packet)
	{
		mosq->out_packet_last->next = packet;
	}
	else
	{
		mosq->out_packet = packet;
	}
	mosq->out_packet_last = packet;
	mosq->out_packet_count++;
	pthread_mutex_unlock(&mosq->out_packet_mutex);
#ifdef WITH_BROKER
#ifdef WITH_WEBSOCKETS
	if (mosq->wsi)
	{
		lws_callback_on_writable(mosq->wsi);
		return MOSQ_ERR_SUCCESS;
	}
	else
	{
		return iot_packet__write(mosq);
	}
#else
	return iot_packet__write(mosq);
#endif
#else

	/* Write a single byte to sockpairW (connected to sockpairR) to break out
	 * of select() if in threaded mode. */
	if (mosq->sockpairW != INVALID_SOCKET)
	{
#ifndef WIN32
		if (write(mosq->sockpairW, &sockpair_data, 1))
		{
		}
#else
		send(mosq->sockpairW, &sockpair_data, 1, 0);
#endif
	}

	if (mosq->in_callback == false && mosq->threaded == mosq_ts_none)
	{
		return iot_packet__write(mosq);
	}
	else
	{
		return MOSQ_ERR_SUCCESS;
	}
#endif
}

int iot_packet__check_oversize(struct mosq_iot *mosq, uint32_t remaining_length)
{
	uint32_t len;

	if (mosq->maximum_packet_size == 0)
		return MOSQ_ERR_SUCCESS;

	len = remaining_length + packet__varint_bytes(remaining_length);
	if (len > mosq->maximum_packet_size)
	{
		return MOSQ_ERR_OVERSIZE_PACKET;
	}
	else
	{
		return MOSQ_ERR_SUCCESS;
	}
}

int iot_packet__write(struct mosq_iot *mosq)
{
	ssize_t write_length;
	struct mosquitto__packet *packet;
	enum mosquitto_client_state state;

	if (!mosq)
		return MOSQ_ERR_INVAL;
	if (mosq->sock == INVALID_SOCKET)
		return MOSQ_ERR_NO_CONN;

	pthread_mutex_lock(&mosq->current_out_packet_mutex);
	pthread_mutex_lock(&mosq->out_packet_mutex);
	if (mosq->out_packet && !mosq->current_out_packet)
	{
		mosq->current_out_packet = mosq->out_packet;
		mosq->out_packet = mosq->out_packet->next;
		if (!mosq->out_packet)
		{
			mosq->out_packet_last = NULL;
		}
		mosq->out_packet_count--;
	}
	pthread_mutex_unlock(&mosq->out_packet_mutex);

#ifdef WITH_BROKER
	if (mosq->current_out_packet)
	{
		iot_mux__add_out(mosq);
	}
#endif

	state = iot_mqtt__get_state(mosq);
#if defined(WITH_TLS) && !defined(WITH_BROKER)
	if (state == mosq_cs_connect_pending || mosq->want_connect)
	{
#else
	if (state == mosq_cs_connect_pending)
	{
#endif
		pthread_mutex_unlock(&mosq->current_out_packet_mutex);
		return MOSQ_ERR_SUCCESS;
	}

	while (mosq->current_out_packet)
	{
		packet = mosq->current_out_packet;

		while (packet->to_process > 0)
		{
			write_length = iot_net__write(mosq, &(packet->payload[packet->pos]), packet->to_process);
			if (write_length > 0)
			{
				G_BYTES_SENT_INC(write_length);
				packet->to_process -= (uint32_t)write_length;
				packet->pos += (uint32_t)write_length;
			}
			else
			{
#ifdef WIN32
				errno = WSAGetLastError();
#endif
				if (errno == EAGAIN || errno == COMPAT_EWOULDBLOCK
#ifdef WIN32
					|| errno == WSAENOTCONN
#endif
				)
				{
					pthread_mutex_unlock(&mosq->current_out_packet_mutex);
					return MOSQ_ERR_SUCCESS;
				}
				else
				{
					pthread_mutex_unlock(&mosq->current_out_packet_mutex);
					switch (errno)
					{
					case COMPAT_ECONNRESET:
						return MOSQ_ERR_CONN_LOST;
					case COMPAT_EINTR:
						return MOSQ_ERR_SUCCESS;
					default:
						return MOSQ_ERR_ERRNO;
					}
				}
			}
		}

		G_MSGS_SENT_INC(1);
		if (((packet->command) & 0xF6) == CMD_PUBLISH)
		{
			G_PUB_MSGS_SENT_INC(1);
#ifndef WITH_BROKER
			pthread_mutex_lock(&mosq->callback_mutex);
			if (mosq->on_publish)
			{
				/* This is a QoS=0 message */
				mosq->in_callback = true;
				mosq->on_publish(mosq, mosq->userdata, packet->mid);
				mosq->in_callback = false;
			}
			if (mosq->on_publish_v5)
			{
				/* This is a QoS=0 message */
				mosq->in_callback = true;
				mosq->on_publish_v5(mosq, mosq->userdata, packet->mid, 0, NULL);
				mosq->in_callback = false;
			}
			pthread_mutex_unlock(&mosq->callback_mutex);
		}
		else if (((packet->command) & 0xF0) == CMD_DISCONNECT)
		{
			do_client_disconnect(mosq, MOSQ_ERR_SUCCESS, NULL);
			packet__cleanup(packet);
			mosquitto__free(packet);
			return MOSQ_ERR_SUCCESS;
#endif
		}
		else if (((packet->command) & 0xF0) == CMD_PUBLISH)
		{
			G_PUB_MSGS_SENT_INC(1);
		}

		/* Free data and reset values */
		pthread_mutex_lock(&mosq->out_packet_mutex);
		mosq->current_out_packet = mosq->out_packet;
		if (mosq->out_packet)
		{
			mosq->out_packet = mosq->out_packet->next;
			if (!mosq->out_packet)
			{
				mosq->out_packet_last = NULL;
			}
			mosq->out_packet_count--;
		}
		pthread_mutex_unlock(&mosq->out_packet_mutex);

		packet__cleanup(packet);
		mosquitto__free(packet);

#ifdef WITH_BROKER
		mosq->next_msg_out = db.now_s + mosq->keepalive;
		if (mosq->current_out_packet == NULL)
		{
			iot_mux__remove_out(mosq);
		}
#else
		pthread_mutex_lock(&mosq->msgtime_mutex);
		mosq->next_msg_out = mosquitto_time() + mosq->keepalive;
		pthread_mutex_unlock(&mosq->msgtime_mutex);
#endif
	}
	pthread_mutex_unlock(&mosq->current_out_packet_mutex);
	return MOSQ_ERR_SUCCESS;
}

int iot_packet__read(struct mosq_iot *mosq)
{
	uint8_t byte;
	ssize_t read_length;
	int rc = 0;
	enum mosquitto_client_state state;

	if (!mosq)
	{
		return MOSQ_ERR_INVAL;
	}
	if (mosq->sock == INVALID_SOCKET)
	{
		return MOSQ_ERR_NO_CONN;
	}

	state = iot_mqtt__get_state(mosq);
	if (state == mosq_cs_connect_pending)
	{
		return MOSQ_ERR_SUCCESS;
	}

	/* This gets called if pselect() indicates that there is network data
	 * available - ie. at least one byte.  What we do depends on what data we
	 * already have.
	 * If we've not got a command, attempt to read one and save it. This should
	 * always work because it's only a single byte.
	 * Then try to read the remaining length. This may fail because it is may
	 * be more than one byte - will need to save data pending next read if it
	 * does fail.
	 * Then try to read the remaining payload, where 'payload' here means the
	 * combined variable header and actual payload. This is the most likely to
	 * fail due to longer length, so save current data and current position.
	 * After all data is read, send to mosquitto__handle_packet() to deal with.
	 * Finally, free the memory and reset everything to starting conditions.
	 */
	if (!mosq->in_packet.command)
	{
		read_length = iot_net__read(mosq, &byte, 1);
		if (read_length == 1)
		{
			mosq->in_packet.command = byte;
#ifdef WITH_BROKER
			G_BYTES_RECEIVED_INC(1);
			/* Clients must send CONNECT as their first command. */
			if (!(mosq->bridge) && state == mosq_cs_connected && (byte & 0xF0) != CMD_CONNECT)
			{
				return MOSQ_ERR_PROTOCOL;
			}
#endif
		}
		else
		{
			if (read_length == 0)
			{
				return MOSQ_ERR_CONN_LOST; /* EOF */
			}
#ifdef WIN32
			errno = WSAGetLastError();
#endif
			if (errno == EAGAIN || errno == COMPAT_EWOULDBLOCK)
			{
				return MOSQ_ERR_SUCCESS;
			}
			else
			{
				switch (errno)
				{
				case COMPAT_ECONNRESET:
					return MOSQ_ERR_CONN_LOST;
				case COMPAT_EINTR:
					return MOSQ_ERR_SUCCESS;
				default:
					return MOSQ_ERR_ERRNO;
				}
			}
		}
	}
	/* remaining_count is the number of bytes that the remaining_length
	 * parameter occupied in this incoming packet. We don't use it here as such
	 * (it is used when allocating an outgoing packet), but we must be able to
	 * determine whether all of the remaining_length parameter has been read.
	 * remaining_count has three states here:
	 *   0 means that we haven't read any remaining_length bytes
	 *   <0 means we have read some remaining_length bytes but haven't finished
	 *   >0 means we have finished reading the remaining_length bytes.
	 */
	if (mosq->in_packet.remaining_count <= 0)
	{
		do
		{
			read_length = iot_net__read(mosq, &byte, 1);
			if (read_length == 1)
			{
				mosq->in_packet.remaining_count--;
				/* Max 4 bytes length for remaining length as defined by protocol.
				 * Anything more likely means a broken/malicious client.
				 */
				if (mosq->in_packet.remaining_count < -4)
				{
					return MOSQ_ERR_PROTOCOL;
				}

				G_BYTES_RECEIVED_INC(1);
				mosq->in_packet.remaining_length += (byte & 127) * mosq->in_packet.remaining_mult;
				mosq->in_packet.remaining_mult *= 128;
			}
			else
			{
				if (read_length == 0)
				{
					return MOSQ_ERR_CONN_LOST; /* EOF */
				}
#ifdef WIN32
				errno = WSAGetLastError();
#endif
				if (errno == EAGAIN || errno == COMPAT_EWOULDBLOCK)
				{
					return MOSQ_ERR_SUCCESS;
				}
				else
				{
					switch (errno)
					{
					case COMPAT_ECONNRESET:
						return MOSQ_ERR_CONN_LOST;
					case COMPAT_EINTR:
						return MOSQ_ERR_SUCCESS;
					default:
						return MOSQ_ERR_ERRNO;
					}
				}
			}
		} while ((byte & 128) != 0);
		/* We have finished reading remaining_length, so make remaining_count
		 * positive. */
		mosq->in_packet.remaining_count = (int8_t)(mosq->in_packet.remaining_count * -1);

#ifdef WITH_BROKER
		if (db.config->max_packet_size > 0 && mosq->in_packet.remaining_length + 1 > db.config->max_packet_size)
		{
			if (mosq->protocol == mosq_p_mqtt5)
			{
				iot_send__disconnect(mosq, MQTT_RC_PACKET_TOO_LARGE, NULL);
			}
			return MOSQ_ERR_OVERSIZE_PACKET;
		}
#else
		// FIXME - client case for incoming message received from broker too large
#endif
		if (mosq->in_packet.remaining_length > 0)
		{
			mosq->in_packet.payload = mosquitto__malloc(mosq->in_packet.remaining_length * sizeof(uint8_t));
			if (!mosq->in_packet.payload)
			{
				return MOSQ_ERR_NOMEM;
			}
			mosq->in_packet.to_process = mosq->in_packet.remaining_length;
		}
	}
	while (mosq->in_packet.to_process > 0)
	{
		read_length = iot_net__read(mosq, &(mosq->in_packet.payload[mosq->in_packet.pos]), mosq->in_packet.to_process);
		if (read_length > 0)
		{
			G_BYTES_RECEIVED_INC(read_length);
			mosq->in_packet.to_process -= (uint32_t)read_length;
			mosq->in_packet.pos += (uint32_t)read_length;
		}
		else
		{
#ifdef WIN32
			errno = WSAGetLastError();
#endif
			if (errno == EAGAIN || errno == COMPAT_EWOULDBLOCK)
			{
				if (mosq->in_packet.to_process > 1000)
				{
					/* Update last_msg_in time if more than 1000 bytes left to
					 * receive. Helps when receiving large messages.
					 * This is an arbitrary limit, but with some consideration.
					 * If a client can't send 1000 bytes in a second it
					 * probably shouldn't be using a 1 second keep alive. */
#ifdef WITH_BROKER
					keepalive__update(mosq);
#else
					pthread_mutex_lock(&mosq->msgtime_mutex);
					mosq->last_msg_in = mosquitto_time();
					pthread_mutex_unlock(&mosq->msgtime_mutex);
#endif
				}
				return MOSQ_ERR_SUCCESS;
			}
			else
			{
				switch (errno)
				{
				case COMPAT_ECONNRESET:
					return MOSQ_ERR_CONN_LOST;
				case COMPAT_EINTR:
					return MOSQ_ERR_SUCCESS;
				default:
					return MOSQ_ERR_ERRNO;
				}
			}
		}
	}

	/* All data for this packet is read. */
	mosq->in_packet.pos = 0;
#ifdef WITH_BROKER
	G_MSGS_RECEIVED_INC(1);
	if (((mosq->in_packet.command) & 0xF5) == CMD_PUBLISH)
	{
		G_PUB_MSGS_RECEIVED_INC(1);
	}
#endif
	rc = iot_handle__packet(mosq);

	/* Free data and reset values */
	packet__cleanup(&mosq->in_packet);

#ifdef WITH_BROKER
	keepalive__update(mosq);
#else
	pthread_mutex_lock(&mosq->msgtime_mutex);
	mosq->last_msg_in = mosquitto_time();
	pthread_mutex_unlock(&mosq->msgtime_mutex);
#endif
	return rc;
}
