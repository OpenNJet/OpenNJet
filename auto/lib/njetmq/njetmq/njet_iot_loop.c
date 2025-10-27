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
   Tatsuzo Osawa - Add epoll.
*/

#include "config.h"

#ifndef WIN32
#define _GNU_SOURCE
#endif

#include <assert.h>
#ifndef WIN32
#include <unistd.h>
#else
#include <process.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#ifndef WIN32
#include <sys/socket.h>
#endif
#include <time.h>
#include <utlist.h>

#include "njet_iot_internal.h"
#include "memory_mosq.h"
#include "mqtt_protocol.h"
#include "njet_iot_packet_mosq.h"
#include "njet_iot_send_mosq.h"
#include "sys_tree.h"
#include "time_mosq.h"
#include "njet_iot_util_mosq.h"

extern bool flag_reload;
#ifdef WITH_PERSISTENCE
extern bool flag_db_backup;
#endif
extern bool flag_tree_print;
// extern int run;

#if defined(WITH_WEBSOCKETS) && LWS_LIBRARY_VERSION_NUMBER == 3002000
void lws__sul_callback(struct lws_sorted_usec_list *l)
{
}

static struct lws_sorted_usec_list sul;
#endif

static int single_publish(struct mosq_iot *context, struct mosquitto_message_v5 *msg, uint32_t message_expiry)
{
	struct mosquitto_msg_store *stored;
	uint16_t mid;

	stored = mosquitto__calloc(1, sizeof(struct mosquitto_msg_store));
	if (stored == NULL)
		return MOSQ_ERR_NOMEM;

	stored->topic = msg->topic;
	msg->topic = NULL;
	stored->retain = 0;
	stored->payloadlen = (uint32_t)msg->payloadlen;
	stored->payload = mosquitto__malloc(stored->payloadlen + 1);
	if (stored->payload == NULL)
	{
		db__msg_store_free(stored);
		return MOSQ_ERR_NOMEM;
	}
	/* Ensure payload is always zero terminated, this is the reason for the extra byte above */
	((uint8_t *)stored->payload)[stored->payloadlen] = 0;
	memcpy(stored->payload, msg->payload, stored->payloadlen);

	if (msg->properties)
	{
		stored->properties = msg->properties;
		msg->properties = NULL;
	}

	if (db__message_store(context, stored, message_expiry, 0, mosq_mo_broker))
		return 1;

	if (msg->qos)
	{
		mid = iot_mqtt__mid_generate(context);
	}
	else
	{
		mid = 0;
	}
	return db__message_insert(context, mid, mosq_md_out, (uint8_t)msg->qos, 0, stored, msg->properties, true);
}

static void read_message_expiry_interval(mosquitto_property **proplist, uint32_t *message_expiry)
{
	mosquitto_property *p, *previous = NULL;

	*message_expiry = 0;

	if (!proplist)
		return;

	p = *proplist;
	while (p)
	{
		if (p->identifier == MQTT_PROP_MESSAGE_EXPIRY_INTERVAL)
		{
			*message_expiry = p->value.i32;
			if (p == *proplist)
			{
				*proplist = p->next;
			}
			else
			{
				previous->next = p->next;
			}
			property__free(&p);
			return;
		}
		previous = p;
		p = p->next;
	}
}

void queue_plugin_msgs(void)
{
	struct mosquitto_message_v5 *msg, *tmp;
	struct mosq_iot *context;
	uint32_t message_expiry;

	DL_FOREACH_SAFE(db.plugin_msgs, msg, tmp)
	{
		DL_DELETE(db.plugin_msgs, msg);

		read_message_expiry_interval(&msg->properties, &message_expiry);

		if (msg->clientid)
		{
			HASH_FIND(hh_id, db.contexts_by_id, msg->clientid, strlen(msg->clientid), context);
			if (context)
			{
				single_publish(context, msg, message_expiry);
			}
		}
		else
		{
			db__messages_easy_queue(NULL, msg->topic, (uint8_t)msg->qos, (uint32_t)msg->payloadlen, msg->payload, msg->retain, message_expiry, &msg->properties);
		}
		mosquitto__free(msg->topic);
		mosquitto__free(msg->payload);
		mosquitto_property_free_all(&msg->properties);
		mosquitto__free(msg->clientid);
		mosquitto__free(msg);
	}
}

int iot_main_loop(struct mosquitto__listener_sock *listensock, int listensock_count,ext_loop_checker mqtt_checker, void* mqtt_check_data)
{
#ifdef WITH_SYS_TREE
	time_t start_time = mosquitto_time();
#endif
#ifdef WITH_PERSISTENCE
	time_t last_backup = mosquitto_time();
#endif
#ifdef WITH_WEBSOCKETS
	int i;
#endif
	int rc;

	/*
	#if defined(WITH_WEBSOCKETS) && LWS_LIBRARY_VERSION_NUMBER == 3002000
		memset(&sul, 0, sizeof(struct lws_sorted_usec_list));
	#endif

		db.now_s = mosquitto_time();
		db.now_real_s = time(NULL);

		rc = mux__init(listensock, listensock_count);
		if(rc) return rc;

	#ifdef WITH_BRIDGE
		rc = bridge__register_local_connections();
		if(rc) return rc;
	#endif
	*/
	  while(1){  
	retain__expire();
	queue_plugin_msgs();
	context__free_disused();
#ifdef WITH_SYS_TREE
	if (db.config->sys_interval > 0)
	{
		sys_tree__update(db.config->sys_interval, start_time);
	}
#endif

	keepalive__check();

#ifdef WITH_BRIDGE
	bridge_check();
#endif

	rc = iot_mux__handle(listensock, listensock_count);
	if (rc)
		return rc;

	session_expiry__check();
	iot_will_delay__check();
#ifdef WITH_PERSISTENCE
	if (db.config->persistence && db.config->autosave_interval)
	{
		if (db.config->autosave_on_changes)
		{
			if (db.persistence_changes >= db.config->autosave_interval)
			{
				persist__backup(false);
				db.persistence_changes = 0;
			}
		}
		else
		{
			if (last_backup + db.config->autosave_interval < db.now_s)
			{
				persist__backup(false);
				last_backup = db.now_s;
			}
		}
	}
#endif
/* backup should move to nginx loop
#ifdef WITH_PERSISTENCE
		if(flag_db_backup){
			persist__backup(false);
			flag_db_backup = false;
		}

#endif
*/
/* reload move to nginx loop
		if(flag_reload){
			iot_log__printf(NULL, MOSQ_LOG_INFO, "Reloading config.");
			config__read(db.config, true);
			listeners__reload_all_certificates();
			mosquitto_security_cleanup(true);
			mosquitto_security_init(true);
			mosquitto_security_apply();
			log__close(db.config);
			log__init(db.config);
			flag_reload = false;
		}

*/
/* printtree should be called in nginx loop
		if(flag_tree_print){
			sub__tree_print(db.normal_subs, 0);
			sub__tree_print(db.shared_subs, 0);
			flag_tree_print = false;
#ifdef WITH_XTREPORT
			xtreport();
#endif
		}
*/
#ifdef WITH_WEBSOCKETS
	for (i = 0; i < db.config->listener_count; i++)
	{
		/* Extremely hacky, should be using the lws provided external poll
		 * interface, but their interface has changed recently and ours
		 * will soon, so for now websockets clients are second class
		 * citizens. */
		if (db.config->listeners[i].ws_context)
		{
#if LWS_LIBRARY_VERSION_NUMBER > 3002000
			lws_service(db.config->listeners[i].ws_context, -1);
#elif LWS_LIBRARY_VERSION_NUMBER == 3002000
			lws_sul_schedule(db.config->listeners[i].ws_context, 0, &sul, lws__sul_callback, 10);
			lws_service(db.config->listeners[i].ws_context, 0);
#else
			lws_service(db.config->listeners[i].ws_context, 0);
#endif
		}
	}
#endif
	plugin__handle_tick();
	if (mqtt_checker) {
		int ext_ret=mqtt_checker(mqtt_check_data);
		if (ext_ret!=0 ) break;
	}
	}
	/* clean up  must be call in mqtt  exit;

		mux__cleanup();
	*/
	return MOSQ_ERR_SUCCESS;
}

void do_disconnect(struct mosq_iot *context, int reason)
{
	char *id;
#ifdef WITH_WEBSOCKETS
	bool is_duplicate = false;
#endif

	if (context->state == mosq_cs_disconnected)
	{
		return;
	}
#ifdef WITH_WEBSOCKETS
	if (context->wsi)
	{
		if (context->state == mosq_cs_duplicate)
		{
			is_duplicate = true;
		}

		if (context->state != mosq_cs_disconnecting && context->state != mosq_cs_disconnect_with_will)
		{
			mosquitto__set_state(context, mosq_cs_disconnect_ws);
		}
		if (context->wsi)
		{
			lws_callback_on_writable(context->wsi);
		}
		if (context->sock != INVALID_SOCKET)
		{
			HASH_DELETE(hh_sock, db.contexts_by_sock, context);
			iot_mux__delete(context);
			context->sock = INVALID_SOCKET;
		}
		if (is_duplicate)
		{
			/* This occurs if another client is taking over the same client id.
			 * It is important to remove this from the by_id hash here, so it
			 * doesn't leave us with multiple clients in the hash with the same
			 * id. Websockets doesn't actually close the connection here,
			 * unlike for normal clients, which means there is extra time when
			 * there could be two clients with the same id in the hash. */
			context__remove_from_by_id(context);
		}
	}
	else
#endif
	{
		if (db.config->connection_messages == true)
		{
			if (context->id)
			{
				id = context->id;
			}
			else
			{
				id = "<unknown>";
			}
			if (context->state != mosq_cs_disconnecting && context->state != mosq_cs_disconnect_with_will)
			{
				switch (reason)
				{
				case MOSQ_ERR_SUCCESS:
					break;
				case MOSQ_ERR_MALFORMED_PACKET:
					iot_log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s disconnected due to malformed packet.", id);
					break;
				case MOSQ_ERR_PROTOCOL:
					iot_log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s disconnected due to protocol error.", id);
					break;
				case MOSQ_ERR_CONN_LOST:
					iot_log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s closed its connection.", id);
					break;
				case MOSQ_ERR_AUTH:
					iot_log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s disconnected, not authorised.", id);
					break;
				case MOSQ_ERR_KEEPALIVE:
					iot_log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s has exceeded timeout, disconnecting.", id);
					break;
				case MOSQ_ERR_OVERSIZE_PACKET:
					iot_log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s disconnected due to oversize packet.", id);
					break;
				case MOSQ_ERR_PAYLOAD_SIZE:
					iot_log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s disconnected due to oversize payload.", id);
					break;
				case MOSQ_ERR_NOMEM:
					iot_log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s disconnected due to out of memory.", id);
					break;
				case MOSQ_ERR_NOT_SUPPORTED:
					iot_log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s disconnected due to QoS too high or retain not supported.", id);
					break;
				case MOSQ_ERR_ADMINISTRATIVE_ACTION:
					iot_log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s been disconnected by administrative action.", id);
					break;
				case MOSQ_ERR_ERRNO:
					iot_log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s disconnected: %s.", id, strerror(errno));
					break;
				default:
					iot_log__printf(NULL, MOSQ_LOG_NOTICE, "Bad socket read/write on client %s: %s", id, mosquitto_strerror(reason));
					break;
				}
			}
			else
			{
				if (reason == MOSQ_ERR_ADMINISTRATIVE_ACTION)
				{
					iot_log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s been disconnected by administrative action.", id);
				}
				else
				{
					iot_log__printf(NULL, MOSQ_LOG_NOTICE, "Client %s disconnected.", id);
				}
			}
		}
		iot_mux__delete(context);
		context__disconnect(context);
	}
}
