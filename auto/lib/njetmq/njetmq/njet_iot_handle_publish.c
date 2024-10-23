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
#include <stdio.h>
#include <string.h>

#include "njet_iot_internal.h"
#include "njet_iot_alias_mosq.h"
#include "mqtt_protocol.h"
#include "memory_mosq.h"
#include "njet_iot_packet_mosq.h"
#include "property_mosq.h"
#include "read_handle.h"
#include "njet_iot_send_mosq.h"
#include "sys_tree.h"
#include "njet_iot_util_mosq.h"


#define NJET_IOT_GOSSIP_NODEINFO "/gossip/nodeinfo"
#define NJET_IOT_GOSSIP_NODEINFO_MASTER_IP_FIELD "master_ip:"
#define NJET_IOT_GOSSIP_NODEINFO_LOCAL_IP_FIELD "local_ip:"
#define NJET_IOT_GOSSIP_NODEINFO_BRIDGE_PORT_FIELD "bridge_port:"
#define NJET_IOT_GOSSIP_BRIDGE_BACKUP "bridge-backup"


#ifdef WITH_BRIDGE
char *
mosquitto_strstrn(char *s1, char *s2, size_t n)
{
    char  c1, c2;

    c2 = *(char *) s2++;

    do {
        do {
            c1 = *s1++;

            if (c1 == 0) {
                return NULL;
            }

        } while (c1 != c2);

    } while (strncmp((const char *)s1, (const char *) s2, n) != 0);

    return --s1;
}


static void mosquitto_gossip_nodeinfo_get_field(char *msg, size_t msg_len,
		char *field_name, size_t field_name_len, char **field_value, size_t *field_value_len)
{
    if (msg == NULL || msg_len < field_name_len
		||msg_len < 0 || field_name_len < 0){
		return;
	}

    char *pfs = mosquitto_strstrn(msg, field_name, field_name_len - 1);
    if (pfs == NULL) {
		iot_log__printf(NULL, MOSQ_LOG_WARNING, "Warning: ==mnsg:%s filed_name:%s len:%ld", msg, field_name, field_name_len - 1);

		return;
	}

    char *pvs = pfs + field_name_len;
    if (pvs >= msg + msg_len) {
		return;
	}

	char *pc1;
    for (pc1 = pvs; pc1 < msg + msg_len && (*pc1 == ' ' || *pc1 == '{'); pc1++);
    pvs = pc1;
    for (pc1 = pvs; pc1 < msg + msg_len && *pc1 != ',' && *pc1 != '}'; pc1++);
    *field_value = pvs;
    *field_value_len = pc1 - pvs;

	iot_log__printf(NULL, MOSQ_LOG_WARNING, "Warning: ==mnsg:%s filed_name:%s len:%ld", msg, field_name, field_name_len - 1);
}


static uint16_t mosquitto_gossip_atoi(u_char *line, size_t n, uint16_t max_value, uint16_t min_value)
{
    uint16_t  value;

    if (n == 0) {
        return 0;
    }

    for (value = 0; n--; line++) {
        if (*line < '0' || *line > '9') {
            return 0;
        }

        value = value * 10 + (*line - '0');

		if (value > max_value || value < min_value) {
            return 0;
        }
    }

    return value;
}

void mosquitto_stop_connect(struct mosq_iot *context){
	if(context == NULL || !context->is_bridge || context->bridge == NULL){
		return;
	}

	if (context->sock != INVALID_SOCKET)
	{
		// HASH_DELETE(hh_sock, db.contexts_by_sock, context);
		iot_mux__delete(context);
		context__disconnect(context);
		context->sock = INVALID_SOCKET;
	}
}


// static int conf__attempt_resolve(const char *host, const char *text, unsigned int log, const char *msg)
// {
// 	struct addrinfo gai_hints;
// 	struct addrinfo *gai_res;
// 	int rc;

// 	memset(&gai_hints, 0, sizeof(struct addrinfo));
// 	gai_hints.ai_family = AF_UNSPEC;
// 	gai_hints.ai_socktype = SOCK_STREAM;
// 	gai_res = NULL;
// 	rc = getaddrinfo(host, NULL, &gai_hints, &gai_res);
// 	if (gai_res)
// 	{
// 		freeaddrinfo(gai_res);
// 	}
// 	if (rc != 0)
// 	{
// #ifndef WIN32
// 		if (rc == EAI_SYSTEM)
// 		{
// 			if (errno == ENOENT)
// 			{
// 				iot_log__printf(NULL, log, "%s: Unable to resolve %s %s.", msg, text, host);
// 			}
// 			else
// 			{
// 				iot_log__printf(NULL, log, "%s: Error resolving %s: %s.", msg, text, strerror(errno));
// 			}
// 		}
// 		else
// 		{
// 			iot_log__printf(NULL, log, "%s: Error resolving %s: %s.", msg, text, gai_strerror(rc));
// 		}
// #else
// 		if (rc == WSAHOST_NOT_FOUND)
// 		{
// 			iot_log__printf(NULL, log, "%s: Error resolving %s.", msg, text);
// 		}
// #endif
// 		return MOSQ_ERR_INVAL;
// 	}
// 	return MOSQ_ERR_SUCCESS;
// }

void mosquitto_master_modify_check(struct mosq_iot *context, char *topic, uint32_t payloadlen, void *payload){
	char 		*master_ip_field_value = NULL;
	size_t 		master_ip_field_value_len = 0;
	char 		tmp_master_ip[20];
	char 		*local_ip_field_value = NULL;
	size_t 		local_ip_field_value_len = 0;
	char 		*bridge_port_field_value = NULL;
	size_t 		bridge_port_field_value_len = 0;
	int 		i;
	// struct mosq_iot *context = NULL;
	struct mosq_iot **bridges;
	char 			*local_id;
	bool 		need_bridge_new = false;
	char 		*last_master_address;
	uint16_t 	bridge_port = 0;

	//filter topic /gossip/nodeinfo
	if(0 != strncmp(topic, NJET_IOT_GOSSIP_NODEINFO, strlen(NJET_IOT_GOSSIP_NODEINFO))
		|| payloadlen < 1
		|| strlen(topic) != strlen(NJET_IOT_GOSSIP_NODEINFO)){
		return;
	}

	//get master ip and local ip
	master_ip_field_value = NULL;
	master_ip_field_value_len = 0;
    mosquitto_gossip_nodeinfo_get_field(payload, payloadlen,
			NJET_IOT_GOSSIP_NODEINFO_MASTER_IP_FIELD,
			strlen(NJET_IOT_GOSSIP_NODEINFO_MASTER_IP_FIELD),
			&master_ip_field_value,
			&master_ip_field_value_len);

    //ipv4 max ip len is 15
    if (master_ip_field_value_len > 15 || master_ip_field_value_len < 7) {
		iot_log__printf(NULL, MOSQ_LOG_WARNING, "Warning: gossip master_ip parse error");
        return;
    }

    //try to get local  ip
	local_ip_field_value = NULL;
	local_ip_field_value_len = 0;
    mosquitto_gossip_nodeinfo_get_field(payload, payloadlen,
			NJET_IOT_GOSSIP_NODEINFO_LOCAL_IP_FIELD,
			strlen(NJET_IOT_GOSSIP_NODEINFO_LOCAL_IP_FIELD),
			&local_ip_field_value,
			&local_ip_field_value_len);

    //ipv4 max ip len is 15
    if (local_ip_field_value_len > 15 || local_ip_field_value_len < 7) {
		iot_log__printf(NULL, MOSQ_LOG_WARNING, "Warning: gossip local_ip parse error");
        return;
    }


	//get bridge port
	bridge_port_field_value = NULL;
	bridge_port_field_value_len = 0;
    mosquitto_gossip_nodeinfo_get_field(payload, payloadlen,
			NJET_IOT_GOSSIP_NODEINFO_BRIDGE_PORT_FIELD,
			strlen(NJET_IOT_GOSSIP_NODEINFO_BRIDGE_PORT_FIELD),
			&bridge_port_field_value,
			&bridge_port_field_value_len);

	bridge_port = mosquitto_gossip_atoi(bridge_port_field_value, bridge_port_field_value_len, 65535, 1);

	//check wether self is master
	if((master_ip_field_value_len == local_ip_field_value_len)
		&& strncmp(master_ip_field_value, local_ip_field_value, local_ip_field_value_len) == 0){
		//if self is master
		//check wether self bridge connect other, is connect, need clean the connection
		for (i = 0; i < db.config->bridge_count; i++)
		{
			if (0 != strcmp(db.config->bridges[i].name, NJET_IOT_GOSSIP_BRIDGE_BACKUP)){
				continue;
			}

			if(db.config->bridges[i].active){
				local_id = mosquitto__strdup(db.config->bridges[i].local_clientid);

				HASH_FIND(hh_id, db.contexts_by_id, local_id, strlen(local_id), context);
				if (context){
					mosquitto_stop_connect(context);
					db.config->bridges[i].active = 0;
					context->sock = INVALID_SOCKET;
					
					iot_log__printf(NULL, MOSQ_LOG_INFO, "INFO: self become master, just stop connection to others");
				}

				mosquitto__free(local_id);
			}

			break;
		}
	}else{
		//if self is not master
		//check wether self bridge connect other
		for (i = 0; i < db.config->bridge_count; i++)
		{
			if (0 != strcmp(db.config->bridges[i].name, NJET_IOT_GOSSIP_BRIDGE_BACKUP)){
				continue;
			}

			// if(db.config->bridges[i].active){
				local_id = mosquitto__strdup(db.config->bridges[i].local_clientid);
				HASH_FIND(hh_id, db.contexts_by_id, local_id, strlen(local_id), context);
				if (context){
					if(context->sock != INVALID_SOCKET){
						//check wether connect is master
						last_master_address = context->bridge->addresses[context->bridge->cur_address].address;
						if(strlen(last_master_address) == master_ip_field_value_len
							&& strncmp(last_master_address, master_ip_field_value, master_ip_field_value_len) == 0){
							//master is not modify, so ignore
							iot_log__printf(NULL, MOSQ_LOG_INFO, "INFO: master change, but is the old master, still user current connection");

							//donothing
							break;
						}else{
							//stop current connect first
							mosquitto_stop_connect(context);
							db.config->bridges[i].active = 0;
							context->sock = INVALID_SOCKET;
							iot_log__printf(NULL, MOSQ_LOG_INFO, "INFO: master change, just stop current connection to others");
						}
					}
				}

				mosquitto__free(local_id);
				need_bridge_new = true;
			// }

			break;
		}

		if(need_bridge_new){
			iot_log__printf(NULL, MOSQ_LOG_INFO, "INFO: master change, start new connection to others");

			db.config->bridges[i].active = 1;
			memset(tmp_master_ip, 0, 20);
			memcpy(tmp_master_ip, master_ip_field_value, master_ip_field_value_len);
			//replace bridge address as new master address
			db.config->bridges[i].addresses[db.config->bridges[i].cur_address].address = mosquitto__strdup(tmp_master_ip);
			if(bridge_port != 0){
				db.config->bridges[i].addresses[db.config->bridges[i].cur_address].port = bridge_port;
			}
			// conf__attempt_resolve(db.config->bridges[i].addresses[db.config->bridges[i].cur_address].address, "bridge address", MOSQ_LOG_WARNING, "Warning");

			//bridge_new
			if (bridge__new(&(db.config->bridges[i])) > 0)
			{
				iot_log__printf(NULL, MOSQ_LOG_WARNING, "Warning: master change, Unable to connect to bridge %s.",
								db.config->bridges[i].name);
			}
		}
	}
}
#endif


int iot_handle__publish(struct mosq_iot *context)
{
	uint8_t dup;
	int rc = 0;
	int rc2;
	uint8_t header = context->in_packet.command;
	int res = 0;
	struct mosquitto_msg_store *msg, *stored = NULL;
	size_t len;
	uint16_t slen;
	char *topic_mount;
	mosquitto_property *properties = NULL;
	mosquitto_property *p, *p_prev;
	mosquitto_property *msg_properties_last;
	uint32_t message_expiry_interval = 0;
	int topic_alias = -1;
	uint8_t reason_code = 0;
	uint16_t mid = 0;

	if (context->state != mosq_cs_active)
	{
		return MOSQ_ERR_PROTOCOL;
	}

	msg = mosquitto__calloc(1, sizeof(struct mosquitto_msg_store));
	if (msg == NULL)
	{
		return MOSQ_ERR_NOMEM;
	}

	dup = (header & 0x08) >> 3;
	msg->qos = (header & 0x06) >> 1;
	if (msg->qos == 3)
	{
		iot_log__printf(NULL, MOSQ_LOG_INFO,
						"Invalid QoS in PUBLISH from %s, disconnecting.", context->id);
		db__msg_store_free(msg);
		return MOSQ_ERR_MALFORMED_PACKET;
	}
	if (msg->qos > context->max_qos)
	{
		iot_log__printf(NULL, MOSQ_LOG_INFO,
						"Too high QoS in PUBLISH from %s, disconnecting.", context->id);
		db__msg_store_free(msg);
		return MOSQ_ERR_QOS_NOT_SUPPORTED;
	}
	msg->retain = (header & 0x01);

	if (msg->retain && db.config->retain_available == false)
	{
		db__msg_store_free(msg);
		return MOSQ_ERR_RETAIN_NOT_SUPPORTED;
	}

	if (packet__read_string(&context->in_packet, &msg->topic, &slen))
	{
		db__msg_store_free(msg);
		return MOSQ_ERR_MALFORMED_PACKET;
	}
	if (!slen && context->protocol != mosq_p_mqtt5)
	{
		/* Invalid publish topic, disconnect client. */
		db__msg_store_free(msg);
		return MOSQ_ERR_MALFORMED_PACKET;
	}

	if (msg->qos > 0)
	{
		if (packet__read_uint16(&context->in_packet, &mid))
		{
			db__msg_store_free(msg);
			return MOSQ_ERR_MALFORMED_PACKET;
		}
		if (mid == 0)
		{
			db__msg_store_free(msg);
			return MOSQ_ERR_PROTOCOL;
		}
		/* It is important to have a separate copy of mid, because msg may be
		 * freed before we want to send a PUBACK/PUBREC. */
		msg->source_mid = mid;
	}

	/* Handle properties */
	if (context->protocol == mosq_p_mqtt5)
	{
		rc = property__read_all(CMD_PUBLISH, &context->in_packet, &properties);
		if (rc)
		{
			db__msg_store_free(msg);
			if (rc == MOSQ_ERR_PROTOCOL)
			{
				return MOSQ_ERR_MALFORMED_PACKET;
			}
			else
			{
				return rc;
			}
		}

		p = properties;
		p_prev = NULL;
		msg->properties = NULL;
		msg_properties_last = NULL;
		while (p)
		{
			switch (p->identifier)
			{
			case MQTT_PROP_CONTENT_TYPE:
			case MQTT_PROP_CORRELATION_DATA:
			case MQTT_PROP_PAYLOAD_FORMAT_INDICATOR:
			case MQTT_PROP_RESPONSE_TOPIC:
			case MQTT_PROP_USER_PROPERTY:
				if (msg->properties)
				{
					msg_properties_last->next = p;
					msg_properties_last = p;
				}
				else
				{
					msg->properties = p;
					msg_properties_last = p;
				}
				if (p_prev)
				{
					p_prev->next = p->next;
					p = p_prev->next;
				}
				else
				{
					properties = p->next;
					p = properties;
				}
				msg_properties_last->next = NULL;
				break;

			case MQTT_PROP_TOPIC_ALIAS:
				topic_alias = p->value.i16;
				p_prev = p;
				p = p->next;
				break;

			case MQTT_PROP_MESSAGE_EXPIRY_INTERVAL:
				message_expiry_interval = p->value.i32;
				p_prev = p;
				p = p->next;
				break;

			case MQTT_PROP_SUBSCRIPTION_IDENTIFIER:
				p_prev = p;
				p = p->next;
				break;

			default:
				p = p->next;
				break;
			}
		}
	}
	mosquitto_property_free_all(&properties);

	if (topic_alias == 0 || (context->listener && topic_alias > context->listener->max_topic_alias))
	{
		db__msg_store_free(msg);
		return MOSQ_ERR_TOPIC_ALIAS_INVALID;
	}
	else if (topic_alias > 0)
	{
		if (msg->topic)
		{
			rc = iot_alias__add(context, msg->topic, (uint16_t)topic_alias);
			if (rc)
			{
				db__msg_store_free(msg);
				return rc;
			}
		}
		else
		{
			rc = iot_alias__find(context, &msg->topic, (uint16_t)topic_alias);
			if (rc)
			{
				db__msg_store_free(msg);
				return MOSQ_ERR_PROTOCOL;
			}
		}
	}

#ifdef WITH_BRIDGE
	rc = bridge__remap_topic_in(context, &msg->topic);
	if (rc)
	{
		db__msg_store_free(msg);
		return rc;
	}

#endif
	if (mosquitto_pub_topic_check(msg->topic) != MOSQ_ERR_SUCCESS)
	{
		/* Invalid publish topic, just swallow it. */
		db__msg_store_free(msg);
		return MOSQ_ERR_PROTOCOL;
	}

	msg->payloadlen = context->in_packet.remaining_length - context->in_packet.pos;
	G_PUB_BYTES_RECEIVED_INC(msg->payloadlen);
	if (context->listener && context->listener->mount_point)
	{
		len = strlen(context->listener->mount_point) + strlen(msg->topic) + 1;
		topic_mount = mosquitto__malloc(len + 1);
		if (!topic_mount)
		{
			db__msg_store_free(msg);
			return MOSQ_ERR_NOMEM;
		}
		snprintf(topic_mount, len, "%s%s", context->listener->mount_point, msg->topic);
		topic_mount[len] = '\0';

		mosquitto__free(msg->topic);
		msg->topic = topic_mount;
	}

	if (msg->payloadlen)
	{
		if (db.config->message_size_limit && msg->payloadlen > db.config->message_size_limit)
		{
			iot_log__printf(NULL, MOSQ_LOG_DEBUG, "Dropped too large PUBLISH from %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", context->id, dup, msg->qos, msg->retain, msg->source_mid, msg->topic, (long)msg->payloadlen);
			reason_code = MQTT_RC_PACKET_TOO_LARGE;
			goto process_bad_message;
		}
		msg->payload = mosquitto__malloc(msg->payloadlen + 1);
		if (msg->payload == NULL)
		{
			db__msg_store_free(msg);
			return MOSQ_ERR_NOMEM;
		}
		/* Ensure payload is always zero terminated, this is the reason for the extra byte above */
		((uint8_t *)msg->payload)[msg->payloadlen] = 0;

		if (packet__read_bytes(&context->in_packet, msg->payload, msg->payloadlen))
		{
			db__msg_store_free(msg);
			return MOSQ_ERR_MALFORMED_PACKET;
		}
	}

	/* Check for topic access */
	rc = mosquitto_acl_check(context, msg->topic, msg->payloadlen, msg->payload, msg->qos, msg->retain, MOSQ_ACL_WRITE);
	if (rc == MOSQ_ERR_ACL_DENIED)
	{
		iot_log__printf(NULL, MOSQ_LOG_DEBUG, "Denied PUBLISH from %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", context->id, dup, msg->qos, msg->retain, msg->source_mid, msg->topic, (long)msg->payloadlen);
		reason_code = MQTT_RC_NOT_AUTHORIZED;
		goto process_bad_message;
	}
	else if (rc != MOSQ_ERR_SUCCESS)
	{
		db__msg_store_free(msg);
		return rc;
	}

	iot_log__printf(NULL, MOSQ_LOG_DEBUG, "Received PUBLISH from %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", context->id, dup, msg->qos, msg->retain, msg->source_mid, msg->topic, (long)msg->payloadlen);

#ifdef WITH_BRIDGE
	//add by clb
	//filter /gossip/nodeinfo topic, and check wether master is modify
	mosquitto_master_modify_check(context, msg->topic, msg->payloadlen, msg->payload);
	//end add by clb
#endif
	if (!strncmp(msg->topic, "$CONTROL/", 9))
	{
#ifdef WITH_CONTROL
		rc = control__process(context, msg);
		db__msg_store_free(msg);
		return rc;
#else
		if (msg->qos == 1)
		{
			if (iot_send__puback(context, msg->source_mid, MQTT_RC_SUCCESS, NULL))
			{
				return MOSQ_ERR_UNKNOWN;
			}
		}
		else if (msg->qos == 2)
		{
			if (iot_send__pubrec(context, msg->source_mid, MQTT_RC_SUCCESS, NULL))
			{
				return MOSQ_ERR_UNKNOWN;
			}
		}
		db__msg_store_free(msg);
		return MOSQ_ERR_SUCCESS;
#endif
	}

	{
		rc = plugin__handle_message(context, msg);
		if (rc)
		{
			db__msg_store_free(msg);
			return rc;
		}
	}

	if (msg->qos > 0)
	{
		db__message_store_find(context, msg->source_mid, &stored);
	}

	if (stored && msg->source_mid != 0 &&
		(stored->qos != msg->qos || stored->payloadlen != msg->payloadlen || strcmp(stored->topic, msg->topic) || memcmp(stored->payload, msg->payload, msg->payloadlen)))
	{

		iot_log__printf(NULL, MOSQ_LOG_WARNING, "Reused message ID %u from %s detected. Clearing from storage.", msg->source_mid, context->id);
		db__message_remove_incoming(context, msg->source_mid);
		stored = NULL;
	}

	if (!stored)
	{
		if (msg->qos == 0 || db__ready_for_flight(&context->msgs_in, msg->qos) || db__ready_for_queue(context, msg->qos, &context->msgs_in))
		{

			dup = 0;
			rc = db__message_store(context, msg, message_expiry_interval, 0, mosq_mo_client);
			if (rc)
				return rc;
		}
		else
		{
			/* Client isn't allowed any more incoming messages, so fail early */
			reason_code = MQTT_RC_QUOTA_EXCEEDED;
			goto process_bad_message;
		}
		stored = msg;
		msg = NULL;
	}
	else
	{
		db__msg_store_free(msg);
		msg = NULL;
		dup = 1;
	}

	switch (stored->qos)
	{
	case 0:
		rc2 = sub__messages_queue(context->id, stored->topic, stored->qos, stored->retain, &stored);
		if (rc2 > 0)
			rc = 1;
		break;
	case 1:
		iot_util__decrement_receive_quota(context);
		rc2 = sub__messages_queue(context->id, stored->topic, stored->qos, stored->retain, &stored);
		/* stored may now be free, so don't refer to it */
		if (rc2 == MOSQ_ERR_SUCCESS || context->protocol != mosq_p_mqtt5)
		{
			if (iot_send__puback(context, mid, 0, NULL))
				rc = 1;
		}
		else if (rc2 == MOSQ_ERR_NO_SUBSCRIBERS)
		{
			if (iot_send__puback(context, mid, MQTT_RC_NO_MATCHING_SUBSCRIBERS, NULL))
				rc = 1;
		}
		else
		{
			rc = rc2;
		}
		break;
	case 2:
		if (dup == 0)
		{
			res = db__message_insert(context, stored->source_mid, mosq_md_in, stored->qos, stored->retain, stored, NULL, false);
		}
		else
		{
			res = 0;
		}
		/* db__message_insert() returns 2 to indicate dropped message
		 * due to queue. This isn't an error so don't disconnect them. */
		/* FIXME - this is no longer necessary due to failing early above */
		if (!res)
		{
			if (iot_send__pubrec(context, stored->source_mid, 0, NULL))
				rc = 1;
		}
		else if (res == 1)
		{
			rc = 1;
		}
		break;
	}

	db__message_write_queued_in(context);
	return rc;
process_bad_message:
	rc = 1;
	if (msg)
	{
		switch (msg->qos)
		{
		case 0:
			rc = MOSQ_ERR_SUCCESS;
			break;
		case 1:
			rc = iot_send__puback(context, msg->source_mid, reason_code, NULL);
			break;
		case 2:
			if (context->protocol == mosq_p_mqtt5)
			{
				rc = iot_send__pubrec(context, msg->source_mid, reason_code, NULL);
			}
			else
			{
				rc = iot_send__pubrec(context, msg->source_mid, 0, NULL);
			}
			break;
		}
		db__msg_store_free(msg);
	}
	return rc;
}
