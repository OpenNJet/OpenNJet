/*
Copyright (c) 2009-2020 Roger Light <roger@atchoo.org>
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

#include "config.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <dirent.h>
#include <strings.h>

#include <netdb.h>
#include <sys/socket.h>

#include <syslog.h>

#include "mosquitto_internal.h"
#include "misc_mosq.h"
#include "tls_mosq.h"
#include "mqtt_protocol.h"

#include "memory_mosq.h"
#include "njet_iot_shared.h"
#include "njet_conf_base.h"

static char client_log_fptr_buffer[BUFSIZ];

struct config_recurse
{
	unsigned int log_dest;
	int log_dest_set;
	unsigned int log_type;
	int log_type_set;
};

int client_config__read_file_core(struct mosq_config *cfg, bool reload, int level, int *lineno, FILE *fptr, char **buf, int *buflen)
{
	int rc;
	char *token;
	int tmp_int;
	char *saveptr = NULL;

	time_t expiration_mult;
	char *key;
	int i;
	int lineno_ext = 0;
	size_t prefix_len;
	char **files;
	int file_count;
#ifdef WITH_TLS
	char *kpass_sha = NULL, *kpass_sha_bin = NULL;
	char *keyform;
#endif
	char topic_buf[128];
	*lineno = 0;

	cfg->retain = 1; // todo: change to init
	cfg->no_retain = true;
	cfg->sub_opts |= MQTT_SUB_OPT_NO_LOCAL;
	cfg->remove_retained = true;
	// cfg_add_topic(cfg,CLIENT_SUB,"/broker/#","-t");
	// tips:subscript to /custer/kv_set/#, so got all messages ,and could easily omit by apply /cluster/kv_set/id
	// cfg_add_topic(cfg,CLIENT_SUB,"/cluster/kv_set/#","-t");  	//rpc
	// cfg_add_topic(cfg,CLIENT_SUB,"/cluster/query/#","-t");  	//rpc
	// cfg_add_topic(cfg,CLIENT_SUB,"/cluster/status","-t");
	// cfg_add_topic(cfg,CLIENT_SUB,"$SYS/broker/clients/connected","-t");   --no needed anymore
	if (cfg->id != NULL)
	{
		snprintf(topic_buf, 128, "%s_rcp_resp", cfg->id);
		cfg_add_topic(cfg, CLIENT_SUB, topic_buf, "-t");
	}

	while (fgets_extending(buf, buflen, fptr))
	{
		(*lineno)++;
		if ((*buf)[0] != '#' && (*buf)[0] != 10 && (*buf)[0] != 13)
		{
			while ((*buf)[strlen((*buf)) - 1] == 10 || (*buf)[strlen((*buf)) - 1] == 13)
			{
				(*buf)[strlen((*buf)) - 1] = 0;
			}
			token = strtok_r((*buf), " ", &saveptr);
			if (token)
			{
				if (!strcmp(token, "bind"))
				{
					if (conf__parse_string(&token, "bind", &cfg->bind_address, saveptr))
						return MOSQ_ERR_INVAL;
				}
				else
					/*
					else

					if(!strcmp(token, "host")){
						if(conf__parse_string(&token, "host", &cfg->host, saveptr)) return MOSQ_ERR_INVAL;
					} else
					if(!strcmp(token, "port")){
						if(conf__parse_int(&token, "port", &cfg->port, saveptr)) return MOSQ_ERR_INVAL;
						 if(cfg->port<0 || cfg->port>65535){
												fprintf(stderr, "Error: Invalid port given: %d\n", cfg->port);
												return MOSQ_ERR_INVAL;
						 }
					} else
					*/
					if (!strcmp(token, "insecure"))
					{
						if (conf__parse_bool(&token, "insecure", &cfg->insecure, saveptr))
							return MOSQ_ERR_INVAL;
					}
					else if (!strcmp(token, "id"))
					{
						if (cfg->id == NULL)
							if (conf__parse_string(&token, "id", &cfg->id, saveptr))
								return MOSQ_ERR_INVAL;
						snprintf(topic_buf, 128, "/cluster/snap/%s", cfg->id);
						cfg_add_topic(cfg, CLIENT_SUB, topic_buf, "-t");
					}
					else if (!strcmp(token, "keepalive"))
					{
						if (conf__parse_int(&token, "keepalive", &cfg->keepalive, saveptr))
							return MOSQ_ERR_INVAL;
					}
					else if (!strcmp(token, "topic"))
					{
						char *tmp_topic = NULL;
						if (conf__parse_string(&token, "topic", &tmp_topic, saveptr))
							return MOSQ_ERR_INVAL;
						// todo: do we need to free tmp_topic?
						cfg_add_topic(cfg, CLIENT_SUB, tmp_topic, "-t");
						free(tmp_topic);
					}
					else if (!strcmp(token, "kv_store_dir"))
					{
						if (conf__parse_string(&token, "kv_store_dir", &cfg->kv_store, saveptr))
							return MOSQ_ERR_INVAL;
					}
					else if (!strcmp(token, "cafile"))
					{
						if (conf__parse_string(&token, "cafile", &cfg->cafile, saveptr))
							return MOSQ_ERR_INVAL;
					}
					else if (!strcmp(token, "certfile"))
					{
						if (conf__parse_string(&token, "certfile", &cfg->certfile, saveptr))
							return MOSQ_ERR_INVAL;
					}
					else if (!strcmp(token, "keyfile"))
					{
						if (conf__parse_string(&token, "keyfile", &cfg->keyfile, saveptr))
							return MOSQ_ERR_INVAL;
					}
					else if (!strcmp(token, "script"))
					{
						if (conf__parse_string(&token, "script", &cfg->script_on_message, saveptr))
							return MOSQ_ERR_INVAL;
					}
					else if (!strcmp(token, "unix_pipe"))
					{
						if (conf__parse_string(&token, "unix_pipe", &cfg->unix_pipe, saveptr))
							return MOSQ_ERR_INVAL;
					}
					else if (!strcmp(token, "log_type"))
					{
						token = strtok_r(NULL, " ", &saveptr);
						if (token)
						{
							if (!strcmp(token, "information"))
							{
								cfg->log_type |= MOSQ_LOG_INFO;
							}
							else if (!strcmp(token, "notice"))
							{
								cfg->log_type |= MOSQ_LOG_NOTICE;
							}
							else if (!strcmp(token, "warning"))
							{
								cfg->log_type |= MOSQ_LOG_WARNING;
							}
							else if (!strcmp(token, "error"))
							{
								cfg->log_type |= MOSQ_LOG_ERR;
							}
							else if (!strcmp(token, "debug"))
							{
								cfg->log_type |= MOSQ_LOG_DEBUG;
							}
							else
							{
								fprintf(stderr, "Error: Invalid log_type value (%s).", token);
								cfg->log_type = MOSQ_LOG_ERR | MOSQ_LOG_NOTICE | MOSQ_LOG_WARNING | MOSQ_LOG_INFO;
								// return MOSQ_ERR_INVAL;
							}
						}
					}
					else if (!strcmp(token, "log_file"))
					{
						if (cfg->log_file == NULL)
							if (conf__parse_string(&token, "log_file", &cfg->log_file, saveptr))
								return MOSQ_ERR_INVAL;
					}
					else if (!strcmp(token, "key"))
					{
						if (conf__parse_string(&token, "key", &cfg->keyfile, saveptr))
							return MOSQ_ERR_INVAL;
					}
					else if (!strcmp(token, "keyform"))
					{
						if (conf__parse_string(&token, "keyform", &cfg->keyform, saveptr))
							return MOSQ_ERR_INVAL;
					}
					else if (!strcmp(token, "max_inflight"))
					{
						if (conf__parse_int(&token, "max_inflight", &cfg->max_inflight, saveptr))
							return MOSQ_ERR_INVAL;
					}
					else if (!strcmp(token, "no_delay"))
					{
						if (conf__parse_bool(&token, "no_delay", &cfg->tcp_nodelay, saveptr))
							return MOSQ_ERR_INVAL;
					}
					else if (!strcmp(token, "password"))
					{
						if (conf__parse_string(&token, "password", &cfg->password, saveptr))
							return MOSQ_ERR_INVAL;
					}
					else if (!strcmp(token, "psk"))
					{
						if (conf__parse_string(&token, "psk", &cfg->psk, saveptr))
							return MOSQ_ERR_INVAL;
					}
					else if (!strcmp(token, "psk_identity"))
					{
						if (conf__parse_string(&token, "psk_identity", &cfg->psk_identity, saveptr))
							return MOSQ_ERR_INVAL;
					}
					else if (!strcmp(token, "qos"))
					{
						if (conf__parse_int(&token, "qos", &cfg->qos, saveptr))
							return MOSQ_ERR_INVAL;
						if (cfg->qos < 0 || cfg->qos > 2)
						{
							fprintf(stderr, "Error: Invalid QoS given: %d\n", cfg->qos);
							return MOSQ_ERR_INVAL;
						}
					}
					else
						/*
					if(!strcmp(token, "unix")){
						if(conf__parse_string(&token, "unix", &cfg->host, saveptr)) return MOSQ_ERR_INVAL;
						cfg->port=0;
					} else
					*/
						if (!strcmp(token, "username"))
						{
							if (conf__parse_string(&token, "username", &cfg->username, saveptr))
								return MOSQ_ERR_INVAL;
						}
						else if (!strcmp(token, "protocol-version"))
						{
							if (conf__parse_int(&token, "protocol-version", &tmp_int, saveptr))
								return MOSQ_ERR_INVAL;
							if (tmp_int == 31)
							{
								cfg->protocol_version = MQTT_PROTOCOL_V31;
							}
							else if (tmp_int == 311)
							{
								cfg->protocol_version = MQTT_PROTOCOL_V311;
							}
							else if (tmp_int == 5)
							{
								cfg->protocol_version = MQTT_PROTOCOL_V5;
							}
							else
							{
								fprintf(stderr, "Error: Invalid protocol version argument given.\n\n");
								return MOSQ_ERR_INVAL;
							}
						}
						else if (!strcmp(token, "broker_addr"))
						{
							char *tmp_str = NULL;
							char *save, *broker;
							int broker_cnt = 0;
							if (conf__parse_string(&token, "broker_addr", &tmp_str, saveptr))
								return MOSQ_ERR_INVAL;
							cfg->brokers = malloc(10 * sizeof(struct broker_config));
							memset(cfg->brokers, '\0', 10 * sizeof(struct broker_config));
							char *buf = malloc(strlen(tmp_str) + 1);
							buf[strlen(tmp_str)] = '\0';
							strcpy(buf, tmp_str);
							broker = strtok_r(buf, ",", &save);
							while (broker != NULL)
							{
								if (!strncasecmp(broker, "mqtts://", 8))
								{
									char *save2, *host, *port;
									char *h = broker;
									h += 8;
									host = strtok_r(h, ":", &save2);
									port = strtok_r(NULL, ":", &save2);
									if (host)
									{
										strcpy(cfg->brokers[broker_cnt].host, host);
										if (port)
											cfg->brokers[broker_cnt].port = atoi(port);
										else
											cfg->brokers[broker_cnt].port = 8883;
										cfg->tls_use_os_certs = true;
									}
								}
								else if (!strncasecmp(broker, "mqtt://", 7))
								{
									char *save2, *host, *port;
									char *h = broker + 7;
									host = strtok_r(h, ":", &save2);
									port = strtok_r(NULL, ":", &save2);
									if (host)
									{
										strcpy(cfg->brokers[broker_cnt].host, host);
										if (port)
											cfg->brokers[broker_cnt].port = atoi(port);
										else
											cfg->brokers[broker_cnt].port = 1883;
										cfg->tls_use_os_certs = false;
									}
								}
								else if (!strncasecmp(broker, "unix:", 5))
								{
									strcpy(cfg->brokers[broker_cnt].host, broker + 5);
									cfg->brokers[broker_cnt].port = 0;
									cfg->tls_use_os_certs = false;
								}
								broker_cnt++;
								broker = strtok_r(NULL, ",", &save);
							}
							free(tmp_str);
							free(buf);
						}
						else if (!strcmp(token, "verbose"))
						{
							cfg->verbose = 1;
						}
			}
		}
	}
	return MOSQ_ERR_SUCCESS;
}

int client_config__read_file(struct mosq_config *config, bool reload, const char *file, int level, int *lineno)
{
	int rc;
	FILE *fptr = NULL;
	char *buf;
	int buflen;
	DIR *dir;

	dir = opendir(file);
	if (dir)
	{
		closedir(dir);
		fprintf(stderr, "Error: Config file %s is a directory.\n", file);
		return 1;
	}

	fptr = mosquitto__fopen(file, "rt", false);
	if (!fptr)
	{
		fprintf(stderr, "Error: Unable to open config file %s.\n", file);
		return 1;
	}

	buflen = 1000;
	buf = mosquitto__malloc((size_t)buflen);
	if (!buf)
	{
		fprintf(stderr, "Error: Out of memory.\n");
		fclose(fptr);
		return MOSQ_ERR_NOMEM;
	}

	rc = client_config__read_file_core(config, reload, level, lineno, fptr, &buf, &buflen);
	mosquitto__free(buf);
	fclose(fptr);
	if (rc != MOSQ_ERR_SUCCESS)
		return rc;
	if (config->log_file)
	{
		config->log_fptr = mosquitto__fopen(config->log_file, "at", false);
		if (config->log_fptr)
		{
			setvbuf(config->log_fptr, client_log_fptr_buffer, _IOLBF, sizeof(client_log_fptr_buffer));
			return MOSQ_ERR_SUCCESS;
		}
		else
		{
			fprintf(stderr, "Error:Unable to open log file %s for writing.:%s",
					config->log_file,
					strerror(errno));
			return MOSQ_ERR_INVAL;
		}
	}
	return MOSQ_ERR_SUCCESS;
}
