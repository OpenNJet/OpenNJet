/*
Copyright (c) 2014-2020 Roger Light <roger@atchoo.org>
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

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <strings.h>

#include <mosquitto.h>
#include <mqtt_protocol.h>
#include "njet_iot_shared.h"

static int client_config_line_proc(struct mosq_config *cfg, int pub_or_sub, int argc, char *argv[]);

static int check_format(const char *str)
{
	size_t i;
	size_t len;

	len = strlen(str);
	for (i = 0; i < len; i++)
	{
		if (str[i] == '%')
		{
			if (i == len - 1)
			{
				// error
				fprintf(stderr, "Error: Incomplete format specifier.\n");
				return 1;
			}
			else
			{
				if (str[i + 1] == '0' || str[i + 1] == '-')
				{
					/* Flag characters */
					i++;
					if (i == len - 1)
					{
						// error
						fprintf(stderr, "Error: Incomplete format specifier.\n");
						return 1;
					}
				}

				/* Field width */
				while (str[i + 1] >= '0' && str[i + 1] <= '9')
				{
					i++;
					if (i == len - 1)
					{
						// error
						fprintf(stderr, "Error: Incomplete format specifier.\n");
						return 1;
					}
				}

				if (str[i + 1] == '.')
				{
					/* Precision specifier */
					i++;
					if (i == len - 1)
					{
						// error
						fprintf(stderr, "Error: Incomplete format specifier.\n");
						return 1;
					}
					/* Precision */
					while (str[i + 1] >= '0' && str[i + 1] <= '9')
					{
						i++;
						if (i == len - 1)
						{
							// error
							fprintf(stderr, "Error: Incomplete format specifier.\n");
							return 1;
						}
					}
				}

				if (str[i + 1] == '%')
				{
					// Print %, ignore
				}
				else if (str[i + 1] == 'A')
				{
					// MQTT v5 property topic-alias
				}
				else if (str[i + 1] == 'C')
				{
					// MQTT v5 property content-type
				}
				else if (str[i + 1] == 'D')
				{
					// MQTT v5 property correlation-data
				}
				else if (str[i + 1] == 'E')
				{
					// MQTT v5 property message-expiry-interval
				}
				else if (str[i + 1] == 'F')
				{
					// MQTT v5 property payload-format-indicator
				}
				else if (str[i + 1] == 'I')
				{
					// ISO 8601 date+time
				}
				else if (str[i + 1] == 'l')
				{
					// payload length
				}
				else if (str[i + 1] == 'm')
				{
					// mid
				}
				else if (str[i + 1] == 'P')
				{
					// MQTT v5 property user-property
				}
				else if (str[i + 1] == 'p')
				{
					// payload
				}
				else if (str[i + 1] == 'q')
				{
					// qos
				}
				else if (str[i + 1] == 'R')
				{
					// MQTT v5 property response-topic
				}
				else if (str[i + 1] == 'S')
				{
					// MQTT v5 property subscription-identifier
				}
				else if (str[i + 1] == 'r')
				{
					// retain
				}
				else if (str[i + 1] == 't')
				{
					// topic
				}
				else if (str[i + 1] == 'j')
				{
					// JSON output, escaped payload
				}
				else if (str[i + 1] == 'J')
				{
					// JSON output, assuming JSON payload
				}
				else if (str[i + 1] == 'U')
				{
					// Unix time+nanoseconds
				}
				else if (str[i + 1] == 'x' || str[i + 1] == 'X')
				{
					// payload in hex
				}
				else
				{
					fprintf(stderr, "Error: Invalid format specifier '%c'.\n", str[i + 1]);
					return 1;
				}
				i++;
			}
		}
		else if (str[i] == '@')
		{
			if (i == len - 1)
			{
				// error
				fprintf(stderr, "Error: Incomplete format specifier.\n");
				return 1;
			}
			i++;
		}
		else if (str[i] == '\\')
		{
			if (i == len - 1)
			{
				// error
				fprintf(stderr, "Error: Incomplete escape specifier.\n");
				return 1;
			}
			else
			{
				switch (str[i + 1])
				{
				case '\\': // '\'
				case '0':  // 0 (NULL)
				case 'a':  // alert
				case 'e':  // escape
				case 'n':  // new line
				case 'r':  // carriage return
				case 't':  // horizontal tab
				case 'v':  // vertical tab
					break;

				default:
					fprintf(stderr, "Error: Invalid escape specifier '%c'.\n", str[i + 1]);
					return 1;
				}
				i++;
			}
		}
	}

	return 0;
}

void init_config(struct mosq_config *cfg, int pub_or_sub)
{
	// memset(cfg, 0, sizeof(*cfg));
	// cfg->port = PORT_UNDEFINED;
	cfg->max_inflight = 20;
	cfg->keepalive = 60;
	cfg->clean_session = true;
	cfg->eol = true;
	cfg->protocol_version = MQTT_PROTOCOL_V5;
	cfg->session_expiry_interval = -1; /* -1 means unset here, the user can't set it to -1. */
}

void client_config_cleanup(struct mosq_config *cfg)
{
	int i;
	free(cfg->id);
	free(cfg->id_prefix);
	// free(cfg->host);
	free(cfg->brokers);

	free(cfg->topic);
	free(cfg->bind_address);
	free(cfg->username);
	free(cfg->password);
	free(cfg->will_topic);
	free(cfg->will_payload);
	free(cfg->format);
	free(cfg->response_topic);
#ifdef WITH_TLS
	free(cfg->cafile);
	free(cfg->capath);
	free(cfg->certfile);
	free(cfg->keyfile);
	free(cfg->ciphers);
	free(cfg->tls_alpn);
	free(cfg->tls_version);
	free(cfg->tls_engine);
	free(cfg->tls_engine_kpass_sha1);
	free(cfg->keyform);
#ifdef FINAL_WITH_TLS_PSK
	free(cfg->psk);
	free(cfg->psk_identity);
#endif
#endif
	if (cfg->topics)
	{
		for (i = 0; i < cfg->topic_count; i++)
		{
			free(cfg->topics[i]);
		}
		free(cfg->topics);
	}
	if (cfg->filter_outs)
	{
		for (i = 0; i < cfg->filter_out_count; i++)
		{
			free(cfg->filter_outs[i]);
		}
		free(cfg->filter_outs);
	}
	if (cfg->unsub_topics)
	{
		for (i = 0; i < cfg->unsub_topic_count; i++)
		{
			free(cfg->unsub_topics[i]);
		}
		free(cfg->unsub_topics);
	}
	mosquitto_property_free_all(&cfg->connect_props);
	mosquitto_property_free_all(&cfg->publish_props);
	mosquitto_property_free_all(&cfg->subscribe_props);
	mosquitto_property_free_all(&cfg->unsubscribe_props);
	mosquitto_property_free_all(&cfg->disconnect_props);
	mosquitto_property_free_all(&cfg->will_props);
	if (cfg->log_file)
		free(cfg->log_file);
	if (cfg->log_fptr)
	{
		fclose(cfg->log_fptr);
	}
}

int client_config_load(struct mosq_config *cfg, int pub_or_sub, const char *cfg_file)
{
	int rc;
	FILE *fptr;
	char line[1024];
	int count;
	size_t len;

	init_config(cfg, pub_or_sub);

	/* Default config file */

	/* Deal with real argc/argv */
	// rc = client_config_line_proc(cfg, pub_or_sub, argc, argv);
	rc = client_config__read_file(cfg, pub_or_sub, cfg_file, 0, &count);
	if (rc)
		return rc;

	if (cfg->will_payload && !cfg->will_topic)
	{
		fprintf(stderr, "Error: Will payload given, but no will topic given.\n");
		return 1;
	}
	if (cfg->will_retain && !cfg->will_topic)
	{
		fprintf(stderr, "Error: Will retain given, but no will topic given.\n");
		return 1;
	}
#ifdef WITH_TLS
	if ((cfg->certfile && !cfg->keyfile) || (cfg->keyfile && !cfg->certfile))
	{
		fprintf(stderr, "Error: Both certfile and keyfile must be provided if one of them is set.\n");
		return 1;
	}
	if ((cfg->keyform && !cfg->keyfile))
	{
		fprintf(stderr, "Error: If keyform is set, keyfile must be also specified.\n");
		return 1;
	}
	if ((cfg->tls_engine_kpass_sha1 && (!cfg->keyform || !cfg->tls_engine)))
	{
		fprintf(stderr, "Error: when using tls-engine-kpass-sha1, both tls-engine and keyform must also be provided.\n");
		return 1;
	}
#endif
#ifdef FINAL_WITH_TLS_PSK
	if ((cfg->cafile || cfg->capath) && cfg->psk)
	{
		fprintf(stderr, "Error: Only one of --psk or --cafile/--capath may be used at once.\n");
		return 1;
	}
	if (cfg->psk && !cfg->psk_identity)
	{
		fprintf(stderr, "Error: --psk-identity required if --psk used.\n");
		return 1;
	}
#endif

	if (cfg->protocol_version == 5)
	{
		if (cfg->clean_session == false && cfg->session_expiry_interval == -1)
		{
			/* User hasn't set session-expiry-interval, but has cleared clean
			 * session so default to persistent session. */
			cfg->session_expiry_interval = UINT32_MAX;
		}
		if (cfg->session_expiry_interval > 0)
		{
			if (cfg->session_expiry_interval == UINT32_MAX && (cfg->id_prefix || !cfg->id))
			{
				fprintf(stderr, "Error: You must provide a client id if you are using an infinite session expiry interval.\n");
				return 1;
			}
			rc = mosquitto_property_add_int32(&cfg->connect_props, MQTT_PROP_SESSION_EXPIRY_INTERVAL, (uint32_t)cfg->session_expiry_interval);
			if (rc)
			{
				fprintf(stderr, "Error adding property session-expiry-interval\n");
			}
		}
	}
	else
	{
		if (cfg->clean_session == false && (cfg->id_prefix || !cfg->id))
		{
			fprintf(stderr, "Error: You must provide a client id if you are using the -c option.\n");
			return 1;
		}
	}

	if (pub_or_sub == CLIENT_SUB)
	{
		if (cfg->topic_count == 0)
		{
			fprintf(stderr, "Error: You must specify a topic to subscribe to.\n");
			return 1;
		}
	}
	/*
	if(!cfg->host){
		cfg->host = strdup("localhost");
		if(!cfg->host){
			err_printf(cfg, "Error: Out of memory.\n");
			return 1;
		}
	}
	*/
	if (!cfg->brokers)
	{
		err_printf(cfg, "no brokers configured: \n");
		return 1;
	}

	rc = mosquitto_property_check_all(CMD_CONNECT, cfg->connect_props);
	if (rc)
	{
		err_printf(cfg, "Error in CONNECT properties: %s\n", mosquitto_strerror(rc));
		return 1;
	}
	rc = mosquitto_property_check_all(CMD_PUBLISH, cfg->publish_props);
	if (rc)
	{
		err_printf(cfg, "Error in PUBLISH properties: %s\n", mosquitto_strerror(rc));
		return 1;
	}
	rc = mosquitto_property_check_all(CMD_SUBSCRIBE, cfg->subscribe_props);
	if (rc)
	{
		err_printf(cfg, "Error in SUBSCRIBE properties: %s\n", mosquitto_strerror(rc));
		return 1;
	}
	rc = mosquitto_property_check_all(CMD_UNSUBSCRIBE, cfg->unsubscribe_props);
	if (rc)
	{
		err_printf(cfg, "Error in UNSUBSCRIBE properties: %s\n", mosquitto_strerror(rc));
		return 1;
	}
	rc = mosquitto_property_check_all(CMD_DISCONNECT, cfg->disconnect_props);
	if (rc)
	{
		err_printf(cfg, "Error in DISCONNECT properties: %s\n", mosquitto_strerror(rc));
		return 1;
	}
	rc = mosquitto_property_check_all(CMD_WILL, cfg->will_props);
	if (rc)
	{
		err_printf(cfg, "Error in Will properties: %s\n", mosquitto_strerror(rc));
		return 1;
	}

	return MOSQ_ERR_SUCCESS;
}

int cfg_add_topic(struct mosq_config *cfg, int type, char *topic, const char *arg)
{
	if (mosquitto_validate_utf8(topic, (int)strlen(topic)))
	{
		fprintf(stderr, "Error: Malformed UTF-8 in %s argument.\n\n", arg);
		return 1;
	}
	if (type == CLIENT_PUB || type == CLIENT_RR)
	{
		if (mosquitto_pub_topic_check(topic) == MOSQ_ERR_INVAL)
		{
			fprintf(stderr, "Error: Invalid publish topic '%s', does it contain '+' or '#'?\n", topic);
			return 1;
		}
		cfg->topic = strdup(topic);
	}
	else if (type == CLIENT_RESPONSE_TOPIC)
	{
		if (mosquitto_pub_topic_check(topic) == MOSQ_ERR_INVAL)
		{
			fprintf(stderr, "Error: Invalid response topic '%s', does it contain '+' or '#'?\n", topic);
			return 1;
		}
		cfg->response_topic = strdup(topic);
	}
	else
	{
		if (mosquitto_sub_topic_check(topic) == MOSQ_ERR_INVAL)
		{
			fprintf(stderr, "Error: Invalid subscription topic '%s', are all '+' and '#' wildcards correct?\n", topic);
			return 1;
		}
		cfg->topic_count++;
		cfg->topics = realloc(cfg->topics, (size_t)cfg->topic_count * sizeof(char *));
		if (!cfg->topics)
		{
			err_printf(cfg, "Error: Out of memory.\n");
			return 1;
		}
		cfg->topics[cfg->topic_count - 1] = strdup(topic);
	}
	return 0;
}

int client_opts_set(struct mosquitto *mosq, struct mosq_config *cfg)
{
#if defined(WITH_TLS)
	int rc;
#endif

	mosquitto_int_option(mosq, MOSQ_OPT_PROTOCOL_VERSION, cfg->protocol_version);

	if (cfg->will_topic && mosquitto_will_set_v5(mosq, cfg->will_topic,
												 cfg->will_payloadlen, cfg->will_payload, cfg->will_qos,
												 cfg->will_retain, cfg->will_props))
	{

		err_printf(cfg, "Error: Problem setting will.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
	cfg->will_props = NULL;

	if ((cfg->username || cfg->password) && mosquitto_username_pw_set(mosq, cfg->username, cfg->password))
	{
		err_printf(cfg, "Error: Problem setting username and/or password.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
#ifdef WITH_TLS
	if (cfg->cafile || cfg->capath)
	{
		rc = mosquitto_tls_set(mosq, cfg->cafile, cfg->capath, cfg->certfile, cfg->keyfile, NULL);
		if (rc)
		{
			if (rc == MOSQ_ERR_INVAL)
			{
				err_printf(cfg, "Error: Problem setting TLS options: File not found.\n");
			}
			else
			{
				err_printf(cfg, "Error: Problem setting TLS options: %s.\n", mosquitto_strerror(rc));
			}
			mosquitto_lib_cleanup();
			return 1;
		}
	} /*

		 else if(cfg->port == 8883){
		 mosquitto_int_option(mosq, MOSQ_OPT_TLS_USE_OS_CERTS, 1);
	 }
	 */
	if (cfg->tls_use_os_certs)
	{
		mosquitto_int_option(mosq, MOSQ_OPT_TLS_USE_OS_CERTS, 1);
	}

	if (cfg->insecure && mosquitto_tls_insecure_set(mosq, true))
	{
		err_printf(cfg, "Error: Problem setting TLS insecure option.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
	if (cfg->tls_engine && mosquitto_string_option(mosq, MOSQ_OPT_TLS_ENGINE, cfg->tls_engine))
	{
		err_printf(cfg, "Error: Problem setting TLS engine, is %s a valid engine?\n", cfg->tls_engine);
		mosquitto_lib_cleanup();
		return 1;
	}
	if (cfg->keyform && mosquitto_string_option(mosq, MOSQ_OPT_TLS_KEYFORM, cfg->keyform))
	{
		err_printf(cfg, "Error: Problem setting key form, it must be one of 'pem' or 'engine'.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
	if (cfg->tls_engine_kpass_sha1 && mosquitto_string_option(mosq, MOSQ_OPT_TLS_ENGINE_KPASS_SHA1, cfg->tls_engine_kpass_sha1))
	{
		err_printf(cfg, "Error: Problem setting TLS engine key pass sha, is it a 40 character hex string?\n");
		mosquitto_lib_cleanup();
		return 1;
	}
	if (cfg->tls_alpn && mosquitto_string_option(mosq, MOSQ_OPT_TLS_ALPN, cfg->tls_alpn))
	{
		err_printf(cfg, "Error: Problem setting TLS ALPN protocol.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
#ifdef FINAL_WITH_TLS_PSK
	if (cfg->psk && mosquitto_tls_psk_set(mosq, cfg->psk, cfg->psk_identity, NULL))
	{
		err_printf(cfg, "Error: Problem setting TLS-PSK options.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
#endif
	if ((cfg->tls_version || cfg->ciphers) && mosquitto_tls_opts_set(mosq, 1, cfg->tls_version, cfg->ciphers))
	{
		err_printf(cfg, "Error: Problem setting TLS options, check the options are valid.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
#endif
	mosquitto_max_inflight_messages_set(mosq, cfg->max_inflight);
	if (cfg->tcp_nodelay)
	{
		mosquitto_int_option(mosq, MOSQ_OPT_TCP_NODELAY, 1);
	}
	return MOSQ_ERR_SUCCESS;
}

int client_id_generate(struct mosq_config *cfg)
{
	if (cfg->id_prefix)
	{
		cfg->id = malloc(strlen(cfg->id_prefix) + 10);
		if (!cfg->id)
		{
			err_printf(cfg, "Error: Out of memory.\n");
			mosquitto_lib_cleanup();
			return 1;
		}
		snprintf(cfg->id, strlen(cfg->id_prefix) + 10, "%s%d", cfg->id_prefix, getpid());
	}
	return MOSQ_ERR_SUCCESS;
}

void err_printf(const struct mosq_config *cfg, const char *fmt, ...)
{
	va_list va;

	if (cfg->quiet)
		return;

	va_start(va, fmt);
	vfprintf(stderr, fmt, va);
	va_end(va);
}
