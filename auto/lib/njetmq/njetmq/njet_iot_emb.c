/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#include "config.h"

#ifndef WIN32
/* For initgroups() */
#include <unistd.h>
#include <grp.h>
#include <assert.h>
#endif

#ifndef WIN32
#include <pwd.h>
#else
#include <process.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#ifndef WIN32
#include <sys/time.h>
#endif

#include <errno.h>
// #include <signal.h>
#include <stdio.h>
#include <string.h>
#ifdef WITH_SYSTEMD
#include <systemd/sd-daemon.h>
#endif
#ifdef WITH_WRAP
#include <tcpd.h>
#endif
#ifdef WITH_WEBSOCKETS
#include <libwebsockets.h>
#endif
#include <signal.h>

#include "njet_iot_internal.h"
#include "memory_mosq.h"
#include "misc_mosq.h"
#include "njet_iot_util_mosq.h"

struct mosquitto_db db;
static struct mosquitto__listener_sock *listensock = NULL;
static int listensock_count = 0;
static int listensock_index = 0;
static struct mosq_iot *ctx = NULL;
static struct mosq_iot *ctx_tmp = NULL;
static const char empty_server_conf_file[] = "/dev/shm/njetmq-server-XXXXXX";

static int quit_flag = 0;
#ifdef WITH_PERSISTENCE
bool flag_db_backup = false;
#endif
bool flag_tree_print = false;
// int run;
#ifdef WITH_WRAP
#include <syslog.h>
int allow_severity = LOG_INFO;
int deny_severity = LOG_INFO;
#endif

#include "njet_iot_emb.h"

void listener__set_defaults(struct mosquitto__listener *listener)
{
	listener->security_options.allow_anonymous = -1;
	listener->security_options.allow_zero_length_clientid = true;
	listener->protocol = mp_mqtt;
	listener->max_connections = -1;
	listener->max_qos = 2;
	listener->max_topic_alias = 10;
}

void listeners__reload_all_certificates()
{
#ifdef WITH_TLS
	int i;
	int rc;
	struct mosquitto__listener *listener;

	for (i = 0; i < db.config->listener_count; i++)
	{
		listener = &db.config->listeners[i];
		if (listener->ssl_ctx && listener->certfile && listener->keyfile)
		{
			rc = net__load_certificates(listener);
			if (rc)
			{
				iot_log__printf(NULL, MOSQ_LOG_ERR, "Error when reloading certificate '%s' or key '%s'.",
								listener->certfile, listener->keyfile);
			}
		}
	}
#endif
}

int listeners__start_single_mqtt(struct mosquitto__listener *listener)
{
	int i;
	struct mosquitto__listener_sock *listensock_new;

	if (net__socket_listen(listener))
	{
		return 1;
	}
	listensock_count += listener->sock_count;
	listensock_new = mosquitto__realloc(listensock, sizeof(struct mosquitto__listener_sock) * (size_t)listensock_count);
	if (!listensock_new)
	{
		return 1;
	}
	listensock = listensock_new;

	for (i = 0; i < listener->sock_count; i++)
	{
		if (listener->socks[i] == INVALID_SOCKET)
		{
			return 1;
		}
		listensock[listensock_index].sock = listener->socks[i];
		listensock[listensock_index].listener = listener;
#ifdef WITH_EPOLL
		listensock[listensock_index].ident = id_listener;
#endif
		listensock_index++;
	}
	return MOSQ_ERR_SUCCESS;
}

int listeners__add_local(const char *host, uint16_t port)
{
	struct mosquitto__listener *listeners;
	listeners = db.config->listeners;

	listener__set_defaults(&listeners[db.config->listener_count]);
	listeners[db.config->listener_count].security_options.allow_anonymous = true;
	listeners[db.config->listener_count].port = port;
	if (port == 0)
	{
#ifdef WITH_UNIX_SOCKETS
		listeners[db.config->listener_count].host = NULL;
		listeners[db.config->listener_count].unix_socket_path = mosquitto__strdup(host);
		if (listeners[db.config->listener_count].unix_socket_path == NULL)
		{
			return MOSQ_ERR_NOMEM;
		}
#else
		iot_log__printf(NULL, MOSQ_LOG_ERR, " unix sockets support should be compiled into code");
		return MOSQ_ERR_NOT_SUPPORTED;
#endif
	}
	else
	{
		listeners[db.config->listener_count].host = mosquitto__strdup(host);
		if (listeners[db.config->listener_count].host == NULL)
		{
			return MOSQ_ERR_NOMEM;
		}
	}
	if (listeners__start_single_mqtt(&listeners[db.config->listener_count]))
	{
		mosquitto__free(listeners[db.config->listener_count].host);
		listeners[db.config->listener_count].host = NULL;
		return MOSQ_ERR_UNKNOWN;
	}
	db.config->listener_count++;
	return MOSQ_ERR_SUCCESS;
}

int listeners__start_local_only(void)
{
	/* Attempt to open listeners locally */
	int i;
	int rc;
	struct mosquitto__listener *listeners;

	listeners = mosquitto__realloc(db.config->listeners, 2 * sizeof(struct mosquitto__listener));
	if (listeners == NULL)
	{
		return MOSQ_ERR_NOMEM;
	}
	memset(listeners, 0, 2 * sizeof(struct mosquitto__listener));
	db.config->listener_count = 0;
	db.config->listeners = listeners;

	iot_log__printf(NULL, MOSQ_LOG_DEBUG, "Starting in local only mode. Connections will only be possible from clients running on this machine.");
	iot_log__printf(NULL, MOSQ_LOG_DEBUG, "Create a configuration file which defines a listener to allow remote access.");
	if (db.config->cmd_port_count == 0)
	{
		char *prefix = db.config->prefix;
		char *tmp_pchar;

		char *unix_sock_file = malloc(strlen(prefix) + 20 + 1); // $prefix/data/mosquitto.sock";
		if (!unix_sock_file) {
			return MOSQ_ERR_NOMEM;
		}
		tmp_pchar = unix_sock_file;
		memcpy(tmp_pchar, prefix, strlen(prefix));
		memcpy(tmp_pchar + strlen(prefix), "/data/mosquitto.sock", 20);
		tmp_pchar[strlen(prefix) + 20] = '\0';

		rc = listeners__add_local(unix_sock_file, 0);
		free(unix_sock_file);
		if (rc == MOSQ_ERR_NOMEM)
			return MOSQ_ERR_NOMEM;
	}
	else
	{
		for (i = 0; i < db.config->cmd_port_count; i++)
		{
			rc = listeners__add_local("127.0.0.1", db.config->cmd_port[i]);
			if (rc == MOSQ_ERR_NOMEM)
				return MOSQ_ERR_NOMEM;
			rc = listeners__add_local("::1", db.config->cmd_port[i]);
			if (rc == MOSQ_ERR_NOMEM)
				return MOSQ_ERR_NOMEM;
		}
	}

	if (db.config->listener_count > 0)
	{
		return MOSQ_ERR_SUCCESS;
	}
	else
	{
		return MOSQ_ERR_UNKNOWN;
	}
}

int listeners__start(void)
{
	int i;

	listensock_count = 0;
	if (db.config->listener_count == 0)
	{
		if (listeners__start_local_only())
		{
			db__close();
			return 1;
		}
		return MOSQ_ERR_SUCCESS;
	}

	for (i = 0; i < db.config->listener_count; i++)
	{
		if (db.config->listeners[i].protocol == mp_mqtt)
		{
			if (listeners__start_single_mqtt(&db.config->listeners[i]))
			{
				db__close();
				return 1;
			}
		}
		else if (db.config->listeners[i].protocol == mp_websockets)
		{
		}
	}
	if (listensock == NULL)
	{
		iot_log__printf(NULL, MOSQ_LOG_ERR, "Error: Unable to start any listening sockets, exiting.");
		return 1;
	}
	return MOSQ_ERR_SUCCESS;
}

void listeners__stop(void)
{
	int i;
	for (i = 0; i < db.config->listener_count; i++)
	{
#ifdef WITH_WEBSOCKETS
		if (db.config->listeners[i].ws_context)
		{
			lws_context_destroy(db.config->listeners[i].ws_context);
		}
		mosquitto__free(db.config->listeners[i].ws_protocol);
#endif
#ifdef WITH_UNIX_SOCKETS
		if (db.config->listeners[i].unix_socket_path != NULL)
		{
			unlink(db.config->listeners[i].unix_socket_path);
		}
#endif
	}

	for (i = 0; i < listensock_count; i++)
	{
		if (listensock[i].sock != INVALID_SOCKET)
		{
			COMPAT_CLOSE(listensock[i].sock);
		}
	}
	mosquitto__free(listensock);
}
void handle_sighup(int signal)
{
	UNUSED(signal);

	quit_flag = 1;
}

static void signal__setup(void)
{
	signal(SIGHUP, handle_sighup);
}

int njet_iot_init(const char *prefix, const char *config_file)
{
	struct mosquitto__config *config;
	struct timeval tv;
	char nameBuff[32] = {0};
	int rc;
	int argc = 3;
	char *argv[3];

	argv[0] = "emb_mqtt";
	argv[1] = "-c";
	argv[2] = (char *)config_file;
	if (config_file == NULL || strlen(config_file) == 0)
	{
		strncpy(nameBuff, empty_server_conf_file, 30);
		rc = mkstemp((char *)nameBuff);
		if (rc == -1)
		{
			fprintf(stderr, "can't create tmp file \"%s\" e\n", nameBuff);
			return 1;
		}
		argv[2] = nameBuff;
	}

	gettimeofday(&tv, NULL);
	srand((unsigned int)(tv.tv_sec + tv.tv_usec));

	memset(&db, 0, sizeof(struct mosquitto_db));
	db.now_s = mosquitto_time();
	db.now_real_s = time(NULL);
	config = malloc(sizeof(struct mosquitto__config));
	db.config = config;
	net__iot_init();
	config__init(config);
	config->prefix = (char *)prefix;

	rc = config__parse_args(config, argc, argv);
	if (config_file == NULL || strlen(config_file) == 0)
	{
		unlink(nameBuff);
	}
	if (rc != MOSQ_ERR_SUCCESS)
		return rc;

	rc = db__open(config);
	if (rc != MOSQ_ERR_SUCCESS)
	{
		iot_log__printf(NULL, MOSQ_LOG_ERR, "Error: Couldn't open database.");
		return rc;
	}

	if (log__init(config))
	{
		rc = 1;
		return rc;
	}

	iot_log__printf(NULL, MOSQ_LOG_INFO, "mosquitto version %s starting", VERSION);

	rc = mosquitto_security_module_init();
	if (rc)
		return rc;
	rc = mosquitto_security_init(false);
	if (rc)
		return rc;
	HASH_ITER(hh_id, db.contexts_by_id, ctx, ctx_tmp)
	{
		if (ctx && !ctx->clean_start && ctx->username)
		{
			rc = acl__find_acls(ctx);
			if (rc)
			{
				iot_log__printf(NULL, MOSQ_LOG_WARNING, "Failed to associate persisted user %s with ACLs, "
														"likely due to changed ports while using a per_listener_settings configuration.",
								ctx->username);
			}
		}
	}

	if (listeners__start())
		return 1;
	signal__setup();

#ifdef WITH_BRIDGE
	bridge__start_all();
#endif
#ifdef WITH_PERSISTENCE
	time_t last_backup = mosquitto_time();
#endif
	db.now_s = mosquitto_time();
	db.now_real_s = time(NULL);

	rc = iot_mux__init(listensock, listensock_count);
	if (rc)
		return rc;

#ifdef WITH_BRIDGE
	rc = bridge__register_local_connections();
	if (rc)
		return rc;
#endif

	iot_log__printf(NULL, MOSQ_LOG_INFO, "mosquitto version %s running", VERSION);
	return 0;
}

int njet_iot_run()
{
	if (quit_flag)
		return -8888;
	return iot_main_loop(listensock, listensock_count);
}

int njet_iot_exit()
{
	int i, rc = 0;
	iot_mux__cleanup();
	iot_log__printf(NULL, MOSQ_LOG_INFO, "mosquitto version %s terminating", VERSION);
	HASH_ITER(hh_id, db.contexts_by_id, ctx, ctx_tmp)
	{
		context__send_will(ctx);
	}
	iot_will_delay__send_all();
#ifdef WITH_PERSISTENCE
	persist__backup(true);
#endif
	session_expiry__remove_all();

	listeners__stop();

	HASH_ITER(hh_id, db.contexts_by_id, ctx, ctx_tmp)
	{
		{
			context__cleanup(ctx, true);
		}
	}
#ifdef WITH_BRIDGE
	for (i = 0; i < db.bridge_count; i++)
	{
		if (db.bridges[i])
		{
			context__cleanup(db.bridges[i], true);
		}
	}
	mosquitto__free(db.bridges);
#endif
	context__free_disused();

	db__close();

	mosquitto_security_module_cleanup();

	log__close(db.config);
	config__cleanup(db.config);
	// todo: free confi structure
	net__iot_cleanup();

	return rc;
}
