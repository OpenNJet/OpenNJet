/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#include "njet_iot_emb.h"
#include "config.h"
#include "mqtt_protocol.h"
#include <stdlib.h>
#include "mosquitto.h"

#include "njet_iot_shared.h"
#include "logging_mosq.h"

#include "mosquitto_internal.h"

#include <unistd.h>
#include <string.h>
#include <libgen.h>
#include <strings.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "lmdb.h"
#include "util_mosq.h"
#define SNAP_SEGMENT_SIZE 16384

struct evt_ctx_t
{
	struct mosquitto *mosq;
	int connected; // 0 not start or connected failed; 1:connecting, 2 connected ok
	struct MDB_env *kv_env;
	msg_resp_pt resp_callback;
	msg_pt msg_callback;
	struct mosq_config *cfg;
	void *data;
};

// struct evt_ctx_t ctx={NULL,NULL,0,NULL,NULL,0,NULL,0,NULL,NULL};
// static struct mosq_config cfg;

static int njet_iot_client_instances = 0;
static const char empty_client_conf_file[] = "/dev/shm/njetmq-client-XXXXXX";

void my_connect_callback(struct mosquitto *mosq, void *obj, int result, int flags, const mosquitto_property *properties)
{
	struct evt_ctx_t *ctx_ptr = (struct evt_ctx_t *)obj;
	struct mosq_config *cfg = ctx_ptr->cfg;
	int i;
	UNUSED(flags);
	UNUSED(properties);
	if (!result)
	{
		log__printf(mosq, MOSQ_LOG_INFO, "Connection ok");
		mosquitto_subscribe_multiple(mosq, NULL, cfg->topic_count, cfg->topics, cfg->qos, cfg->sub_opts, cfg->subscribe_props);
		ctx_ptr->connected = 2;
		for (i = 0; i < cfg->unsub_topic_count; i++)
		{
			mosquitto_unsubscribe_v5(mosq, NULL, cfg->unsub_topics[i], cfg->unsubscribe_props);
		}
	}
	else
	{
		if (result)
		{
			ctx_ptr->connected = 0;
			if (cfg->protocol_version == MQTT_PROTOCOL_V5)
			{
				if (result == MQTT_RC_UNSUPPORTED_PROTOCOL_VERSION)
				{
					log__printf(mosq, MOSQ_LOG_WARNING, "Connection error: %s. Try connecting to an MQTT v5 broker, or use MQTT v3.x mode.", mosquitto_reason_string(result));
				}
				else
				{
					log__printf(mosq, MOSQ_LOG_WARNING, "Connection error: %s", mosquitto_reason_string(result));
				}
			}
			else
			{
				log__printf(mosq, MOSQ_LOG_WARNING, "Connection error: %s", mosquitto_connack_string(result));
			}
		}
		mosquitto_disconnect_v5(mosq, 0, cfg->disconnect_props);
	}
}

void my_subscribe_callback(struct mosquitto *mosq, void *obj, int mid, int qos_count, const int *granted_qos)
{
}
void my_log_callback(struct mosquitto *mosq, void *obj, int level, const char *str)
{
	struct timeval curTime;
	struct tm nowTime;
	int mill;
	char log_line[1000];
	size_t log_line_pos;
	struct evt_ctx_t *ctx_ptr = (struct evt_ctx_t *)obj;
	struct mosq_config *cfg = ctx_ptr->cfg;
	UNUSED(mosq);
	// UNUSED(obj);

	gettimeofday(&curTime, NULL);
	mill = curTime.tv_usec / 1000;
	localtime_r(&curTime.tv_sec, &nowTime);
	log_line_pos = strftime(log_line, sizeof(log_line), "%Y/%m/%d %H:%M:%S:", &nowTime);
	sprintf(log_line + log_line_pos, "%03d [%02d]", mill, level);
	log_line_pos += 3 + 5;
	if (log_line_pos < sizeof(log_line) - 2)
	{
		log_line[log_line_pos] = ' ';
		log_line[log_line_pos + 1] = '\0';
		log_line_pos += 1;
	}
	snprintf(&log_line[log_line_pos], sizeof(log_line) - log_line_pos, "%s", str);
	log_line[sizeof(log_line) - 1] = '\0'; /* Ensure string is null terminated. */

	if ((cfg->log_fptr) && (cfg->log_type & level))
		fprintf(cfg->log_fptr, "%s\n", log_line);
}

void my_message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message, const mosquitto_property *properties)
{
	int i, identifier;
	bool res;
	int session_id = 0;
	const mosquitto_property *prop;
	char *resp_topic = NULL;

	struct evt_ctx_t *ctx = (struct evt_ctx_t *)obj;
	struct mosq_config *cfg = ctx->cfg;
	int topic_len = strlen(message->topic);

	if (properties != NULL)
	{ // means rpc message
		int *cor_id = NULL;
		uint16_t i16value;
		if (mosquitto_property_read_binary(properties, MQTT_PROP_CORRELATION_DATA, (void **)&cor_id, &i16value, false))
		{
			log__printf(ctx->mosq, MOSQ_LOG_ERR, "received cor data:%d,size:%d", *cor_id, i16value);
			session_id = *cor_id;
			free(cor_id);
		}
		mosquitto_property_read_string(properties, MQTT_PROP_RESPONSE_TOPIC, &resp_topic, false);
                if (resp_topic == NULL) 
                {
                  log__printf(ctx->mosq, MOSQ_LOG_ERR, "received a message with properties but can't get resp topic from it");
                  return; 
                }

		if (strlen(resp_topic) == strlen(message->topic) &&
			memcmp(resp_topic, message->topic, strlen(message->topic)) == 0)
		{
			if (ctx->resp_callback)
			{
				int out_len;
				ctx->resp_callback(message->topic, 1, message->payload, message->payloadlen, session_id, &out_len);
				goto endrr;
			}
			else
			{
				log__printf(ctx->mosq, MOSQ_LOG_ERR, "received a  rpc response message, but no callback configured");
				goto endrr;
			}
		}
		else
		{ // tips: means request
			if (ctx->resp_callback)
			{
				int out_len;
				char *rr_reply =
					ctx->resp_callback(message->topic, 0, message->payload, message->payloadlen, session_id, &out_len);
				if (rr_reply)
				{
					njet_iot_client_sendmsg_rr(resp_topic, rr_reply, out_len, 0, session_id, 1, ctx);
					free(rr_reply);
				}
				goto endrr;
			}
			else
			{
				log__printf(ctx->mosq, MOSQ_LOG_ERR, "received a  rpc response message, but no callback configured");
				goto endrr;
			}
		}
	endrr:
		free(resp_topic);
		return;
	}

	if (ctx->msg_callback)
	{
		int callback_ret = ctx->msg_callback(message->topic, message->payload, message->payloadlen, ctx->data);
		log__printf(ctx->mosq, MOSQ_LOG_ERR, "callback process msg of topic:%s, %d", message->topic, callback_ret);
		if (callback_ret != 1)
		{
			if (callback_ret != 0)
				log__printf(ctx->mosq, MOSQ_LOG_ERR, "callback process msg of topic:%s failed:%d", message->topic, callback_ret);
			return;
		}
	}
	if (resp_topic)
		free(resp_topic);
	return;
}

void my_publish_callback(struct mosquitto *mosq, void *obj, int mid, int reason_code, const mosquitto_property *properties)
{
	char *reason_string = NULL;
	// UNUSED(obj);
	UNUSED(properties);

	if (reason_code > 127)
	{
		log__printf(mosq, MOSQ_LOG_WARNING, "Publish %d failed: %s.", mid, mosquitto_reason_string(reason_code));
		mosquitto_property_read_string(properties, MQTT_PROP_REASON_STRING, &reason_string, false);
		if (reason_string)
		{
			log__printf(mosq, MOSQ_LOG_WARNING, "%s", reason_string);
			free(reason_string);
		}
	}
	else
	{
		log__printf(mosq, MOSQ_LOG_INFO, "Publish %d  ok");
	}
}

int njet_iot_client_pub_kv(const u_char *cluster, u_int32_t c_l, const u_char *key, u_int32_t key_l, const u_char *val, u_int32_t val_l, struct evt_ctx_t *ctx)
{
	char kv_topic[128]; // topic is like /cluster/{$cluster_name}/kv_set/{$var}

	memset(kv_topic, 0, 128);
	strcpy(kv_topic, "/cluster/");
	memcpy(kv_topic + 9, cluster, c_l);
	strcpy(kv_topic + 9 + c_l, "/kv_set/");
	memcpy(kv_topic + 9 + c_l + 8, key, key_l);

	int out_size = sizeof(int) + key_l + 1 + val_l + 1;
	int mid = mosquitto__mid_generate(ctx->mosq);
	char *p, *buf = malloc(out_size);
	memset(buf, 0, out_size);

	p = buf;
	memcpy(p, &mid, sizeof(int));

	p += sizeof(int);
	memcpy(p, key, key_l);
	p += key_l + 1;
	memcpy(p, val, val_l);
	int ret = mosquitto_publish_v5(ctx->mosq, NULL, kv_topic, out_size, buf, 0, 1, NULL);
	free(buf);
	if (ret < 0)
	{
		log__printf(ctx->mosq, MOSQ_LOG_INFO, "publish kv msg failed:%d", ret);
		return -1;
	}
	else
	{
		log__printf(ctx->mosq, MOSQ_LOG_INFO, "publish kv msg ok, mid:%d", mid);
		return 0;
	}
}
int njet_iot_client_sendmsg(const char *topic, const void *msg, int l, int qos, struct evt_ctx_t *ctx)
{
	int mid = 0;
	int retained = 0;
	if (!ctx)
	{
		return MOSQ_ERR_INVAL;
	}
	if (qos >= 16)
	{
		qos = qos - 16;
		retained = 1;
	}
	int ret = mosquitto_publish_v5(ctx->mosq, &mid, topic, l, msg, qos, retained, NULL);
	if (ret < 0)
		return ret;
	else
		return mid;
}
int njet_iot_client_sendmsg_rr(const char *topic, const void *msg, int l, int qos, int session_id, int is_reply, struct evt_ctx_t *ctx)
{
	int mid = 0;
	int rc;
	int retained = 0;
	mosquitto_property *proplist = NULL;
	if (!ctx)
	{
		return MOSQ_ERR_INVAL;
	}
	if (qos >= 16)
	{
		qos = qos - 16;
		retained = 1;
	}
	struct mosq_config *cfg = ctx->cfg;
	char resp_topic[128] = {0};
	if (is_reply == 1)
		strcpy(resp_topic, topic);
	else
		snprintf(resp_topic, 128, "%s_rcp_resp", cfg->id);

	rc = mosquitto_property_add_string(&proplist, MQTT_PROP_RESPONSE_TOPIC, resp_topic);
	if (rc)
	{
		log__printf(ctx->mosq, MOSQ_LOG_ERR, "err add MQTT_PROP_RESPONSE_TOPIC:%s,%d", resp_topic, rc);
		goto cleanup;
	}
	rc = mosquitto_property_add_binary(&proplist, MQTT_PROP_CORRELATION_DATA, (void **)&session_id, sizeof(int));
	if (rc)
	{
		log__printf(ctx->mosq, MOSQ_LOG_ERR, "err add MQTT_PROP_CORRELATION_DATA:%d", rc);
		goto cleanup;
	}
	rc = mosquitto_publish_v5(ctx->mosq, &mid, topic, l, msg, qos, retained, proplist);
	// log__printf(ctx.mosq,MOSQ_LOG_ERR,"publish v5:%s,%d",resp_topic,rc);
cleanup:
	mosquitto_property_free_all(&proplist);
	if (rc < 0)
		return rc;
	else
		return mid;
}
struct evt_ctx_t *njet_iot_client_init(const char *prefix, const char *cfg_file, msg_resp_pt resp_pt, msg_pt msg_callback, const char *client_id, const char *log_file, void *out_data)
{
	int ret;
	int i;
	char *cfg_dir, *tmp_name;
	char nameBuff[32];
	MDB_envinfo info;
	struct evt_ctx_t *ctx;
	struct mosq_config *cfg;
	if (njet_iot_client_instances == 0)
	{
		ret = mosquitto_lib_init();
		if (ret != MOSQ_ERR_SUCCESS)
			return NULL;
		njet_iot_client_instances++;
	}
	ctx = malloc(sizeof(struct evt_ctx_t));
	if (ctx==NULL) return NULL;
	memset(ctx, 0, sizeof(struct evt_ctx_t));
	ctx->data = out_data;
        ctx->resp_callback = resp_pt;
	ctx->msg_callback = msg_callback;

	ret = mdb_env_create(&ctx->kv_env);
	if (ret != 0)
		return NULL;
	mdb_env_set_mapsize(ctx->kv_env, 1024 * 1024 * 4);

	cfg = malloc(sizeof(struct mosq_config));
	if (cfg==NULL) {
		free(ctx);
		return NULL;
	}
	memset(cfg, 0, sizeof(*cfg));

	if (client_id)
		cfg->id = strdup(client_id);
	if (log_file)
		cfg->log_file = strdup(log_file);

	cfg->prefix = (char *)prefix;

	if (cfg_file == NULL || strlen(cfg_file) == 0)
	{
		strncpy(nameBuff, empty_client_conf_file, 30);
		ret = mkstemp((char *)nameBuff);
		if (ret == -1)
		{
			fprintf(stderr, "can't create tmp file \"%s\" e\n", nameBuff);
			goto INIT_ERR;
		}
		cfg_file = nameBuff;
	}
	ret = client_config_load(cfg, CLIENT_SUB, cfg_file);
	unlink(nameBuff);
	if (ret != MOSQ_ERR_SUCCESS)
		goto INIT_ERR;
	ctx->cfg = cfg;
	if (cfg->kv_store)
	{
		ret = mdb_env_open(ctx->kv_env, cfg->kv_store, MDB_MAPASYNC | MDB_WRITEMAP, 0666);
		if (ret != 0)
		{
			fprintf(stderr, "mdb directory \"%s\" open error, check config file\n", cfg->kv_store);
			goto INIT_ERR;
		}
	}

	if (client_id_generate(cfg))
	{
		goto INIT_ERR;
	}
	ctx->mosq = mosquitto_new(cfg->id, false, ctx);
	if (ctx->mosq == NULL)
	{
		goto INIT_ERR;
	}
	mosquitto_log_callback_set(ctx->mosq, my_log_callback);

	mosquitto_connect_v5_callback_set(ctx->mosq, my_connect_callback);
	mosquitto_publish_v5_callback_set(ctx->mosq, my_publish_callback);
	mosquitto_subscribe_callback_set(ctx->mosq, my_subscribe_callback);
	mosquitto_message_v5_callback_set(ctx->mosq, my_message_callback);

	if (client_opts_set(ctx->mosq, ctx->cfg))
	{
		goto INIT_ERR;
	}
	return ctx;
INIT_ERR:
	free(ctx);
	free(cfg);
        return NULL;
};
int njet_iot_client_connect(int retries, int interval, struct evt_ctx_t *ctx)
{
	int ret;
	struct mosq_config *cfg = ctx->cfg;
	if (cfg->broker_used == NULL || cfg->broker_used->host[0] == '\0')
		cfg->broker_used = cfg->brokers;
	// if it is connecting or connected, return -5, it means no need to reconnect, and  -5 is not used in MQTT ERROR Code
	if (ctx->connected == 2 || ctx->connected == 1)
	{
		return -5;
	}
	log__printf(ctx->mosq, MOSQ_LOG_INFO, "try connect to:%s,%d", cfg->broker_used->host, cfg->broker_used->port);
	ret = mosquitto_connect(ctx->mosq, cfg->broker_used->host, cfg->broker_used->port, cfg->keepalive);
	cfg->broker_used++;
	ctx->connected = 1;
	ret = mosquitto_loop_write(ctx->mosq, 1);
	if (ret != 0)
	{
		ctx->connected = 0;
	}
	return ret;
}
int njet_iot_client_run(struct evt_ctx_t *ctx)
{
	int ret = mosquitto_loop(ctx->mosq, 1, 1);
	if (ret != 0)
	{
		ctx->connected = 0;
	}
	return ret;
}
void njet_iot_client_exit(struct evt_ctx_t *ctx)
{
	if (ctx == NULL)
		return;
	if (ctx->mosq)
	{
		mosquitto_destroy(ctx->mosq);
	}
	if (ctx->kv_env)
		mdb_env_close(ctx->kv_env);
	// todo: use a ref , to clean up
	njet_iot_client_instances--;
	if (njet_iot_client_instances <= 0)
		mosquitto_lib_cleanup();
	client_config_cleanup(ctx->cfg);
	free(ctx);
};
int njet_iot_client_socket(struct evt_ctx_t *ctx)
{
	return mosquitto_socket(ctx->mosq);
};
int njet_iot_client_kv_get(void *key, u_int32_t key_len, void **val, u_int32_t *val_len, struct evt_ctx_t *ctx)
{
	MDB_txn *txn;
	MDB_dbi dbi;
	MDB_val mk, mv;
	if (!ctx)
	{
		return MOSQ_ERR_INVAL;
	}
	int ret = mdb_txn_begin(ctx->kv_env, NULL, MDB_RDONLY, &txn);
	if (ret != 0)
	{
		MDB_envinfo info;
		mdb_env_info(ctx->kv_env, &info);
		log__printf(ctx->mosq, MOSQ_LOG_ERR, "mdb:reads%d:%d", info.me_maxreaders, info.me_numreaders);
		log__printf(ctx->mosq, MOSQ_LOG_INFO, "get open trans failed:%d", ret);
		return -1;
	}
	ret = mdb_dbi_open(txn, NULL, MDB_CREATE, &dbi);
	if (ret != 0)
	{
		log__printf(ctx->mosq, MOSQ_LOG_INFO, "open db failed:%d", ret);
		mdb_txn_abort(txn);
		return -1;
	}
	mk.mv_data = key;
	mk.mv_size = key_len;
	ret = mdb_get(txn, dbi, &mk, &mv);
	if (ret != 0)
	{
		log__printf(ctx->mosq, MOSQ_LOG_INFO, "kv_get failed:%d,maybe not found", ret);
		mdb_txn_abort(txn);
		return -1;
	}
	*val = mv.mv_data;
	*val_len = mv.mv_size;
	mdb_txn_abort(txn);
	return 0;
}
int njet_iot_client_kv_set(const void *key, u_int32_t key_len, const void *val, u_int32_t val_len, const void *data, struct evt_ctx_t *ctx)
{
	MDB_txn *txn;
	MDB_dbi dbi;
	MDB_val mk, mv;
	if (!ctx)
	{
		return MOSQ_ERR_INVAL;
	}
	// log__printf(ctx.mosq,MOSQ_LOG_INFO,"kv set begin");
	int ret = mdb_txn_begin(ctx->kv_env, NULL, 0, &txn);
	if (ret != 0)
	{
		log__printf(ctx->mosq, MOSQ_LOG_INFO, "set open trans failed:%d", ret);
		return -1;
	}
	ret = mdb_dbi_open(txn, NULL, MDB_CREATE, &dbi);
	if (ret != 0)
	{
		log__printf(ctx->mosq, MOSQ_LOG_INFO, "open db failed:%d", ret);
		mdb_txn_abort(txn);
		return -1;
	}
	mk.mv_data = (char *)key;
	mk.mv_size = key_len;
	mv.mv_data = (char *)val;
	mv.mv_size = val_len;
	ret = mdb_put(txn, dbi, &mk, &mv, 0);
	if (ret != 0)
	{
		log__printf(ctx->mosq, MOSQ_LOG_INFO, "set failed:%d", ret);
		mdb_txn_abort(txn);
		return -1;
	}
	mdb_txn_commit(txn);
	// log__printf(ctx.mosq,MOSQ_LOG_INFO,"kv set end");
	if (ret != 0)
	{
		log__printf(ctx->mosq, MOSQ_LOG_INFO, "commit failed:%d", ret);
		return -1;
	}
	return 0;
}

int njet_iot_client_kv_del(const void *key, u_int32_t key_len, const void *val, u_int32_t val_len, struct evt_ctx_t *ctx)
{
	MDB_txn *txn;
	MDB_dbi dbi;
	MDB_val mk, mv;
	if (!ctx)
	{
		return MOSQ_ERR_INVAL;
	}
	// log__printf(ctx.mosq,MOSQ_LOG_INFO,"kv set begin");
	int ret = mdb_txn_begin(ctx->kv_env, NULL, 0, &txn);
	if (ret != 0)
	{
		log__printf(ctx->mosq, MOSQ_LOG_INFO, "set open trans failed:%d", ret);
		return -1;
	}
	ret = mdb_dbi_open(txn, NULL, MDB_CREATE, &dbi);
	if (ret != 0)
	{
		log__printf(ctx->mosq, MOSQ_LOG_INFO, "open db failed:%d", ret);
		mdb_txn_abort(txn);
		return -1;
	}
	mk.mv_data = (char *)key;
	mk.mv_size = key_len;
	mv.mv_data = (char *)val;
	mv.mv_size = val_len;
	ret = mdb_del(txn, dbi, &mk, &mv);
	if (ret != 0)
	{
		log__printf(ctx->mosq, MOSQ_LOG_INFO, "set failed:%d", ret);
		mdb_txn_abort(txn);
		return -1;
	}
	mdb_txn_commit(txn);
	// log__printf(ctx.mosq,MOSQ_LOG_INFO,"kv set end");
	if (ret != 0)
	{
		log__printf(ctx->mosq, MOSQ_LOG_INFO, "commit failed:%d", ret);
		return -1;
	}
	return 0;
}

int njet_iot_client_add_topic(struct evt_ctx_t *ctx, char *topic)
{
	if (ctx == NULL)
	{
		return -1;
	}
	cfg_add_topic(ctx->cfg, CLIENT_SUB, topic, "-t");
	return 0;
}

