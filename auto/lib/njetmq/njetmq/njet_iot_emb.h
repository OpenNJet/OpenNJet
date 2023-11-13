/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#ifndef MOSQUITTO_EMB_H_
#define MOSQUITTO_EMB_H_

#include <sys/types.h>
#include <inttypes.h>

int njet_iot_init(const char *prefix, const char *config_file);
int njet_iot_run();
int njet_iot_exit();

// client section

struct evt_ctx_t;

typedef char *(*msg_resp_pt)(const char *topic, int is_req, const char *msg, int msg_len, int session_id, int *out_len);
typedef int (*msg_pt)(const char *topic, const char *msg, int msg_len, void *out_data);

struct evt_ctx_t *njet_iot_client_init( const char *prefix, const char *cfg_file, msg_resp_pt resp_pt, msg_pt msg_callback, const char *id, const char *iot_log, void *out_data);
int njet_iot_client_run(struct evt_ctx_t *ctx);
int njet_iot_client_connect(int retries, int interval, struct evt_ctx_t *ctx);
void njet_iot_client_exit(struct evt_ctx_t *ctx);
int njet_iot_client_socket(struct evt_ctx_t *ctx);
int njet_iot_client_sendmsg(const char *topic, const void *msg, int l, int qos, struct evt_ctx_t *ctx);
int njet_iot_client_kv_set(const void *key, u_int32_t ken_len, const void *val, u_int32_t val_len, const void *data, struct evt_ctx_t *ctx);
int njet_iot_client_kv_get(void *key, u_int32_t ken_len, void **val, u_int32_t *val_len, struct evt_ctx_t *ctx);
int njet_iot_client_kv_del(const void *key, u_int32_t ken_len, const void *val, u_int32_t val_len, struct evt_ctx_t *ctx);
int njet_iot_client_sendmsg_rr(const char *topic, const void *msg, int l, int qos, int session_id, int is_reply, struct evt_ctx_t *ctx);
int njet_iot_client_pub_kv(const u_char *cluster, u_int32_t c_l, const u_char *key, u_int32_t key_l, const u_char *val, u_int32_t val_l, struct evt_ctx_t *ctx);
int njet_iot_client_add_topic(struct evt_ctx_t *ctx, char *topic);

#endif
