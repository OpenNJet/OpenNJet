#ifndef MOSQUITTO_EMB_H_
#define MOSQUITTO_EMB_H_

#include <sys/types.h>
#include <inttypes.h>

int mqtt_init(const char* config_file);
int mqtt_run();
int mqtt_exit();
int mqtt_reload_cfg();

//client section

struct mqtt_ctx_t;

typedef void (*msg_resp_pt) (const char* topic, const char* msg, int msg_len, int session_id);
typedef int (*msg_pt) (const char* topic, const char* msg, int msg_len,void *out_data);

struct mqtt_ctx_t*  mqtt_client_init(const char* cfg_file,msg_resp_pt resp_pt,msg_pt msg_callback,const char *id, const char* iot_log, void* out_data);
int mqtt_client_run(struct mqtt_ctx_t *ctx);
int mqtt_client_connect(int retries, int interval, struct mqtt_ctx_t *ctx);
void	mqtt_client_exit(struct mqtt_ctx_t *ctx);
int mqtt_client_socket(struct mqtt_ctx_t *ctx);
int mqtt_client_sendmsg(const char *topic, const void *msg, int l, int qos,struct mqtt_ctx_t *ctx);
int mqtt_client_kv_set(const void* key, u_int32_t ken_len, const void* val, u_int32_t val_len,const void* data,struct mqtt_ctx_t *ctx);
int mqtt_client_kv_get(void* key, u_int32_t ken_len, void** val, u_int32_t* val_len, struct mqtt_ctx_t *ctx);
const char*  mqtt_client_get_ipc_path(struct mqtt_ctx_t *ctx);
int mqtt_client_sendmsg_rr(const char* topic, const void* msg, int l, int qos, int session_id, int is_reply, struct mqtt_ctx_t *ctx);
int mqtt_client_pub_kv(const u_char* cluster, u_int32_t c_l, const u_char* key, u_int32_t key_l, const u_char* val , u_int32_t val_l,struct mqtt_ctx_t *ctx);

int mqtt_client_get_seq(const void* key, u_int32_t key_len, void **val,u_int32_t * val_len, struct mqtt_ctx_t *ctx);


#endif


