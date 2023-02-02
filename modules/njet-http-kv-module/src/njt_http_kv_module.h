#ifndef NJT_HTTP_KV_MODULE_H_
#define NJT_HTTP_KV_MODULE_H_

typedef int (*kv_change_handler)(njt_str_t *key, njt_str_t *value, void *data);

int njt_reg_kv_change_handler(njt_str_t *key, kv_change_handler handler, void *data);

typedef int (*topic_msg_handler)(njt_str_t *topic, njt_str_t *msg, void *data);

int njt_reg_topic_msg_handler(njt_str_t *topic_prefix, topic_msg_handler handler, void *data);

int njt_dyn_sendmsg(njt_str_t *topic, njt_str_t *content, int retain_flag);
int njt_dyn_kv_get(njt_str_t *key, njt_str_t *value);
int njt_dyn_kv_set(njt_str_t *key, njt_str_t *value);
#endif
