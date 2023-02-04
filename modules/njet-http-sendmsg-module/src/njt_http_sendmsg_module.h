#ifndef NJT_HTTP_SENDMSG_MODULE_H_
#define NJT_HTTP_SENDMSG_MODULE_H_

int njt_dyn_sendmsg(njt_str_t *topic, njt_str_t *content, int retain_flag);

int njt_dyn_kv_get(njt_str_t *key, njt_str_t *value);
int njt_dyn_kv_set(njt_str_t *key, njt_str_t *value);
#endif
