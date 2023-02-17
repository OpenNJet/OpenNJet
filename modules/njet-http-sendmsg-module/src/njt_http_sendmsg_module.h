#ifndef NJT_HTTP_SENDMSG_MODULE_H_
#define NJT_HTTP_SENDMSG_MODULE_H_
#include <njt_core.h>

typedef int (*rpc_msg_handler)(int session_id, njt_str_t *msg, void *data);

int njt_dyn_sendmsg(njt_str_t *topic, njt_str_t *content, int retain_flag);
int dyn_rpc(njt_str_t *topic, njt_str_t *request, int session_id, rpc_msg_handler handler, void *data);

int njt_dyn_kv_get(njt_str_t *key, njt_str_t *value);
int njt_dyn_kv_set(njt_str_t *key, njt_str_t *value);
#endif
