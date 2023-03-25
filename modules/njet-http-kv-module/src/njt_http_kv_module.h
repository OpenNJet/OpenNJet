#ifndef NJT_HTTP_KV_MODULE_H_
#define NJT_HTTP_KV_MODULE_H_
#include <njt_core.h>

typedef int (*kv_change_handler)(njt_str_t *key, njt_str_t *value, void *data);

//u_char is malloc in handler and free by caller, returned string length should set in len 
typedef u_char* (*kv_rpc_handler)(njt_str_t *topic, njt_str_t *request, int* len, void *data);

int njt_reg_kv_change_handler(njt_str_t *key, kv_change_handler handler, kv_rpc_handler rpc_handler,  void *data);
int njt_kv_sendmsg(njt_str_t *topic, njt_str_t *content, int retain_flag);
int njt_db_kv_get(njt_str_t *key, njt_str_t *value);
int njt_db_kv_set(njt_str_t *key, njt_str_t *value);


#endif
