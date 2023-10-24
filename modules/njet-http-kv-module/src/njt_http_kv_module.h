/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#ifndef NJT_HTTP_KV_MODULE_H_
#define NJT_HTTP_KV_MODULE_H_
#include <njt_core.h>

//obsolete, dynamic module now support rpc put handler
typedef int (*kv_change_handler)(njt_str_t *key, njt_str_t *value, void *data);

// u_char is malloc in handler and free by caller, returned string length should set in len
typedef u_char *(*kv_rpc_handler)(njt_str_t *topic, njt_str_t *request, int *len, void *data);

typedef enum {
    NJT_KV_API_TYPE_DECLATIVE=0,
    NJT_KV_API_TYPE_INSTRUCTIONAL 
} njt_kv_api_type_e;

struct njt_kv_reg_handler_s {
   njt_str_t *key;
   kv_change_handler handler;
   kv_rpc_handler rpc_get_handler;
   kv_rpc_handler rpc_put_handler;
   void *data;
   njt_kv_api_type_e  api_type;
};

typedef struct njt_kv_reg_handler_s njt_kv_reg_handler_t;

int njt_kv_sendmsg(njt_str_t *topic, njt_str_t *content, int retain_flag);
int njt_kv_reg_handler(njt_kv_reg_handler_t *handler_t);

int njt_db_kv_get(njt_str_t *key, njt_str_t *value);
int njt_db_kv_set(njt_str_t *key, njt_str_t *value);
int njt_db_kv_del(njt_str_t *key);

#endif
