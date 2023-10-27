/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#ifndef NJT_HTTP_SENDMSG_MODULE_H_
#define NJT_HTTP_SENDMSG_MODULE_H_
#include <njt_core.h>

#define RPC_RC_OK 0
#define RPC_RC_TIMEOUT 1

struct njt_dyn_rpc_res_s
{
    int session_id;
    void *data;
    int rc;
};
typedef struct njt_dyn_rpc_res_s njt_dyn_rpc_res_t;

typedef int (*rpc_msg_handler)(njt_dyn_rpc_res_t* res, njt_str_t *msg);

int njt_dyn_rpc(njt_str_t *topic, njt_str_t *request, int retain_flag, int session_id, rpc_msg_handler handler, void *data);

int njt_dyn_sendmsg(njt_str_t *topic, njt_str_t *content, int retain_flag);
int njt_dyn_kv_get(njt_str_t *key, njt_str_t *value);
int njt_dyn_kv_set(njt_str_t *key, njt_str_t *value);
int njt_dyn_kv_del(njt_str_t *key);
#endif
