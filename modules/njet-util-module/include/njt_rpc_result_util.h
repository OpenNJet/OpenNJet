/*
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#ifndef NJET_MAIN_RPC_RESULT_UTIL_H
#define NJET_MAIN_RPC_RESULT_UTIL_H
#include <njt_json_api.h>
#include <njt_core.h>

// 通用错误码定义
enum
{
    NJT_RPC_RSP_SUCCESS = 0,
    NJT_RPC_RSP_ERR_GENERAL,
    NJT_RPC_RSP_ERR_POOL_CREATION,
    NJT_RPC_RSP_ERR_JSON,
    NJT_RPC_RSP_ERR_TOTAL_PERCENTAGE
} NJT_HTTP_RSP_ERROR;

struct njt_rpc_result_s{
    // njt_str_t[]
    njt_int_t code;
    njt_str_t msg;
    njt_array_t *data;
    njt_pool_t * pool;
};

typedef struct njt_rpc_result_s njt_rpc_result_t;

njt_rpc_result_t * njt_rpc_result_create();

void  njt_rpc_result_set_code(njt_rpc_result_t * rpc_result,njt_int_t code);

void njt_rpc_result_set_msg(njt_rpc_result_t * rpc_result,u_char * msg);

void njt_rpc_result_add_error_data(njt_rpc_result_t * rpc_result,njt_str_t * msg);

njt_int_t njt_rpc_result_to_json_str(njt_rpc_result_t * rpc_result,njt_str_t *json_str);

void njt_rpc_result_destroy(njt_rpc_result_t * rpc_result);

#endif //NJET_MAIN_RPC_RESULT_UTIL_H
