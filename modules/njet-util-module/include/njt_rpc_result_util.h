/*
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#ifndef NJET_MAIN_RPC_RESULT_UTIL_H
#define NJET_MAIN_RPC_RESULT_UTIL_H
#include <njt_json_api.h>
#include <njt_core.h>

typedef njt_json_manager * rpc_result_pt;
rpc_result_pt rpc_result_init();

void rpc_result_set_code(rpc_result_pt rpc_result,njt_int_t code);

void rpc_result_set_msg(rpc_result_pt rpc_result,njt_str_t msg);

void rpc_result_add_loc(rpc_result_pt rpc_result,njt_loc_ msg);

void rpc_result_add_loc(rpc_result_pt rpc_result,njt_loc_ msg);


void rpc_result_free(rpc_result_pt rpc_result);

#endif //NJET_MAIN_RPC_RESULT_UTIL_H
