/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */
#ifndef NJET_MAIN_NJT_DYNLOG_MODULE_H
#define NJET_MAIN_NJT_DYNLOG_MODULE_H

#include <njt_core.h>
#include <njt_json_api.h>
#include "njt_json_util.h"
#include "njt_dynlog_module.h"
#include "njt_http_dyn_module.h"
#include "njt_dynlog_parser.h"
extern njt_cycle_t *njet_master_cycle;
extern njt_module_t njt_ctrl_config_api_module;

//typedef struct {
//    njt_array_t listens;
//    njt_array_t server_names;
//    njt_array_t locs;
//}njt_http_dyn_access_api_srv_t;
//typedef dynlog_servers_item_t njt_http_dyn_access_api_srv_t;

//typedef struct {
//    njt_array_t servers;
//    njt_array_t log_formats;
//    njt_int_t rc;
//    unsigned success:1;
//}njt_http_dyn_access_api_main_t;

//typedef dynlog_t njt_http_dyn_access_api_main_t;
#endif //NJET_MAIN_NJT_DYNLOG_MODULE_H
