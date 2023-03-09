/*************************************************************************************
 Copyright (C), 2021-2023, TMLake(Beijing) Technology Ltd.,
 File name    : njt_dynlog_module.h
 Version      : 1.0
 Author       : ChengXu
 Date         : 2023/2/20/020 
 Description  : 
 Other        :
 History      :
 <author>       <time>          <version >      <desc>
 ChengXu        2023/2/20/020       1.1             
***********************************************************************************/
//
// Created by Administrator on 2023/2/20/020.
//

#ifndef NJET_MAIN_NJT_DYNLOG_MODULE_H
#define NJET_MAIN_NJT_DYNLOG_MODULE_H

#include <njt_core.h>
#include <njt_json_api.h>
#include "njt_json_util.h"
#include "njt_dynlog_module.h"
#include "njt_http_dyn_module.h"

extern njt_cycle_t *njet_master_cycle;
extern njt_module_t njt_ctrl_config_api_module;

typedef struct {
    njt_array_t listens;
    njt_array_t server_names;
    njt_array_t locs;
}njt_http_dyn_access_api_srv_t;

typedef struct {
    njt_str_t name;
    njt_str_t format;
    njt_str_t escape;
}njt_http_dyn_access_log_format_t;

typedef struct {
    njt_array_t servers;
    njt_array_t log_formats;
    njt_int_t rc;
    unsigned success:1;
}njt_http_dyn_access_api_main_t;


#endif //NJET_MAIN_NJT_DYNLOG_MODULE_H
