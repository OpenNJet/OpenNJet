/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */
#ifndef NJT_HTTP_DYN_SERVER_MODULE_H_
#define NJT_HTTP_DYN_SERVER_MODULE_H_
#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


typedef struct njt_http_dyn_server_info_s {
    njt_str_t file;
    njt_str_t type;
    njt_str_t addr_port;
    njt_str_t server_name;
    njt_str_t server_body;
    njt_str_t listens;
    njt_pool_t *pool;
    njt_http_core_srv_conf_t *cscf;
    njt_str_t     msg;
    njt_str_t buffer;
    njt_int_t   bind;
} njt_http_dyn_server_info_t;

typedef struct njt_http_dyn_server_loc_conf_s {
    njt_flag_t dyn_server_enable;
} njt_http_dyn_server_loc_conf_t;

njt_http_dyn_server_info_t * njt_http_parser_server_data(njt_str_t json_str,njt_uint_t method);
njt_int_t njt_http_check_upstream_exist(njt_cycle_t *cycle,njt_pool_t *pool, njt_str_t *name);
#endif
