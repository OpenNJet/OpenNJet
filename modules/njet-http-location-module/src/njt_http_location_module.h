/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */
#ifndef NJT_HTTP_LOCATION_MODULE_H_
#define NJT_HTTP_LOCATION_MODULE_H_
#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>

typedef struct njt_http_sub_location_info_s {
    
	njt_str_t location_rule;
    njt_str_t location;
    njt_str_t proxy_pass;
    njt_str_t location_body;
	njt_array_t   *sub_location_array;
} njt_http_sub_location_info_t;

typedef struct njt_http_location_info_s {
    njt_str_t file;
	njt_str_t type;
    njt_str_t addr_port;
    njt_str_t server_name;
	njt_str_t location_rule;
    njt_str_t location;
    //njt_str_t proxy_pass;
    //njt_str_t location_body;
	njt_pool_t *pool;
    njt_http_core_srv_conf_t *cscf;
    njt_str_t     msg;
	njt_array_t   *location_array;
	njt_str_t     buffer;
} njt_http_location_info_t;

typedef struct njt_http_location_loc_conf_s {
    njt_flag_t dyn_location_enable;
} njt_http_location_loc_conf_t;

njt_http_location_info_t * njt_http_parser_location_data(njt_str_t json_str,njt_uint_t method);
#endif
