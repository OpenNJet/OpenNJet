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

typedef struct njt_http_dyn_upstream_info_s
{
    njt_str_t file;
    njt_str_t type;
    njt_str_t upstream_name;       // 查找用。去掉开头结尾 "
    njt_str_t old_upstream_name; // 原始的。
    njt_str_t upstream_body;
    njt_pool_t *pool;
    njt_http_upstream_srv_conf_t *upstream;
    njt_str_t msg;
    njt_str_t buffer;
} njt_http_dyn_upstream_info_t;

typedef struct njt_http_dyn_upstream_loc_conf_s
{
    njt_flag_t dyn_upstream_enable;
} njt_http_dyn_upstream_loc_conf_t;
njt_http_dyn_upstream_info_t *njt_http_parser_upstream_data(njt_str_t json_str, njt_uint_t method);


typedef struct njt_http_dyn_upstream_domain_main_conf_s
{
   njt_slab_pool_t *shpool;
   njt_shm_zone_t shm_zone;
} njt_http_dyn_upstream_domain_main_conf_t;

#endif
