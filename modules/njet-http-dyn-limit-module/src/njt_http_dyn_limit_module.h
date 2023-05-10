/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */
#ifndef NJT_HTTP_DYN_LIMIT_MODULE_H_
#define NJT_HTTP_DYN_LIMIT_MODULE_H_
#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>



typedef struct
{
    njt_str_t     zone;
    njt_int_t    burst;
    njt_str_t    delay;
} njt_http_dyn_limit_req_t;

typedef struct
{
    njt_str_t   zone;
    njt_int_t   conn;
} njt_http_dyn_limit_conn_t;


struct njt_http_dyn_limit_loc_s
{
    njt_str_t          full_name;
    
    //limit req
    /*up_share: from up(server or http level for share)
              not support modify, just read
    location: location use, can modify */
    njt_str_t          limit_reqs_scope;         
    njt_array_t        limit_reqs;
    njt_str_t          limit_req_dry_run;
    njt_str_t          limit_req_log_level;
    njt_uint_t         limit_req_status;

    //limit conn
    /*up_share: from up(server or http level for share)
              not support modify, just read
    location: location use, can modify */
    njt_str_t          limit_conns_scope;
    njt_array_t        limit_conns;
    njt_str_t          limit_conn_dry_run;
    njt_str_t          limit_conn_log_level;
    njt_uint_t         limit_conn_status;

    //limit rate
    njt_str_t          limit_rate;
    njt_str_t          limit_rate_after;

    njt_array_t        locs;
};
typedef struct njt_http_dyn_limit_loc_s njt_http_dyn_limit_loc_t;

typedef struct
{
    njt_array_t listens;
    njt_array_t server_names;
    njt_array_t locs;
} njt_http_dyn_limit_srv_t;


typedef struct {
    njt_str_t zone;
    njt_str_t rate;
}njt_http_dyn_limit_rps_t;

typedef struct
{
    njt_array_t servers;
    njt_array_t limit_rps;
    njt_int_t   rc;
    unsigned    success : 1;
} njt_http_dyn_limit_main_t;

#endif
