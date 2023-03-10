/*************************************************************************************
 Copyright (C), 2021-2023, TMLake(Beijing) Technology Ltd.,
 File name    : njt_http_dyn_module.h
 Version      : 1.0
 Author       : ChengXu
 Date         : 2023/2/21/021 
 Description  : 
 Other        :
 History      :
 <author>       <time>          <version >      <desc>
 ChengXu        2023/2/21/021       1.1             
***********************************************************************************/
//
// Created by Administrator on 2023/2/21/021.
//

#ifndef NJET_MAIN_NJT_HTTP_DYN_MODULE_H
#define NJET_MAIN_NJT_HTTP_DYN_MODULE_H

#include "njt_core.h"
#include "njt_json_util.h"
#include "njt_json_api.h"

#define NJT_HTTP_DYN_LOG 1

typedef struct {
    njt_array_t                *logs;       /* array of njt_http_log_t */

    njt_open_file_cache_t      *open_file_cache;
    time_t                      open_file_cache_valid;
    njt_uint_t                  open_file_cache_min_uses;

    njt_uint_t                  off;        /* unsigned  off:1 */
    njt_int_t dynamic;
} njt_http_log_loc_conf_t;


typedef struct {
    njt_str_t                   name;
    njt_array_t                *flushes;
    njt_array_t                *ops;        /* array of njt_http_log_op_t */
    njt_str_t                   format;
    njt_str_t                   escape;
    njt_int_t dynamic;
} njt_http_log_fmt_t;

typedef struct {
    njt_array_t                *lengths;
    njt_array_t                *values;
} njt_http_log_script_t;

typedef struct {
    njt_open_file_t            *file;
    njt_http_log_script_t      *script;
    time_t                      disk_full_time;
    time_t                      error_log_time;
    njt_syslog_peer_t          *syslog_peer;
    njt_http_log_fmt_t         *format;
    njt_http_complex_value_t   *filter;
    njt_str_t path;
} njt_http_log_t;



extern njt_module_t  njt_http_log_module;

typedef struct {
    in_addr_t         mask;
    in_addr_t         addr;
    njt_uint_t        deny;      /* unsigned  deny:1; */
} njt_http_access_rule_t;

#if (NJT_HAVE_INET6)

typedef struct {
    struct in6_addr   addr;
    struct in6_addr   mask;
    njt_uint_t        deny;      /* unsigned  deny:1; */
} njt_http_access_rule6_t;

#endif

#if (NJT_HAVE_UNIX_DOMAIN)

typedef struct {
    njt_uint_t        deny;      /* unsigned  deny:1; */
} njt_http_access_rule_un_t;

#endif

typedef struct {
    njt_array_t      *rules;     /* array of njt_http_access_rule_t */
#if (NJT_HAVE_INET6)
    njt_array_t      *rules6;    /* array of njt_http_access_rule6_t */
#endif
#if (NJT_HAVE_UNIX_DOMAIN)
    njt_array_t      *rules_un;  /* array of njt_http_access_rule_un_t */
#endif
} njt_http_access_loc_conf_t;


typedef struct njt_http_dyn_access_api_loc_s njt_http_dyn_access_api_loc_t;

struct njt_http_dyn_access_api_loc_s {
    njt_str_t full_name;
    bool log_on;
    njt_array_t logs;
    njt_array_t locs;
};

typedef struct njt_http_dyn_access_log_conf_s njt_http_dyn_access_log_conf_t;

struct njt_http_dyn_access_log_conf_s {
    njt_str_t format;
    njt_str_t path;
};

typedef struct {
    njt_str_t name;
    njt_str_t format;
    njt_str_t escape;
}njt_http_dyn_access_log_format_t;

typedef struct {
    njt_array_t                 formats;    /* array of njt_http_log_fmt_t */
    njt_uint_t                  combined_used; /* unsigned  combined_used:1 */
#if (NJT_HTTP_DYN_LOG)
    njt_queue_t                 file_queue; /* 打开文件句柄列表 */
    njt_pool_t                  *pool;
#endif
} njt_http_log_main_conf_t;

njt_int_t njt_http_log_dyn_set_log(njt_pool_t *pool, njt_http_dyn_access_api_loc_t *data,njt_http_conf_ctx_t* ctx);

njt_int_t njt_http_log_dyn_set_format(njt_http_dyn_access_log_format_t *data);

#endif //NJET_MAIN_NJT_HTTP_DYN_MODULE_H
