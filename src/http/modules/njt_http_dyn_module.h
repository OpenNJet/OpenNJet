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
#include <njt_hash_util.h>

#define NJT_HTTP_DYN_LOG 1

typedef struct {
    njt_rbtree_t                  rbtree;
    njt_rbtree_node_t             sentinel;
    njt_queue_t                   queue;
} njt_http_limit_req_shctx_t;

typedef struct {
    u_char                       color;
    u_char                       dummy;
    u_short                      len;
    njt_queue_t                  queue;
    njt_msec_t                   last;
    /* integer value, 1 corresponds to 0.001 r/s */
    njt_uint_t                   excess;
    njt_uint_t                   count;
    u_char                       data[1];
} njt_http_limit_req_node_t;

typedef struct {
    njt_http_limit_req_shctx_t *sh;
    njt_slab_pool_t *shpool;
    /* integer value, 1 corresponds to 0.001 r/s */
    njt_uint_t                   rate;
#if (NJT_HTTP_DYNAMIC_LOC)
    njt_int_t                    scale;
    njt_uint_t                   ori_rate;
#endif
    njt_http_complex_value_t     key;
    njt_http_limit_req_node_t *node;
} njt_http_limit_req_ctx_t;

typedef struct {
    njt_shm_zone_t *shm_zone;
    /* integer value, 1 corresponds to 0.001 r/s */
    njt_uint_t                   burst;
    njt_uint_t                   delay;
} njt_http_limit_req_limit_t;


typedef struct {
    njt_array_t                  limits;
    njt_uint_t                   limit_log_level;
    njt_uint_t                   delay_log_level;
    njt_uint_t                   status_code;
    njt_flag_t                   dry_run;
    njt_flag_t                   from_up;
} njt_http_limit_req_conf_t;



typedef struct {
    njt_shm_zone_t *shm_zone;
    njt_uint_t                    conn;
} njt_http_limit_conn_limit_t;

typedef struct {
    njt_array_t                   limits;
    njt_uint_t                    log_level;
    njt_uint_t                    status_code;
    njt_flag_t                    dry_run;
    //add by clb
#if (NJT_HTTP_DYNAMIC_LOC)
    njt_flag_t                    from_up;
#endif
} njt_http_limit_conn_conf_t;


typedef struct {
    njt_array_t *logs;       /* array of njt_http_log_t */

    njt_open_file_cache_t *open_file_cache;
    time_t                      open_file_cache_valid;
    njt_uint_t                  open_file_cache_min_uses;

    njt_uint_t                  off;        /* unsigned  off:1 */
    njt_int_t dynamic;
} njt_http_log_loc_conf_t;


typedef struct {
    njt_str_t                   name;
    njt_array_t *flushes;
    njt_array_t *ops;        /* array of njt_http_log_op_t */
    njt_str_t                   format;
    njt_str_t                   escape;
    njt_int_t dynamic;
} njt_http_log_fmt_t;

typedef struct {
    njt_array_t *lengths;
    njt_array_t *values;
} njt_http_log_script_t;

typedef struct {
    njt_open_file_t *file;
    njt_http_log_script_t *script;
    time_t                      disk_full_time;
    time_t                      error_log_time;
    njt_syslog_peer_t *syslog_peer;
    njt_http_log_fmt_t *format;
    njt_http_complex_value_t *filter;
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
    njt_array_t *rules;     /* array of njt_http_access_rule_t */
#if (NJT_HAVE_INET6)
    njt_array_t *rules6;    /* array of njt_http_access_rule6_t */
#endif
#if (NJT_HAVE_UNIX_DOMAIN)
    njt_array_t *rules_un;  /* array of njt_http_access_rule_un_t */
#endif
    njt_int_t        dynamic;
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
    njt_pool_t *pool;
#endif
} njt_http_log_main_conf_t;

typedef struct {
    njt_uint_t                    fault_inject_type;     // type
    njt_msec_t                    duration;              // delay time
    njt_str_t                     str_duration;          // duration string
    njt_uint_t                    status_code;           // abort status code
    uint32_t                      delay_percent;         // delay percent, default 100
    uint32_t                      abort_percent;         // abort percent, default 100   
    
    njt_uint_t                    dynamic;               // 
    njt_pool_t                    *pool;
} njt_http_fault_inject_conf_t;


njt_int_t njt_http_log_dyn_set_log(njt_pool_t *pool, njt_http_dyn_access_api_loc_t *data,njt_http_conf_ctx_t* ctx,njt_str_t * msg,njt_uint_t msg_capacity);

njt_int_t njt_http_log_dyn_set_format(njt_http_dyn_access_log_format_t *data);
void njt_http_map_del_by_name(njt_str_t name);

typedef struct {
    njt_http_map_t              map;
    njt_http_complex_value_t    value;
    njt_http_variable_value_t *default_value;
    njt_uint_t                  hostnames;      /* unsigned  hostnames:1 */
    njt_pool_t                  *pool;
} njt_http_map_ctx_t;

typedef struct {
    njt_uint_t                  hash_max_size;
    njt_uint_t                  hash_bucket_size;
#if NJT_HTTP_DYN_MAP_MODULE
    njt_lvlhash_map_t           var_hash;
    njt_array_t *var_hash_items;
#endif
} njt_http_map_conf_t;

#if NJT_HTTP_DYN_MAP_MODULE
typedef struct {
    njt_str_t  v_from;
    njt_str_t  v_to;
} njt_http_map_ori_conf_item_t;

typedef struct {
    njt_str_t   key_from;
    njt_str_t   name;
    njt_array_t *ori_conf;
    njt_http_map_ctx_t *map;
    unsigned     no_cacheable : 1;
    unsigned     dynamic      : 1;
} njt_http_map_var_hash_t;
#endif

typedef struct {
    njt_hash_keys_arrays_t      keys;

    njt_array_t *values_hash;
#if (NJT_PCRE)
    njt_array_t                 regexes;
#endif

    njt_http_variable_value_t *default_value;
    njt_conf_t *cf;
    unsigned                    hostnames : 1;
    unsigned                    no_cacheable : 1;
#if NJT_HTTP_DYN_MAP_MODULE
    njt_array_t *ori_conf;
#endif
} njt_http_map_conf_ctx_t;

#endif //NJET_MAIN_NJT_HTTP_DYN_MODULE_H
