/*
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#ifndef NJET_MAIN_NJT_STREAM_DYN_MODULE_H
#define NJET_MAIN_NJT_STREAM_DYN_MODULE_H

#include <njt_core.h>
#include <njt_stream.h>
#include <njt_hash_util.h>

typedef struct {
    njt_uint_t                    hash_max_size;
    njt_uint_t                    hash_bucket_size;
#if NJT_STREAM_DYN_MAP_MODULE
    njt_lvlhash_map_t           var_hash;
    njt_array_t *var_hash_items;
#endif
} njt_stream_map_conf_t;

typedef struct {
    njt_stream_map_t              map;
    njt_stream_complex_value_t    value;
    njt_stream_variable_value_t *default_value;
    njt_uint_t                    hostnames;      /* unsigned  hostnames:1 */
} njt_stream_map_ctx_t;

#if NJT_STREAM_DYN_MAP_MODULE
typedef struct {
    njt_str_t  v_from;
    njt_str_t  v_to;
} njt_stream_map_ori_conf_item_t;

typedef struct {
    njt_str_t   name;
    njt_array_t *ori_conf;
    njt_stream_map_ctx_t *map;
    njt_int_t    dynamic;
} njt_stream_map_var_hash_t;
#endif

typedef struct {
    njt_hash_keys_arrays_t        keys;

    njt_array_t *values_hash;
#if (NJT_PCRE)
    njt_array_t                   regexes;
#endif

    njt_stream_variable_value_t *default_value;
    njt_conf_t *cf;
    unsigned                      hostnames : 1;
    unsigned                      no_cacheable : 1;
#if NJT_STREAM_DYN_MAP_MODULE
    njt_array_t *ori_conf;
#endif
} njt_stream_map_conf_ctx_t;

typedef struct {
    njt_rbtree_t                              *rbtree;

    /* array of njt_stream_server_traffic_status_filter_t */
    njt_array_t                               *filter_keys;

    /* array of njt_stream_server_traffic_status_limit_t */
    njt_array_t                               *limit_traffics;

    /* array of njt_stream_server_traffic_status_limit_t */
    njt_array_t                               *limit_filter_traffics;

    njt_flag_t                                 enable;
    njt_flag_t                                 filter_check_duplicate;
    njt_flag_t                                 limit_check_duplicate;

    njt_stream_upstream_main_conf_t           *upstream;
    njt_str_t                                  shm_name;
    ssize_t                                    shm_size;
} njt_stream_server_traffic_status_ctx_t;


#endif //NJET_MAIN_NJT_STREAM_DYN_MODULE_H