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

#define NJT_STREAM_SERVER_TRAFFIC_STATUS_DEFAULT_QUEUE_LEN   64
#define NJT_STREAM_SERVER_TRAFFIC_STATUS_DEFAULT_BUCKET_LEN  32
typedef struct {
    njt_stream_complex_value_t                filter_key;
    njt_stream_complex_value_t                filter_name;
} njt_stream_server_traffic_status_filter_t;

typedef struct {
    njt_msec_t                                               time;
    njt_msec_int_t                                           msec;
} njt_stream_server_traffic_status_node_time_t;


typedef struct {
    njt_stream_server_traffic_status_node_time_t             times[NJT_STREAM_SERVER_TRAFFIC_STATUS_DEFAULT_QUEUE_LEN];
    njt_int_t                                                front;
    njt_int_t                                                rear;
    njt_int_t                                                len;
} njt_stream_server_traffic_status_node_time_queue_t;

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

typedef struct {
    njt_msec_int_t                                            msec;
    njt_atomic_t                                              counter;
} njt_stream_server_traffic_status_node_histogram_t;


typedef struct {
    njt_stream_server_traffic_status_node_histogram_t         buckets[NJT_STREAM_SERVER_TRAFFIC_STATUS_DEFAULT_BUCKET_LEN];
    njt_int_t                                                 len;
} njt_stream_server_traffic_status_node_histogram_bucket_t;


typedef struct {
    /* unsigned type:5 */
    unsigned                                                  type;
    
    njt_atomic_t                                              connect_time_counter;
    njt_msec_t                                                connect_time;
    njt_stream_server_traffic_status_node_time_queue_t        connect_times;
    njt_stream_server_traffic_status_node_histogram_bucket_t  connect_buckets;

    njt_atomic_t                                              first_byte_time_counter;
    njt_msec_t                                                first_byte_time;
    njt_stream_server_traffic_status_node_time_queue_t        first_byte_times;
    njt_stream_server_traffic_status_node_histogram_bucket_t  first_byte_buckets;

    njt_atomic_t                                              session_time_counter;
    njt_msec_t                                                session_time;
    njt_stream_server_traffic_status_node_time_queue_t        session_times;
    njt_stream_server_traffic_status_node_histogram_bucket_t  session_buckets;
} njt_stream_server_traffic_status_node_upstream_t;

typedef struct {
    u_char                                                    color;
    njt_atomic_t                                              stat_connect_counter;
    njt_atomic_t                                              stat_in_bytes;
    njt_atomic_t                                              stat_out_bytes;
    njt_atomic_t                                              stat_1xx_counter;
    njt_atomic_t                                              stat_2xx_counter;
    njt_atomic_t                                              stat_3xx_counter;
    njt_atomic_t                                              stat_4xx_counter;
    njt_atomic_t                                              stat_5xx_counter;
    
    njt_atomic_t                                              stat_session_time_counter;
    njt_msec_t                                                stat_session_time;
    njt_stream_server_traffic_status_node_time_queue_t        stat_session_times;
    njt_stream_server_traffic_status_node_histogram_bucket_t  stat_session_buckets;

    /* deals with the overflow of variables */
    njt_atomic_t                                              stat_connect_counter_oc;
    njt_atomic_t                                              stat_in_bytes_oc;
    njt_atomic_t                                              stat_out_bytes_oc;
    njt_atomic_t                                              stat_1xx_counter_oc;
    njt_atomic_t                                              stat_2xx_counter_oc;
    njt_atomic_t                                              stat_3xx_counter_oc;
    njt_atomic_t                                              stat_4xx_counter_oc;
    njt_atomic_t                                              stat_5xx_counter_oc;
    njt_atomic_t                                              stat_session_time_counter_oc;
    njt_atomic_t                                              stat_u_connect_time_counter_oc;
    njt_atomic_t                                              stat_u_first_byte_time_counter_oc;
    njt_atomic_t                                              stat_u_session_time_counter_oc;

    njt_stream_server_traffic_status_node_upstream_t          stat_upstream;

    njt_uint_t                                                port;
    int                                                       protocol;
    u_short                                                   len;
    u_char                                                    data[1];
} njt_stream_server_traffic_status_node_t;


typedef struct {
    njt_shm_zone_t                            *shm_zone;
    njt_str_t                                  shm_name;
    njt_flag_t                                 enable;
    njt_flag_t                                 filter;
    njt_flag_t                                 filter_check_duplicate;

    /* array of njt_stream_server_traffic_status_filter_t */
    njt_array_t                               *filter_keys;

    njt_flag_t                                 limit;
    njt_flag_t                                 limit_check_duplicate;

    /* array of njt_stream_server_traffic_status_limit_t */
    njt_array_t                               *limit_traffics;

    /* array of njt_stream_server_traffic_status_limit_t */
    njt_array_t                               *limit_filter_traffics;

    njt_stream_server_traffic_status_node_t    stats;
    njt_msec_t                                 start_msec;

    njt_flag_t                                 average_method;
    njt_msec_t                                 average_period;

    /* array of njt_stream_server_traffic_status_node_histogram_t */
    njt_array_t                               *histogram_buckets;


    njt_rbtree_node_t                        **node_caches;
#if NJT_STREAM_DYN_STS_MODULE
    njt_int_t                                  dynamic;
    njt_pool_t                                *dyn_pool;
#endif
} njt_stream_server_traffic_status_conf_t;


#endif //NJET_MAIN_NJT_STREAM_DYN_MODULE_H