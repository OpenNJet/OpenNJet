
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 * Copyright (C), 2021-2023, TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_VTS_NODE_H_INCLUDED_
#define _NJT_HTTP_VTS_NODE_H_INCLUDED_


#define NJT_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_QUEUE_LEN    64
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_BUCKET_LEN   32


typedef struct {
    njt_msec_t                                             time;
    njt_msec_int_t                                         msec;
} njt_http_vhost_traffic_status_node_time_t;


typedef struct {
    njt_http_vhost_traffic_status_node_time_t              times[NJT_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_QUEUE_LEN];
    njt_int_t                                              front;
    njt_int_t                                              rear;
    njt_int_t                                              len;
} njt_http_vhost_traffic_status_node_time_queue_t;


typedef struct {
    njt_msec_int_t                                         msec;
    njt_atomic_t                                           counter;
} njt_http_vhost_traffic_status_node_histogram_t;


typedef struct {
    njt_http_vhost_traffic_status_node_histogram_t         buckets[NJT_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_BUCKET_LEN];
    njt_int_t                                              len;
} njt_http_vhost_traffic_status_node_histogram_bucket_t;


typedef struct {
    /* unsigned type:5 */
    unsigned                                               type;
    njt_atomic_t                                           response_time_counter;
    njt_msec_t                                             response_time;
    njt_http_vhost_traffic_status_node_time_queue_t        response_times;
    njt_http_vhost_traffic_status_node_histogram_bucket_t  response_buckets;
} njt_http_vhost_traffic_status_node_upstream_t;


typedef struct {
    u_char                                                 color;
    njt_atomic_t                                           stat_request_counter;
    njt_atomic_t                                           stat_in_bytes;
    njt_atomic_t                                           stat_out_bytes;
    njt_atomic_t                                           stat_1xx_counter;
    njt_atomic_t                                           stat_2xx_counter;
    njt_atomic_t                                           stat_3xx_counter;
    njt_atomic_t                                           stat_4xx_counter;
    njt_atomic_t                                           stat_5xx_counter;

    njt_atomic_t                                           stat_request_time_counter;
    njt_msec_t                                             stat_request_time;
    njt_http_vhost_traffic_status_node_time_queue_t        stat_request_times;
    njt_http_vhost_traffic_status_node_histogram_bucket_t  stat_request_buckets;

    /* deals with the overflow of variables */
    njt_atomic_t                                           stat_request_counter_oc;
    njt_atomic_t                                           stat_in_bytes_oc;
    njt_atomic_t                                           stat_out_bytes_oc;
    njt_atomic_t                                           stat_1xx_counter_oc;
    njt_atomic_t                                           stat_2xx_counter_oc;
    njt_atomic_t                                           stat_3xx_counter_oc;
    njt_atomic_t                                           stat_4xx_counter_oc;
    njt_atomic_t                                           stat_5xx_counter_oc;
    njt_atomic_t                                           stat_timeo_counter_oc;
    njt_atomic_t                                           stat_request_time_counter_oc;
    njt_atomic_t                                           stat_response_time_counter_oc;

#if (NJT_HTTP_CACHE)
    njt_atomic_t                                           stat_cache_max_size;
    njt_atomic_t                                           stat_cache_used_size;
    njt_atomic_t                                           stat_cache_miss_counter;
    njt_atomic_t                                           stat_cache_bypass_counter;
    njt_atomic_t                                           stat_cache_expired_counter;
    njt_atomic_t                                           stat_cache_stale_counter;
    njt_atomic_t                                           stat_cache_updating_counter;
    njt_atomic_t                                           stat_cache_revalidated_counter;
    njt_atomic_t                                           stat_cache_hit_counter;
    njt_atomic_t                                           stat_cache_scarce_counter;

    /* deals with the overflow of variables */
    njt_atomic_t                                           stat_cache_miss_counter_oc;
    njt_atomic_t                                           stat_cache_bypass_counter_oc;
    njt_atomic_t                                           stat_cache_expired_counter_oc;
    njt_atomic_t                                           stat_cache_stale_counter_oc;
    njt_atomic_t                                           stat_cache_updating_counter_oc;
    njt_atomic_t                                           stat_cache_revalidated_counter_oc;
    njt_atomic_t                                           stat_cache_hit_counter_oc;
    njt_atomic_t                                           stat_cache_scarce_counter_oc;
#endif

    njt_http_vhost_traffic_status_node_upstream_t          stat_upstream;
    u_short                                                len;
    njt_atomic_t                                           lock;
    u_char                                                 data[0];
} njt_http_vhost_traffic_status_node_t;


njt_int_t njt_http_vhost_traffic_status_node_generate_key(njt_pool_t *pool,
    njt_str_t *buf, njt_str_t *dst, unsigned type);
njt_int_t njt_http_vhost_traffic_status_node_position_key(njt_str_t *buf,
    size_t pos);

njt_rbtree_node_t *njt_http_vhost_traffic_status_node_lookup(
    njt_rbtree_t *rbtree, njt_str_t *key, uint32_t hash);
void njt_http_vhost_traffic_status_node_zero(
    njt_http_vhost_traffic_status_node_t *vtsn);
void njt_http_vhost_traffic_status_nodes_zero(
    njt_http_vhost_traffic_status_node_t *vtsn);
void njt_http_vhost_traffic_status_node_init(njt_http_request_t *r,
    njt_http_vhost_traffic_status_node_t *vtsn);
void njt_http_vhost_traffic_status_node_init_update(njt_http_request_t *r,
    njt_http_vhost_traffic_status_node_t *vtsn);
void njt_http_vhost_traffic_status_nodes_init(njt_http_request_t *r,
    njt_http_vhost_traffic_status_node_t *vtsn);
void njt_http_vhost_traffic_status_node_set(njt_http_request_t *r,
    njt_http_vhost_traffic_status_node_t *vtsn);
void njt_http_vhost_traffic_status_node_update(njt_http_request_t *r,
    njt_http_vhost_traffic_status_node_t *vtsn, njt_msec_int_t ms);

void njt_http_vhost_traffic_status_node_time_queue_zero(
    njt_http_vhost_traffic_status_node_time_queue_t *q);
void njt_http_vhost_traffic_status_node_time_queue_init(
    njt_http_vhost_traffic_status_node_time_queue_t *q);
void njt_http_vhost_traffic_status_node_time_queue_insert(
    njt_http_vhost_traffic_status_node_time_queue_t *q,
    njt_msec_int_t x);
njt_int_t njt_http_vhost_traffic_status_node_time_queue_push(
    njt_http_vhost_traffic_status_node_time_queue_t *q,
    njt_msec_int_t x);
njt_int_t njt_http_vhost_traffic_status_node_time_queue_pop(
    njt_http_vhost_traffic_status_node_time_queue_t *q,
    njt_http_vhost_traffic_status_node_time_t *x);
njt_int_t njt_http_vhost_traffic_status_node_time_queue_rear(
    njt_http_vhost_traffic_status_node_time_queue_t *q);

njt_msec_t njt_http_vhost_traffic_status_node_time_queue_average(
    njt_http_vhost_traffic_status_node_time_queue_t *q,
    njt_int_t method, njt_msec_t period);
njt_msec_t njt_http_vhost_traffic_status_node_time_queue_amm(
    njt_http_vhost_traffic_status_node_time_queue_t *q,
    njt_msec_t period);
njt_msec_t njt_http_vhost_traffic_status_node_time_queue_wma(
    njt_http_vhost_traffic_status_node_time_queue_t *q,
    njt_msec_t period);
void njt_http_vhost_traffic_status_node_time_queue_merge(
    njt_http_vhost_traffic_status_node_time_queue_t *a,
    njt_http_vhost_traffic_status_node_time_queue_t *b,
    njt_msec_t period);

void njt_http_vhost_traffic_status_node_histogram_bucket_init(
    njt_http_request_t *r,
    njt_http_vhost_traffic_status_node_histogram_bucket_t *b);
void njt_http_vhost_traffic_status_node_histogram_observe(
    njt_http_vhost_traffic_status_node_histogram_bucket_t *b,
    njt_msec_int_t x);

void njt_http_vhost_traffic_status_find_name(njt_http_request_t *r,
    njt_str_t *buf);
njt_rbtree_node_t *njt_http_vhost_traffic_status_find_node(njt_http_request_t *r,
    njt_str_t *key, unsigned type, uint32_t key_hash);

njt_rbtree_node_t *njt_http_vhost_traffic_status_find_lru(njt_http_request_t *r);
njt_rbtree_node_t *njt_http_vhost_traffic_status_find_lru_node(njt_http_request_t *r,
    njt_rbtree_node_t *a, njt_rbtree_node_t *b);
njt_rbtree_node_t *njt_http_vhost_traffic_status_find_lru_node_cmp(njt_http_request_t *r,
    njt_rbtree_node_t *a, njt_rbtree_node_t *b);

njt_int_t njt_http_vhost_traffic_status_node_member_cmp(njt_str_t *member, const char *name);
njt_atomic_uint_t njt_http_vhost_traffic_status_node_member(
    njt_http_vhost_traffic_status_node_t *vtsn,
    njt_str_t *member);


#endif /* _NJT_HTTP_VTS_NODE_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
