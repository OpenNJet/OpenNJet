
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#ifndef _NJT_STREAM_STS_NODE_H_INCLUDED_
#define _NJT_STREAM_STS_NODE_H_INCLUDED_

#define NJT_STREAM_SERVER_TRAFFIC_STATUS_DEFAULT_QUEUE_LEN   64
#define NJT_STREAM_SERVER_TRAFFIC_STATUS_DEFAULT_BUCKET_LEN  32


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


njt_int_t njt_stream_server_traffic_status_node_generate_key(njt_pool_t *pool,
    njt_str_t *buf, njt_str_t *dst, unsigned type);
njt_int_t njt_stream_server_traffic_status_node_position_key(njt_str_t *buf,
    size_t pos);

njt_rbtree_node_t *njt_stream_server_traffic_status_node_lookup(
    njt_rbtree_t *rbtree, njt_str_t *key, uint32_t hash);
void njt_stream_server_traffic_status_node_zero(
    njt_stream_server_traffic_status_node_t *stsn);
void njt_stream_server_traffic_status_node_init(njt_stream_session_t *s,
    njt_stream_server_traffic_status_node_t *stsn);
void njt_stream_server_traffic_status_node_set(njt_stream_session_t *s,
    njt_stream_server_traffic_status_node_t *stsn);

void njt_stream_server_traffic_status_node_time_queue_zero(
    njt_stream_server_traffic_status_node_time_queue_t *q);
void njt_stream_server_traffic_status_node_time_queue_init(
    njt_stream_server_traffic_status_node_time_queue_t *q);
void njt_stream_server_traffic_status_node_time_queue_insert(
    njt_stream_server_traffic_status_node_time_queue_t *q,
    njt_msec_int_t x);
njt_int_t njt_stream_server_traffic_status_node_time_queue_push(
    njt_stream_server_traffic_status_node_time_queue_t *q,
    njt_msec_int_t x);
njt_int_t njt_stream_server_traffic_status_node_time_queue_pop(
    njt_stream_server_traffic_status_node_time_queue_t *q,
    njt_stream_server_traffic_status_node_time_t *x);
njt_msec_t njt_stream_server_traffic_status_node_time_queue_average(
    njt_stream_server_traffic_status_node_time_queue_t *q,
    njt_int_t method, njt_msec_t period);
njt_msec_t njt_stream_server_traffic_status_node_time_queue_amm(
    njt_stream_server_traffic_status_node_time_queue_t *q,
    njt_msec_t period);
njt_msec_t njt_stream_server_traffic_status_node_time_queue_wma(
    njt_stream_server_traffic_status_node_time_queue_t *q,
    njt_msec_t period);

void njt_stream_server_traffic_status_node_histogram_bucket_init(
    njt_stream_session_t *s,
    njt_stream_server_traffic_status_node_histogram_bucket_t *b);
void njt_stream_server_traffic_status_node_histogram_observe(
    njt_stream_server_traffic_status_node_histogram_bucket_t *b,
    njt_msec_int_t x);

njt_int_t njt_stream_server_traffic_status_find_name(njt_stream_session_t *s,
    njt_str_t *buf);
njt_rbtree_node_t *njt_stream_server_traffic_status_find_node(njt_stream_session_t *s,
    njt_str_t *key, unsigned type, uint32_t key_hash);

njt_int_t njt_stream_server_traffic_status_node_member_cmp(njt_str_t *member, const char *name);
njt_atomic_uint_t njt_stream_server_traffic_status_node_member(njt_stream_server_traffic_status_node_t *stsn,
    njt_str_t *member);


#endif /* _NJT_STREAM_STS_NODE_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
