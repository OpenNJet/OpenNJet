
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#ifndef _NJT_STREAM_STS_NODE_H_INCLUDED_
#define _NJT_STREAM_STS_NODE_H_INCLUDED_

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
