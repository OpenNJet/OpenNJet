
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#ifndef _NJT_HTTP_STREAM_STS_FILTER_H_INCLUDED_
#define _NJT_HTTP_STREAM_STS_FILTER_H_INCLUDED_


typedef struct {
    njt_http_complex_value_t                      filter_key;
    njt_http_complex_value_t                      filter_name;
} njt_http_stream_server_traffic_status_filter_t;


typedef struct {
    njt_str_t                                      key;
} njt_http_stream_server_traffic_status_filter_key_t;


typedef struct {
    uint32_t                                       hash;
    njt_uint_t                                     index;
} njt_http_stream_server_traffic_status_filter_uniq_t;


typedef struct {
    njt_http_stream_server_traffic_status_node_t  *node;
} njt_http_stream_server_traffic_status_filter_node_t;


int njt_libc_cdecl njt_http_stream_server_traffic_status_filter_cmp_keys(
    const void *one, const void *two);
njt_int_t njt_http_stream_server_traffic_status_filter_get_keys(
    njt_http_request_t *r, njt_array_t **filter_keys,
    njt_rbtree_node_t *node);
njt_int_t njt_http_stream_server_traffic_status_filter_get_nodes(
    njt_http_request_t *r, njt_array_t **filter_nodes,
    njt_str_t *name, njt_rbtree_node_t *node);


#endif /* _NJT_HTTP_STREAM_STS_FILTER_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
