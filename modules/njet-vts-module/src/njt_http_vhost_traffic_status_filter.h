
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 * Copyright (C), 2021-2023, TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_VTS_FILTER_H_INCLUDED_
#define _NJT_HTTP_VTS_FILTER_H_INCLUDED_


typedef struct {
    njt_http_complex_value_t               filter_key;
    njt_http_complex_value_t               filter_name;
} njt_http_vhost_traffic_status_filter_t;


typedef struct {
    njt_str_t                              key;
} njt_http_vhost_traffic_status_filter_key_t;


typedef struct {
    uint32_t                               hash;
    njt_uint_t                             index;
} njt_http_vhost_traffic_status_filter_uniq_t;


typedef struct {
    njt_http_vhost_traffic_status_node_t  *node;
} njt_http_vhost_traffic_status_filter_node_t;


typedef struct {
    njt_str_t                              match;
} njt_http_vhost_traffic_status_filter_match_t;


int njt_libc_cdecl njt_http_traffic_status_filter_cmp_hashs(
    const void *one, const void *two);
int njt_libc_cdecl njt_http_traffic_status_filter_cmp_keys(
    const void *one, const void *two);
njt_int_t njt_http_vhost_traffic_status_filter_unique(
    njt_pool_t *pool, njt_array_t **keys);
njt_int_t njt_http_vhost_traffic_status_filter_get_keys(
    njt_http_request_t *r, njt_array_t **filter_keys,
    njt_rbtree_node_t *node);
njt_int_t njt_http_vhost_traffic_status_filter_get_nodes(
    njt_http_request_t *r, njt_array_t **filter_nodes,
    njt_str_t *name, njt_rbtree_node_t *node);
njt_int_t njt_http_vhost_traffic_status_filter_max_node_match(
    njt_http_request_t *r, njt_str_t *filter);

char *njt_http_vhost_traffic_status_filter_by_set_key(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);


#endif /* _NJT_HTTP_VTS_FILTER_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
