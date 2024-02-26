
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#ifndef _NJT_STREAM_STS_FILTER_H_INCLUDED_
#define _NJT_STREAM_STS_FILTER_H_INCLUDED_


typedef struct {
    njt_str_t                                 key;
} njt_stream_server_traffic_status_filter_key_t;


typedef struct {
    uint32_t                                  hash;
    njt_uint_t                                index;
} njt_stream_server_traffic_status_filter_uniq_t;


typedef struct {
    njt_stream_server_traffic_status_node_t  *node;
} njt_stream_server_traffic_status_filter_node_t;


int njt_libc_cdecl njt_stream_server_traffic_status_filter_cmp_hashs(
    const void *one, const void *two);
int njt_libc_cdecl njt_stream_server_traffic_status_filter_cmp_keys(
    const void *one, const void *two);
njt_int_t njt_stream_server_traffic_status_filter_unique(
    njt_pool_t *pool, njt_array_t **keys);
njt_int_t njt_stream_server_traffic_status_filter_get_keys(
    njt_stream_session_t *s, njt_array_t **filter_keys,
    njt_rbtree_node_t *node);
njt_int_t njt_stream_server_traffic_status_filter_get_nodes(
    njt_stream_session_t *s, njt_array_t **filter_nodes,
    njt_str_t *name, njt_rbtree_node_t *node);


char *njt_stream_server_traffic_status_filter_by_set_key(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);


#endif /* _NJT_STREAM_STS_FILTER_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
