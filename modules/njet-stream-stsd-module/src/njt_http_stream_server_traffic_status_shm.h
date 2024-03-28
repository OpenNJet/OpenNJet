
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#ifndef _NJT_HTTP_STREAM_STS_SHM_H_INCLUDED_
#define _NJT_HTTP_STREAM_STS_SHM_H_INCLUDED_


typedef struct {
    njt_str_t   *name;
    njt_uint_t   max_size;
    njt_uint_t   used_size;
    njt_uint_t   used_node;
} njt_http_stream_server_traffic_status_shm_info_t;


void njt_http_stream_server_traffic_status_shm_info_node(njt_http_request_t *r,
    njt_http_stream_server_traffic_status_shm_info_t *shm_info,
    njt_rbtree_node_t *node);
void njt_http_stream_server_traffic_status_shm_info(njt_http_request_t *r,
    njt_http_stream_server_traffic_status_shm_info_t *shm_info);

njt_int_t njt_http_stream_server_traffic_status_shm_init(njt_http_request_t *r);
njt_shm_zone_t *njt_http_stream_server_traffic_status_shm_find_zone(njt_http_request_t *r,
    njt_str_t *name);


#endif /* _NJT_HTTP_STREAM_STS_SHM_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
