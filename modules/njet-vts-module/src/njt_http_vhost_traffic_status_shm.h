
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 * Copyright (C), 2021-2023, TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_VTS_SHM_H_INCLUDED_
#define _NJT_HTTP_VTS_SHM_H_INCLUDED_


typedef struct {
    njt_str_t   *name;
    njt_uint_t   max_size;
    njt_uint_t   used_size;
    njt_uint_t   used_node;

    njt_uint_t   filter_used_size;
    njt_uint_t   filter_used_node;
} njt_http_vhost_traffic_status_shm_info_t;


njt_int_t njt_http_vhost_traffic_status_shm_add_server(njt_http_request_t *r);
njt_int_t njt_http_vhost_traffic_status_shm_add_filter(njt_http_request_t *r);
njt_int_t njt_http_vhost_traffic_status_shm_add_upstream(njt_http_request_t *r);

#if (NJT_HTTP_CACHE)
njt_int_t njt_http_vhost_traffic_status_shm_add_cache(njt_http_request_t *r);
#endif

void njt_http_vhost_traffic_status_shm_info_node(njt_http_request_t *r,
    njt_http_vhost_traffic_status_shm_info_t *shm_info, njt_rbtree_node_t *node);
void njt_http_vhost_traffic_status_shm_info(njt_http_request_t *r,
    njt_http_vhost_traffic_status_shm_info_t *shm_info);
njt_http_vhost_traffic_status_node_t *
    njt_http_vhost_traffic_status_map_node(njt_slab_pool_t *shpool, njt_http_vhost_traffic_status_node_t *vtsn);


#endif /* _NJT_HTTP_VTS_SHM_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
