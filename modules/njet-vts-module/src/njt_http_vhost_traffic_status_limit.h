
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 * Copyright (C), 2021-2023, TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_VTS_LIMIT_H_INCLUDED_
#define _NJT_HTTP_VTS_LIMIT_H_INCLUDED_


typedef struct {
    njt_http_complex_value_t     key;
    njt_http_complex_value_t     variable;
    njt_atomic_t                 size;
    njt_uint_t                   code;
    unsigned                     type;        /* unsigned type:5 */
} njt_http_vhost_traffic_status_limit_t;


njt_int_t njt_http_vhost_traffic_status_limit_handler(njt_http_request_t *r);
njt_int_t njt_http_vhost_traffic_status_limit_handler_traffic(njt_http_request_t *r,
    njt_array_t *traffics);

njt_int_t njt_http_vhost_traffic_status_limit_traffic_unique(
    njt_pool_t *pool, njt_array_t **keys);
char *njt_http_vhost_traffic_status_limit_traffic(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);
char *njt_http_vhost_traffic_status_limit_traffic_by_set_key(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);


#endif /* _NJT_HTTP_VTS_LIMIT_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
