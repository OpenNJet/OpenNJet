
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 * Copyright (C), 2021-2023, TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_VTS_SET_H_INCLUDED_
#define _NJT_HTTP_VTS_SET_H_INCLUDED_


typedef struct {
    njt_int_t                  index;
    njt_http_complex_value_t   value;
    njt_http_set_variable_pt   set_handler;
} njt_http_vhost_traffic_status_filter_variable_t;


njt_int_t njt_http_vhost_traffic_status_set_handler(njt_http_request_t *r);
char *njt_http_vhost_traffic_status_set_by_filter(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);


#endif /* _NJT_HTTP_VTS_SET_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
