
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 * Copyright (C), 2021-2023, TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_VTS_VARIABLES_H_INCLUDED_
#define _NJT_HTTP_VTS_VARIABLES_H_INCLUDED_


njt_int_t njt_http_vhost_traffic_status_node_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
njt_int_t njt_http_vhost_traffic_status_add_variables(njt_conf_t *cf);


#endif /* _NJT_HTTP_VTS_VARIABLES_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
