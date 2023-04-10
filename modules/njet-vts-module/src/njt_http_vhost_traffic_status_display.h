
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 * Copyright (C), 2021-2023, TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_VTS_DISPLAY_H_INCLUDED_
#define _NJT_HTTP_VTS_DISPLAY_H_INCLUDED_


njt_int_t njt_http_vhost_traffic_status_display_get_upstream_nelts(
    njt_http_request_t *r);
njt_int_t njt_http_vhost_traffic_status_display_get_size(
    njt_http_request_t *r, njt_int_t format);

u_char *njt_http_vhost_traffic_status_display_get_time_queue(
    njt_http_request_t *r,
    njt_http_vhost_traffic_status_node_time_queue_t *q,
    njt_uint_t offset);
u_char *njt_http_vhost_traffic_status_display_get_time_queue_times(
    njt_http_request_t *r,
    njt_http_vhost_traffic_status_node_time_queue_t *q);
u_char *njt_http_vhost_traffic_status_display_get_time_queue_msecs(
    njt_http_request_t *r,
    njt_http_vhost_traffic_status_node_time_queue_t *q);

u_char *njt_http_vhost_traffic_status_display_get_histogram_bucket(
    njt_http_request_t *r,
    njt_http_vhost_traffic_status_node_histogram_bucket_t *b,
    njt_uint_t offset, const char *fmt);
u_char *njt_http_vhost_traffic_status_display_get_histogram_bucket_msecs(
    njt_http_request_t *r,
    njt_http_vhost_traffic_status_node_histogram_bucket_t *b);
u_char *njt_http_vhost_traffic_status_display_get_histogram_bucket_counters(
    njt_http_request_t *r,
    njt_http_vhost_traffic_status_node_histogram_bucket_t *q);



char *njt_http_vhost_traffic_status_display(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);


#endif /* _NJT_HTTP_VTS_DISPLAY_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
