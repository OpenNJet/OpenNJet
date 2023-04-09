
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 * Copyright (C), 2021-2023, TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_VTS_CONTROL_H_INCLUDED_
#define _NJT_HTTP_VTS_CONTROL_H_INCLUDED_


#define NJT_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_CMD_NONE     0
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_CMD_STATUS   1
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_CMD_DELETE   2
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_CMD_RESET    3

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_NONE   0
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_ALL    1
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_GROUP  2
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_CONTROL_RANGE_ZONE   3

#define NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_CONTROL "{"                     \
    "\"processingReturn\":%s,"                                                 \
    "\"processingCommandString\":\"%V\","                                      \
    "\"processingGroupString\":\"%V\","                                        \
    "\"processingZoneString\":\"%V\","                                         \
    "\"processingCounts\":%ui"                                                 \
    "}"


typedef struct {
    njt_rbtree_node_t           *node;
} njt_http_vhost_traffic_status_delete_t;


typedef struct {
    njt_http_request_t          *r;
    njt_uint_t                   command;
    njt_int_t                    group;
    njt_str_t                   *zone;
    njt_str_t                   *arg_cmd;
    njt_str_t                   *arg_group;
    njt_str_t                   *arg_zone;
    njt_str_t                   *arg_name;
    njt_uint_t                   range;
    njt_uint_t                   count;
    u_char                     **buf;
} njt_http_vhost_traffic_status_control_t;


void njt_http_vhost_traffic_status_node_control_range_set(
    njt_http_vhost_traffic_status_control_t *control);
void njt_http_vhost_traffic_status_node_status(
    njt_http_vhost_traffic_status_control_t *control);
void njt_http_vhost_traffic_status_node_delete(
    njt_http_vhost_traffic_status_control_t *control);
void njt_http_vhost_traffic_status_node_reset(
    njt_http_vhost_traffic_status_control_t *control);

void njt_http_vhost_traffic_status_node_upstream_lookup(
    njt_http_vhost_traffic_status_control_t *control,
    njt_http_upstream_server_t *us);

#endif /* _NJT_HTTP_VTS_CONTROL_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
