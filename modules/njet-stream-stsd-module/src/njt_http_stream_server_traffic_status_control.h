
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#ifndef _NJT_HTTP_STREAM_STS_CONTROL_H_INCLUDED_
#define _NJT_HTTP_STREAM_STS_CONTROL_H_INCLUDED_


#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_CONTROL_CMD_NONE     0
#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_CONTROL_CMD_STATUS   1
#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_CONTROL_CMD_DELETE   2
#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_CONTROL_CMD_RESET    3

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_CONTROL_RANGE_NONE   0
#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_CONTROL_RANGE_ALL    1
#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_CONTROL_RANGE_GROUP  2
#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_CONTROL_RANGE_ZONE   3

#define NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_CONTROL "{" \
    "\"processingReturn\":%s,"                                     \
    "\"processingCommandString\":\"%V\","                          \
    "\"processingGroupString\":\"%V\","                            \
    "\"processingZoneString\":\"%V\","                             \
    "\"processingCounts\":%ui"                                     \
    "}"


typedef struct {
    njt_rbtree_node_t    *node;
} njt_http_stream_server_traffic_status_delete_t;


typedef struct {
    njt_http_request_t   *r;
    njt_uint_t            command;
    njt_int_t             group;
    njt_str_t            *zone;
    njt_str_t            *arg_cmd;
    njt_str_t            *arg_group;
    njt_str_t            *arg_zone;
    njt_uint_t            range;
    njt_uint_t            count;
    u_char              **buf;
} njt_http_stream_server_traffic_status_control_t;


void njt_http_stream_server_traffic_status_node_control_range_set(
    njt_http_stream_server_traffic_status_control_t *control);
void njt_http_stream_server_traffic_status_node_status(
    njt_http_stream_server_traffic_status_control_t *control);
void njt_http_stream_server_traffic_status_node_delete(
    njt_http_stream_server_traffic_status_control_t *control);
void njt_http_stream_server_traffic_status_node_reset(
    njt_http_stream_server_traffic_status_control_t *control);


#endif /* _NJT_HTTP_STREAM_STS_CONTROL_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
