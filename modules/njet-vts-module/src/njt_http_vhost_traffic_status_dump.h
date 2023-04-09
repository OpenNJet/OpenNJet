
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 * Copyright (C), 2021-2023, TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_VTS_DUMP_H_INCLUDED_
#define _NJT_HTTP_VTS_DUMP_H_INCLUDED_


#define NJT_HTTP_VHOST_TRAFFIC_STATUS_DUMP_HEADER_NAME_SIZE  128
#define NJT_HTTP_VHOST_TRAFFIC_STATUS_DUMP_DATA_BUF_SIZE     1024


typedef struct {
    u_char           name[NJT_HTTP_VHOST_TRAFFIC_STATUS_DUMP_HEADER_NAME_SIZE];
    njt_msec_t       time;
    njt_uint_t       version;
} njt_http_vhost_traffic_status_dump_header_t;


void njt_http_vhost_traffic_status_file_lock(njt_file_t *file);
void njt_http_vhost_traffic_status_file_unlock(njt_file_t *file);
void njt_http_vhost_traffic_status_file_close(njt_file_t *file);

njt_int_t njt_http_vhost_traffic_status_dump_execute(njt_event_t *ev);
void njt_http_vhost_traffic_status_dump_handler(njt_event_t *ev);
void njt_http_vhost_traffic_status_dump_restore(njt_event_t *ev);


#endif /* _NJT_HTTP_VTS_DUMP_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
