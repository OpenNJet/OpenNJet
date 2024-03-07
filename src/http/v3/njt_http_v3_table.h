
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_V3_TABLE_H_INCLUDED_
#define _NJT_HTTP_V3_TABLE_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


typedef struct {
    njt_str_t                     name;
    njt_str_t                     value;
} njt_http_v3_field_t;


typedef struct {
    njt_http_v3_field_t         **elts;
    njt_uint_t                    nelts;
    njt_uint_t                    base;
    size_t                        size;
    size_t                        capacity;
    uint64_t                      insert_count;
    uint64_t                      ack_insert_count;
    njt_event_t                   send_insert_count;
} njt_http_v3_dynamic_table_t;


void njt_http_v3_inc_insert_count_handler(njt_event_t *ev);
void njt_http_v3_cleanup_table(njt_http_v3_session_t *h3c);
njt_int_t njt_http_v3_ref_insert(njt_connection_t *c, njt_uint_t dynamic,
    njt_uint_t index, njt_str_t *value);
njt_int_t njt_http_v3_insert(njt_connection_t *c, njt_str_t *name,
    njt_str_t *value);
njt_int_t njt_http_v3_set_capacity(njt_connection_t *c, njt_uint_t capacity);
njt_int_t njt_http_v3_duplicate(njt_connection_t *c, njt_uint_t index);
njt_int_t njt_http_v3_ack_section(njt_connection_t *c, njt_uint_t stream_id);
njt_int_t njt_http_v3_inc_insert_count(njt_connection_t *c, njt_uint_t inc);
njt_int_t njt_http_v3_lookup_static(njt_connection_t *c, njt_uint_t index,
    njt_str_t *name, njt_str_t *value);
njt_int_t njt_http_v3_lookup(njt_connection_t *c, njt_uint_t index,
    njt_str_t *name, njt_str_t *value);
njt_int_t njt_http_v3_decode_insert_count(njt_connection_t *c,
    njt_uint_t *insert_count);
njt_int_t njt_http_v3_check_insert_count(njt_connection_t *c,
    njt_uint_t insert_count);
void njt_http_v3_ack_insert_count(njt_connection_t *c, uint64_t insert_count);
njt_int_t njt_http_v3_set_param(njt_connection_t *c, uint64_t id,
    uint64_t value);


#endif /* _NJT_HTTP_V3_TABLE_H_INCLUDED_ */
