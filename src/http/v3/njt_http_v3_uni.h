
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_V3_UNI_H_INCLUDED_
#define _NJT_HTTP_V3_UNI_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


void njt_http_v3_init_uni_stream(njt_connection_t *c);
njt_int_t njt_http_v3_register_uni_stream(njt_connection_t *c, uint64_t type);

njt_int_t njt_http_v3_cancel_stream(njt_connection_t *c, njt_uint_t stream_id);

njt_int_t njt_http_v3_send_settings(njt_connection_t *c);
njt_int_t njt_http_v3_send_goaway(njt_connection_t *c, uint64_t id);
njt_int_t njt_http_v3_send_ack_section(njt_connection_t *c,
    njt_uint_t stream_id);
njt_int_t njt_http_v3_send_cancel_stream(njt_connection_t *c,
    njt_uint_t stream_id);
njt_int_t njt_http_v3_send_inc_insert_count(njt_connection_t *c,
    njt_uint_t inc);


#endif /* _NJT_HTTP_V3_UNI_H_INCLUDED_ */
