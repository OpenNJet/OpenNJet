
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_V3_ENCODE_H_INCLUDED_
#define _NJT_HTTP_V3_ENCODE_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


uintptr_t njt_http_v3_encode_varlen_int(u_char *p, uint64_t value);
uintptr_t njt_http_v3_encode_prefix_int(u_char *p, uint64_t value,
    njt_uint_t prefix);

uintptr_t njt_http_v3_encode_field_section_prefix(u_char *p,
    njt_uint_t insert_count, njt_uint_t sign, njt_uint_t delta_base);
uintptr_t njt_http_v3_encode_field_ri(u_char *p, njt_uint_t dynamic,
    njt_uint_t index);
uintptr_t njt_http_v3_encode_field_lri(u_char *p, njt_uint_t dynamic,
    njt_uint_t index, u_char *data, size_t len);
uintptr_t njt_http_v3_encode_field_l(u_char *p, njt_str_t *name,
    njt_str_t *value);
uintptr_t njt_http_v3_encode_field_pbi(u_char *p, njt_uint_t index);
uintptr_t njt_http_v3_encode_field_lpbi(u_char *p, njt_uint_t index,
    u_char *data, size_t len);


#endif /* _NJT_HTTP_V3_ENCODE_H_INCLUDED_ */
