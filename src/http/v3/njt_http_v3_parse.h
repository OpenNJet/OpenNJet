
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_V3_PARSE_H_INCLUDED_
#define _NJT_HTTP_V3_PARSE_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


typedef struct {
    njt_uint_t                      state;
    uint64_t                        value;
} njt_http_v3_parse_varlen_int_t;


typedef struct {
    njt_uint_t                      state;
    njt_uint_t                      shift;
    uint64_t                        value;
} njt_http_v3_parse_prefix_int_t;


typedef struct {
    njt_uint_t                      state;
    uint64_t                        id;
    njt_http_v3_parse_varlen_int_t  vlint;
} njt_http_v3_parse_settings_t;


typedef struct {
    njt_uint_t                      state;
    njt_uint_t                      insert_count;
    njt_uint_t                      delta_base;
    njt_uint_t                      sign;
    njt_uint_t                      base;
    njt_http_v3_parse_prefix_int_t  pint;
} njt_http_v3_parse_field_section_prefix_t;


typedef struct {
    njt_uint_t                      state;
    njt_uint_t                      length;
    njt_uint_t                      huffman;
    njt_str_t                       value;
    u_char                         *last;
    u_char                          huffstate;
} njt_http_v3_parse_literal_t;


typedef struct {
    njt_uint_t                      state;
    njt_uint_t                      index;
    njt_uint_t                      base;
    njt_uint_t                      dynamic;

    njt_str_t                       name;
    njt_str_t                       value;

    njt_http_v3_parse_prefix_int_t  pint;
    njt_http_v3_parse_literal_t     literal;
} njt_http_v3_parse_field_t;


typedef struct {
    njt_uint_t                      state;
    njt_http_v3_parse_field_t       field;
} njt_http_v3_parse_field_rep_t;


typedef struct {
    njt_uint_t                      state;
    njt_uint_t                      type;
    njt_uint_t                      length;
    njt_http_v3_parse_varlen_int_t  vlint;
    njt_http_v3_parse_field_section_prefix_t  prefix;
    njt_http_v3_parse_field_rep_t   field_rep;
} njt_http_v3_parse_headers_t;


typedef struct {
    njt_uint_t                      state;
    njt_http_v3_parse_field_t       field;
    njt_http_v3_parse_prefix_int_t  pint;
} njt_http_v3_parse_encoder_t;


typedef struct {
    njt_uint_t                      state;
    njt_http_v3_parse_prefix_int_t  pint;
} njt_http_v3_parse_decoder_t;


typedef struct {
    njt_uint_t                      state;
    njt_uint_t                      type;
    njt_uint_t                      length;
    njt_http_v3_parse_varlen_int_t  vlint;
    njt_http_v3_parse_settings_t    settings;
} njt_http_v3_parse_control_t;


typedef struct {
    njt_uint_t                      state;
    njt_http_v3_parse_varlen_int_t  vlint;
    union {
        njt_http_v3_parse_encoder_t  encoder;
        njt_http_v3_parse_decoder_t  decoder;
        njt_http_v3_parse_control_t  control;
    } u;
} njt_http_v3_parse_uni_t;


typedef struct {
    njt_uint_t                      state;
    njt_uint_t                      type;
    njt_uint_t                      length;
    njt_http_v3_parse_varlen_int_t  vlint;
} njt_http_v3_parse_data_t;


/*
 * Parse functions return codes:
 *   NJT_DONE - parsing done
 *   NJT_OK - sub-element done
 *   NJT_AGAIN - more data expected
 *   NJT_BUSY - waiting for external event
 *   NJT_ERROR - internal error
 *   NJT_HTTP_V3_ERROR_XXX - HTTP/3 or QPACK error
 */

njt_int_t njt_http_v3_parse_headers(njt_connection_t *c,
    njt_http_v3_parse_headers_t *st, njt_buf_t *b);
njt_int_t njt_http_v3_parse_data(njt_connection_t *c,
    njt_http_v3_parse_data_t *st, njt_buf_t *b);
njt_int_t njt_http_v3_parse_uni(njt_connection_t *c,
    njt_http_v3_parse_uni_t *st, njt_buf_t *b);


#endif /* _NJT_HTTP_V3_PARSE_H_INCLUDED_ */
