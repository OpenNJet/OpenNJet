/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#ifndef __NJT_HTTP_MATCH_MODULE_H__
#define __NJT_HTTP_MATCH_MODULE_H__

#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>

typedef struct njt_http_match_code_s {
    /*range such as 100-200 or a single one such as 188*/
    njt_flag_t  single;
    njt_uint_t  code;
    njt_uint_t  last_code;
} njt_http_match_code_t;


typedef struct njt_http_match_status_s {
    njt_flag_t    not_operation;
    /*array of the njt_http_status_t */
    njt_array_t   codes;
} njt_http_match_status_t;

#define  NJT_HTTP_MATCH_CONTAIN       0
#define  NJT_HTTP_MATCH_NOT_CONTAIN   1
#define  NJT_HTTP_MATCH_EQUAL         2
#define  NJT_HTTP_MATCH_NOT_EQUAL     4
#define  NJT_HTTP_MATCH_REG_MATCH     8
#define  NJT_HTTP_MATCH_NOT_REG_MATCH 16

typedef struct njt_http_match_header_s {
    njt_str_t      key;
    njt_str_t      value;
    njt_regex_t    *regex;
    njt_uint_t     operation;
} njt_http_match_header_t;


typedef struct njt_http_match_body_s {
    njt_uint_t           operation;
    njt_regex_t          *regex;
    njt_str_t            value;
} njt_http_match_body_t;


typedef struct njt_http_match_s {
    njt_flag_t                defined;
    njt_flag_t                conditions;
    njt_str_t                 name;
    njt_http_match_status_t   status;
    /*array of njt_http_match_header_t*/
    njt_array_t               headers;
    njt_http_match_body_t     body;
} njt_http_match_t;

/*
    by zhaokang
    stream match rule
*/
typedef struct njt_stream_match_s {
    njt_str_t                  send;      /* content need to send */
    njt_str_t                  expect;    /* expect string or binary */
} njt_stream_match_t;

#endif
