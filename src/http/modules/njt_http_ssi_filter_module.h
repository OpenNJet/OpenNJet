
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_SSI_FILTER_H_INCLUDED_
#define _NJT_HTTP_SSI_FILTER_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


#define NJT_HTTP_SSI_MAX_PARAMS       16

#define NJT_HTTP_SSI_COMMAND_LEN      32
#define NJT_HTTP_SSI_PARAM_LEN        32
#define NJT_HTTP_SSI_PARAMS_N         4


#define NJT_HTTP_SSI_COND_IF          1
#define NJT_HTTP_SSI_COND_ELSE        2


#define NJT_HTTP_SSI_NO_ENCODING      0
#define NJT_HTTP_SSI_URL_ENCODING     1
#define NJT_HTTP_SSI_ENTITY_ENCODING  2


typedef struct {
    njt_hash_t                hash;
    njt_hash_keys_arrays_t    commands;
} njt_http_ssi_main_conf_t;


typedef struct {
    njt_buf_t                *buf;

    u_char                   *pos;
    u_char                   *copy_start;
    u_char                   *copy_end;

    njt_uint_t                key;
    njt_str_t                 command;
    njt_array_t               params;
    njt_table_elt_t          *param;
    njt_table_elt_t           params_array[NJT_HTTP_SSI_PARAMS_N];

    njt_chain_t              *in;
    njt_chain_t              *out;
    njt_chain_t             **last_out;
    njt_chain_t              *busy;
    njt_chain_t              *free;

    njt_uint_t                state;
    njt_uint_t                saved_state;
    size_t                    saved;
    size_t                    looked;

    size_t                    value_len;

    njt_list_t               *variables;
    njt_array_t              *blocks;

#if (NJT_PCRE)
    njt_uint_t                ncaptures;
    int                      *captures;
    u_char                   *captures_data;
#endif

    unsigned                  shared:1;
    unsigned                  conditional:2;
    unsigned                  encoding:2;
    unsigned                  block:1;
    unsigned                  output:1;
    unsigned                  output_chosen:1;

    njt_http_request_t       *wait;
    void                     *value_buf;
    njt_str_t                 timefmt;
    njt_str_t                 errmsg;
} njt_http_ssi_ctx_t;


typedef njt_int_t (*njt_http_ssi_command_pt) (njt_http_request_t *r,
    njt_http_ssi_ctx_t *ctx, njt_str_t **);


typedef struct {
    njt_str_t                 name;
    njt_uint_t                index;

    unsigned                  mandatory:1;
    unsigned                  multiple:1;
} njt_http_ssi_param_t;


typedef struct {
    njt_str_t                 name;
    njt_http_ssi_command_pt   handler;
    njt_http_ssi_param_t     *params;

    unsigned                  conditional:2;
    unsigned                  block:1;
    unsigned                  flush:1;
} njt_http_ssi_command_t;


extern njt_module_t  njt_http_ssi_filter_module;


#endif /* _NJT_HTTP_SSI_FILTER_H_INCLUDED_ */
