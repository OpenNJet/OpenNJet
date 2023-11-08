
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_VARIABLES_H_INCLUDED_
#define _NJT_HTTP_VARIABLES_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


typedef njt_variable_value_t  njt_http_variable_value_t;

#define njt_http_variable(v)     { sizeof(v) - 1, 1, 0, 0, 0, (u_char *) v }

typedef struct njt_http_variable_s  njt_http_variable_t;

typedef void (*njt_http_set_variable_pt) (njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
typedef njt_int_t (*njt_http_get_variable_pt) (njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);


#define NJT_HTTP_VAR_CHANGEABLE   1
#define NJT_HTTP_VAR_NOCACHEABLE  2
#define NJT_HTTP_VAR_INDEXED      4
#define NJT_HTTP_VAR_NOHASH       8
#define NJT_HTTP_VAR_WEAK         16
#define NJT_HTTP_VAR_PREFIX       32
#define NJT_HTTP_DYN_VAR          64
#define NJT_HTTP_DYN_DEL          128
#define NJT_VAR_INIT_REF_COUNT    1


struct njt_http_variable_s {
    njt_str_t                     name;   /* must be first to build the hash */
    njt_http_set_variable_pt      set_handler;
    njt_http_get_variable_pt      get_handler;
    uintptr_t                     data;
    njt_uint_t                    flags;
    njt_uint_t                    index;
	njt_uint_t                    ref_count;
};
#define njt_http_null_variable  { njt_null_string, NULL, NULL, 0, 0, 0, NJT_VAR_INIT_REF_COUNT}


njt_http_variable_t *njt_http_add_variable(njt_conf_t *cf, njt_str_t *name,
    njt_uint_t flags);
njt_int_t njt_http_get_variable_index(njt_conf_t *cf, njt_str_t *name);
njt_http_variable_value_t *njt_http_get_indexed_variable(njt_http_request_t *r,
    njt_uint_t index);
njt_http_variable_value_t *njt_http_get_flushed_variable(njt_http_request_t *r,
    njt_uint_t index);

njt_http_variable_value_t *njt_http_get_variable(njt_http_request_t *r,
    njt_str_t *name, njt_uint_t key);

njt_int_t njt_http_variable_unknown_header(njt_http_request_t *r,
    njt_http_variable_value_t *v, njt_str_t *var, njt_list_part_t *part,
    size_t prefix);


#if (NJT_PCRE)

typedef struct {
    njt_uint_t                    capture;
    njt_int_t                     index;
} njt_http_regex_variable_t;


typedef struct {
    njt_regex_t                  *regex;
    njt_uint_t                    ncaptures;
    njt_http_regex_variable_t    *variables;
    njt_uint_t                    nvariables;
    njt_str_t                     name;
} njt_http_regex_t;


typedef struct {
    njt_http_regex_t             *regex;
    void                         *value;
} njt_http_map_regex_t;


njt_http_regex_t *njt_http_regex_compile(njt_conf_t *cf,
    njt_regex_compile_t *rc);
njt_int_t njt_http_regex_exec(njt_http_request_t *r, njt_http_regex_t *re,
    njt_str_t *s);

#endif


typedef struct {
    njt_hash_combined_t           hash;
#if (NJT_PCRE)
    njt_http_map_regex_t         *regex;
    njt_uint_t                    nregex;
#endif
} njt_http_map_t;


void *njt_http_map_find(njt_http_request_t *r, njt_http_map_t *map,
    njt_str_t *match);


njt_int_t njt_http_variables_add_core_vars(njt_conf_t *cf);
njt_int_t njt_http_variables_init_vars(njt_conf_t *cf);
njt_int_t njt_http_variables_init_vars_dyn(njt_conf_t *cf);


extern njt_http_variable_value_t  njt_http_variable_null_value;
extern njt_http_variable_value_t  njt_http_variable_true_value;


#endif /* _NJT_HTTP_VARIABLES_H_INCLUDED_ */
