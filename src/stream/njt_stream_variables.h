
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_STREAM_VARIABLES_H_INCLUDED_
#define _NJT_STREAM_VARIABLES_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>


typedef njt_variable_value_t  njt_stream_variable_value_t;

#define njt_stream_variable(v)     { sizeof(v) - 1, 1, 0, 0, 0, (u_char *) v }

typedef struct njt_stream_variable_s  njt_stream_variable_t;

typedef void (*njt_stream_set_variable_pt) (njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);
typedef njt_int_t (*njt_stream_get_variable_pt) (njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);


#define NJT_STREAM_VAR_CHANGEABLE   1
#define NJT_STREAM_VAR_NOCACHEABLE  2
#define NJT_STREAM_VAR_INDEXED      4
#define NJT_STREAM_VAR_NOHASH       8
#define NJT_STREAM_VAR_WEAK         16
#define NJT_STREAM_VAR_PREFIX       32


struct njt_stream_variable_s {
    njt_str_t                     name;   /* must be first to build the hash */
    njt_stream_set_variable_pt    set_handler;
    njt_stream_get_variable_pt    get_handler;
    uintptr_t                     data;
    njt_uint_t                    flags;
    njt_uint_t                    index;
};

#define njt_stream_null_variable  { njt_null_string, NULL, NULL, 0, 0, 0 }


njt_stream_variable_t *njt_stream_add_variable(njt_conf_t *cf, njt_str_t *name,
    njt_uint_t flags);
njt_int_t njt_stream_get_variable_index(njt_conf_t *cf, njt_str_t *name);
njt_stream_variable_value_t *njt_stream_get_indexed_variable(
    njt_stream_session_t *s, njt_uint_t index);
njt_stream_variable_value_t *njt_stream_get_flushed_variable(
    njt_stream_session_t *s, njt_uint_t index);

njt_stream_variable_value_t *njt_stream_get_variable(njt_stream_session_t *s,
    njt_str_t *name, njt_uint_t key);


#if (NJT_PCRE)

typedef struct {
    njt_uint_t                    capture;
    njt_int_t                     index;
} njt_stream_regex_variable_t;


typedef struct {
    njt_regex_t                  *regex;
    njt_uint_t                    ncaptures;
    njt_stream_regex_variable_t  *variables;
    njt_uint_t                    nvariables;
    njt_str_t                     name;
} njt_stream_regex_t;


typedef struct {
    njt_stream_regex_t           *regex;
    void                         *value;
} njt_stream_map_regex_t;


njt_stream_regex_t *njt_stream_regex_compile(njt_conf_t *cf,
    njt_regex_compile_t *rc);
njt_int_t njt_stream_regex_exec(njt_stream_session_t *s, njt_stream_regex_t *re,
    njt_str_t *str);

#endif


typedef struct {
    njt_hash_combined_t           hash;
#if (NJT_PCRE)
    njt_stream_map_regex_t       *regex;
    njt_uint_t                    nregex;
#endif
} njt_stream_map_t;


void *njt_stream_map_find(njt_stream_session_t *s, njt_stream_map_t *map,
    njt_str_t *match);


njt_int_t njt_stream_variables_add_core_vars(njt_conf_t *cf);
njt_int_t njt_stream_variables_init_vars(njt_conf_t *cf);


extern njt_stream_variable_value_t  njt_stream_variable_null_value;
extern njt_stream_variable_value_t  njt_stream_variable_true_value;


#endif /* _NJT_STREAM_VARIABLES_H_INCLUDED_ */
