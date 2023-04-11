
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_STREAM_SCRIPT_H_INCLUDED_
#define _NJT_STREAM_SCRIPT_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>


typedef struct {
    u_char                       *ip;
    u_char                       *pos;
    njt_stream_variable_value_t  *sp;

    njt_str_t                     buf;
    njt_str_t                     line;

    unsigned                      flushed:1;
    unsigned                      skip:1;

    njt_stream_session_t         *session;
} njt_stream_script_engine_t;


typedef struct {
    njt_conf_t                   *cf;
    njt_str_t                    *source;

    njt_array_t                 **flushes;
    njt_array_t                 **lengths;
    njt_array_t                 **values;

    njt_uint_t                    variables;
    njt_uint_t                    ncaptures;
    njt_uint_t                    size;

    void                         *main;

    unsigned                      complete_lengths:1;
    unsigned                      complete_values:1;
    unsigned                      zero:1;
    unsigned                      conf_prefix:1;
    unsigned                      root_prefix:1;
} njt_stream_script_compile_t;


typedef struct {
    njt_str_t                     value;
    njt_uint_t                   *flushes;
    void                         *lengths;
    void                         *values;

    union {
        size_t                    size;
    } u;
} njt_stream_complex_value_t;


typedef struct {
    njt_conf_t                   *cf;
    njt_str_t                    *value;
    njt_stream_complex_value_t   *complex_value;

    unsigned                      zero:1;
    unsigned                      conf_prefix:1;
    unsigned                      root_prefix:1;
} njt_stream_compile_complex_value_t;


typedef void (*njt_stream_script_code_pt) (njt_stream_script_engine_t *e);
typedef size_t (*njt_stream_script_len_code_pt) (njt_stream_script_engine_t *e);


typedef struct {
    njt_stream_script_code_pt     code;
    uintptr_t                     len;
} njt_stream_script_copy_code_t;


typedef struct {
    njt_stream_script_code_pt     code;
    uintptr_t                     index;
} njt_stream_script_var_code_t;


typedef struct {
    njt_stream_script_code_pt     code;
    uintptr_t                     n;
} njt_stream_script_copy_capture_code_t;


typedef struct {
    njt_stream_script_code_pt     code;
    uintptr_t                     conf_prefix;
} njt_stream_script_full_name_code_t;


void njt_stream_script_flush_complex_value(njt_stream_session_t *s,
    njt_stream_complex_value_t *val);
njt_int_t njt_stream_complex_value(njt_stream_session_t *s,
    njt_stream_complex_value_t *val, njt_str_t *value);
size_t njt_stream_complex_value_size(njt_stream_session_t *s,
    njt_stream_complex_value_t *val, size_t default_value);
njt_int_t njt_stream_compile_complex_value(
    njt_stream_compile_complex_value_t *ccv);
char *njt_stream_set_complex_value_slot(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_stream_set_complex_value_zero_slot(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_stream_set_complex_value_size_slot(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);


njt_uint_t njt_stream_script_variables_count(njt_str_t *value);
njt_int_t njt_stream_script_compile(njt_stream_script_compile_t *sc);
u_char *njt_stream_script_run(njt_stream_session_t *s, njt_str_t *value,
    void *code_lengths, size_t reserved, void *code_values);
void njt_stream_script_flush_no_cacheable_variables(njt_stream_session_t *s,
    njt_array_t *indices);

void *njt_stream_script_add_code(njt_array_t *codes, size_t size, void *code);

size_t njt_stream_script_copy_len_code(njt_stream_script_engine_t *e);
void njt_stream_script_copy_code(njt_stream_script_engine_t *e);
size_t njt_stream_script_copy_var_len_code(njt_stream_script_engine_t *e);
void njt_stream_script_copy_var_code(njt_stream_script_engine_t *e);
size_t njt_stream_script_copy_capture_len_code(njt_stream_script_engine_t *e);
void njt_stream_script_copy_capture_code(njt_stream_script_engine_t *e);

#endif /* _NJT_STREAM_SCRIPT_H_INCLUDED_ */
