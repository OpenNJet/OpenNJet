
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_SCRIPT_H_INCLUDED_
#define _NJT_HTTP_SCRIPT_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


typedef struct {
    u_char                     *ip;
    u_char                     *pos;
    njt_http_variable_value_t  *sp;

    njt_str_t                   buf;
    njt_str_t                   line;

    /* the start of the rewritten arguments */
    u_char                     *args;

    unsigned                    flushed:1;
    unsigned                    skip:1;
    unsigned                    quote:1;
    unsigned                    is_args:1;
    unsigned                    log:1;

    njt_int_t                   status;
    njt_http_request_t         *request;
    njt_int_t                   ret;
} njt_http_script_engine_t;


typedef struct {
    njt_conf_t                 *cf;
    njt_str_t                  *source;

    njt_array_t               **flushes;
    njt_array_t               **lengths;
    njt_array_t               **values;

    njt_uint_t                  variables;
    njt_uint_t                  ncaptures;
    njt_uint_t                  captures_mask;
    njt_uint_t                  size;

    void                       *main;

    unsigned                    compile_args:1;
    unsigned                    complete_lengths:1;
    unsigned                    complete_values:1;
    unsigned                    zero:1;
    unsigned                    conf_prefix:1;
    unsigned                    root_prefix:1;

    unsigned                    dup_capture:1;
    unsigned                    args:1;
} njt_http_script_compile_t;


typedef struct {
    njt_str_t                   value;
    njt_uint_t                 *flushes;
    void                       *lengths;
    void                       *values;

    union {
        size_t                  size;
    } u;

//add by clb
#if (NJT_HTTP_DYNAMIC_LOC)
    njt_uint_t                  dynamic;
    njt_pool_t                  *pool;
#endif
} njt_http_complex_value_t;


typedef struct {
    njt_conf_t                 *cf;
    njt_str_t                  *value;
    njt_http_complex_value_t   *complex_value;

    unsigned                    zero:1;
    unsigned                    conf_prefix:1;
    unsigned                    root_prefix:1;
} njt_http_compile_complex_value_t;


typedef void (*njt_http_script_code_pt) (njt_http_script_engine_t *e);
typedef size_t (*njt_http_script_len_code_pt) (njt_http_script_engine_t *e);


typedef struct {
    njt_http_script_code_pt     code;
    uintptr_t                   len;
} njt_http_script_copy_code_t;


typedef struct {
    njt_http_script_code_pt     code;
    uintptr_t                   index;
} njt_http_script_var_code_t;


typedef struct {
    njt_http_script_code_pt     code;
    njt_http_set_variable_pt    handler;
    uintptr_t                   data;
} njt_http_script_var_handler_code_t;


typedef struct {
    njt_http_script_code_pt     code;
    uintptr_t                   n;
} njt_http_script_copy_capture_code_t;


#if (NJT_PCRE)

typedef struct {
    njt_http_script_code_pt     code;
    njt_http_regex_t           *regex;
    njt_array_t                *lengths;
    uintptr_t                   size;
    uintptr_t                   status;
    uintptr_t                   next;

    unsigned                    test:1;
    unsigned                    negative_test:1;
    unsigned                    uri:1;
    unsigned                    args:1;

    /* add the r->args to the new arguments */
    unsigned                    add_args:1;

    unsigned                    redirect:1;
    unsigned                    break_cycle:1;

    njt_str_t                   name;
} njt_http_script_regex_code_t;


typedef struct {
    njt_http_script_code_pt     code;

    unsigned                    uri:1;
    unsigned                    args:1;

    /* add the r->args to the new arguments */
    unsigned                    add_args:1;

    unsigned                    redirect:1;
} njt_http_script_regex_end_code_t;

#endif


typedef struct {
    njt_http_script_code_pt     code;
    uintptr_t                   conf_prefix;
} njt_http_script_full_name_code_t;


typedef struct {
    njt_http_script_code_pt     code;
    uintptr_t                   status;
    njt_http_complex_value_t    text;
} njt_http_script_return_code_t;


typedef enum {
    njt_http_script_file_plain = 0,
    njt_http_script_file_not_plain,
    njt_http_script_file_dir,
    njt_http_script_file_not_dir,
    njt_http_script_file_exists,
    njt_http_script_file_not_exists,
    njt_http_script_file_exec,
    njt_http_script_file_not_exec
} njt_http_script_file_op_e;


typedef struct {
    njt_http_script_code_pt     code;
    uintptr_t                   op;
} njt_http_script_file_code_t;


typedef struct {
    njt_http_script_code_pt     code;
    uintptr_t                   next;
    void                      **loc_conf;
} njt_http_script_if_code_t;


typedef struct {
    njt_http_script_code_pt     code;
    njt_array_t                *lengths;
} njt_http_script_complex_value_code_t;


typedef struct {
    njt_http_script_code_pt     code;
    uintptr_t                   value;
    uintptr_t                   text_len;
    uintptr_t                   text_data;
} njt_http_script_value_code_t;


void njt_http_script_flush_complex_value(njt_http_request_t *r,
    njt_http_complex_value_t *val);
njt_int_t njt_http_complex_value(njt_http_request_t *r,
    njt_http_complex_value_t *val, njt_str_t *value);
size_t njt_http_complex_value_size(njt_http_request_t *r,
    njt_http_complex_value_t *val, size_t default_value);
njt_int_t njt_http_compile_complex_value(njt_http_compile_complex_value_t *ccv);
char *njt_http_set_complex_value_slot(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_http_set_complex_value_zero_slot(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_http_set_complex_value_size_slot(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);


njt_int_t njt_http_test_predicates(njt_http_request_t *r,
    njt_array_t *predicates);
njt_int_t njt_http_test_required_predicates(njt_http_request_t *r,
    njt_array_t *predicates);
char *njt_http_set_predicate_slot(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);

njt_uint_t njt_http_script_variables_count(njt_str_t *value);
njt_int_t njt_http_script_compile(njt_http_script_compile_t *sc);
u_char *njt_http_script_run(njt_http_request_t *r, njt_str_t *value,
    void *code_lengths, size_t reserved, void *code_values);
void njt_http_script_flush_no_cacheable_variables(njt_http_request_t *r,
    njt_array_t *indices);

void *njt_http_script_start_code(njt_pool_t *pool, njt_array_t **codes,
    size_t size);
void *njt_http_script_add_code(njt_array_t *codes, size_t size, void *code);

size_t njt_http_script_copy_len_code(njt_http_script_engine_t *e);
void njt_http_script_copy_code(njt_http_script_engine_t *e);
size_t njt_http_script_copy_var_len_code(njt_http_script_engine_t *e);
void njt_http_script_copy_var_code(njt_http_script_engine_t *e);
size_t njt_http_script_copy_capture_len_code(njt_http_script_engine_t *e);
void njt_http_script_copy_capture_code(njt_http_script_engine_t *e);
size_t njt_http_script_mark_args_code(njt_http_script_engine_t *e);
void njt_http_script_start_args_code(njt_http_script_engine_t *e);
#if (NJT_PCRE)
void njt_http_script_regex_start_code(njt_http_script_engine_t *e);
void njt_http_script_regex_end_code(njt_http_script_engine_t *e);
#endif
void njt_http_script_return_code(njt_http_script_engine_t *e);
void njt_http_script_break_code(njt_http_script_engine_t *e);
void njt_http_script_if_code(njt_http_script_engine_t *e);
void njt_http_script_equal_code(njt_http_script_engine_t *e);
void njt_http_script_not_equal_code(njt_http_script_engine_t *e);
void njt_http_script_file_code(njt_http_script_engine_t *e);
void njt_http_script_complex_value_code(njt_http_script_engine_t *e);
void njt_http_script_value_code(njt_http_script_engine_t *e);
void njt_http_script_set_var_code(njt_http_script_engine_t *e);
void njt_http_script_var_set_handler_code(njt_http_script_engine_t *e);
void njt_http_script_var_code(njt_http_script_engine_t *e);
void njt_http_script_nop_code(njt_http_script_engine_t *e);


#endif /* _NJT_HTTP_SCRIPT_H_INCLUDED_ */
