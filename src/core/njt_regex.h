
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_REGEX_H_INCLUDED_
#define _NJT_REGEX_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


#if (NJT_PCRE2)

#define PCRE2_CODE_UNIT_WIDTH  8
#include <pcre2.h>

#define NJT_REGEX_NO_MATCHED   PCRE2_ERROR_NOMATCH   /* -1 */

typedef pcre2_code  njt_regex_t;

#else

#include <pcre.h>

#define NJT_REGEX_NO_MATCHED   PCRE_ERROR_NOMATCH    /* -1 */

typedef struct {
    pcre        *code;
    pcre_extra  *extra;
} njt_regex_t;

#endif


#define NJT_REGEX_CASELESS     0x00000001
#define NJT_REGEX_MULTILINE    0x00000002


typedef struct {
    njt_str_t     pattern;
    njt_pool_t   *pool;
    njt_uint_t    options;

    njt_regex_t  *regex;
    int           captures;
    int           named_captures;
    int           name_size;
    u_char       *names;
    njt_str_t     err;
} njt_regex_compile_t;


typedef struct {
    njt_regex_t  *regex;
    u_char       *name;
    njt_uint_t           dynamic; 
} njt_regex_elt_t;


void njt_regex_init(void);
njt_int_t njt_regex_compile(njt_regex_compile_t *rc);

njt_int_t njt_regex_exec(njt_regex_t *re, njt_str_t *s, int *captures,
    njt_uint_t size);

#if (NJT_PCRE2)
#define njt_regex_exec_n       "pcre2_match()"
#else
#define njt_regex_exec_n       "pcre_exec()"
#endif

njt_int_t njt_regex_exec_array(njt_array_t *a, njt_str_t *s, njt_log_t *log);


#endif /* _NJT_REGEX_H_INCLUDED_ */
