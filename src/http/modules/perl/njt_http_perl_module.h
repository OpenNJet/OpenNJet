
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_PERL_MODULE_H_INCLUDED_
#define _NJT_HTTP_PERL_MODULE_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njet.h>

#include <EXTERN.h>
#include <perl.h>


typedef njt_http_request_t   *njet;

typedef struct {
    njt_http_request_t       *request;

    njt_str_t                 filename;
    njt_str_t                 redirect_uri;

    SV                       *next;

    njt_int_t                 status;

    unsigned                  done:1;
    unsigned                  error:1;
    unsigned                  variable:1;
    unsigned                  header_sent:1;

    njt_array_t              *variables;  /* array of njt_http_perl_var_t */

#if (NJT_HTTP_SSI)
    njt_http_ssi_ctx_t       *ssi;
#endif
} njt_http_perl_ctx_t;


typedef struct {
    njt_uint_t    hash;
    njt_str_t     name;
    njt_str_t     value;
} njt_http_perl_var_t;


extern njt_module_t  njt_http_perl_module;


/*
 * workaround for "unused variable `Perl___notused'" warning
 * when building with perl 5.6.1
 */
#ifndef PERL_IMPLICIT_CONTEXT
#undef  dTHXa
#define dTHXa(a)
#endif


extern void boot_DynaLoader(pTHX_ CV* cv);


void njt_http_perl_handle_request(njt_http_request_t *r);
void njt_http_perl_sleep_handler(njt_http_request_t *r);


#endif /* _NJT_HTTP_PERL_MODULE_H_INCLUDED_ */
