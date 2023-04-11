
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/ddebug.h.tt2
 */


/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _DDEBUG_H_INCLUDED_
#define _DDEBUG_H_INCLUDED_


#include <njt_config.h>
#include <njet.h>
#include <njt_core.h>


#if defined(DDEBUG) && (DDEBUG)

#   if (NJT_HAVE_VARIADIC_MACROS)

#       define dd(...) fprintf(stderr, "lua *** %s: ", __func__);            \
            fprintf(stderr, __VA_ARGS__);                                    \
            fprintf(stderr, " at %s line %d.\n", __FILE__, __LINE__)

#   else

#include <stdarg.h>
#include <stdio.h>

#include <stdarg.h>

static njt_inline void
dd(const char *fmt, ...) {
}

#    endif

#else

#   if (NJT_HAVE_VARIADIC_MACROS)

#       define dd(...)

#   else

#include <stdarg.h>

static njt_inline void
dd(const char *fmt, ...) {
}

#   endif

#endif

#if defined(DDEBUG) && (DDEBUG)

#define dd_check_read_event_handler(r)                                       \
    dd("r->read_event_handler = %s",                                         \
       r->read_event_handler == njt_http_block_reading ?                     \
       "njt_http_block_reading" :                                            \
       r->read_event_handler == njt_http_test_reading ?                      \
       "njt_http_test_reading" :                                             \
       r->read_event_handler == njt_http_request_empty_handler ?             \
       "njt_http_request_empty_handler" : "UNKNOWN")

#define dd_check_write_event_handler(r)                                      \
    dd("r->write_event_handler = %s",                                        \
       r->write_event_handler == njt_http_handler ?                          \
       "njt_http_handler" :                                                  \
       r->write_event_handler == njt_http_core_run_phases ?                  \
       "njt_http_core_run_phases" :                                          \
       r->write_event_handler == njt_http_request_empty_handler ?            \
       "njt_http_request_empty_handler" : "UNKNOWN")

#else

#define dd_check_read_event_handler(r)
#define dd_check_write_event_handler(r)

#endif


#endif /* _DDEBUG_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
