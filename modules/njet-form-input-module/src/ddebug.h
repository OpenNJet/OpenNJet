#ifndef DDEBUG_H
#define DDEBUG_H

#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njet.h>

#if defined(DDEBUG) && (DDEBUG)

#   if (NJT_HAVE_VARIADIC_MACROS)

#       define dd(...) fprintf(stderr, "form-input *** %s: ", __func__); \
            fprintf(stderr, __VA_ARGS__); \
            fprintf(stderr, " at %s line %d.\n", __FILE__, __LINE__)

#   else

#include <stdarg.h>
#include <stdio.h>

#include <stdarg.h>

static void dd(const char * fmt, ...) {
}

#    endif

#   if DDEBUG > 1

#       define dd_enter() dd_enter_helper(r, __func__)


#       if defined(nginx_version) && nginx_version >= 8011
#           define dd_main_req_count r->main->count
#       else
#           define dd_main_req_count 0
#       endif

static void dd_enter_helper(njt_http_request_t *r, const char *func) {
    njt_http_posted_request_t       *pr;

    fprintf(stderr, ">enter %s %.*s %.*s?%.*s c:%d m:%p r:%p ar:%p pr:%p",
            func,
            (int) r->method_name.len, r->method_name.data,
            (int) r->uri.len, r->uri.data,
            (int) r->args.len, r->args.data,
            (int) dd_main_req_count, r->main,
            r, r->connection->data, r->parent);

    if (r->posted_requests) {
        fprintf(stderr, " posted:");

        for (pr = r->posted_requests; pr; pr = pr->next) {
            fprintf(stderr, "%p,", pr);
        }
    }

    fprintf(stderr, "\n");
}

#   else

#       define dd_enter()

#   endif

#else

#   if (NJT_HAVE_VARIADIC_MACROS)

#       define dd(...)

#       define dd_enter()

#   else

#include <stdarg.h>

static void dd(const char * fmt, ...) {
}

static void dd_enter() {
}

#   endif

#endif

#if defined(DDEBUG) && (DDEBUG)

#define dd_check_read_event_handler(r)   \
    dd("r->read_event_handler = %s", \
        r->read_event_handler == njt_http_block_reading ? \
            "njt_http_block_reading" : \
        r->read_event_handler == njt_http_test_reading ? \
            "njt_http_test_reading" : \
        r->read_event_handler == njt_http_request_empty_handler ? \
            "njt_http_request_empty_handler" : "UNKNOWN")

#define dd_check_write_event_handler(r)   \
    dd("r->write_event_handler = %s", \
        r->write_event_handler == njt_http_handler ? \
            "njt_http_handler" : \
        r->write_event_handler == njt_http_core_run_phases ? \
            "njt_http_core_run_phases" : \
        r->write_event_handler == njt_http_request_empty_handler ? \
            "njt_http_request_empty_handler" : "UNKNOWN")

#else

#define dd_check_read_event_handler(r)
#define dd_check_write_event_handler(r)

#endif

#endif /* DDEBUG_H */

