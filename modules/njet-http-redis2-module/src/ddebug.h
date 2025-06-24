#ifndef DDEBUG_H
#define DDEBUG_H

#include <njt_config.h>
#include <njt_core.h>

#if defined(DDEBUG) && (DDEBUG)

#   if (NJT_HAVE_VARIADIC_MACROS)

#       define dd(...) fprintf(stderr, "redis2 *** "); \
            fprintf(stderr, __VA_ARGS__); \
            fprintf(stderr, " at %s line %d.\n", __FILE__, __LINE__)

#   else

#include <stdarg.h>
#include <stdio.h>

#include <stdarg.h>

static njt_inline void
dd(const char* fmt, ...) {
}

#    endif

#else

#   if (NJT_HAVE_VARIADIC_MACROS)

#       define dd(...)

#   else

#include <stdarg.h>

static njt_inline void
dd(const char* fmt, ...) {
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

