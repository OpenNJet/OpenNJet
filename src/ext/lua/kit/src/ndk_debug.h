#ifndef NDK_DEBUG_H
#define NDK_DEBUG_H


/* TODO : use the NJet printf function */


#include <njt_core.h>
#include <njt_http.h>

/* TODO
- andk_debug variety of debugging formats
- global include file for all debugging - can pass declaration to cflags for the option
*/


#if (NDK_DEBUG)

    #if (NJT_HAVE_VARIADIC_MACROS)

        #define ndk_debug(...)  ndk_debug_helper (__func__,__VA_ARGS__)

        #define ndk_debug_helper(func,...) \
            fprintf(stderr, "%-60s", func); \
            fprintf(stderr, (const char *)__VA_ARGS__); \
            fprintf(stderr,"\n");
            /*fprintf(stderr, " at %s line %d.\n", __FILE__, __LINE__)*/

    #else

        /* NOTE : these includes might not be necessary since they're probably included with the core */

        #include <stdarg.h>
        #include <stdio.h>
        #include <stdarg.h>

        static void ndk_debug (const char * fmt, ...) {
        }

    #endif

    #if NDK_DEBUG > 1

        #define ndk_debug_request()  ndk_debug_request_helper(r, __func__)

        static njt_inline void
        ndk_debug_request_helper (njt_http_request_t *r, const char *func)
        {
            njt_http_posted_request_t       *pr;

            /* TODO : improve the format */

            fprintf (stderr, "%s %.*s %.*s?%.*s c:%d m:%p r:%p ar:%p pr:%p",
                    func,
                    (int) r->method_name.len, r->method_name.data,
                    (int) r->uri.len, r->uri.data,
                    (int) r->args.len, r->args.data,
                    0/*(int) r->main->count*/, r->main,
                    r, r->connection->data, r->parent);

            if (r->posted_requests) {
                fprintf(stderr, " posted:");

                for (pr = r->posted_requests; pr; pr = pr->next) {
                    fprintf (stderr, "%p,", pr);
                }
            }

            fprintf (stderr, "\n");
        }


    #else

        #define ndk_debug_request()

    #endif


    static njt_inline void
    ndk_debug_print_posted_requests (njt_http_request_t *r)
    {
        njt_http_posted_request_t   *pr;

        ndk_request_log_debug_http (r, "ndk debug - http posted requests");

        for (pr = r->main->posted_requests; pr; pr = pr->next) {

            if (!pr->request)
                continue;

            ndk_request_log_debug_http (r, "ndk debug - http posted request:%V", &pr->request->uri);
        }
    }


    #define ndk_debug_http_conf_location(cf)    ndk_debug_http_conf_location_helper (cf, __func__)

    static njt_inline void
    ndk_debug_http_conf_location_helper (njt_conf_t *cf, const char *func)
    {
        njt_http_core_loc_conf_t        *lcf;

        lcf = njt_http_conf_get_module_loc_conf (cf, njt_http_core_module);

        ndk_debug_helper (func, "[%s]", lcf->name.data);
    }

    /*
    static void
    ndk_debug_log_chain (njt_log_t *log, njt_chain_t *cl)
    {


    }
    */

#else

    #if (NJT_HAVE_VARIADIC_MACROS)

        #define     ndk_debug(...)
        #define     ndk_debug_request()

    #else

        #include <stdarg.h>

        static void ndk_debug (const char * fmt, ...) {
        }

        static void ndk_debug_request() {
        }

    #endif

    #define     ndk_debug_http_conf_location(cf)

#endif

#if (NDK_DEBUG)

    #define     ndk_debug_check_read_event_handler(r)                               \
                                                                                    \
                    ndk_debug("r->read_event_handler = %s",                         \
                        r->read_event_handler == njt_http_block_reading ?           \
                            "njt_http_block_reading" :                              \
                        r->read_event_handler == njt_http_test_reading ?            \
                            "njt_http_test_reading" :                               \
                        r->read_event_handler == njt_http_request_empty_handler ?   \
                            "njt_http_request_empty_handler" : "UNKNOWN")

    #define     ndk_debug_check_write_event_handler(r)                              \
                                                                                    \
                    ndk_debug ("r->write_event_handler = %s",                       \
                        r->write_event_handler == njt_http_handler ?                \
                            "njt_http_handler" :                                    \
                        r->write_event_handler == njt_http_core_run_phases ?        \
                            "njt_http_core_run_phases" :                            \
                        r->write_event_handler == njt_http_request_empty_handler ?  \
                            "njt_http_request_empty_handler" : "UNKNOWN")

#else

    #define     ndk_debug_check_read_event_handler(r)
    #define     ndk_debug_check_write_event_handler(r)

#endif

#endif /* NDK_DEBUG_H */

