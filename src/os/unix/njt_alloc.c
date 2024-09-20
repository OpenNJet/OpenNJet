
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>

njt_uint_t  njt_pagesize;
njt_uint_t  njt_pagesize_shift;
njt_uint_t  njt_cacheline_size;

////by cheng xu
//#if (NJT_DEBUG)
//#include <execinfo.h>
//
//typedef struct {
//    njt_log_t              *log;
//    njt_int_t               max_stack_size;
//} njt_backtrace_conf_t;
//static void
//ngx_error_signal_handler()
//{
//    void                 *buffer;
//    size_t                size;
//    njt_backtrace_conf_t bcf;
//
//    bcf.max_stack_size = 30;
//
//
//
//    buffer = calloc(1,sizeof(void *) * bcf.max_stack_size);
//    if (buffer == NULL) {
//        goto invalid;
//    }
//
//    size = backtrace(buffer, bcf.max_stack_size);
//    backtrace_symbols_fd(buffer, size, 2);
//    njt_free(buffer);
//
//    return;
//
//    invalid:
//
//    exit(1);
//}
//
//
//void njt_cx_free(void *p){
//    fprintf(stderr,"free: %016x cx_free\r\n",(unsigned int)(uintptr_t)p);
//    free(p);
//}
//void *njt_cx_malloc (size_t size){
//    void  *p;
//    p = calloc(1,size);
//    fprintf(stderr,"malloc：%016x:%u cx_malloc \r\n",(unsigned int)(uintptr_t)p,(unsigned int)size);
//    ngx_error_signal_handler();
//    return p;
//}
//#endif
////end

void *
njt_alloc(size_t size, njt_log_t *log)
{
    void  *p;

    p = malloc(size);
    if (p == NULL) {
        njt_log_error(NJT_LOG_EMERG, log, njt_errno,
                      "malloc(%uz) failed", size);
    }

    // njt_log_debug2(NJT_LOG_DEBUG_ALLOC, log, 0, "malloc: %p:%uz", p, size);

    return p;
}


void *
njt_calloc(size_t size, njt_log_t *log)
{
    void  *p;

    p = njt_alloc(size, log);

    if (p) {
        njt_memzero(p, size);
    }

    return p;
}


#if (NJT_HAVE_POSIX_MEMALIGN)

void *
njt_memalign(size_t alignment, size_t size, njt_log_t *log)
{
    void  *p;
    int    err;

    err = posix_memalign(&p, alignment, size);

    if (err) {
        njt_log_error(NJT_LOG_EMERG, log, err,
                      "posix_memalign(%uz, %uz) failed", alignment, size);
        p = NULL;
    }

    njt_log_debug3(NJT_LOG_DEBUG_ALLOC, log, 0,
                   "posix_memalign: %p:%uz @%uz", p, size, alignment);

    return p;
}

#elif (NJT_HAVE_MEMALIGN)

void *
njt_memalign(size_t alignment, size_t size, njt_log_t *log)
{
    void  *p;

    p = memalign(alignment, size);
    if (p == NULL) {
        njt_log_error(NJT_LOG_EMERG, log, njt_errno,
                      "memalign(%uz, %uz) failed", alignment, size);
    }

    njt_log_debug3(NJT_LOG_DEBUG_ALLOC, log, 0,
                   "memalign: %p:%uz @%uz", p, size, alignment);

    return p;
}

#endif
