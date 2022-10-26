
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) TMLake, Inc.
 */


#include <njt_config.h>
#include <njt_core.h>


njt_uint_t  njt_pagesize;
njt_uint_t  njt_pagesize_shift;
njt_uint_t  njt_cacheline_size;


void *
njt_alloc(size_t size, njt_log_t *log)
{
    void  *p;

    p = malloc(size);
    if (p == NULL) {
        njt_log_error(NJT_LOG_EMERG, log, njt_errno,
                      "malloc(%uz) failed", size);
    }

    njt_log_debug2(NJT_LOG_DEBUG_ALLOC, log, 0, "malloc: %p:%uz", p, size);

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
