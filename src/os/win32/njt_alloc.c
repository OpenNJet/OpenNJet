
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


void *njt_alloc(size_t size, njt_log_t *log)
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


void *njt_calloc(size_t size, njt_log_t *log)
{
    void  *p;

    p = njt_alloc(size, log);

    if (p) {
        njt_memzero(p, size);
    }

    return p;
}
