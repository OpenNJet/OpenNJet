
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_ALLOC_H_INCLUDED_
#define _NJT_ALLOC_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


void *njt_alloc(size_t size, njt_log_t *log);
void *njt_calloc(size_t size, njt_log_t *log);

#define njt_free          free
#define njt_memalign(alignment, size, log)  njt_alloc(size, log)

extern njt_uint_t  njt_pagesize;
extern njt_uint_t  njt_pagesize_shift;
extern njt_uint_t  njt_cacheline_size;


#endif /* _NJT_ALLOC_H_INCLUDED_ */
