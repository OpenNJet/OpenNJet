
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
////by cheng xu
//#if (NJT_DEBUG)
//#define njt_free          njt_cx_free
//void njt_cx_free(void *p);
//void *njt_cx_malloc (size_t size);
//#define malloc           njt_cx_malloc
//#else
#define njt_free          free
//#endif
////end




/*
 * Linux has memalign() or posix_memalign()
 * Solaris has memalign()
 * FreeBSD 7.0 has posix_memalign(), besides, early version's malloc()
 * aligns allocations bigger than page size at the page boundary
 */

#if (NJT_HAVE_POSIX_MEMALIGN || NJT_HAVE_MEMALIGN)

void *njt_memalign(size_t alignment, size_t size, njt_log_t *log);

#else

#define njt_memalign(alignment, size, log)  njt_alloc(size, log)

#endif


extern njt_uint_t  njt_pagesize;
extern njt_uint_t  njt_pagesize_shift;
extern njt_uint_t  njt_cacheline_size;


#endif /* _NJT_ALLOC_H_INCLUDED_ */
