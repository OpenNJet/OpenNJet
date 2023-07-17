
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_SLAB_H_INCLUDED_
#define _NJT_SLAB_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


typedef struct njt_slab_page_s  njt_slab_page_t;

struct njt_slab_page_s {
    uintptr_t         slab;
    njt_slab_page_t  *next;
    uintptr_t         prev;
};


typedef struct {
    njt_uint_t        total;
    njt_uint_t        used;

    njt_uint_t        reqs;
    njt_uint_t        fails;
} njt_slab_stat_t;


typedef struct {
    njt_shmtx_sh_t    lock;

    size_t            min_size;
    size_t            min_shift;

    njt_slab_page_t  *pages;
    njt_slab_page_t  *last;
    njt_slab_page_t   free;

    njt_slab_stat_t  *stats;
    njt_uint_t        pfree;

    u_char           *start;
    u_char           *end;

    union {
        njt_shmtx_t       mutex;
        njt_shrwlock_t    rwlock;
    };

    u_char           *log_ctx;
    u_char            zero;

    unsigned          log_nomem:1;

    void             *data;
    void             *addr;
} njt_slab_pool_t;


void njt_slab_sizes_init(void);
void njt_slab_init(njt_slab_pool_t *pool);
void *njt_slab_alloc(njt_slab_pool_t *pool, size_t size);
void *njt_slab_alloc_locked(njt_slab_pool_t *pool, size_t size);
void *njt_slab_calloc(njt_slab_pool_t *pool, size_t size);
void *njt_slab_calloc_locked(njt_slab_pool_t *pool, size_t size);
void njt_slab_free(njt_slab_pool_t *pool, void *p);
void njt_slab_free_locked(njt_slab_pool_t *pool, void *p);


#endif /* _NJT_SLAB_H_INCLUDED_ */
