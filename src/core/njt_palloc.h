
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_PALLOC_H_INCLUDED_
#define _NJT_PALLOC_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include "njt_queue.h"


/*
 * NJT_MAX_ALLOC_FROM_POOL should be (njt_pagesize - 1), i.e. 4095 on x86.
 * On Windows NT it decreases a number of locked pages in a kernel.
 */
#define NJT_MAX_ALLOC_FROM_POOL  (njt_pagesize - 1)

#define NJT_DEFAULT_POOL_SIZE    (16 * 1024)

#define NJT_POOL_ALIGNMENT       16
#define NJT_MIN_POOL_SIZE                                                     \
    njt_align((sizeof(njt_pool_t) + 2 * sizeof(njt_pool_large_t)),            \
              NJT_POOL_ALIGNMENT)


typedef void (*njt_pool_cleanup_pt)(void *data);

typedef struct njt_pool_cleanup_s  njt_pool_cleanup_t;

struct njt_pool_cleanup_s {
    njt_pool_cleanup_pt   handler;
    void                 *data;
    njt_pool_cleanup_t   *next;
};


typedef struct njt_pool_large_s  njt_pool_large_t;

struct njt_pool_large_s {
    njt_pool_large_t     *next;
    void                 *alloc;
};


typedef struct {
    u_char               *last;
    u_char               *end;
    njt_pool_t           *next;
    njt_uint_t            failed;
} njt_pool_data_t;

struct njt_pool_s {
    njt_pool_data_t       d;
    size_t                max;
    njt_pool_t           *current;
    njt_chain_t          *chain;
    njt_pool_large_t     *large;
    njt_pool_cleanup_t   *cleanup;
    njt_log_t            *log;
    // by ChengXu
#if (NJT_DYNAMIC_POOL)
//    njt_pool_link_t      *sub_pools;
//    njt_pool_t           *parent_pool;
    njt_queue_t          sub_pools;
    njt_queue_t          parent_pool;
    unsigned             dynamic:1;
#endif
    // end
};


typedef struct {
    njt_fd_t              fd;
    u_char               *name;
    njt_log_t            *log;
} njt_pool_cleanup_file_t;


njt_pool_t *njt_create_pool(size_t size, njt_log_t *log);
void njt_destroy_pool(njt_pool_t *pool);
void njt_reset_pool(njt_pool_t *pool);
// by ChengXu
#if (NJT_DYNAMIC_POOL)
njt_pool_t *njt_create_dynamic_pool(size_t size, njt_log_t *log);
njt_int_t njt_sub_pool(njt_pool_t *pool,njt_pool_t *sub);
#endif
// end

void *njt_palloc(njt_pool_t *pool, size_t size);
void *njt_pnalloc(njt_pool_t *pool, size_t size);
void *njt_pcalloc(njt_pool_t *pool, size_t size);
void *njt_pmemalign(njt_pool_t *pool, size_t size, size_t alignment);
njt_int_t njt_pfree(njt_pool_t *pool, void *p);


njt_pool_cleanup_t *njt_pool_cleanup_add(njt_pool_t *p, size_t size);
njt_pool_cleanup_t *
njt_pool_cleanup_add_tail(njt_pool_t *p, size_t size);
void njt_pool_run_cleanup_file(njt_pool_t *p, njt_fd_t fd);
void njt_pool_cleanup_file(void *data);
void njt_pool_delete_file(void *data);


#endif /* _NJT_PALLOC_H_INCLUDED_ */
