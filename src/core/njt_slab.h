
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_SLAB_H_INCLUDED_
#define _NJT_SLAB_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>

#define NJT_MIN_MAIN_SLAB_SIZE  (10 * 1024 * 1024)

#define NJT_DYN_SHM_CREATE_OR_OPEN  0x01
#define NJT_DYN_SHM_OPEN            0x02
#define NJT_DYN_SHM_NOREUSE         0x04

typedef struct njt_slab_page_s  njt_slab_page_t;
typedef struct njt_slab_pool_s  njt_slab_pool_t;

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


struct njt_slab_pool_s {
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

    njt_slab_pool_t  *next;
    njt_slab_pool_t  *first;
};


typedef struct njt_share_slab_pool_node_s {
    struct njt_share_slab_pool_node_s *next;
    void               *tag; // module
    njt_str_t           name;
    njt_slab_pool_t    *pool;
    njt_uint_t          size;
    njt_uint_t          delete;
    njt_uint_t          noreuse; // init on reload
} njt_share_slab_pool_node_t;

typedef struct {
    njt_shm_t          shm; // its addr will always point to the list tail
    njt_slab_pool_t   *header;
    ssize_t            total_size;
    size_t             count;
    njt_uint_t         array_size;
    njt_share_slab_pool_node_t  *sub_pool_header;
 } njt_main_slab_t;

// move from njt_cycle.h
typedef struct njt_shm_zone_s  njt_shm_zone_t;

typedef njt_int_t (*njt_shm_zone_init_pt) (njt_shm_zone_t *zone, void *data);
struct njt_shm_zone_s {
    void                     *data;
    njt_shm_t                 shm;
    njt_shm_zone_init_pt      init;
    njt_shm_zone_init_pt      merge;
    void                     *tag;
    void                     *sync;
    njt_uint_t                noreuse;  /* unsigned  noreuse:1; */
};
// move from njt_cycle.h end


void njt_slab_sizes_init(void);
void njt_slab_init(njt_slab_pool_t *pool);
void *njt_slab_alloc(njt_slab_pool_t *pool, size_t size);
void *njt_slab_alloc_locked(njt_slab_pool_t *pool, size_t size);
void *njt_slab_calloc(njt_slab_pool_t *pool, size_t size);
void *njt_slab_calloc_locked(njt_slab_pool_t *pool, size_t size);
void njt_slab_free(njt_slab_pool_t *pool, void *p);
void njt_slab_free_locked(njt_slab_pool_t *pool, void *p);
njt_int_t njt_slab_add_main_pool(njt_slab_pool_t *first_pool,
    njt_slab_pool_t *new_pool, size_t size, njt_log_t *log);
njt_int_t njt_slab_add_new_pool(njt_slab_pool_t *first_pool,
    njt_slab_pool_t *new_pool, size_t size, njt_log_t *log);
void njt_shm_free_chain(njt_shm_t *shm, njt_slab_pool_t *shared_pool);
void njt_main_slab_init(njt_main_slab_t *slab, size_t size, njt_log_t *log);
void njt_share_slab_set_header(njt_slab_pool_t *header);
njt_int_t  njt_share_slab_get_pool(njt_cycle_t  *cycle, njt_shm_zone_t *zone, njt_uint_t flags, njt_slab_pool_t **shpool);
void njt_share_slab_init_pool_list(njt_cycle_t *cycle);
njt_int_t njt_share_slab_free_pool(njt_cycle_t *cycle, njt_slab_pool_t *pool);
void njt_share_slab_mark_pool_delete(njt_cycle_t *cycle, njt_slab_pool_t *pool);

#endif /* _NJT_SLAB_H_INCLUDED_ */
