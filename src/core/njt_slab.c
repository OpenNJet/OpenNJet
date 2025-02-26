
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2025  TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_config.h>
#include <njt_core.h>
#include <ftw.h>

#if (NJT_SHM_STATUS)
#include <njt_shm_status_module.h>
#endif


#define NJT_SLAB_PAGE_MASK   3
#define NJT_SLAB_PAGE        0
#define NJT_SLAB_BIG         1
#define NJT_SLAB_EXACT       2
#define NJT_SLAB_SMALL       3

#if (NJT_PTR_SIZE == 4)

#define NJT_SLAB_PAGE_FREE   0
#define NJT_SLAB_PAGE_BUSY   0xffffffff
#define NJT_SLAB_PAGE_START  0x80000000

#define NJT_SLAB_SHIFT_MASK  0x0000000f
#define NJT_SLAB_MAP_MASK    0xffff0000
#define NJT_SLAB_MAP_SHIFT   16

#define NJT_SLAB_BUSY        0xffffffff

#else /* (NJT_PTR_SIZE == 8) */

#define NJT_SLAB_PAGE_FREE   0
#define NJT_SLAB_PAGE_BUSY   0xffffffffffffffff
#define NJT_SLAB_PAGE_START  0x8000000000000000

#define NJT_SLAB_SHIFT_MASK  0x000000000000000f
#define NJT_SLAB_MAP_MASK    0xffffffff00000000
#define NJT_SLAB_MAP_SHIFT   32

#define NJT_SLAB_BUSY        0xffffffffffffffff

#endif


#define njt_slab_slots(pool)                                                  \
    (njt_slab_page_t *) ((u_char *) (pool) + sizeof(njt_slab_pool_t))

#define njt_slab_page_type(page)   ((page)->prev & NJT_SLAB_PAGE_MASK)

#define njt_slab_page_prev(page)                                              \
    (njt_slab_page_t *) ((page)->prev & ~NJT_SLAB_PAGE_MASK)

#define njt_slab_page_addr(pool, page)                                        \
    ((((page) - (pool)->pages) << njt_pagesize_shift)                         \
     + (uintptr_t) (pool)->start)


#if (NJT_DEBUG_MALLOC)

#define njt_slab_junk(p, size)     njt_memset(p, 0xA5, size)

#elif (NJT_HAVE_DEBUG_MALLOC)

#define njt_slab_junk(p, size)                                                \
    if (njt_debug_malloc)          njt_memset(p, 0xA5, size)

#else

#define njt_slab_junk(p, size)

#endif

static njt_slab_page_t *njt_slab_alloc_pages(njt_slab_pool_t *pool,
    njt_uint_t pages);
static void njt_slab_free_pages(njt_slab_pool_t *pool, njt_slab_page_t *page,
    njt_uint_t pages);
static void njt_slab_error(njt_slab_pool_t *pool, njt_uint_t level,
    char *text);
static void* njt_slab_try_alloc(njt_slab_pool_t *pool, size_t size);
static njt_uint_t njt_share_slab_is_hidden_file_opened_locked(njt_cycle_t *cycle,
     njt_share_slab_pool_node_t *node); 
njt_int_t njt_share_slab_free_pool_locked(njt_cycle_t *cycle, njt_slab_pool_t *pool);
njt_int_t njt_share_slab_is_dyn_admin(njt_str_t *zone_name);
njt_share_slab_pool_node_t* njt_share_slab_get_old_node_locked(njt_cycle_t *cycle, njt_shm_zone_t *shm_zone, njt_slab_pool_t *pool);
njt_share_slab_pool_node_t* njt_share_slab_get_node_locked(njt_cycle_t *cycle, njt_shm_zone_t *shm_zone, njt_slab_pool_t *pool);

static njt_uint_t  njt_slab_max_size;
static njt_uint_t  njt_slab_exact_size;
static njt_uint_t  njt_slab_exact_shift;
njt_slab_pool_t *njt_shared_slab_header;
static njt_slab_pool_t *njt_shared_admin_slab_header;
njt_share_slab_queues_t *njt_shared_slab_queue_header;

#if (NJT_SHM_STATUS)
extern njt_shm_status_summary_t *njt_shm_status_summary;
static njt_shm_status_slab_update_item_t njt_slab_update_item;
njt_shm_status_slab_update_item_t *slab_update_item = &njt_slab_update_item;
#endif


void njt_share_slab_set_header(njt_slab_pool_t *header) {
    njt_shared_slab_header = header;
}

njt_int_t
njt_slab_add_new_pool(njt_slab_pool_t *first_pool,
    njt_slab_pool_t *new_pool, size_t size, njt_log_t *log)
{
    njt_slab_pool_t *pool;

    for(pool = first_pool; pool->next != NULL; pool = pool->next) {/**/}

    new_pool->end = (u_char *) new_pool + size;
    new_pool->min_shift = pool->min_shift;
    new_pool->addr = new_pool;
    new_pool->next = NULL;
    new_pool->first = first_pool;
    //将新slab_pool 挂到上一个slab_pool上
    pool->next = new_pool;

    // initialize new pool and mutex (mayble unuseable)
    if (njt_shmtx_create(&new_pool->mutex, &new_pool->lock, NULL) != NJT_OK) {
        return NJT_ERROR;
    }

    njt_log_error(NJT_LOG_NOTICE, log, 0,
            "dyn_slab add new slab pool: %p, size %d", (void *) new_pool, size);
    njt_slab_init(new_pool);

#if (NJT_SHM_STATUS)
    if (njt_shm_status_summary && new_pool->first->status_rec) {
        njt_shm_status_add_pool_record(new_pool->first->status_rec, size, NJT_SHM_STATUS_DYNAMIC, &new_pool->status_rec);
    }
#endif

    return NJT_OK;
}

njt_int_t njt_slab_add_main_pool(njt_slab_pool_t *first_pool, njt_slab_pool_t *new_pool, size_t size, njt_log_t *log) {
    njt_slab_pool_t *pool;

    for(pool = first_pool; pool->next != NULL; pool = pool->next) {/**/}

    pool->next = new_pool;
    new_pool->first = first_pool;

#if (NJT_SHM_STATUS)
    if (njt_shm_status_summary) {
        njt_shm_status_add_main_pool(new_pool);
    }
#endif

    return NJT_OK;
}


njt_int_t
njt_slab_rm_main_pool(njt_slab_pool_t *first_pool,
    njt_slab_pool_t *new_pool, size_t size, njt_log_t *log)
{
    njt_slab_pool_t *pool;

    for(pool = first_pool; pool->next != new_pool; pool = pool->next) {/**/}

    pool->next = NULL;

#if (NJT_SHM_STATUS)
    if (njt_shm_status_summary) {
        njt_shm_status_rm_main_pool(new_pool);
    }
#endif

    return NJT_OK;
}


void
njt_main_slab_init(njt_main_slab_t *slab, size_t size, njt_log_t *log)
{
    njt_str_set(&slab->shm.name, "njt_main_slab");
    slab->shm.size = size;
    slab->total_size = size;
    slab->count = 1;
    slab->shm.log = log;
}


void
njt_slab_sizes_init(void)
{
    njt_uint_t  n;

    njt_slab_max_size = njt_pagesize / 2;
    njt_slab_exact_size = njt_pagesize / (8 * sizeof(uintptr_t));
    for (n = njt_slab_exact_size; n >>= 1; njt_slab_exact_shift++) {
        /* void */
    }
}


void
njt_slab_init_chain(njt_slab_pool_t *pool){
    njt_slab_pool_t  *cur, *next;

    cur = pool;
    while (cur) {
        next = cur->next;
        njt_slab_init(cur);
        cur = next;
    }
}


njt_int_t
njt_slab_can_alloc(njt_slab_pool_t *pool, size_t new_size) {
    size_t            size;
    njt_uint_t        n, pages, new_pages;

    size = pool->end - (u_char *) njt_slab_slots(pool);
    n = njt_pagesize_shift - pool->min_shift;
    size -= n * (sizeof(njt_slab_page_t) + sizeof(njt_slab_stat_t));

    pages = (njt_uint_t) (size / (njt_pagesize + sizeof(njt_slab_page_t)));
    new_pages = (new_size >> njt_pagesize_shift) + ((new_size % njt_pagesize) ? 1 : 0); 

    return new_pages > pages ? NJT_ERROR : NJT_OK;
}


void
njt_slab_init(njt_slab_pool_t *pool)
{
    u_char           *p;
    size_t            size;
    njt_int_t         m;
    njt_uint_t        i, n, pages;
    njt_slab_page_t  *slots, *page;

    pool->min_size = (size_t) 1 << pool->min_shift;

    slots = njt_slab_slots(pool);

    p = (u_char *) slots;
    size = pool->end - p;

    njt_slab_junk(p, size);

    n = njt_pagesize_shift - pool->min_shift;

    for (i = 0; i < n; i++) {
        /* only "next" is used in list head */
        slots[i].slab = 0;
        slots[i].next = &slots[i];
        slots[i].prev = 0;
    }

    p += n * sizeof(njt_slab_page_t);

    pool->stats = (njt_slab_stat_t *) p;
    njt_memzero(pool->stats, n * sizeof(njt_slab_stat_t));

    p += n * sizeof(njt_slab_stat_t);

    size -= n * (sizeof(njt_slab_page_t) + sizeof(njt_slab_stat_t));

    pages = (njt_uint_t) (size / (njt_pagesize + sizeof(njt_slab_page_t)));

    pool->pages = (njt_slab_page_t *) p;
    njt_memzero(pool->pages, pages * sizeof(njt_slab_page_t));

    page = pool->pages;

    /* only "next" is used in list head */
    pool->free.slab = 0;
    pool->free.next = page;
    pool->free.prev = 0;

    page->slab = pages;
    page->next = &pool->free;
    page->prev = (uintptr_t) &pool->free;

    pool->start = njt_align_ptr(p + pages * sizeof(njt_slab_page_t),
                                njt_pagesize);

    m = pages - (pool->end - pool->start) / njt_pagesize;
    if (m > 0) {
        pages -= m;
        page->slab = pages;
    }

    pool->last = pool->pages + pages;
    pool->pfree = pages;

    pool->log_nomem = 1;
    pool->log_ctx = &pool->zero;
    pool->zero = '\0';

#if (NJT_SHM_STATUS)
    pool->status_rec = NULL;
#endif
}


void *
njt_slab_alloc(njt_slab_pool_t *pool, size_t size)
{
    void  *p;

    njt_cycle->log->action = "dyn slob";
    njt_shmtx_lock(&pool->mutex);

    p = njt_slab_alloc_locked(pool, size);

    njt_shmtx_unlock(&pool->mutex);

    return p;
}


void *
njt_slab_alloc_locked(njt_slab_pool_t *pool, size_t size)
{
    size_t            s;
    uintptr_t         p, m, mask, *bitmap;
    njt_uint_t        i, n, slot, shift, map;
    njt_slab_page_t  *page, *prev, *slots;
    njt_slab_pool_t  *new_pool;

#if (NJT_SHM_STATUS)
    slab_update_item->rec = pool->status_rec;
    slab_update_item->alloc = 1;
    slab_update_item->pages = 0;
    slab_update_item->slot  = 0;
    slab_update_item->failed = 0;
#endif

    if (size > njt_slab_max_size) {

        njt_log_debug1(NJT_LOG_DEBUG_ALLOC, njt_cycle->log, 0,
                       "slab alloc: %uz", size);

        page = njt_slab_alloc_pages(pool, (size >> njt_pagesize_shift)
                                          + ((size % njt_pagesize) ? 1 : 0));
        if (page) {
            p = njt_slab_page_addr(pool, page);

        } else {
            p = 0;
        }

        goto done;
    }

    if (size > pool->min_size) {
        shift = 1;
        for (s = size - 1; s >>= 1; shift++) { /* void */ }
        slot = shift - pool->min_shift;

    } else {
        shift = pool->min_shift;
        slot = 0;
    }

    pool->stats[slot].reqs++;

    njt_log_debug2(NJT_LOG_DEBUG_ALLOC, njt_cycle->log, 0,
                   "slab alloc: %uz slot: %ui", size, slot);

    slots = njt_slab_slots(pool);
    page = slots[slot].next;

#if (NJT_SHM_STATUS)
    slab_update_item->slot = shift;
#endif 

    if (page->next != page) {

        if (shift < njt_slab_exact_shift) {

            bitmap = (uintptr_t *) njt_slab_page_addr(pool, page);

            map = (njt_pagesize >> shift) / (8 * sizeof(uintptr_t));

            for (n = 0; n < map; n++) {

                if (bitmap[n] != NJT_SLAB_BUSY) {

                    for (m = 1, i = 0; m; m <<= 1, i++) {
                        if (bitmap[n] & m) {
                            continue;
                        }

                        bitmap[n] |= m;

                        i = (n * 8 * sizeof(uintptr_t) + i) << shift;

                        p = (uintptr_t) bitmap + i;

                        pool->stats[slot].used++;

                        if (bitmap[n] == NJT_SLAB_BUSY) {
                            for (n = n + 1; n < map; n++) {
                                if (bitmap[n] != NJT_SLAB_BUSY) {
                                    goto done;
                                }
                            }

                            prev = njt_slab_page_prev(page);
                            prev->next = page->next;
                            page->next->prev = page->prev;

                            page->next = NULL;
                            page->prev = NJT_SLAB_SMALL;
                        }

                        goto done;
                    }
                }
            }

        } else if (shift == njt_slab_exact_shift) {

            for (m = 1, i = 0; m; m <<= 1, i++) {
                if (page->slab & m) {
                    continue;
                }

                page->slab |= m;

                if (page->slab == NJT_SLAB_BUSY) {
                    prev = njt_slab_page_prev(page);
                    prev->next = page->next;
                    page->next->prev = page->prev;

                    page->next = NULL;
                    page->prev = NJT_SLAB_EXACT;
                }

                p = njt_slab_page_addr(pool, page) + (i << shift);

                pool->stats[slot].used++;

                goto done;
            }

        } else { /* shift > njt_slab_exact_shift */

            mask = ((uintptr_t) 1 << (njt_pagesize >> shift)) - 1;
            mask <<= NJT_SLAB_MAP_SHIFT;

            for (m = (uintptr_t) 1 << NJT_SLAB_MAP_SHIFT, i = 0;
                 m & mask;
                 m <<= 1, i++)
            {
                if (page->slab & m) {
                    continue;
                }

                page->slab |= m;

                if ((page->slab & NJT_SLAB_MAP_MASK) == mask) {
                    prev = njt_slab_page_prev(page);
                    prev->next = page->next;
                    page->next->prev = page->prev;

                    page->next = NULL;
                    page->prev = NJT_SLAB_BIG;
                }

                p = njt_slab_page_addr(pool, page) + (i << shift);

                pool->stats[slot].used++;

                goto done;
            }
        }

        njt_slab_error(pool, NJT_LOG_ALERT, "njt_slab_alloc(): page is busy");
        njt_debug_point();
    }

    page = njt_slab_alloc_pages(pool, 1);

    if (page) {
        if (shift < njt_slab_exact_shift) {
            bitmap = (uintptr_t *) njt_slab_page_addr(pool, page);

            n = (njt_pagesize >> shift) / ((1 << shift) * 8);

            if (n == 0) {
                n = 1;
            }

            /* "n" elements for bitmap, plus one requested */

            for (i = 0; i < (n + 1) / (8 * sizeof(uintptr_t)); i++) {
                bitmap[i] = NJT_SLAB_BUSY;
            }

            m = ((uintptr_t) 1 << ((n + 1) % (8 * sizeof(uintptr_t)))) - 1;
            bitmap[i] = m;

            map = (njt_pagesize >> shift) / (8 * sizeof(uintptr_t));

            for (i = i + 1; i < map; i++) {
                bitmap[i] = 0;
            }

            page->slab = shift;
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | NJT_SLAB_SMALL;

            slots[slot].next = page;

            pool->stats[slot].total += (njt_pagesize >> shift) - n;

            p = njt_slab_page_addr(pool, page) + (n << shift);

            pool->stats[slot].used++;

            goto done;

        } else if (shift == njt_slab_exact_shift) {

            page->slab = 1;
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | NJT_SLAB_EXACT;

            slots[slot].next = page;

            pool->stats[slot].total += 8 * sizeof(uintptr_t);

            p = njt_slab_page_addr(pool, page);

            pool->stats[slot].used++;

            goto done;

        } else { /* shift > njt_slab_exact_shift */

            page->slab = ((uintptr_t) 1 << NJT_SLAB_MAP_SHIFT) | shift;
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | NJT_SLAB_BIG;

            slots[slot].next = page;

            pool->stats[slot].total += njt_pagesize >> shift;

            p = njt_slab_page_addr(pool, page);

            pool->stats[slot].used++;

            goto done;
        }
    }

    p = 0;

    pool->stats[slot].fails++;

done:
    if (p == 0 && pool->next != NULL) {
        return njt_slab_alloc_locked(pool->next, size);
    }

    s = (size_t)(pool->end - (u_char *)pool);
    if ( p == 0 && pool->first != njt_shared_slab_header
                && pool->first->auto_scale
                && njt_shared_slab_header != NULL
                && njt_slab_can_alloc(pool, size) == NJT_OK)
    {
        new_pool = (njt_slab_pool_t *) njt_slab_try_alloc(njt_shared_slab_header, s);
        if (new_pool != NULL) {
            njt_slab_add_new_pool(pool->first, new_pool, s, njt_cycle->log);
            njt_log_debug2(NJT_LOG_DEBUG_ALLOC, njt_cycle->log, 0,
                "new slab pool alloc: %p, size %d", (void *) new_pool, s);
            return njt_slab_alloc_locked(new_pool, size);
        }
    }

    if (p == 0) {
        if (pool->log_nomem) {
            njt_slab_error(pool, NJT_LOG_CRIT,
                        "njt_slab_alloc() failed: no memory");
        }
    }

    njt_log_debug1(NJT_LOG_DEBUG_ALLOC, njt_cycle->log, 0,
                   "slab alloc: %p", (void *) p);

#if (NJT_SHM_STATUS)
    slab_update_item->failed = p == 0 ? 1 : 0;
    if (pool->first != njt_shared_slab_header && slab_update_item->rec) {
        njt_shm_status_update_alloc_item(slab_update_item);
    }
#endif

    return (void *) p;
}


void *
njt_slab_calloc(njt_slab_pool_t *pool, size_t size)
{
    void  *p;

    njt_shmtx_lock(&pool->mutex);

    p = njt_slab_calloc_locked(pool, size);

    njt_shmtx_unlock(&pool->mutex);

    return p;
}


void *
njt_slab_calloc_locked(njt_slab_pool_t *pool, size_t size)
{
    void  *p;

    p = njt_slab_alloc_locked(pool, size);
    if (p) {
        njt_memzero(p, size);
    }

    return p;
}


void
njt_slab_free(njt_slab_pool_t *pool, void *p)
{
    njt_shmtx_lock(&pool->mutex);

    njt_slab_free_locked(pool, p);

    njt_shmtx_unlock(&pool->mutex);
}


void
njt_slab_free_locked(njt_slab_pool_t *first_pool, void *p)
{
    size_t            size;
    uintptr_t         slab, m, *bitmap;
    njt_uint_t        i, n, type, slot, shift, map;
    njt_slab_page_t  *slots, *page;
    njt_slab_pool_t  *pool;

    for (pool = first_pool; pool->next != NULL; pool = pool->next) {
        if ((u_char *) p >= pool->start && (u_char *) p < pool->end) {
            break;
        }
    }

#if (NJT_SHM_STATUS)
    slab_update_item->rec = pool->status_rec;
    slab_update_item->alloc = 0;
    slab_update_item->failed = 0;
    slab_update_item->pages = 0;
    slab_update_item->slot = 0;
#endif

    njt_log_debug1(NJT_LOG_DEBUG_ALLOC, njt_cycle->log, 0, "slab free: %p", p);

    if ((u_char *) p < pool->start || (u_char *) p > pool->end) {
        njt_slab_error(pool, NJT_LOG_ALERT, "njt_slab_free(): outside of pool");
        goto fail;
    }

    n = ((u_char *) p - pool->start) >> njt_pagesize_shift;
    page = &pool->pages[n];
    slab = page->slab;
    type = njt_slab_page_type(page);

    switch (type) {

    case NJT_SLAB_SMALL:

        shift = slab & NJT_SLAB_SHIFT_MASK;
        size = (size_t) 1 << shift;

        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        n = ((uintptr_t) p & (njt_pagesize - 1)) >> shift;
        m = (uintptr_t) 1 << (n % (8 * sizeof(uintptr_t)));
        n /= 8 * sizeof(uintptr_t);
        bitmap = (uintptr_t *)
                             ((uintptr_t) p & ~((uintptr_t) njt_pagesize - 1));

        if (bitmap[n] & m) {
            slot = shift - pool->min_shift;

#if (NJT_SHM_STATUS)
            slab_update_item->slot = shift;
#endif

            if (page->next == NULL) {
                slots = njt_slab_slots(pool);

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | NJT_SLAB_SMALL;
                page->next->prev = (uintptr_t) page | NJT_SLAB_SMALL;
            }

            bitmap[n] &= ~m;

            n = (njt_pagesize >> shift) / ((1 << shift) * 8);

            if (n == 0) {
                n = 1;
            }

            i = n / (8 * sizeof(uintptr_t));
            m = ((uintptr_t) 1 << (n % (8 * sizeof(uintptr_t)))) - 1;

            if (bitmap[i] & ~m) {
                goto done;
            }

            map = (njt_pagesize >> shift) / (8 * sizeof(uintptr_t));

            for (i = i + 1; i < map; i++) {
                if (bitmap[i]) {
                    goto done;
                }
            }

            njt_slab_free_pages(pool, page, 1);

            pool->stats[slot].total -= (njt_pagesize >> shift) - n;

            goto done;
        }

        goto chunk_already_free;

    case NJT_SLAB_EXACT:

        m = (uintptr_t) 1 <<
                (((uintptr_t) p & (njt_pagesize - 1)) >> njt_slab_exact_shift);
        size = njt_slab_exact_size;

        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        if (slab & m) {
            slot = njt_slab_exact_shift - pool->min_shift;

#if (NJT_SHM_STATUS)
            slab_update_item->slot = njt_slab_exact_shift;
#endif

            if (slab == NJT_SLAB_BUSY) {
                slots = njt_slab_slots(pool);

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | NJT_SLAB_EXACT;
                page->next->prev = (uintptr_t) page | NJT_SLAB_EXACT;
            }

            page->slab &= ~m;

            if (page->slab) {
                goto done;
            }

            njt_slab_free_pages(pool, page, 1);

            pool->stats[slot].total -= 8 * sizeof(uintptr_t);

            goto done;
        }

        goto chunk_already_free;

    case NJT_SLAB_BIG:

        shift = slab & NJT_SLAB_SHIFT_MASK;
        size = (size_t) 1 << shift;

        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        m = (uintptr_t) 1 << ((((uintptr_t) p & (njt_pagesize - 1)) >> shift)
                              + NJT_SLAB_MAP_SHIFT);

        if (slab & m) {
            slot = shift - pool->min_shift;

#if (NJT_SHM_STATUS)
            slab_update_item->slot = shift;
#endif

            if (page->next == NULL) {
                slots = njt_slab_slots(pool);

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | NJT_SLAB_BIG;
                page->next->prev = (uintptr_t) page | NJT_SLAB_BIG;
            }

            page->slab &= ~m;

            if (page->slab & NJT_SLAB_MAP_MASK) {
                goto done;
            }

            njt_slab_free_pages(pool, page, 1);

            pool->stats[slot].total -= njt_pagesize >> shift;

            goto done;
        }

        goto chunk_already_free;

    case NJT_SLAB_PAGE:

        if ((uintptr_t) p & (njt_pagesize - 1)) {
            goto wrong_chunk;
        }

        if (!(slab & NJT_SLAB_PAGE_START)) {
            njt_slab_error(pool, NJT_LOG_ALERT,
                           "njt_slab_free(): page is already free");
            goto fail;
        }

        if (slab == NJT_SLAB_PAGE_BUSY) {
            njt_slab_error(pool, NJT_LOG_ALERT,
                           "njt_slab_free(): pointer to wrong page");
            goto fail;
        }

        size = slab & ~NJT_SLAB_PAGE_START;

        njt_slab_free_pages(pool, page, size);

        njt_slab_junk(p, size << njt_pagesize_shift);

#if (NJT_SHM_STATUS)
    if (slab_update_item->rec) {
        njt_shm_status_update_alloc_item(slab_update_item);
    }
#endif

        return;
    }

    /* not reached */

    return;

done:

    pool->stats[slot].used--;

    njt_slab_junk(p, size);

#if (NJT_SHM_STATUS)
    if (slab_update_item->rec) {
        njt_shm_status_update_alloc_item(slab_update_item);
    }
#endif

    return;

wrong_chunk:

    njt_slab_error(pool, NJT_LOG_ALERT,
                   "njt_slab_free(): pointer to wrong chunk");

    goto fail;

chunk_already_free:

    njt_slab_error(pool, NJT_LOG_ALERT,
                   "njt_slab_free(): chunk is already free");

fail:

    return;
}


static njt_slab_page_t *
njt_slab_alloc_pages(njt_slab_pool_t *pool, njt_uint_t pages)
{
    njt_slab_page_t  *page, *p;

#if (NJT_SHM_STATUS)
    slab_update_item->pages = pages;
#endif

    for (page = pool->free.next; page != &pool->free; page = page->next) {

        if (page->slab >= pages) {

            if (page->slab > pages) {
                page[page->slab - 1].prev = (uintptr_t) &page[pages];

                page[pages].slab = page->slab - pages;
                page[pages].next = page->next;
                page[pages].prev = page->prev;

                p = (njt_slab_page_t *) page->prev;
                p->next = &page[pages];
                page->next->prev = (uintptr_t) &page[pages];

            } else {
                p = (njt_slab_page_t *) page->prev;
                p->next = page->next;
                page->next->prev = page->prev;
            }

            page->slab = pages | NJT_SLAB_PAGE_START;
            page->next = NULL;
            page->prev = NJT_SLAB_PAGE;

            pool->pfree -= pages;

            if (--pages == 0) {
                return page;
            }

            for (p = page + 1; pages; pages--) {
                p->slab = NJT_SLAB_PAGE_BUSY;
                p->next = NULL;
                p->prev = NJT_SLAB_PAGE;
                p++;
            }

            return page;
        }
    }

    // if (pool->log_nomem) {
    //     njt_slab_error(pool, NJT_LOG_CRIT,
    //                    "njt_slab_alloc() failed: no memory");
    // }

    return NULL;
}


static void
njt_slab_free_pages(njt_slab_pool_t *pool, njt_slab_page_t *page,
    njt_uint_t pages)
{
    njt_slab_page_t  *prev, *join;

#if (NJT_SHM_STATUS)
    slab_update_item->pages = pages;
#endif

    pool->pfree += pages;

    page->slab = pages--;

    if (pages) {
        njt_memzero(&page[1], pages * sizeof(njt_slab_page_t));
    }

    if (page->next) {
        prev = njt_slab_page_prev(page);
        prev->next = page->next;
        page->next->prev = page->prev;
    }

    join = page + page->slab;

    if (join < pool->last) {

        if (njt_slab_page_type(join) == NJT_SLAB_PAGE) {

            if (join->next != NULL) {
                pages += join->slab;
                page->slab += join->slab;

                prev = njt_slab_page_prev(join);
                prev->next = join->next;
                join->next->prev = join->prev;

                join->slab = NJT_SLAB_PAGE_FREE;
                join->next = NULL;
                join->prev = NJT_SLAB_PAGE;
            }
        }
    }

    if (page > pool->pages) {
        join = page - 1;

        if (njt_slab_page_type(join) == NJT_SLAB_PAGE) {

            if (join->slab == NJT_SLAB_PAGE_FREE) {
                join = njt_slab_page_prev(join);
            }

            if (join->next != NULL) {
                pages += join->slab;
                join->slab += page->slab;

                prev = njt_slab_page_prev(join);
                prev->next = join->next;
                join->next->prev = join->prev;

                page->slab = NJT_SLAB_PAGE_FREE;
                page->next = NULL;
                page->prev = NJT_SLAB_PAGE;

                page = join;
            }
        }
    }

    if (pages) {
        page[pages].prev = (uintptr_t) page;
    }

    page->prev = (uintptr_t) &pool->free;
    page->next = pool->free.next;

    page->next->prev = (uintptr_t) page;

    pool->free.next = page;
}


static void
njt_slab_error(njt_slab_pool_t *pool, njt_uint_t level, char *text)
{
    njt_log_error(level, njt_cycle->log, 0, "%s%s", text, pool->log_ctx);
}


void
njt_shm_free_chain(njt_shm_t *shm, njt_slab_pool_t *shared_pool)
{
    njt_slab_pool_t *pool, *cur;

    pool = (njt_slab_pool_t *)shm->addr;

#ifdef NJT_SHM_STATUS
    if (njt_shm_status_summary && njt_process != NJT_PROCESS_HELPER) {
        njt_shm_status_rm_zone_record(pool);
    }
#endif

    for (cur = pool->next; cur != NULL;) {
        pool = cur->next; // must set before free slab_pool
        njt_slab_free(shared_pool, cur);
        cur = pool;
    }

    njt_shm_free(shm);
}


void
njt_share_slab_free_chain_locked(njt_slab_pool_t *header)
{
    njt_slab_pool_t  *pool, *cur;

    pool = header;

    for (cur = pool->next; cur != NULL;) {
        pool = cur->next;
        njt_slab_free_locked(njt_shared_slab_header, cur);
        cur = pool;
    }

    njt_slab_free_locked(njt_shared_slab_header, header);
}


njt_int_t
njt_share_slab_free_pool_locked_impl(njt_slab_pool_t *pool)
{
    njt_queue_t                 *header, *cur;
    njt_share_slab_pool_node_t  *node;

    header = &njt_shared_slab_queue_header->zones;
    node = NULL;
    cur = njt_queue_next(header);

    while (cur != header) {
        node = (njt_share_slab_pool_node_t *)njt_queue_data(cur, njt_share_slab_pool_node_t, queue);
        if (node->pool == pool) {
            break;
        }
        cur = njt_queue_next(cur);
    }

    if (cur != header) {
#if (NJT_SHM_STATUS)
        if (njt_shm_status_summary) {
            njt_shm_status_rm_zone_record(pool);
        }
#endif

        njt_share_slab_free_chain_locked(node->pool);
        njt_slab_free_locked(njt_shared_admin_slab_header, node->name.data);
        njt_queue_remove(&node->queue);
        if (node->del_queue.next) {
            njt_queue_remove(&node->del_queue);
        }
        njt_slab_free_locked(njt_shared_admin_slab_header, node);

        return  NJT_OK;

    } else { // not find
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "can not find pool %p", pool);
        return   NJT_ERROR;
    }
}


struct FTW*  no_use_struct_declaration_for_gcc_warning;
int unlink_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    int rv = remove(fpath);

    if (rv) {
        perror(fpath);
    }

    return rv;
}


njt_int_t
njt_share_slab_create_hidden_dir(njt_cycle_t *cycle)
{
    char dir_path[PATH_MAX+1];
    u_char *p;

    p = njt_sprintf((u_char *)dir_path, "%V", &cycle->prefix);
    if (*(p-1) != '/') {
        *p++ = '/';
    } 

    p = njt_sprintf(p, "%s", "data/.dyn_slab");
    *p = '\0';


    if (mkdir(dir_path, 0755) == -1) { // 如果mkdir函数返回-1，表示创建目录失败
        if (errno == EEXIST) {
            nftw(dir_path, unlink_cb, 64, FTW_DEPTH | FTW_PHYS);
            mkdir(dir_path, 0755);
        } else {
            // 打印错误消息
            njt_log_error(NJT_LOG_INFO, cycle->log, 0, "failed to create dyn zone file directory");
            return NJT_ERROR;
        }
    }

    njt_log_debug1(NJT_LOG_DEBUG_ALLOC, cycle->log, 0, "Directory '%s' created successfully.\n", dir_path);
    return NJT_OK;;
}


void
njt_share_slab_open_hidden_pool_file(njt_cycle_t *cycle, njt_share_slab_pool_node_t *node)
{
    u_char    path[PATH_MAX+1];
    u_char   *p;
    njt_fd_t  fd;

    if (njt_process == NJT_PROCESS_MASTER && node->fd != -1) {
        njt_close_file(node->fd);
    }

    p = njt_sprintf(path, "%v", &cycle->prefix);
    if (*(p-1) != '/') {
        *p++ = '/';
    } 

    p = njt_sprintf(p, "%s/.%p", "data/.dyn_slab", node->pool);
    *p = '\0';
    // fprintf(stderr, "%s", path);
    fd = njt_open_file(path, NJT_FILE_CREATE_OR_OPEN | NJT_FILE_RDWR, NJT_FILE_TRUNCATE,
                       NJT_FILE_DEFAULT_ACCESS);    
    if (fd == NJT_INVALID_FILE) {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, "failed to open dyn zone pool file %s", path);
    } else if (njt_process == NJT_PROCESS_MASTER) {
        node->fd = fd;
    }
}


void
njt_share_slab_close_hidden_pool_file(njt_cycle_t *cycle, njt_share_slab_pool_node_t *node)
{
    DIR                    *dir, *dir_fd;
    struct dirent          *fd_entry;
    static char             path[PATH_MAX+1], fd_path[PATH_MAX+PATH_MAX+1], real_path[PATH_MAX+1], abs_path[PATH_MAX+1];
    ssize_t                 len, real_len;
    u_char                 *p;

    p = njt_sprintf((u_char *)path, "%V", &cycle->prefix);
    if (*(p-1) != '/') {
        *p++ = '/';
    }
    njt_sprintf(p, "%s/.%p", "data/.dyn_slab", node->pool);

    njt_memzero(abs_path, PATH_MAX+1);
    p = (u_char *)realpath(path, abs_path); //example: abs_path /usr/local/njet/data/.dyn_slab/.00007DD040910000
    real_len = strlen(abs_path);

    if (!(dir = opendir("/proc"))) {
        perror("opendir");
        return;
    }

    sprintf(path, "/proc/%d/fd", njt_pid);

    if (!(dir_fd = opendir(path))) { // check pid exists
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, "pid not exist in /proc %d", njt_pid);
    }

    while ((fd_entry = readdir(dir_fd)) != NULL) {
        sprintf(fd_path, "%s/%s", path, fd_entry->d_name);
        len = readlink(fd_path, real_path, sizeof(real_path) - 1);
        if (len != -1 && len >= real_len) {
            real_path[len] = '\0';
            if (strncmp(real_path, abs_path, real_len) == 0) {
                njt_log_error(NJT_LOG_ERR, cycle->log, 0, "close fd %s", fd_entry->d_name);
                close(atoi(fd_entry->d_name));
                break;
            }
        }
    }

    closedir(dir_fd);
    closedir(dir);
}


void
njt_share_slab_try_free_pools_locked(njt_cycle_t *cycle)
{
    njt_queue_t                 *head, *cur;
    njt_share_slab_pool_node_t  *node;

    head = &cycle->shared_slab.queues_header->delete_zones;
    cur = njt_queue_next(head);

    while (cur != head) {
        node = (njt_share_slab_pool_node_t *)njt_queue_data(cur, njt_share_slab_pool_node_t, del_queue);
        cur = njt_queue_next(cur);
        if (node->merge && !node->merged) {
            continue;
        }
        if (node->ref_cnt == 0 || !njt_share_slab_is_hidden_file_opened_locked(cycle, node)) {
            njt_share_slab_free_pool_locked(cycle, node->pool);
        }
    }
}


void
njt_share_slab_set_ctrl_pid(njt_cycle_t *cycle)
{
    njt_share_slab_pid_t    *node;
    njt_queue_t             *head;

    if (njt_process == NJT_PROCESS_MASTER) {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, "this func should not be called from master");
    }

    if (!cycle->shared_slab.header) {
        return;
    }

    head = &cycle->shared_slab.queues_header->pids;

    njt_shmtx_lock(&cycle->shared_slab.header->mutex);
    node = njt_slab_alloc_locked(njt_shared_admin_slab_header, sizeof(njt_share_slab_pid_t));
    node->pid = njt_pid;
    njt_queue_insert_tail(head, &node->queue);
    njt_shmtx_unlock(&cycle->shared_slab.header->mutex);

}


void
njt_share_slab_close_dyn_files(njt_cycle_t *cycle)
{
    njt_share_slab_pool_node_t  *node;
    njt_queue_t                 *head, *cur;

    if (njt_process == NJT_PROCESS_MASTER) {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, "this func should not be called from master");
    } 

    if (!cycle->shared_slab.header) {
        return;
    }
    
    njt_shmtx_lock(&cycle->shared_slab.header->mutex);
    head = &cycle->shared_slab.queues_header->zones;
    cur = njt_queue_next(head);
    while(cur != head) {
        node = (njt_share_slab_pool_node_t *)njt_queue_data(cur, njt_share_slab_pool_node_t, queue);
        if (!node->del && node->fd > 0) {
            njt_log_error(NJT_LOG_ERR, cycle->log, 0, "close fd %d", node->fd);
            njt_close_file(node->fd);
        }
        cur = njt_queue_next(cur);
    }
    njt_shmtx_unlock(&cycle->shared_slab.header->mutex);
}

njt_int_t
njt_share_slab_free_pool(njt_cycle_t *cycle, njt_slab_pool_t *pool)
{
    njt_queue_t  *zone_header, *del_header, *cur;
    njt_share_slab_pool_node_t *node;

    if (cycle->shared_slab.header == NULL) {
        return NJT_ERROR;
    }

    if (pool == njt_shared_admin_slab_header) {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, "remove dyn_admin_pool is forbidden");
        return NJT_ERROR;
    }

    njt_shmtx_lock(&njt_shared_slab_header->mutex);
    node = NULL;
    zone_header = &cycle->shared_slab.queues_header->zones;
    cur = njt_queue_next(zone_header);

    while(cur != zone_header) {
        node = (njt_share_slab_pool_node_t *)njt_queue_data(cur, njt_share_slab_pool_node_t, queue);
        if (node->pool == pool) {
            break;
        }
        cur = njt_queue_next(cur);
    }

    if (cur != zone_header) {
        if (!node->del) {
            cycle->shared_slab.dyn_zone_count --;
        }
        node->del = 1;
        node->ref_cnt --;

        njt_share_slab_close_hidden_pool_file(cycle, node);
        if (node->ref_cnt == 0) {
            njt_share_slab_free_pool_locked(cycle, node->pool);
            njt_shmtx_unlock(&njt_shared_slab_header->mutex);
            return NJT_OK;
        }
        if (node->del_queue.prev == NULL) {
            del_header = &cycle->shared_slab.queues_header->delete_zones;
            njt_queue_insert_tail(del_header, &node->del_queue);

#if (NJT_SHM_STATUS)
            if (njt_shm_status_summary) {
                njt_shm_status_mark_zone_delete(node->pool);
            }
#endif
        }

    } else {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, "try to free dyn zone pool unexist %p", pool);
        njt_shmtx_unlock(&njt_shared_slab_header->mutex);
        return NJT_ERROR;
    }

    njt_shmtx_unlock(&njt_shared_slab_header->mutex);
    return NJT_OK;
}


njt_int_t
njt_share_slab_free_pool_locked(njt_cycle_t *cycle, njt_slab_pool_t *pool)
{
    njt_int_t        ret;
    njt_slab_pool_t *saved_header =  njt_shared_slab_header;

    njt_share_slab_set_header(cycle->shared_slab.header);
    if (njt_shared_slab_header == NULL) {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, "no share slab pool exist");
        njt_share_slab_set_header(saved_header);
        return NJT_ERROR;
    }

    if (pool == NULL || pool->first != pool) {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, "null pool or non_first passed to njt_share_slab_free_pool");
        njt_share_slab_set_header(saved_header);
        return NJT_ERROR;
    }

    ret = njt_share_slab_free_pool_locked_impl(pool);

    njt_share_slab_set_header(saved_header);

    return ret;
}


njt_int_t
njt_share_slab_update_pid_queue(njt_cycle_t *cycle, njt_queue_t *head, njt_pid_t pid) {
    njt_queue_t           *cur;
    njt_share_slab_pid_t  *node;

    // if (njt_queue_empty(head)) {
    //     njt_log_error(NJT_LOG_DEBUG, cycle->log, 0, "queue is empty");
    //     return NJT_ERROR;
    // }

    cur = njt_queue_next(head);
    while (cur != head) {
        node = (njt_share_slab_pid_t *)njt_queue_data(cur, njt_share_slab_pid_t, queue);
        if (node->pid == pid) {
            return NJT_OK;
        }
        cur = njt_queue_next(cur);
    }

    node = njt_slab_alloc_locked(njt_shared_admin_slab_header, sizeof(njt_share_slab_pid_t));
    if (node == NULL) {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, "alloc pid_node failed");
        return NJT_ERROR;
    }

    node->pid = pid;
    njt_queue_insert_tail(head, &node->queue);

    return NJT_OK;
}


njt_int_t
njt_share_slab_save_pids(njt_cycle_t *cycle) {
    njt_queue_t  *head;
    njt_int_t     i;

    if (njt_process != NJT_PROCESS_MASTER) {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, "save pids should not be called from non-master");
    }

    if (!cycle->shared_slab.header) {
        return NJT_OK;
    }

    head = &cycle->shared_slab.queues_header->pids;

    njt_shmtx_lock(&njt_shared_slab_header->mutex);

    for (i = 0; i < njt_last_process; i++) {
        if ( strlen(njt_processes[i].name) == strlen("worker process") 
            && njt_strncmp(njt_processes[i].name, "worker process", 14) == 0 
            &&  njt_processes[i].pid != -1) 
        {
            if(njt_share_slab_update_pid_queue(cycle, head, njt_processes[i].pid) != NJT_OK) {
                 njt_shmtx_unlock(&njt_shared_slab_header->mutex);
                 return NJT_ERROR;
            }
        }
    }

    njt_shmtx_unlock(&njt_shared_slab_header->mutex);
    return NJT_OK;

}


njt_int_t
njt_share_slab_rm_pid(njt_pid_t pid) {
    njt_queue_t           *head, *cur;
    njt_share_slab_pid_t  *node;

    if (njt_process != NJT_PROCESS_MASTER) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "rm worker pid should not be called from non-master");
        return NJT_OK;
    }

    if (!njt_shared_slab_header) {
        return NJT_OK;
    }

    head = &njt_shared_slab_queue_header->pids;

    njt_shmtx_lock(&njt_shared_slab_header->mutex);

    cur = njt_queue_next(head);
    while (cur != head) {
        node = (njt_share_slab_pid_t *)njt_queue_data(cur, njt_share_slab_pid_t, queue);
        if (node->pid == pid) {
            njt_queue_remove(cur);
            break;
        }
        cur = njt_queue_next(cur);
    }

    njt_shmtx_unlock(&njt_shared_slab_header->mutex);

    return NJT_OK;
}

void
njt_share_slab_update_node_pid(njt_share_slab_pool_node_t *node)
{
    njt_pid_t pid;

    if (njt_process != NJT_PROCESS_MASTER) {
        pid = njt_pid; // pid = getpid();
        node->pid_max = njt_max(node->pid_max, pid);
        node->pid_min = njt_min(node->pid_max, pid);
        node->ref_cnt ++;
    }
}


njt_int_t
njt_share_slab_get_pool_locked(void *tag, njt_str_t *name, size_t size,
                               njt_uint_t flags, njt_slab_pool_t **shpool)
{
    njt_slab_pool_t             *pool;
    njt_share_slab_pool_node_t  *node;
    njt_queue_t                 *header, *cur;

    if (!(flags & NJT_DYN_SHM_OPEN) && !(flags & NJT_DYN_SHM_CREATE_OR_OPEN)) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "must set flags with NJT_DYN_SHM_OPEN OR NJT_DYN_SHM_CREATE_ON_OPEN");
        goto failed;
    }

    if (name == NULL || name->len == 0 || tag == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "tag is null or name is null or name length is zero");
        goto failed;
    }

    header = &njt_shared_slab_queue_header->zones;
    cur = njt_queue_next(header);
    node = NULL;

    while (cur != header) {
        node = (njt_share_slab_pool_node_t *)njt_queue_data(cur, njt_share_slab_pool_node_t, queue);
        if ( node->name.len == name->len
            && njt_memcmp(node->name.data, name->data, name->len) == 0
            && !node->del) {
            break;
        }
        cur = njt_queue_next(cur);
    }

    if (cur != header) {
        if (flags & NJT_DYN_SHM_OPEN) {
            if (node->tag == tag) {
                *shpool = node->pool;
                return NJT_OK;
            }
            goto failed;
        }
        if (node->tag != tag) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "same name with different tag is forbidden, zone_name %V, old tag %p,  new tag %p", name, node->tag, tag);
            *shpool = NULL;
            return NJT_DONE;
        }
        if (node->size == size) {
            *shpool = node->pool;
            njt_share_slab_update_node_pid(node);
            njt_share_slab_open_hidden_pool_file((njt_cycle_t *)njt_cycle, node);
            return NJT_DONE;
        } else {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "a dynamic zone does not support create with different sizes, zone name %V, original size %ui, new size",
                name, node->size, size);
            *shpool = NULL;
            return NJT_DONE;

        }
    }

    if (flags & NJT_DYN_SHM_OPEN) {
        goto failed;
    }

    pool = njt_slab_calloc_locked(njt_shared_slab_header, size);
    if (pool == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "failed to alloc dyn slab pool");
        goto failed;
    }

    // INIT NEW SLAB POOL
    pool->end = (u_char *) pool + size;
    pool->min_shift = 3; // same as value in njt_init_shm_pool()
    pool->addr = pool;
    pool->next = NULL;
    pool->first = pool;

    if (njt_shmtx_create(&pool->mutex, &pool->lock, NULL) != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "failed to create shared slab's shmtx");
        goto failed;
    }

    njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0,
        "dyn_slab add allocate new slab name='%V' pool: %p, size %d", name,(void *) pool, size);
    njt_slab_init(pool);
    *shpool = pool;

    node = njt_slab_alloc_locked(njt_shared_admin_slab_header, sizeof(njt_share_slab_pool_node_t));

    if (node == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "failed to alloc dyn slab node");
        njt_slab_free_locked(njt_shared_slab_header, pool);
        goto failed;
    }

    node->name.data = njt_slab_calloc_locked(njt_shared_admin_slab_header, name->len);
    if (node->name.data == NULL) {
        njt_slab_free_locked(njt_shared_slab_header, node);
        njt_slab_free_locked(njt_shared_slab_header, pool);
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "failed to alloc dyn slab node name");
        goto failed;
    }

    node->name.len = name->len;
    njt_memcpy(node->name.data, name->data, name->len);
    node->pool = pool;
    node->size = size;
    node->tag = tag;
    node->noreuse = flags & NJT_DYN_SHM_NOREUSE ? 1 : 0;
    node->new_create = 1;
    node->del = 0;
    node->ref_cnt = 0;
    node->pid_max = 0;
    node->pid_min = INT32_MAX;
    node->del_queue.next = NULL;
    node->del_queue.prev = NULL;
    njt_queue_insert_tail(header, &node->queue);
    njt_share_slab_open_hidden_pool_file((njt_cycle_t *)njt_cycle, node);

    njt_share_slab_update_node_pid(node);

#if (NJT_SHM_STATUS)
    if (njt_shm_status_summary) {
        njt_shm_status_add_zone_record(name, size, NJT_SHM_STATUS_DYNAMIC, &pool->status_rec);
    }
#endif

    return NJT_OK;

failed:
    *shpool = NULL;
    return NJT_ERROR;
}


njt_int_t
njt_share_slab_add_post_request(njt_cycle_t *cycle,
    njt_shm_zone_t *zone, njt_uint_t flags, njt_slab_pool_t **shpool)
{
    njt_queue_t                 *head;
    njt_share_slab_wait_zone_t  *node;

    // if (zone->noreuse == 0) {
    //     njt_log_error(NJT_LOG_ERR, cycle->log, 0, "alloc noreuse_zone in post_config, name %V", &zone->shm.name);
    //     *shpool = NULL;
    //     return NJT_ERROR;
    // }

    head = &cycle->shared_slab.wait_zones;
    node = njt_palloc(cycle->shared_slab.pool, sizeof(njt_share_slab_wait_zone_t));
    if (node == NULL) {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, "no memory for alloc waiting zones");
        *shpool = NULL;
        return NJT_ERROR;
    }

    node->zone = zone;
    node->flag = flags;
    node->shpool = shpool;
    *(node->shpool) = NULL;
    node->new_alloc = 0;

    njt_queue_insert_tail(head, &node->queue);
    return NJT_OK;
}


void
njt_share_slab_defer_get_pool(njt_cycle_t *cycle, njt_shm_zone_t *zone,
                        njt_uint_t flags, njt_slab_pool_t **shpool)
{
    njt_int_t                    ret;
    njt_str_t                   *name;

    name = &zone->shm.name;

    if (zone->noreuse) {
        flags = flags | NJT_DYN_SHM_NOREUSE;
    } else {
        flags = flags & (~NJT_DYN_SHM_NOREUSE);
    }

    if (njt_share_slab_is_dyn_admin(&zone->shm.name)) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "zone name 'dyn_admin_zone' is reserved by njet");
        *shpool = NULL;
        return;
    }

     if (zone->shm.size == 0) {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0,
                        "zero size dynamic shared memory zone \"%V\"",
                        &zone->shm.name);
        *shpool = NULL;
        return;
    }

    if (njt_share_slab_is_init_phase(cycle)) {
        if (njt_process == NJT_PROCESS_HELPER) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "call slab_get_pool from post_config phase in HELPER PROCESS is invalid, pid = %d, zone_name = %V", njt_pid, name);
            *shpool = NULL;
            return;
        }
        ret = njt_share_slab_add_post_request(cycle, zone, flags, shpool);
        if (ret != NJT_OK) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "call njt_share_slab_add_post_request return NJT_ERROR");
        }
        return;
    }

    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "call slab_get_defer_pool in non_post_config phase is invalid, pid = %d, zone_name = %V", njt_pid, name);
    *shpool = NULL;
    return ;
}


njt_int_t
njt_share_slab_get_pool(njt_cycle_t *cycle, njt_shm_zone_t *zone,
                        njt_uint_t flags, njt_slab_pool_t **shpool)
{
    njt_int_t                    ret;
    void                        *tag;
    njt_str_t                   *name;
    size_t                       size;
    njt_queue_t                 *head, *cur;
    njt_share_slab_pool_node_t  *node, *old_node;

    tag = zone->tag;
    name = &zone->shm.name;
    size = zone->shm.size;

    if (zone->noreuse) {
        flags = flags | NJT_DYN_SHM_NOREUSE;
    } else {
        flags = flags & (~NJT_DYN_SHM_NOREUSE);
    }

    if (njt_share_slab_is_dyn_admin(&zone->shm.name)) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "zone name 'dyn_admin_zone' is reserved by njet");
        *shpool = NULL;
        return NJT_ERROR;
    }

     if (zone->shm.size == 0) {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0,
                        "zero size dynamic shared memory zone \"%V\"",
                        &zone->shm.name);
        *shpool = NULL;
        return NJT_ERROR;
    }

    if (njt_share_slab_is_init_phase(cycle)) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "call slab_get_pool from post_config phase in forbidden, call njt_share_slab_defer_get_pool instead, pid = %d, zone_name = %V", njt_pid, name);
        *shpool = NULL;
        return NJT_ERROR;
    }

    if (njt_shared_slab_header == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "please use shared_slab_pool_size cmd to create share slab pool first");
        *shpool = NULL;
        return NJT_ERROR;
    }

    njt_slab_pool_t *saved_header =  njt_shared_slab_header;
    njt_share_slab_set_header(cycle->shared_slab.header);

    njt_shmtx_lock(&njt_shared_slab_header->mutex);
    njt_share_slab_try_free_pools_locked(cycle);

    // there is a dyn_admin_zone if use dyn shared memory
    if (cycle->shared_slab.dyn_zone_count >= cycle->shared_slab.max_dyn_zone_count) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
            "total dyn zone count exceeds the limit(%ld)",
                cycle->shared_slab.max_dyn_zone_count);
        *shpool = NULL;
        njt_shmtx_unlock(&njt_shared_slab_header->mutex);
        njt_share_slab_set_header(saved_header);
        return NJT_ERROR;
    }

    ret = njt_share_slab_get_pool_locked(tag, name, size, flags, shpool);
    zone->shm.addr = (u_char *)*shpool;

    if (flags & NJT_DYN_SHM_CREATE_OR_OPEN && ret == NJT_OK && *shpool != NULL) {

        head = &njt_shared_slab_queue_header->zones;
        cur = njt_queue_prev(head);
        node = (njt_share_slab_pool_node_t *)njt_queue_data(cur, njt_share_slab_pool_node_t, queue);
        old_node = njt_share_slab_get_old_node_locked(cycle, zone, NULL);

        if (zone->merge && zone->noreuse) {
            node->merge = 1;
            if (old_node != NULL) {
                zone->merge(zone, old_node->pool);
                old_node->merged = 1;
            }
        }

        if(zone->init != NULL) {
            if (zone->init(zone, NULL) != NJT_OK) {
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                    "dyn slab: get pool failed to init new created node '%V'",
                    &zone->shm.name);
                njt_share_slab_free_pool_locked(cycle, *shpool);
                *shpool = NULL;
                ret = NJT_ERROR;
            }

            node->inited = 1;
        }
        cycle->shared_slab.dyn_zone_count ++;
    } else if (flags & NJT_DYN_SHM_CREATE_OR_OPEN && ret == NJT_DONE && *shpool != NULL) {
        if (zone->init_other && zone->init_other(zone, *shpool) != NJT_OK) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "dyn slab: get pool failed to init_done node '%V'",
                &zone->shm.name);
            *shpool = NULL;
            ret = NJT_ERROR;
        }
    }

    njt_shmtx_unlock(&njt_shared_slab_header->mutex);
    njt_share_slab_set_header(saved_header);

    return ret;
}


njt_int_t
njt_share_slab_init_pool_list(njt_cycle_t *cycle)
{
    njt_share_slab_pool_node_t  *node;
    njt_share_slab_queues_t     *header;
    njt_queue_t                 *h, *cur, *del;
    njt_slab_pool_t             *pool;
    const char                  *zone_name = "dyn_admin_zone";
    const size_t                 zone_size = 1024 * 1024; // 1M

    if (njt_shared_slab_header == NULL) {
        return NJT_OK;
    }

    njt_shmtx_lock(&njt_shared_slab_header->mutex);

    if (cycle->shared_slab.queues_header) { // reload
        h = &cycle->shared_slab.queues_header->zones;
        del = &cycle->shared_slab.queues_header->delete_zones;
        cur = njt_queue_next(h);

        while (cur != h) {
            node = njt_queue_data(cur, njt_share_slab_pool_node_t, queue);
            node->new_create = 0;
            cur = njt_queue_next(cur);
        }

        cur = njt_queue_next(h);
        while (cur != h) {
            node = njt_queue_data(cur, njt_share_slab_pool_node_t, queue);
            if (!node->del && node->noreuse && !node->new_create) {
                node->del = 1;
                cycle->shared_slab.dyn_zone_count --;
                njt_queue_insert_tail(del, &node->del_queue);

#if (NJT_SHM_STATUS)
                if (njt_shm_status_summary) {
                    njt_shm_status_mark_zone_delete(node->pool);
                }
#endif
            }

            if (!node->del && !node->noreuse && !node->new_create) {
                node->inited = 0;
            }

            if (node->fd > 0 && node->del) {
                njt_close_file(node->fd); // only called by njt_master_process in init_cycle()
                node->fd = NJT_INVALID_FILE; 
            }
            cur = njt_queue_next(cur);
        }
        njt_shmtx_unlock(&njt_shared_slab_header->mutex);
        return NJT_OK;
    }

    pool = (njt_slab_pool_t *)njt_slab_alloc_locked(njt_shared_slab_header, 1 * 1024 * 1024);
    if (pool == NULL) {
        goto failed;
    };

    pool->end = (u_char *) pool + zone_size;
    pool->min_shift = 3; // same as value in func njt_init_shm_pool
    pool->addr = pool;
    pool->next = NULL;
    pool->first = pool;

    if (njt_shmtx_create(&pool->mutex, &pool->lock, NULL) != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "failed to create shared slab's shmtx");
        goto failed;
    }

    njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0,
        "dyn_slab allocate dyn_amdin_zone pool: %p, size 1M", (void *) pool);
    njt_slab_init(pool);
    pool->auto_scale = 1; // auto scale for admin zone

    header = (njt_share_slab_queues_t *)njt_slab_calloc(pool, sizeof(njt_share_slab_queues_t));
    if (header == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "failed to create shared slab's queue header");
        goto failed;
    }
    njt_queue_init(&header->delete_zones);
    njt_queue_init(&header->pids);
    njt_queue_init(&header->zones);

    node = (njt_share_slab_pool_node_t *)njt_slab_calloc(pool, sizeof(njt_share_slab_pool_node_t));
    if (node == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "failed to create shared slab's first node");
        goto failed;
    }

    node->name.len = strlen(zone_name);
    node->name.data = njt_slab_calloc_locked(pool, node->name.len);
    if (node->name.data == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "failed to create shared slab's first node's name");
        goto failed;
    }

    njt_memcpy(node->name.data, zone_name, node->name.len);
    node->pool = pool;
    node->size = zone_size;
    node->tag = &njt_core_module;
    node->noreuse = 0;  // reuse
    node->del = 0;
    node->new_create = 0;
    njt_queue_insert_tail(&header->zones, &node->queue);

    cycle->shared_slab.dyn_admin_pool = pool;
    cycle->shared_slab.queues_header = header;
    njt_shared_slab_queue_header = header;
    njt_cycle->shared_slab.queues_header = header;
    njt_shared_admin_slab_header = node->pool;

    njt_shmtx_unlock(&njt_shared_slab_header->mutex);
    return NJT_OK;

failed:
    njt_shmtx_unlock(&njt_shared_slab_header->mutex);
    return NJT_ERROR;
}


njt_int_t
njt_share_slab_pre_alloc_locked(njt_cycle_t *cycle)
{
    njt_queue_t                 *head, *cur;
    njt_share_slab_wait_zone_t  *wait_zone;
    njt_share_slab_pool_node_t  *old_node;
    njt_slab_pool_t             *pool;

    head = &cycle->shared_slab.wait_zones;
    cur = njt_queue_next(head);

    while (cur != head) {
        wait_zone = (njt_share_slab_wait_zone_t *)njt_queue_data(cur, njt_share_slab_wait_zone_t, queue);
        old_node = njt_share_slab_get_node_locked(cycle, wait_zone->zone, NULL);
        if (old_node != NULL) {
            if (old_node->tag != wait_zone->zone->tag) {
                njt_log_error(NJT_LOG_ERR, cycle->log, 0, "same name with different tag is forbidden, zone_name %V, old tag %p,  new tag %p",
                &old_node->name, old_node->tag, wait_zone->zone->tag);
                return NJT_ERROR;
            }
            if (old_node->size != wait_zone->zone->shm.size) {
                njt_log_error(NJT_LOG_ERR, cycle->log, 0, "same name with different size is forbidden, zone_name %V, old size %ui,  new size %ui",
                &old_node->name, old_node->size, wait_zone->zone->shm.size);
                return NJT_ERROR;
            }
            if (!wait_zone->zone->noreuse) {
                *(wait_zone->shpool) = old_node->pool;
                cur = njt_queue_next(cur);
                continue;
            }
        }

        pool = njt_slab_alloc_locked(njt_shared_slab_header, wait_zone->zone->shm.size);
        if (pool == NULL) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                           "failed to alloc dyn slab pool in pre alloc, name %V, size %d",
                           &wait_zone->zone->shm.name, wait_zone->zone->shm.size);
            return NJT_ERROR;
        }

        pool->next = NULL;
        *(wait_zone->shpool) = pool;
        wait_zone->new_alloc = 1;
        cur = njt_queue_next(cur);

        cycle->shared_slab.dyn_zone_count ++;
        if (cycle->shared_slab.dyn_zone_count >= cycle->shared_slab.max_dyn_zone_count) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                "total dyn zone count exceeds the limit(%ld)",
                 cycle->shared_slab.max_dyn_zone_count);
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


njt_int_t
njt_share_slab_pre_alloc_finished(njt_cycle_t *cycle)
{
    njt_queue_t                 *head, *cur;
    njt_queue_t                 *zone_head;
    njt_share_slab_wait_zone_t  *wait_zone;
    njt_share_slab_pool_node_t  *node, *old_node;
    njt_slab_pool_t             *pool;
    njt_str_t                   *name;
    size_t                       size;
    void                        *data;

    head = &cycle->shared_slab.wait_zones;
    zone_head = &cycle->shared_slab.queues_header->zones;
    cur = njt_queue_next(head);

    while (cur != head) {
        wait_zone = (njt_share_slab_wait_zone_t *)njt_queue_data(cur, njt_share_slab_wait_zone_t, queue);

        pool = *(wait_zone->shpool);
        name = &wait_zone->zone->shm.name;
        size = wait_zone->zone->shm.size;

        pool->end = (u_char *) pool + size;
        pool->min_shift = 3; // same as value in njt_init_shm_pool()
        pool->addr = pool;
        pool->next = NULL;
        pool->first = pool;

        if (njt_shmtx_create(&pool->mutex, &pool->lock, NULL) != NJT_OK) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "failed to create shared slab's shmtx");
            return NJT_ERROR;
        }

        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0,
            "dyn_slab add allocate new slab pool: %p, size %d", (void *) pool, size);
        njt_slab_init(pool);

        node = njt_slab_alloc_locked(njt_shared_admin_slab_header, sizeof(njt_share_slab_pool_node_t));
        if (node == NULL) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "failed to alloc dyn slab node");
            njt_slab_free_locked(njt_shared_slab_header, pool);
            return NJT_ERROR;
        }

        node->name.data = njt_slab_calloc_locked(njt_shared_admin_slab_header, name->len);
        if (node->name.data == NULL) {
            njt_slab_free_locked(njt_shared_slab_header, node);
            njt_slab_free_locked(njt_shared_slab_header, pool);
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "failed to alloc dyn slab node name");
            return NJT_ERROR;
        }

        wait_zone->zone->shm.addr = (u_char *)pool;
        old_node = njt_share_slab_get_old_node_locked(cycle, wait_zone->zone, pool);

        node->name.len = name->len;
        njt_memcpy(node->name.data, name->data, name->len);
        node->pool = pool;
        node->size = size;
        node->tag = wait_zone->zone->tag;
        node->noreuse = wait_zone->zone->noreuse;
        node->del = 0;
        node->post = 1;
        node->new_create = 1;
        node->ref_cnt = 1;
        node->pid_max = 0;
        node->pid_min = INT32_MAX;
        node->del_queue.prev = NULL;
        node->del_queue.next = NULL;
        njt_queue_insert_tail(zone_head, &node->queue);
        // only called in master cycle, no need to update pid

        if (wait_zone->zone->merge && wait_zone->zone->noreuse) {
            node->merge = 1;
            if (old_node != NULL) {
                wait_zone->zone->merge(wait_zone->zone, old_node->pool);
                old_node->merged = 1;
            }
        }

        if(wait_zone->zone->init != NULL) {
            data = NULL;
            if (!wait_zone->zone->noreuse && old_node != NULL) {
                data = old_node->pool;
            }

            if (wait_zone->zone->init(wait_zone->zone, data) != NJT_OK) {
                njt_log_error(NJT_LOG_ERR, cycle->log, 0,
                    "dyn slab: get pool failed to init new created node '%V'",
                    &wait_zone->zone->shm.name);
                return NJT_ERROR;
            }

            if (old_node != NULL) {
                old_node->inited = 1;
            }
        }

        njt_share_slab_open_hidden_pool_file(cycle, node);
        cur = njt_queue_next(cur);
    }

    zone_head = &cycle->shared_slab.queues_header->delete_zones;
    cur = njt_queue_next(zone_head);
    while (cur != zone_head) {
        node = (njt_share_slab_pool_node_t *)njt_queue_data(cur, njt_share_slab_pool_node_t, del_queue);
        if (node->post) {
            node->merged = 1;
            node->inited = 1;
            njt_share_slab_close_hidden_pool_file(cycle, node);
        }
        cur = njt_queue_next(cur);
    }

    njt_destroy_pool(cycle->shared_slab.pool);
    cycle->shared_slab.pool = NULL;

    return NJT_OK;
}


void
njt_share_slab_pre_alloc_failed(njt_cycle_t *cycle)
{
    njt_queue_t                 *head, *cur, *next;
    njt_share_slab_wait_zone_t  *wait_zone;
    njt_slab_pool_t             *pool, *next_pool;

    head = &cycle->shared_slab.wait_zones;
    cur = njt_queue_next(head);

    while (cur != head) {
        wait_zone = (njt_share_slab_wait_zone_t *)njt_queue_data(cur, njt_share_slab_wait_zone_t, queue);

        pool = *(wait_zone->shpool);
        while (pool != NULL && wait_zone->new_alloc) {
            next_pool = pool->next;
            njt_slab_free_locked(njt_shared_slab_header, pool);
            cycle->shared_slab.dyn_zone_count --;
            pool = next_pool;
        }

        next = njt_queue_next(cur);
        cur = next;
    }

    njt_destroy_pool(cycle->shared_slab.pool);
    cycle->shared_slab.pool = NULL;
}


njt_int_t
njt_share_slab_pre_alloc(njt_cycle_t *cycle)
{
    if (njt_queue_empty(&cycle->shared_slab.wait_zones)) {
        return NJT_OK;
    }

    if (cycle->shared_slab.header == NULL) {
        return NJT_ERROR;
    }

    njt_shmtx_lock(&njt_shared_slab_header->mutex);
    njt_share_slab_try_free_pools_locked(cycle);
    if (njt_share_slab_pre_alloc_locked(cycle) == NJT_OK) {
        if (njt_share_slab_pre_alloc_finished(cycle) != NJT_OK){
            njt_share_slab_pre_alloc_failed(cycle);
            njt_shmtx_unlock(&njt_shared_slab_header->mutex);
            return NJT_ERROR;
        };
    } else {
        njt_share_slab_pre_alloc_failed(cycle);
        njt_shmtx_unlock(&njt_shared_slab_header->mutex);
        return NJT_ERROR;
    }
    njt_shmtx_unlock(&njt_shared_slab_header->mutex);

    return NJT_OK;
}


njt_uint_t
njt_share_slab_is_hidden_file_opened_locked(njt_cycle_t *cycle, njt_share_slab_pool_node_t *node)
{
    DIR                    *dir, *dir_fd;
    struct dirent          *fd_entry;
    static char             path[PATH_MAX+1], fd_path[PATH_MAX+PATH_MAX+1], real_path[PATH_MAX+1], abs_path[PATH_MAX+1];
    njt_uint_t              found = 0; 
    ssize_t                 len, real_len;
    njt_queue_t            *head, *cur, *next;
    njt_share_slab_pid_t   *pnode;
    u_char                 *p;
    
    p = njt_sprintf((u_char *)path, "%V", &cycle->prefix);
    if (*(p-1) != '/') {
        *p++ = '/';
    }
    njt_sprintf(p, "%s/.%p", "data/.dyn_slab", node->pool);

    njt_memzero(abs_path, PATH_MAX+1);
    p = (u_char *)realpath(path, abs_path); //example: abs_path /usr/local/njet/data/.dyn_slab/.00007DD040910000
    real_len = strlen(abs_path);
    // if (p == NULL) {
    //     // file already been deleted
    //     return 0;
    // }

    if (!(dir = opendir("/proc"))) {
        perror("opendir");
        return 0;
    }

    head = &cycle->shared_slab.queues_header->pids;
    cur = njt_queue_next(head);
    while (cur != head) {
        pnode = (njt_share_slab_pid_t *) njt_queue_data(cur, njt_share_slab_pid_t, queue);
        sprintf(path, "/proc/%d/fd", pnode->pid);

        if (!(dir_fd = opendir(path))) { // check pid exists
            next = njt_queue_next(cur);
            njt_queue_remove(cur);
            njt_log_error(NJT_LOG_DEBUG, cycle->log, 0, "rm pid_node %d", pnode->pid);
            cur = next; 
            continue;
        }

        while ((fd_entry = readdir(dir_fd)) != NULL) {
            sprintf(fd_path, "%s/%s", path, fd_entry->d_name);
            len = readlink(fd_path, real_path, sizeof(real_path) - 1);
            if (len != -1 && len >= real_len) {
                real_path[len] = '\0';
                if (strncmp(real_path, abs_path, real_len) == 0) {
                    found = 1;
                    break;
                }
            }
        }

        closedir(dir_fd);
        if (found) {
            break;
        }

        cur = njt_queue_next(cur);
    }

    closedir(dir);
    return found;
}


static void*
njt_slab_try_alloc(njt_slab_pool_t *pool, size_t size)
{
    if (*pool->mutex.lock == 0) { // 正常情况
        return njt_slab_alloc(pool, size);
    } 
    
    if ((njt_pid_t )(*pool->mutex.lock) == njt_pid) { // 本进程已经加锁
        return njt_slab_alloc_locked(pool, size);
    } else { // 其他进程加锁
        return njt_slab_alloc(pool, size);
    }
}


void njt_share_slab_set_auotscale(njt_slab_pool_t *pool, njt_int_t value){
    pool->auto_scale = value;
#if (NJT_SHM_STATUS)
    if (pool->status_rec) {
        njt_shm_status_mark_zone_autoscale(pool);
    }
#endif
}


void*
njt_share_slab_get_pool_by_name(njt_cycle_t *cycle, njt_str_t *zone_name, njt_int_t dyn)
{
    njt_shm_zone_t              *shm_zone;
    njt_list_part_t             *part;
    njt_share_slab_pool_node_t  *node;
    njt_queue_t                 *head, *cur;
    njt_uint_t                   i;

    if (!dyn) {

        part = &cycle->shared_memory.part;
        shm_zone = part->elts;

        for (i = 0; /* void */ ; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }
                part = part->next;
                shm_zone = part->elts;
                i = 0;
            }

            if (shm_zone[i].shm.name.len != zone_name->len) {
                continue;
            }

            if (njt_strncmp(shm_zone[i].shm.name.data, zone_name->data, zone_name->len) != 0) {
                continue;
            }

            return shm_zone[i].shm.addr;
        }

        return NULL;
    }

    if (cycle->shared_slab.header == NULL) {
        return NULL;
    }

    njt_shmtx_lock(&cycle->shared_slab.header->mutex);
    head = &cycle->shared_slab.queues_header->zones;
    cur = njt_queue_next(head);
    if (njt_share_slab_is_dyn_admin(zone_name)) {
        return NULL;
    }

    while (cur != head) {
        node = (njt_share_slab_pool_node_t *)njt_queue_data(cur, njt_share_slab_pool_node_t, queue);
        if (!node->del && node->name.len == zone_name->len
            && njt_strncmp(node->name.data, zone_name->data, zone_name->len) == 0)
        {
            njt_shmtx_unlock(&cycle->shared_slab.header->mutex);
            return node->pool;
        }

        cur = njt_queue_next(cur);
    }
    njt_shmtx_unlock(&cycle->shared_slab.header->mutex);

    return NULL;
}


njt_int_t
njt_share_slab_is_dyn_admin(njt_str_t *zone_name)
{
    static njt_str_t name;

    njt_str_set(&name, "dyn_admin_zone");
    return (zone_name->len == name.len && njt_strncmp(zone_name->data, name.data, name.len) == 0);
}


njt_share_slab_pool_node_t*
njt_share_slab_get_old_node_locked(njt_cycle_t *cycle, njt_shm_zone_t *shm_zone, njt_slab_pool_t *pool)
{
    njt_queue_t                 *head, *cur;
    njt_share_slab_pool_node_t  *node;
    njt_str_t                   *zone_name;

    zone_name = &shm_zone->shm.name;
    node = NULL;

    if (shm_zone->noreuse) {
        head = &njt_shared_slab_queue_header->delete_zones;
        cur = njt_queue_prev(head);

        while(cur != head) {
            node = (njt_share_slab_pool_node_t *)njt_queue_data(cur, njt_share_slab_pool_node_t, del_queue);
            if (node->name.len == zone_name->len
                && node->tag == shm_zone->tag
                && node->size == shm_zone->shm.size
                && node->pool != pool
                && njt_strncmp(node->name.data, zone_name->data, zone_name->len) == 0)
            {
                break;
            }
            cur = njt_queue_prev(cur);
        }
    } else {
        head = &njt_shared_slab_queue_header->zones;
        cur = njt_queue_prev(head);

        while(cur != head) {
            node = (njt_share_slab_pool_node_t *)njt_queue_data(cur, njt_share_slab_pool_node_t, queue);
            if (node->name.len == zone_name->len
                && node->tag == shm_zone->tag
                && node->size == shm_zone->shm.size
                && !node->del
                && njt_strncmp(node->name.data, zone_name->data, zone_name->len) == 0)
            {
                break;
            }
            cur = njt_queue_prev(cur);
        }

    }

    if ( cur == head) {
        // njt_log_error(NJT_LOG_DEBUG, cycle->log, 0, "dyn zone '%V': can not find old zone", zone_name);
        return NULL;
    }

    return node;
}


njt_share_slab_pool_node_t*
njt_share_slab_get_node_locked(njt_cycle_t *cycle, njt_shm_zone_t *shm_zone, njt_slab_pool_t *pool)
{
    njt_queue_t                 *head, *cur;
    njt_share_slab_pool_node_t  *node;
    njt_str_t                   *zone_name;

    zone_name = &shm_zone->shm.name;
    node = NULL;

    head = &njt_shared_slab_queue_header->zones;
    cur = njt_queue_prev(head);

    while(cur != head) {
        node = (njt_share_slab_pool_node_t *)njt_queue_data(cur, njt_share_slab_pool_node_t, queue);
        if (node->name.len == zone_name->len
            && !node->del
            && njt_strncmp(node->name.data, zone_name->data, zone_name->len) == 0)
        {
            break;
        }
        cur = njt_queue_prev(cur);
    }


    if ( cur == head) {
        // njt_log_error(NJT_LOG_DEBUG, cycle->log, 0, "dyn zone '%V': can not find old zone", zone_name);
        return NULL;
    }

    return node;
}
