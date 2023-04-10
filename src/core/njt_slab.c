
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_config.h>
#include <njt_core.h>


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


static njt_uint_t  njt_slab_max_size;
static njt_uint_t  njt_slab_exact_size;
static njt_uint_t  njt_slab_exact_shift;


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
}


void *
njt_slab_alloc(njt_slab_pool_t *pool, size_t size)
{
    void  *p;

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

    njt_log_debug1(NJT_LOG_DEBUG_ALLOC, njt_cycle->log, 0,
                   "slab alloc: %p", (void *) p);

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
njt_slab_free_locked(njt_slab_pool_t *pool, void *p)
{
    size_t            size;
    uintptr_t         slab, m, *bitmap;
    njt_uint_t        i, n, type, slot, shift, map;
    njt_slab_page_t  *slots, *page;

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

        return;
    }

    /* not reached */

    return;

done:

    pool->stats[slot].used--;

    njt_slab_junk(p, size);

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

    if (pool->log_nomem) {
        njt_slab_error(pool, NJT_LOG_CRIT,
                       "njt_slab_alloc() failed: no memory");
    }

    return NULL;
}


static void
njt_slab_free_pages(njt_slab_pool_t *pool, njt_slab_page_t *page,
    njt_uint_t pages)
{
    njt_slab_page_t  *prev, *join;

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
