
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>



static njt_inline void *njt_palloc_small(njt_pool_t *pool, size_t size,
    njt_uint_t align);
static void *njt_palloc_block(njt_pool_t *pool, size_t size);
static void *njt_palloc_large(njt_pool_t *pool, size_t size);


njt_pool_t *
njt_create_pool(size_t size, njt_log_t *log)
{
    njt_pool_t  *p;

    p = njt_memalign(NJT_POOL_ALIGNMENT, size, log);
    if (p == NULL) {
        return NULL;
    }

    p->d.last = (u_char *) p + sizeof(njt_pool_t);
    p->d.end = (u_char *) p + size;
    p->d.next = NULL;
    p->d.failed = 0;

    size = size - sizeof(njt_pool_t);
    p->max = (size < NJT_MAX_ALLOC_FROM_POOL) ? size : NJT_MAX_ALLOC_FROM_POOL;

    p->current = p;
    p->chain = NULL;
    p->large = NULL;
    p->cleanup = NULL;
    p->log = log;
    // by ChengXu
#if (NJT_DYNAMIC_POOL)
    njt_queue_init(&p->parent_pool);
    njt_queue_init(&p->sub_pools);
    p->dynamic = 0;
#endif
    //end

    return p;
}
// by ChengXu
#if (NJT_DYNAMIC_POOL)
njt_pool_t *
njt_create_dynamic_pool(size_t size, njt_log_t *log)
{
    njt_pool_t  *p;

    p = njt_memalign(NJT_POOL_ALIGNMENT, size, log);
    if (p == NULL) {
        return NULL;
    }

    p->d.last = (u_char *) p + sizeof(njt_pool_t);
    p->d.end = (u_char *) p + size;
    p->d.next = NULL;
    p->d.failed = 0;

    size = size - sizeof(njt_pool_t);
    p->max = (size < NJT_MAX_ALLOC_FROM_POOL) ? size : NJT_MAX_ALLOC_FROM_POOL;

    p->current = p;
    p->chain = NULL;
    p->large = NULL;
    p->cleanup = NULL;
    p->log = log;
    njt_queue_init(&p->parent_pool);
    njt_queue_init(&p->sub_pools);
    p->dynamic = 1;
    return p;
}
#endif
//end
// by ChengXu
#if (NJT_DYNAMIC_POOL)
njt_int_t njt_sub_pool(njt_pool_t *pool,njt_pool_t *sub){

    if (!njt_queue_empty(&sub->parent_pool)) {
        return NJT_ERROR;
    }
    njt_queue_insert_head(&pool->sub_pools,&sub->parent_pool);
    return NJT_OK;
}



static void *
njt_dynamic_alloc(njt_pool_t *pool, size_t size)
{
    void              *p;
    //njt_uint_t         n;
    njt_pool_large_t  *large;

    //njt_log_debug1(NJT_LOG_DEBUG_ALLOC,njt_cycle->log, 0,"dynamic_alloc: %p,", pool);

    p = njt_alloc(size + sizeof(njt_pool_large_t),njt_cycle->log);
    if (p == NULL) {
        return NULL;
    }
//    ngx_error_signal_handler(pool);

    large = p;
    large->alloc = p;
    large->next = pool->large;
    pool->large = large;

    return (void*)(large+1);
}



#endif
// end


void
njt_destroy_pool(njt_pool_t *pool)
{
    njt_pool_t          *p, *n;
    njt_pool_large_t    *l;
    njt_pool_cleanup_t  *c;
    // by ChengXu
#if (NJT_DYNAMIC_POOL)
    njt_pool_t          *sub_pool;
    njt_queue_t         *sub_queue;
    pool->log = njt_cycle->log;
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                          "njt_destroy_pool=%p",pool);

    if (pool->parent_pool.prev != NULL && pool->parent_pool.next != NULL && !njt_queue_empty(&pool->parent_pool)){
        njt_queue_remove(&pool->parent_pool);
    }
    for (sub_queue = njt_queue_head(&pool->sub_pools);
         sub_queue != njt_queue_sentinel(&pool->sub_pools); ){
        sub_pool = njt_queue_data(sub_queue,njt_pool_t,parent_pool);
        sub_queue = njt_queue_next(sub_queue);  // 先计算偏移防止节点被删除
	sub_pool->log = pool->log;
        njt_destroy_pool(sub_pool);
    }
#endif
    // end

    for (c = pool->cleanup; c; c = c->next) {
        if (c->handler) {
            njt_log_debug1(NJT_LOG_DEBUG_ALLOC, pool->log, 0,
                           "run cleanup: %p", c);
            c->handler(c->data);
        }
    }

#if (NJT_DEBUG)

    /*
     * we could allocate the pool->log from this pool
     * so we cannot use this log while free()ing the pool
     */

    for (l = pool->large; l; l = l->next) {
        njt_log_debug1(NJT_LOG_DEBUG_ALLOC, pool->log, 0, "free: %p", l->alloc);
    }

    for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
        njt_log_debug2(NJT_LOG_DEBUG_ALLOC, pool->log, 0,
                       "free: %p, unused: %uz", p, p->d.end - p->d.last);

        if (n == NULL) {
            break;
        }
    }

#endif

    // by ChengXu
#if (NJT_DYNAMIC_POOL)
    void* data;
    for (l = pool->large; l; ) {
        data = l->alloc;
        l = l->next;
        if (data) {
            njt_free(data);
        }
    }
#else
    for (l = pool->large; l; l = l->next) {
        if (l->alloc) {
            njt_free(l->alloc);
        }
    }
#endif
    //end


    for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
        njt_free(p);

        if (n == NULL) {
            break;
        }
    }
}


void
njt_reset_pool(njt_pool_t *pool)
{
    njt_pool_t        *p;
    njt_pool_large_t  *l;

    for (l = pool->large; l; l = l->next) {
        if (l->alloc) {
            njt_free(l->alloc);
        }
    }

    for (p = pool; p; p = p->d.next) {
        p->d.last = (u_char *) p + sizeof(njt_pool_t);
        p->d.failed = 0;
    }

    pool->current = pool;
    pool->chain = NULL;
    pool->large = NULL;
}


void *
njt_palloc(njt_pool_t *pool, size_t size)
{
// by ChengXu
#if (NJT_DYNAMIC_POOL)
    if( pool->dynamic ){
        return njt_dynamic_alloc(pool,size);
    }
#endif
//end
#if !(NJT_DEBUG_PALLOC)
    if (size <= pool->max) {
        return njt_palloc_small(pool, size, 1);
    }
#endif

    return njt_palloc_large(pool, size);
}


void *
njt_pnalloc(njt_pool_t *pool, size_t size)
{
    // by ChengXu
#if (NJT_DYNAMIC_POOL)
    if( pool->dynamic ){
        return njt_dynamic_alloc(pool,size);
    }
#endif
//end
#if !(NJT_DEBUG_PALLOC)
    if (size <= pool->max) {
        return njt_palloc_small(pool, size, 0);
    }
#endif

    return njt_palloc_large(pool, size);
}


static njt_inline void *
njt_palloc_small(njt_pool_t *pool, size_t size, njt_uint_t align)
{
    u_char      *m;
    njt_pool_t  *p;

    p = pool->current;

    do {
        m = p->d.last;

        if (align) {
            m = njt_align_ptr(m, NJT_ALIGNMENT);
        }

        if ((size_t) (p->d.end - m) >= size) {
            p->d.last = m + size;

            return m;
        }

        p = p->d.next;

    } while (p);

    return njt_palloc_block(pool, size);
}


static void *
njt_palloc_block(njt_pool_t *pool, size_t size)
{
    u_char      *m;
    size_t       psize;
    njt_pool_t  *p, *new;

    psize = (size_t) (pool->d.end - (u_char *) pool);

    m = njt_memalign(NJT_POOL_ALIGNMENT, psize, pool->log);
    if (m == NULL) {
        return NULL;
    }

    new = (njt_pool_t *) m;

    new->d.end = m + psize;
    new->d.next = NULL;
    new->d.failed = 0;

    m += sizeof(njt_pool_data_t);
    m = njt_align_ptr(m, NJT_ALIGNMENT);
    new->d.last = m + size;

    for (p = pool->current; p->d.next; p = p->d.next) {
        if (p->d.failed++ > 4) {
            pool->current = p->d.next;
        }
    }

    p->d.next = new;

    return m;
}


static void *
njt_palloc_large(njt_pool_t *pool, size_t size)
{
    void              *p;
    njt_uint_t         n;
    njt_pool_large_t  *large;

    p = njt_alloc(size, pool->log);
    if (p == NULL) {
        return NULL;
    }

    n = 0;

    for (large = pool->large; large; large = large->next) {
        if (large->alloc == NULL) {
            large->alloc = p;
            return p;
        }

        if (n++ > 3) {
            break;
        }
    }

    large = njt_palloc_small(pool, sizeof(njt_pool_large_t), 1);
    if (large == NULL) {
        njt_free(p);
        return NULL;
    }

    large->alloc = p;
    large->next = pool->large;
    pool->large = large;

    return p;
}


void *
njt_pmemalign(njt_pool_t *pool, size_t size, size_t alignment)
{
    void              *p;
    njt_pool_large_t  *large;

    p = njt_memalign(alignment, size, pool->log);
    if (p == NULL) {
        return NULL;
    }

    large = njt_palloc_small(pool, sizeof(njt_pool_large_t), 1);
    if (large == NULL) {
        njt_free(p);
        return NULL;
    }

    large->alloc = p;
    large->next = pool->large;
    pool->large = large;

    return p;
}
#if (NJT_DYNAMIC_POOL)
njt_int_t
njt_pfree(njt_pool_t *pool, void *p)
{
    njt_pool_large_t  **l; 
    pool->log = njt_cycle->log;
    for (l = &pool->large; *l; ) {
        // by ChengXu

        if (pool->dynamic){
            void *fp = (*l)->alloc;
            void* data = ((njt_pool_large_t*)p)-1;
            if (data == fp) {
                njt_log_debug1(NJT_LOG_DEBUG_ALLOC, pool->log, 0,
                               "free: %p", (*l)->alloc);
                *l = (*l)->next;
                njt_free(fp);
                return NJT_OK;
            }

        }else{
            if (p == (*l)->alloc) {
                njt_log_debug1(NJT_LOG_DEBUG_ALLOC, pool->log, 0,
                               "free: %p", (*l)->alloc);
                njt_free((*l)->alloc);
                (*l)->alloc = NULL;
                return NJT_OK;
            }
        }
        l = &(*l)->next;
    }
    njt_log_debug1(NJT_LOG_DEBUG_ALLOC, pool->log, 0,
                   "free error: %p", p);
    return NJT_DECLINED;
}

#else

njt_int_t
njt_pfree(njt_pool_t *pool, void *p)
{
    njt_pool_large_t  *l;
    for (l = pool->large; l; ) {
        if (p == l->alloc) {
            njt_log_debug1(NJT_LOG_DEBUG_ALLOC, pool->log, 0,
                           "free: %p", l->alloc);
            njt_free(l->alloc);
            l->alloc = NULL;

            return NJT_OK;
        }
    }

    return NJT_DECLINED;
}
#endif
//end

void *
njt_pcalloc(njt_pool_t *pool, size_t size)
{
    void *p;

    p = njt_palloc(pool, size);
    if (p) {
        njt_memzero(p, size);
    }

    return p;
}


njt_pool_cleanup_t *
njt_pool_cleanup_add(njt_pool_t *p, size_t size)
{
    njt_pool_cleanup_t  *c;

    c = njt_palloc(p, sizeof(njt_pool_cleanup_t));
    if (c == NULL) {
        return NULL;
    }

    if (size) {
        c->data = njt_palloc(p, size);
        if (c->data == NULL) {
            return NULL;
        }

    } else {
        c->data = NULL;
    }

    c->handler = NULL;
    c->next = p->cleanup;

    p->cleanup = c;

    njt_log_debug1(NJT_LOG_DEBUG_ALLOC, p->log, 0, "add cleanup: %p", c);

    return c;
}
/// @brief  尾部添加。 by zyg
/// @param p 
/// @param size 
/// @return 
njt_pool_cleanup_t *
njt_pool_cleanup_add_tail(njt_pool_t *p, size_t size)
{
    njt_pool_cleanup_t  *c;
    njt_pool_cleanup_t   **cln;
    c = njt_palloc(p, sizeof(njt_pool_cleanup_t));
    if (c == NULL) {
        return NULL;
    }

    if (size) {
        c->data = njt_palloc(p, size);
        if (c->data == NULL) {
            return NULL;
        }

    } else {
        c->data = NULL;
    }

    c->handler = NULL;
    c->next = NULL;
    cln = &p->cleanup;
    while (*cln != NULL){
            cln = &(*cln)->next;
    }
    *cln = c;
    njt_log_debug1(NJT_LOG_DEBUG_ALLOC, p->log, 0, "add tail cleanup: %p", c);

    return c;
}


void
njt_pool_run_cleanup_file(njt_pool_t *p, njt_fd_t fd)
{
    njt_pool_cleanup_t       *c;
    njt_pool_cleanup_file_t  *cf;

    for (c = p->cleanup; c; c = c->next) {
        if (c->handler == njt_pool_cleanup_file) {

            cf = c->data;

            if (cf->fd == fd) {
                c->handler(cf);
                c->handler = NULL;
                return;
            }
        }
    }
}


void
njt_pool_cleanup_file(void *data)
{
    njt_pool_cleanup_file_t  *c = data;

    njt_log_debug1(NJT_LOG_DEBUG_ALLOC, c->log, 0, "file cleanup: fd:%d",
                   c->fd);

    if (njt_close_file(c->fd) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_ALERT, c->log, njt_errno,
                      njt_close_file_n " \"%s\" failed", c->name);
    }
}


void
njt_pool_delete_file(void *data)
{
    njt_pool_cleanup_file_t  *c = data;

    njt_err_t  err;

    njt_log_debug2(NJT_LOG_DEBUG_ALLOC, c->log, 0, "file cleanup: fd:%d %s",
                   c->fd, c->name);

    if (njt_delete_file(c->name) == NJT_FILE_ERROR) {
        err = njt_errno;

        if (err != NJT_ENOENT) {
            njt_log_error(NJT_LOG_CRIT, c->log, err,
                          njt_delete_file_n " \"%s\" failed", c->name);
        }
    }

    if (njt_close_file(c->fd) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_ALERT, c->log, njt_errno,
                      njt_close_file_n " \"%s\" failed", c->name);
    }
}


#if 0

static void *
njt_get_cached_block(size_t size)
{
    void                     *p;
    njt_cached_block_slot_t  *slot;

    if (njt_cycle->cache == NULL) {
        return NULL;
    }

    slot = &njt_cycle->cache[(size + njt_pagesize - 1) / njt_pagesize];

    slot->tries++;

    if (slot->number) {
        p = slot->block;
        slot->block = slot->block->next;
        slot->number--;
        return p;
    }

    return NULL;
}

#endif
