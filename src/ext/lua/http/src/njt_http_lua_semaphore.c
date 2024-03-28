
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) cuiweixie
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.yy
 * I hereby assign copyright in this code to the lua-njet-module project,
 * to be licensed under the same terms as the rest of the code.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_http_lua_util.h"
#include "njt_http_lua_semaphore.h"
#include "njt_http_lua_contentby.h"


njt_int_t njt_http_lua_sema_mm_init(njt_conf_t *cf,
    njt_http_lua_main_conf_t *lmcf);
void njt_http_lua_sema_mm_cleanup(void *data);
static njt_http_lua_sema_t *njt_http_lua_alloc_sema(void);
static void njt_http_lua_free_sema(njt_http_lua_sema_t *sem);
static njt_int_t njt_http_lua_sema_resume(njt_http_request_t *r);
int njt_http_lua_ffi_sema_new(njt_http_lua_sema_t **psem,
    int n, char **errmsg);
int njt_http_lua_ffi_sema_post(njt_http_lua_sema_t *sem, int n);
int njt_http_lua_ffi_sema_wait(njt_http_request_t *r,
    njt_http_lua_sema_t *sem, int wait_ms, u_char *err, size_t *errlen);
static void njt_http_lua_sema_cleanup(void *data);
static void njt_http_lua_sema_handler(njt_event_t *ev);
static void njt_http_lua_sema_timeout_handler(njt_event_t *ev);
void njt_http_lua_ffi_sema_gc(njt_http_lua_sema_t *sem);


enum {
    SEMAPHORE_WAIT_SUCC = 0,
    SEMAPHORE_WAIT_TIMEOUT = 1,
};


njt_int_t
njt_http_lua_sema_mm_init(njt_conf_t *cf, njt_http_lua_main_conf_t *lmcf)
{
    njt_http_lua_sema_mm_t *mm;

    mm = njt_palloc(cf->pool, sizeof(njt_http_lua_sema_mm_t));
    if (mm == NULL) {
        return NJT_ERROR;
    }

    lmcf->sema_mm = mm;
    mm->lmcf = lmcf;

    njt_queue_init(&mm->free_queue);
    mm->cur_epoch = 0;
    mm->total = 0;
    mm->used = 0;

    /* it's better to be 4096, but it needs some space for
     * njt_http_lua_sema_mm_block_t, one is enough, so it is 4095
     */
    mm->num_per_block = 4095;

    return NJT_OK;
}


static njt_http_lua_sema_t *
njt_http_lua_alloc_sema(void)
{
    njt_uint_t                           i, n;
    njt_queue_t                         *q;
    njt_http_lua_sema_t                 *sem, *iter;
    njt_http_lua_sema_mm_t              *mm;
    njt_http_lua_main_conf_t            *lmcf;
    njt_http_lua_sema_mm_block_t        *block;

    njt_http_lua_assert(njt_cycle && njt_cycle->conf_ctx);

    lmcf = njt_http_cycle_get_module_main_conf(njt_cycle,
                                               njt_http_lua_module);

    njt_http_lua_assert(lmcf != NULL);

    mm = lmcf->sema_mm;

    if (!njt_queue_empty(&mm->free_queue)) {
        q = njt_queue_head(&mm->free_queue);
        njt_queue_remove(q);

        sem = njt_queue_data(q, njt_http_lua_sema_t, chain);

        sem->block->used++;

        njt_memzero(&sem->sem_event, sizeof(njt_event_t));

        sem->sem_event.handler = njt_http_lua_sema_handler;
        sem->sem_event.data = sem;
        sem->sem_event.log = njt_cycle->log;

        mm->used++;

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "from head of free queue, alloc semaphore: %p", sem);

        return sem;
    }

    /* free_queue is empty */

    n = sizeof(njt_http_lua_sema_mm_block_t)
        + mm->num_per_block * sizeof(njt_http_lua_sema_t);

    dd("block size: %d, item size: %d",
       (int) sizeof(njt_http_lua_sema_mm_block_t),
       (int) sizeof(njt_http_lua_sema_t));

    block = njt_alloc(n, njt_cycle->log);
    if (block == NULL) {
        return NULL;
    }

    mm->cur_epoch++;
    mm->total += mm->num_per_block;
    mm->used++;

    block->mm = mm;
    block->epoch = mm->cur_epoch;

    sem = (njt_http_lua_sema_t *) (block + 1);
    sem->block = block;
    sem->block->used = 1;

    njt_memzero(&sem->sem_event, sizeof(njt_event_t));

    sem->sem_event.handler = njt_http_lua_sema_handler;
    sem->sem_event.data = sem;
    sem->sem_event.log = njt_cycle->log;

    for (iter = sem + 1, i = 1; i < mm->num_per_block; i++, iter++) {
        iter->block = block;
        njt_queue_insert_tail(&mm->free_queue, &iter->chain);
    }

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "new block, alloc semaphore: %p block: %p", sem, block);

    return sem;
}


void
njt_http_lua_sema_mm_cleanup(void *data)
{
    njt_uint_t                           i;
    njt_queue_t                         *q;
    njt_http_lua_sema_t                 *sem, *iter;
    njt_http_lua_sema_mm_t              *mm;
    njt_http_lua_main_conf_t            *lmcf;
    njt_http_lua_sema_mm_block_t        *block;

    lmcf = (njt_http_lua_main_conf_t *) data;
    mm = lmcf->sema_mm;

    while (!njt_queue_empty(&mm->free_queue)) {
        q = njt_queue_head(&mm->free_queue);

        sem = njt_queue_data(q, njt_http_lua_sema_t, chain);
        block = sem->block;

        njt_http_lua_assert(block != NULL);

        if (block->used == 0) {
            iter = (njt_http_lua_sema_t *) (block + 1);

            for (i = 0; i < block->mm->num_per_block; i++, iter++) {
                njt_queue_remove(&iter->chain);
            }

            dd("free sema block: %p at final", block);

            njt_free(block);

        } else {
            /* just return directly when some thing goes wrong */

            njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
                          "lua sema mm: freeing a block %p that is still "
                          " used by someone", block);

            return;
        }
    }

    dd("lua sema mm cleanup done");
}


static void
njt_http_lua_free_sema(njt_http_lua_sema_t *sem)
{
    njt_http_lua_sema_t            *iter;
    njt_uint_t                      i, mid_epoch;
    njt_http_lua_sema_mm_block_t   *block;
    njt_http_lua_sema_mm_t         *mm;

    block = sem->block;
    block->used--;

    mm = block->mm;
    mm->used--;

    mid_epoch = mm->cur_epoch - ((mm->total / mm->num_per_block) >> 1);

    if (block->epoch < mid_epoch) {
        njt_queue_insert_tail(&mm->free_queue, &sem->chain);
        njt_log_debug4(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "add to free queue tail semaphore: %p epoch: %d"
                       "mid_epoch: %d cur_epoch: %d", sem, (int) block->epoch,
                       (int) mid_epoch, (int) mm->cur_epoch);

    } else {
        njt_queue_insert_head(&mm->free_queue, &sem->chain);
        njt_log_debug4(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "add to free queue head semaphore: %p epoch: %d"
                       "mid_epoch: %d cur_epoch: %d", sem, (int) block->epoch,
                       (int) mid_epoch, (int) mm->cur_epoch);
    }

    dd("used: %d", (int) block->used);

    if (block->used == 0
        && mm->used <= (mm->total >> 1)
        && block->epoch < mid_epoch)
    {
        /* load <= 50% and it's on the older side */
        iter = (njt_http_lua_sema_t *) (block + 1);

        for (i = 0; i < mm->num_per_block; i++, iter++) {
            njt_queue_remove(&iter->chain);
        }

        mm->total -= mm->num_per_block;

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "free semaphore block: %p", block);

        njt_free(block);
    }
}


static njt_int_t
njt_http_lua_sema_resume(njt_http_request_t *r)
{
    lua_State                   *vm;
    njt_connection_t            *c;
    njt_int_t                    rc;
    njt_uint_t                   nreqs;
    njt_http_lua_ctx_t          *ctx;

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
    if (ctx == NULL) {
        return NJT_ERROR;
    }

    ctx->resume_handler = njt_http_lua_wev_handler;

    c = r->connection;
    vm = njt_http_lua_get_lua_vm(r, ctx);
    nreqs = c->requests;

    if (ctx->cur_co_ctx->sem_resume_status == SEMAPHORE_WAIT_SUCC) {
        lua_pushboolean(ctx->cur_co_ctx->co, 1);
        lua_pushnil(ctx->cur_co_ctx->co);

    } else {
        lua_pushboolean(ctx->cur_co_ctx->co, 0);
        lua_pushliteral(ctx->cur_co_ctx->co, "timeout");
    }

    rc = njt_http_lua_run_thread(vm, r, ctx, 2);

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua run thread returned %d", rc);

    if (rc == NJT_AGAIN) {
        return njt_http_lua_run_posted_threads(c, vm, r, ctx, nreqs);
    }

    if (rc == NJT_DONE) {
        njt_http_lua_finalize_request(r, NJT_DONE);
        return njt_http_lua_run_posted_threads(c, vm, r, ctx, nreqs);
    }

    /* rc == NJT_ERROR || rc >= NJT_OK */

    if (ctx->entered_content_phase) {
        njt_http_lua_finalize_request(r, rc);
        return NJT_DONE;
    }

    return rc;
}


int
njt_http_lua_ffi_sema_new(njt_http_lua_sema_t **psem,
    int n, char **errmsg)
{
    njt_http_lua_sema_t    *sem;

    sem = njt_http_lua_alloc_sema();
    if (sem == NULL) {
        *errmsg = "no memory";
        return NJT_ERROR;
    }

    njt_queue_init(&sem->wait_queue);

    sem->resource_count = n;
    sem->wait_count = 0;
    *psem = sem;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "http lua semaphore new: %p, resources: %d",
                   sem, sem->resource_count);

    return NJT_OK;
}


int
njt_http_lua_ffi_sema_post(njt_http_lua_sema_t *sem, int n)
{
    njt_log_debug3(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "http lua semaphore post: %p, n: %d, resources: %d",
                   sem, n, sem->resource_count);

    sem->resource_count += n;

    if (!njt_queue_empty(&sem->wait_queue)) {
        /* we need the extra parentheses around the first argument of
         * njt_post_event() just to work around macro issues in njet
         * cores older than njet 1.7.12 (exclusive).
         */
        njt_post_event((&sem->sem_event), &njt_posted_events);
    }

    return NJT_OK;
}


int
njt_http_lua_ffi_sema_wait(njt_http_request_t *r,
    njt_http_lua_sema_t *sem, int wait_ms, u_char *err, size_t *errlen)
{
    njt_http_lua_ctx_t           *ctx;
    njt_http_lua_co_ctx_t        *wait_co_ctx;
    njt_int_t                     rc;

    njt_log_debug4(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "http lua semaphore wait: %p, timeout: %d, "
                   "resources: %d, event posted: %d",
                   sem, wait_ms, sem->resource_count,
#if (njet_version >= 1007005)
                   (int) sem->sem_event.posted
#else
                   sem->sem_event.prev ? 1 : 0
#endif
                   );

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
    if (ctx == NULL) {
        *errlen = njt_snprintf(err, *errlen, "no request ctx found") - err;
        return NJT_ERROR;
    }

    rc = njt_http_lua_ffi_check_context(ctx, NJT_HTTP_LUA_CONTEXT_YIELDABLE,
                                        err, errlen);

    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    /* we keep the order, will first resume the thread waiting for the
     * longest time in njt_http_lua_sema_handler
     */

    if (njt_queue_empty(&sem->wait_queue) && sem->resource_count > 0) {
        sem->resource_count--;
        return NJT_OK;
    }

    if (wait_ms == 0) {
        return NJT_DECLINED;
    }

    sem->wait_count++;
    wait_co_ctx = ctx->cur_co_ctx;

    wait_co_ctx->sleep.handler = njt_http_lua_sema_timeout_handler;
    wait_co_ctx->sleep.data = ctx->cur_co_ctx;
    wait_co_ctx->sleep.log = r->connection->log;

    njt_add_timer(&wait_co_ctx->sleep, (njt_msec_t) wait_ms);

    dd("njt_http_lua_ffi_sema_wait add timer coctx:%p wait: %d(ms)",
       wait_co_ctx, wait_ms);

    njt_queue_insert_tail(&sem->wait_queue, &wait_co_ctx->sem_wait_queue);

    wait_co_ctx->data = sem;
    wait_co_ctx->cleanup = njt_http_lua_sema_cleanup;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "http lua semaphore wait yielding");

    return NJT_AGAIN;
}


int
njt_http_lua_ffi_sema_count(njt_http_lua_sema_t *sem)
{
    return sem->resource_count - sem->wait_count;
}


static void
njt_http_lua_sema_cleanup(void *data)
{
    njt_http_lua_co_ctx_t          *coctx = data;
    njt_queue_t                    *q;
    njt_http_lua_sema_t            *sem;

    sem = coctx->data;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "http lua semaphore cleanup");

    if (coctx->sleep.timer_set) {
        njt_del_timer(&coctx->sleep);
    }

    q = &coctx->sem_wait_queue;

    njt_queue_remove(q);
    sem->wait_count--;
    coctx->cleanup = NULL;
}


static void
njt_http_lua_sema_handler(njt_event_t *ev)
{
    njt_http_lua_sema_t         *sem;
    njt_http_request_t          *r;
    njt_http_lua_ctx_t          *ctx;
    njt_http_lua_co_ctx_t       *wait_co_ctx;
    njt_connection_t            *c;
    njt_queue_t                 *q;

    sem = ev->data;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "semaphore handler: wait queue: %sempty, resource count: %d",
                   njt_queue_empty(&sem->wait_queue) ? "" : "not ",
                   sem->resource_count);
    while (!njt_queue_empty(&sem->wait_queue) && sem->resource_count > 0) {
        q = njt_queue_head(&sem->wait_queue);
        njt_queue_remove(q);

        sem->wait_count--;

        wait_co_ctx = njt_queue_data(q, njt_http_lua_co_ctx_t, sem_wait_queue);
        wait_co_ctx->cleanup = NULL;

        if (wait_co_ctx->sleep.timer_set) {
            njt_del_timer(&wait_co_ctx->sleep);
        }

        r = njt_http_lua_get_req(wait_co_ctx->co);
        c = r->connection;

        ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
        njt_http_lua_assert(ctx != NULL);

        sem->resource_count--;

        ctx->cur_co_ctx = wait_co_ctx;

        wait_co_ctx->sem_resume_status = SEMAPHORE_WAIT_SUCC;

        if (ctx->entered_content_phase) {
            (void) njt_http_lua_sema_resume(r);

        } else {
            ctx->resume_handler = njt_http_lua_sema_resume;
            njt_http_core_run_phases(r);
        }

        njt_http_run_posted_requests(c);
    }
}


static void
njt_http_lua_sema_timeout_handler(njt_event_t *ev)
{
    njt_http_lua_co_ctx_t       *wait_co_ctx;
    njt_http_request_t          *r;
    njt_http_lua_ctx_t          *ctx;
    njt_connection_t            *c;
    njt_http_lua_sema_t         *sem;

    wait_co_ctx = ev->data;
    wait_co_ctx->cleanup = NULL;

    dd("njt_http_lua_sema_timeout_handler timeout coctx:%p", wait_co_ctx);

    sem = wait_co_ctx->data;

    njt_queue_remove(&wait_co_ctx->sem_wait_queue);
    sem->wait_count--;

    r = njt_http_lua_get_req(wait_co_ctx->co);
    c = r->connection;

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
    njt_http_lua_assert(ctx != NULL);

    ctx->cur_co_ctx = wait_co_ctx;

    wait_co_ctx->sem_resume_status = SEMAPHORE_WAIT_TIMEOUT;

    if (ctx->entered_content_phase) {
        (void) njt_http_lua_sema_resume(r);

    } else {
        ctx->resume_handler = njt_http_lua_sema_resume;
        njt_http_core_run_phases(r);
    }

    njt_http_run_posted_requests(c);
}


void
njt_http_lua_ffi_sema_gc(njt_http_lua_sema_t *sem)
{
    njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "in lua gc, semaphore %p", sem);

    if (sem == NULL) {
        return;
    }

    if (!njt_terminate
        && !njt_quit
        && !njt_queue_empty(&sem->wait_queue))
    {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                      "in lua semaphore gc wait queue is"
                      " not empty while the semaphore %p is being "
                      "destroyed", sem);
    }

    if (sem->sem_event.posted) {
        njt_delete_posted_event(&sem->sem_event);
    }

    njt_http_lua_free_sema(sem);
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
