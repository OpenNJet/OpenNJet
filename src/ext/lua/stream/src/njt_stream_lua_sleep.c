
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_sleep.c.tt2
 */


/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_stream_lua_util.h"
#include "njt_stream_lua_sleep.h"
#include "njt_stream_lua_contentby.h"


static int njt_stream_lua_njt_sleep(lua_State *L);
static void njt_stream_lua_sleep_handler(njt_event_t *ev);
static void njt_stream_lua_sleep_cleanup(void *data);
static njt_int_t njt_stream_lua_sleep_resume(njt_stream_lua_request_t *r);


static int
njt_stream_lua_njt_sleep(lua_State *L)
{
    int                          n;
    njt_int_t                    delay; /* in msec */
    njt_stream_lua_request_t    *r;

    njt_stream_lua_ctx_t                *ctx;
    njt_stream_lua_co_ctx_t             *coctx;

    n = lua_gettop(L);
    if (n != 1) {
        return luaL_error(L, "attempt to pass %d arguments, but accepted 1", n);
    }

    r = njt_stream_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    delay = (njt_int_t) (luaL_checknumber(L, 1) * 1000);

    if (delay < 0) {
        return luaL_error(L, "invalid sleep duration \"%d\"", delay);
    }

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    njt_stream_lua_check_context(L, ctx, NJT_STREAM_LUA_CONTEXT_YIELDABLE);

    coctx = ctx->cur_co_ctx;
    if (coctx == NULL) {
        return luaL_error(L, "no co ctx found");
    }

    njt_stream_lua_cleanup_pending_operation(coctx);
    coctx->cleanup = njt_stream_lua_sleep_cleanup;
    coctx->data = r;

    coctx->sleep.handler = njt_stream_lua_sleep_handler;
    coctx->sleep.data = coctx;
    coctx->sleep.log = r->connection->log;

    if (delay == 0) {
#ifdef HAVE_POSTED_DELAYED_EVENTS_PATCH
        dd("posting 0 sec sleep event to head of delayed queue");

        coctx->sleep.delayed = 1;
        njt_post_event(&coctx->sleep, &njt_posted_delayed_events);
#else
        njt_log_error(NJT_LOG_WARN, r->connection->log, 0, "njt.sleep(0)"
                      " called without delayed events patch, this will"
                      " hurt performance");
        njt_add_timer(&coctx->sleep, (njt_msec_t) delay);
#endif

    } else {
        dd("adding timer with delay %lu ms, r:%p", (unsigned long) delay, r);

        njt_add_timer(&coctx->sleep, (njt_msec_t) delay);
    }

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "lua ready to sleep for %d ms", delay);

    return lua_yield(L, 0);
}


void
njt_stream_lua_sleep_handler(njt_event_t *ev)
{
#if (NJT_DEBUG)
    njt_connection_t                *c;
#endif
    njt_stream_lua_request_t        *r;
    njt_stream_lua_ctx_t            *ctx;
    njt_stream_lua_co_ctx_t         *coctx;

    coctx = ev->data;

    r = coctx->data;

#if (NJT_DEBUG)

    c = r->connection;

#endif

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);

    if (ctx == NULL) {
        return;
    }


    coctx->cleanup = NULL;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "stream lua sleep timer expired");

    ctx->cur_co_ctx = coctx;

    if (ctx->entered_content_phase) {
        (void) njt_stream_lua_sleep_resume(r);

    } else {
        ctx->resume_handler = njt_stream_lua_sleep_resume;
        njt_stream_lua_core_run_phases(r);
    }

}


void
njt_stream_lua_inject_sleep_api(lua_State *L)
{
    lua_pushcfunction(L, njt_stream_lua_njt_sleep);
    lua_setfield(L, -2, "sleep");
}


static void
njt_stream_lua_sleep_cleanup(void *data)
{
    njt_stream_lua_co_ctx_t                *coctx = data;

    if (coctx->sleep.timer_set) {
        njt_log_debug0(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0,
                       "lua clean up the timer for pending njt.sleep");

        njt_del_timer(&coctx->sleep);
    }

#ifdef HAVE_POSTED_DELAYED_EVENTS_PATCH
    if (coctx->sleep.posted) {
        njt_log_debug0(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0,
                       "lua clean up the posted event for pending njt.sleep");

        njt_delete_posted_event(&coctx->sleep);
    }
#endif
}


static njt_int_t
njt_stream_lua_sleep_resume(njt_stream_lua_request_t *r)
{
    lua_State                           *vm;
    njt_connection_t                    *c;
    njt_int_t                            rc;
    njt_uint_t                           nreqs;
    njt_stream_lua_ctx_t                *ctx;

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        return NJT_ERROR;
    }

    ctx->resume_handler = njt_stream_lua_wev_handler;

    c = r->connection;
    vm = njt_stream_lua_get_lua_vm(r, ctx);
    nreqs = c->requests;

    rc = njt_stream_lua_run_thread(vm, r, ctx, 0);

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "lua run thread returned %d", rc);

    if (rc == NJT_AGAIN) {
        return njt_stream_lua_run_posted_threads(c, vm, r, ctx, nreqs);
    }

    if (rc == NJT_DONE) {
        njt_stream_lua_finalize_request(r, NJT_DONE);
        return njt_stream_lua_run_posted_threads(c, vm, r, ctx, nreqs);
    }

    if (ctx->entered_content_phase) {
        njt_stream_lua_finalize_request(r, rc);
        return NJT_DONE;
    }

    return rc;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
