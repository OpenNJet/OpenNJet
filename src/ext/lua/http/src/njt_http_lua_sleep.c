
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.yy
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_http_lua_util.h"
#include "njt_http_lua_sleep.h"
#include "njt_http_lua_contentby.h"


static int njt_http_lua_njt_sleep(lua_State *L);
static void njt_http_lua_sleep_handler(njt_event_t *ev);
static void njt_http_lua_sleep_cleanup(void *data);
static njt_int_t njt_http_lua_sleep_resume(njt_http_request_t *r);


static int
njt_http_lua_njt_sleep(lua_State *L)
{
    int                          n;
    njt_int_t                    delay; /* in msec */
    njt_http_request_t          *r;
    njt_http_lua_ctx_t          *ctx;
    njt_http_lua_co_ctx_t       *coctx;

    n = lua_gettop(L);
    if (n != 1) {
        return luaL_error(L, "attempt to pass %d arguments, but accepted 1", n);
    }

    r = njt_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    delay = (njt_int_t) (luaL_checknumber(L, 1) * 1000);

    if (delay < 0) {
        return luaL_error(L, "invalid sleep duration \"%d\"", delay);
    }

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    njt_http_lua_check_context(L, ctx, NJT_HTTP_LUA_CONTEXT_YIELDABLE);

    coctx = ctx->cur_co_ctx;
    if (coctx == NULL) {
        return luaL_error(L, "no co ctx found");
    }

    njt_http_lua_cleanup_pending_operation(coctx);
    coctx->cleanup = njt_http_lua_sleep_cleanup;
    coctx->data = r;

    coctx->sleep.handler = njt_http_lua_sleep_handler;
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
        dd("adding timer with delay %lu ms, r:%.*s", (unsigned long) delay,
           (int) r->uri.len, r->uri.data);

        njt_add_timer(&coctx->sleep, (njt_msec_t) delay);
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua ready to sleep for %d ms", delay);

    return lua_yield(L, 0);
}


void
njt_http_lua_sleep_handler(njt_event_t *ev)
{
    njt_connection_t        *c;
    njt_http_request_t      *r;
    njt_http_lua_ctx_t      *ctx;
    njt_http_log_ctx_t      *log_ctx;
    njt_http_lua_co_ctx_t   *coctx;

    coctx = ev->data;

    r = coctx->data;
    c = r->connection;

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);

    if (ctx == NULL) {
        return;
    }

    if (c->fd != (njt_socket_t) -1) {  /* not a fake connection */
        log_ctx = c->log->data;
        log_ctx->current_request = r;
    }

    coctx->cleanup = NULL;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "lua sleep timer expired: \"%V?%V\"", &r->uri, &r->args);

    ctx->cur_co_ctx = coctx;

    if (ctx->entered_content_phase) {
        (void) njt_http_lua_sleep_resume(r);

    } else {
        ctx->resume_handler = njt_http_lua_sleep_resume;
        njt_http_core_run_phases(r);
    }

    njt_http_run_posted_requests(c);
}


void
njt_http_lua_inject_sleep_api(lua_State *L)
{
    lua_pushcfunction(L, njt_http_lua_njt_sleep);
    lua_setfield(L, -2, "sleep");
}


static void
njt_http_lua_sleep_cleanup(void *data)
{
    njt_http_lua_co_ctx_t          *coctx = data;

    if (coctx->sleep.timer_set) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "lua clean up the timer for pending njt.sleep");

        njt_del_timer(&coctx->sleep);
    }

#ifdef HAVE_POSTED_DELAYED_EVENTS_PATCH
#if (njet_version >= 1007005)
    if (coctx->sleep.posted) {
#else
    if (coctx->sleep.prev) {
#endif
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "lua clean up the posted event for pending njt.sleep");

        /*
        * We need the extra parentheses around the argument
        * of njt_delete_posted_event() just to work around macro issues in
        * njet cores older than 1.7.5 (exclusive).
        */
        njt_delete_posted_event((&coctx->sleep));
    }
#endif
}


static njt_int_t
njt_http_lua_sleep_resume(njt_http_request_t *r)
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

    rc = njt_http_lua_run_thread(vm, r, ctx, 0);

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua run thread returned %d", rc);

    if (rc == NJT_AGAIN) {
        return njt_http_lua_run_posted_threads(c, vm, r, ctx, nreqs);
    }

    if (rc == NJT_DONE) {
        njt_http_lua_finalize_request(r, NJT_DONE);
        return njt_http_lua_run_posted_threads(c, vm, r, ctx, nreqs);
    }

    if (ctx->entered_content_phase) {
        njt_http_lua_finalize_request(r, rc);
        return NJT_DONE;
    }

    return rc;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
