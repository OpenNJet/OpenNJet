
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.yy
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_http_lua_timer.h"
#include "njt_http_lua_util.h"
#include "njt_http_lua_contentby.h"
#include "njt_http_lua_probe.h"


#define NJT_HTTP_LUA_TIMER_ERRBUF_SIZE  128


typedef struct {
    void        **main_conf;
    void        **srv_conf;
    void        **loc_conf;

    lua_State    *co;

    njt_pool_t   *pool;

    njt_listening_t                   *listening;
    njt_str_t                          client_addr_text;

    njt_http_lua_main_conf_t          *lmcf;
    njt_http_lua_vm_state_t           *vm_state;

    int           co_ref;
    unsigned      delay:31;
    unsigned      premature:1;
} njt_http_lua_timer_ctx_t;


static int njt_http_lua_njt_timer_at(lua_State *L);
static int njt_http_lua_njt_timer_every(lua_State *L);
static int njt_http_lua_njt_timer_helper(lua_State *L, int every);
static int njt_http_lua_njt_timer_running_count(lua_State *L);
static int njt_http_lua_njt_timer_pending_count(lua_State *L);
static njt_int_t njt_http_lua_timer_copy(njt_http_lua_timer_ctx_t *old_tctx);
static void njt_http_lua_timer_handler(njt_event_t *ev);
static u_char *njt_http_lua_log_timer_error(njt_log_t *log, u_char *buf,
    size_t len);
static void njt_http_lua_abort_pending_timers(njt_event_t *ev);


void
njt_http_lua_inject_timer_api(lua_State *L)
{
    lua_createtable(L, 0 /* narr */, 4 /* nrec */);    /* njt.timer. */

    lua_pushcfunction(L, njt_http_lua_njt_timer_at);
    lua_setfield(L, -2, "at");

    lua_pushcfunction(L, njt_http_lua_njt_timer_every);
    lua_setfield(L, -2, "every");

    lua_pushcfunction(L, njt_http_lua_njt_timer_running_count);
    lua_setfield(L, -2, "running_count");

    lua_pushcfunction(L, njt_http_lua_njt_timer_pending_count);
    lua_setfield(L, -2, "pending_count");

    lua_setfield(L, -2, "timer");
}


static int
njt_http_lua_njt_timer_running_count(lua_State *L)
{
    njt_http_request_t          *r;
    njt_http_lua_main_conf_t    *lmcf;

    r = njt_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request");
    }

    lmcf = njt_http_get_module_main_conf(r, njt_http_lua_module);

    lua_pushnumber(L, lmcf->running_timers);

    return 1;
}


static int
njt_http_lua_njt_timer_pending_count(lua_State *L)
{
    njt_http_request_t          *r;
    njt_http_lua_main_conf_t    *lmcf;

    r = njt_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request");
    }

    lmcf = njt_http_get_module_main_conf(r, njt_http_lua_module);

    lua_pushnumber(L, lmcf->pending_timers);

    return 1;
}


static int
njt_http_lua_njt_timer_at(lua_State *L)
{
    return njt_http_lua_njt_timer_helper(L, 0);
}


/*
 * TODO: return a timer handler instead which can be passed to
 * the njt.timer.cancel method to cancel the timer.
 */
static int
njt_http_lua_njt_timer_every(lua_State *L)
{
    return njt_http_lua_njt_timer_helper(L, 1);
}


static int
njt_http_lua_njt_timer_helper(lua_State *L, int every)
{
    int                      nargs;
    int                      co_ref;
    u_char                  *p;
    lua_State               *vm;  /* the main thread */
    lua_State               *co;
    njt_msec_t               delay;
    njt_event_t             *ev = NULL;
    njt_http_request_t      *r;
    njt_connection_t        *saved_c = NULL;
    njt_http_lua_ctx_t      *ctx;
#if 0
    njt_http_connection_t   *hc;
#endif

    njt_http_lua_timer_ctx_t      *tctx = NULL;
    njt_http_lua_main_conf_t      *lmcf;
#if 0
    njt_http_core_main_conf_t     *cmcf;
#endif

    nargs = lua_gettop(L);
    if (nargs < 2) {
        return luaL_error(L, "expecting at least 2 arguments but got %d",
                          nargs);
    }

    delay = (njt_msec_t) (luaL_checknumber(L, 1) * 1000);

    if (every && delay == 0) {
        return luaL_error(L, "delay cannot be zero");
    }

    luaL_argcheck(L, lua_isfunction(L, 2) && !lua_iscfunction(L, 2), 2,
                  "Lua function expected");

    r = njt_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request");
    }

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
    njt_http_lua_assert(ctx != NULL);

    /*
     * Since njet has been confirmed that all timers have been cleaned up when
     * exit worker is executed, all timers will no longer be executed in exit
     * worker phase.
     * Reference https://github.com/njet/njet/blob/f02e2a734ef472f0dcf83ab2
     * e8ce96d1acead8a5/src/os/unix/njt_process_cycle.c#L715
     */
    njt_http_lua_check_context(L, ctx, ~NJT_HTTP_LUA_CONTEXT_EXIT_WORKER);

    if (njt_exiting && delay > 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "process exiting");
        return 2;
    }

    lmcf = njt_http_get_module_main_conf(r, njt_http_lua_module);

    if (lmcf->pending_timers >= lmcf->max_pending_timers) {
        lua_pushnil(L);
        lua_pushliteral(L, "too many pending timers");
        return 2;
    }

    if (lmcf->watcher == NULL) {
        /* create the watcher fake connection */

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "lua creating fake watcher connection");

        if (njt_cycle->files) {
            saved_c = njt_cycle->files[0];
        }

        lmcf->watcher = njt_get_connection(0, njt_cycle->log);

        if (njt_cycle->files) {
            njt_cycle->files[0] = saved_c;
        }

        if (lmcf->watcher == NULL) {
            return luaL_error(L, "no memory");
        }

        /* to work around the -1 check in njt_worker_process_cycle: */
        lmcf->watcher->fd = (njt_socket_t) -2;

        lmcf->watcher->idle = 1;
        lmcf->watcher->read->handler = njt_http_lua_abort_pending_timers;
        lmcf->watcher->data = lmcf;
    }

    vm = njt_http_lua_get_lua_vm(r, ctx);

    co_ref = njt_http_lua_new_cached_thread(vm, &co, lmcf, 1);

    /* vm stack: coroutines thread */

    /* L stack: time func [args] */

    njt_http_lua_probe_user_coroutine_create(r, L, co);

    /* co stack: <empty> */

    dd("stack top: %d", lua_gettop(L));

    lua_xmove(vm, L, 1);    /* move coroutine from main thread to L */

    lua_pop(vm, 1);  /* pop coroutines */

    /* L stack: time func [args] thread */
    /* vm stack: empty */

    lua_pushvalue(L, 2);    /* copy entry function to top of L*/

    /* L stack: time func [args] thread func */

    lua_xmove(L, co, 1);    /* move entry function from L to co */

    /* L stack: time func [args] thread */
    /* co stack: func */

#ifndef OPENRESTY_LUAJIT
    njt_http_lua_get_globals_table(co);
    lua_setfenv(co, -2);
#endif

    /* co stack: func */

    /* L stack: time func [args] thread */

    if (nargs > 2) {
        lua_pop(L, 1);  /* L stack: time func [args] */
        lua_xmove(L, co, nargs - 2);  /* L stack: time func */

        /* co stack: func [args] */
    }

    p = njt_alloc(sizeof(njt_event_t) + sizeof(njt_http_lua_timer_ctx_t),
                  r->connection->log);
    if (p == NULL) {
        goto nomem;
    }

    ev = (njt_event_t *) p;

    njt_memzero(ev, sizeof(njt_event_t));

    p += sizeof(njt_event_t);

    tctx = (njt_http_lua_timer_ctx_t *) p;

    tctx->delay = every ? delay : 0;

    tctx->premature = 0;
    tctx->co_ref = co_ref;
    tctx->co = co;
    tctx->main_conf = r->main_conf;
    tctx->srv_conf = r->srv_conf;
    tctx->loc_conf = r->loc_conf;
    tctx->lmcf = lmcf;

    tctx->pool = njt_create_pool(128, njt_cycle->log);
    if (tctx->pool == NULL) {
        goto nomem;
    }

    if (r->connection) {
        tctx->listening = r->connection->listening;

    } else {
        tctx->listening = NULL;
    }

    if (r->connection->addr_text.len) {
        tctx->client_addr_text.data = njt_palloc(tctx->pool,
                                                 r->connection->addr_text.len);
        if (tctx->client_addr_text.data == NULL) {
            goto nomem;
        }

        njt_memcpy(tctx->client_addr_text.data, r->connection->addr_text.data,
                   r->connection->addr_text.len);
        tctx->client_addr_text.len = r->connection->addr_text.len;

    } else {
        tctx->client_addr_text.len = 0;
        tctx->client_addr_text.data = NULL;
    }

    if (ctx->vm_state) {
        tctx->vm_state = ctx->vm_state;
        tctx->vm_state->count++;

    } else {
        tctx->vm_state = NULL;
    }

    ev->handler = njt_http_lua_timer_handler;
    ev->data = tctx;
    ev->log = njt_cycle->log;

    lmcf->pending_timers++;

#ifdef HAVE_POSTED_DELAYED_EVENTS_PATCH
    if (delay == 0 && !njt_exiting) {
        dd("posting 0 sec sleep event to head of delayed queue");
        njt_post_event(ev, &njt_posted_delayed_events);

        lua_pushinteger(L, 1);
        return 1;
    }
#endif

    njt_add_timer(ev, delay);

    njt_log_debug3(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "created timer (co: %p delay: %M ms): sz=%d", tctx->co,
                   delay, lua_gettop(L));

    lua_pushinteger(L, 1);
    return 1;

nomem:

    if (tctx && tctx->pool) {
        njt_destroy_pool(tctx->pool);
    }

    if (ev) {
        njt_free(ev);
    }

    njt_http_lua_free_thread(r, L, co_ref, co, lmcf);

    return luaL_error(L, "no memory");
}


static njt_int_t
njt_http_lua_timer_copy(njt_http_lua_timer_ctx_t *old_tctx)
{
    int                          nargs, co_ref, i;
    u_char                      *p;
    lua_State                   *vm;  /* the main thread */
    lua_State                   *co;
    lua_State                   *L;
    njt_event_t                 *ev = NULL;
    njt_http_lua_timer_ctx_t    *tctx = NULL;
    njt_http_lua_main_conf_t    *lmcf;

    /* L stack: func [args] */
    L = old_tctx->co;

    lmcf = old_tctx->lmcf;

    vm = old_tctx->vm_state ? old_tctx->vm_state->vm : lmcf->lua;

    co_ref = njt_http_lua_new_cached_thread(vm, &co, lmcf, 1);

    /* co stack: <empty> */

    dd("stack top: %d", lua_gettop(L));

    lua_xmove(vm, L, 1);    /* move coroutine from main thread to L */

    lua_pop(vm, 1);  /* pop coroutines */

    /* L stack: func [args] thread */
    /* vm stack: empty */

    lua_pushvalue(L, 1);    /* copy entry function to top of L*/

    /* L stack: func [args] thread func */

    lua_xmove(L, co, 1);    /* move entry function from L to co */

    /* L stack: func [args] thread */
    /* co stack: func */

#ifndef OPENRESTY_LUAJIT
    njt_http_lua_get_globals_table(co);
    lua_setfenv(co, -2);
#endif

    /* co stack: func */

    lua_pop(L, 1);  /* pop thread */

    /* L stack: func [args] */

    nargs = lua_gettop(L);
    if (nargs > 1) {
        for (i = 2; i <= nargs; i++) {
            lua_pushvalue(L, i);
        }

        /* L stack: func [args] [args] */

        lua_xmove(L, co, nargs - 1);

        /* L stack: func [args] */
        /* co stack: func [args] */
    }

    p = njt_alloc(sizeof(njt_event_t) + sizeof(njt_http_lua_timer_ctx_t),
                  njt_cycle->log);
    if (p == NULL) {
        goto nomem;
    }

    ev = (njt_event_t *) p;

    njt_memzero(ev, sizeof(njt_event_t));

    p += sizeof(njt_event_t);

    tctx = (njt_http_lua_timer_ctx_t *) p;

    njt_memcpy(tctx, old_tctx, sizeof(njt_http_lua_timer_ctx_t));

    tctx->co_ref = co_ref;
    tctx->co = co;

    tctx->pool = njt_create_pool(128, njt_cycle->log);
    if (tctx->pool == NULL) {
        goto nomem;
    }

    if (tctx->client_addr_text.len) {
        tctx->client_addr_text.data = njt_palloc(tctx->pool,
                                                 tctx->client_addr_text.len);
        if (tctx->client_addr_text.data == NULL) {
            goto nomem;
        }

        njt_memcpy(tctx->client_addr_text.data, old_tctx->client_addr_text.data,
                   tctx->client_addr_text.len);
    }

    if (tctx->vm_state) {
        tctx->vm_state->count++;
    }

    ev->handler = njt_http_lua_timer_handler;
    ev->data = tctx;
    ev->log = njt_cycle->log;

    lmcf->pending_timers++;

    njt_add_timer(ev, tctx->delay);

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "created next timer (co: %p delay: %M ms)", tctx->co,
                   tctx->delay);

    return NJT_OK;

nomem:

    if (tctx && tctx->pool) {
        njt_destroy_pool(tctx->pool);
    }

    if (ev) {
        njt_free(ev);
    }

    /* L stack: func [args] */

    njt_http_lua_free_thread(NULL, L, co_ref, co, lmcf);

    return NJT_ERROR;
}


static void
njt_http_lua_timer_handler(njt_event_t *ev)
{
    int                      n;
    lua_State               *L = NULL;
    njt_int_t                rc;
    njt_connection_t        *c = NULL;
    njt_http_request_t      *r = NULL;
    njt_http_lua_ctx_t      *ctx;
    njt_pool_cleanup_t      *cln;
    njt_pool_cleanup_t      *pcln;

    njt_http_lua_timer_ctx_t         tctx;
    njt_http_lua_main_conf_t        *lmcf;
    njt_http_core_loc_conf_t        *clcf;

    lua_Debug                ar;
    u_char                  *p;
    u_char                   errbuf[NJT_HTTP_LUA_TIMER_ERRBUF_SIZE];
    const char              *source;
    const char              *errmsg;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "lua njt.timer expired");

    njt_memcpy(&tctx, ev->data, sizeof(njt_http_lua_timer_ctx_t));
    njt_free(ev);

    njt_http_lua_assert(tctx.co_ref && tctx.co);

    lmcf = tctx.lmcf;

    lmcf->pending_timers--;

    if (!njt_exiting && tctx.delay > 0) {
        rc = njt_http_lua_timer_copy(&tctx);
        if (rc != NJT_OK) {
            njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
                          "failed to create the next timer of delay %ud ms",
                          (unsigned) tctx.delay);
        }
    }

    if (lmcf->running_timers >= lmcf->max_running_timers) {
        p = njt_snprintf(errbuf, NJT_HTTP_LUA_TIMER_ERRBUF_SIZE - 1,
                         "%i lua_max_running_timers are not enough",
                         lmcf->max_running_timers);
        *p = '\0';
        errmsg = (const char *) errbuf;
        goto failed;
    }

    c = njt_http_lua_create_fake_connection(tctx.pool);
    if (c == NULL) {
        errmsg = "could not create fake connection";
        /* tctx.pool is freed in njt_http_lua_create_fake_connection */
        tctx.pool = NULL;
        goto failed;
    }

    c->log->handler = njt_http_lua_log_timer_error;
    c->log->data = c;

    c->listening = tctx.listening;
    c->addr_text = tctx.client_addr_text;

    r = njt_http_lua_create_fake_request(c);
    if (r == NULL) {
        errmsg = "could not create fake request";
        goto failed;
    }

    r->main_conf = tctx.main_conf;
    r->srv_conf = tctx.srv_conf;
    r->loc_conf = tctx.loc_conf;

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

#if (njet_version >= 1009000)
    njt_set_connection_log(r->connection, clcf->error_log);

#else
    njt_http_set_connection_log(r->connection, clcf->error_log);
#endif

    dd("lmcf: %p", lmcf);

    ctx = njt_http_lua_create_ctx(r);
    if (ctx == NULL) {
        errmsg = "could not create ctx";
        goto failed;
    }

    if (tctx.vm_state) {
        ctx->vm_state = tctx.vm_state;

        pcln = njt_pool_cleanup_add(r->pool, 0);
        if (pcln == NULL) {
            errmsg = "could not add vm cleanup";
            goto failed;
        }

        pcln->handler = njt_http_lua_cleanup_vm;
        pcln->data = tctx.vm_state;
    }

    ctx->cur_co_ctx = &ctx->entry_co_ctx;

    L = njt_http_lua_get_lua_vm(r, ctx);

    cln = njt_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        errmsg = "could not add request cleanup";
        goto failed;
    }

    cln->handler = njt_http_lua_request_cleanup_handler;
    cln->data = ctx;
    ctx->cleanup = &cln->handler;

    ctx->entered_content_phase = 1;
    ctx->context = NJT_HTTP_LUA_CONTEXT_TIMER;

    r->read_event_handler = njt_http_block_reading;

    ctx->cur_co_ctx->co_ref = tctx.co_ref;
    ctx->cur_co_ctx->co = tctx.co;
    ctx->cur_co_ctx->co_status = NJT_HTTP_LUA_CO_RUNNING;

    dd("r connection: %p, log %p", r->connection, r->connection->log);

    /*  save the request in coroutine globals table */
    njt_http_lua_set_req(tctx.co, r);

    njt_http_lua_attach_co_ctx_to_L(tctx.co, ctx->cur_co_ctx);

    lmcf->running_timers++;

    lua_pushboolean(tctx.co, tctx.premature);

    n = lua_gettop(tctx.co);
    if (n > 2) {
        lua_insert(tctx.co, 2);
    }

#ifdef NJT_LUA_USE_ASSERT
    ctx->cur_co_ctx->co_top = 1;
#endif

    rc = njt_http_lua_run_thread(L, r, ctx, n - 1);

    dd("timer lua run thread: %d", (int) rc);

    if (rc == NJT_ERROR || rc >= NJT_OK) {
        /* do nothing */

    } else if (rc == NJT_AGAIN) {
        rc = njt_http_lua_content_run_posted_threads(L, r, ctx, 0);

    } else if (rc == NJT_DONE) {
        rc = njt_http_lua_content_run_posted_threads(L, r, ctx, 1);

    } else {
        rc = NJT_OK;
    }

    njt_http_lua_finalize_request(r, rc);
    return;

failed:

    /* co stack: func [args] */
    lua_pushvalue(tctx.co, 1);
    /* co stack: func [args] func */
    lua_getinfo(tctx.co, ">Sf", &ar);

    source = ar.source;

    if (source == NULL) {
        source = "(unknown)";
    }

    njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
                  "lua failed to run timer with function defined at %s:%d: %s",
                  source, ar.linedefined, errmsg);

#if 1
    if (L == NULL) {
        if (tctx.vm_state != NULL) {
            L = tctx.vm_state->vm;
        }

        if (L == NULL) {
            L = lmcf->lua;
        }
    }
#endif

    if (L != NULL) {
        njt_http_lua_free_thread(r, L, tctx.co_ref, tctx.co, lmcf);
    }

    if (tctx.vm_state != NULL) {
        njt_http_lua_cleanup_vm(tctx.vm_state);
    }

    if (c != NULL) {
        njt_http_lua_close_fake_connection(c);

    } else if (tctx.pool) {
        njt_destroy_pool(tctx.pool);
    }
}


static u_char *
njt_http_lua_log_timer_error(njt_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;
    njt_connection_t    *c;

    if (log->action) {
        p = njt_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    c = log->data;

    dd("ctx = %p", c);

    p = njt_snprintf(buf, len, ", context: njt.timer");
    len -= p - buf;
    buf = p;

    if (c != NULL) {
        if (c->addr_text.len) {
            p = njt_snprintf(buf, len, ", client: %V", &c->addr_text);
            len -= p - buf;
            buf = p;
        }

        if (c->listening && c->listening->addr_text.len) {
            p = njt_snprintf(buf, len, ", server: %V",
                             &c->listening->addr_text);
            /* len -= p - buf; */
            buf = p;
        }
    }

    return buf;
}


static void
njt_http_lua_abort_pending_timers(njt_event_t *ev)
{
    njt_int_t                    i, n;
    njt_event_t                **events;
    njt_connection_t            *c, *saved_c = NULL;
    njt_rbtree_node_t           *cur, *prev, *next, *sentinel, *temp;
    njt_http_lua_timer_ctx_t    *tctx;
    njt_http_lua_main_conf_t    *lmcf;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "lua abort pending timers");

    c = ev->data;
    lmcf = c->data;

    dd("lua connection fd: %d", (int) c->fd);

    if (!c->close) {
        return;
    }

    c->read->closed = 1;
    c->write->closed = 1;

    /* we temporarily use a valid fd (0) to make njt_free_connection happy */

    c->fd = 0;

    if (njt_cycle->files) {
        saved_c = njt_cycle->files[0];
    }

    njt_free_connection(c);

    c->fd = (njt_socket_t) -1;

    if (njt_cycle->files) {
        njt_cycle->files[0] = saved_c;
    }

    if (lmcf->pending_timers == 0) {
        return;
    }

    /* expire pending timers immediately */

    sentinel = njt_event_timer_rbtree.sentinel;

    cur = njt_event_timer_rbtree.root;

    /* XXX njet does not guarantee the parent of root is meaningful,
     * so we temporarily override it to simplify tree traversal. */
    temp = cur->parent;
    cur->parent = NULL;

    prev = NULL;

    events = njt_pcalloc(njt_cycle->pool,
                         lmcf->pending_timers * sizeof(njt_event_t *));
    if (events == NULL) {
        return;
    }

    n = 0;

    dd("root: %p, root parent: %p, sentinel: %p", cur, cur->parent, sentinel);

    while (n < lmcf->pending_timers) {
        if  (cur == sentinel || cur == NULL) {
            njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
                          "lua pending timer counter got out of sync: %i",
                          lmcf->pending_timers);
            break;
        }

        dd("prev: %p, cur: %p, cur parent: %p, cur left: %p, cur right: %p",
           prev, cur, cur->parent, cur->left, cur->right);

        if (prev == cur->parent) {
            /* neither of the children has been accessed yet */

            next = cur->left;
            if (next == sentinel) {
                ev = (njt_event_t *)
                    ((char *) cur - offsetof(njt_event_t, timer));

                if (ev->handler == njt_http_lua_timer_handler) {
                    dd("found node: %p", cur);
                    events[n++] = ev;
                }

                next = (cur->right != sentinel) ? cur->right : cur->parent;
            }

        } else if (prev == cur->left) {
            /* just accessed the left child */

            ev = (njt_event_t *)
                ((char *) cur - offsetof(njt_event_t, timer));

            if (ev->handler == njt_http_lua_timer_handler) {
                dd("found node 2: %p", cur);
                events[n++] = ev;
            }

            next = (cur->right != sentinel) ? cur->right : cur->parent;

        } else if (prev == cur->right) {
            /* already accessed both children */
            next = cur->parent;

        } else {
            /* not reachable */
            next = NULL;
        }

        prev = cur;
        cur = next;
    }

    /* restore the old tree root's parent */
    njt_event_timer_rbtree.root->parent = temp;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                   "lua found %i pending timers to be aborted prematurely",
                   n);

    for (i = 0; i < n; i++) {
        ev = events[i];

        njt_rbtree_delete(&njt_event_timer_rbtree, &ev->timer);

#if (NJT_DEBUG)
        ev->timer.left = NULL;
        ev->timer.right = NULL;
        ev->timer.parent = NULL;
#endif

        ev->timer_set = 0;

        ev->timedout = 1;

        tctx = ev->data;
        tctx->premature = 1;

        dd("calling timer handler prematurely");
        ev->handler(ev);
    }

#if 0
    if (pending_timers) {
        njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
                      "lua pending timer counter got out of sync: %i",
                      pending_timers);
    }
#endif
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
