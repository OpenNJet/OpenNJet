
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_http_lua_coroutine.h"
#include "njt_http_lua_util.h"
#include "njt_http_lua_probe.h"


/*
 * Design:
 *
 * In order to support using njt.* API in Lua coroutines, we have to create
 * new coroutine in the main coroutine instead of the calling coroutine
 */


static int njt_http_lua_coroutine_create(lua_State *L);
static int njt_http_lua_coroutine_wrap(lua_State *L);
static int njt_http_lua_coroutine_resume(lua_State *L);
static int njt_http_lua_coroutine_yield(lua_State *L);
static int njt_http_lua_coroutine_status(lua_State *L);


static const njt_str_t
    njt_http_lua_co_status_names[] =
    {
        njt_string("running"),
        njt_string("suspended"),
        njt_string("normal"),
        njt_string("dead"),
        njt_string("zombie")
    };



static int
njt_http_lua_coroutine_create(lua_State *L)
{
    njt_http_request_t          *r;
    njt_http_lua_ctx_t          *ctx;

    r = njt_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    return njt_http_lua_coroutine_create_helper(L, r, ctx, NULL, NULL);
}


static int
njt_http_lua_coroutine_wrap_runner(lua_State *L)
{
    /* retrieve closure and insert it at the bottom of
     * the stack for coroutine.resume() */
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_insert(L, 1);

    return njt_http_lua_coroutine_resume(L);
}


static int
njt_http_lua_coroutine_wrap(lua_State *L)
{
    njt_http_request_t          *r;
    njt_http_lua_ctx_t          *ctx;
    njt_http_lua_co_ctx_t       *coctx = NULL;

    r = njt_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    njt_http_lua_coroutine_create_helper(L, r, ctx, &coctx, NULL);

    coctx->is_wrap = 1;

    lua_pushcclosure(L, njt_http_lua_coroutine_wrap_runner, 1);

    return 1;
}


int
njt_http_lua_coroutine_create_helper(lua_State *L, njt_http_request_t *r,
    njt_http_lua_ctx_t *ctx, njt_http_lua_co_ctx_t **pcoctx, int *co_ref)
{
    lua_State                     *vm;  /* the Lua VM */
    lua_State                     *co;  /* new coroutine to be created */
    njt_http_lua_co_ctx_t         *coctx; /* co ctx for the new coroutine */
    njt_http_lua_main_conf_t      *lmcf;

    luaL_argcheck(L, lua_isfunction(L, 1) && !lua_iscfunction(L, 1), 1,
                  "Lua function expected");

    njt_http_lua_check_context(L, ctx, NJT_HTTP_LUA_CONTEXT_YIELDABLE);

    vm = njt_http_lua_get_lua_vm(r, ctx);

    /* create new coroutine on root Lua state, so it always yields
     * to main Lua thread
     */
    if (co_ref == NULL) {
        co = lua_newthread(vm);

    } else {
        lmcf = njt_http_get_module_main_conf(r, njt_http_lua_module);
        *co_ref = njt_http_lua_new_cached_thread(vm, &co, lmcf, 0);
    }

    njt_http_lua_probe_user_coroutine_create(r, L, co);

    coctx = njt_http_lua_get_co_ctx(co, ctx);
    if (coctx == NULL) {
        coctx = njt_http_lua_create_co_ctx(r, ctx);
        if (coctx == NULL) {
            return luaL_error(L, "no memory");
        }

    } else {
        njt_memzero(coctx, sizeof(njt_http_lua_co_ctx_t));
        coctx->next_zombie_child_thread = &coctx->zombie_child_threads;
        coctx->co_ref = LUA_NOREF;
    }

    coctx->co = co;
    coctx->co_status = NJT_HTTP_LUA_CO_SUSPENDED;

#ifdef OPENRESTY_LUAJIT
    njt_http_lua_set_req(co, r);
    njt_http_lua_attach_co_ctx_to_L(co, coctx);
#else
    /* make new coroutine share globals of the parent coroutine.
     * NOTE: globals don't have to be separated! */
    njt_http_lua_get_globals_table(L);
    lua_xmove(L, co, 1);
    njt_http_lua_set_globals_table(co);
#endif

    lua_xmove(vm, L, 1);    /* move coroutine from main thread to L */

    if (co_ref) {
        lua_pop(vm, 1);  /* pop coroutines */
    }

    lua_pushvalue(L, 1);    /* copy entry function to top of L*/
    lua_xmove(L, co, 1);    /* move entry function from L to co */

    if (pcoctx) {
        *pcoctx = coctx;
    }

#ifdef NJT_LUA_USE_ASSERT
    coctx->co_top = 1;
#endif

    return 1;    /* return new coroutine to Lua */
}


static int
njt_http_lua_coroutine_resume(lua_State *L)
{
    lua_State                   *co;
    njt_http_request_t          *r;
    njt_http_lua_ctx_t          *ctx;
    njt_http_lua_co_ctx_t       *coctx;
    njt_http_lua_co_ctx_t       *p_coctx; /* parent co ctx */

    co = lua_tothread(L, 1);

    luaL_argcheck(L, co, 1, "coroutine expected");

    r = njt_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    njt_http_lua_check_context(L, ctx, NJT_HTTP_LUA_CONTEXT_YIELDABLE);

    p_coctx = ctx->cur_co_ctx;
    if (p_coctx == NULL) {
        return luaL_error(L, "no parent co ctx found");
    }

    coctx = njt_http_lua_get_co_ctx(co, ctx);
    if (coctx == NULL) {
        return luaL_error(L, "no co ctx found");
    }

    njt_http_lua_probe_user_coroutine_resume(r, L, co);

    if (coctx->co_status != NJT_HTTP_LUA_CO_SUSPENDED) {
        dd("coroutine resume: %d", coctx->co_status);

        lua_pushboolean(L, 0);
        lua_pushfstring(L, "cannot resume %s coroutine",
                        njt_http_lua_co_status_names[coctx->co_status].data);
        return 2;
    }

    p_coctx->co_status = NJT_HTTP_LUA_CO_NORMAL;

    coctx->parent_co_ctx = p_coctx;

    dd("set coroutine to running");
    coctx->co_status = NJT_HTTP_LUA_CO_RUNNING;

    ctx->co_op = NJT_HTTP_LUA_USER_CORO_RESUME;
    ctx->cur_co_ctx = coctx;

    /* yield and pass args to main thread, and resume target coroutine from
     * there */
    return lua_yield(L, lua_gettop(L) - 1);
}


static int
njt_http_lua_coroutine_yield(lua_State *L)
{
    njt_http_request_t          *r;
    njt_http_lua_ctx_t          *ctx;
    njt_http_lua_co_ctx_t       *coctx;

    r = njt_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    njt_http_lua_check_context(L, ctx, NJT_HTTP_LUA_CONTEXT_YIELDABLE);

    coctx = ctx->cur_co_ctx;

    coctx->co_status = NJT_HTTP_LUA_CO_SUSPENDED;

    ctx->co_op = NJT_HTTP_LUA_USER_CORO_YIELD;

    if (!coctx->is_uthread && coctx->parent_co_ctx) {
        dd("set coroutine to running");
        coctx->parent_co_ctx->co_status = NJT_HTTP_LUA_CO_RUNNING;

        njt_http_lua_probe_user_coroutine_yield(r, coctx->parent_co_ctx->co, L);

    } else {
        njt_http_lua_probe_user_coroutine_yield(r, NULL, L);
    }

    /* yield and pass retvals to main thread,
     * and resume parent coroutine there */
    return lua_yield(L, lua_gettop(L));
}


void
njt_http_lua_inject_coroutine_api(njt_log_t *log, lua_State *L)
{
    int         rc;

    /* new coroutine table */
    lua_createtable(L, 0 /* narr */, 16 /* nrec */);

    /* get old coroutine table */
    lua_getglobal(L, "coroutine");

    /* set running to the old one */
    lua_getfield(L, -1, "running");
    lua_setfield(L, -3, "running");

    lua_getfield(L, -1, "create");
    lua_setfield(L, -3, "_create");

    lua_getfield(L, -1, "wrap");
    lua_setfield(L, -3, "_wrap");

    lua_getfield(L, -1, "resume");
    lua_setfield(L, -3, "_resume");

    lua_getfield(L, -1, "yield");
    lua_setfield(L, -3, "_yield");

    lua_getfield(L, -1, "status");
    lua_setfield(L, -3, "_status");

    /* pop the old coroutine */
    lua_pop(L, 1);

    lua_pushcfunction(L, njt_http_lua_coroutine_create);
    lua_setfield(L, -2, "__create");

    lua_pushcfunction(L, njt_http_lua_coroutine_wrap);
    lua_setfield(L, -2, "__wrap");

    lua_pushcfunction(L, njt_http_lua_coroutine_resume);
    lua_setfield(L, -2, "__resume");

    lua_pushcfunction(L, njt_http_lua_coroutine_yield);
    lua_setfield(L, -2, "__yield");

    lua_pushcfunction(L, njt_http_lua_coroutine_status);
    lua_setfield(L, -2, "__status");

    lua_setglobal(L, "coroutine");

    /* inject coroutine APIs */
    {
        const char buf[] =
            "local keys = {'create', 'yield', 'resume', 'status', 'wrap'}\n"
#ifdef OPENRESTY_LUAJIT
            "local get_req = require 'thread.exdata'\n"
#else
            "local getfenv = getfenv\n"
#endif
            "for _, key in ipairs(keys) do\n"
               "local std = coroutine['_' .. key]\n"
               "local ours = coroutine['__' .. key]\n"
               "local raw_ctx = njt._phase_ctx\n"
               "coroutine[key] = function (...)\n"
#ifdef OPENRESTY_LUAJIT
                    "local r = get_req()\n"
#else
                    "local r = getfenv(0).__njt_req\n"
#endif
                    "if r ~= nil then\n"
#ifdef OPENRESTY_LUAJIT
                        "local ctx = raw_ctx()\n"
#else
                        "local ctx = raw_ctx(r)\n"
#endif
                        /* ignore header and body filters */
                        "if ctx ~= 0x020 and ctx ~= 0x040 then\n"
                            "return ours(...)\n"
                        "end\n"
                    "end\n"
                    "return std(...)\n"
                "end\n"
            "end\n"
            "package.loaded.coroutine = coroutine"
#if 0
            "debug.sethook(function () collectgarbage() end, 'rl', 1)"
#endif
            ;

        rc = luaL_loadbuffer(L, buf, sizeof(buf) - 1, "=coroutine_api");
    }

    if (rc != 0) {
        njt_log_error(NJT_LOG_ERR, log, 0,
                      "failed to load Lua code for coroutine_api: %i: %s",
                      rc, lua_tostring(L, -1));

        lua_pop(L, 1);
        return;
    }

    rc = lua_pcall(L, 0, 0, 0);
    if (rc != 0) {
        njt_log_error(NJT_LOG_ERR, log, 0,
                      "failed to run the Lua code for coroutine_api: %i: %s",
                      rc, lua_tostring(L, -1));
        lua_pop(L, 1);
    }
}


static int
njt_http_lua_coroutine_status(lua_State *L)
{
    lua_State                     *co;  /* new coroutine to be created */
    njt_http_request_t            *r;
    njt_http_lua_ctx_t            *ctx;
    njt_http_lua_co_ctx_t         *coctx; /* co ctx for the new coroutine */

    co = lua_tothread(L, 1);

    luaL_argcheck(L, co, 1, "coroutine expected");

    r = njt_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    njt_http_lua_check_context(L, ctx, NJT_HTTP_LUA_CONTEXT_YIELDABLE);

    coctx = njt_http_lua_get_co_ctx(co, ctx);
    if (coctx == NULL) {
        lua_pushlstring(L, (const char *)
                        njt_http_lua_co_status_names[NJT_HTTP_LUA_CO_DEAD].data,
                        njt_http_lua_co_status_names[NJT_HTTP_LUA_CO_DEAD].len);
        return 1;
    }

    dd("co status: %d", coctx->co_status);

    lua_pushlstring(L, (const char *)
                    njt_http_lua_co_status_names[coctx->co_status].data,
                    njt_http_lua_co_status_names[coctx->co_status].len);
    return 1;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
