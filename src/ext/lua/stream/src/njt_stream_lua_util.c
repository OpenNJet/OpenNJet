
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_util.c.tt2
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


#include "njet.h"
#include "njt_stream_lua_directive.h"
#include "njt_stream_lua_util.h"
#include "njt_stream_lua_exception.h"
#include "njt_stream_lua_pcrefix.h"
#include "njt_stream_lua_args.h"
#include "njt_stream_lua_output.h"
#include "njt_stream_lua_control.h"
#include "njt_stream_lua_log.h"
#include "njt_stream_lua_string.h"
#include "njt_stream_lua_misc.h"
#include "njt_stream_lua_consts.h"
#include "njt_stream_lua_shdict.h"
#include "njt_stream_lua_coroutine.h"
#include "njt_stream_lua_socket_tcp.h"
#include "njt_stream_lua_socket_udp.h"
#include "njt_stream_lua_sleep.h"
#include "njt_stream_lua_probe.h"
#include "njt_stream_lua_uthread.h"
#include "njt_stream_lua_contentby.h"
#include "njt_stream_lua_timer.h"
#include "njt_stream_lua_config.h"
#include "njt_stream_lua_ssl.h"


#include "njt_stream_lua_phase.h"


#if 1
#undef njt_stream_lua_probe_info
#define njt_stream_lua_probe_info(msg)
#endif


#ifndef NJT_STREAM_LUA_BT_DEPTH
#define NJT_STREAM_LUA_BT_DEPTH  22
#endif


#ifndef NJT_STREAM_LUA_BT_MAX_COROS
#define NJT_STREAM_LUA_BT_MAX_COROS  5
#endif


#if (NJT_STREAM_LUA_HAVE_SA_RESTART)
#define NJT_STREAM_LUA_SA_RESTART_SIGS {                                     \
    njt_signal_value(NJT_RECONFIGURE_SIGNAL),                                \
    njt_signal_value(NJT_REOPEN_SIGNAL),                                     \
    njt_signal_value(NJT_NOACCEPT_SIGNAL),                                   \
    njt_signal_value(NJT_TERMINATE_SIGNAL),                                  \
    njt_signal_value(NJT_SHUTDOWN_SIGNAL),                                   \
    njt_signal_value(NJT_CHANGEBIN_SIGNAL),                                  \
    SIGALRM,                                                                 \
    SIGINT,                                                                  \
    SIGIO,                                                                   \
    SIGCHLD,                                                                 \
    SIGSYS,                                                                  \
    SIGPIPE,                                                                 \
    0                                                                        \
};
#endif


char njt_stream_lua_code_cache_key;
char njt_stream_lua_regex_cache_key;
char njt_stream_lua_socket_pool_key;
char njt_stream_lua_coroutines_key;

static void njt_stream_lua_init_registry(lua_State *L, njt_log_t *log);
static void njt_stream_lua_init_globals(lua_State *L, njt_cycle_t *cycle,
    njt_stream_lua_main_conf_t *lmcf, njt_log_t *log);
#ifdef OPENRESTY_LUAJIT
static void njt_stream_lua_inject_global_write_guard(lua_State *L,
    njt_log_t *log);
#endif
static void njt_stream_lua_set_path(njt_cycle_t *cycle, lua_State *L,
    int tab_idx, const char *fieldname, const char *path,
    const char *default_path, njt_log_t *log);
static njt_int_t njt_stream_lua_handle_exit(lua_State *L,
    njt_stream_lua_request_t *r, njt_stream_lua_ctx_t *ctx);
static int njt_stream_lua_thread_traceback(lua_State *L, lua_State *co,
    njt_stream_lua_co_ctx_t *coctx);
static void njt_stream_lua_inject_njt_api(lua_State *L,
    njt_stream_lua_main_conf_t *lmcf, njt_log_t *log);
static njt_int_t njt_stream_lua_output_filter(njt_stream_lua_request_t *r,
    njt_chain_t *in);
static void njt_stream_lua_finalize_threads(njt_stream_lua_request_t *r,
    njt_stream_lua_ctx_t *ctx, lua_State *L);
static njt_int_t njt_stream_lua_post_zombie_thread(njt_stream_lua_request_t *r,
    njt_stream_lua_co_ctx_t *parent, njt_stream_lua_co_ctx_t *thread);
static void njt_stream_lua_cleanup_zombie_child_uthreads(
    njt_stream_lua_request_t *r, lua_State *L, njt_stream_lua_ctx_t *ctx,
    njt_stream_lua_co_ctx_t *coctx);
static njt_int_t njt_stream_lua_on_abort_resume(njt_stream_lua_request_t *r);
static void njt_stream_lua_close_fake_request(njt_stream_lua_request_t *r);
static njt_int_t njt_stream_lua_flush_pending_output(
    njt_stream_lua_request_t *r, njt_stream_lua_ctx_t *ctx);
static njt_int_t
    njt_stream_lua_process_flushing_coroutines(njt_stream_lua_request_t *r,
    njt_stream_lua_ctx_t *ctx);
static lua_State *njt_stream_lua_new_state(lua_State *parent_vm,
    njt_cycle_t *cycle, njt_stream_lua_main_conf_t *lmcf, njt_log_t *log);
static int njt_stream_lua_get_raw_phase_context(lua_State *L);
static int njt_stream_lua_req_socket(lua_State *L);


#ifndef LUA_PATH_SEP
#define LUA_PATH_SEP ";"
#endif


#if !defined(LUA_DEFAULT_PATH)
#define LUA_DEFAULT_PATH "/usr/local/njet/lualib/lib/?.lua;lualib/lib/?.lua;"                      
                         //"/etc/njet/lua-resty-lrucache/lib/?.lua"
#endif


#define AUX_MARK "\1"


static void
njt_stream_lua_set_path(njt_cycle_t *cycle, lua_State *L, int tab_idx,
    const char *fieldname, const char *path, const char *default_path,
    njt_log_t *log)
{
    const char          *tmp_path;
    const char          *prefix;

    /* XXX here we use some hack to simplify string manipulation */
    tmp_path = luaL_gsub(L, path, LUA_PATH_SEP LUA_PATH_SEP,
                         LUA_PATH_SEP AUX_MARK LUA_PATH_SEP);

    lua_pushlstring(L, (char *) cycle->prefix.data, cycle->prefix.len);
    prefix = lua_tostring(L, -1);
    tmp_path = luaL_gsub(L, tmp_path, "$prefix", prefix);
    tmp_path = luaL_gsub(L, tmp_path, "${prefix}", prefix);
    lua_pop(L, 3);

    dd("tmp_path path: %s", tmp_path);

#if (NJT_DEBUG)
    tmp_path =
#else
    (void)
#endif
        luaL_gsub(L, tmp_path, AUX_MARK, default_path);

#if (NJT_DEBUG)
    njt_log_debug2(NJT_LOG_DEBUG_STREAM, log, 0,
                   "lua setting lua package.%s to \"%s\"", fieldname, tmp_path);
#endif

    lua_remove(L, -2);

    /* fix negative index as there's new data on stack */
    tab_idx = (tab_idx < 0) ? (tab_idx - 1) : tab_idx;
    lua_setfield(L, tab_idx, fieldname);
}


#ifndef OPENRESTY_LUAJIT
/**
 * Create new table and set _G field to itself.
 *
 * After:
 *         | new table | <- top
 *         |    ...    |
 * */
void
njt_stream_lua_create_new_globals_table(lua_State *L, int narr, int nrec)
{
    lua_createtable(L, narr, nrec + 1);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "_G");
}
#endif /* OPENRESTY_LUAJIT */


static lua_State *
njt_stream_lua_new_state(lua_State *parent_vm, njt_cycle_t *cycle,
    njt_stream_lua_main_conf_t *lmcf, njt_log_t *log)
{
    lua_State       *L;
    const char      *old_path;
    const char      *new_path;
    size_t           old_path_len;
    const char      *old_cpath;
    const char      *new_cpath;
    size_t           old_cpath_len;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, log, 0, "lua creating new vm state");

    L = luaL_newstate();
    if (L == NULL) {
        return NULL;
    }

    luaL_openlibs(L);

    lua_getglobal(L, "package");

    if (!lua_istable(L, -1)) {
        njt_log_error(NJT_LOG_EMERG, log, 0,
                      "the \"package\" table does not exist");
        return NULL;
    }

    if (parent_vm) {
        lua_getglobal(parent_vm, "package");
        lua_getfield(parent_vm, -1, "path");
        old_path = lua_tolstring(parent_vm, -1, &old_path_len);
        lua_pop(parent_vm, 1);

        lua_pushlstring(L, old_path, old_path_len);
        lua_setfield(L, -2, "path");

        lua_getfield(parent_vm, -1, "cpath");
        old_path = lua_tolstring(parent_vm, -1, &old_path_len);
        lua_pop(parent_vm, 2);

        lua_pushlstring(L, old_path, old_path_len);
        lua_setfield(L, -2, "cpath");

    } else {
#ifdef LUA_DEFAULT_PATH
#   define LUA_DEFAULT_PATH_LEN (sizeof(LUA_DEFAULT_PATH) - 1)
        njt_log_debug1(NJT_LOG_DEBUG_STREAM, log, 0,
                       "lua prepending default package.path with %s",
                       LUA_DEFAULT_PATH);

        lua_pushliteral(L, LUA_DEFAULT_PATH ";"); /* package default */
        lua_getfield(L, -2, "path"); /* package default old */
        lua_concat(L, 2); /* package new */
        lua_setfield(L, -2, "path"); /* package */
#endif

#ifdef LUA_DEFAULT_CPATH
#   define LUA_DEFAULT_CPATH_LEN (sizeof(LUA_DEFAULT_CPATH) - 1)
        njt_log_debug1(NJT_LOG_DEBUG_STREAM, log, 0,
                       "lua prepending default package.cpath with %s",
                       LUA_DEFAULT_CPATH);

        lua_pushliteral(L, LUA_DEFAULT_CPATH ";"); /* package default */
        lua_getfield(L, -2, "cpath"); /* package default old */
        old_cpath = lua_tolstring(L, -1, &old_cpath_len);
        lua_concat(L, 2); /* package new */
        lua_setfield(L, -2, "cpath"); /* package */
#endif

        if (lmcf->lua_path.len != 0) {
            lua_getfield(L, -1, "path"); /* get original package.path */
            old_path = lua_tolstring(L, -1, &old_path_len);

            dd("old path: %s", old_path);

            lua_pushlstring(L, (char *) lmcf->lua_path.data,
                            lmcf->lua_path.len);
            new_path = lua_tostring(L, -1);

            njt_stream_lua_set_path(cycle, L, -3, "path", new_path, old_path,
                                    log);

            lua_pop(L, 2);
        }

        if (lmcf->lua_cpath.len != 0) {
            lua_getfield(L, -1, "cpath"); /* get original package.cpath */
            old_cpath = lua_tolstring(L, -1, &old_cpath_len);

            dd("old cpath: %s", old_cpath);

            lua_pushlstring(L, (char *) lmcf->lua_cpath.data,
                            lmcf->lua_cpath.len);
            new_cpath = lua_tostring(L, -1);

            njt_stream_lua_set_path(cycle, L, -3, "cpath", new_cpath, old_cpath,
                                    log);


            lua_pop(L, 2);
        }
    }

    lua_pop(L, 1); /* remove the "package" table */

    njt_stream_lua_init_registry(L, log);
    njt_stream_lua_init_globals(L, cycle, lmcf, log);

    return L;
}


lua_State *
njt_stream_lua_new_thread(njt_stream_lua_request_t *r, lua_State *L, int *ref)
{
    int              base;
    lua_State       *co;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "lua creating new thread");

    base = lua_gettop(L);

    lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(
                          coroutines_key));
    lua_rawget(L, LUA_REGISTRYINDEX);

    co = lua_newthread(L);

#ifndef OPENRESTY_LUAJIT
    /*  {{{ inherit coroutine's globals to main thread's globals table
     *  for print() function will try to find tostring() in current
     *  globals table.
     */
    /*  new globals table for coroutine */
    njt_stream_lua_create_new_globals_table(co, 0, 0);

    lua_createtable(co, 0, 1);
    njt_stream_lua_get_globals_table(co);
    lua_setfield(co, -2, "__index");
    lua_setmetatable(co, -2);

    njt_stream_lua_set_globals_table(co);
    /*  }}} */
#endif /* OPENRESTY_LUAJIT */

    *ref = luaL_ref(L, -2);

    if (*ref == LUA_NOREF) {
        lua_settop(L, base);  /* restore main thread stack */
        return NULL;
    }

    lua_settop(L, base);
    return co;
}


void
njt_stream_lua_del_thread(njt_stream_lua_request_t *r, lua_State *L,
    njt_stream_lua_ctx_t *ctx, njt_stream_lua_co_ctx_t *coctx)
{
    if (coctx->co_ref == LUA_NOREF) {
        return;
    }

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "lua deleting light thread");

    lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(
                          coroutines_key));
    lua_rawget(L, LUA_REGISTRYINDEX);

    njt_stream_lua_probe_thread_delete(r, coctx->co, ctx);

    luaL_unref(L, -1, coctx->co_ref);
    coctx->co_ref = LUA_NOREF;
    coctx->co_status = NJT_STREAM_LUA_CO_DEAD;

    lua_pop(L, 1);
}


u_char *
njt_stream_lua_rebase_path(njt_pool_t *pool, u_char *src, size_t len)
{
    u_char     *p;
    njt_str_t   dst;

    dst.data = njt_palloc(pool, len + 1);
    if (dst.data == NULL) {
        return NULL;
    }

    dst.len = len;

    p = njt_copy(dst.data, src, len);
    *p = '\0';

    if (njt_get_full_name(pool, (njt_str_t *) &njt_cycle->prefix, &dst)
        != NJT_OK)
    {
        return NULL;
    }

    return dst.data;
}




njt_int_t
njt_stream_lua_send_chain_link(njt_stream_lua_request_t *r,
    njt_stream_lua_ctx_t *ctx, njt_chain_t *in)
{
    if (in == NULL) {
        ctx->eof = 1;

        return NJT_OK;
    }

    return njt_stream_lua_output_filter(r, in);
}




static njt_int_t
njt_stream_lua_output_filter(njt_stream_lua_request_t *r, njt_chain_t *in)
{
    njt_int_t                    rc;
    njt_stream_lua_ctx_t        *ctx;

    rc = njt_stream_top_filter(r->session, in, 1);

    if (rc == NJT_ERROR) {
        return NJT_ERROR;
    }

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);

    njt_chain_update_chains(r->pool,
                            &ctx->free_bufs, &ctx->busy_bufs, &in,
                            (njt_buf_tag_t) &njt_stream_lua_module);

    return rc;
}




static void
njt_stream_lua_init_registry(lua_State *L, njt_log_t *log)
{
    njt_log_debug0(NJT_LOG_DEBUG_STREAM, log, 0,
                   "lua initializing lua registry");

    /* {{{ register a table to anchor lua coroutines reliably:
     * {([int]ref) = [cort]} */
    lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(
                          coroutines_key));
    lua_createtable(L, 0, 32 /* nrec */);
    lua_rawset(L, LUA_REGISTRYINDEX);
    /* }}} */

    /* create the registry entry for the Lua request ctx data table */
    lua_pushliteral(L, njt_stream_lua_ctx_tables_key);
    lua_createtable(L, 0, 32 /* nrec */);
    lua_rawset(L, LUA_REGISTRYINDEX);

    /* create the registry entry for the Lua socket connection pool table */
    lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(
                          socket_pool_key));
    lua_createtable(L, 0, 8 /* nrec */);
    lua_rawset(L, LUA_REGISTRYINDEX);

#if (NJT_PCRE)
    /* create the registry entry for the Lua precompiled regex object cache */
    lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(
                          regex_cache_key));
    lua_createtable(L, 0, 16 /* nrec */);
    lua_rawset(L, LUA_REGISTRYINDEX);
#endif

    /* {{{ register table to cache user code:
     * { [(string)cache_key] = <code closure> } */
    lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(
                          code_cache_key));
    lua_createtable(L, 0, 8 /* nrec */);
    lua_rawset(L, LUA_REGISTRYINDEX);
    /* }}} */
}


static void
njt_stream_lua_init_globals(lua_State *L, njt_cycle_t *cycle,
    njt_stream_lua_main_conf_t *lmcf, njt_log_t *log)
{
    njt_log_debug0(NJT_LOG_DEBUG_STREAM, log, 0,
                   "lua initializing lua globals");


    njt_stream_lua_inject_njt_api(L, lmcf, log);
}


static void
njt_stream_lua_inject_njt_api(lua_State *L, njt_stream_lua_main_conf_t *lmcf,
    njt_log_t *log)
{
    lua_createtable(L, 0 /* narr */, 113 /* nrec */);    /* njt.* */

    lua_pushcfunction(L, njt_stream_lua_get_raw_phase_context);
    lua_setfield(L, -2, "_phase_ctx");


    njt_stream_lua_inject_core_consts(L);

    njt_stream_lua_inject_log_api(L);
    njt_stream_lua_inject_output_api(L);
    njt_stream_lua_inject_string_api(L);
    njt_stream_lua_inject_control_api(log, L);


    njt_stream_lua_inject_sleep_api(L);
    njt_stream_lua_inject_phase_api(L);

    njt_stream_lua_inject_req_api(log, L);


    njt_stream_lua_inject_shdict_api(lmcf, L);
    njt_stream_lua_inject_socket_tcp_api(log, L);
    njt_stream_lua_inject_socket_udp_api(log, L);
    njt_stream_lua_inject_uthread_api(log, L);
    njt_stream_lua_inject_timer_api(L);
    njt_stream_lua_inject_config_api(L);

    lua_getglobal(L, "package"); /* njt package */
    lua_getfield(L, -1, "loaded"); /* njt package loaded */
    lua_pushvalue(L, -3); /* njt package loaded njt */
    lua_setfield(L, -2, "njt"); /* njt package loaded */
    lua_pop(L, 2);

    lua_setglobal(L, "njt");

    njt_stream_lua_inject_coroutine_api(log, L);
}

#ifdef OPENRESTY_LUAJIT
static void
njt_stream_lua_inject_global_write_guard(lua_State *L, njt_log_t *log)
{
    int         rc;

    const char buf[] =
        "local njt_log = njt.log\n"
        "local njt_WARN = njt.WARN\n"
        "local tostring = tostring\n"
        "local njt_get_phase = njt.get_phase\n"
        "local traceback = require 'debug'.traceback\n"
        "local function newindex(table, key, value)\n"
            "rawset(table, key, value)\n"
            "local phase = njt_get_phase()\n"
            "if phase == 'init_worker' or phase == 'init' then\n"
                "return\n"
            "end\n"
            "njt_log(njt_WARN, 'writing a global Lua variable "
                     "(\\'', tostring(key), '\\') which may lead to "
                     "race conditions between concurrent requests, so "
                     "prefer the use of \\'local\\' variables', "
                     "traceback('', 2))\n"
        "end\n"
        "setmetatable(_G, { __newindex = newindex })\n"
        ;

    rc = luaL_loadbuffer(L, buf, sizeof(buf) - 1, "=_G write guard");

    if (rc != 0) {
        njt_log_error(NJT_LOG_ERR, log, 0,
                      "failed to load Lua code (%i): %s",
                      rc, lua_tostring(L, -1));

        lua_pop(L, 1);
        return;
    }

    rc = lua_pcall(L, 0, 0, 0);
    if (rc != 0) {
        njt_log_error(NJT_LOG_ERR, log, 0,
                      "failed to run Lua code (%i): %s",
                      rc, lua_tostring(L, -1));
        lua_pop(L, 1);
    }
}
#endif


void
njt_stream_lua_discard_bufs(njt_pool_t *pool, njt_chain_t *in)
{
    njt_chain_t         *cl;

    for (cl = in; cl; cl = cl->next) {
        cl->buf->pos = cl->buf->last;
        cl->buf->file_pos = cl->buf->file_last;
    }
}


njt_int_t
njt_stream_lua_add_copy_chain(njt_stream_lua_request_t *r,
    njt_stream_lua_ctx_t *ctx, njt_chain_t ***plast, njt_chain_t *in,
    njt_int_t *eof)
{
    njt_chain_t     *cl;
    size_t           len;
    njt_buf_t       *b;

    len = 0;
    *eof = 0;

    for (cl = in; cl; cl = cl->next) {
        if (njt_buf_in_memory(cl->buf)) {
            len += cl->buf->last - cl->buf->pos;
        }

        if (cl->buf->last_in_chain || cl->buf->last_buf) {
            *eof = 1;
        }
    }

    if (len == 0) {
        return NJT_OK;
    }

    cl = njt_stream_lua_chain_get_free_buf(r->connection->log, r->pool,
                                           &ctx->free_bufs, len);
    if (cl == NULL) {
        return NJT_ERROR;
    }

    dd("chains get free buf: %d == %d", (int) (cl->buf->end - cl->buf->start),
       (int) len);

    b = cl->buf;

    while (in) {
        if (njt_buf_in_memory(in->buf)) {
            b->last = njt_copy(b->last, in->buf->pos,
                               in->buf->last - in->buf->pos);
        }

        in = in->next;
    }

    **plast = cl;
    *plast = &cl->next;

    return NJT_OK;
}


void
njt_stream_lua_reset_ctx(njt_stream_lua_request_t *r, lua_State *L,
    njt_stream_lua_ctx_t *ctx)
{
    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "lua reset ctx");

    njt_stream_lua_finalize_threads(r, ctx, L);

#if 0
    if (ctx->user_co_ctx) {
        /* no way to destroy a list but clean up the whole pool */
        ctx->user_co_ctx = NULL;
    }
#endif

    njt_memzero(&ctx->entry_co_ctx, sizeof(njt_stream_lua_co_ctx_t));

    ctx->entry_co_ctx.co_ref = LUA_NOREF;


    ctx->entered_content_phase = 0;

    ctx->exit_code = 0;
    ctx->exited = 0;
    ctx->resume_handler = njt_stream_lua_wev_handler;


    ctx->co_op = 0;
}




void
njt_stream_lua_request_cleanup_handler(void *data)
{
    njt_stream_lua_ctx_t                *ctx = data;

    njt_stream_lua_request_cleanup(ctx, 0 /* forcible */);
}


void
njt_stream_lua_request_cleanup(njt_stream_lua_ctx_t *ctx, int forcible)
{
    lua_State                           *L;
    njt_stream_lua_request_t            *r;
    njt_stream_lua_main_conf_t          *lmcf;

    /*  force coroutine handling the request quit */
    if (ctx == NULL) {
        dd("ctx is NULL");
        return;
    }

    r = ctx->request;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "lua request cleanup: forcible=%d", forcible);

    if (ctx->cleanup) {
        *ctx->cleanup = NULL;
        ctx->cleanup = NULL;
    }

    lmcf = njt_stream_lua_get_module_main_conf(r, njt_stream_lua_module);

#if 1
    if (r->connection->fd == (njt_socket_t) -1) {
        /* being a fake request */

        if (ctx->context == NJT_STREAM_LUA_CONTEXT_TIMER) {
            /* being a timer handler */
            lmcf->running_timers--;
        }
    }
#endif

    L = njt_stream_lua_get_lua_vm(r, ctx);

    njt_stream_lua_finalize_threads(r, ctx, L);
}


/*
 * description:
 *  run a Lua coroutine specified by ctx->cur_co_ctx->co
 * return value:
 *  NJT_AGAIN:      I/O interruption: r->main->count intact
 *  NJT_DONE:       I/O interruption: r->main->count already incremented by 1
 *  NJT_ERROR:      error
 *  >= 200          HTTP status code
 */
njt_int_t
njt_stream_lua_run_thread(lua_State *L, njt_stream_lua_request_t *r,
    njt_stream_lua_ctx_t *ctx, volatile int nrets)
{
    njt_stream_lua_co_ctx_t         *next_coctx, *parent_coctx, *orig_coctx;

    int                      rv, success = 1;
    lua_State               *next_co;
    lua_State               *old_co;
    const char              *err, *msg, *trace;


#if (NJT_PCRE)
    njt_pool_t              *old_pool = NULL;
#endif

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "lua run thread, top:%d", lua_gettop(L));

    /* set Lua VM panic handler */
    lua_atpanic(L, njt_stream_lua_atpanic);

    NJT_LUA_EXCEPTION_TRY {

        /*
         * silence a -Werror=clobbered warning with gcc 5.4
         * due to above setjmp
         */
        err = NULL;
        msg = NULL;
        trace = NULL;

        if (ctx->cur_co_ctx->thread_spawn_yielded) {
            njt_stream_lua_probe_info("thread spawn yielded");

            ctx->cur_co_ctx->thread_spawn_yielded = 0;
            nrets = 1;
        }

        for ( ;; ) {

            dd("ctx: %p, co: %p, co status: %d, co is_wrap: %d",
               ctx, ctx->cur_co_ctx->co, ctx->cur_co_ctx->co_status,
               ctx->cur_co_ctx->is_wrap);

#if (NJT_PCRE)
            /* XXX: work-around to njet regex subsystem */
            old_pool = njt_stream_lua_pcre_malloc_init(r->pool);
#endif

            orig_coctx = ctx->cur_co_ctx;

#ifdef NJT_LUA_USE_ASSERT
            dd("%p: saved co top: %d, nrets: %d, true top: %d",
               orig_coctx->co,
               (int) orig_coctx->co_top, (int) nrets,
               (int) lua_gettop(orig_coctx->co));
#endif

#if DDEBUG
            if (lua_gettop(orig_coctx->co) > 0) {
                dd("co top elem: %s", luaL_typename(orig_coctx->co, -1));
            }

            if (orig_coctx->propagate_error) {
                dd("co propagate_error: %d", orig_coctx->propagate_error);
            }
#endif

            if (orig_coctx->propagate_error) {
                orig_coctx->propagate_error = 0;
                goto propagate_error;
            }

            njt_stream_lua_assert(orig_coctx->co_top + nrets
                                  == lua_gettop(orig_coctx->co));

            rv = lua_resume(orig_coctx->co, nrets);

#if (NJT_PCRE)
            /* XXX: work-around to njet regex subsystem */
            njt_stream_lua_pcre_malloc_done(old_pool);
#endif

#if 0
            /* test the longjmp thing */
            if (rand() % 2 == 0) {
                NJT_LUA_EXCEPTION_THROW(1);
            }
#endif

            njt_log_debug1(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                           "lua resume returned %d", rv);

            switch (rv) {
            case LUA_YIELD:
                /*  yielded, let event handler do the rest job */
                /*  FIXME: add io cmd dispatcher here */

                njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                               "lua thread yielded");

#ifdef NJT_LUA_USE_ASSERT
                dd("%p: saving curr top after yield: %d (co-op: %d)",
                   orig_coctx->co,
                   (int) lua_gettop(orig_coctx->co), (int) ctx->co_op);
                orig_coctx->co_top = lua_gettop(orig_coctx->co);
#endif


                if (ctx->exited) {
                    return njt_stream_lua_handle_exit(L, r, ctx);
                }


                /*
                 * check if coroutine.resume or coroutine.yield called
                 * lua_yield()
                 */
                switch (ctx->co_op) {

                case NJT_STREAM_LUA_USER_CORO_NOP:
                    dd("hit! it is the API yield");

                    njt_stream_lua_assert(lua_gettop(ctx->cur_co_ctx->co) == 0);

                    ctx->cur_co_ctx = NULL;

                    return NJT_AGAIN;

                case NJT_STREAM_LUA_USER_THREAD_RESUME:

                    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                                   "lua user thread resume");

                    ctx->co_op = NJT_STREAM_LUA_USER_CORO_NOP;
                    nrets = lua_gettop(ctx->cur_co_ctx->co) - 1;
                    dd("nrets = %d", nrets);

#ifdef NJT_LUA_USE_ASSERT
                    /* ignore the return value (the thread) already pushed */
                    orig_coctx->co_top--;
#endif

                    break;

                case NJT_STREAM_LUA_USER_CORO_RESUME:
                    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                                   "lua coroutine: resume");

                    /*
                     * the target coroutine lies at the base of the
                     * parent's stack
                     */
                    ctx->co_op = NJT_STREAM_LUA_USER_CORO_NOP;

                    old_co = ctx->cur_co_ctx->parent_co_ctx->co;

                    nrets = lua_gettop(old_co);
                    if (nrets) {
                        dd("moving %d return values to parent", nrets);
                        lua_xmove(old_co, ctx->cur_co_ctx->co, nrets);

#ifdef NJT_LUA_USE_ASSERT
                        ctx->cur_co_ctx->parent_co_ctx->co_top -= nrets;
#endif
                    }

                    break;

                default:
                    /* ctx->co_op == NJT_STREAM_LUA_USER_CORO_YIELD */

                    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                                   "lua coroutine: yield");

                    ctx->co_op = NJT_STREAM_LUA_USER_CORO_NOP;

                    if (njt_stream_lua_is_thread(ctx)) {
                        njt_stream_lua_probe_thread_yield(r,
                                                          ctx->cur_co_ctx->co);

                        /* discard any return values from user
                         * coroutine.yield()'s arguments */
                        lua_settop(ctx->cur_co_ctx->co, 0);

#ifdef NJT_LUA_USE_ASSERT
                        ctx->cur_co_ctx->co_top = 0;
#endif

                        njt_stream_lua_probe_info("set co running");
                        ctx->cur_co_ctx->co_status = NJT_STREAM_LUA_CO_RUNNING;

                        if (ctx->posted_threads) {
                            njt_stream_lua_post_thread(r, ctx, ctx->cur_co_ctx);
                            ctx->cur_co_ctx = NULL;
                            return NJT_AGAIN;
                        }

                        /* no pending threads, so resume the thread
                         * immediately */

                        nrets = 0;
                        continue;
                    }

                    /* being a user coroutine that has a parent */

                    nrets = lua_gettop(ctx->cur_co_ctx->co);

                    next_coctx = ctx->cur_co_ctx->parent_co_ctx;
                    next_co = next_coctx->co;

                    if (nrets) {
                        dd("moving %d return values to next co", nrets);
                        lua_xmove(ctx->cur_co_ctx->co, next_co, nrets);
#ifdef NJT_LUA_USE_ASSERT
                        ctx->cur_co_ctx->co_top -= nrets;
#endif
                    }

                    if (!ctx->cur_co_ctx->is_wrap) {
                        /* prepare return values for coroutine.resume
                         * (true plus any retvals)
                         */
                        lua_pushboolean(next_co, 1);
                        lua_insert(next_co, 1);
                        nrets++; /* add the true boolean value */
                    }

                    ctx->cur_co_ctx = next_coctx;

                    break;
                }

                /* try resuming on the new coroutine again */
                continue;

            case 0:

                njt_stream_lua_cleanup_pending_operation(ctx->cur_co_ctx);

                njt_stream_lua_probe_coroutine_done(r, ctx->cur_co_ctx->co, 1);

                ctx->cur_co_ctx->co_status = NJT_STREAM_LUA_CO_DEAD;

                if (ctx->cur_co_ctx->zombie_child_threads) {
                    njt_stream_lua_cleanup_zombie_child_uthreads(r, L, ctx,
                                                               ctx->cur_co_ctx);
                }

                njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                               "lua light thread ended normally");

                if (njt_stream_lua_is_entry_thread(ctx)) {

                    lua_settop(L, 0);

                    njt_stream_lua_del_thread(r, L, ctx, ctx->cur_co_ctx);

                    dd("uthreads: %d", (int) ctx->uthreads);

                    if (ctx->uthreads) {

                        ctx->cur_co_ctx = NULL;
                        return NJT_AGAIN;
                    }

                    /* all user threads terminated already */
                    goto done;
                }

                if (ctx->cur_co_ctx->is_uthread) {
                    /* being a user thread */

                    lua_settop(L, 0);

                    parent_coctx = ctx->cur_co_ctx->parent_co_ctx;

                    if (njt_stream_lua_coroutine_alive(parent_coctx)) {
                        if (ctx->cur_co_ctx->waited_by_parent) {
                            njt_stream_lua_probe_info("parent already waiting");
                            ctx->cur_co_ctx->waited_by_parent = 0;
                            success = 1;
                            goto user_co_done;
                        }

                        njt_stream_lua_probe_info("parent still alive");

                        if (njt_stream_lua_post_zombie_thread(r, parent_coctx,
                                                              ctx->cur_co_ctx)
                            != NJT_OK)
                        {
                            return NJT_ERROR;
                        }

                        lua_pushboolean(ctx->cur_co_ctx->co, 1);
                        lua_insert(ctx->cur_co_ctx->co, 1);

                        ctx->cur_co_ctx->co_status = NJT_STREAM_LUA_CO_ZOMBIE;
                        ctx->cur_co_ctx = NULL;
                        return NJT_AGAIN;
                    }

                    njt_stream_lua_del_thread(r, L, ctx, ctx->cur_co_ctx);
                    ctx->uthreads--;

                    if (ctx->uthreads == 0) {
                        if (njt_stream_lua_entry_thread_alive(ctx)) {
                            ctx->cur_co_ctx = NULL;
                            return NJT_AGAIN;
                        }

                        /* all threads terminated already */
                        goto done;
                    }

                    /* some other user threads still running */
                    ctx->cur_co_ctx = NULL;
                    return NJT_AGAIN;
                }

                /* being a user coroutine that has a parent */

                success = 1;

user_co_done:

                nrets = lua_gettop(ctx->cur_co_ctx->co);

                next_coctx = ctx->cur_co_ctx->parent_co_ctx;

                if (next_coctx == NULL) {
                    /* being a light thread */
                    goto no_parent;
                }

                next_co = next_coctx->co;

                if (nrets) {
                    lua_xmove(ctx->cur_co_ctx->co, next_co, nrets);
                }

                if (ctx->cur_co_ctx->is_uthread) {
                    njt_stream_lua_del_thread(r, L, ctx, ctx->cur_co_ctx);
                    ctx->uthreads--;
                }

                if (!ctx->cur_co_ctx->is_wrap) {
                    /* ended successfully, coroutine.resume returns true plus
                     * any return values
                     */
                    lua_pushboolean(next_co, success);
                    lua_insert(next_co, 1);
                    nrets++;
                }

                ctx->cur_co_ctx = next_coctx;

                njt_stream_lua_probe_info("set parent running");

                next_coctx->co_status = NJT_STREAM_LUA_CO_RUNNING;

                njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                               "lua coroutine: lua user thread ended normally");

                continue;

            case LUA_ERRRUN:
                err = "runtime error";
                break;

            case LUA_ERRSYNTAX:
                err = "syntax error";
                break;

            case LUA_ERRMEM:
                err = "[lua] memory allocation error";
                njt_log_error(NJT_LOG_ALERT, r->connection->log, 0, err);
                abort();
                break;

            case LUA_ERRERR:
                err = "error handler error";
                break;

            default:
                err = "unknown error";
                break;
            }

            if (ctx->cur_co_ctx != orig_coctx) {
                ctx->cur_co_ctx = orig_coctx;
            }

            njt_stream_lua_cleanup_pending_operation(ctx->cur_co_ctx);

            njt_stream_lua_probe_coroutine_done(r, ctx->cur_co_ctx->co, 0);

            ctx->cur_co_ctx->co_status = NJT_STREAM_LUA_CO_DEAD;

            if (orig_coctx->is_uthread
                || orig_coctx->is_wrap
                || njt_stream_lua_is_entry_thread(ctx))
            {
                njt_stream_lua_thread_traceback(L, orig_coctx->co,
                                                orig_coctx);
                trace = lua_tostring(L, -1);

                if (lua_isstring(orig_coctx->co, -1)) {
                    msg = lua_tostring(orig_coctx->co, -1);
                    dd("user custom error msg: %s", msg);

                } else {
                    msg = "unknown reason";
                }
            }

propagate_error:

            if (ctx->cur_co_ctx->is_uthread) {
                njt_stream_lua_assert(err != NULL && msg != NULL
                                      && trace != NULL);

                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "stream lua user thread aborted: %s: %s\n%s",
                              err, msg, trace);

                lua_settop(L, 0);

                parent_coctx = ctx->cur_co_ctx->parent_co_ctx;

                if (njt_stream_lua_coroutine_alive(parent_coctx)) {
                    if (ctx->cur_co_ctx->waited_by_parent) {
                        ctx->cur_co_ctx->waited_by_parent = 0;
                        success = 0;
                        goto user_co_done;
                    }

                    if (njt_stream_lua_post_zombie_thread(r, parent_coctx,
                                                          ctx->cur_co_ctx)
                        != NJT_OK)
                    {
                        return NJT_ERROR;
                    }

                    lua_pushboolean(ctx->cur_co_ctx->co, 0);
                    lua_insert(ctx->cur_co_ctx->co, 1);

                    ctx->cur_co_ctx->co_status = NJT_STREAM_LUA_CO_ZOMBIE;
                    ctx->cur_co_ctx = NULL;
                    return NJT_AGAIN;
                }

                njt_stream_lua_del_thread(r, L, ctx, ctx->cur_co_ctx);
                ctx->uthreads--;

                if (ctx->uthreads == 0) {
                    if (njt_stream_lua_entry_thread_alive(ctx)) {
                        ctx->cur_co_ctx = NULL;
                        return NJT_AGAIN;
                    }

                    /* all threads terminated already */
                    goto done;
                }

                /* some other user threads still running */
                ctx->cur_co_ctx = NULL;
                return NJT_AGAIN;
            }

            if (njt_stream_lua_is_entry_thread(ctx)) {
                njt_stream_lua_assert(err != NULL && msg != NULL
                                      && trace != NULL);

                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "lua entry thread aborted: %s: %s\n%s",
                              err, msg, trace);

                lua_settop(L, 0);

                /* being the entry thread aborted */


                njt_stream_lua_request_cleanup(ctx, 0);


                if (ctx->no_abort) {
                    ctx->no_abort = 0;
                    return NJT_ERROR;
                }

                return NJT_STREAM_INTERNAL_SERVER_ERROR;
            }

            /* being a user coroutine that has a parent */

            next_coctx = ctx->cur_co_ctx->parent_co_ctx;
            if (next_coctx == NULL) {
                goto no_parent;
            }

            next_co = next_coctx->co;

            njt_stream_lua_probe_info("set parent running");

            next_coctx->co_status = NJT_STREAM_LUA_CO_RUNNING;

            ctx->cur_co_ctx = next_coctx;

            if (orig_coctx->is_wrap) {
                /*
                 * coroutine.wrap propagates errors
                 * to its parent coroutine
                 */
                next_coctx->propagate_error = 1;
                continue;
            }

            /*
             * ended with error, coroutine.resume returns false plus
             * err msg
             */
            lua_pushboolean(next_co, 0);
            lua_xmove(orig_coctx->co, next_co, 1);
            nrets = 2;

            /* try resuming on the new coroutine again */
            continue;
        }

    } NJT_LUA_EXCEPTION_CATCH {
        dd("njet execution restored");
    }

    return NJT_ERROR;

no_parent:

    lua_settop(L, 0);

    ctx->cur_co_ctx->co_status = NJT_STREAM_LUA_CO_DEAD;


    njt_stream_lua_request_cleanup(ctx, 0);

    njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "lua handler aborted: "
                  "user coroutine has no parent");

    return NJT_STREAM_INTERNAL_SERVER_ERROR;

done:


    return NJT_OK;
}


njt_int_t
njt_stream_lua_wev_handler(njt_stream_lua_request_t *r)
{
    njt_int_t                    rc;
    njt_event_t                 *wev;
    njt_connection_t            *c;

    njt_stream_lua_ctx_t                *ctx;

    njt_stream_lua_srv_conf_t   *cllscf;

    njt_stream_lua_socket_tcp_upstream_t       *u;

    c = r->connection;
    wev = c->write;

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        return NJT_ERROR;
    }

    njt_log_debug3(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "lua run write event handler: timedout:%ud, ready:%ud, "
                   "writing_raw_req_socket:%ud",
                   wev->timedout, wev->ready, ctx->writing_raw_req_socket);

    cllscf = njt_stream_lua_get_module_srv_conf(r, njt_stream_lua_module);

    if (wev->timedout && !ctx->writing_raw_req_socket) {
        if (!wev->delayed) {
            njt_log_error(NJT_LOG_INFO, c->log, NJT_ETIMEDOUT,
                          "client timed out");
            c->timedout = 1;

            goto flush_coros;
        }

        wev->timedout = 0;
        wev->delayed = 0;

        if (!wev->ready) {
            njt_add_timer(wev, cllscf->send_timeout);

            if (njt_handle_write_event(wev, cllscf->send_lowat) != NJT_OK) {
                if (ctx->entered_content_phase) {
                    njt_stream_lua_finalize_request(r, NJT_ERROR);
                }

                return NJT_ERROR;
            }
        }
    }

    if (!wev->ready && !wev->timedout) {
        goto useless;
    }

    if (ctx->writing_raw_req_socket) {
        ctx->writing_raw_req_socket = 0;

        u = ctx->downstream;
        if (u == NULL) {
            return NJT_ERROR;
        }

        u->write_event_handler(r, u);
        return NJT_DONE;
    }

    if (c->buffered) {

        rc = njt_stream_lua_flush_pending_output(r, ctx);

        dd("flush pending output returned %d, c->error: %d", (int) rc,
           c->error);

        if (rc != NJT_ERROR && rc != NJT_OK) {
            goto useless;
        }

        /* when rc == NJT_ERROR, c->error must be set */
    }

flush_coros:

    dd("ctx->flushing_coros: %d", (int) ctx->flushing_coros);

    if (ctx->flushing_coros) {
        return njt_stream_lua_process_flushing_coroutines(r, ctx);
    }

    /* ctx->flushing_coros == 0 */

useless:

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "useless lua write event handler");

    if (ctx->entered_content_phase) {
        return NJT_OK;
    }

    return NJT_DONE;
}


static njt_int_t
njt_stream_lua_process_flushing_coroutines(njt_stream_lua_request_t *r,
    njt_stream_lua_ctx_t *ctx)
{
    njt_int_t                    rc, n;
    njt_uint_t                   i;
    njt_list_part_t             *part;

    njt_stream_lua_co_ctx_t             *coctx;

    dd("processing flushing coroutines");

    coctx = &ctx->entry_co_ctx;
    n = ctx->flushing_coros;

    if (coctx->flushing) {
        coctx->flushing = 0;

        ctx->flushing_coros--;
        n--;
        ctx->cur_co_ctx = coctx;

        rc = njt_stream_lua_flush_resume_helper(r, ctx);
        if (rc == NJT_ERROR || rc >= NJT_OK) {
            return rc;
        }

        /* rc == NJT_DONE */
    }

    if (n) {

        if (ctx->user_co_ctx == NULL) {
            return NJT_ERROR;
        }

        part = &ctx->user_co_ctx->part;
        coctx = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                coctx = part->elts;
                i = 0;
            }

            if (coctx[i].flushing) {
                coctx[i].flushing = 0;
                ctx->flushing_coros--;
                n--;
                ctx->cur_co_ctx = &coctx[i];

                rc = njt_stream_lua_flush_resume_helper(r, ctx);
                if (rc == NJT_ERROR || rc >= NJT_OK) {
                    return rc;
                }

                /* rc == NJT_DONE */

                if (n == 0) {
                    return NJT_DONE;
                }
            }
        }
    }

    if (n) {
        return NJT_ERROR;
    }

    return NJT_DONE;
}


static njt_int_t
njt_stream_lua_flush_pending_output(njt_stream_lua_request_t *r,
    njt_stream_lua_ctx_t *ctx)
{
    njt_int_t           rc;
    njt_chain_t        *cl;
    njt_event_t        *wev;
    njt_connection_t   *c;

    njt_stream_lua_srv_conf_t   *cllscf;

    c = r->connection;
    wev = c->write;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "lua flushing output: buffered 0x%uxd",
                   c->buffered);

    if (ctx->busy_bufs) {
        /* FIXME since cosockets also share this busy_bufs chain, this condition
         * might not be strong enough. better use separate busy_bufs chains. */
        rc = njt_stream_lua_output_filter(r, NULL);

    } else {
        cl = njt_stream_lua_get_flush_chain(r, ctx);
        if (cl == NULL) {
            return NJT_ERROR;
        }

        rc = njt_stream_lua_output_filter(r, cl);
    }

    dd("output filter returned %d", (int) rc);

    if (rc == NJT_ERROR || rc > NJT_OK) {
        return rc;
    }

    if (c->buffered) {

        cllscf = njt_stream_lua_get_module_srv_conf(r, njt_stream_lua_module);

        if (!wev->delayed) {
            njt_add_timer(wev, cllscf->send_timeout);
        }

        if (njt_handle_write_event(wev, cllscf->send_lowat) != NJT_OK) {
            if (ctx->entered_content_phase) {
                njt_stream_lua_finalize_request(r, NJT_ERROR);
            }

            return NJT_ERROR;
        }

        if (ctx->flushing_coros) {
            njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                           "lua flush still waiting: buffered 0x%uxd",
                           c->buffered);

            return NJT_DONE;
        }

    } else {
#if 1
        if (wev->timer_set && !wev->delayed) {
            njt_del_timer(wev);
        }
#endif
    }

    return NJT_OK;
}


u_char *
njt_stream_lua_digest_hex(u_char *dest, const u_char *buf, int buf_len)
{
    njt_md5_t                     md5;
    u_char                        md5_buf[MD5_DIGEST_LENGTH];

    njt_md5_init(&md5);
    njt_md5_update(&md5, buf, buf_len);
    njt_md5_final(md5_buf, &md5);

    return njt_hex_dump(dest, md5_buf, sizeof(md5_buf));
}


void
njt_stream_lua_set_multi_value_table(lua_State *L, int index)
{
    if (index < 0) {
        index = lua_gettop(L) + index + 1;
    }

    lua_pushvalue(L, -2); /* stack: table key value key */
    lua_rawget(L, index);
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1); /* stack: table key value */
        lua_rawset(L, index); /* stack: table */

    } else {
        if (!lua_istable(L, -1)) {
            /* just inserted one value */
            lua_createtable(L, 4, 0);
                /* stack: table key value value table */
            lua_insert(L, -2);
                /* stack: table key value table value */
            lua_rawseti(L, -2, 1);
                /* stack: table key value table */
            lua_insert(L, -2);
                /* stack: table key table value */

            lua_rawseti(L, -2, 2); /* stack: table key table */

            lua_rawset(L, index); /* stack: table */

        } else {
            /* stack: table key value table */
            lua_insert(L, -2); /* stack: table key table value */

            lua_rawseti(L, -2, lua_objlen(L, -2) + 1);
                /* stack: table key table  */
            lua_pop(L, 2); /* stack: table */
        }
    }
}


uintptr_t
njt_stream_lua_escape_uri(u_char *dst, u_char *src, size_t size,
    njt_uint_t type)
{
    njt_uint_t      n;
    uint32_t       *escape;
    static u_char   hex[] = "0123456789ABCDEF";

                    /* " ", "#", "%", "?", %00-%1F, %7F-%FF */

    static uint32_t   uri[] = {
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0x80000029, /* 1000 0000 0000 0000  0000 0000 0010 1001 */

                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    };

                    /* " ", "#", "%", "+", "?", %00-%1F, %7F-%FF */

    static uint32_t   args[] = {
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0x80000829, /* 1000 0000 0000 0000  0000 1000 0010 1001 */

                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    };

                    /* not ALPHA, DIGIT, "-", ".", "_", "~" */

    static uint32_t   uri_component[] = {
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0xfc00987d, /* 1111 1100 0000 0000  1001 1000 0111 1101 */

                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0x78000001, /* 0111 1000 0000 0000  0000 0000 0000 0001 */

                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0xb8000001, /* 1011 1000 0000 0000  0000 0000 0000 0001 */

        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    };

                    /* " ", "#", """, "%", "'", %00-%1F, %7F-%FF */

    static uint32_t   html[] = {
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0x000000ad, /* 0000 0000 0000 0000  0000 0000 1010 1101 */

                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    };

                    /* " ", """, "%", "'", %00-%1F, %7F-%FF */

    static uint32_t   refresh[] = {
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0x00000085, /* 0000 0000 0000 0000  0000 0000 1000 0101 */

                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    };

                    /* " ", "%", %00-%1F */

    static uint32_t   memcached[] = {
        0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0x00000021, /* 0000 0000 0000 0000  0000 0000 0010 0001 */

                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
    };

                    /* mail_auth is the same as memcached */

    static uint32_t  *map[] =
        { uri, args, uri_component, html, refresh, memcached, memcached };

    escape = map[type];

    if (dst == NULL) {

        /* find the number of the characters to be escaped */

        n = 0;

        while (size) {
            if (escape[*src >> 5] & (1 << (*src & 0x1f))) {
                n++;
            }
            src++;
            size--;
        }

        return (uintptr_t) n;
    }

    while (size) {
        if (escape[*src >> 5] & (1 << (*src & 0x1f))) {
            *dst++ = '%';
            *dst++ = hex[*src >> 4];
            *dst++ = hex[*src & 0xf];
            src++;

        } else {
            *dst++ = *src++;
        }
        size--;
    }

    return (uintptr_t) dst;
}


/* XXX we also decode '+' to ' ' */
void
njt_stream_lua_unescape_uri(u_char **dst, u_char **src, size_t size,
    njt_uint_t type)
{
    u_char  *d, *s, ch, c, decoded;
    enum {
        sw_usual = 0,
        sw_quoted,
        sw_quoted_second
    } state;

    d = *dst;
    s = *src;

    state = 0;
    decoded = 0;

    while (size--) {

        ch = *s++;

        switch (state) {
        case sw_usual:
            if (ch == '?'
                && (type & (NJT_UNESCAPE_URI|NJT_UNESCAPE_REDIRECT)))
            {
                *d++ = ch;
                goto done;
            }

            if (ch == '%') {
                state = sw_quoted;
                break;
            }

            if (ch == '+') {
                *d++ = ' ';
                break;
            }

            *d++ = ch;
            break;

        case sw_quoted:

            if (ch >= '0' && ch <= '9') {
                decoded = (u_char) (ch - '0');
                state = sw_quoted_second;
                break;
            }

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                decoded = (u_char) (c - 'a' + 10);
                state = sw_quoted_second;
                break;
            }

            /* the invalid quoted character */

            state = sw_usual;

            *d++ = ch;

            break;

        case sw_quoted_second:

            state = sw_usual;

            if (ch >= '0' && ch <= '9') {
                ch = (u_char) ((decoded << 4) + ch - '0');

                if (type & NJT_UNESCAPE_REDIRECT) {
                    if (ch > '%' && ch < 0x7f) {
                        *d++ = ch;
                        break;
                    }

                    *d++ = '%'; *d++ = *(s - 2); *d++ = *(s - 1);
                    break;
                }

                *d++ = ch;

                break;
            }

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                ch = (u_char) ((decoded << 4) + c - 'a' + 10);

                if (type & NJT_UNESCAPE_URI) {
                    if (ch == '?') {
                        *d++ = ch;
                        goto done;
                    }

                    *d++ = ch;
                    break;
                }

                if (type & NJT_UNESCAPE_REDIRECT) {
                    if (ch == '?') {
                        *d++ = ch;
                        goto done;
                    }

                    if (ch > '%' && ch < 0x7f) {
                        *d++ = ch;
                        break;
                    }

                    *d++ = '%'; *d++ = *(s - 2); *d++ = *(s - 1);
                    break;
                }

                *d++ = ch;

                break;
            }

            /* the invalid quoted character */

            break;
        }
    }

done:

    *dst = d;
    *src = s;
}


static int
njt_stream_lua_req_socket(lua_State *L)
{
    njt_stream_lua_request_t   *r;
    njt_stream_lua_ctx_t       *ctx;

    r = njt_stream_lua_get_req(L);

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no ctx found");
    }

    njt_stream_lua_check_fake_request2(L, r, ctx);

    switch (r->connection->type) {
    case SOCK_STREAM:
        return njt_stream_lua_req_socket_tcp(L);

    case SOCK_DGRAM:
        return njt_stream_lua_req_socket_udp(L);
    }

    /* shouldn't happen */
    njt_log_error(NJT_LOG_EMERG, r->connection->log, 0,
                  "stream unexpected connection type: %d",
                  r->connection->type);

    njt_stream_lua_assert(0);

    return luaL_error(L, "unexpected connection type");
}


void
njt_stream_lua_inject_req_api(njt_log_t *log, lua_State *L)
{
    /* njt.req table */

    lua_createtable(L, 0 /* narr */, 1 /* nrec */);    /* .req */


    lua_pushcfunction(L, njt_stream_lua_req_socket);
    lua_setfield(L, -2, "socket");

    lua_setfield(L, -2, "req");
}




static njt_int_t
njt_stream_lua_handle_exit(lua_State *L, njt_stream_lua_request_t *r,
    njt_stream_lua_ctx_t *ctx)
{

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "lua thread aborting request with status %d",
                   ctx->exit_code);

    njt_stream_lua_cleanup_pending_operation(ctx->cur_co_ctx);

    njt_stream_lua_probe_coroutine_done(r, ctx->cur_co_ctx->co, 1);

    ctx->cur_co_ctx->co_status = NJT_STREAM_LUA_CO_DEAD;


    njt_stream_lua_request_cleanup(ctx, 0);

    if (r->connection->fd == (njt_socket_t) -1) {  /* fake request */
        return ctx->exit_code;
    }


    return ctx->exit_code;
}


void
njt_stream_lua_process_args_option(njt_stream_lua_request_t *r, lua_State *L,
    int table, njt_str_t *args)
{
    u_char              *key;
    size_t               key_len;
    u_char              *value;
    size_t               value_len;
    size_t               len = 0;
    size_t               key_escape = 0;
    uintptr_t            total_escape = 0;
    int                  n;
    int                  i;
    u_char              *p;

    if (table < 0) {
        table = lua_gettop(L) + table + 1;
    }

    n = 0;
    lua_pushnil(L);
    while (lua_next(L, table) != 0) {
        if (lua_type(L, -2) != LUA_TSTRING) {
            luaL_error(L, "attempt to use a non-string key in the "
                       "\"args\" option table");
            return;
        }

        key = (u_char *) lua_tolstring(L, -2, &key_len);

        key_escape = 2 * njt_stream_lua_escape_uri(NULL, key, key_len,
                                                   NJT_ESCAPE_URI_COMPONENT);
        total_escape += key_escape;

        switch (lua_type(L, -1)) {
        case LUA_TNUMBER:
        case LUA_TSTRING:
            value = (u_char *) lua_tolstring(L, -1, &value_len);

            total_escape += 2 * njt_stream_lua_escape_uri(NULL, value,
                                                          value_len,
                                                      NJT_ESCAPE_URI_COMPONENT);

            len += key_len + value_len + (sizeof("=") - 1);
            n++;

            break;

        case LUA_TBOOLEAN:
            if (lua_toboolean(L, -1)) {
                len += key_len;
                n++;
            }

            break;

        case LUA_TTABLE:

            i = 0;
            lua_pushnil(L);
            while (lua_next(L, -2) != 0) {
                if (lua_isboolean(L, -1)) {
                    if (lua_toboolean(L, -1)) {
                        len += key_len;

                    } else {
                        lua_pop(L, 1);
                        continue;
                    }

                } else {
                    value = (u_char *) lua_tolstring(L, -1, &value_len);

                    if (value == NULL) {
                        luaL_error(L, "attempt to use %s as query arg value",
                                   luaL_typename(L, -1));
                        return;
                    }

                    total_escape +=
                        2 * njt_stream_lua_escape_uri(NULL, value,
                                                      value_len,
                                                      NJT_ESCAPE_URI_COMPONENT);

                    len += key_len + value_len + (sizeof("=") - 1);
                }

                if (i++ > 0) {
                    total_escape += key_escape;
                }

                n++;
                lua_pop(L, 1);
            }

            break;

        default:
            luaL_error(L, "attempt to use %s as query arg value",
                       luaL_typename(L, -1));
            return;
        }

        lua_pop(L, 1);
    }

    len += (size_t) total_escape;

    if (n > 1) {
        len += (n - 1) * (sizeof("&") - 1);
    }

    dd("len 1: %d", (int) len);

    if (r) {
        p = njt_palloc(r->pool, len);
        if (p == NULL) {
            luaL_error(L, "no memory");
            return;
        }

    } else {
        p = lua_newuserdata(L, len);
    }

    args->data = p;
    args->len = len;

    i = 0;
    lua_pushnil(L);
    while (lua_next(L, table) != 0) {
        key = (u_char *) lua_tolstring(L, -2, &key_len);

        switch (lua_type(L, -1)) {
        case LUA_TNUMBER:
        case LUA_TSTRING:

            if (total_escape) {
                p = (u_char *) njt_stream_lua_escape_uri(p, key, key_len,
                                                      NJT_ESCAPE_URI_COMPONENT);

            } else {
                dd("shortcut: no escape required");

                p = njt_copy(p, key, key_len);
            }

            *p++ = '=';

            value = (u_char *) lua_tolstring(L, -1, &value_len);

            if (total_escape) {
                p = (u_char *) njt_stream_lua_escape_uri(p, value, value_len,
                                                      NJT_ESCAPE_URI_COMPONENT);

            } else {
                p = njt_copy(p, value, value_len);
            }

            if (i != n - 1) {
                /* not the last pair */
                *p++ = '&';
            }

            i++;

            break;

        case LUA_TBOOLEAN:
            if (lua_toboolean(L, -1)) {
                if (total_escape) {
                    p = (u_char *) njt_stream_lua_escape_uri(p, key, key_len,
                                                      NJT_ESCAPE_URI_COMPONENT);

                } else {
                    dd("shortcut: no escape required");

                    p = njt_copy(p, key, key_len);
                }

                if (i != n - 1) {
                    /* not the last pair */
                    *p++ = '&';
                }

                i++;
            }

            break;

        case LUA_TTABLE:

            lua_pushnil(L);
            while (lua_next(L, -2) != 0) {

                if (lua_isboolean(L, -1)) {
                    if (lua_toboolean(L, -1)) {
                        if (total_escape) {
                            p = (u_char *) njt_stream_lua_escape_uri(p, key,
                                                                     key_len,
                                                      NJT_ESCAPE_URI_COMPONENT);

                        } else {
                            dd("shortcut: no escape required");

                            p = njt_copy(p, key, key_len);
                        }

                    } else {
                        lua_pop(L, 1);
                        continue;
                    }

                } else {

                    if (total_escape) {
                        p = (u_char *)
                                njt_stream_lua_escape_uri(p, key,
                                                          key_len,
                                                      NJT_ESCAPE_URI_COMPONENT);

                    } else {
                        dd("shortcut: no escape required");

                        p = njt_copy(p, key, key_len);
                    }

                    *p++ = '=';

                    value = (u_char *) lua_tolstring(L, -1, &value_len);

                    if (total_escape) {
                        p = (u_char *)
                                njt_stream_lua_escape_uri(p, value,
                                                          value_len,
                                                      NJT_ESCAPE_URI_COMPONENT);

                    } else {
                        p = njt_copy(p, value, value_len);
                    }
                }

                if (i != n - 1) {
                    /* not the last pair */
                    *p++ = '&';
                }

                i++;
                lua_pop(L, 1);
            }

            break;

        default:
            luaL_error(L, "should not reach here");
            return;
        }

        lua_pop(L, 1);
    }

    if (p - args->data != (ssize_t) len) {
        luaL_error(L, "buffer error: %d != %d",
                   (int) (p - args->data), (int) len);
        return;
    }
}



/* XXX njt_open_and_stat_file is static in the core. sigh. */
njt_int_t
njt_stream_lua_open_and_stat_file(u_char *name, njt_open_file_info_t *of,
    njt_log_t *log)
{
    njt_fd_t         fd;
    njt_file_info_t  fi;

    if (of->fd != NJT_INVALID_FILE) {

        if (njt_file_info(name, &fi) == NJT_FILE_ERROR) {
            of->failed = njt_file_info_n;
            goto failed;
        }

        if (of->uniq == njt_file_uniq(&fi)) {
            goto done;
        }

    } else if (of->test_dir) {

        if (njt_file_info(name, &fi) == NJT_FILE_ERROR) {
            of->failed = njt_file_info_n;
            goto failed;
        }

        if (njt_is_dir(&fi)) {
            goto done;
        }
    }

    if (!of->log) {

        /*
         * Use non-blocking open() not to hang on FIFO files, etc.
         * This flag has no effect on a regular files.
         */

        fd = njt_open_file(name, NJT_FILE_RDONLY|NJT_FILE_NONBLOCK,
                           NJT_FILE_OPEN, 0);

    } else {
        fd = njt_open_file(name, NJT_FILE_APPEND, NJT_FILE_CREATE_OR_OPEN,
                           NJT_FILE_DEFAULT_ACCESS);
    }

    if (fd == NJT_INVALID_FILE) {
        of->failed = njt_open_file_n;
        goto failed;
    }

    if (njt_fd_info(fd, &fi) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_CRIT, log, njt_errno,
                      njt_fd_info_n " \"%s\" failed", name);

        if (njt_close_file(fd) == NJT_FILE_ERROR) {
            njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                          njt_close_file_n " \"%s\" failed", name);
        }

        of->fd = NJT_INVALID_FILE;

        return NJT_ERROR;
    }

    if (njt_is_dir(&fi)) {
        if (njt_close_file(fd) == NJT_FILE_ERROR) {
            njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                          njt_close_file_n " \"%s\" failed", name);
        }

        of->fd = NJT_INVALID_FILE;

    } else {
        of->fd = fd;

        if (of->directio <= njt_file_size(&fi)) {
            if (njt_directio_on(fd) == NJT_FILE_ERROR) {
                njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                              njt_directio_on_n " \"%s\" failed", name);

            } else {
                of->is_directio = 1;
            }
        }
    }

done:

    of->uniq = njt_file_uniq(&fi);
    of->mtime = njt_file_mtime(&fi);
    of->size = njt_file_size(&fi);
    of->fs_size = njt_file_fs_size(&fi);
    of->is_dir = njt_is_dir(&fi);
    of->is_file = njt_is_file(&fi);
    of->is_link = njt_is_link(&fi);
    of->is_exec = njt_is_exec(&fi);

    return NJT_OK;

failed:

    of->fd = NJT_INVALID_FILE;
    of->err = njt_errno;

    return NJT_ERROR;
}


njt_chain_t *
njt_stream_lua_chain_get_free_buf(njt_log_t *log, njt_pool_t *p,
    njt_chain_t **free, size_t len)
{
    njt_buf_t    *b;
    njt_chain_t  *cl;
    u_char       *start, *end;

    const njt_buf_tag_t  tag = (njt_buf_tag_t) &njt_stream_lua_module;

    if (*free) {
        cl = *free;
        *free = cl->next;
        cl->next = NULL;

        b = cl->buf;
        start = b->start;
        end = b->end;
        if (start && (size_t) (end - start) >= len) {
            njt_log_debug4(NJT_LOG_DEBUG_STREAM, log, 0,
                           "lua reuse free buf memory %O >= %uz, cl:%p, p:%p",
                           (off_t) (end - start), len, cl, start);

            njt_memzero(b, sizeof(njt_buf_t));

            b->start = start;
            b->pos = start;
            b->last = start;
            b->end = end;
            b->tag = tag;

            if (len) {
                b->temporary = 1;
            }

            return cl;
        }

        njt_log_debug4(NJT_LOG_DEBUG_STREAM, log, 0,
                       "lua reuse free buf chain, but reallocate memory "
                       "because %uz >= %O, cl:%p, p:%p", len,
                       (off_t) (b->end - b->start), cl, b->start);

        if (njt_buf_in_memory(b) && b->start) {
            njt_pfree(p, b->start);
        }

        njt_memzero(b, sizeof(njt_buf_t));

        if (len == 0) {
            return cl;
        }

        b->start = njt_palloc(p, len);
        if (b->start == NULL) {
            return NULL;
        }

        b->end = b->start + len;

        dd("buf start: %p", cl->buf->start);

        b->pos = b->start;
        b->last = b->start;
        b->tag = tag;
        b->temporary = 1;

        return cl;
    }

    cl = njt_alloc_chain_link(p);
    if (cl == NULL) {
        return NULL;
    }

    njt_log_debug2(NJT_LOG_DEBUG_STREAM, log, 0,
                   "lua allocate new chainlink and new buf of size %uz, cl:%p",
                   len, cl);

    cl->buf = len ? njt_create_temp_buf(p, len) : njt_calloc_buf(p);
    if (cl->buf == NULL) {
        return NULL;
    }

    dd("buf start: %p", cl->buf->start);

    cl->buf->tag = tag;
    cl->next = NULL;

    return cl;
}


static int
njt_stream_lua_thread_traceback(lua_State *L, lua_State *co,
    njt_stream_lua_co_ctx_t *coctx)
{
    int         base;
    int         level, coid;
    lua_Debug   ar;

    base = lua_gettop(L);
    lua_checkstack(L, 3);
    lua_pushliteral(L, "stack traceback:");
    coid = 0;

    while (co) {

        if (coid >= NJT_STREAM_LUA_BT_MAX_COROS) {
            break;
        }

        lua_checkstack(L, 2);
        lua_pushfstring(L, "\ncoroutine %d:", coid++);

        level = 0;

        while (lua_getstack(co, level++, &ar)) {

            lua_checkstack(L, 5);

            if (level > NJT_STREAM_LUA_BT_DEPTH) {
                lua_pushliteral(L, "\n\t...");
                break;
            }

            lua_pushliteral(L, "\n\t");
            lua_getinfo(co, "Snl", &ar);
            lua_pushfstring(L, "%s:", ar.short_src);

            if (ar.currentline > 0) {
                lua_pushfstring(L, "%d:", ar.currentline);
            }

            if (*ar.namewhat != '\0') {  /* is there a name? */
                lua_pushfstring(L, " in function " LUA_QS, ar.name);

            } else {
                if (*ar.what == 'm') {  /* main? */
                    lua_pushliteral(L, " in main chunk");

                } else if (*ar.what == 'C' || *ar.what == 't') {
                    lua_pushliteral(L, " ?");  /* C function or tail call */

                } else {
                    lua_pushfstring(L, " in function <%s:%d>",
                                    ar.short_src, ar.linedefined);
                }
            }
        }

        if (lua_gettop(L) - base >= 15) {
            lua_concat(L, lua_gettop(L) - base);
        }

        /* check if the coroutine has a parent coroutine*/
        coctx = coctx->parent_co_ctx;
        if (!coctx || coctx->co_status == NJT_STREAM_LUA_CO_DEAD) {
            break;
        }

        co = coctx->co;
    }

    lua_concat(L, lua_gettop(L) - base);
    return 1;
}


int
njt_stream_lua_traceback(lua_State *L)
{
    if (!lua_isstring(L, 1)) { /* 'message' not a string? */
        return 1;  /* keep it intact */
    }

    lua_getglobal(L, "debug");
    if (!lua_istable(L, -1)) {
        lua_pop(L, 1);
        return 1;
    }

    lua_getfield(L, -1, "traceback");
    if (!lua_isfunction(L, -1)) {
        lua_pop(L, 2);
        return 1;
    }

    lua_pushvalue(L, 1);  /* pass error message */
    lua_pushinteger(L, 2);  /* skip this function and traceback */
    lua_call(L, 2, 1);  /* call debug.traceback */
    return 1;
}




njt_stream_lua_co_ctx_t *
njt_stream_lua_get_co_ctx(lua_State *L, njt_stream_lua_ctx_t *ctx)
{
#ifdef HAVE_LUA_EXDATA2
    return (njt_stream_lua_co_ctx_t *) lua_getexdata2(L);
#else
    njt_uint_t                   i;
    njt_list_part_t             *part;

    njt_stream_lua_co_ctx_t             *coctx;

    if (L == ctx->entry_co_ctx.co) {
        return &ctx->entry_co_ctx;
    }

    if (ctx->user_co_ctx == NULL) {
        return NULL;
    }

    part = &ctx->user_co_ctx->part;
    coctx = part->elts;

    /* FIXME: we should use rbtree here to prevent O(n) lookup overhead */

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            coctx = part->elts;
            i = 0;
        }

        if (coctx[i].co == L) {
            return &coctx[i];
        }
    }

    return NULL;
#endif
}


njt_stream_lua_co_ctx_t *
njt_stream_lua_create_co_ctx(njt_stream_lua_request_t *r,
    njt_stream_lua_ctx_t *ctx)
{
    njt_stream_lua_co_ctx_t             *coctx;

    if (ctx->user_co_ctx == NULL) {
        ctx->user_co_ctx = njt_list_create(r->pool, 4,
                                           sizeof(njt_stream_lua_co_ctx_t));
        if (ctx->user_co_ctx == NULL) {
            return NULL;
        }
    }

    coctx = njt_list_push(ctx->user_co_ctx);
    if (coctx == NULL) {
        return NULL;
    }

    njt_memzero(coctx, sizeof(njt_stream_lua_co_ctx_t));

    coctx->co_ref = LUA_NOREF;

    return coctx;
}


/* this is for callers other than the content handler */
njt_int_t
njt_stream_lua_run_posted_threads(njt_connection_t *c, lua_State *L,
    njt_stream_lua_request_t *r, njt_stream_lua_ctx_t *ctx, njt_uint_t nreqs)
{
    njt_int_t        rc;

    njt_stream_lua_posted_thread_t          *pt;

    for ( ;; ) {
        if (c->destroyed || c->requests != nreqs) {
            return NJT_DONE;
        }

        pt = ctx->posted_threads;
        if (pt == NULL) {
            return NJT_DONE;
        }

        ctx->posted_threads = pt->next;

        njt_stream_lua_probe_run_posted_thread(r, pt->co_ctx->co,
                                               (int) pt->co_ctx->co_status);

        if (pt->co_ctx->co_status != NJT_STREAM_LUA_CO_RUNNING) {
            continue;
        }

        ctx->cur_co_ctx = pt->co_ctx;

        rc = njt_stream_lua_run_thread(L, r, ctx, 0);

        if (rc == NJT_AGAIN) {
            continue;
        }

        if (rc == NJT_DONE) {
            njt_stream_lua_finalize_request(r, NJT_DONE);
            continue;
        }

        /* rc == NJT_ERROR || rc >= NJT_OK */

        if (ctx->entered_content_phase) {
            njt_stream_lua_finalize_request(r, rc);
        }

        return rc;
    }

    /* impossible to reach here */
}


njt_int_t
njt_stream_lua_post_thread(njt_stream_lua_request_t *r,
    njt_stream_lua_ctx_t *ctx, njt_stream_lua_co_ctx_t *coctx)
{
    njt_stream_lua_posted_thread_t        **p;
    njt_stream_lua_posted_thread_t         *pt;

    pt = njt_palloc(r->pool, sizeof(njt_stream_lua_posted_thread_t));
    if (pt == NULL) {
        return NJT_ERROR;
    }

    pt->co_ctx = coctx;
    pt->next = NULL;

    for (p = &ctx->posted_threads; *p; p = &(*p)->next) { /* void */ }

    *p = pt;

    return NJT_OK;
}


static void
njt_stream_lua_finalize_threads(njt_stream_lua_request_t *r,
    njt_stream_lua_ctx_t *ctx, lua_State *L)
{
#ifdef NJT_LUA_USE_ASSERT
    int                              top;
#endif
    int                              inited = 0, ref;
    njt_uint_t                       i;
    njt_list_part_t                 *part;

    njt_stream_lua_co_ctx_t                 *cc, *coctx;

#ifdef NJT_LUA_USE_ASSERT
    top = lua_gettop(L);
#endif

#if 1
    coctx = ctx->on_abort_co_ctx;
    if (coctx && coctx->co_ref != LUA_NOREF) {
        if (coctx->co_status != NJT_STREAM_LUA_CO_SUSPENDED) {
            /* the on_abort thread contributes to the coctx->uthreads
             * counter only when it actually starts running */
            njt_stream_lua_cleanup_pending_operation(coctx);
            ctx->uthreads--;
        }

        njt_stream_lua_probe_thread_delete(r, coctx->co, ctx);

        lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(
                              coroutines_key));
        lua_rawget(L, LUA_REGISTRYINDEX);
        inited = 1;

        luaL_unref(L, -1, coctx->co_ref);
        coctx->co_ref = LUA_NOREF;

        coctx->co_status = NJT_STREAM_LUA_CO_DEAD;
        ctx->on_abort_co_ctx = NULL;
    }
#endif

    if (ctx->user_co_ctx) {
        part = &ctx->user_co_ctx->part;
        cc = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                cc = part->elts;
                i = 0;
            }

            coctx = &cc[i];

            ref = coctx->co_ref;

            if (ref != LUA_NOREF) {
                njt_stream_lua_cleanup_pending_operation(coctx);

                njt_stream_lua_probe_thread_delete(r, coctx->co, ctx);

                if (!inited) {
                    lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(
                                          coroutines_key));
                    lua_rawget(L, LUA_REGISTRYINDEX);
                    inited = 1;
                }

                njt_stream_lua_assert(lua_gettop(L) - top == 1);

                luaL_unref(L, -1, ref);
                coctx->co_ref = LUA_NOREF;

                coctx->co_status = NJT_STREAM_LUA_CO_DEAD;
                ctx->uthreads--;
            }
        }

        ctx->user_co_ctx = NULL;
    }

    njt_stream_lua_assert(ctx->uthreads == 0);

    coctx = &ctx->entry_co_ctx;

    ref = coctx->co_ref;
    if (ref != LUA_NOREF) {
        njt_stream_lua_cleanup_pending_operation(coctx);

        njt_stream_lua_probe_thread_delete(r, coctx->co, ctx);

        if (!inited) {
            lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(
                                  coroutines_key));
            lua_rawget(L, LUA_REGISTRYINDEX);
            inited = 1;
        }

        njt_stream_lua_assert(lua_gettop(L) - top == 1);

        luaL_unref(L, -1, coctx->co_ref);
        coctx->co_ref = LUA_NOREF;
        coctx->co_status = NJT_STREAM_LUA_CO_DEAD;
    }

    if (inited) {
        lua_pop(L, 1);
    }
}


static njt_int_t
njt_stream_lua_post_zombie_thread(njt_stream_lua_request_t *r,
    njt_stream_lua_co_ctx_t *parent, njt_stream_lua_co_ctx_t *thread)
{
    njt_stream_lua_posted_thread_t        **p;
    njt_stream_lua_posted_thread_t         *pt;

    pt = njt_palloc(r->pool, sizeof(njt_stream_lua_posted_thread_t));
    if (pt == NULL) {
        return NJT_ERROR;
    }

    pt->co_ctx = thread;
    pt->next = NULL;

    for (p = &parent->zombie_child_threads; *p; p = &(*p)->next) { /* void */ }

    *p = pt;

    return NJT_OK;
}


static void
njt_stream_lua_cleanup_zombie_child_uthreads(njt_stream_lua_request_t *r,
    lua_State *L, njt_stream_lua_ctx_t *ctx, njt_stream_lua_co_ctx_t *coctx)
{
    njt_stream_lua_posted_thread_t         *pt;

    for (pt = coctx->zombie_child_threads; pt; pt = pt->next) {
        if (pt->co_ctx->co_ref != LUA_NOREF) {
            njt_stream_lua_del_thread(r, L, ctx, pt->co_ctx);
            ctx->uthreads--;
        }
    }

    coctx->zombie_child_threads = NULL;
}


njt_int_t
njt_stream_lua_check_broken_connection(njt_stream_lua_request_t *r,
    njt_event_t *ev)
{
    int                  n;
    char                 buf[1];
    njt_err_t            err;
    njt_int_t            event;
    njt_connection_t    *c;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, ev->log, 0,
                   "stream lua check client, write event:%d", ev->write);

    c = r->connection;

    if (c->error) {
        if ((njt_event_flags & NJT_USE_LEVEL_EVENT) && ev->active) {

            event = ev->write ? NJT_WRITE_EVENT : NJT_READ_EVENT;

            if (njt_del_event(ev, event, 0) != NJT_OK) {
                return NJT_STREAM_INTERNAL_SERVER_ERROR;
            }
        }

        return NJT_ERROR;
    }



#if (NJT_HAVE_KQUEUE)

    if (njt_event_flags & NJT_USE_KQUEUE_EVENT) {

        if (!ev->pending_eof) {
            return NJT_OK;
        }

        ev->eof = 1;

        if (ev->kq_errno) {
            ev->error = 1;
        }

        njt_log_error(NJT_LOG_INFO, ev->log, ev->kq_errno,
                      "kevent() reported that client prematurely closed "
                      "connection");

        return NJT_ERROR;
    }

#endif

    n = recv(c->fd, buf, 1, MSG_PEEK);

    err = njt_socket_errno;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, ev->log, err,
                   "http lua recv(): %d", n);

    if (ev->write && (n >= 0 || err == NJT_EAGAIN)) {
        return NJT_OK;
    }

    if ((njt_event_flags & NJT_USE_LEVEL_EVENT) && ev->active) {
        dd("event is active");

        event = ev->write ? NJT_WRITE_EVENT : NJT_READ_EVENT;

#if 1
        if (njt_del_event(ev, event, 0) != NJT_OK) {
            return NJT_STREAM_INTERNAL_SERVER_ERROR;
        }
#endif
    }

    dd("HERE %d", (int) n);

    if (n > 0) {
        return NJT_OK;
    }

    if (n == -1) {
        if (err == NJT_EAGAIN) {
            dd("HERE");
            return NJT_OK;
        }

        ev->error = 1;

    } else { /* n == 0 */
        err = 0;
    }

    ev->eof = 1;

    njt_log_error(NJT_LOG_INFO, ev->log, err,
                  "stream client prematurely closed connection");

    return NJT_ERROR;
}


void
njt_stream_lua_rd_check_broken_connection(njt_stream_lua_request_t *r)
{
    njt_int_t                   rc;
    njt_event_t                *rev;
    njt_stream_lua_ctx_t       *ctx;


    rc = njt_stream_lua_check_broken_connection(r, r->connection->read);

    if (rc == NJT_OK) {
        return;
    }

    /* rc == NJT_ERROR || rc > NJT_OK */

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        return;
    }

    if (ctx->on_abort_co_ctx == NULL) {
        r->connection->error = 1;
        njt_stream_lua_request_cleanup(ctx, 0);
        njt_stream_lua_finalize_request(r, rc);
        return;
    }

    if (ctx->on_abort_co_ctx->co_status != NJT_STREAM_LUA_CO_SUSPENDED) {

        /* on_abort already run for the current request handler */

        rev = r->connection->read;

        if ((njt_event_flags & NJT_USE_LEVEL_EVENT) && rev->active) {
            if (njt_del_event(rev, NJT_READ_EVENT, 0) != NJT_OK) {
                njt_stream_lua_request_cleanup(ctx, 0);

                njt_stream_lua_finalize_request(r,
                                              NJT_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }
        }

        return;
    }

    ctx->uthreads++;
    ctx->resume_handler = njt_stream_lua_on_abort_resume;
    ctx->on_abort_co_ctx->co_status = NJT_STREAM_LUA_CO_RUNNING;
    ctx->cur_co_ctx = ctx->on_abort_co_ctx;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "lua waking up the on_abort callback thread");

    if (ctx->entered_content_phase) {
        r->write_event_handler = njt_stream_lua_content_wev_handler;

    } else {
        r->write_event_handler = njt_stream_lua_core_run_phases;
    }

    r->write_event_handler(r);
}


static njt_int_t
njt_stream_lua_on_abort_resume(njt_stream_lua_request_t *r)
{
    lua_State                           *vm;
    njt_int_t                            rc;
    njt_uint_t                           nreqs;
    njt_connection_t                    *c;
    njt_stream_lua_ctx_t                *ctx;

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        return NJT_ERROR;
    }

    ctx->resume_handler = njt_stream_lua_wev_handler;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "lua resuming the on_abort callback thread");

#if 0
    njt_stream_lua_probe_info("tcp resume");
#endif

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




void
njt_stream_lua_finalize_request(njt_stream_lua_request_t *r, njt_int_t rc)
{
    njt_stream_lua_ctx_t                    *ctx;

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx && ctx->cur_co_ctx) {
        njt_stream_lua_cleanup_pending_operation(ctx->cur_co_ctx);
    }

    if (r->connection->fd != (njt_socket_t) -1) {

        njt_stream_lua_finalize_real_request(r, rc);

        return;
    }

    njt_stream_lua_finalize_fake_request(r, rc);
}


void
njt_stream_lua_finalize_fake_request(njt_stream_lua_request_t *r, njt_int_t rc)
{
    njt_connection_t          *c;

#if (NJT_STREAM_SSL)
    njt_ssl_conn_t            *ssl_conn;

    njt_stream_lua_ssl_ctx_t          *cctx;
#endif

    c = r->connection;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "stream lua finalize fake request: %d", rc);

    if (rc == NJT_DONE) {


        return;
    }

    if (rc == NJT_ERROR || rc >= NJT_STREAM_BAD_REQUEST) {

#if (NJT_STREAM_SSL)

        if (r->connection->ssl) {
            ssl_conn = r->connection->ssl->connection;
            if (ssl_conn) {
                c = njt_ssl_get_connection(ssl_conn);

                if (c && c->ssl) {
                    cctx = njt_stream_lua_ssl_get_ctx(c->ssl->connection);
                    if (cctx != NULL) {
                        cctx->exit_code = 0;
                    }
                }
            }
        }

#endif

        njt_stream_lua_close_fake_request(r);
        return;
    }

    if (c->read->timer_set) {
        njt_del_timer(c->read);
    }

    if (c->write->timer_set) {
        c->write->delayed = 0;
        njt_del_timer(c->write);
    }

    njt_stream_lua_close_fake_request(r);
}


static void
njt_stream_lua_close_fake_request(njt_stream_lua_request_t *r)
{
    njt_connection_t  *c;


    c = r->connection;



    njt_stream_lua_free_fake_request(r);
    njt_stream_lua_close_fake_connection(c);
}


void
njt_stream_lua_free_fake_request(njt_stream_lua_request_t *r)
{
    njt_log_t                 *log;

    njt_stream_lua_cleanup_t  *cln;

    log = r->connection->log;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, log, 0, "stream lua close fake "
                   "request");

    if (r->pool == NULL) {
        njt_log_error(NJT_LOG_ALERT, log, 0, "stream lua fake request "
                      "already closed");
        return;
    }

    cln = r->cleanup;
    r->cleanup = NULL;

    while (cln) {
        if (cln->handler) {
            cln->handler(cln->data);
        }

        cln = cln->next;
    }


    r->connection->destroyed = 1;
}


void
njt_stream_lua_close_fake_connection(njt_connection_t *c)
{
    njt_pool_t          *pool;
    njt_connection_t    *saved_c = NULL;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "stream lua close fake stream connection %p", c);

    c->destroyed = 1;

    pool = c->pool;

    if (c->read->timer_set) {
        njt_del_timer(c->read);
    }

    if (c->write->timer_set) {
        njt_del_timer(c->write);
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

    if (pool) {
        njt_destroy_pool(pool);
    }
}


njt_int_t
njt_stream_lua_init_vm(lua_State **new_vm, lua_State *parent_vm,
    njt_cycle_t *cycle, njt_pool_t *pool,
    njt_stream_lua_main_conf_t *lmcf, njt_log_t *log,
    njt_pool_cleanup_t **pcln)
{
    int                              rc;
    lua_State                       *L;
    njt_uint_t                       i;
    njt_pool_cleanup_t              *cln;

    njt_stream_lua_preload_hook_t           *hook;
    njt_stream_lua_vm_state_t               *state;

    cln = njt_pool_cleanup_add(pool, 0);
    if (cln == NULL) {
        return NJT_ERROR;
    }

    /* create new Lua VM instance */
    L = njt_stream_lua_new_state(parent_vm, cycle, lmcf, log);
    if (L == NULL) {
        return NJT_ERROR;
    }

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, log, 0, "lua initialize the "
                   "global Lua VM %p", L);

    /* register cleanup handler for Lua VM */
    cln->handler = njt_stream_lua_cleanup_vm;

    state = njt_alloc(sizeof(njt_stream_lua_vm_state_t), log);
    if (state == NULL) {
        return NJT_ERROR;
    }
    state->vm = L;
    state->count = 1;

    cln->data = state;

    if (lmcf->vm_cleanup == NULL) {
        /* this assignment will happen only once,
         * and also only for the main Lua VM */
        lmcf->vm_cleanup = cln;
    }

    if (pcln) {
        *pcln = cln;
    }

#ifdef OPENRESTY_LUAJIT
    /* load FFI library first since cdata needs it */
    luaopen_ffi(L);
#endif

    if (lmcf->preload_hooks) {

        /* register the 3rd-party module's preload hooks */

        lua_getglobal(L, "package");
        lua_getfield(L, -1, "preload");

        hook = lmcf->preload_hooks->elts;

        for (i = 0; i < lmcf->preload_hooks->nelts; i++) {

            njt_stream_lua_probe_register_preload_package(L,
                                                          hook[i].package);

            lua_pushcfunction(L, hook[i].loader);
            lua_setfield(L, -2, (char *) hook[i].package);
        }

        lua_pop(L, 2);
    }

    *new_vm = L;

    lua_getglobal(L, "require");
    lua_pushstring(L, "resty.core");

    rc = lua_pcall(L, 1, 1, 0);
    if (rc != 0) {
        return NJT_DECLINED;
    }

#ifdef OPENRESTY_LUAJIT
    njt_stream_lua_inject_global_write_guard(L, log);
#endif

    return NJT_OK;
}


void
njt_stream_lua_cleanup_vm(void *data)
{
    lua_State                       *L;
    njt_stream_lua_vm_state_t       *state = data;

#if (DDEBUG)
    if (state) {
        dd("cleanup VM: c:%d, s:%p", (int) state->count, state->vm);
    }
#endif

    if (state) {
        njt_log_debug1(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0,
                       "stream lua decrementing the reference count "
                       "for Lua VM: %i", state->count);

        if (--state->count == 0) {
            L = state->vm;

            njt_stream_lua_cleanup_conn_pools(L);

            njt_log_debug1(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0,
                           "stream lua close the global Lua VM %p", L);
            lua_close(L);
            njt_free(state);
        }
    }
}


njt_connection_t *
njt_stream_lua_create_fake_connection(njt_pool_t *pool)
{
    njt_log_t               *log;
    njt_connection_t        *c;
    njt_connection_t        *saved_c = NULL;

    /* (we temporarily use a valid fd (0) to make njt_get_connection happy) */
    if (njt_cycle->files) {
        saved_c = njt_cycle->files[0];
    }

    c = njt_get_connection(0, njt_cycle->log);

    if (njt_cycle->files) {
        njt_cycle->files[0] = saved_c;
    }

    if (c == NULL) {
        return NULL;
    }

    c->fd = (njt_socket_t) -1;
    c->number = njt_atomic_fetch_add(njt_connection_counter, 1);

    if (pool) {
        c->pool = pool;

    } else {
        c->pool = njt_create_pool(128, c->log);
        if (c->pool == NULL) {
            goto failed;
        }
    }

    log = njt_pcalloc(c->pool, sizeof(njt_log_t));
    if (log == NULL) {
        goto failed;
    }

    c->log = log;
    c->log->connection = c->number;
    c->log->action = NULL;
    c->log->data = NULL;

    c->log_error = NJT_ERROR_INFO;

#if 0
    c->buffer = njt_create_temp_buf(c->pool, 2);
    if (c->buffer == NULL) {
        goto failed;
    }

    c->buffer->start[0] = CR;
    c->buffer->start[1] = LF;
#endif

    c->error = 1;

    dd("created fake connection: %p", c);

    return c;

failed:

    njt_stream_lua_close_fake_connection(c);
    return NULL;
}


njt_stream_session_t *
njt_stream_lua_create_fake_session(njt_connection_t *c)
{
    njt_stream_session_t      *s;

    s = njt_pcalloc(c->pool, sizeof(njt_stream_session_t));
    if (s == NULL) {
        return NULL;
    }

    s->ctx = njt_pcalloc(c->pool, sizeof(void *) * njt_stream_max_module);
    if (s->ctx == NULL) {
        return NULL;
    }

    s->connection = c;

    c->data = s;
    s->signature = NJT_STREAM_MODULE;

    dd("created fake session %p", s);

    return s;
}


njt_stream_lua_request_t *
njt_stream_lua_create_fake_request(njt_stream_session_t *s)
{
    njt_stream_lua_request_t      *r;

    r = njt_pcalloc(s->connection->pool, sizeof(njt_stream_lua_request_t));
    if (r == NULL) {
        return NULL;
    }

    r->connection = s->connection;
    r->session = s;
    r->pool = s->connection->pool;

    return r;
}


njt_int_t
njt_stream_lua_report(njt_log_t *log, lua_State *L, int status,
    const char *prefix)
{
    const char      *msg;

    if (status && !lua_isnil(L, -1)) {
        msg = lua_tostring(L, -1);
        if (msg == NULL) {
            msg = "unknown error";
        }

        njt_log_error(NJT_LOG_ERR, log, 0, "%s error: %s", prefix, msg);
        lua_pop(L, 1);
    }

    /* force a full garbage-collection cycle */
    lua_gc(L, LUA_GCCOLLECT, 0);

    return status == 0 ? NJT_OK : NJT_ERROR;
}


int
njt_stream_lua_do_call(njt_log_t *log, lua_State *L)
{
    int                 status, base;
#if (NJT_PCRE)
    njt_pool_t         *old_pool;
#endif

    base = lua_gettop(L);  /* function index */
    lua_pushcfunction(L, njt_stream_lua_traceback);
                                                   /* push traceback function */
    lua_insert(L, base);  /* put it under chunk and args */

#if (NJT_PCRE)
    old_pool = njt_stream_lua_pcre_malloc_init(njt_cycle->pool);
#endif

    status = lua_pcall(L, 0, 0, base);

#if (NJT_PCRE)
    njt_stream_lua_pcre_malloc_done(old_pool);
#endif

    lua_remove(L, base);

    return status;
}


static int
njt_stream_lua_get_raw_phase_context(lua_State *L)
{
    njt_stream_lua_request_t        *r;
    njt_stream_lua_ctx_t            *ctx;

#ifdef OPENRESTY_LUAJIT
    r = lua_getexdata(L);
#else
    r = lua_touserdata(L, 1);
#endif

    if (r == NULL) {
        return 0;
    }

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        return 0;
    }

    lua_pushinteger(L, (int) ctx->context);
    return 1;
}




void
njt_stream_lua_cleanup_free(njt_stream_lua_request_t *r,
    njt_stream_lua_cleanup_pt *cleanup)
{
    njt_stream_lua_cleanup_t        **last;
    njt_stream_lua_cleanup_t         *cln;
    njt_stream_lua_ctx_t             *ctx;

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        return;
    }


    cln = (njt_stream_lua_cleanup_t *)
          ((u_char *) cleanup - offsetof(njt_stream_lua_cleanup_t, handler));

    dd("cln: %p, cln->handler: %p, &cln->handler: %p",
       cln, cln->handler, &cln->handler);

    last = &r->cleanup;

    while (*last) {
        if (*last == cln) {
            *last = cln->next;

            cln->next = ctx->free_cleanup;
            ctx->free_cleanup = cln;

            njt_log_debug1(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                           "lua stream cleanup free: %p", cln);

            return;
        }

        last = &(*last)->next;
    }
}


#if (NJT_STREAM_LUA_HAVE_SA_RESTART)
void
njt_stream_lua_set_sa_restart(njt_log_t *log)
{
    int                    *signo;
    int                     sigs[] = NJT_STREAM_LUA_SA_RESTART_SIGS;
    struct sigaction        act;

    for (signo = sigs; *signo != 0; signo++) {
        njt_log_debug1(NJT_LOG_DEBUG_STREAM, log, 0,
                       "setting SA_RESTART for signal %d", *signo);

        if (sigaction(*signo, NULL, &act) != 0) {
            njt_log_error(NJT_LOG_WARN, log, njt_errno, "failed to get "
                          "sigaction for signal %d", *signo);
        }

        act.sa_flags |= SA_RESTART;

        if (sigaction(*signo, &act, NULL) != 0) {
            njt_log_error(NJT_LOG_WARN, log, njt_errno, "failed to set "
                          "sigaction for signal %d", *signo);
        }
    }
}
#endif


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
