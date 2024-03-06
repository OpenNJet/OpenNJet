
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_http_lua_directive.h"
#include "njt_http_lua_logby.h"
#include "njt_http_lua_exception.h"
#include "njt_http_lua_util.h"
#include "njt_http_lua_pcrefix.h"
#include "njt_http_lua_log.h"
#include "njt_http_lua_cache.h"
#include "njt_http_lua_headers.h"
#include "njt_http_lua_string.h"
#include "njt_http_lua_misc.h"
#include "njt_http_lua_consts.h"
#include "njt_http_lua_shdict.h"
#if (NJT_HTTP_LUA_HAVE_MALLOC_TRIM)
#include <malloc.h>
#endif


static njt_int_t njt_http_lua_log_by_chunk(lua_State *L, njt_http_request_t *r);


static void
njt_http_lua_log_by_lua_env(lua_State *L, njt_http_request_t *r)
{
    njt_http_lua_set_req(L, r);

#ifndef OPENRESTY_LUAJIT
    /**
     * we want to create empty environment for current script
     *
     * newt = {}
     * newt["_G"] = newt
     * setmetatable(newt, {__index = _G})
     *
     * if a function or symbol is not defined in our env, __index will lookup
     * in the global env.
     *
     * all variables created in the script-env will be thrown away at the end
     * of the script run.
     * */
    njt_http_lua_create_new_globals_table(L, 0 /* narr */, 1 /* nrec */);

    /*  {{{ make new env inheriting main thread's globals table */
    lua_createtable(L, 0, 1);    /*  the metatable for the new env */
    njt_http_lua_get_globals_table(L);
    lua_setfield(L, -2, "__index");
    lua_setmetatable(L, -2);    /*  setmetatable({}, {__index = _G}) */
    /*  }}} */

    lua_setfenv(L, -2);    /*  set new running env for the code closure */
#endif /* OPENRESTY_LUAJIT */
}


njt_int_t
njt_http_lua_log_handler(njt_http_request_t *r)
{
#if (NJT_HTTP_LUA_HAVE_MALLOC_TRIM)
    njt_uint_t                   trim_cycle, trim_nreq;
    njt_http_lua_main_conf_t    *lmcf;
#if (NJT_DEBUG)
    njt_int_t                    trim_ret;
#endif
#endif
    njt_http_lua_loc_conf_t     *llcf;
    njt_http_lua_ctx_t          *ctx;

#if (NJT_HTTP_LUA_HAVE_MALLOC_TRIM)
    lmcf = njt_http_get_module_main_conf(r, njt_http_lua_module);

    trim_cycle = lmcf->malloc_trim_cycle;

    if (trim_cycle > 0) {

        dd("cycle: %d", (int) trim_cycle);

        trim_nreq = ++lmcf->malloc_trim_req_count;

        if (trim_nreq >= trim_cycle) {
            lmcf->malloc_trim_req_count = 0;

#if (NJT_DEBUG)
            trim_ret = malloc_trim(1);
            njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "malloc_trim(1) returned %d", trim_ret);
#else
            (void) malloc_trim(1);
#endif
        }
    }
#   if (NJT_DEBUG)
    else {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "malloc_trim() disabled");
    }
#   endif
#endif

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua log handler, uri:\"%V\" c:%ud", &r->uri,
                   r->main->count);

    llcf = njt_http_get_module_loc_conf(r, njt_http_lua_module);

    if (llcf->log_handler == NULL) {
        dd("no log handler found");
        return NJT_DECLINED;
    }

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);

    dd("ctx = %p", ctx);

    if (ctx == NULL) {
        ctx = njt_http_lua_create_ctx(r);
        if (ctx == NULL) {
            return NJT_ERROR;
        }
    }

    ctx->context = NJT_HTTP_LUA_CONTEXT_LOG;

    dd("calling log handler");
    return llcf->log_handler(r);
}


njt_int_t
njt_http_lua_log_handler_inline(njt_http_request_t *r)
{
    lua_State                   *L;
    njt_int_t                    rc;
    njt_http_lua_loc_conf_t     *llcf;

    dd("log by lua inline");

    llcf = njt_http_get_module_loc_conf(r, njt_http_lua_module);

    L = njt_http_lua_get_lua_vm(r, NULL);

    /*  load Lua inline script (w/ cache) sp = 1 */
    rc = njt_http_lua_cache_loadbuffer(r->connection->log, L,
                                       llcf->log_src.value.data,
                                       llcf->log_src.value.len,
                                       &llcf->log_src_ref,
                                       llcf->log_src_key,
                                       (const char *) llcf->log_chunkname);
    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    return njt_http_lua_log_by_chunk(L, r);
}


njt_int_t
njt_http_lua_log_handler_file(njt_http_request_t *r)
{
    lua_State                       *L;
    njt_int_t                        rc;
    u_char                          *script_path;
    njt_http_lua_loc_conf_t         *llcf;
    njt_str_t                        eval_src;

    llcf = njt_http_get_module_loc_conf(r, njt_http_lua_module);

    if (njt_http_complex_value(r, &llcf->log_src, &eval_src) != NJT_OK) {
        return NJT_ERROR;
    }

    script_path = njt_http_lua_rebase_path(r->pool, eval_src.data,
                                           eval_src.len);

    if (script_path == NULL) {
        return NJT_ERROR;
    }

    L = njt_http_lua_get_lua_vm(r, NULL);

    /*  load Lua script file (w/ cache)        sp = 1 */
    rc = njt_http_lua_cache_loadfile(r->connection->log, L, script_path,
                                     &llcf->log_src_ref,
                                     llcf->log_src_key);
    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    return njt_http_lua_log_by_chunk(L, r);
}


njt_int_t
njt_http_lua_log_by_chunk(lua_State *L, njt_http_request_t *r)
{
    njt_int_t        rc;
    u_char          *err_msg;
    size_t           len;
#if (NJT_PCRE)
    njt_pool_t      *old_pool;
#endif

    /*  set Lua VM panic handler */
    lua_atpanic(L, njt_http_lua_atpanic);

    NJT_LUA_EXCEPTION_TRY {

        /* initialize njet context in Lua VM, code chunk at stack top sp = 1 */
        njt_http_lua_log_by_lua_env(L, r);

#if (NJT_PCRE)
        /* XXX: work-around to njet regex subsystem */
        old_pool = njt_http_lua_pcre_malloc_init(r->pool);
#endif

        lua_pushcfunction(L, njt_http_lua_traceback);
        lua_insert(L, 1);  /* put it under chunk and args */

        /*  protected call user code */
        rc = lua_pcall(L, 0, 1, 1);

        lua_remove(L, 1);  /* remove traceback function */

#if (NJT_PCRE)
        /* XXX: work-around to njet regex subsystem */
        njt_http_lua_pcre_malloc_done(old_pool);
#endif

        if (rc != 0) {
            /*  error occurred when running loaded code */
            err_msg = (u_char *) lua_tolstring(L, -1, &len);

            if (err_msg == NULL) {
                err_msg = (u_char *) "unknown reason";
                len = sizeof("unknown reason") - 1;
            }

            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "failed to run log_by_lua*: %*s", len, err_msg);

            lua_settop(L, 0);    /*  clear remaining elems on stack */

            return NJT_ERROR;
        }

    } NJT_LUA_EXCEPTION_CATCH {

        dd("njet execution restored");
        return NJT_ERROR;
    }

    /*  clear Lua stack */
    lua_settop(L, 0);

    return NJT_OK;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
