
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"

#include "njt_http_lua_headerfilterby.h"
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


static njt_http_output_header_filter_pt njt_http_next_header_filter;


/**
 * Set environment table for the given code closure.
 *
 * Before:
 *         | code closure | <- top
 *         |      ...     |
 *
 * After:
 *         | code closure | <- top
 *         |      ...     |
 * */
static void
njt_http_lua_header_filter_by_lua_env(lua_State *L, njt_http_request_t *r)
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
    lua_createtable(L, 0, 1 /* nrec */);   /* the metatable for the new env */
    njt_http_lua_get_globals_table(L);
    lua_setfield(L, -2, "__index");
    lua_setmetatable(L, -2);    /*  setmetatable({}, {__index = _G}) */
    /*  }}} */

    lua_setfenv(L, -2);    /*  set new running env for the code closure */
#endif /* OPENRESTY_LUAJIT */
}


njt_int_t
njt_http_lua_header_filter_by_chunk(lua_State *L, njt_http_request_t *r)
{
    int              old_exit_code = 0;
    njt_int_t        rc;
    u_char          *err_msg;
    size_t           len;
#if (NJT_PCRE)
    njt_pool_t      *old_pool;
#endif
    njt_http_lua_ctx_t          *ctx;

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
    if (ctx->exited) {
        old_exit_code = ctx->exit_code;
    }

    /*  initialize njet context in Lua VM, code chunk at stack top    sp = 1 */
    njt_http_lua_header_filter_by_lua_env(L, r);

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

    dd("rc == %d", (int) rc);

    if (rc != 0) {
        /*  error occurred when running loaded code */
        err_msg = (u_char *) lua_tolstring(L, -1, &len);

        if (err_msg == NULL) {
            err_msg = (u_char *) "unknown reason";
            len = sizeof("unknown reason") - 1;
        }

        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "failed to run header_filter_by_lua*: %*s", len, err_msg);

        lua_settop(L, 0); /*  clear remaining elems on stack */

        return NJT_ERROR;
    }

    dd("exited: %d, exit code: %d, old exit code: %d",
       (int) ctx->exited, (int) ctx->exit_code, (int) old_exit_code);

#if 1
    /*  clear Lua stack */
    lua_settop(L, 0);
#endif

    if (ctx->exited && ctx->exit_code != old_exit_code) {
        if (ctx->exit_code == NJT_ERROR) {
            return NJT_ERROR;
        }

        dd("finalize request with %d", (int) ctx->exit_code);

        rc = njt_http_filter_finalize_request(r, &njt_http_lua_module,
                                              ctx->exit_code);
        if (rc == NJT_ERROR || rc == NJT_AGAIN) {
            return rc;
        }

        return NJT_DECLINED;
    }

    return NJT_OK;
}


njt_int_t
njt_http_lua_header_filter_inline(njt_http_request_t *r)
{
    lua_State                   *L;
    njt_int_t                    rc;
    njt_http_lua_loc_conf_t     *llcf;

    llcf = njt_http_get_module_loc_conf(r, njt_http_lua_module);

    L = njt_http_lua_get_lua_vm(r, NULL);

    /*  load Lua inline script (w/ cache) sp = 1 */
    rc = njt_http_lua_cache_loadbuffer(r->connection->log, L,
                                       llcf->header_filter_src.value.data,
                                       llcf->header_filter_src.value.len,
                                       &llcf->header_filter_src_ref,
                                       llcf->header_filter_src_key,
                                       (const char *)
                                       llcf->header_filter_chunkname);
    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    dd("calling header filter by chunk");

    return njt_http_lua_header_filter_by_chunk(L, r);
}


njt_int_t
njt_http_lua_header_filter_file(njt_http_request_t *r)
{
    lua_State                       *L;
    njt_int_t                        rc;
    u_char                          *script_path;
    njt_http_lua_loc_conf_t         *llcf;
    njt_str_t                        eval_src;

    llcf = njt_http_get_module_loc_conf(r, njt_http_lua_module);

    /* Eval njet variables in code path string first */
    if (njt_http_complex_value(r, &llcf->header_filter_src, &eval_src)
        != NJT_OK)
    {
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
                                     &llcf->header_filter_src_ref,
                                     llcf->header_filter_src_key);
    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    /*  make sure we have a valid code chunk */
    njt_http_lua_assert(lua_isfunction(L, -1));

    return njt_http_lua_header_filter_by_chunk(L, r);
}


static njt_int_t
njt_http_lua_header_filter(njt_http_request_t *r)
{
    njt_http_lua_loc_conf_t     *llcf;
    njt_http_lua_ctx_t          *ctx;
    njt_int_t                    rc;
    njt_pool_cleanup_t          *cln;
    uint16_t                     old_context;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua header filter for user lua code, uri \"%V\"", &r->uri);

    llcf = njt_http_get_module_loc_conf(r, njt_http_lua_module);

    if (llcf->body_filter_handler) {
        r->filter_need_in_memory = 1;
    }

    if (llcf->header_filter_handler == NULL) {
        dd("no header filter handler found");
        return njt_http_next_header_filter(r);
    }

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);

    dd("ctx = %p", ctx);

    if (ctx == NULL) {
        ctx = njt_http_lua_create_ctx(r);
        if (ctx == NULL) {
            return NJT_ERROR;
        }
    }

    if (ctx->cleanup == NULL) {
        cln = njt_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) {
            return NJT_ERROR;
        }

        cln->handler = njt_http_lua_request_cleanup_handler;
        cln->data = ctx;
        ctx->cleanup = &cln->handler;
    }

    old_context = ctx->context;
    ctx->context = NJT_HTTP_LUA_CONTEXT_HEADER_FILTER;

    dd("calling header filter handler");
    rc = llcf->header_filter_handler(r);

    ctx->context = old_context;

    if (rc == NJT_DECLINED) {
        return NJT_OK;
    }

    if (rc == NJT_AGAIN || rc == NJT_ERROR) {
        return rc;
    }

    return njt_http_next_header_filter(r);
}


njt_int_t
njt_http_lua_header_filter_init(void)
{
    dd("calling header filter init");
    njt_http_next_header_filter = njt_http_top_header_filter;
    njt_http_top_header_filter = njt_http_lua_header_filter;

    return NJT_OK;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
