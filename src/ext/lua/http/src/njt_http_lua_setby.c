
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.yy
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_http_lua_setby.h"
#include "njt_http_lua_exception.h"
#include "njt_http_lua_util.h"
#include "njt_http_lua_pcrefix.h"
#include "njt_http_lua_log.h"
#include "njt_http_lua_string.h"
#include "njt_http_lua_misc.h"
#include "njt_http_lua_consts.h"
#include "njt_http_lua_shdict.h"
#include "njt_http_lua_util.h"


static void njt_http_lua_set_by_lua_env(lua_State *L, njt_http_request_t *r,
    size_t nargs, njt_http_variable_value_t *args);


njt_int_t
njt_http_lua_set_by_chunk(lua_State *L, njt_http_request_t *r, njt_str_t *val,
    njt_http_variable_value_t *args, size_t nargs, njt_str_t *script)
{
    size_t           i;
    njt_int_t        rc;
    u_char          *err_msg;
    size_t           len;
    u_char          *data;
#if (NJT_PCRE)
    njt_pool_t      *old_pool;
#endif

    dd("nargs: %d", (int) nargs);

    dd("set Lua VM panic handler");

    lua_atpanic(L, njt_http_lua_atpanic);

    NJT_LUA_EXCEPTION_TRY {
        dd("initialize njet context in Lua VM, code chunk at "
           "stack top    sp = 1");
        njt_http_lua_set_by_lua_env(L, r, nargs, args);

        /*  passing directive arguments to the user code */
        for (i = 0; i < nargs; i++) {
            lua_pushlstring(L, (const char *) args[i].data, args[i].len);
        }

#if (NJT_PCRE)
        /* XXX: work-around to njet regex subsystem */
        old_pool = njt_http_lua_pcre_malloc_init(r->pool);
#endif

        lua_pushcfunction(L, njt_http_lua_traceback);
        lua_insert(L, 1);  /* put it under chunk and args */

        dd("protected call user code");

        rc = lua_pcall(L, nargs, 1, 1);

        dd("after protected call user code");

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
                          "failed to run set_by_lua*: %*s", len, err_msg);

            lua_settop(L, 0);    /*  clear remaining elems on stack */

            return NJT_ERROR;
        }

        data = (u_char *) lua_tolstring(L, -1, &len);

        if (data) {
            val->data = njt_palloc(r->pool, len);
            if (val->data == NULL) {
                return NJT_ERROR;
            }

            njt_memcpy(val->data, data, len);
            val->len = len;

        } else {
            val->data = NULL;
            val->len = 0;
        }

    } NJT_LUA_EXCEPTION_CATCH {

        dd("njet execution restored");
        return NJT_ERROR;
    }

    /*  clear Lua stack */
    lua_settop(L, 0);

    return NJT_OK;
}


void
njt_http_lua_ffi_get_setby_param(njt_http_request_t *r, int idx,
    u_char **data_p, size_t *len_p)
{
    int         n;

    njt_http_variable_value_t       *v;
    njt_http_lua_main_conf_t        *lmcf;

    idx--;

    lmcf = njt_http_get_module_main_conf(r, njt_http_lua_module);

    /*  get number of args from lmcf */
    n = lmcf->setby_nargs;

    /*  get args from lmcf */
    v = lmcf->setby_args;

    if (idx < 0 || idx > n - 1) {
        *len_p = 0;

    } else {
        *data_p = v[idx].data;
        *len_p = v[idx].len;
    }
}


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
njt_http_lua_set_by_lua_env(lua_State *L, njt_http_request_t *r, size_t nargs,
    njt_http_variable_value_t *args)
{
    njt_http_lua_main_conf_t        *lmcf;

    njt_http_lua_set_req(L, r);

    lmcf = njt_http_get_module_main_conf(r, njt_http_lua_module);

    lmcf->setby_nargs = nargs;
    lmcf->setby_args = args;

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
    /* the metatable for the new env */
    lua_createtable(L, 0 /* narr */, 1 /* nrec */);
    njt_http_lua_get_globals_table(L);
    lua_setfield(L, -2, "__index");
    lua_setmetatable(L, -2);    /*  setmetatable(newt, {__index = _G}) */
    /*  }}} */

    lua_setfenv(L, -2);    /*  set new running env for the code closure */
#endif
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
