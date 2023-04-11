
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_cache.c.tt2
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


#include <njet.h>
#include <njt_md5.h>
#include "njt_stream_lua_common.h"
#include "njt_stream_lua_cache.h"
#include "njt_stream_lua_clfactory.h"
#include "njt_stream_lua_util.h"


/**
 * Find code chunk associated with the given key in code cache,
 * and push it to the top of Lua stack if found.
 *
 * Stack layout before call:
 *         |     ...    | <- top
 *
 * Stack layout after call:
 *         | code chunk | <- top
 *         |     ...    |
 *
 * */
static njt_int_t
njt_stream_lua_cache_load_code(njt_log_t *log, lua_State *L,
    const char *key)
{
#ifndef OPENRESTY_LUAJIT
    int          rc;
    u_char      *err;
#endif

    /*  get code cache table */
    lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(
                          code_cache_key));
    lua_rawget(L, LUA_REGISTRYINDEX);    /*  sp++ */

    dd("Code cache table to load: %p", lua_topointer(L, -1));

    if (!lua_istable(L, -1)) {
        dd("Error: code cache table to load did not exist!!");
        return NJT_ERROR;
    }

    lua_getfield(L, -1, key);    /*  sp++ */

    if (lua_isfunction(L, -1)) {
#ifdef OPENRESTY_LUAJIT
        lua_remove(L, -2);   /*  sp-- */
        return NJT_OK;
#else
        /*  call closure factory to gen new closure */
        rc = lua_pcall(L, 0, 1, 0);
        if (rc == 0) {
            /*  remove cache table from stack, leave code chunk at
             *  top of stack */
            lua_remove(L, -2);   /*  sp-- */
            return NJT_OK;
        }

        if (lua_isstring(L, -1)) {
            err = (u_char *) lua_tostring(L, -1);

        } else {
            err = (u_char *) "unknown error";
        }

        njt_log_error(NJT_LOG_ERR, log, 0,
                      "lua: failed to run factory at key \"%s\": %s",
                      key, err);
        lua_pop(L, 2);
        return NJT_ERROR;
#endif /* OPENRESTY_LUAJIT */
    }

    dd("Value associated with given key in code cache table is not code "
       "chunk: stack top=%d, top value type=%s\n",
       lua_gettop(L), luaL_typename(L, -1));

    /*  remove cache table and value from stack */
    lua_pop(L, 2);                                /*  sp-=2 */

    return NJT_DECLINED;
}


/**
 * Store the closure factory at the top of Lua stack to code cache, and
 * associate it with the given key. Then generate new closure.
 *
 * Stack layout before call:
 *         | code factory | <- top
 *         |     ...      |
 *
 * Stack layout after call:
 *         | code chunk | <- top
 *         |     ...    |
 *
 * */
static njt_int_t
njt_stream_lua_cache_store_code(lua_State *L, const char *key)
{
#ifndef OPENRESTY_LUAJIT
    int rc;
#endif

    /*  get code cache table */
    lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(
                          code_cache_key));
    lua_rawget(L, LUA_REGISTRYINDEX);

    dd("Code cache table to store: %p", lua_topointer(L, -1));

    if (!lua_istable(L, -1)) {
        dd("Error: code cache table to load did not exist!!");
        return NJT_ERROR;
    }

    lua_pushvalue(L, -2); /* closure cache closure */
    lua_setfield(L, -2, key); /* closure cache */

    /*  remove cache table, leave closure factory at top of stack */
    lua_pop(L, 1); /* closure */

#ifndef OPENRESTY_LUAJIT
    /*  call closure factory to generate new closure */
    rc = lua_pcall(L, 0, 1, 0);
    if (rc != 0) {
        dd("Error: failed to call closure factory!!");
        return NJT_ERROR;
    }
#endif

    return NJT_OK;
}


njt_int_t
njt_stream_lua_cache_loadbuffer(njt_log_t *log, lua_State *L,
    const u_char *src, size_t src_len, const u_char *cache_key,
    const char *name)
{
    int          n;
    njt_int_t    rc;
    const char  *err = NULL;

    n = lua_gettop(L);

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, log, 0,
                   "looking up Lua code cache with key '%s'", cache_key);

    rc = njt_stream_lua_cache_load_code(log, L, (char *) cache_key);
    if (rc == NJT_OK) {
        /*  code chunk loaded from cache, sp++ */
        dd("Code cache hit! cache key='%s', stack top=%d, script='%.*s'",
           cache_key, lua_gettop(L), (int) src_len, src);
        return NJT_OK;
    }

    if (rc == NJT_ERROR) {
        return NJT_ERROR;
    }

    /* rc == NJT_DECLINED */

    dd("Code cache missed! cache key='%s', stack top=%d, script='%.*s'",
       cache_key, lua_gettop(L), (int) src_len, src);

    /* load closure factory of inline script to the top of lua stack, sp++ */
    rc = njt_stream_lua_clfactory_loadbuffer(L, (char *) src, src_len, name);

    if (rc != 0) {
        /*  Oops! error occurred when loading Lua script */
        if (rc == LUA_ERRMEM) {
            err = "memory allocation error";

        } else {
            if (lua_isstring(L, -1)) {
                err = lua_tostring(L, -1);

            } else {
                err = "unknown error";
            }
        }

        goto error;
    }

    /*  store closure factory and gen new closure at the top of lua stack to
     *  code cache */
    rc = njt_stream_lua_cache_store_code(L, (char *) cache_key);
    if (rc != NJT_OK) {
        err = "fail to generate new closure from the closure factory";
        goto error;
    }

    return NJT_OK;

error:

    njt_log_error(NJT_LOG_ERR, log, 0,
                  "failed to load inlined Lua code: %s", err);
    lua_settop(L, n);
    return NJT_ERROR;
}


njt_int_t
njt_stream_lua_cache_loadfile(njt_log_t *log, lua_State *L,
    const u_char *script, const u_char *cache_key)
{
    int              n;
    njt_int_t        rc, errcode = NJT_ERROR;
    u_char          *p;
    u_char           buf[NJT_STREAM_LUA_FILE_KEY_LEN + 1];
    const char      *err = NULL;

    n = lua_gettop(L);

    /*  calculate digest of script file path */
    if (cache_key == NULL) {
        dd("CACHE file key not pre-calculated...calculating");
        p = njt_copy(buf, NJT_STREAM_LUA_FILE_TAG, NJT_STREAM_LUA_FILE_TAG_LEN);

        p = njt_stream_lua_digest_hex(p, script, njt_strlen(script));

        *p = '\0';
        cache_key = buf;

    } else {
        dd("CACHE file key already pre-calculated");
    }

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, log, 0,
                   "looking up Lua code cache with key '%s'", cache_key);

    rc = njt_stream_lua_cache_load_code(log, L, (char *) cache_key);
    if (rc == NJT_OK) {
        /*  code chunk loaded from cache, sp++ */
        dd("Code cache hit! cache key='%s', stack top=%d, file path='%s'",
           cache_key, lua_gettop(L), script);
        return NJT_OK;
    }

    if (rc == NJT_ERROR) {
        return NJT_ERROR;
    }

    /* rc == NJT_DECLINED */

    dd("Code cache missed! cache key='%s', stack top=%d, file path='%s'",
       cache_key, lua_gettop(L), script);

    /*  load closure factory of script file to the top of lua stack, sp++ */
    rc = njt_stream_lua_clfactory_loadfile(L, (char *) script);

    dd("loadfile returns %d (%d)", (int) rc, LUA_ERRFILE);

    if (rc != 0) {
        /*  Oops! error occurred when loading Lua script */
        switch (rc) {
        case LUA_ERRMEM:
            err = "memory allocation error";
            break;

        case LUA_ERRFILE:
            errcode = NJT_STREAM_INTERNAL_SERVER_ERROR;
            /* fall through */

        default:
            if (lua_isstring(L, -1)) {
                err = lua_tostring(L, -1);

            } else {
                err = "unknown error";
            }
        }

        goto error;
    }

    /*  store closure factory and gen new closure at the top of lua stack
     *  to code cache */
    rc = njt_stream_lua_cache_store_code(L, (char *) cache_key);
    if (rc != NJT_OK) {
        err = "fail to generate new closure from the closure factory";
        goto error;
    }

    return NJT_OK;

error:

    njt_log_error(NJT_LOG_ERR, log, 0,
                  "failed to load external Lua file \"%s\": %s", script, err);

    lua_settop(L, n);
    return errcode;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
