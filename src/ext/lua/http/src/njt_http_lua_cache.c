
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
#include "njt_http_lua_common.h"
#include "njt_http_lua_cache.h"
#include "njt_http_lua_clfactory.h"
#include "njt_http_lua_util.h"


static u_char *njt_http_lua_gen_file_cache_key_helper(u_char *out,
    const u_char *src, size_t src_len);


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
njt_http_lua_cache_load_code(njt_log_t *log, lua_State *L,
    int *ref, const char *key)
{
#ifndef OPENRESTY_LUAJIT
    int          rc;
    u_char      *err;
#endif

    /*  get code cache table */
    lua_pushlightuserdata(L, njt_http_lua_lightudata_mask(
                          code_cache_key));
    lua_rawget(L, LUA_REGISTRYINDEX);    /*  sp++ */

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, log, 0,
                   "code cache lookup (key='%s', ref=%d)", key, *ref);

    dd("code cache table to load: %p", lua_topointer(L, -1));

    if (!lua_istable(L, -1)) {
        dd("Error: code cache table to load did not exist!!");
        return NJT_ERROR;
    }

    njt_http_lua_assert(key != NULL);

    if (*ref == LUA_NOREF) {
        lua_getfield(L, -1, key); /* cache closure */

    } else {
        if (*ref == LUA_REFNIL) {
            lua_getfield(L, -1, key); /* cache ref */

            if (!lua_isnumber(L, -1)) {
                goto not_found;
            }

            *ref = lua_tonumber(L, -1);

            njt_log_debug2(NJT_LOG_DEBUG_HTTP, log, 0,
                           "code cache setting ref (key='%s', ref=%d)",
                           key, *ref);

            lua_pop(L, 1); /* cache */
        }

        lua_rawgeti(L, -1, *ref); /* cache closure */
    }

    if (lua_isfunction(L, -1)) {
        njt_log_debug2(NJT_LOG_DEBUG_HTTP, log, 0,
                       "code cache hit (key='%s', ref=%d)", key, *ref);

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

not_found:

    dd("Value associated with given key in code cache table is not code "
       "chunk: stack top=%d, top value type=%s\n",
       lua_gettop(L), luaL_typename(L, -1));

    /*  remove cache table and value from stack */
    lua_pop(L, 2);                                /*  sp-=2 */

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, log, 0,
                   "code cache miss (key='%s', ref=%d)", key, *ref);

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
njt_http_lua_cache_store_code(lua_State *L, int *ref, const char *key)
{
#ifndef OPENRESTY_LUAJIT
    int rc;
#endif

    /*  get code cache table */
    lua_pushlightuserdata(L, njt_http_lua_lightudata_mask(
                          code_cache_key));
    lua_rawget(L, LUA_REGISTRYINDEX);

    dd("Code cache table to store: %p", lua_topointer(L, -1));

    if (!lua_istable(L, -1)) {
        dd("Error: code cache table to load did not exist!!");
        return NJT_ERROR;
    }

    njt_http_lua_assert(key != NULL);

    lua_pushvalue(L, -2); /* closure cache closure */

    if (*ref == LUA_NOREF) {
        /*  cache closure by cache key */
        lua_setfield(L, -2, key); /* closure cache */

    } else {
        /*  cache closure with reference */
        *ref = luaL_ref(L, -2); /* closure cache */

        /*  cache reference by cache key */
        lua_pushnumber(L, *ref); /* closure cache ref */
        lua_setfield(L, -2, key); /* closure cache */
    }

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
njt_http_lua_cache_loadbuffer(njt_log_t *log, lua_State *L,
    const u_char *src, size_t src_len, int *cache_ref, const u_char *cache_key,
    const char *name)
{
    int          n;
    njt_int_t    rc;
    const char  *err = NULL;

    n = lua_gettop(L);

    rc = njt_http_lua_cache_load_code(log, L, cache_ref, (char *) cache_key);
    if (rc == NJT_OK) {
        return NJT_OK;
    }

    if (rc == NJT_ERROR) {
        return NJT_ERROR;
    }

    /* rc == NJT_DECLINED */

    /* load closure factory of inline script to the top of lua stack, sp++ */
    rc = njt_http_lua_clfactory_loadbuffer(L, (char *) src, src_len, name);

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
    rc = njt_http_lua_cache_store_code(L, cache_ref, (char *) cache_key);
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
njt_http_lua_cache_loadfile(njt_log_t *log, lua_State *L,
    const u_char *script, int *cache_ref, const u_char *cache_key)
{
    int              n;
    njt_int_t        rc, errcode = NJT_ERROR;
    u_char           buf[NJT_HTTP_LUA_FILE_KEY_LEN + 1];
    const char      *err = NULL;

    n = lua_gettop(L);

    /*  calculate digest of script file path */
    if (cache_key == NULL) {
        dd("CACHE file key not pre-calculated...calculating");

        cache_key = njt_http_lua_gen_file_cache_key_helper(buf, script,
                                                           njt_strlen(script));
        *cache_ref = LUA_NOREF;

    } else {
        dd("CACHE file key already pre-calculated");

        njt_http_lua_assert(cache_ref != NULL && *cache_ref != LUA_NOREF);
    }

    rc = njt_http_lua_cache_load_code(log, L, cache_ref, (char *) cache_key);
    if (rc == NJT_OK) {
        return NJT_OK;
    }

    if (rc == NJT_ERROR) {
        return NJT_ERROR;
    }

    /* rc == NJT_DECLINED */

    /*  load closure factory of script file to the top of lua stack, sp++ */
    rc = njt_http_lua_clfactory_loadfile(L, (char *) script);

    dd("loadfile returns %d (%d)", (int) rc, LUA_ERRFILE);

    if (rc != 0) {
        /*  Oops! error occurred when loading Lua script */
        switch (rc) {
        case LUA_ERRMEM:
            err = "memory allocation error";
            break;

        case LUA_ERRFILE:
            if (errno == ENOENT) {
                errcode = NJT_HTTP_NOT_FOUND;

            } else {
                errcode = NJT_HTTP_SERVICE_UNAVAILABLE;
            }

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
    rc = njt_http_lua_cache_store_code(L, cache_ref, (char *) cache_key);
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


u_char *
njt_http_lua_gen_chunk_cache_key(njt_conf_t *cf, const char *tag,
    const u_char *src, size_t src_len)
{
    u_char      *p, *out;
    size_t       tag_len;

    tag_len = njt_strlen(tag);

    out = njt_palloc(cf->pool, tag_len + NJT_HTTP_LUA_INLINE_KEY_LEN + 2);
    if (out == NULL) {
        return NULL;
    }

    p = njt_copy(out, tag, tag_len);
    p = njt_copy(p, "_", 1);
    p = njt_copy(p, NJT_HTTP_LUA_INLINE_TAG, NJT_HTTP_LUA_INLINE_TAG_LEN);
    p = njt_http_lua_digest_hex(p, src, src_len);
    *p = '\0';

    return out;
}


static u_char *
njt_http_lua_gen_file_cache_key_helper(u_char *out, const u_char *src,
    size_t src_len)
{
    u_char      *p;

    njt_http_lua_assert(out != NULL);

    if (out == NULL) {
        return NULL;
    }

    p = njt_copy(out, NJT_HTTP_LUA_FILE_TAG, NJT_HTTP_LUA_FILE_TAG_LEN);
    p = njt_http_lua_digest_hex(p, src, src_len);
    *p = '\0';

    return out;
}


u_char *
njt_http_lua_gen_file_cache_key(njt_conf_t *cf, const u_char *src,
    size_t src_len)
{
    u_char      *out;

    out = njt_palloc(cf->pool, NJT_HTTP_LUA_FILE_KEY_LEN + 1);
    if (out == NULL) {
        return NULL;
    }

    return njt_http_lua_gen_file_cache_key_helper(out, src, src_len);
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
