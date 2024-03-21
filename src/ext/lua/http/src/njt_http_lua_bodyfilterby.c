
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_http_lua_bodyfilterby.h"
#include "njt_http_lua_exception.h"
#include "njt_http_lua_util.h"
#include "njt_http_lua_pcrefix.h"
#include "njt_http_lua_log.h"
#include "njt_http_lua_cache.h"
#include "njt_http_lua_headers.h"
#include "njt_http_lua_string.h"
#include "njt_http_lua_misc.h"
#include "njt_http_lua_consts.h"
#include "njt_http_lua_output.h"


static void njt_http_lua_body_filter_by_lua_env(lua_State *L,
    njt_http_request_t *r, njt_chain_t *in);
static njt_http_output_body_filter_pt njt_http_next_body_filter;


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
njt_http_lua_body_filter_by_lua_env(lua_State *L, njt_http_request_t *r,
    njt_chain_t *in)
{
    njt_http_lua_main_conf_t    *lmcf;

    njt_http_lua_set_req(L, r);

    lmcf = njt_http_get_module_main_conf(r, njt_http_lua_module);
    lmcf->body_filter_chain = in;

#ifndef OPENRESTY_LUAJIT
    /**
     * we want to create empty environment for current script
     *
     * setmetatable({}, {__index = _G})
     *
     * if a function or symbol is not defined in our env, __index will lookup
     * in the global env.
     *
     * all variables created in the script-env will be thrown away at the end
     * of the script run.
     * */
    njt_http_lua_create_new_globals_table(L, 0 /* narr */, 1 /* nrec */);

    /*  {{{ make new env inheriting main thread's globals table */
    lua_createtable(L, 0, 1 /* nrec */);    /*  the metatable for the new
                                                env */
    njt_http_lua_get_globals_table(L);
    lua_setfield(L, -2, "__index");
    lua_setmetatable(L, -2);    /*  setmetatable({}, {__index = _G}) */
    /*  }}} */

    lua_setfenv(L, -2);    /*  set new running env for the code closure */
#endif /* OPENRESTY_LUAJIT */
}


njt_int_t
njt_http_lua_body_filter_by_chunk(lua_State *L, njt_http_request_t *r,
    njt_chain_t *in)
{
    njt_int_t        rc;
    u_char          *err_msg;
    size_t           len;
#if (NJT_PCRE)
    njt_pool_t      *old_pool;
#endif

    dd("initialize njet context in Lua VM, code chunk at stack top  sp = 1");
    njt_http_lua_body_filter_by_lua_env(L, r, in);

#if (NJT_PCRE)
    /* XXX: work-around to njet regex subsystem */
    old_pool = njt_http_lua_pcre_malloc_init(r->pool);
#endif

    lua_pushcfunction(L, njt_http_lua_traceback);
    lua_insert(L, 1);  /* put it under chunk and args */

    dd("protected call user code");
    rc = lua_pcall(L, 0, 1, 1);

    lua_remove(L, 1);  /* remove traceback function */

#if (NJT_PCRE)
    /* XXX: work-around to njet regex subsystem */
    njt_http_lua_pcre_malloc_done(old_pool);
#endif

    if (rc != 0) {

        /*  error occurred */
        err_msg = (u_char *) lua_tolstring(L, -1, &len);

        if (err_msg == NULL) {
            err_msg = (u_char *) "unknown reason";
            len = sizeof("unknown reason") - 1;
        }

        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "failed to run body_filter_by_lua*: %*s", len, err_msg);

        lua_settop(L, 0);    /*  clear remaining elems on stack */

        return NJT_ERROR;
    }

    /* rc == 0 */

    rc = (njt_int_t) lua_tointeger(L, -1);

    dd("got return value: %d", (int) rc);

    lua_settop(L, 0);

    if (rc == NJT_ERROR || rc >= NJT_HTTP_SPECIAL_RESPONSE) {
        return NJT_ERROR;
    }

    return NJT_OK;
}


njt_int_t
njt_http_lua_body_filter_inline(njt_http_request_t *r, njt_chain_t *in)
{
    lua_State                   *L;
    njt_int_t                    rc;
    njt_http_lua_loc_conf_t     *llcf;

    llcf = njt_http_get_module_loc_conf(r, njt_http_lua_module);

    L = njt_http_lua_get_lua_vm(r, NULL);

    /*  load Lua inline script (w/ cache) sp = 1 */
    rc = njt_http_lua_cache_loadbuffer(r->connection->log, L,
                                       llcf->body_filter_src.value.data,
                                       llcf->body_filter_src.value.len,
                                       &llcf->body_filter_src_ref,
                                       llcf->body_filter_src_key,
                                       (const char *)
                                       llcf->body_filter_chunkname);
    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    rc = njt_http_lua_body_filter_by_chunk(L, r, in);

    dd("body filter by chunk returns %d", (int) rc);

    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    return NJT_OK;
}


njt_int_t
njt_http_lua_body_filter_file(njt_http_request_t *r, njt_chain_t *in)
{
    lua_State                       *L;
    njt_int_t                        rc;
    u_char                          *script_path;
    njt_http_lua_loc_conf_t         *llcf;
    njt_str_t                        eval_src;

    llcf = njt_http_get_module_loc_conf(r, njt_http_lua_module);

    /* Eval njet variables in code path string first */
    if (njt_http_complex_value(r, &llcf->body_filter_src, &eval_src)
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
                                     &llcf->body_filter_src_ref,
                                     llcf->body_filter_src_key);
    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    /*  make sure we have a valid code chunk */
    njt_http_lua_assert(lua_isfunction(L, -1));

    rc = njt_http_lua_body_filter_by_chunk(L, r, in);

    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_lua_body_filter(njt_http_request_t *r, njt_chain_t *in)
{
    njt_http_lua_loc_conf_t     *llcf;
    njt_http_lua_ctx_t          *ctx;
    njt_int_t                    rc;
    uint16_t                     old_context;
    njt_pool_cleanup_t          *cln;
    njt_chain_t                 *out;
    njt_chain_t                 *cl, *ln;
    njt_http_lua_main_conf_t    *lmcf;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua body filter for user lua code, uri \"%V\"", &r->uri);

    llcf = njt_http_get_module_loc_conf(r, njt_http_lua_module);

    if (llcf->body_filter_handler == NULL || r->header_only) {
        dd("no body filter handler found");
        return njt_http_next_body_filter(r, in);
    }

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);

    dd("ctx = %p", ctx);

    if (ctx == NULL) {
        ctx = njt_http_lua_create_ctx(r);
        if (ctx == NULL) {
            return NJT_ERROR;
        }
    }

    if (ctx->seen_last_in_filter) {
        for (/* void */; in; in = in->next) {
            dd("mark the buf as consumed: %d", (int) njt_buf_size(in->buf));
            in->buf->pos = in->buf->last;
            in->buf->file_pos = in->buf->file_last;
        }

        in = NULL;

        /* continue to call njt_http_next_body_filter to process cached data */
    }

    if (in != NULL
        && njt_chain_add_copy(r->pool, &ctx->filter_in_bufs, in) != NJT_OK)
    {
        return NJT_ERROR;
    }

    if (ctx->filter_busy_bufs != NULL
        && (r->connection->buffered
            & (NJT_HTTP_LOWLEVEL_BUFFERED | NJT_LOWLEVEL_BUFFERED)))
    {
        /* Socket write buffer was full on last write.
         * Try to write the remain data, if still can not write
         * do not execute body_filter_by_lua otherwise the `in` chain will be
         * replaced by new content from lua and buf of `in` mark as consumed.
         * And then njt_output_chain will call the filter chain again which
         * make all the data cached in the memory and long njt_chain_t link
         * cause CPU 100%.
         */
        rc = njt_http_next_body_filter(r, NULL);

        if (rc == NJT_ERROR) {
            return rc;
        }

        out = NULL;
        njt_chain_update_chains(r->pool,
                                &ctx->free_bufs, &ctx->filter_busy_bufs, &out,
                                (njt_buf_tag_t) &njt_http_lua_body_filter);
        if (rc != NJT_OK
            && ctx->filter_busy_bufs != NULL
            && (r->connection->buffered
                & (NJT_HTTP_LOWLEVEL_BUFFERED | NJT_LOWLEVEL_BUFFERED)))
        {
            njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "waiting body filter busy buffer to be sent");
            return NJT_AGAIN;
        }

        /* continue to process bufs in ctx->filter_in_bufs */
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
    ctx->context = NJT_HTTP_LUA_CONTEXT_BODY_FILTER;

    in = ctx->filter_in_bufs;
    ctx->filter_in_bufs = NULL;

    if (in != NULL) {
        dd("calling body filter handler");
        rc = llcf->body_filter_handler(r, in);

        dd("calling body filter handler returned %d", (int) rc);

        ctx->context = old_context;

        if (rc != NJT_OK) {
            return NJT_ERROR;
        }

        lmcf = njt_http_get_module_main_conf(r, njt_http_lua_module);

        /* lmcf->body_filter_chain is the new buffer chain if
         * body_filter_by_lua set new body content via njt.arg[1] = new_content
         * otherwise it is the original `in` buffer chain.
         */
        out = lmcf->body_filter_chain;

        if (in != out) {
            /* content of body was replaced in
             * njt_http_lua_body_filter_param_set and the buffers was marked
             * as consumed.
             */
            for (cl = in; cl != NULL; cl = ln) {
                ln = cl->next;
                njt_free_chain(r->pool, cl);
            }

            if (out == NULL) {
                /* do not forward NULL to the next filters because the input is
                 * not NULL */
                return NJT_OK;
            }
        }

    } else {
        out = NULL;
    }

    rc = njt_http_next_body_filter(r, out);
    if (rc == NJT_ERROR) {
        return NJT_ERROR;
    }

    njt_chain_update_chains(r->pool,
                            &ctx->free_bufs, &ctx->filter_busy_bufs, &out,
                            (njt_buf_tag_t) &njt_http_lua_body_filter);

    return rc;
}


njt_int_t
njt_http_lua_body_filter_init(void)
{
    dd("calling body filter init");
    njt_http_next_body_filter = njt_http_top_body_filter;
    njt_http_top_body_filter = njt_http_lua_body_filter;

    return NJT_OK;
}


int
njt_http_lua_ffi_get_body_filter_param_eof(njt_http_request_t *r)
{
    njt_chain_t         *cl;
    njt_chain_t         *in;

    njt_http_lua_main_conf_t    *lmcf;

    lmcf = njt_http_get_module_main_conf(r, njt_http_lua_module);
    in = lmcf->body_filter_chain;

    /* asking for the eof argument */

    for (cl = in; cl; cl = cl->next) {
        if (cl->buf->last_buf || cl->buf->last_in_chain) {
            return 1;
        }
    }

    return 0;
}


int
njt_http_lua_ffi_get_body_filter_param_body(njt_http_request_t *r,
    u_char **data_p, size_t *len_p)
{
    size_t               size;
    njt_chain_t         *cl;
    njt_buf_t           *b;
    njt_chain_t         *in;

    njt_http_lua_main_conf_t    *lmcf;

    lmcf = njt_http_get_module_main_conf(r, njt_http_lua_module);
    in = lmcf->body_filter_chain;

    size = 0;

    if (in == NULL) {
        /* being a cleared chain on the Lua land */
        *len_p = 0;
        return NJT_OK;
    }

    if (in->next == NULL) {

        dd("seen only single buffer");

        b = in->buf;
        *data_p = b->pos;
        *len_p = b->last - b->pos;
        return NJT_OK;
    }

    dd("seen multiple buffers");

    for (cl = in; cl; cl = cl->next) {
        b = cl->buf;

        size += b->last - b->pos;

        if (b->last_buf || b->last_in_chain) {
            break;
        }
    }

    /* the buf is need and is not allocated from Lua land yet, return with
     * the actual size */
    *len_p = size;
    return NJT_AGAIN;
}


int
njt_http_lua_ffi_copy_body_filter_param_body(njt_http_request_t *r,
    u_char *data)
{
    u_char              *p;
    njt_chain_t         *cl;
    njt_buf_t           *b;
    njt_chain_t         *in;

    njt_http_lua_main_conf_t    *lmcf;

    lmcf = njt_http_get_module_main_conf(r, njt_http_lua_module);
    in = lmcf->body_filter_chain;

    for (p = data, cl = in; cl; cl = cl->next) {
        b = cl->buf;
        p = njt_copy(p, b->pos, b->last - b->pos);

        if (b->last_buf || b->last_in_chain) {
            break;
        }
    }

    return NJT_OK;
}


int
njt_http_lua_body_filter_param_set(lua_State *L, njt_http_request_t *r,
    njt_http_lua_ctx_t *ctx)
{
    int                      type;
    int                      idx;
    int                      found;
    u_char                  *data;
    size_t                   size;
    unsigned                 last;
    unsigned                 flush = 0;
    njt_buf_t               *b;
    njt_chain_t             *cl;
    njt_chain_t             *in;

    njt_http_lua_main_conf_t    *lmcf;

    idx = luaL_checkint(L, 2);

    dd("index: %d", idx);

    if (idx != 1 && idx != 2) {
        return luaL_error(L, "bad index: %d", idx);
    }

    lmcf = njt_http_get_module_main_conf(r, njt_http_lua_module);

    if (idx == 2) {
        /* overwriting the eof flag */
        last = lua_toboolean(L, 3);

        in = lmcf->body_filter_chain;

        if (last) {
            ctx->seen_last_in_filter = 1;

            /* the "in" chain cannot be NULL and we set the "last_buf" or
             * "last_in_chain" flag in the last buf of "in" */

            for (cl = in; cl; cl = cl->next) {
                if (cl->next == NULL) {
                    if (r == r->main) {
                        cl->buf->last_buf = 1;

                    } else {
                        cl->buf->last_in_chain = 1;
                    }

                    break;
                }
            }

        } else {
            /* last == 0 */

            found = 0;

            for (cl = in; cl; cl = cl->next) {
                b = cl->buf;

                if (b->last_buf) {
                    b->last_buf = 0;
                    found = 1;
                }

                if (b->last_in_chain) {
                    b->last_in_chain = 0;
                    found = 1;
                }

                if (found && b->last == b->pos && !njt_buf_in_memory(b)) {
                    /* make it a special sync buf to make
                     * njt_http_write_filter_module happy. */
                    b->sync = 1;
                }
            }

            ctx->seen_last_in_filter = 0;
        }

        return 0;
    }

    /* idx == 1, overwriting the chunk data */

    type = lua_type(L, 3);

    switch (type) {
    case LUA_TSTRING:
    case LUA_TNUMBER:
        data = (u_char *) lua_tolstring(L, 3, &size);
        break;

    case LUA_TNIL:
        /* discard the buffers */

        in = lmcf->body_filter_chain;

        last = 0;

        for (cl = in; cl; cl = cl->next) {
            b = cl->buf;

            if (b->flush) {
                flush = 1;
            }

            if (b->last_in_chain || b->last_buf) {
                last = 1;
            }

            dd("mark the buf as consumed: %d", (int) njt_buf_size(b));
            b->pos = b->last;
        }

        /* cl == NULL */

        goto done;

    case LUA_TTABLE:
        size = njt_http_lua_calc_strlen_in_table(L, 3 /* index */, 3 /* arg */,
                                                 1 /* strict */);
        data = NULL;
        break;

    default:
        return luaL_error(L, "bad chunk data type: %s",
                          lua_typename(L, type));
    }

    in = lmcf->body_filter_chain;

    last = 0;

    for (cl = in; cl; cl = cl->next) {
        b = cl->buf;

        if (b->flush) {
            flush = 1;
        }

        if (b->last_buf || b->last_in_chain) {
            last = 1;
        }

        dd("mark the buf as consumed: %d", (int) njt_buf_size(cl->buf));
        cl->buf->pos = cl->buf->last;
    }

    /* cl == NULL */

    if (size == 0) {
        goto done;
    }

    cl = njt_http_lua_chain_get_free_buf(r->connection->log, r->pool,
                                         &ctx->free_bufs, size);
    if (cl == NULL) {
        return luaL_error(L, "no memory");
    }

    cl->buf->tag = (njt_buf_tag_t) &njt_http_lua_body_filter;
    if (type == LUA_TTABLE) {
        cl->buf->last = njt_http_lua_copy_str_in_table(L, 3, cl->buf->last);

    } else {
        cl->buf->last = njt_copy(cl->buf->pos, data, size);
    }

done:

    if (last || flush) {
        if (cl == NULL) {
            cl = njt_http_lua_chain_get_free_buf(r->connection->log,
                                                 r->pool,
                                                 &ctx->free_bufs, 0);
            if (cl == NULL) {
                return luaL_error(L, "no memory");
            }

            cl->buf->tag = (njt_buf_tag_t) &njt_http_lua_body_filter;
        }

        if (last) {
            ctx->seen_last_in_filter = 1;

            if (r == r->main) {
                cl->buf->last_buf = 1;

            } else {
                cl->buf->last_in_chain = 1;
            }
        }

        if (flush) {
            cl->buf->flush = 1;
        }
    }

    lmcf->body_filter_chain = cl;

    return 0;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
