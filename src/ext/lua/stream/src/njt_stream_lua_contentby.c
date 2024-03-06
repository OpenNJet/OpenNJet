
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_contentby.c.tt2
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


#include "njt_stream_lua_contentby.h"
#include "njt_stream_lua_util.h"
#include "njt_stream_lua_exception.h"
#include "njt_stream_lua_cache.h"
#include "njt_stream_lua_probe.h"




njt_int_t
njt_stream_lua_content_by_chunk(lua_State *L, njt_stream_lua_request_t *r)
{
    int                      co_ref;
    njt_int_t                rc;
    lua_State               *co;
    njt_event_t             *rev;

    njt_stream_lua_ctx_t                *ctx;
    njt_stream_lua_cleanup_t            *cln;
    njt_stream_lua_loc_conf_t           *llcf;

    dd("content by chunk");

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);

    njt_stream_lua_assert(ctx != NULL);

    dd("reset ctx");
    njt_stream_lua_reset_ctx(r, L, ctx);

    ctx->entered_content_phase = 1;

    /*  {{{ new coroutine to handle request */
    co = njt_stream_lua_new_thread(r, L, &co_ref);

    if (co == NULL) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "lua: failed to create new coroutine to handle request");

        return NJT_ERROR;
    }

    /*  move code closure to new coroutine */
    lua_xmove(L, co, 1);

#ifndef OPENRESTY_LUAJIT
    /*  set closure's env table to new coroutine's globals table */
    njt_stream_lua_get_globals_table(co);
    lua_setfenv(co, -2);
#endif

    /*  save njet request in coroutine globals table */
    njt_stream_lua_set_req(co, r);

    ctx->cur_co_ctx = &ctx->entry_co_ctx;
    ctx->cur_co_ctx->co = co;
    ctx->cur_co_ctx->co_ref = co_ref;
#ifdef NJT_LUA_USE_ASSERT
    ctx->cur_co_ctx->co_top = 1;
#endif

    njt_stream_lua_attach_co_ctx_to_L(co, ctx->cur_co_ctx);

    /*  {{{ register request cleanup hooks */
    if (ctx->cleanup == NULL) {
        cln = njt_stream_lua_cleanup_add(r, 0);
        if (cln == NULL) {
            return NJT_ERROR;
        }

        cln->handler = njt_stream_lua_request_cleanup_handler;
        cln->data = ctx;
        ctx->cleanup = &cln->handler;
    }
    /*  }}} */

    ctx->context = NJT_STREAM_LUA_CONTEXT_CONTENT;

    llcf = njt_stream_lua_get_module_loc_conf(r, njt_stream_lua_module);

    r->connection->read->handler = njt_stream_lua_request_handler;
    r->connection->write->handler = njt_stream_lua_request_handler;

    if (llcf->check_client_abort) {
        r->read_event_handler = njt_stream_lua_rd_check_broken_connection;


        rev = r->connection->read;

        if (!rev->active) {
            if (njt_add_event(rev, NJT_READ_EVENT, 0) != NJT_OK) {
                return NJT_ERROR;
            }
        }


    } else {
        r->read_event_handler = njt_stream_lua_block_reading;
    }

    rc = njt_stream_lua_run_thread(L, r, ctx, 0);

    if (rc == NJT_ERROR || rc >= NJT_OK) {
        return rc;
    }

    if (rc == NJT_AGAIN) {
        return njt_stream_lua_content_run_posted_threads(L, r, ctx, 0);
    }

    if (rc == NJT_DONE) {
        return njt_stream_lua_content_run_posted_threads(L, r, ctx, 1);
    }

    return NJT_OK;
}


void
njt_stream_lua_content_wev_handler(njt_stream_lua_request_t *r)
{
    njt_stream_lua_ctx_t                *ctx;

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        return;
    }

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "lua njt_stream_lua_content_wev_handler");

    (void) ctx->resume_handler(r);
}


void
njt_stream_lua_content_handler(njt_stream_session_t *s)
{
    njt_stream_lua_srv_conf_t     *lscf;
    njt_stream_lua_ctx_t          *ctx;
    njt_int_t                      rc;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream lua content handler");

    lscf = njt_stream_get_module_srv_conf(s, njt_stream_lua_module);

    if (lscf->content_handler == NULL) {
        dd("no content handler found");
        njt_stream_finalize_session(s, NJT_DECLINED);

        return;
    }

    ctx = njt_stream_get_module_ctx(s, njt_stream_lua_module);

    dd("ctx = %p", ctx);

    if (ctx == NULL) {
        ctx = njt_stream_lua_create_ctx(s);
        if (ctx == NULL) {
            njt_stream_finalize_session(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    dd("entered? %d", (int) ctx->entered_content_phase);

    if (ctx->entered_content_phase) {
        dd("calling wev handler");
        rc = ctx->resume_handler(ctx->request);
        dd("wev handler returns %d", (int) rc);

        njt_stream_lua_finalize_request(ctx->request, rc);
        return;
    }

    dd("setting entered");

    ctx->entered_content_phase = 1;

    dd("calling content handler");
    njt_stream_lua_finalize_request(ctx->request,
                                    lscf->content_handler(ctx->request));

    return;
}




njt_int_t
njt_stream_lua_content_handler_file(njt_stream_lua_request_t *r)
{
    lua_State                       *L;
    njt_int_t                        rc;
    u_char                          *script_path;
    njt_str_t                        eval_src;

    njt_stream_lua_loc_conf_t               *llcf;

    llcf = njt_stream_lua_get_module_loc_conf(r, njt_stream_lua_module);

    if (njt_stream_complex_value(r->session, &llcf->content_src, &eval_src)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    script_path = njt_stream_lua_rebase_path(r->pool, eval_src.data,
                                             eval_src.len);

    if (script_path == NULL) {
        return NJT_ERROR;
    }

    L = njt_stream_lua_get_lua_vm(r, NULL);

    /*  load Lua script file (w/ cache)        sp = 1 */
    rc = njt_stream_lua_cache_loadfile(r->connection->log, L, script_path,
                                       llcf->content_src_key);
    if (rc != NJT_OK) {

        return rc;
    }

    /*  make sure we have a valid code chunk */
    njt_stream_lua_assert(lua_isfunction(L, -1));

    return njt_stream_lua_content_by_chunk(L, r);
}


njt_int_t
njt_stream_lua_content_handler_inline(njt_stream_lua_request_t *r)
{
    lua_State                   *L;
    njt_int_t                    rc;

    njt_stream_lua_loc_conf_t           *llcf;

    llcf = njt_stream_lua_get_module_loc_conf(r, njt_stream_lua_module);

    L = njt_stream_lua_get_lua_vm(r, NULL);

    /*  load Lua inline script (w/ cache) sp = 1 */
    rc = njt_stream_lua_cache_loadbuffer(r->connection->log, L,
                                         llcf->content_src.value.data,
                                         llcf->content_src.value.len,
                                         llcf->content_src_key,
                                         (const char *)
                                         llcf->content_chunkname);
    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    return njt_stream_lua_content_by_chunk(L, r);
}


njt_int_t
njt_stream_lua_content_run_posted_threads(lua_State *L,
    njt_stream_lua_request_t *r, njt_stream_lua_ctx_t *ctx, int n)
{
    njt_int_t                        rc;

    njt_stream_lua_posted_thread_t          *pt;

    dd("run posted threads: %p", ctx->posted_threads);

    for ( ;; ) {
        pt = ctx->posted_threads;
        if (pt == NULL) {
            goto done;
        }

        ctx->posted_threads = pt->next;

        njt_stream_lua_probe_run_posted_thread(r, pt->co_ctx->co,
                                               (int) pt->co_ctx->co_status);

        dd("posted thread status: %d", pt->co_ctx->co_status);

        if (pt->co_ctx->co_status != NJT_STREAM_LUA_CO_RUNNING) {
            continue;
        }

        ctx->cur_co_ctx = pt->co_ctx;

        rc = njt_stream_lua_run_thread(L, r, ctx, 0);

        if (rc == NJT_AGAIN) {
            continue;
        }

        if (rc == NJT_DONE) {
            n++;
            continue;
        }

        if (rc == NJT_OK) {
            while (n > 0) {
                njt_stream_lua_finalize_request(r, NJT_DONE);
                n--;
            }

            return NJT_OK;
        }

        /* rc == NJT_ERROR || rc > NJT_OK */

        return rc;
    }

done:

    if (n == 1) {
        return NJT_DONE;
    }

    if (n == 0) {
        return NJT_DONE;
    }

    /* n > 1 */

    do {
        njt_stream_lua_finalize_request(r, NJT_DONE);
    } while (--n > 1);

    return NJT_DONE;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
