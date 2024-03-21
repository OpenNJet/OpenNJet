
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_http_lua_contentby.h"
#include "njt_http_lua_util.h"
#include "njt_http_lua_exception.h"
#include "njt_http_lua_cache.h"
#include "njt_http_lua_probe.h"


static void njt_http_lua_content_phase_post_read(njt_http_request_t *r);


njt_int_t
njt_http_lua_content_by_chunk(lua_State *L, njt_http_request_t *r)
{
    int                      co_ref;
    njt_int_t                rc;
    lua_State               *co;
    njt_event_t             *rev;
    njt_http_lua_ctx_t      *ctx;
    njt_pool_cleanup_t      *cln;

    njt_http_lua_loc_conf_t      *llcf;

    dd("content by chunk");

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);

    if (ctx == NULL) {
        ctx = njt_http_lua_create_ctx(r);
        if (ctx == NULL) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

    } else {
        dd("reset ctx");
        njt_http_lua_reset_ctx(r, L, ctx);
    }

    ctx->entered_content_phase = 1;

    /*  {{{ new coroutine to handle request */
    co = njt_http_lua_new_thread(r, L, &co_ref);

    if (co == NULL) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "lua: failed to create new coroutine to handle request");

        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    /*  move code closure to new coroutine */
    lua_xmove(L, co, 1);

#ifndef OPENRESTY_LUAJIT
    /*  set closure's env table to new coroutine's globals table */
    njt_http_lua_get_globals_table(co);
    lua_setfenv(co, -2);
#endif

    /*  save njet request in coroutine globals table */
    njt_http_lua_set_req(co, r);

    ctx->cur_co_ctx = &ctx->entry_co_ctx;
    ctx->cur_co_ctx->co = co;
    ctx->cur_co_ctx->co_ref = co_ref;
#ifdef NJT_LUA_USE_ASSERT
    ctx->cur_co_ctx->co_top = 1;
#endif

    njt_http_lua_attach_co_ctx_to_L(co, ctx->cur_co_ctx);

    /*  {{{ register request cleanup hooks */
    if (ctx->cleanup == NULL) {
        cln = njt_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        cln->handler = njt_http_lua_request_cleanup_handler;
        cln->data = ctx;
        ctx->cleanup = &cln->handler;
    }
    /*  }}} */

    ctx->context = NJT_HTTP_LUA_CONTEXT_CONTENT;

    llcf = njt_http_get_module_loc_conf(r, njt_http_lua_module);

    if (llcf->check_client_abort) {
        r->read_event_handler = njt_http_lua_rd_check_broken_connection;

#if (NJT_HTTP_V2)
        if (!r->stream) {
#endif

        rev = r->connection->read;

        if (!rev->active) {
            if (njt_add_event(rev, NJT_READ_EVENT, 0) != NJT_OK) {
                return NJT_ERROR;
            }
        }

#if (NJT_HTTP_V2)
        }
#endif

    } else {
        r->read_event_handler = njt_http_block_reading;
    }

    rc = njt_http_lua_run_thread(L, r, ctx, 0);

    if (rc == NJT_ERROR || rc >= NJT_OK) {
        return rc;
    }

    if (rc == NJT_AGAIN) {
        return njt_http_lua_content_run_posted_threads(L, r, ctx, 0);
    }

    if (rc == NJT_DONE) {
        return njt_http_lua_content_run_posted_threads(L, r, ctx, 1);
    }

    return NJT_OK;
}


void
njt_http_lua_content_wev_handler(njt_http_request_t *r)
{
    njt_http_lua_ctx_t          *ctx;

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
    if (ctx == NULL) {
        return;
    }

    (void) ctx->resume_handler(r);
}


njt_int_t
njt_http_lua_content_handler(njt_http_request_t *r)
{
    njt_http_lua_loc_conf_t     *llcf;
    njt_http_lua_ctx_t          *ctx;
    njt_int_t                    rc;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua content handler, uri:\"%V\" c:%ud", &r->uri,
                   r->main->count);

    llcf = njt_http_get_module_loc_conf(r, njt_http_lua_module);

    if (llcf->content_handler == NULL) {
        dd("no content handler found");
        return NJT_DECLINED;
    }

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);

    dd("ctx = %p", ctx);

    if (ctx == NULL) {
        ctx = njt_http_lua_create_ctx(r);
        if (ctx == NULL) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    dd("entered? %d", (int) ctx->entered_content_phase);

    if (ctx->waiting_more_body) {
        return NJT_DONE;
    }

    if (ctx->entered_content_phase) {
        dd("calling wev handler");
        rc = ctx->resume_handler(r);
        dd("wev handler returns %d", (int) rc);
        return rc;
    }

    if (llcf->force_read_body && !ctx->read_body_done) {

#if (NJT_HTTP_V2)
        if (r->main->stream && r->headers_in.content_length_n < 0) {
            njt_log_error(NJT_LOG_WARN, r->connection->log, 0,
                          "disable lua_need_request_body, since "
                          "http2 read_body may break http2 stream process");
            goto done;
        }
#endif

#if (NJT_HTTP_V3)
        if (r->http_version == NJT_HTTP_VERSION_30
            && r->headers_in.content_length_n < 0)
        {
            njt_log_error(NJT_LOG_WARN, r->connection->log, 0,
                          "disable lua_need_request_body, since "
                          "http2 read_body may break http2 stream process");
            goto done;
        }
#endif
        r->request_body_in_single_buf = 1;
        r->request_body_in_persistent_file = 1;
        r->request_body_in_clean_file = 1;

        rc = njt_http_read_client_request_body(r,
                                        njt_http_lua_content_phase_post_read);

        if (rc == NJT_ERROR || rc >= NJT_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        if (rc == NJT_AGAIN) {
            ctx->waiting_more_body = 1;

            return NJT_DONE;
        }
    }

#if defined(NJT_HTTP_V3) || defined(NJT_HTTP_V2)

done:

#endif

    dd("setting entered");

    ctx->entered_content_phase = 1;

    dd("calling content handler");
    return llcf->content_handler(r);
}


/* post read callback for the content phase */
static void
njt_http_lua_content_phase_post_read(njt_http_request_t *r)
{
    njt_http_lua_ctx_t  *ctx;

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);

    ctx->read_body_done = 1;

    if (ctx->waiting_more_body) {
        ctx->waiting_more_body = 0;
        njt_http_lua_finalize_request(r, njt_http_lua_content_handler(r));

    } else {
        r->main->count--;
    }
}


njt_int_t
njt_http_lua_content_handler_file(njt_http_request_t *r)
{
    lua_State                       *L;
    njt_int_t                        rc;
    u_char                          *script_path;
    njt_http_lua_loc_conf_t         *llcf;
    njt_str_t                        eval_src;

    llcf = njt_http_get_module_loc_conf(r, njt_http_lua_module);

    if (njt_http_complex_value(r, &llcf->content_src, &eval_src) != NJT_OK) {
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
                                     &llcf->content_src_ref,
                                     llcf->content_src_key);
    if (rc != NJT_OK) {
        if (rc < NJT_HTTP_SPECIAL_RESPONSE) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        return rc;
    }

    /*  make sure we have a valid code chunk */
    njt_http_lua_assert(lua_isfunction(L, -1));

    return njt_http_lua_content_by_chunk(L, r);
}


njt_int_t
njt_http_lua_content_handler_inline(njt_http_request_t *r)
{
    lua_State                   *L;
    njt_int_t                    rc;
    njt_http_lua_loc_conf_t     *llcf;

    llcf = njt_http_get_module_loc_conf(r, njt_http_lua_module);

    L = njt_http_lua_get_lua_vm(r, NULL);

    /*  load Lua inline script (w/ cache) sp = 1 */
    rc = njt_http_lua_cache_loadbuffer(r->connection->log, L,
                                       llcf->content_src.value.data,
                                       llcf->content_src.value.len,
                                       &llcf->content_src_ref,
                                       llcf->content_src_key,
                                       (const char *)
                                       llcf->content_chunkname);
    if (rc != NJT_OK) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    return njt_http_lua_content_by_chunk(L, r);
}


njt_int_t
njt_http_lua_content_run_posted_threads(lua_State *L, njt_http_request_t *r,
    njt_http_lua_ctx_t *ctx, int n)
{
    njt_int_t                        rc;
    njt_http_lua_posted_thread_t    *pt;

    dd("run posted threads: %p", ctx->posted_threads);

    for ( ;; ) {
        pt = ctx->posted_threads;
        if (pt == NULL) {
            goto done;
        }

        ctx->posted_threads = pt->next;

        njt_http_lua_probe_run_posted_thread(r, pt->co_ctx->co,
                                             (int) pt->co_ctx->co_status);

        dd("posted thread status: %d", pt->co_ctx->co_status);

        if (pt->co_ctx->co_status != NJT_HTTP_LUA_CO_RUNNING) {
            continue;
        }

        ctx->cur_co_ctx = pt->co_ctx;

        rc = njt_http_lua_run_thread(L, r, ctx, 0);

        if (rc == NJT_AGAIN) {
            continue;
        }

        if (rc == NJT_DONE) {
            n++;
            continue;
        }

        if (rc == NJT_OK) {
            while (n > 0) {
                njt_http_lua_finalize_request(r, NJT_DONE);
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
        r->main->count++;
        return NJT_DONE;
    }

    /* n > 1 */

    do {
        njt_http_lua_finalize_request(r, NJT_DONE);
    } while (--n > 1);

    return NJT_DONE;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
