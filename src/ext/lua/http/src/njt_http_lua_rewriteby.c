
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.yy
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"

#include <njet.h>
#include "njt_http_lua_rewriteby.h"
#include "njt_http_lua_util.h"
#include "njt_http_lua_exception.h"
#include "njt_http_lua_cache.h"


static njt_int_t njt_http_lua_rewrite_by_chunk(lua_State *L,
    njt_http_request_t *r);


njt_int_t
njt_http_lua_rewrite_handler(njt_http_request_t *r)
{
    njt_http_lua_loc_conf_t     *llcf;
    njt_http_lua_ctx_t          *ctx;
    njt_int_t                    rc;
    njt_http_lua_main_conf_t    *lmcf;

    /* XXX we need to take into account njt_rewrite's location dump */
    if (r->uri_changed) {
        return NJT_DECLINED;
    }

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua rewrite handler, uri:\"%V\" c:%ud", &r->uri,
                   r->main->count);

    lmcf = njt_http_get_module_main_conf(r, njt_http_lua_module);

    if (!lmcf->postponed_to_rewrite_phase_end) {
        njt_http_core_main_conf_t       *cmcf;
        njt_http_phase_handler_t        tmp;
        njt_http_phase_handler_t        *ph;
        njt_http_phase_handler_t        *cur_ph;
        njt_http_phase_handler_t        *last_ph;

        lmcf->postponed_to_rewrite_phase_end = 1;

        cmcf = njt_http_get_module_main_conf(r, njt_http_core_module);

        ph = cmcf->phase_engine.handlers;
        cur_ph = &ph[r->phase_handler];
        last_ph = &ph[cur_ph->next - 1];

#if 0
        if (cur_ph == last_ph) {
            dd("XXX our handler is already the last rewrite phase handler");
        }
#endif

        if (cur_ph < last_ph) {
            dd("swapping the contents of cur_ph and last_ph...");

            tmp      = *cur_ph;

            memmove(cur_ph, cur_ph + 1,
                    (last_ph - cur_ph) * sizeof (njt_http_phase_handler_t));

            *last_ph = tmp;

            r->phase_handler--; /* redo the current ph */

            return NJT_DECLINED;
        }
    }

    llcf = njt_http_get_module_loc_conf(r, njt_http_lua_module);

    if (llcf->rewrite_handler == NULL) {
        dd("no rewrite handler found");
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

    dd("entered? %d", (int) ctx->entered_rewrite_phase);

    if (ctx->entered_rewrite_phase) {
        dd("rewriteby: calling wev handler");
        rc = ctx->resume_handler(r);
        dd("rewriteby: wev handler returns %d", (int) rc);

        if (rc == NJT_OK) {
            rc = NJT_DECLINED;
        }

        if (rc == NJT_DECLINED) {
            if (r->header_sent) {
                dd("header already sent");

                /* response header was already generated in rewrite_by_lua*,
                 * so it is no longer safe to proceed to later phases
                 * which may generate responses again */

                if (!ctx->eof) {
                    dd("eof not yet sent");

                    rc = njt_http_lua_send_chain_link(r, ctx, NULL
                                                     /* indicate last_buf */);
                    if (rc == NJT_ERROR || rc > NJT_OK) {
                        return rc;
                    }
                }

                return NJT_HTTP_OK;
            }

            r->write_event_handler = njt_http_core_run_phases;
            ctx->entered_rewrite_phase = 0;

            return NJT_DECLINED;
        }

        return rc;
    }

    if (ctx->waiting_more_body) {
        return NJT_DONE;
    }

/* http2 read body may break http2 stream process */
#if (NJT_HTTP_V2)
    if (llcf->force_read_body && !ctx->read_body_done && !r->main->stream) {
#else
    if (llcf->force_read_body && !ctx->read_body_done) {
#endif
        r->request_body_in_single_buf = 1;
        r->request_body_in_persistent_file = 1;
        r->request_body_in_clean_file = 1;

        rc = njt_http_read_client_request_body(r,
                                       njt_http_lua_generic_phase_post_read);

        if (rc == NJT_ERROR || rc >= NJT_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        if (rc == NJT_AGAIN) {
            ctx->waiting_more_body = 1;
            return NJT_DONE;
        }
    }

    dd("calling rewrite handler");
    return llcf->rewrite_handler(r);
}


njt_int_t
njt_http_lua_rewrite_handler_inline(njt_http_request_t *r)
{
    lua_State                   *L;
    njt_int_t                    rc;
    njt_http_lua_loc_conf_t     *llcf;

    dd("rewrite by lua inline");

    llcf = njt_http_get_module_loc_conf(r, njt_http_lua_module);
    L = njt_http_lua_get_lua_vm(r, NULL);

    /*  load Lua inline script (w/ cache) sp = 1 */
    rc = njt_http_lua_cache_loadbuffer(r->connection->log, L,
                                       llcf->rewrite_src.value.data,
                                       llcf->rewrite_src.value.len,
                                       &llcf->rewrite_src_ref,
                                       llcf->rewrite_src_key,
                                       (const char *)
                                       llcf->rewrite_chunkname);
    if (rc != NJT_OK) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    return njt_http_lua_rewrite_by_chunk(L, r);
}


njt_int_t
njt_http_lua_rewrite_handler_file(njt_http_request_t *r)
{
    lua_State                       *L;
    njt_int_t                        rc;
    u_char                          *script_path;
    njt_http_lua_loc_conf_t         *llcf;
    njt_str_t                        eval_src;

    llcf = njt_http_get_module_loc_conf(r, njt_http_lua_module);

    if (njt_http_complex_value(r, &llcf->rewrite_src, &eval_src) != NJT_OK) {
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
                                     &llcf->rewrite_src_ref,
                                     llcf->rewrite_src_key);
    if (rc != NJT_OK) {
        if (rc < NJT_HTTP_SPECIAL_RESPONSE) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        return rc;
    }

    return njt_http_lua_rewrite_by_chunk(L, r);
}


static njt_int_t
njt_http_lua_rewrite_by_chunk(lua_State *L, njt_http_request_t *r)
{
    int                      co_ref;
    lua_State               *co;
    njt_int_t                rc;
    njt_uint_t               nreqs;
    njt_event_t             *rev;
    njt_connection_t        *c;
    njt_http_lua_ctx_t      *ctx;
    njt_pool_cleanup_t      *cln;

    njt_http_lua_loc_conf_t     *llcf;

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

    /*  {{{ initialize request context */
    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);

    dd("ctx = %p", ctx);

    if (ctx == NULL) {
        return NJT_ERROR;
    }

    njt_http_lua_reset_ctx(r, L, ctx);

    ctx->entered_rewrite_phase = 1;

    ctx->cur_co_ctx = &ctx->entry_co_ctx;
    ctx->cur_co_ctx->co = co;
    ctx->cur_co_ctx->co_ref = co_ref;
#ifdef NJT_LUA_USE_ASSERT
    ctx->cur_co_ctx->co_top = 1;
#endif

    njt_http_lua_attach_co_ctx_to_L(co, ctx->cur_co_ctx);

    /*  }}} */

    /*  {{{ register njet pool cleanup hooks */
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

    ctx->context = NJT_HTTP_LUA_CONTEXT_REWRITE;

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

    c = r->connection;
    nreqs = c->requests;

    rc = njt_http_lua_run_thread(L, r, ctx, 0);

    if (rc == NJT_ERROR || rc > NJT_OK) {
        return rc;
    }

    if (rc == NJT_AGAIN) {
        rc = njt_http_lua_run_posted_threads(c, L, r, ctx, nreqs);

    } else if (rc == NJT_DONE) {
        njt_http_lua_finalize_request(r, NJT_DONE);
        rc = njt_http_lua_run_posted_threads(c, L, r, ctx, nreqs);
    }

    if (rc == NJT_OK || rc == NJT_DECLINED) {
        if (r->header_sent) {
            dd("header already sent");

            /* response header was already generated in rewrite_by_lua*,
             * so it is no longer safe to proceed to later phases
             * which may generate responses again */

            if (!ctx->eof) {
                dd("eof not yet sent");

                rc = njt_http_lua_send_chain_link(r, ctx, NULL
                                                  /* indicate last_buf */);
                if (rc == NJT_ERROR || rc > NJT_OK) {
                    return rc;
                }
            }

            return NJT_HTTP_OK;
        }

        r->write_event_handler = njt_http_core_run_phases;
        ctx->entered_rewrite_phase = 0;

        return NJT_DECLINED;
    }

    return rc;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
