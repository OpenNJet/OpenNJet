
/*
 * Copyright (C) OpenResty Inc.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include <njet.h>
#include "njt_stream_lua_prereadby.h"
#include "njt_stream_lua_util.h"
#include "njt_stream_lua_exception.h"
#include "njt_stream_lua_cache.h"


static njt_int_t njt_stream_lua_preread_by_chunk(lua_State *L,
    njt_stream_lua_request_t *r);


njt_int_t
njt_stream_lua_preread_handler(njt_stream_session_t *s)
{
    njt_int_t                     rc;
    njt_stream_lua_ctx_t         *ctx;
    njt_stream_lua_srv_conf_t    *lscf;
    njt_stream_lua_main_conf_t   *lmcf;
    njt_stream_lua_request_t     *r;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "lua preread handler");

    lmcf = njt_stream_get_module_main_conf(s, njt_stream_lua_module);

    if (!lmcf->postponed_to_preread_phase_end) {
        njt_stream_core_main_conf_t       *cmcf;
        njt_stream_phase_handler_t         tmp;
        njt_stream_phase_handler_t        *ph;
        njt_stream_phase_handler_t        *cur_ph;
        njt_stream_phase_handler_t        *last_ph;

        lmcf->postponed_to_preread_phase_end = 1;

        cmcf = njt_stream_get_module_main_conf(s, njt_stream_core_module);

        ph = cmcf->phase_engine.handlers;
        cur_ph = &ph[s->phase_handler];
        last_ph = &ph[cur_ph->next - 1];

        if (cur_ph < last_ph) {
            tmp      = *cur_ph;

            njt_memmove(cur_ph, cur_ph + 1, (last_ph - cur_ph)
                        * sizeof (njt_stream_phase_handler_t));

            *last_ph = tmp;

            s->phase_handler--; /* redo the current ph */

            return NJT_DECLINED;
        }
    }

    lscf = njt_stream_get_module_srv_conf(s, njt_stream_lua_module);

    if (lscf->preread_handler == NULL) {
        njt_log_debug0(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "no preread handler found");
        return NJT_DECLINED;
    }

    ctx = njt_stream_get_module_ctx(s, njt_stream_lua_module);

    dd("ctx = %p", ctx);

    if (ctx == NULL) {
        ctx = njt_stream_lua_create_ctx(s);
        if (ctx == NULL) {
            return NJT_STREAM_INTERNAL_SERVER_ERROR;
        }
    }

    r = ctx->request;

    dd("entered? %d", (int) ctx->entered_preread_phase);

    if (ctx->entered_preread_phase) {
        dd("calling wev handler");
        rc = ctx->resume_handler(r);
        dd("wev handler returns %d", (int) rc);

        if (rc == NJT_ERROR || rc > NJT_OK) {
            njt_stream_lua_finalize_request(ctx->request, rc);
            return NJT_DONE;
        }

        if (rc == NJT_DONE && ctx->peek_needs_more_data) {
            return NJT_AGAIN;
        }

        if (rc == NJT_OK || rc == NJT_DONE) {
            return rc;
        }

        return NJT_DECLINED;
    }

    r->connection->read->handler = njt_stream_lua_request_handler;
    r->connection->write->handler = njt_stream_lua_request_handler;

    dd("calling preread handler");
    rc = lscf->preread_handler(r);

    if (rc == NJT_ERROR || rc > NJT_OK) {
        njt_stream_lua_finalize_request(ctx->request, rc);
        return NJT_DONE;
    }

    return rc;
}


njt_int_t
njt_stream_lua_preread_handler_inline(njt_stream_lua_request_t *r)
{
    njt_int_t                    rc;
    lua_State                   *L;
    njt_stream_lua_srv_conf_t   *lscf;

    lscf = njt_stream_lua_get_module_srv_conf(r, njt_stream_lua_module);

    L = njt_stream_lua_get_lua_vm(r, NULL);

    /*  load Lua inline script (w/ cache) sp = 1 */
    rc = njt_stream_lua_cache_loadbuffer(r->connection->log, L,
                                         lscf->preread_src.value.data,
                                         lscf->preread_src.value.len,
                                         lscf->preread_src_key,
                                         (const char *)
                                         lscf->preread_chunkname);

    if (rc != NJT_OK) {
        return NJT_STREAM_INTERNAL_SERVER_ERROR;
    }

    return njt_stream_lua_preread_by_chunk(L, r);
}


njt_int_t
njt_stream_lua_preread_handler_file(njt_stream_lua_request_t *r)
{
    u_char                      *script_path;
    njt_int_t                    rc;
    njt_str_t                    eval_src;
    lua_State                   *L;
    njt_stream_lua_srv_conf_t   *lscf;

    lscf = njt_stream_lua_get_module_srv_conf(r, njt_stream_lua_module);

    /* Eval njet variables in code path string first */
    if (njt_stream_complex_value(r->session, &lscf->preread_src, &eval_src)
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
                                       lscf->preread_src_key);
    if (rc != NJT_OK) {
        return rc;
    }

    /*  make sure we have a valid code chunk */
    njt_stream_lua_assert(lua_isfunction(L, -1));

    return njt_stream_lua_preread_by_chunk(L, r);
}


static njt_int_t
njt_stream_lua_preread_by_chunk(lua_State *L, njt_stream_lua_request_t *r)
{
    int                          co_ref;
    njt_int_t                    rc;
    lua_State                   *co;
    njt_event_t                 *rev;
    njt_connection_t            *c;
    njt_stream_lua_ctx_t        *ctx;
    njt_stream_lua_cleanup_t    *cln;

    njt_stream_lua_srv_conf_t     *lscf;

    /*  {{{ new coroutine to handle request */
    co = njt_stream_lua_new_thread(r, L, &co_ref);

    if (co == NULL) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "lua: failed to create new coroutine "
                      "to handle request");

        return NJT_STREAM_INTERNAL_SERVER_ERROR;
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

    /*  {{{ initialize request context */
    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);

    dd("ctx = %p", ctx);

    if (ctx == NULL) {
        return NJT_ERROR;
    }

    njt_stream_lua_reset_ctx(r, L, ctx);

    ctx->entered_preread_phase = 1;

    ctx->cur_co_ctx = &ctx->entry_co_ctx;
    ctx->cur_co_ctx->co = co;
    ctx->cur_co_ctx->co_ref = co_ref;
#ifdef NJT_LUA_USE_ASSERT
    ctx->cur_co_ctx->co_top = 1;
#endif

    njt_stream_lua_attach_co_ctx_to_L(co, ctx->cur_co_ctx);

    /*  }}} */

    /*  {{{ register request cleanup hooks */
    if (ctx->cleanup == NULL) {
        cln = njt_stream_lua_cleanup_add(r, 0);
        if (cln == NULL) {
            return NJT_STREAM_INTERNAL_SERVER_ERROR;
        }

        cln->handler = njt_stream_lua_request_cleanup_handler;
        cln->data = ctx;
        ctx->cleanup = &cln->handler;
    }
    /*  }}} */

    ctx->context = NJT_STREAM_LUA_CONTEXT_PREREAD;

    lscf = njt_stream_lua_get_module_srv_conf(r, njt_stream_lua_module);

    if (lscf->check_client_abort) {
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

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "preread run thread returned %d", (int) rc);

    if (rc == NJT_ERROR || rc > NJT_OK) {
        return rc;
    }

    c = r->connection;

    if (rc == NJT_AGAIN) {
        rc = njt_stream_lua_run_posted_threads(c, L, r, ctx, 0);

        if (rc == NJT_DONE && ctx->peek_needs_more_data) {
            return NJT_AGAIN;
        }

        if (rc == NJT_ERROR || rc == NJT_DONE || rc > NJT_OK) {
            return rc;
        }

        if (rc != NJT_OK) {
            return NJT_DECLINED;
        }

    } else if (rc == NJT_DONE) {
        njt_stream_lua_finalize_request(r, NJT_DONE);

        rc = njt_stream_lua_run_posted_threads(c, L, r, ctx, 0);

        if (rc == NJT_ERROR || rc == NJT_DONE || rc > NJT_OK) {
            return rc;
        }

        if (rc != NJT_OK) {
            return NJT_DECLINED;
        }
    }

#if 1
    if (rc == NJT_OK) {
        return NJT_OK;
    }
#endif

    return NJT_DECLINED;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
