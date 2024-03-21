
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
#include "njt_http_lua_accessby.h"
#include "njt_http_lua_util.h"
#include "njt_http_lua_exception.h"
#include "njt_http_lua_cache.h"


static njt_int_t njt_http_lua_access_by_chunk(lua_State *L,
    njt_http_request_t *r);


njt_int_t
njt_http_lua_access_handler(njt_http_request_t *r)
{
    njt_int_t                   rc;
    njt_http_lua_ctx_t         *ctx;
    njt_http_lua_loc_conf_t    *llcf;
    njt_http_lua_main_conf_t   *lmcf;
    njt_http_phase_handler_t    tmp, *ph, *cur_ph, *last_ph;
    njt_http_core_main_conf_t  *cmcf;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua access handler, uri:\"%V\" c:%ud", &r->uri,
                   r->main->count);

    lmcf = njt_http_get_module_main_conf(r, njt_http_lua_module);

    if (!lmcf->postponed_to_access_phase_end) {

        lmcf->postponed_to_access_phase_end = 1;

        cmcf = njt_http_get_module_main_conf(r, njt_http_core_module);

        ph = cmcf->phase_engine.handlers;
        cur_ph = &ph[r->phase_handler];

        /* we should skip the post_access phase handler here too */
        last_ph = &ph[cur_ph->next - 2];

        dd("ph cur: %d, ph next: %d", (int) r->phase_handler,
           (int) (cur_ph->next - 2));

#if 0
        if (cur_ph == last_ph) {
            dd("XXX our handler is already the last access phase handler");
        }
#endif

        if (cur_ph < last_ph) {
            dd("swapping the contents of cur_ph and last_ph...");

            tmp = *cur_ph;

            memmove(cur_ph, cur_ph + 1,
                    (last_ph - cur_ph) * sizeof (njt_http_phase_handler_t));

            *last_ph = tmp;

            r->phase_handler--; /* redo the current ph */

            return NJT_DECLINED;
        }
    }

    llcf = njt_http_get_module_loc_conf(r, njt_http_lua_module);

    if (llcf->access_handler == NULL) {
        dd("no access handler found");
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

    dd("entered? %d", (int) ctx->entered_access_phase);

    if (ctx->entered_access_phase) {
        dd("calling wev handler");
        rc = ctx->resume_handler(r);
        dd("wev handler returns %d", (int) rc);

        if (rc == NJT_ERROR || rc == NJT_DONE || rc > NJT_OK) {
            return rc;
        }

        if (rc == NJT_OK) {
            if (r->header_sent) {
                dd("header already sent");

                /* response header was already generated in access_by_lua*,
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

            return NJT_OK;
        }

        return NJT_DECLINED;
    }

    if (ctx->waiting_more_body) {
        dd("WAITING MORE BODY");
        return NJT_DONE;
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
                                       njt_http_lua_generic_phase_post_read);

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

    dd("calling access handler");
    return llcf->access_handler(r);
}


njt_int_t
njt_http_lua_access_handler_inline(njt_http_request_t *r)
{
    njt_int_t                  rc;
    lua_State                 *L;
    njt_http_lua_loc_conf_t   *llcf;

    llcf = njt_http_get_module_loc_conf(r, njt_http_lua_module);

    L = njt_http_lua_get_lua_vm(r, NULL);

    /*  load Lua inline script (w/ cache) sp = 1 */
    rc = njt_http_lua_cache_loadbuffer(r->connection->log, L,
                                       llcf->access_src.value.data,
                                       llcf->access_src.value.len,
                                       &llcf->access_src_ref,
                                       llcf->access_src_key,
                                       (const char *) llcf->access_chunkname);

    if (rc != NJT_OK) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    return njt_http_lua_access_by_chunk(L, r);
}


njt_int_t
njt_http_lua_access_handler_file(njt_http_request_t *r)
{
    u_char                    *script_path;
    njt_int_t                  rc;
    njt_str_t                  eval_src;
    lua_State                 *L;
    njt_http_lua_loc_conf_t   *llcf;

    llcf = njt_http_get_module_loc_conf(r, njt_http_lua_module);

    /* Eval njet variables in code path string first */
    if (njt_http_complex_value(r, &llcf->access_src, &eval_src) != NJT_OK) {
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
                                     &llcf->access_src_ref,
                                     llcf->access_src_key);
    if (rc != NJT_OK) {
        if (rc < NJT_HTTP_SPECIAL_RESPONSE) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        return rc;
    }

    /*  make sure we have a valid code chunk */
    njt_http_lua_assert(lua_isfunction(L, -1));

    return njt_http_lua_access_by_chunk(L, r);
}


static njt_int_t
njt_http_lua_access_by_chunk(lua_State *L, njt_http_request_t *r)
{
    int                  co_ref;
    njt_int_t            rc;
    njt_uint_t           nreqs;
    lua_State           *co;
    njt_event_t         *rev;
    njt_connection_t    *c;
    njt_http_lua_ctx_t  *ctx;
    njt_pool_cleanup_t  *cln;

    njt_http_lua_loc_conf_t     *llcf;

    /*  {{{ new coroutine to handle request */
    co = njt_http_lua_new_thread(r, L, &co_ref);

    if (co == NULL) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "lua: failed to create new coroutine "
                      "to handle request");

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

    ctx->entered_access_phase = 1;

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

    ctx->context = NJT_HTTP_LUA_CONTEXT_ACCESS;

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

    dd("returned %d", (int) rc);

    if (rc == NJT_ERROR || rc > NJT_OK) {
        return rc;
    }

    if (rc == NJT_AGAIN) {
        rc = njt_http_lua_run_posted_threads(c, L, r, ctx, nreqs);

        if (rc == NJT_ERROR || rc == NJT_DONE || rc > NJT_OK) {
            return rc;
        }

        if (rc != NJT_OK) {
            return NJT_DECLINED;
        }

    } else if (rc == NJT_DONE) {
        njt_http_lua_finalize_request(r, NJT_DONE);

        rc = njt_http_lua_run_posted_threads(c, L, r, ctx, nreqs);

        if (rc == NJT_ERROR || rc == NJT_DONE || rc > NJT_OK) {
            return rc;
        }

        if (rc != NJT_OK) {
            return NJT_DECLINED;
        }
    }

#if 1
    if (rc == NJT_OK) {
        if (r->header_sent) {
            dd("header already sent");

            /* response header was already generated in access_by_lua*,
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

        return NJT_OK;
    }
#endif

    return NJT_DECLINED;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
