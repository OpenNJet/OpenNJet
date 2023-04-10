
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
#include "njt_http_lua_capturefilter.h"
#include "njt_http_lua_util.h"
#include "njt_http_lua_exception.h"
#include "njt_http_lua_subrequest.h"


njt_http_output_header_filter_pt njt_http_lua_next_header_filter;
njt_http_output_body_filter_pt njt_http_lua_next_body_filter;


static njt_int_t njt_http_lua_capture_header_filter(njt_http_request_t *r);
static njt_int_t njt_http_lua_capture_body_filter(njt_http_request_t *r,
    njt_chain_t *in);


njt_int_t
njt_http_lua_capture_filter_init(njt_conf_t *cf)
{
    /* setting up output filters to intercept subrequest responses */
    njt_http_lua_next_header_filter = njt_http_top_header_filter;
    njt_http_top_header_filter = njt_http_lua_capture_header_filter;

    njt_http_lua_next_body_filter = njt_http_top_body_filter;
    njt_http_top_body_filter = njt_http_lua_capture_body_filter;

    return NJT_OK;
}


static njt_int_t
njt_http_lua_capture_header_filter(njt_http_request_t *r)
{
    njt_http_post_subrequest_t      *psr;
    njt_http_lua_ctx_t              *old_ctx;
    njt_http_lua_ctx_t              *ctx;

    njt_http_lua_post_subrequest_data_t      *psr_data;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua capture header filter, uri \"%V\"", &r->uri);

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);

    dd("old ctx: %p", ctx);

    if (ctx == NULL || ! ctx->capture) {

        psr = r->post_subrequest;

        if (psr != NULL
            && psr->handler == njt_http_lua_post_subrequest
            && psr->data != NULL)
        {
            /* the lua ctx has been cleared by njt_http_internal_redirect,
             * resume it from the post_subrequest data
             */
            psr_data = psr->data;

            old_ctx = psr_data->ctx;

            if (ctx == NULL) {
                ctx = old_ctx;
                njt_http_set_ctx(r, ctx, njt_http_lua_module);

            } else {
                njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "lua restoring ctx with capture %d, index %d",
                               old_ctx->capture, old_ctx->index);

                ctx->capture = old_ctx->capture;
                ctx->index = old_ctx->index;
                ctx->body = NULL;
                ctx->last_body = &ctx->body;
                psr_data->ctx = ctx;
            }
        }
    }

    if (ctx && ctx->capture) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "lua capturing response body");

        /* force subrequest response body buffer in memory */
        r->filter_need_in_memory = 1;
        r->header_sent = 1;
        ctx->header_sent = 1;

        if (r->method == NJT_HTTP_HEAD) {
            r->header_only = 1;
        }

        return NJT_OK;
    }

    return njt_http_lua_next_header_filter(r);
}


static njt_int_t
njt_http_lua_capture_body_filter(njt_http_request_t *r, njt_chain_t *in)
{
    int                              rc;
    njt_int_t                        eof;
    njt_http_lua_ctx_t              *ctx;
    njt_http_lua_ctx_t              *pr_ctx;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua capture body filter, uri \"%V\"", &r->uri);

    if (in == NULL) {
        return njt_http_lua_next_body_filter(r, NULL);
    }

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);

    if (!ctx || !ctx->capture) {
        dd("no ctx or no capture %.*s", (int) r->uri.len, r->uri.data);

        return njt_http_lua_next_body_filter(r, in);
    }

    if (ctx->run_post_subrequest) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "lua body filter skipped because post subrequest "
                       "already run");
        return NJT_OK;
    }

    if (r->parent == NULL) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "lua body filter skipped because no parent request "
                       "found");

        return NJT_ERROR;
    }

    pr_ctx = njt_http_get_module_ctx(r->parent, njt_http_lua_module);
    if (pr_ctx == NULL) {
        return NJT_ERROR;
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua capture body filter capturing response body, uri "
                   "\"%V\"", &r->uri);

    rc = njt_http_lua_add_copy_chain(r, pr_ctx, &ctx->last_body, in, &eof);
    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    dd("add copy chain eof: %d, sr: %d", (int) eof, r != r->main);

    if (eof) {
        ctx->seen_last_for_subreq = 1;
    }

    njt_http_lua_discard_bufs(r->pool, in);

    return NJT_OK;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
