
/*
 * Copyright (C) OpenResty Inc.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>
#include "ddebug.h"
#include "njt_stream_lua_common.h"
#include "njt_stream_lua_request.h"
#include "njt_stream_lua_contentby.h"


static njt_int_t njt_stream_lua_set_write_handler(njt_stream_lua_request_t *r);
static void njt_stream_lua_writer(njt_stream_lua_request_t *r);
static void njt_stream_lua_request_cleanup(void *data);


njt_stream_lua_cleanup_t *
njt_stream_lua_cleanup_add(njt_stream_lua_request_t *r, size_t size)
{
    njt_stream_lua_cleanup_t    *cln;
    njt_stream_lua_ctx_t        *ctx;

    if (size == 0) {
        ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);

        if (ctx != NULL && ctx->free_cleanup) {
            cln = ctx->free_cleanup;
            ctx->free_cleanup = cln->next;

            dd("reuse cleanup: %p", cln);

            njt_log_debug1(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                           "lua stream cleanup reuse: %p", cln);

            cln->handler = NULL;
            cln->next = r->cleanup;

            r->cleanup = cln;

            return cln;
        }
    }

    cln = njt_palloc(r->pool, sizeof(njt_stream_lua_cleanup_t));
    if (cln == NULL) {
        return NULL;
    }

    if (size) {
        cln->data = njt_palloc(r->pool, size);
        if (cln->data == NULL) {
            return NULL;
        }

    } else {
        cln->data = NULL;
    }

    cln->handler = NULL;
    cln->next = r->cleanup;

    r->cleanup = cln;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream cleanup add: %p", cln);

    return cln;
}


static void
njt_stream_lua_request_cleanup(void *data)
{
    njt_stream_lua_request_t    *r = data;
    njt_stream_lua_cleanup_t    *cln;

    cln = r->cleanup;
    r->cleanup = NULL;

    while (cln) {
        if (cln->handler) {
            cln->handler(cln->data);
        }

        cln = cln->next;
    }
}


njt_stream_lua_request_t *
njt_stream_lua_create_request(njt_stream_session_t *s)
{
    njt_pool_t                  *pool;
    njt_stream_lua_request_t    *r;
    njt_pool_cleanup_t          *cln;

#if 0
    pool = njt_create_pool(NJT_DEFAULT_POOL_SIZE, s->connection->log);
    if (pool == NULL) {
        return NULL;
    }
#endif

    pool = s->connection->pool;

    r = njt_pcalloc(pool, sizeof(njt_stream_lua_request_t));
    if (r == NULL) {
        return NULL;
    }

    r->connection = s->connection;
    r->session = s;
    r->pool = pool;

    cln = njt_pool_cleanup_add(pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = njt_stream_lua_request_cleanup;
    cln->data = r;

    return r;
}


void
njt_stream_lua_request_handler(njt_event_t *ev)
{
    njt_connection_t          *c;
    njt_stream_session_t      *s;
    njt_stream_lua_request_t  *r;
    njt_stream_lua_ctx_t      *ctx;

    c = ev->data;
    s = c->data;

    if (ev->delayed && ev->timedout) {
        ev->delayed = 0;
        ev->timedout = 0;
    }

    ctx = njt_stream_get_module_ctx(s, njt_stream_lua_module);
    if (ctx == NULL) {
        return;
    }

    r = ctx->request;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "session run request: \"%p\"", r);

    if (ev->write) {
        r->write_event_handler(r);

    } else {
        r->read_event_handler(r);
    }
}


void
njt_stream_lua_empty_handler(njt_event_t *wev)
{
    njt_log_debug0(NJT_LOG_DEBUG_STREAM, wev->log, 0,
                   "stream lua empty handler");
    return;
}


void
njt_stream_lua_block_reading(njt_stream_lua_request_t *r)
{
    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream reading blocked");

    /* aio does not call this handler */

    if ((njt_event_flags & NJT_USE_LEVEL_EVENT)
        && r->connection->read->active)
    {
        if (njt_del_event(r->connection->read, NJT_READ_EVENT, 0) != NJT_OK) {
            njt_stream_lua_finalize_real_request(r,
                                              NJT_STREAM_INTERNAL_SERVER_ERROR);
        }
    }
}


void
njt_stream_lua_finalize_real_request(njt_stream_lua_request_t *r, njt_int_t rc)
{
#if 0
    njt_pool_t                *pool;
#endif
    njt_stream_session_t      *s;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "finalize stream request: %i", rc);

    s = r->session;

    if (rc == NJT_ERROR) {
        rc = NJT_STREAM_INTERNAL_SERVER_ERROR;
    }

    if (rc == NJT_DECLINED || rc == NJT_STREAM_INTERNAL_SERVER_ERROR) {
        goto done;
    }

    if (rc == NJT_DONE) {
        return;
    }

    if (rc == NJT_OK) {
        rc = NJT_STREAM_OK;
    }

    if (r->connection->buffered) {
        if (njt_stream_lua_set_write_handler(r) != NJT_OK) {
            goto done;
        }

        return;
    }

done:

#if 0
    pool = r->pool;
    r->pool = NULL;

    njt_destroy_pool(pool);
#endif

    njt_stream_finalize_session(s, rc);
    return;
}


void
njt_stream_lua_request_empty_handler(njt_stream_lua_request_t *r)
{
    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream request empty handler");

    return;
}


static void
njt_stream_lua_writer(njt_stream_lua_request_t *r)
{
    njt_int_t                    rc;
    njt_event_t                 *wev;
    njt_connection_t            *c;
    njt_stream_lua_srv_conf_t   *lscf;

    c = r->connection;
    wev = c->write;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, wev->log, 0,
                   "stream writer handler");

    lscf = njt_stream_lua_get_module_srv_conf(r, njt_stream_lua_module);

    if (wev->timedout) {
        njt_log_error(NJT_LOG_INFO, c->log, NJT_ETIMEDOUT,
                      "client timed out");
        c->timedout = 1;

        njt_stream_lua_finalize_real_request(r, NJT_ERROR);
        return;
    }

    rc = njt_stream_top_filter(r->session, NULL, 1);

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "stream writer output filter: %i", rc);

    if (rc == NJT_ERROR) {
        njt_stream_lua_finalize_real_request(r, rc);
        return;
    }

    if (c->buffered) {
        if (!wev->delayed) {
            njt_add_timer(wev, lscf->send_timeout);
        }

        if (njt_handle_write_event(wev, lscf->send_lowat) != NJT_OK) {
            njt_stream_lua_finalize_real_request(r, NJT_ERROR);
        }

        return;
    }

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, wev->log, 0,
                   "stream writer done");

    r->write_event_handler = njt_stream_lua_request_empty_handler;

    njt_stream_lua_finalize_real_request(r, rc);
}


static njt_int_t
njt_stream_lua_set_write_handler(njt_stream_lua_request_t *r)
{
    njt_event_t                 *wev;
    njt_stream_lua_srv_conf_t   *lscf;

    r->read_event_handler = njt_stream_lua_request_empty_handler;
    r->write_event_handler = njt_stream_lua_writer;

    wev = r->connection->write;

    if (wev->ready && wev->delayed) {
        return NJT_OK;
    }

    lscf = njt_stream_lua_get_module_srv_conf(r, njt_stream_lua_module);
    if (!wev->delayed) {
        njt_add_timer(wev, lscf->send_timeout);
    }

    if (njt_handle_write_event(wev, lscf->send_lowat) != NJT_OK) {
        return NJT_ERROR;
    }

    return NJT_OK;
}


void
njt_stream_lua_core_run_phases(njt_stream_lua_request_t *r)
{
    njt_stream_session_t      *s;

    s = r->session;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "lua session run phases: \"%p\"", r);

    njt_stream_core_run_phases(s);
}
