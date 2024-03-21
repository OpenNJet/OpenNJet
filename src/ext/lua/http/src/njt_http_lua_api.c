
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_http_lua_common.h"
#include "api/njt_http_lua_api.h"
#include "njt_http_lua_shdict.h"
#include "njt_http_lua_util.h"


lua_State *
njt_http_lua_get_global_state(njt_conf_t *cf)
{
    njt_http_lua_main_conf_t *lmcf;

    lmcf = njt_http_conf_get_module_main_conf(cf, njt_http_lua_module);

    return lmcf->lua;
}


njt_http_request_t *
njt_http_lua_get_request(lua_State *L)
{
    return njt_http_lua_get_req(L);
}


static njt_int_t njt_http_lua_shared_memory_init(njt_shm_zone_t *shm_zone,
    void *data);


njt_int_t
njt_http_lua_add_package_preload(njt_conf_t *cf, const char *package,
    lua_CFunction func)
{
    lua_State                     *L;
    njt_http_lua_main_conf_t      *lmcf;
    njt_http_lua_preload_hook_t   *hook;

    lmcf = njt_http_conf_get_module_main_conf(cf, njt_http_lua_module);

    L = lmcf->lua;

    if (L) {
        lua_getglobal(L, "package");
        lua_getfield(L, -1, "preload");
        lua_pushcfunction(L, func);
        lua_setfield(L, -2, package);
        lua_pop(L, 2);
    }

    /* we always register preload_hooks since we always create new Lua VMs
     * when lua code cache is off. */

    if (lmcf->preload_hooks == NULL) {
        lmcf->preload_hooks =
            njt_array_create(cf->pool, 4,
                             sizeof(njt_http_lua_preload_hook_t));

        if (lmcf->preload_hooks == NULL) {
            return NJT_ERROR;
        }
    }

    hook = njt_array_push(lmcf->preload_hooks);
    if (hook == NULL) {
        return NJT_ERROR;
    }

    hook->package = (u_char *) package;
    hook->loader = func;

    return NJT_OK;
}


njt_shm_zone_t *
njt_http_lua_shared_memory_add(njt_conf_t *cf, njt_str_t *name, size_t size,
    void *tag)
{
    njt_http_lua_main_conf_t     *lmcf;
    njt_shm_zone_t              **zp;
    njt_shm_zone_t               *zone;
    njt_http_lua_shm_zone_ctx_t  *ctx;
    njt_int_t                     n;

    lmcf = njt_http_conf_get_module_main_conf(cf, njt_http_lua_module);
    if (lmcf == NULL) {
        return NULL;
    }

    if (lmcf->shm_zones == NULL) {
        lmcf->shm_zones = njt_palloc(cf->pool, sizeof(njt_array_t));
        if (lmcf->shm_zones == NULL) {
            return NULL;
        }

        if (njt_array_init(lmcf->shm_zones, cf->pool, 2,
                           sizeof(njt_shm_zone_t *))
            != NJT_OK)
        {
            return NULL;
        }
    }

    zone = njt_shared_memory_add(cf, name, (size_t) size, tag);
    if (zone == NULL) {
        return NULL;
    }

    if (zone->data) {
        ctx = (njt_http_lua_shm_zone_ctx_t *) zone->data;
        return &ctx->zone;
    }

    n = sizeof(njt_http_lua_shm_zone_ctx_t);

    ctx = njt_pcalloc(cf->pool, n);
    if (ctx == NULL) {
        return NULL;
    }

    ctx->lmcf = lmcf;
    ctx->log = &cf->cycle->new_log;
    ctx->cycle = cf->cycle;

    njt_memcpy(&ctx->zone, zone, sizeof(njt_shm_zone_t));

    zp = njt_array_push(lmcf->shm_zones);
    if (zp == NULL) {
        return NULL;
    }

    *zp = zone;

    /* set zone init */
    zone->init = njt_http_lua_shared_memory_init;
    zone->data = ctx;

    lmcf->requires_shm = 1;

    return &ctx->zone;
}


static njt_int_t
njt_http_lua_shared_memory_init(njt_shm_zone_t *shm_zone, void *data)
{
    njt_http_lua_shm_zone_ctx_t *octx = data;
    njt_shm_zone_t              *ozone;
    void                        *odata;

    njt_int_t                    rc;
    volatile njt_cycle_t        *saved_cycle;
    njt_http_lua_main_conf_t    *lmcf;
    njt_http_lua_shm_zone_ctx_t *ctx;
    njt_shm_zone_t              *zone;

    ctx = (njt_http_lua_shm_zone_ctx_t *) shm_zone->data;
    zone = &ctx->zone;

    odata = NULL;
    if (octx) {
        ozone = &octx->zone;
        odata = ozone->data;
    }

    zone->shm = shm_zone->shm;
#if (njet_version >= 1009000)
    zone->noreuse = shm_zone->noreuse;
#endif

    if (zone->init(zone, odata) != NJT_OK) {
        return NJT_ERROR;
    }

    dd("get lmcf");

    lmcf = ctx->lmcf;
    if (lmcf == NULL) {
        return NJT_ERROR;
    }

    dd("lmcf->lua: %p", lmcf->lua);

    lmcf->shm_zones_inited++;

    if (lmcf->shm_zones_inited == lmcf->shm_zones->nelts
        && lmcf->init_handler && !njt_test_config)
    {
        saved_cycle = njt_cycle;
        njt_cycle = ctx->cycle;

        rc = lmcf->init_handler(ctx->log, lmcf, lmcf->lua);

        njt_cycle = saved_cycle;

        if (rc != NJT_OK) {
            /* an error happened */
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


njt_http_lua_co_ctx_t *
njt_http_lua_get_cur_co_ctx(njt_http_request_t *r)
{
    njt_http_lua_ctx_t  *ctx;

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);

    return ctx->cur_co_ctx;
}


void
njt_http_lua_set_cur_co_ctx(njt_http_request_t *r, njt_http_lua_co_ctx_t *coctx)
{
    njt_http_lua_ctx_t  *ctx;

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);

    coctx->data = r;

    ctx->cur_co_ctx = coctx;
}


lua_State *
njt_http_lua_get_co_ctx_vm(njt_http_lua_co_ctx_t *coctx)
{
    return coctx->co;
}


static njt_int_t
njt_http_lua_co_ctx_resume(njt_http_request_t *r)
{
    lua_State                   *vm;
    njt_connection_t            *c;
    njt_int_t                    rc;
    njt_uint_t                   nreqs;
    njt_http_lua_ctx_t          *ctx;

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
    if (ctx == NULL) {
        return NJT_ERROR;
    }

    ctx->resume_handler = njt_http_lua_wev_handler;

    c = r->connection;
    vm = njt_http_lua_get_lua_vm(r, ctx);
    nreqs = c->requests;

    rc = njt_http_lua_run_thread(vm, r, ctx, ctx->cur_co_ctx->nrets);

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua run thread returned %d", rc);

    if (rc == NJT_AGAIN) {
        return njt_http_lua_run_posted_threads(c, vm, r, ctx, nreqs);
    }

    if (rc == NJT_DONE) {
        njt_http_lua_finalize_request(r, NJT_DONE);
        return njt_http_lua_run_posted_threads(c, vm, r, ctx, nreqs);
    }

    if (ctx->entered_content_phase) {
        njt_http_lua_finalize_request(r, rc);
        return NJT_DONE;
    }

    return rc;
}


void
njt_http_lua_co_ctx_resume_helper(njt_http_lua_co_ctx_t *coctx, int nrets)
{
    njt_connection_t        *c;
    njt_http_request_t      *r;
    njt_http_lua_ctx_t      *ctx;
    njt_http_log_ctx_t      *log_ctx;

    r = coctx->data;
    c = r->connection;

    ctx = njt_http_get_module_ctx(r, njt_http_lua_module);

    if (ctx == NULL) {
        return;
    }

    if (c->fd != (njt_socket_t) -1) {  /* not a fake connection */
        log_ctx = c->log->data;
        log_ctx->current_request = r;
    }

    coctx->nrets = nrets;
    coctx->cleanup = NULL;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "lua coctx resume handler: \"%V?%V\"", &r->uri, &r->args);

    ctx->cur_co_ctx = coctx;

    if (ctx->entered_content_phase) {
        (void) njt_http_lua_co_ctx_resume(r);

    } else {
        ctx->resume_handler = njt_http_lua_co_ctx_resume;
        njt_http_core_run_phases(r);
    }

    njt_http_run_posted_requests(c);
}


int
njt_http_lua_get_lua_http10_buffering(njt_http_request_t *r)
{
    njt_http_lua_loc_conf_t      *llcf;

    llcf = njt_http_get_module_loc_conf(r, njt_http_lua_module);

    return llcf->http10_buffering;
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
