
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_api.c.tt2
 */


/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_stream_lua_common.h"
#include "api/njt_stream_lua_api.h"
#include "njt_stream_lua_shdict.h"
#include "njt_stream_lua_util.h"


lua_State *
njt_stream_lua_get_global_state(njt_conf_t *cf)
{
    njt_stream_lua_main_conf_t       *lmcf;

    lmcf = njt_stream_conf_get_module_main_conf(cf, njt_stream_lua_module);

    return lmcf->lua;
}




static njt_int_t njt_stream_lua_shared_memory_init(njt_shm_zone_t *shm_zone,
    void *data);


njt_int_t
njt_stream_lua_add_package_preload(njt_conf_t *cf, const char *package,
    lua_CFunction func)
{
    lua_State       *L;

    njt_stream_lua_main_conf_t            *lmcf;
    njt_stream_lua_preload_hook_t         *hook;

    lmcf = njt_stream_conf_get_module_main_conf(cf, njt_stream_lua_module);

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
                             sizeof(njt_stream_lua_preload_hook_t));

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
njt_stream_lua_shared_memory_add(njt_conf_t *cf, njt_str_t *name,
    size_t size, void *tag)
{
    njt_stream_lua_main_conf_t           *lmcf;
    njt_stream_lua_shm_zone_ctx_t        *ctx;

    njt_shm_zone_t              **zp;
    njt_shm_zone_t               *zone;
    njt_int_t                     n;

    lmcf = njt_stream_conf_get_module_main_conf(cf, njt_stream_lua_module);
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
        ctx = (njt_stream_lua_shm_zone_ctx_t *) zone->data;
        return &ctx->zone;
    }

    n = sizeof(njt_stream_lua_shm_zone_ctx_t);

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
    zone->init = njt_stream_lua_shared_memory_init;
    zone->data = ctx;

    lmcf->requires_shm = 1;

    return &ctx->zone;
}


static njt_int_t
njt_stream_lua_shared_memory_init(njt_shm_zone_t *shm_zone, void *data)
{
    njt_stream_lua_shm_zone_ctx_t       *octx = data;
    njt_stream_lua_main_conf_t          *lmcf;
    njt_stream_lua_shm_zone_ctx_t       *ctx;

    njt_shm_zone_t              *ozone;
    void                        *odata;
    njt_int_t                    rc;
    volatile njt_cycle_t        *saved_cycle;
    njt_shm_zone_t              *zone;

    ctx = (njt_stream_lua_shm_zone_ctx_t *) shm_zone->data;
    zone = &ctx->zone;

    odata = NULL;
    if (octx) {
        ozone = &octx->zone;
        odata = ozone->data;
    }

    zone->shm = shm_zone->shm;
#if defined(njet_version) && njet_version >= 1009000
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

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
