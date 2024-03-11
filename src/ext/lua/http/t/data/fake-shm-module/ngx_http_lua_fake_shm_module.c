#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njet.h>


#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>


#include "njt_http_lua_api.h"


static void *njt_http_lua_fake_shm_create_main_conf(njt_conf_t *cf);
static njt_int_t njt_http_lua_fake_shm_init(njt_conf_t *cf);

static char *njt_http_lua_fake_shm(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static njt_int_t njt_http_lua_fake_shm_init_zone(njt_shm_zone_t *shm_zone,
    void *data);
static int njt_http_lua_fake_shm_preload(lua_State *L);
static int njt_http_lua_fake_shm_get_info(lua_State *L);


typedef struct {
    njt_array_t     *shm_zones;
} njt_http_lua_fake_shm_main_conf_t;


static njt_command_t njt_http_lua_fake_shm_cmds[] = {

    { njt_string("lua_fake_shm"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      njt_http_lua_fake_shm,
      0,
      0,
      NULL },

    njt_null_command
};


static njt_http_module_t  njt_http_lua_fake_shm_module_ctx = {
    NULL,                                   /* preconfiguration */
    njt_http_lua_fake_shm_init,             /* postconfiguration */

    njt_http_lua_fake_shm_create_main_conf, /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    NULL,                                   /* create location configuration */
    NULL,                                   /* merge location configuration */
};


njt_module_t  njt_http_lua_fake_shm_module = {
    NGX_MODULE_V1,
    &njt_http_lua_fake_shm_module_ctx, /* module context */
    njt_http_lua_fake_shm_cmds,        /* module directives */
    NGX_HTTP_MODULE,                   /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    NULL,                              /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NGX_MODULE_V1_PADDING
};


typedef struct {
    njt_str_t   name;
    size_t      size;
    njt_int_t   isold;
    njt_int_t   isinit;
} njt_http_lua_fake_shm_ctx_t;


static void *
njt_http_lua_fake_shm_create_main_conf(njt_conf_t *cf)
{
    njt_http_lua_fake_shm_main_conf_t *lfsmcf;

    lfsmcf = njt_pcalloc(cf->pool, sizeof(*lfsmcf));
    if (lfsmcf == NULL) {
        return NULL;
    }

    return lfsmcf;
}


static char *
njt_http_lua_fake_shm(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_lua_fake_shm_main_conf_t   *lfsmcf = conf;

    njt_str_t                   *value, name;
    njt_shm_zone_t              *zone;
    njt_shm_zone_t             **zp;
    njt_http_lua_fake_shm_ctx_t *ctx;
    ssize_t                      size;

    if (lfsmcf->shm_zones == NULL) {
        lfsmcf->shm_zones = njt_palloc(cf->pool, sizeof(njt_array_t));
        if (lfsmcf->shm_zones == NULL) {
            return NGX_CONF_ERROR;
        }

        if (njt_array_init(lfsmcf->shm_zones, cf->pool, 2,
                           sizeof(njt_shm_zone_t *))
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    ctx = NULL;

    if (value[1].len == 0) {
        njt_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid lua fake_shm name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    name = value[1];

    size = njt_parse_size(&value[2]);

    if (size <= 8191) {
        njt_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid lua fake_shm size \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    ctx = njt_pcalloc(cf->pool, sizeof(njt_http_lua_fake_shm_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx->name = name;
    ctx->size = size;

    zone = njt_http_lua_shared_memory_add(cf, &name, (size_t) size,
                                          &njt_http_lua_fake_shm_module);
    if (zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (zone->data) {
        ctx = zone->data;

        njt_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "lua_fake_shm \"%V\" is already defined as "
                           "\"%V\"", &name, &ctx->name);
        return NGX_CONF_ERROR;
    }

    zone->init = njt_http_lua_fake_shm_init_zone;
    zone->data = ctx;

    zp = njt_array_push(lfsmcf->shm_zones);
    if (zp == NULL) {
        return NGX_CONF_ERROR;
    }

    *zp = zone;

    return NGX_CONF_OK;
}


static njt_int_t
njt_http_lua_fake_shm_init_zone(njt_shm_zone_t *shm_zone, void *data)
{
    njt_http_lua_fake_shm_ctx_t  *octx = data;

    njt_http_lua_fake_shm_ctx_t  *ctx;

    ctx = shm_zone->data;

    if (octx) {
        ctx->isold = 1;
    }

    ctx->isinit = 1;

    return NGX_OK;
}


static njt_int_t
njt_http_lua_fake_shm_init(njt_conf_t *cf)
{
    njt_http_lua_add_package_preload(cf, "fake_shm_zones",
                                     njt_http_lua_fake_shm_preload);
    return NGX_OK;
}


static int
njt_http_lua_fake_shm_preload(lua_State *L)
{
    njt_http_lua_fake_shm_main_conf_t *lfsmcf;
    njt_http_conf_ctx_t               *hmcf_ctx;
    njt_cycle_t                       *cycle;

    njt_uint_t                   i;
    njt_shm_zone_t             **zone;
    njt_shm_zone_t             **zone_udata;

    cycle = (njt_cycle_t *) njt_cycle;

    hmcf_ctx = (njt_http_conf_ctx_t *) cycle->conf_ctx[njt_http_module.index];
    lfsmcf = hmcf_ctx->main_conf[njt_http_lua_fake_shm_module.ctx_index];

    if (lfsmcf->shm_zones != NULL) {
        lua_createtable(L, 0, lfsmcf->shm_zones->nelts /* nrec */);

        lua_createtable(L, 0 /* narr */, 2 /* nrec */); /* shared mt */

        lua_pushcfunction(L, njt_http_lua_fake_shm_get_info);
        lua_setfield(L, -2, "get_info");

        lua_pushvalue(L, -1); /* shared mt mt */
        lua_setfield(L, -2, "__index"); /* shared mt */

        zone = lfsmcf->shm_zones->elts;

        for (i = 0; i < lfsmcf->shm_zones->nelts; i++) {
            lua_pushlstring(L, (char *) zone[i]->shm.name.data,
                            zone[i]->shm.name.len);

            /* shared mt key */

            lua_createtable(L, 1 /* narr */, 0 /* nrec */);
                /* table of zone[i] */
            zone_udata = lua_newuserdata(L, sizeof(njt_shm_zone_t *));
                /* shared mt key ud */
            *zone_udata = zone[i];
            lua_rawseti(L, -2, 1); /* {zone[i]} */
            lua_pushvalue(L, -3); /* shared mt key ud mt */
            lua_setmetatable(L, -2); /* shared mt key ud */
            lua_rawset(L, -4); /* shared mt */
        }

        lua_pop(L, 1); /* shared */

    } else {
        lua_newtable(L);    /* njt.shared */
    }

    return 1;
}


static int
njt_http_lua_fake_shm_get_info(lua_State *L)
{
    njt_int_t                         n;
    njt_shm_zone_t                   *zone;
    njt_shm_zone_t                  **zone_udata;
    njt_http_lua_fake_shm_ctx_t      *ctx;

    n = lua_gettop(L);

    if (n != 1) {
        return luaL_error(L, "expecting exactly one arguments, "
                          "but only seen %d", n);
    }

    luaL_checktype(L, 1, LUA_TTABLE);

    lua_rawgeti(L, 1, 1);
    zone_udata = lua_touserdata(L, -1);
    lua_pop(L, 1);

    if (zone_udata == NULL) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    zone = *zone_udata;

    ctx = (njt_http_lua_fake_shm_ctx_t *) zone->data;

    lua_pushlstring(L, (char *) zone->shm.name.data, zone->shm.name.len);
    lua_pushnumber(L, zone->shm.size);
    lua_pushboolean(L, ctx->isinit);
    lua_pushboolean(L, ctx->isold);

    return 4;
}
