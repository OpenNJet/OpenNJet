/*
 * This fake_delayed_load delayed load module was used to reproduce
 * a bug in njt_lua's function njt_http_lua_add_package_preload.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njet.h>


#include "njt_http_lua_api.h"


static njt_int_t njt_http_lua_fake_delayed_load_init(njt_conf_t *cf);
static int njt_http_lua_fake_delayed_load_preload(lua_State *L);
static int njt_http_lua_fake_delayed_load_function(lua_State * L);


static njt_http_module_t njt_http_lua_fake_delayed_load_module_ctx = {
    NULL,                                 /* preconfiguration */
    njt_http_lua_fake_delayed_load_init,  /* postconfiguration */

    NULL,                                 /* create main configuration */
    NULL,                                 /* init main configuration */

    NULL,                                 /* create server configuration */
    NULL,                                 /* merge server configuration */

    NULL,                                 /* create location configuration */
    NULL,                                 /* merge location configuration */
};

/* flow identify module struct */
njt_module_t  njt_http_lua_fake_delayed_load_module = {
    NGX_MODULE_V1,
    &njt_http_lua_fake_delayed_load_module_ctx,   /* module context */
    NULL,                                         /* module directives */
    NGX_HTTP_MODULE,                              /* module type */
    NULL,                                         /* init master */
    NULL,                                         /* init module */
    NULL,                                         /* init process */
    NULL,                                         /* init thread */
    NULL,                                         /* exit thread */
    NULL,                                         /* exit process */
    NULL,                                         /* exit master */
    NGX_MODULE_V1_PADDING
};


static njt_int_t
njt_http_lua_fake_delayed_load_init(njt_conf_t *cf)
{
    njt_http_lua_add_package_preload(cf, "njt.delayed_load",
                                     njt_http_lua_fake_delayed_load_preload);
    return NGX_OK;
}


static int
njt_http_lua_fake_delayed_load_preload(lua_State *L)
{
    lua_createtable(L, 0, 1);

    lua_pushcfunction(L, njt_http_lua_fake_delayed_load_function);
    lua_setfield(L, -2, "get_function");

    return 1;
}


static int
njt_http_lua_fake_delayed_load_function(lua_State * L)
{
    return 0;
}
