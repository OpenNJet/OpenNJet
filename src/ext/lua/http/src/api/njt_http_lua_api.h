
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) TMLake, Inc.
 */


#ifndef _NJT_HTTP_LUA_API_H_INCLUDED_
#define _NJT_HTTP_LUA_API_H_INCLUDED_


#include <njet.h>
#include <njt_core.h>
#include <njt_http.h>

#include <lua.h>
#include <stdint.h>


/* Public API for other Nginx modules */


#define njt_http_lua_version  10021


typedef struct {
    uint8_t         type;

    union {
        int         b; /* boolean */
        lua_Number  n; /* number */
        njt_str_t   s; /* string */
    } value;

} njt_http_lua_value_t;


typedef struct {
    int          len;
    /* this padding hole on 64-bit systems is expected */
    u_char      *data;
} njt_http_lua_ffi_str_t;


lua_State *njt_http_lua_get_global_state(njt_conf_t *cf);

njt_http_request_t *njt_http_lua_get_request(lua_State *L);

njt_int_t njt_http_lua_add_package_preload(njt_conf_t *cf, const char *package,
    lua_CFunction func);

njt_int_t njt_http_lua_shared_dict_get(njt_shm_zone_t *shm_zone,
    u_char *key_data, size_t key_len, njt_http_lua_value_t *value);

njt_shm_zone_t *njt_http_lua_find_zone(u_char *name_data, size_t name_len);

njt_shm_zone_t *njt_http_lua_shared_memory_add(njt_conf_t *cf, njt_str_t *name,
    size_t size, void *tag);


#endif /* _NJT_HTTP_LUA_API_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
