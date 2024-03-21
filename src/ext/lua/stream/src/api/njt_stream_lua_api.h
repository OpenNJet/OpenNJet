
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/api/njt_subsys_lua_api.h.tt2
 */


/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_STREAM_LUA_API_H_INCLUDED_
#define _NJT_STREAM_LUA_API_H_INCLUDED_


#include <njet.h>
#include <njt_core.h>




#include <lua.h>
#include <stdint.h>


/* Public API for other NJet modules */


#define njt_stream_lua_version  14


typedef struct {
    uint8_t         type;

    union {
        int         b; /* boolean */
        lua_Number  n; /* number */
        njt_str_t   s; /* string */
    } value;

} njt_stream_lua_value_t;


typedef struct {
    int          len;
    /* this padding hole on 64-bit systems is expected */
    u_char      *data;
} njt_stream_lua_ffi_str_t;


lua_State *njt_stream_lua_get_global_state(njt_conf_t *cf);


njt_int_t njt_stream_lua_add_package_preload(njt_conf_t *cf,
    const char *package, lua_CFunction func);

njt_int_t njt_stream_lua_shared_dict_get(njt_shm_zone_t *shm_zone,
    u_char *key_data, size_t key_len, njt_stream_lua_value_t *value);

njt_shm_zone_t *njt_stream_lua_find_zone(u_char *name_data,
    size_t name_len);

njt_shm_zone_t *njt_stream_lua_shared_memory_add(njt_conf_t *cf,
    njt_str_t *name, size_t size, void *tag);


#endif /* _NJT_STREAM_LUA_API_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
