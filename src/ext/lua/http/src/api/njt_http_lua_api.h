
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_LUA_API_H_INCLUDED_
#define _NJT_HTTP_LUA_API_H_INCLUDED_


#include <njet.h>
#include <njt_core.h>
#include <njt_http.h>

#include <lua.h>
#include <stdint.h>


/* Public API for other Nginx modules */


#define njt_http_lua_version  10026


typedef struct njt_http_lua_co_ctx_s  njt_http_lua_co_ctx_t;


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

njt_http_lua_co_ctx_t *njt_http_lua_get_cur_co_ctx(njt_http_request_t *r);

void njt_http_lua_set_cur_co_ctx(njt_http_request_t *r,
    njt_http_lua_co_ctx_t *coctx);

lua_State *njt_http_lua_get_co_ctx_vm(njt_http_lua_co_ctx_t *coctx);

void njt_http_lua_co_ctx_resume_helper(njt_http_lua_co_ctx_t *coctx, int nrets);

int njt_http_lua_get_lua_http10_buffering(njt_http_request_t *r);


#endif /* _NJT_HTTP_LUA_API_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
