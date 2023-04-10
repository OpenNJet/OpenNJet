
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_LUA_BALANCER_H_INCLUDED_
#define _NJT_HTTP_LUA_BALANCER_H_INCLUDED_


#include "njt_http_lua_common.h"


njt_int_t njt_http_lua_balancer_handler_inline(njt_http_request_t *r,
    njt_http_lua_srv_conf_t *lscf, lua_State *L);

njt_int_t njt_http_lua_balancer_handler_file(njt_http_request_t *r,
    njt_http_lua_srv_conf_t *lscf, lua_State *L);

char *njt_http_lua_balancer_by_lua(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);

char *njt_http_lua_balancer_by_lua_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);


#endif /* _NJT_HTTP_LUA_BALANCER_H_INCLUDED_ */
