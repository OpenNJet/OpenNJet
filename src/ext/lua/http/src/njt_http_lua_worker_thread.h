/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) Jinhua Luo (kingluo)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 * I hereby assign copyright in this code to the lua-njet-module project,
 * to be licensed under the same terms as the rest of the code.
 */

#ifndef _NJT_HTTP_LUA_WORKER_THREAD_H_INCLUDED_
#define _NJT_HTTP_LUA_WORKER_THREAD_H_INCLUDED_


#include "njt_http_lua_common.h"


void njt_http_lua_inject_worker_thread_api(njt_log_t *log, lua_State *L);
void njt_http_lua_thread_exit_process(void);


#endif /* _NJT_HTTP_LUA_WORKER_THREAD_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
