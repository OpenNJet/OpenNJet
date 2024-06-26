
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.yy
 */


#ifndef _NJT_HTTP_LUA_UTHREAD_H_INCLUDED_
#define _NJT_HTTP_LUA_UTHREAD_H_INCLUDED_


#include "njt_http_lua_common.h"


#define njt_http_lua_is_thread(ctx)                                          \
    ((ctx)->cur_co_ctx->is_uthread || (ctx)->cur_co_ctx == &(ctx)->entry_co_ctx)


#define njt_http_lua_is_entry_thread(ctx)                                    \
    ((ctx)->cur_co_ctx == &(ctx)->entry_co_ctx)


#define njt_http_lua_entry_thread_alive(ctx)                                 \
    ((ctx)->entry_co_ctx.co_ref != LUA_NOREF)


#define njt_http_lua_coroutine_alive(coctx)                                  \
    ((coctx)->co_status != NJT_HTTP_LUA_CO_DEAD                              \
     && (coctx)->co_status != NJT_HTTP_LUA_CO_ZOMBIE)


void njt_http_lua_inject_uthread_api(njt_log_t *log, lua_State *L);


#endif /* _NJT_HTTP_LUA_UTHREAD_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
