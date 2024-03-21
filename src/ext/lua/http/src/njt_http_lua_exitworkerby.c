
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_http_lua_exitworkerby.h"
#include "njt_http_lua_util.h"

#if (NJT_THREADS)
#include "njt_http_lua_worker_thread.h"
#endif


void
njt_http_lua_exit_worker(njt_cycle_t *cycle)
{
    njt_http_lua_main_conf_t    *lmcf;
    njt_connection_t            *c = NULL;
    njt_http_request_t          *r = NULL;
    njt_http_lua_ctx_t          *ctx;
    njt_http_conf_ctx_t         *conf_ctx;

#if (NJT_THREADS)
    njt_http_lua_thread_exit_process();
#endif

    lmcf = njt_http_cycle_get_module_main_conf(cycle, njt_http_lua_module);
    if (lmcf == NULL
        || lmcf->exit_worker_handler == NULL
        || lmcf->lua == NULL
#if !(NJT_WIN32)
        || ((njt_process == NJT_PROCESS_HELPER && njt_is_privileged_helper != 1)
#   ifdef HAVE_PRIVILEGED_PROCESS_PATCH
            && !njt_is_privileged_agent
#   endif
           )
#endif  /* NJT_WIN32 */
       )
    {
        return;
    }

    conf_ctx = ((njt_http_conf_ctx_t *) cycle->conf_ctx[njt_http_module.index]);

    c = njt_http_lua_create_fake_connection(NULL);
    if (c == NULL) {
        goto failed;
    }

    c->log = njt_cycle->log;

    r = njt_http_lua_create_fake_request(c);
    if (r == NULL) {
        goto failed;
    }

    r->main_conf = conf_ctx->main_conf;
    r->srv_conf = conf_ctx->srv_conf;
    r->loc_conf = conf_ctx->loc_conf;

    ctx = njt_http_lua_create_ctx(r);
    if (ctx == NULL) {
        goto failed;
    }

    ctx->context = NJT_HTTP_LUA_CONTEXT_EXIT_WORKER;
    ctx->cur_co_ctx = NULL;

    njt_http_lua_set_req(lmcf->lua, r);

    (void) lmcf->exit_worker_handler(cycle->log, lmcf, lmcf->lua);

    njt_destroy_pool(c->pool);
    return;

failed:

    if (c) {
        njt_http_lua_close_fake_connection(c);
    }

    return;
}


njt_int_t
njt_http_lua_exit_worker_by_inline(njt_log_t *log,
    njt_http_lua_main_conf_t *lmcf, lua_State *L)
{
    int         status;
    const char *chunkname;

    if (lmcf->exit_worker_chunkname == NULL) {
        chunkname = "=exit_worker_by_lua";

    } else {
        chunkname = (const char *) lmcf->exit_worker_chunkname;
    }

    status = luaL_loadbuffer(L, (char *) lmcf->exit_worker_src.data,
                             lmcf->exit_worker_src.len, chunkname)
             || njt_http_lua_do_call(log, L);

    return njt_http_lua_report(log, L, status, "exit_worker_by_lua");
}


njt_int_t
njt_http_lua_exit_worker_by_file(njt_log_t *log, njt_http_lua_main_conf_t *lmcf,
    lua_State *L)
{
    int         status;

    status = luaL_loadfile(L, (char *) lmcf->exit_worker_src.data)
             || njt_http_lua_do_call(log, L);

    return njt_http_lua_report(log, L, status, "exit_worker_by_lua_file");
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
