
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_http_lua_initworkerby.h"
#include "njt_http_lua_util.h"
#include "njt_http_lua_pipe.h"


static u_char *njt_http_lua_log_init_worker_error(njt_log_t *log,
    u_char *buf, size_t len);


njt_int_t
njt_http_lua_init_worker(njt_cycle_t *cycle)
{
    char                        *rv;
    void                        *cur, *prev;
    njt_uint_t                   i;
    njt_conf_t                   conf;
    njt_conf_file_t              cf_file;
    njt_cycle_t                 *fake_cycle;
    njt_module_t               **modules;
    njt_open_file_t             *file, *ofile;
    njt_list_part_t             *part;
    njt_connection_t            *c = NULL;
    njt_http_module_t           *module;
    njt_http_request_t          *r = NULL;
    njt_http_lua_ctx_t          *ctx;
    njt_http_conf_ctx_t         *conf_ctx, http_ctx;
    njt_http_lua_loc_conf_t     *top_llcf;
    njt_http_lua_main_conf_t    *lmcf;
    njt_http_core_loc_conf_t    *clcf, *top_clcf;

    lmcf = njt_http_cycle_get_module_main_conf(cycle, njt_http_lua_module);

    if (lmcf == NULL || lmcf->lua == NULL) {
        return NJT_OK;
    }

    /* lmcf != NULL && lmcf->lua != NULL */

#if !(NJT_WIN32)
    if ((njt_process == NJT_PROCESS_HELPER && njt_is_privileged_helper != 1)
#   ifdef HAVE_PRIVILEGED_PROCESS_PATCH
        && !njt_is_privileged_agent
#   endif
       )
    {
        /* disable init_worker_by_lua* and destroy lua VM in cache processes */

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "lua close the global Lua VM %p in the "
                       "cache helper process %P", lmcf->lua, njt_pid);

        lmcf->vm_cleanup->handler(lmcf->vm_cleanup->data);
        lmcf->vm_cleanup->handler = NULL;

        return NJT_OK;
    }

#   ifdef HAVE_NJT_LUA_PIPE
    if (njt_http_lua_pipe_add_signal_handler(cycle) != NJT_OK) {
        return NJT_ERROR;
    }
#   endif

#endif  /* NJT_WIN32 */

#if (NJT_HTTP_LUA_HAVE_SA_RESTART)
    if (lmcf->set_sa_restart) {
        njt_http_lua_set_sa_restart(njt_cycle->log);
    }
#endif

    if (lmcf->init_worker_handler == NULL) {
        return NJT_OK;
    }

    conf_ctx = (njt_http_conf_ctx_t *) cycle->conf_ctx[njt_http_module.index];
    http_ctx.main_conf = conf_ctx->main_conf;

    top_clcf = conf_ctx->loc_conf[njt_http_core_module.ctx_index];
    top_llcf = conf_ctx->loc_conf[njt_http_lua_module.ctx_index];

    njt_memzero(&conf, sizeof(njt_conf_t));

    conf.temp_pool = njt_create_pool(NJT_CYCLE_POOL_SIZE, cycle->log);
    if (conf.temp_pool == NULL) {
        return NJT_ERROR;
    }

    conf.temp_pool->log = cycle->log;

    /* we fake a temporary njt_cycle_t here because some
     * modules' merge conf handler may produce side effects in
     * cf->cycle (like njt_proxy vs cf->cycle->paths).
     * also, we cannot allocate our temp cycle on the stack
     * because some modules like njt_http_core_module reference
     * addresses within cf->cycle (i.e., via "&cf->cycle->new_log")
     */

    fake_cycle = njt_palloc(cycle->pool, sizeof(njt_cycle_t));
    if (fake_cycle == NULL) {
        goto failed;
    }

    njt_memcpy(fake_cycle, cycle, sizeof(njt_cycle_t));

    njt_queue_init(&fake_cycle->reusable_connections_queue);

    if (njt_array_init(&fake_cycle->listening, cycle->pool,
                       cycle->listening.nelts ? cycle->listening.nelts : 1,
                       sizeof(njt_listening_t))
        != NJT_OK)
    {
        goto failed;
    }

    if (njt_array_init(&fake_cycle->paths, cycle->pool,
                       cycle->paths.nelts ? cycle->paths.nelts : 1,
                       sizeof(njt_path_t *))
        != NJT_OK)
    {
        goto failed;
    }

    part = &cycle->open_files.part;
    ofile = part->elts;

    if (njt_list_init(&fake_cycle->open_files, cycle->pool,
                      part->nelts ? part->nelts : 1,
                      sizeof(njt_open_file_t))
        != NJT_OK)
    {
        goto failed;
    }

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            ofile = part->elts;
            i = 0;
        }

        file = njt_list_push(&fake_cycle->open_files);
        if (file == NULL) {
            goto failed;
        }

        njt_memcpy(file, ofile, sizeof(njt_open_file_t));
    }

    if (njt_list_init(&fake_cycle->shared_memory, cycle->pool, 1,
                      sizeof(njt_shm_zone_t))
        != NJT_OK)
    {
        goto failed;
    }

    conf.ctx = &http_ctx;
    conf.cycle = fake_cycle;
    conf.pool = fake_cycle->pool;
    conf.log = cycle->log;

    njt_memzero(&cf_file, sizeof(cf_file));
    cf_file.file.name = cycle->conf_file;
    conf.conf_file = &cf_file;

    http_ctx.loc_conf = njt_pcalloc(conf.pool,
                                    sizeof(void *) * njt_http_max_module);
    if (http_ctx.loc_conf == NULL) {
        return NJT_ERROR;
    }

    http_ctx.srv_conf = njt_pcalloc(conf.pool,
                                    sizeof(void *) * njt_http_max_module);
    if (http_ctx.srv_conf == NULL) {
        return NJT_ERROR;
    }

#if (njet_version >= 1009011)
    modules = cycle->modules;
#else
    modules = njt_modules;
#endif

    for (i = 0; modules[i]; i++) {
        if (modules[i]->type != NJT_HTTP_MODULE) {
            continue;
        }

        module = modules[i]->ctx;

        if (module->create_srv_conf) {
            cur = module->create_srv_conf(&conf);
            if (cur == NULL) {
                return NJT_ERROR;
            }

            http_ctx.srv_conf[modules[i]->ctx_index] = cur;

            if (module->merge_srv_conf) {
                prev = module->create_srv_conf(&conf);
                if (prev == NULL) {
                    return NJT_ERROR;
                }

                rv = module->merge_srv_conf(&conf, prev, cur);
                if (rv != NJT_CONF_OK) {
                    goto failed;
                }
            }
        }

        if (module->create_loc_conf) {
            cur = module->create_loc_conf(&conf);
            if (cur == NULL) {
                return NJT_ERROR;
            }

            http_ctx.loc_conf[modules[i]->ctx_index] = cur;

            if (module->merge_loc_conf) {
                if (modules[i] == &njt_http_lua_module) {
                    prev = top_llcf;

                } else if (modules[i] == &njt_http_core_module) {
                    prev = top_clcf;

                } else {
                    prev = module->create_loc_conf(&conf);
                    if (prev == NULL) {
                        return NJT_ERROR;
                    }
                }

                rv = module->merge_loc_conf(&conf, prev, cur);
                if (rv != NJT_CONF_OK) {
                    goto failed;
                }
            }
        }
    }

    njt_destroy_pool(conf.temp_pool);
    conf.temp_pool = NULL;

    c = njt_http_lua_create_fake_connection(NULL);
    if (c == NULL) {
        goto failed;
    }

    c->log->handler = njt_http_lua_log_init_worker_error;

    r = njt_http_lua_create_fake_request(c);
    if (r == NULL) {
        goto failed;
    }

    r->main_conf = http_ctx.main_conf;
    r->srv_conf = http_ctx.srv_conf;
    r->loc_conf = http_ctx.loc_conf;

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

#if (njet_version >= 1009000)
    njt_set_connection_log(r->connection, clcf->error_log);

#else
    njt_http_set_connection_log(r->connection, clcf->error_log);
#endif

    ctx = njt_http_lua_create_ctx(r);
    if (ctx == NULL) {
        goto failed;
    }

    ctx->context = NJT_HTTP_LUA_CONTEXT_INIT_WORKER;
    ctx->cur_co_ctx = NULL;
    r->read_event_handler = njt_http_block_reading;

    njt_http_lua_set_req(lmcf->lua, r);

    (void) lmcf->init_worker_handler(cycle->log, lmcf, lmcf->lua);

    njt_destroy_pool(c->pool);
    return NJT_OK;

failed:

    if (conf.temp_pool) {
        njt_destroy_pool(conf.temp_pool);
    }

    if (c) {
        njt_http_lua_close_fake_connection(c);
    }

    return NJT_ERROR;
}


njt_int_t
njt_http_lua_init_worker_by_inline(njt_log_t *log,
    njt_http_lua_main_conf_t *lmcf, lua_State *L)
{
    int         status;
    const char *chunkname;

    if (lmcf->init_worker_chunkname == NULL) {
        chunkname = "=init_worker_by_lua";

    } else {
        chunkname = (const char *) lmcf->init_worker_chunkname;
    }

    status = luaL_loadbuffer(L, (char *) lmcf->init_worker_src.data,
                             lmcf->init_worker_src.len, chunkname)
             || njt_http_lua_do_call(log, L);

    return njt_http_lua_report(log, L, status, "init_worker_by_lua");
}


njt_int_t
njt_http_lua_init_worker_by_file(njt_log_t *log, njt_http_lua_main_conf_t *lmcf,
    lua_State *L)
{
    int         status;

    status = luaL_loadfile(L, (char *) lmcf->init_worker_src.data)
             || njt_http_lua_do_call(log, L);

    return njt_http_lua_report(log, L, status, "init_worker_by_lua_file");
}


static u_char *
njt_http_lua_log_init_worker_error(njt_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;

    if (log->action) {
        p = njt_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    return njt_snprintf(buf, len, ", context: init_worker_by_lua*");
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
