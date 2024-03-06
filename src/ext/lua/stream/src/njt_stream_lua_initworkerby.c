
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_initworkerby.c.tt2
 */


/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_stream_lua_initworkerby.h"
#include "njt_stream_lua_util.h"

#include "njt_stream_lua_contentby.h"



static u_char *njt_stream_lua_log_init_worker_error(njt_log_t *log,
    u_char *buf, size_t len);


njt_int_t
njt_stream_lua_init_worker(njt_cycle_t *cycle)
{
    char                            *rv;
    void                            *cur, *prev;
    njt_uint_t                       i;
    njt_conf_t                       conf;
    njt_cycle_t                     *fake_cycle;
    njt_module_t                   **modules;
    njt_open_file_t                 *file, *ofile;
    njt_list_part_t                 *part;
    njt_connection_t                *c = NULL;
    njt_stream_module_t             *module;
    njt_stream_lua_request_t        *r = NULL;
    njt_stream_lua_ctx_t            *ctx;
    njt_stream_conf_ctx_t           *conf_ctx, stream_ctx;

    njt_stream_lua_main_conf_t          *lmcf;

    njt_conf_file_t         *conf_file;
    njt_stream_session_t    *s;

    njt_stream_core_srv_conf_t    *cscf, *top_cscf;
    njt_stream_lua_srv_conf_t     *lscf, *top_lscf;

    lmcf = njt_stream_cycle_get_module_main_conf(cycle, njt_stream_lua_module);

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

        njt_log_debug2(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0,
                       "lua close the global Lua VM %p in the "
                       "cache helper process %P", lmcf->lua, njt_pid);

        lmcf->vm_cleanup->handler(lmcf->vm_cleanup->data);
        lmcf->vm_cleanup->handler = NULL;

        return NJT_OK;
    }


#endif  /* NJT_WIN32 */

#if (NJT_STREAM_LUA_HAVE_SA_RESTART)
    if (lmcf->set_sa_restart) {
        njt_stream_lua_set_sa_restart(njt_cycle->log);
    }
#endif

    if (lmcf->init_worker_handler == NULL) {
        return NJT_OK;
    }

    conf_ctx = (njt_stream_conf_ctx_t *)
               cycle->conf_ctx[njt_stream_module.index];
    stream_ctx.main_conf = conf_ctx->main_conf;

    top_cscf = conf_ctx->srv_conf[njt_stream_core_module.ctx_index];
    top_lscf = conf_ctx->srv_conf[njt_stream_lua_module.ctx_index];

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
     * because some modules like njt_stream_core_module reference
     * addresses within cf->cycle (i.e., via "&cf->cycle->new_log")
     */

    fake_cycle = njt_palloc(cycle->pool, sizeof(njt_cycle_t));
    if (fake_cycle == NULL) {
        goto failed;
    }

    njt_memcpy(fake_cycle, cycle, sizeof(njt_cycle_t));

    njt_queue_init(&fake_cycle->reusable_connections_queue);

    if (njt_array_init(&fake_cycle->listening, cycle->pool,
                       cycle->listening.nelts || 1,
                       sizeof(njt_listening_t))
        != NJT_OK)
    {
        goto failed;
    }

    if (njt_array_init(&fake_cycle->paths, cycle->pool, cycle->paths.nelts || 1,
                       sizeof(njt_path_t *))
        != NJT_OK)
    {
        goto failed;
    }

    part = &cycle->open_files.part;
    ofile = part->elts;

    if (njt_list_init(&fake_cycle->open_files, cycle->pool, part->nelts || 1,
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

    conf_file = njt_pcalloc(fake_cycle->pool, sizeof(njt_conf_file_t));
    if (conf_file == NULL) {
        return NJT_ERROR;
    }

    /* workaround to make njt_stream_core_create_srv_conf not SEGFAULT */
    conf_file->file.name.data = (u_char *) "dummy";
    conf_file->file.name.len = sizeof("dummy") - 1;
    conf_file->line = 1;
    conf.conf_file = conf_file;

    conf.ctx = &stream_ctx;
    conf.cycle = fake_cycle;
    conf.pool = fake_cycle->pool;
    conf.log = cycle->log;


    stream_ctx.srv_conf = njt_pcalloc(conf.pool,
                                      sizeof(void *) * njt_stream_max_module);
    if (stream_ctx.srv_conf == NULL) {
        return NJT_ERROR;
    }

#if defined(njet_version) && njet_version >= 1009011
    modules = cycle->modules;
#else
    modules = njt_modules;
#endif

    for (i = 0; modules[i]; i++) {
        if (modules[i]->type != NJT_STREAM_MODULE) {
            continue;
        }

        module = modules[i]->ctx;

        if (module->create_srv_conf) {
            cur = module->create_srv_conf(&conf);
            if (cur == NULL) {
                return NJT_ERROR;
            }

            stream_ctx.srv_conf[modules[i]->ctx_index] = cur;

            if (modules[i]->ctx_index == njt_stream_core_module.ctx_index) {
                cscf = cur;
                /* just to silence the error in
                 * njt_stream_core_merge_srv_conf */
                cscf->handler = njt_stream_lua_content_handler;
            }

            if (module->merge_srv_conf) {
                if (modules[i] == &njt_stream_lua_module) {
                    prev = top_lscf;

                } else if (modules[i] == &njt_stream_core_module) {
                    prev = top_cscf;

                } else {
                    prev = module->create_srv_conf(&conf);
                    if (prev == NULL) {
                        return NJT_ERROR;
                    }
                }

                rv = module->merge_srv_conf(&conf, prev, cur);
                if (rv != NJT_CONF_OK) {
                    goto failed;
                }
            }
        }

    }

    njt_destroy_pool(conf.temp_pool);
    conf.temp_pool = NULL;

    c = njt_stream_lua_create_fake_connection(NULL);
    if (c == NULL) {
        goto failed;
    }

    c->log->handler = njt_stream_lua_log_init_worker_error;

    s = njt_stream_lua_create_fake_session(c);
    if (s == NULL) {
        goto failed;
    }

    s->main_conf = stream_ctx.main_conf;
    s->srv_conf = stream_ctx.srv_conf;

    cscf = njt_stream_get_module_srv_conf(s, njt_stream_core_module);

    lscf = njt_stream_get_module_srv_conf(s, njt_stream_lua_module);

    if (top_lscf->log_socket_errors != NJT_CONF_UNSET) {
        lscf->log_socket_errors = top_lscf->log_socket_errors;
    }

    if (top_cscf->resolver != NULL) {
        cscf->resolver = top_cscf->resolver;
    }

    if (top_cscf->resolver_timeout != NJT_CONF_UNSET_MSEC) {
        cscf->resolver_timeout = top_cscf->resolver_timeout;
    }

#if defined(njet_version) && njet_version >= 1009000
    njt_set_connection_log(s->connection, cscf->error_log);

#else
#endif

    ctx = njt_stream_lua_create_ctx(s);
    if (ctx == NULL) {
        goto failed;
    }

    r = ctx->request;

    ctx->context = NJT_STREAM_LUA_CONTEXT_INIT_WORKER;
    ctx->cur_co_ctx = NULL;
    r->read_event_handler = njt_stream_lua_block_reading;

    njt_stream_lua_set_req(lmcf->lua, r);

    (void) lmcf->init_worker_handler(cycle->log, lmcf, lmcf->lua);

    njt_destroy_pool(c->pool);
    return NJT_OK;

failed:

    if (conf.temp_pool) {
        njt_destroy_pool(conf.temp_pool);
    }

    if (c) {
        njt_stream_lua_close_fake_connection(c);
    }

    return NJT_ERROR;
}


njt_int_t
njt_stream_lua_init_worker_by_inline(njt_log_t *log,
    njt_stream_lua_main_conf_t *lmcf, lua_State *L)
{
    int         status;

    status = luaL_loadbuffer(L, (char *) lmcf->init_worker_src.data,
                             lmcf->init_worker_src.len, "=init_worker_by_lua")
             || njt_stream_lua_do_call(log, L);

    return njt_stream_lua_report(log, L, status, "init_worker_by_lua");
}


njt_int_t
njt_stream_lua_init_worker_by_file(njt_log_t *log,
    njt_stream_lua_main_conf_t *lmcf, lua_State *L)
{
    int         status;

    status = luaL_loadfile(L, (char *) lmcf->init_worker_src.data)
             || njt_stream_lua_do_call(log, L);

    return njt_stream_lua_report(log, L, status, "init_worker_by_lua_file");
}


static u_char *
njt_stream_lua_log_init_worker_error(njt_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;

    if (log->action) {
        p = njt_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    return njt_snprintf(buf, len, ", context: init_worker_by_lua*");
}
