
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


static void njt_destroy_cycle_pools(njt_conf_t *conf);
static njt_int_t njt_init_zone_pool(njt_cycle_t *cycle,
    njt_shm_zone_t *shm_zone);
static njt_int_t njt_test_lockfile(u_char *file, njt_log_t *log);
static void njt_clean_old_cycles(njt_event_t *ev);
static void njt_shutdown_timer_handler(njt_event_t *ev);
static void njt_replace_pool_log(njt_pool_t *pool, 
    njt_log_t *old_log, njt_log_t *new_log);


volatile njt_cycle_t  *njt_cycle;
njt_array_t            njt_old_cycles;

static njt_pool_t     *njt_temp_pool;
static njt_event_t     njt_cleaner_event;
static njt_event_t     njt_shutdown_event;

njt_uint_t             njt_test_config;
njt_uint_t             njt_dump_config;
njt_uint_t             njt_quiet_mode;


/* STUB NAME */
static njt_connection_t  dumb;
/* STUB */

static void
njt_replace_pool_log(njt_pool_t *pool, njt_log_t *old_log, njt_log_t *new_log)
{
    // by Clb
#if (NJT_DYNAMIC_POOL)
    njt_pool_t          *sub_pool;
    njt_queue_t         *sub_queue;

    if(pool->log == old_log){
        pool->log = new_log;
    } 
 
    for (sub_queue = njt_queue_head(&pool->sub_pools);
         sub_queue != njt_queue_sentinel(&pool->sub_pools); ){
        sub_pool = njt_queue_data(sub_queue,njt_pool_t,parent_pool);
        sub_queue = njt_queue_next(sub_queue);  // 先计算偏移防止节点被删除
        njt_replace_pool_log(sub_pool, old_log, new_log);
    }
#endif
}

extern char *
njt_conf_parse_post_helper(njt_cycle_t *cycle);

static char *
njt_conf_parse_post(njt_cycle_t *cycle)
{
    return njt_conf_parse_post_helper(cycle);
}

njt_cycle_t *
njt_init_cycle(njt_cycle_t *old_cycle)
{
    void                *rv;
    char               **senv;
    njt_uint_t           i, n;
    njt_log_t           *log;
    njt_time_t          *tp;
    njt_conf_t           conf;
    njt_pool_t          *pool;
    njt_cycle_t         *cycle, **old;
    njt_shm_zone_t      *shm_zone, *oshm_zone;
    njt_list_part_t     *part, *opart;
    njt_open_file_t     *file;
    njt_listening_t     *ls, *nls;
    njt_core_conf_t     *ccf, *old_ccf;
    njt_core_module_t   *module;
    njt_log_t           *old_log;
    char                 hostname[NJT_MAXHOSTNAMELEN];

    njt_timezone_update();

    /* force localtime update with a new timezone */

    tp = njt_timeofday();
    tp->sec = 0;

    njt_time_update();


    log = old_cycle->log;

    pool = njt_create_pool(NJT_CYCLE_POOL_SIZE, log);
    if (pool == NULL) {
        return NULL;
    }

    pool->log = log;

    cycle = njt_pcalloc(pool, sizeof(njt_cycle_t));
    if (cycle == NULL) {
        njt_destroy_pool(pool);
        return NULL;
    }

    cycle->pool = pool;
    cycle->log = log;
    cycle->old_cycle = old_cycle;

    cycle->conf_prefix.len = old_cycle->conf_prefix.len;
    cycle->conf_prefix.data = njt_pstrdup(pool, &old_cycle->conf_prefix);
    if (cycle->conf_prefix.data == NULL) {
        njt_destroy_pool(pool);
        return NULL;
    }

    cycle->prefix.len = old_cycle->prefix.len;
    cycle->prefix.data = njt_pstrdup(pool, &old_cycle->prefix);
    if (cycle->prefix.data == NULL) {
        njt_destroy_pool(pool);
        return NULL;
    }

    cycle->error_log.len = old_cycle->error_log.len;
    cycle->error_log.data = njt_pnalloc(pool, old_cycle->error_log.len + 1);
    if (cycle->error_log.data == NULL) {
        njt_destroy_pool(pool);
        return NULL;
    }
    njt_cpystrn(cycle->error_log.data, old_cycle->error_log.data,
                old_cycle->error_log.len + 1);

    cycle->conf_file.len = old_cycle->conf_file.len;
    cycle->conf_file.data = njt_pnalloc(pool, old_cycle->conf_file.len + 1);
    if (cycle->conf_file.data == NULL) {
        njt_destroy_pool(pool);
        return NULL;
    }
    njt_cpystrn(cycle->conf_file.data, old_cycle->conf_file.data,
                old_cycle->conf_file.len + 1);

    cycle->conf_param.len = old_cycle->conf_param.len;
    cycle->conf_param.data = njt_pstrdup(pool, &old_cycle->conf_param);
    if (cycle->conf_param.data == NULL) {
        njt_destroy_pool(pool);
        return NULL;
    }


    n = old_cycle->paths.nelts ? old_cycle->paths.nelts : 10;

    if (njt_array_init(&cycle->paths, pool, n, sizeof(njt_path_t *))
        != NJT_OK)
    {
        njt_destroy_pool(pool);
        return NULL;
    }

    njt_memzero(cycle->paths.elts, n * sizeof(njt_path_t *));


    if (njt_array_init(&cycle->config_dump, pool, 1, sizeof(njt_conf_dump_t))
        != NJT_OK)
    {
        njt_destroy_pool(pool);
        return NULL;
    }

    njt_rbtree_init(&cycle->config_dump_rbtree, &cycle->config_dump_sentinel,
                    njt_str_rbtree_insert_value);
    cycle->old_config_dump_rbtree = cycle->config_dump_rbtree;
    if (old_cycle->open_files.part.nelts) {
        n = old_cycle->open_files.part.nelts;
        for (part = old_cycle->open_files.part.next; part; part = part->next) {
            n += part->nelts;
        }

    } else {
        n = 20;
    }

    if (njt_list_init(&cycle->open_files, pool, n, sizeof(njt_open_file_t))
        != NJT_OK)
    {
        njt_destroy_pool(pool);
        return NULL;
    }


    if (old_cycle->shared_memory.part.nelts) {
        n = old_cycle->shared_memory.part.nelts;
        for (part = old_cycle->shared_memory.part.next; part; part = part->next)
        {
            n += part->nelts;
        }

    } else {
        n = 1;
    }

    if (njt_list_init(&cycle->shared_memory, pool, n, sizeof(njt_shm_zone_t))
        != NJT_OK)
    {
        njt_destroy_pool(pool);
        return NULL;
    }

    n = old_cycle->listening.nelts ? old_cycle->listening.nelts : 10;

    if (njt_array_init(&cycle->listening, pool, n, sizeof(njt_listening_t))
        != NJT_OK)
    {
        njt_destroy_pool(pool);
        return NULL;
    }

    njt_memzero(cycle->listening.elts, n * sizeof(njt_listening_t));


    njt_queue_init(&cycle->reusable_connections_queue);


    cycle->conf_ctx = njt_pcalloc(pool, njt_max_module * sizeof(void *));
    if (cycle->conf_ctx == NULL) {
        njt_destroy_pool(pool);
        return NULL;
    }


    if (gethostname(hostname, NJT_MAXHOSTNAMELEN) == -1) {
        njt_log_error(NJT_LOG_EMERG, log, njt_errno, "gethostname() failed");
        njt_destroy_pool(pool);
        return NULL;
    }

    /* on Linux gethostname() silently truncates name that does not fit */

    hostname[NJT_MAXHOSTNAMELEN - 1] = '\0';
    cycle->hostname.len = njt_strlen(hostname);

    cycle->hostname.data = njt_pnalloc(pool, cycle->hostname.len);
    if (cycle->hostname.data == NULL) {
        njt_destroy_pool(pool);
        return NULL;
    }

    njt_strlow(cycle->hostname.data, (u_char *) hostname, cycle->hostname.len);


    if (njt_cycle_modules(cycle) != NJT_OK) {
        njt_destroy_pool(pool);
        return NULL;
    }


    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->type != NJT_CORE_MODULE) {
            continue;
        }

        module = cycle->modules[i]->ctx;

        if (module->create_conf) {
            rv = module->create_conf(cycle);
            if (rv == NULL) {
                njt_destroy_pool(pool);
                return NULL;
            }
            cycle->conf_ctx[cycle->modules[i]->index] = rv;
        }
    }


    senv = environ;

    njt_memzero(&conf, sizeof(njt_conf_t));
    /* STUB: init array ? */
    conf.args = njt_array_create(pool, 10, sizeof(njt_str_t));
    if (conf.args == NULL) {
        njt_destroy_pool(pool);
        return NULL;
    }

    conf.temp_pool = njt_create_pool(NJT_CYCLE_POOL_SIZE, log);
    if (conf.temp_pool == NULL) {
        njt_destroy_pool(pool);
        return NULL;
    }

    conf.ctx = cycle->conf_ctx;
    conf.cycle = cycle;
    conf.pool = pool;
    conf.log = log;
    conf.module_type = NJT_CORE_MODULE;
    conf.cmd_type = NJT_MAIN_CONF;

#if 0
    log->log_level = NJT_LOG_DEBUG_ALL;
#endif

    if (njt_conf_param(&conf) != NJT_CONF_OK) {
        environ = senv;
        njt_destroy_cycle_pools(&conf);
        return NULL;
    }

#if (NJT_HELPER_GO_DYNCONF) // by lcm
    njt_conf_element_t *conf_root;
    cycle->conf_root = njt_pcalloc(cycle->pool, sizeof(njt_conf_element_t));
    conf_root = cycle->conf_root;
    njt_memzero(conf_root, sizeof(njt_conf_element_t));
    njt_conf_init_conf_parse(cycle->conf_root, cycle->pool);
#endif



    if (njt_conf_parse(&conf, &cycle->conf_file) != NJT_CONF_OK) {
        environ = senv;
        njt_destroy_cycle_pools(&conf);
        return NULL;
    }

#if (NJT_HELPER_GO_DYNCONF) // by lcm
    njt_conf_finish_conf_parse();
    njt_conf_check_svrname_listen(pool, conf_root);
#endif

    if (njt_conf_parse_post(cycle) != NJT_CONF_OK) {
        environ = senv;
        njt_destroy_cycle_pools(&conf);
        return NULL;
    }

    if (njt_test_config && !njt_quiet_mode) {
        njt_log_stderr(0, "the configuration file %s syntax is ok",
                       cycle->conf_file.data);
    }

    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->type != NJT_CORE_MODULE) {
            continue;
        }

        module = cycle->modules[i]->ctx;

        if (module->init_conf) {
            if (module->init_conf(cycle,
                                  cycle->conf_ctx[cycle->modules[i]->index])
                == NJT_CONF_ERROR)
            {
                environ = senv;
                njt_destroy_cycle_pools(&conf);
                return NULL;
            }
        }
    }

    if (njt_process == NJT_PROCESS_SIGNALLER) {
        return cycle;
    }

    ccf = (njt_core_conf_t *) njt_get_conf(cycle->conf_ctx, njt_core_module);

    if (njt_test_config) {

        if (njt_create_pidfile(&ccf->pid, log) != NJT_OK) {
            goto failed;
        }

    } else if (!njt_is_init_cycle(old_cycle)) {

        /*
         * we do not create the pid file in the first njt_init_cycle() call
         * because we need to write the demonized process pid
         */

        old_ccf = (njt_core_conf_t *) njt_get_conf(old_cycle->conf_ctx,
                                                   njt_core_module);
        if (ccf->pid.len != old_ccf->pid.len
            || njt_strcmp(ccf->pid.data, old_ccf->pid.data) != 0)
        {
            /* new pid file name */

            if (njt_create_pidfile(&ccf->pid, log) != NJT_OK) {
                goto failed;
            }

            if (njt_process != NJT_PROCESS_HELPER) {
                njt_delete_pidfile(old_cycle);
            }
        }
    }


    if (njt_test_lockfile(cycle->lock_file.data, log) != NJT_OK) {
        goto failed;
    }


    if (njt_create_paths(cycle, ccf->user) != NJT_OK) {
        goto failed;
    }


    if (njt_log_open_default(cycle) != NJT_OK) {
        goto failed;
    }

    /* open the new files */

    part = &cycle->open_files.part;
    file = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            file = part->elts;
            i = 0;
        }

        if (file[i].name.len == 0) {
            continue;
        }

        file[i].fd = njt_open_file(file[i].name.data,
                                   NJT_FILE_APPEND,
                                   NJT_FILE_CREATE_OR_OPEN,
                                   NJT_FILE_DEFAULT_ACCESS);

        njt_log_debug3(NJT_LOG_DEBUG_CORE, log, 0,
                       "log: %p %d \"%s\"",
                       &file[i], file[i].fd, file[i].name.data);

        if (file[i].fd == NJT_INVALID_FILE) {
            njt_log_error(NJT_LOG_EMERG, log, njt_errno,
                          njt_open_file_n " \"%s\" failed",
                          file[i].name.data);
            goto failed;
        }

#if !(NJT_WIN32)
        if (fcntl(file[i].fd, F_SETFD, FD_CLOEXEC) == -1) {
            njt_log_error(NJT_LOG_EMERG, log, njt_errno,
                          "fcntl(FD_CLOEXEC) \"%s\" failed",
                          file[i].name.data);
            goto failed;
        }
#endif
    }

    //save old log
    old_log = cycle->log;

    cycle->log = &cycle->new_log;
    pool->log = &cycle->new_log;

    //foreach
    njt_replace_pool_log(conf.pool, old_log, pool->log);

    /* create shared memory */

    part = &cycle->shared_memory.part;
    shm_zone = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            shm_zone = part->elts;
            i = 0;
        }

        if (shm_zone[i].shm.size == 0) {
            njt_log_error(NJT_LOG_EMERG, log, 0,
                          "zero size shared memory zone \"%V\"",
                          &shm_zone[i].shm.name);
            goto failed;
        }

        shm_zone[i].shm.log = cycle->log;

        opart = &old_cycle->shared_memory.part;
        oshm_zone = opart->elts;

        for (n = 0; /* void */ ; n++) {

            if (n >= opart->nelts) {
                if (opart->next == NULL) {
                    break;
                }
                opart = opart->next;
                oshm_zone = opart->elts;
                n = 0;
            }

            if (shm_zone[i].shm.name.len != oshm_zone[n].shm.name.len) {
                continue;
            }

            if (njt_strncmp(shm_zone[i].shm.name.data,
                            oshm_zone[n].shm.name.data,
                            shm_zone[i].shm.name.len)
                != 0)
            {
                continue;
            }

            if (shm_zone[i].tag == oshm_zone[n].tag
                && shm_zone[i].shm.size == oshm_zone[n].shm.size
                && !shm_zone[i].noreuse)
            {
                shm_zone[i].shm.addr = oshm_zone[n].shm.addr;
#if (NJT_WIN32)
                shm_zone[i].shm.handle = oshm_zone[n].shm.handle;
#endif

                if (shm_zone[i].init(&shm_zone[i], oshm_zone[n].data)
                    != NJT_OK)
                {
                    goto failed;
                }

                goto shm_zone_found;
            } else if (shm_zone[i].tag == oshm_zone[n].tag
		&& shm_zone[i].shm.size == oshm_zone[n].shm.size
		&& shm_zone[i].noreuse == 1 && shm_zone[i].merge != NULL){
			shm_zone[i].merge(&shm_zone[i], oshm_zone[n].data);
		}

            break;
        }

        if (njt_shm_alloc(&shm_zone[i].shm) != NJT_OK) {
            goto failed;
        }

        if (njt_init_zone_pool(cycle, &shm_zone[i]) != NJT_OK) {
            goto failed;
        }

        if (shm_zone[i].init(&shm_zone[i], NULL) != NJT_OK) {
            goto failed;
        }

    shm_zone_found:

        continue;
    }


    /* handle the listening sockets */

    if (old_cycle->listening.nelts) {
        ls = old_cycle->listening.elts;
        for (i = 0; i < old_cycle->listening.nelts; i++) {
            ls[i].remain = 0;
        }

        nls = cycle->listening.elts;
        for (n = 0; n < cycle->listening.nelts; n++) {

            for (i = 0; i < old_cycle->listening.nelts; i++) {
                if (ls[i].ignore) {
                    continue;
                }

                if (ls[i].remain) {
                    continue;
                }

                if (ls[i].type != nls[n].type) {
                    continue;
                }

                if (njt_cmp_sockaddr(nls[n].sockaddr, nls[n].socklen,
                                     ls[i].sockaddr, ls[i].socklen, 1)
                    == NJT_OK)
                {
                    nls[n].fd = ls[i].fd;
                    nls[n].inherited = ls[i].inherited;
                    nls[n].previous = &ls[i];
                    ls[i].remain = 1;

                    if (ls[i].backlog != nls[n].backlog) {
                        nls[n].listen = 1;
                    }

#if (NJT_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)

                    /*
                     * FreeBSD, except the most recent versions,
                     * could not remove accept filter
                     */
                    nls[n].deferred_accept = ls[i].deferred_accept;

                    if (ls[i].accept_filter && nls[n].accept_filter) {
                        if (njt_strcmp(ls[i].accept_filter,
                                       nls[n].accept_filter)
                            != 0)
                        {
                            nls[n].delete_deferred = 1;
                            nls[n].add_deferred = 1;
                        }

                    } else if (ls[i].accept_filter) {
                        nls[n].delete_deferred = 1;

                    } else if (nls[n].accept_filter) {
                        nls[n].add_deferred = 1;
                    }
#endif

#if (NJT_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)

                    if (ls[i].deferred_accept && !nls[n].deferred_accept) {
                        nls[n].delete_deferred = 1;

                    } else if (ls[i].deferred_accept != nls[n].deferred_accept)
                    {
                        nls[n].add_deferred = 1;
                    }
#endif

#if (NJT_HAVE_REUSEPORT)
                    if (nls[n].reuseport && !ls[i].reuseport) {
                        nls[n].add_reuseport = 1;
                    }
#endif

                    break;
                }
            }

            if (nls[n].fd == (njt_socket_t) -1) {
                nls[n].open = 1;
#if (NJT_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
                if (nls[n].accept_filter) {
                    nls[n].add_deferred = 1;
                }
#endif
#if (NJT_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
                if (nls[n].deferred_accept) {
                    nls[n].add_deferred = 1;
                }
#endif
            }
        }

    } else {
        ls = cycle->listening.elts;
        for (i = 0; i < cycle->listening.nelts; i++) {
            ls[i].open = 1;
#if (NJT_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
            if (ls[i].accept_filter) {
                ls[i].add_deferred = 1;
            }
#endif
#if (NJT_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
            if (ls[i].deferred_accept) {
                ls[i].add_deferred = 1;
            }
#endif
        }
    }

    if (njt_open_listening_sockets(cycle) != NJT_OK) {
        goto failed;
    }

    if (!njt_test_config) {
        njt_configure_listening_sockets(cycle);
    }


    /* commit the new cycle configuration */

    if (!njt_use_stderr) {
        (void) njt_log_redirect_stderr(cycle);
    }

    pool->log = cycle->log;

    if (njt_init_modules(cycle) != NJT_OK) {
        /* fatal */
        exit(1);
    }


    /* close and delete stuff that lefts from an old cycle */

    /* free the unnecessary shared memory */

    opart = &old_cycle->shared_memory.part;
    oshm_zone = opart->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= opart->nelts) {
            if (opart->next == NULL) {
                goto old_shm_zone_done;
            }
            opart = opart->next;
            oshm_zone = opart->elts;
            i = 0;
        }

        part = &cycle->shared_memory.part;
        shm_zone = part->elts;

        for (n = 0; /* void */ ; n++) {

            if (n >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }
                part = part->next;
                shm_zone = part->elts;
                n = 0;
            }

            if (oshm_zone[i].shm.name.len != shm_zone[n].shm.name.len) {
                continue;
            }

            if (njt_strncmp(oshm_zone[i].shm.name.data,
                            shm_zone[n].shm.name.data,
                            oshm_zone[i].shm.name.len)
                != 0)
            {
                continue;
            }

            if (oshm_zone[i].tag == shm_zone[n].tag
                && oshm_zone[i].shm.size == shm_zone[n].shm.size
                && !oshm_zone[i].noreuse)
            {
                goto live_shm_zone;
            }

            break;
        }

        njt_shm_free(&oshm_zone[i].shm);

    live_shm_zone:

        continue;
    }

old_shm_zone_done:


    /* close the unnecessary listening sockets */

    ls = old_cycle->listening.elts;
    for (i = 0; i < old_cycle->listening.nelts; i++) {

        if (ls[i].remain || ls[i].fd == (njt_socket_t) -1) {
            continue;
        }

        if (njt_close_socket(ls[i].fd) == -1) {
            njt_log_error(NJT_LOG_EMERG, log, njt_socket_errno,
                          njt_close_socket_n " listening socket on %V failed",
                          &ls[i].addr_text);
        }

#if (NJT_HAVE_UNIX_DOMAIN)

        if (ls[i].sockaddr->sa_family == AF_UNIX) {
            u_char  *name;

            name = ls[i].addr_text.data + sizeof("unix:") - 1;

            njt_log_error(NJT_LOG_WARN, cycle->log, 0,
                          "deleting socket %s", name);

            if (njt_delete_file(name) == NJT_FILE_ERROR) {
                njt_log_error(NJT_LOG_EMERG, cycle->log, njt_socket_errno,
                              njt_delete_file_n " %s failed", name);
            }
        }

#endif
    }


    /* close the unnecessary open files */

    part = &old_cycle->open_files.part;
    file = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            file = part->elts;
            i = 0;
        }

        if (file[i].fd == NJT_INVALID_FILE || file[i].fd == njt_stderr) {
            continue;
        }

        if (njt_close_file(file[i].fd) == NJT_FILE_ERROR) {
            njt_log_error(NJT_LOG_EMERG, log, njt_errno,
                          njt_close_file_n " \"%s\" failed",
                          file[i].name.data);
        }
    }
    // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
    if (njt_sub_pool(conf.pool,conf.temp_pool) != NJT_OK){
        njt_log_error(NJT_LOG_EMERG, cycle->log, 0,
                      "could not set sub_pool njt_temp_pool");
        exit(1);
    }
#else
    njt_destroy_pool(conf.temp_pool);
#endif
    //end
    if (njt_process == NJT_PROCESS_MASTER || njt_is_init_cycle(old_cycle)) {

        // openresty patch
        if (njt_is_init_cycle(old_cycle)) {
            saved_init_cycle_pool = NULL;
        }
        // openresty patch end

        njt_destroy_pool(old_cycle->pool);
        cycle->old_cycle = NULL;

        return cycle;
    }


    if (njt_temp_pool == NULL) {
        njt_temp_pool = njt_create_pool(128, cycle->log);
        if (njt_temp_pool == NULL) {
            njt_log_error(NJT_LOG_EMERG, cycle->log, 0,
                          "could not create njt_temp_pool");
            exit(1);
        }

        n = 10;

        if (njt_array_init(&njt_old_cycles, njt_temp_pool, n,
                           sizeof(njt_cycle_t *))
            != NJT_OK)
        {
            exit(1);
        }

        njt_memzero(njt_old_cycles.elts, n * sizeof(njt_cycle_t *));

        njt_cleaner_event.handler = njt_clean_old_cycles;
        njt_cleaner_event.log = cycle->log;
        njt_cleaner_event.data = &dumb;
        dumb.fd = (njt_socket_t) -1;
    }

    njt_temp_pool->log = cycle->log;

    old = njt_array_push(&njt_old_cycles);
    if (old == NULL) {
        exit(1);
    }
    *old = old_cycle;

    if (!njt_cleaner_event.timer_set) {
        njt_add_timer(&njt_cleaner_event, 30000);
        njt_cleaner_event.timer_set = 1;
    }

    return cycle;


failed:

    if (!njt_is_init_cycle(old_cycle)) {
        old_ccf = (njt_core_conf_t *) njt_get_conf(old_cycle->conf_ctx,
                                                   njt_core_module);
        if (old_ccf->environment) {
            environ = old_ccf->environment;
        }
    }

    /* rollback the new cycle configuration */

    part = &cycle->open_files.part;
    file = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            file = part->elts;
            i = 0;
        }

        if (file[i].fd == NJT_INVALID_FILE || file[i].fd == njt_stderr) {
            continue;
        }

        if (njt_close_file(file[i].fd) == NJT_FILE_ERROR) {
            njt_log_error(NJT_LOG_EMERG, log, njt_errno,
                          njt_close_file_n " \"%s\" failed",
                          file[i].name.data);
        }
    }

    /* free the newly created shared memory */

    part = &cycle->shared_memory.part;
    shm_zone = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            shm_zone = part->elts;
            i = 0;
        }

        if (shm_zone[i].shm.addr == NULL) {
            continue;
        }

        opart = &old_cycle->shared_memory.part;
        oshm_zone = opart->elts;

        for (n = 0; /* void */ ; n++) {

            if (n >= opart->nelts) {
                if (opart->next == NULL) {
                    break;
                }
                opart = opart->next;
                oshm_zone = opart->elts;
                n = 0;
            }

            if (shm_zone[i].shm.name.len != oshm_zone[n].shm.name.len) {
                continue;
            }

            if (njt_strncmp(shm_zone[i].shm.name.data,
                            oshm_zone[n].shm.name.data,
                            shm_zone[i].shm.name.len)
                != 0)
            {
                continue;
            }

            if (shm_zone[i].tag == oshm_zone[n].tag
                && shm_zone[i].shm.size == oshm_zone[n].shm.size
                && !shm_zone[i].noreuse)
            {
                goto old_shm_zone_found;
            }

            break;
        }

        njt_shm_free(&shm_zone[i].shm);

    old_shm_zone_found:

        continue;
    }

    if (njt_test_config) {
        njt_destroy_cycle_pools(&conf);
        return NULL;
    }

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {
        if (ls[i].fd == (njt_socket_t) -1 || !ls[i].open) {
            continue;
        }

        if (njt_close_socket(ls[i].fd) == -1) {
            njt_log_error(NJT_LOG_EMERG, log, njt_socket_errno,
                          njt_close_socket_n " %V failed",
                          &ls[i].addr_text);
        }
    }

    njt_destroy_cycle_pools(&conf);

    return NULL;
}


static void
njt_destroy_cycle_pools(njt_conf_t *conf)
{
    njt_destroy_pool(conf->temp_pool);
    njt_destroy_pool(conf->pool);
}


static njt_int_t
njt_init_zone_pool(njt_cycle_t *cycle, njt_shm_zone_t *zn)
{
    u_char           *file;
    njt_slab_pool_t  *sp;

    sp = (njt_slab_pool_t *) zn->shm.addr;

    if (zn->shm.exists) {

        if (sp == sp->addr) {
            return NJT_OK;
        }

#if (NJT_WIN32)

        /* remap at the required address */

        if (njt_shm_remap(&zn->shm, sp->addr) != NJT_OK) {
            return NJT_ERROR;
        }

        sp = (njt_slab_pool_t *) zn->shm.addr;

        if (sp == sp->addr) {
            return NJT_OK;
        }

#endif

        njt_log_error(NJT_LOG_EMERG, cycle->log, 0,
                      "shared zone \"%V\" has no equal addresses: %p vs %p",
                      &zn->shm.name, sp->addr, sp);
        return NJT_ERROR;
    }

    sp->end = zn->shm.addr + zn->shm.size;
    sp->min_shift = 3;
    sp->addr = zn->shm.addr;

#if (NJT_HAVE_ATOMIC_OPS)

    file = NULL;

#else

    file = njt_pnalloc(cycle->pool,
                       cycle->lock_file.len + zn->shm.name.len + 1);
    if (file == NULL) {
        return NJT_ERROR;
    }

    (void) njt_sprintf(file, "%V%V%Z", &cycle->lock_file, &zn->shm.name);

#endif

    if (njt_shmtx_create(&sp->mutex, &sp->lock, file) != NJT_OK) {
        return NJT_ERROR;
    }

    njt_slab_init(sp);

    return NJT_OK;
}


njt_int_t
njt_create_pidfile(njt_str_t *name, njt_log_t *log)
{
    size_t      len;
    njt_int_t   rc;
    njt_uint_t  create;
    njt_file_t  file;
    u_char      pid[NJT_INT64_LEN + 2];

    if (njt_process > NJT_PROCESS_MASTER) {
        return NJT_OK;
    }

    njt_memzero(&file, sizeof(njt_file_t));

    file.name = *name;
    file.log = log;

    create = njt_test_config ? NJT_FILE_CREATE_OR_OPEN : NJT_FILE_TRUNCATE;

    file.fd = njt_open_file(file.name.data, NJT_FILE_RDWR,
                            create, NJT_FILE_DEFAULT_ACCESS);

    if (file.fd == NJT_INVALID_FILE) {
        njt_log_error(NJT_LOG_EMERG, log, njt_errno,
                      njt_open_file_n " \"%s\" failed", file.name.data);
        return NJT_ERROR;
    }

    rc = NJT_OK;

    if (!njt_test_config) {
        len = njt_snprintf(pid, NJT_INT64_LEN + 2, "%P%N", njt_pid) - pid;

        if (njt_write_file(&file, pid, len, 0) == NJT_ERROR) {
            rc = NJT_ERROR;
        }
    }

    if (njt_close_file(file.fd) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                      njt_close_file_n " \"%s\" failed", file.name.data);
    }

    return rc;
}


void
njt_delete_pidfile(njt_cycle_t *cycle)
{
    u_char           *name;
    njt_core_conf_t  *ccf;

    ccf = (njt_core_conf_t *) njt_get_conf(cycle->conf_ctx, njt_core_module);

    name = njt_new_binary ? ccf->oldpid.data : ccf->pid.data;

    if (njt_delete_file(name) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      njt_delete_file_n " \"%s\" failed", name);
    }
}


njt_int_t
njt_signal_process(njt_cycle_t *cycle, char *sig)
{
    ssize_t           n;
    njt_pid_t         pid;
    njt_file_t        file;
    njt_core_conf_t  *ccf;
    u_char            buf[NJT_INT64_LEN + 2];

    njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "signal process started");

    ccf = (njt_core_conf_t *) njt_get_conf(cycle->conf_ctx, njt_core_module);

    njt_memzero(&file, sizeof(njt_file_t));

    file.name = ccf->pid;
    file.log = cycle->log;

    file.fd = njt_open_file(file.name.data, NJT_FILE_RDONLY,
                            NJT_FILE_OPEN, NJT_FILE_DEFAULT_ACCESS);

    if (file.fd == NJT_INVALID_FILE) {
        njt_log_error(NJT_LOG_ERR, cycle->log, njt_errno,
                      njt_open_file_n " \"%s\" failed", file.name.data);
        return 1;
    }

    n = njt_read_file(&file, buf, NJT_INT64_LEN + 2, 0);

    if (njt_close_file(file.fd) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      njt_close_file_n " \"%s\" failed", file.name.data);
    }

    if (n == NJT_ERROR) {
        return 1;
    }

    while (n-- && (buf[n] == CR || buf[n] == LF)) { /* void */ }

    pid = njt_atoi(buf, ++n);

    if (pid == (njt_pid_t) NJT_ERROR) {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0,
                      "invalid PID number \"%*s\" in \"%s\"",
                      n, buf, file.name.data);
        return 1;
    }

    return njt_os_signal_process(cycle, sig, pid);

}


static njt_int_t
njt_test_lockfile(u_char *file, njt_log_t *log)
{
#if !(NJT_HAVE_ATOMIC_OPS)
    njt_fd_t  fd;

    fd = njt_open_file(file, NJT_FILE_RDWR, NJT_FILE_CREATE_OR_OPEN,
                       NJT_FILE_DEFAULT_ACCESS);

    if (fd == NJT_INVALID_FILE) {
        njt_log_error(NJT_LOG_EMERG, log, njt_errno,
                      njt_open_file_n " \"%s\" failed", file);
        return NJT_ERROR;
    }

    if (njt_close_file(fd) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                      njt_close_file_n " \"%s\" failed", file);
    }

    if (njt_delete_file(file) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                      njt_delete_file_n " \"%s\" failed", file);
    }

#endif

    return NJT_OK;
}


void
njt_reopen_files(njt_cycle_t *cycle, njt_uid_t user)
{
    njt_fd_t          fd;
    njt_uint_t        i;
    njt_list_part_t  *part;
    njt_open_file_t  *file;

    part = &cycle->open_files.part;
    file = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            file = part->elts;
            i = 0;
        }

        if (file[i].name.len == 0) {
            continue;
        }

        if (file[i].flush) {
            file[i].flush(&file[i], cycle->log);
        }

        fd = njt_open_file(file[i].name.data, NJT_FILE_APPEND,
                           NJT_FILE_CREATE_OR_OPEN, NJT_FILE_DEFAULT_ACCESS);

        njt_log_debug3(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                       "reopen file \"%s\", old:%d new:%d",
                       file[i].name.data, file[i].fd, fd);

        if (fd == NJT_INVALID_FILE) {
            njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                          njt_open_file_n " \"%s\" failed", file[i].name.data);
            continue;
        }

#if !(NJT_WIN32)
        if (user != (njt_uid_t) NJT_CONF_UNSET_UINT) {
            njt_file_info_t  fi;

            if (njt_file_info(file[i].name.data, &fi) == NJT_FILE_ERROR) {
                njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                              njt_file_info_n " \"%s\" failed",
                              file[i].name.data);

                if (njt_close_file(fd) == NJT_FILE_ERROR) {
                    njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                                  njt_close_file_n " \"%s\" failed",
                                  file[i].name.data);
                }

                continue;
            }

            if (fi.st_uid != user) {
                if (chown((const char *) file[i].name.data, user, -1) == -1) {
                    njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                                  "chown(\"%s\", %d) failed",
                                  file[i].name.data, user);

                    if (njt_close_file(fd) == NJT_FILE_ERROR) {
                        njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                                      njt_close_file_n " \"%s\" failed",
                                      file[i].name.data);
                    }

                    continue;
                }
            }

            if ((fi.st_mode & (S_IRUSR|S_IWUSR)) != (S_IRUSR|S_IWUSR)) {

                fi.st_mode |= (S_IRUSR|S_IWUSR);

                if (chmod((const char *) file[i].name.data, fi.st_mode) == -1) {
                    njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                                  "chmod() \"%s\" failed", file[i].name.data);

                    if (njt_close_file(fd) == NJT_FILE_ERROR) {
                        njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                                      njt_close_file_n " \"%s\" failed",
                                      file[i].name.data);
                    }

                    continue;
                }
            }
        }

        if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
            njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                          "fcntl(FD_CLOEXEC) \"%s\" failed",
                          file[i].name.data);

            if (njt_close_file(fd) == NJT_FILE_ERROR) {
                njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                              njt_close_file_n " \"%s\" failed",
                              file[i].name.data);
            }

            continue;
        }
#endif

        if (njt_close_file(file[i].fd) == NJT_FILE_ERROR) {
            njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                          njt_close_file_n " \"%s\" failed",
                          file[i].name.data);
        }

        file[i].fd = fd;
    }

    (void) njt_log_redirect_stderr(cycle);
}


njt_shm_zone_t *
njt_shared_memory_add(njt_conf_t *cf, njt_str_t *name, size_t size, void *tag)
{
    njt_uint_t        i;
    njt_shm_zone_t   *shm_zone;
    njt_list_part_t  *part;

    part = &cf->cycle->shared_memory.part;
    shm_zone = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            shm_zone = part->elts;
            i = 0;
        }

        if (name->len != shm_zone[i].shm.name.len) {
            continue;
        }

        if (njt_strncmp(name->data, shm_zone[i].shm.name.data, name->len)
            != 0)
        {
            continue;
        }

        if (tag != shm_zone[i].tag) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                            "the shared memory zone \"%V\" is "
                            "already declared for a different use",
                            &shm_zone[i].shm.name);
            return NULL;
        }

        if (shm_zone[i].shm.size == 0) {
            shm_zone[i].shm.size = size;
        }

        if (size && size != shm_zone[i].shm.size) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                            "the size %uz of shared memory zone \"%V\" "
                            "conflicts with already declared size %uz",
                            size, &shm_zone[i].shm.name, shm_zone[i].shm.size);
            return NULL;
        }

        return &shm_zone[i];
    }
    if(cf->dynamic == 1) {  //by zyg
	 njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                            "unsupported create dynamic shared memory zone \"%V\"" ,name);
	 return NULL;
    }
    shm_zone = njt_list_push(&cf->cycle->shared_memory);

    if (shm_zone == NULL) {
        return NULL;
    }

    shm_zone->data = NULL;
    shm_zone->shm.log = cf->cycle->log;
    shm_zone->shm.addr = NULL;
    shm_zone->shm.size = size;
    shm_zone->shm.name = *name;
    shm_zone->shm.exists = 0;
    shm_zone->init = NULL;
    shm_zone->merge = NULL;
    shm_zone->tag = tag;
    shm_zone->noreuse = 0;

    return shm_zone;
}


static void
njt_clean_old_cycles(njt_event_t *ev)
{
    njt_uint_t     i, n, found, live;
    njt_log_t     *log;
    njt_cycle_t  **cycle;

    log = njt_cycle->log;
    njt_temp_pool->log = log;

    njt_log_debug0(NJT_LOG_DEBUG_CORE, log, 0, "clean old cycles");

    live = 0;

    cycle = njt_old_cycles.elts;
    for (i = 0; i < njt_old_cycles.nelts; i++) {

        if (cycle[i] == NULL) {
            continue;
        }

        found = 0;

        for (n = 0; n < cycle[i]->connection_n; n++) {
            if (cycle[i]->connections[n].fd != (njt_socket_t) -1) {
                found = 1;

                njt_log_debug1(NJT_LOG_DEBUG_CORE, log, 0, "live fd:%ui", n);

                break;
            }
        }

        if (found) {
            live = 1;
            continue;
        }

        njt_log_debug1(NJT_LOG_DEBUG_CORE, log, 0, "clean old cycle: %ui", i);

        njt_destroy_pool(cycle[i]->pool);
        cycle[i] = NULL;
    }

    njt_log_debug1(NJT_LOG_DEBUG_CORE, log, 0, "old cycles status: %ui", live);

    if (live) {
        njt_add_timer(ev, 30000);

    } else {
        njt_destroy_pool(njt_temp_pool);
        njt_temp_pool = NULL;
        njt_old_cycles.nelts = 0;
    }
}


void
njt_set_shutdown_timer(njt_cycle_t *cycle)
{
    njt_core_conf_t  *ccf;

    ccf = (njt_core_conf_t *) njt_get_conf(cycle->conf_ctx, njt_core_module);

    if (ccf->shutdown_timeout) {
        njt_shutdown_event.handler = njt_shutdown_timer_handler;
        njt_shutdown_event.data = cycle;
        njt_shutdown_event.log = cycle->log;
        njt_shutdown_event.cancelable = 1;

        njt_add_timer(&njt_shutdown_event, ccf->shutdown_timeout);
    }
}


static void
njt_shutdown_timer_handler(njt_event_t *ev)
{
    njt_uint_t         i;
    njt_cycle_t       *cycle;
    njt_connection_t  *c;

    cycle = ev->data;

    c = cycle->connections;

    for (i = 0; i < cycle->connection_n; i++) {

        if (c[i].fd == (njt_socket_t) -1
            || c[i].read == NULL
            || c[i].read->accept
            || c[i].read->channel
            || c[i].read->resolver)
        {
            continue;
        }

        njt_log_debug1(NJT_LOG_DEBUG_CORE, ev->log, 0,
                       "*%uA shutdown timeout", c[i].number);

        c[i].close = 1;
        c[i].error = 1;

        c[i].read->handler(c[i].read);
    }
}
