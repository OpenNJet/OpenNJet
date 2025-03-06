/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>
#include <njet.h>
#include <njt_conf_ext_module.h>
#include <njt_stream_upstream_dynamic_servers.h>

#define njt_resolver_node(n) \
    (njt_resolver_node_t *)((u_char *)(n) - offsetof(njt_resolver_node_t, node))

static njt_str_t njt_stream_upstream_dynamic_server_null_route =
    njt_string("127.255.255.255");

static void *njt_stream_upstream_dynamic_server_main_conf(njt_conf_t *cf);

static char *njt_stream_upstream_dynamic_server_directive(njt_conf_t *cf,
                                                          njt_command_t *cmd, void *conf);

static char *njt_stream_upstream_resolver_directive(njt_conf_t *cf,
                                                    njt_command_t *cmd, void *conf);
static char *njt_stream_upstream_resolver_timeout_directive(njt_conf_t *cf,
                                                            njt_command_t *cmd, void *conf);

static char *njt_stream_upstream_dynamic_servers_merge_conf(njt_conf_t *cf,
                                                            void *parent, void *child);
static njt_int_t njt_stream_upstream_dynamic_servers_init_process(
    njt_cycle_t *cycle);

static njt_int_t njt_stream_upstream_dynamic_server_init_zone(njt_shm_zone_t *shm_zone, void *data);

static njt_int_t
njt_stream_upstream_dynamic_servers_init(njt_conf_t *cf);
static char *
njt_stream_upstream_state(njt_conf_t *cf, njt_command_t *cmd, void *conf);

static char *njt_stream_upstream_check(njt_conf_t *cf, njt_command_t *cmd,
                                       void *conf);

static njt_command_t njt_stream_upstream_dynamic_servers_commands[] = {
    {njt_string("server"),
     NJT_STREAM_UPS_CONF | NJT_CONF_1MORE,
     njt_stream_upstream_dynamic_server_directive,
     0,
     0,
     NULL},

    {njt_string("resolver"),
     NJT_STREAM_UPS_CONF | NJT_CONF_1MORE,
     njt_stream_upstream_resolver_directive,
     0,
     0,
     NULL},

    {njt_string("resolver_timeout"),
     NJT_STREAM_UPS_CONF | NJT_CONF_TAKE1,
     njt_stream_upstream_resolver_timeout_directive,
     0,
     0,
     NULL},
    {njt_string("state"),
     NJT_STREAM_UPS_CONF | NJT_CONF_TAKE1,
     njt_stream_upstream_state,
     0,
     0,
     NULL},
    {njt_string("health_check"),
     NJT_STREAM_UPS_CONF | NJT_CONF_1MORE,
     njt_stream_upstream_check,
     0,
     0,
     NULL},
    njt_null_command};

static njt_stream_module_t njt_stream_upstream_dynamic_servers_module_ctx = {
    NULL,                                     /* preconfiguration */
    njt_stream_upstream_dynamic_servers_init, /* postconfiguration */

    njt_stream_upstream_dynamic_server_main_conf, /* create main configuration */
    NULL,                                         /* init main configuration */

    NULL,                                          /* create server configuration */
    njt_stream_upstream_dynamic_servers_merge_conf /* merge server configuration */

};

njt_module_t njt_stream_upstream_dynamic_servers_module = {
    NJT_MODULE_V1,
    &njt_stream_upstream_dynamic_servers_module_ctx,  /* module context */
    njt_stream_upstream_dynamic_servers_commands,     /* module directives */
    NJT_STREAM_MODULE,                                /* module type */
    NULL,                                             /* init master */
    NULL,                                             /* init module */
    njt_stream_upstream_dynamic_servers_init_process, /* init process */
    NULL,                                             /* init thread */
    NULL,                                             /* exit thread */
    NULL,                                             /* exit process */
    NULL,                                             /* exit master */
    NJT_MODULE_V1_PADDING};

static njt_int_t
njt_stream_upstream_dynamic_servers_init(njt_conf_t *cf)
{

    njt_uint_t i, j;
    njt_stream_upstream_dynamic_server_conf_t *dynamic_server;
    njt_stream_upstream_main_conf_t *umcf;
    njt_list_part_t *part;
    njt_stream_upstream_srv_conf_t *uscf, **uscfp;
    njt_flag_t have_dyserver;
    njt_stream_upstream_dynamic_server_main_conf_t *udsmcf;
    njt_conf_ext_t *mcf;
    mcf = (njt_conf_ext_t *) njt_get_conf(cf->cycle->conf_ctx, njt_conf_ext_module);

    ssize_t size;
    njt_str_t zone = njt_string("api_stream_server");
    size = (ssize_t)(10 * njt_pagesize);

    udsmcf = njt_stream_conf_get_module_main_conf(cf,
                                                  njt_stream_upstream_dynamic_servers_module);
    have_dyserver = 0;
    umcf = njt_stream_conf_get_module_main_conf(cf, njt_stream_upstream_module);
    uscfp = umcf->upstreams.elts;
    for (i = 0; i < umcf->upstreams.nelts; i++)
    {
        uscf = uscfp[i];
        part = &udsmcf->dynamic_servers->part;
        dynamic_server = part->elts;
      
        if (uscf->resolver == NULL)
        {
            uscf->resolver = udsmcf->resolver;
            uscf->resolver_timeout = udsmcf->resolver_timeout;
            uscf->valid = udsmcf->valid;
        }
        if (uscf->resolver != NULL)
        {
            have_dyserver = 1;
        }
        for (j = 0;; j++)
        {
            if (j >= part->nelts)
            {
                if (part->next == NULL)
                    break;
                part = part->next;
                dynamic_server = part->elts;
                j = 0;
            }
            if (dynamic_server && dynamic_server->upstream_conf == uscf)
            {
                if (uscf->shm_zone == NULL)
                {
                    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                       "in upstream \"%V\" resolve must coexist with a shared memory zone",
                                       &uscf->host);
                    return NJT_ERROR;
                }
                if (uscf->resolver == NULL)
                {
                    uscf->resolver = udsmcf->resolver;
                    uscf->resolver_timeout = udsmcf->resolver_timeout;
                    uscf->valid = udsmcf->valid;
                }
                if (uscf->resolver == NULL)
                {
                    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                       "no resolver defined to resolve names at run time in upstream \"%V\"", &uscf->host);
                    return NJT_ERROR;
                }
                have_dyserver = 1;
            }
        }
    }

    if (have_dyserver == 1 && udsmcf->shm_zone == NULL && mcf && mcf->enabled == 1)
    {
        uscf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_upstream_module);
        udsmcf->shm_zone = njt_shared_memory_add(cf, &zone, size, &njt_stream_upstream_module);
        if (udsmcf->shm_zone == NULL)
        {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "in upstream \"%V\" resolve must coexist with a  api shared memory zone",
                               &uscf->host);
            return NJT_ERROR;
        }
        udsmcf->shm_zone->data = udsmcf;
        udsmcf->shm_zone->init = njt_stream_upstream_dynamic_server_init_zone;
        udsmcf->shm_zone->noreuse = 1;
        udsmcf->upstream_conf = uscf;
    }

    return NJT_OK;
}

static njt_err_t
njt_create_sate_file(u_char *dir, njt_uid_t user, njt_uid_t group, njt_uint_t access, njt_cycle_t *cycle)
{
    u_char *p, ch;
    njt_err_t err;
    njt_fd_t fd;
    err = 0;

#if (NJT_WIN32)
    p = dir + 3;
#else
    p = dir + 1;
#endif

    for (/* void */; *p; p++)
    {
        ch = *p;

        if (ch != '/')
        {
            continue;
        }

        *p = '\0';

        if (njt_create_dir(dir, access) == NJT_FILE_ERROR)
        {
            err = njt_errno;

            switch (err)
            {
            case NJT_EEXIST:
                err = NJT_EEXIST;
                break;
            case NJT_EACCES:
                break;

            default:
                return err;
            }
        }
        if (err == 0)
        {
            if (chown((const char *)dir, user, getgid()) == -1)
            {
                njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                              "chmod() \"%s\" failed", dir);
            }
        }
        err = 0;
        *p = '/';
    }
    fd = njt_open_file(dir, NJT_FILE_CREATE_OR_OPEN | NJT_FILE_RDWR, NJT_FILE_OPEN, 0666);
    if (fd == NJT_INVALID_FILE)
    {
        njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                      "njt_open_file() \"%s\" failed", dir);
        err = njt_errno;
        return err;
    }
    if (fchown(fd, user, group) == -1)
    {
        njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                      "fchown() \"%s\" failed", dir);
    }
    if (njt_close_file(fd) == NJT_FILE_ERROR)
    {
        njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                      "njt_close_file() \"%s\" failed", dir);
    }

    return err;
}

static char *
njt_stream_upstream_state(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t *value, file;
    njt_stream_upstream_srv_conf_t *uscf;
    // njt_fd_t          fd;
    njt_core_conf_t *ccf;
    value = cf->args->elts;
    file = value[1];

    ccf = (njt_core_conf_t *)njt_get_conf(cf->cycle->conf_ctx,
                                          njt_core_module);
    njt_log_debug1(NJT_LOG_DEBUG_CORE, cf->log, 0, "state %V", &file);

    if (njt_conf_full_name(cf->cycle, &file, 1) != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    if (strpbrk((char *)file.data, "*?[") != NULL)
    {
        njt_log_debug1(NJT_LOG_DEBUG_CORE, cf->log, 0,
                       "the name of file %s contains *?[ chars", file.data);
        return "file name contains *?[ chars";
    }

    uscf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_upstream_module);

    if (uscf->state_file.data != NULL || uscf->state_file.len != 0)
    {
        return "\"state\" directive is duplicate";
    }
    uscf->state_file = file;

    if (uscf->servers->nelts > 0)
    {
        return "\"state\" directive is incompatible with \"server\"";
    }

    njt_log_debug1(NJT_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);
    if (ccf)
    {
        njt_create_sate_file(file.data, ccf->user, ccf->group, 0755, cf->cycle);
    }
    // njt_create_full_path(file.data,0700);
    // pwd = getpwnam((const char *) value[1].data);

    return njt_conf_parse(cf, &file);
}

static char *njt_stream_upstream_resolver_timeout_directive(njt_conf_t *cf,
                                                            njt_command_t *cmd, void *conf)
{

    njt_stream_upstream_srv_conf_t *udsmcf;
    njt_str_t *value;

    udsmcf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_upstream_module);
    value = cf->args->elts;
    udsmcf->resolver_timeout = njt_parse_time(&value[1], 0);
    if (udsmcf->resolver_timeout == (njt_msec_t)NJT_ERROR)
    {
        return "invalid value";
    }

    return NJT_CONF_OK;
}

static char *njt_stream_upstream_resolver_directive(njt_conf_t *cf,
                                                    njt_command_t *cmd, void *conf)
{
    njt_stream_upstream_srv_conf_t *udsmcf;
    njt_str_t *value;
    njt_str_t s;
    njt_uint_t i;
    udsmcf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_upstream_module);

    value = cf->args->elts;
    udsmcf->resolver_timeout = 10;
    udsmcf->resolver = njt_resolver_create(cf, &value[1], cf->args->nelts - 1);
    if (udsmcf->resolver == NULL)
    {
        return NJT_CONF_ERROR;
    }
    for (i = 2; i < cf->args->nelts; i++)
    {
        if (njt_strncmp(value[i].data, "valid=", 6) == 0)
        {
            s.len = value[i].len - 6;
            s.data = value[i].data + 6;

            udsmcf->valid = njt_parse_time(&s, 1);

            if (udsmcf->valid == (time_t)NJT_ERROR)
            {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid parameter: %V", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }
    }

    return NJT_CONF_OK;
}

/*Overwrite the njet "server" directive based on its
 implementation of "njt_stream_upstream_server" from
 src/stream/njt_stream_upstream.c (njet version 1.7.7), and should be kept in
 sync with njet's source code. Customizations noted in comments.
 This make possible use the same syntax of njet comercial version.*/

static char *njt_stream_upstream_dynamic_server_directive(njt_conf_t *cf,
                                                          njt_command_t *cmd, void *conf)
{
    /* BEGIN CUSTOMIZATION: differs from default "server" implementation*/
    njt_stream_upstream_srv_conf_t *uscf;
    njt_stream_upstream_dynamic_server_main_conf_t *udsmcf;
    njt_stream_upstream_dynamic_server_conf_t *dynamic_server = NULL;
    /* END CUSTOMIZATION*/

    time_t fail_timeout;
    njt_str_t *value, s;
    njt_url_t u;
    njt_int_t weight, max_conns, max_fails, slow_start;
    njt_uint_t i;
    njt_stream_upstream_server_t *us;
    njt_uint_t no_resolve = 0;

    /* BEGIN CUSTOMIZATION: differs from default "server" implementation */
    uscf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_upstream_module);
    udsmcf = njt_stream_conf_get_module_main_conf(cf,
                                                  njt_stream_upstream_dynamic_servers_module);
    /* END CUSTOMIZATION*/

    if (uscf->state_file.data != NULL && (uscf->state_file.len != cf->conf_file->file.name.len || njt_strncmp(uscf->state_file.data, cf->conf_file->file.name.data, uscf->state_file.len) != 0))
    {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "\"server\" directive is incompatible with \"state\"");
        return NJT_CONF_ERROR;
    }

    us = njt_array_push(uscf->servers);
    if (us == NULL)
    {
        return NJT_CONF_ERROR;
    }

    njt_memzero(us, sizeof(njt_stream_upstream_server_t));

    value = cf->args->elts;

    weight = 1;
    max_conns = 0;
    max_fails = 1;
    fail_timeout = 10;
    slow_start = 0;
    njt_memzero(&u, sizeof(njt_url_t));
    u.url = value[1];

    for (i = 2; i < cf->args->nelts; i++)
    {

        if (njt_strncmp(value[i].data, "weight=", 7) == 0)
        {

            if (!(uscf->flags & NJT_STREAM_UPSTREAM_WEIGHT))
            {
                goto not_supported;
            }

            weight = njt_atoi(&value[i].data[7], value[i].len - 7);

            if (weight == NJT_ERROR || weight == 0)
            {
                goto invalid;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "max_conns=", 10) == 0)
        {

            if (!(uscf->flags & NJT_STREAM_UPSTREAM_MAX_CONNS))
            {
                goto not_supported;
            }

            max_conns = njt_atoi(&value[i].data[10], value[i].len - 10);

            if (max_conns == NJT_ERROR)
            {
                goto invalid;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "max_fails=", 10) == 0)
        {

            if (!(uscf->flags & NJT_STREAM_UPSTREAM_MAX_FAILS))
            {
                goto not_supported;
            }

            max_fails = njt_atoi(&value[i].data[10], value[i].len - 10);

            if (max_fails == NJT_ERROR)
            {
                goto invalid;
            }

            continue;
        }
        if (njt_strncmp(value[i].data, "slow_start=", 11) == 0)
        {

            s.len = value[i].len - 11;
            s.data = &value[i].data[11];
            slow_start = njt_parse_time(&s, 1);
            // slow_start = njt_atoi(&value[i].data[11], value[i].len - 11);
            /*
            if (slow_start == NJT_ERROR) {
                slow_start = njt_atoi(&value[i].data[11], value[i].len - 12);
                if (slow_start == NJT_ERROR) {
                   goto invalid;
                }
                switch (value[i].data[value[i].len - 1]) {
                case 's':
                    break;
                case 'm':
                    slow_start *= 60;
                    break;
                case 'h':
                    slow_start *= 60 * 60;
                    break;
                case 'd':
                    slow_start *= 60 * 60 * 24 * 1;
                    break;
                case 'M':
                    slow_start *= 60 * 60 * 24 * 30;
                    break;
                case 'y':
                    slow_start *= 60 * 60 * 24 * 365;
                    break;
                default:
                     goto invalid;
                }
            }*/
            if (!(uscf->flags & NJT_STREAM_UPSTREAM_SLOW_START))
            {
                goto not_supported;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "fail_timeout=", 13) == 0)
        {

            if (!(uscf->flags & NJT_STREAM_UPSTREAM_FAIL_TIMEOUT))
            {
                goto not_supported;
            }

            s.len = value[i].len - 13;
            s.data = &value[i].data[13];

            fail_timeout = njt_parse_time(&s, 1);

            if (fail_timeout == (time_t)NJT_ERROR)
            {
                goto invalid;
            }

            continue;
        }

        if (njt_strcmp(value[i].data, "backup") == 0)
        {

            if (!(uscf->flags & NJT_STREAM_UPSTREAM_BACKUP))
            {
                goto not_supported;
            }

            us->backup = 1;

            continue;
        }

        if (njt_strcmp(value[i].data, "down") == 0)
        {

            if (!(uscf->flags & NJT_STREAM_UPSTREAM_DOWN))
            {
                goto not_supported;
            }

            us->down = 1;

            continue;
        }

        /* BEGIN CUSTOMIZATION: differs from default "server" implementationa*/
        if (njt_strcmp(value[i].data, "resolve") == 0)
        {
            /* Determine if the server given is an IP address or a hostname by running
               through njt_parse_url with no_resolve enabled. Only if a hostname is given
               will we add this to the list of dynamic servers that we will resolve again.*/

            // u.no_resolve = 1;
            no_resolve = 1;
            u.no_resolve = 1;
            njt_parse_url(cf->pool, &u);
            if (u.no_port)
            {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "no port in upstream \"%V\"", &u.url);
                return NJT_CONF_ERROR;
            }
            if (u.naddrs == 1 && us->name.len <= u.addrs[0].name.len && njt_strncmp(us->name.data, u.addrs[0].name.data, us->name.len) == 0)
            {
                continue;
            }
            // if (!u.addrs || !u.addrs[0].sockaddr) {
            dynamic_server = njt_list_push(&udsmcf->dy_servers);
            if (dynamic_server == NULL)
            {
                return NJT_CONF_ERROR;
            }

            njt_memzero(dynamic_server, sizeof(njt_stream_upstream_dynamic_server_conf_t));
            us->dynamic = 1;
            dynamic_server->server = us;
            dynamic_server->upstream_conf = uscf;

            dynamic_server->host = u.host;
            dynamic_server->port = (in_port_t)(u.no_port ? u.default_port : u.port);
            //}

            continue;
        }

        /* END CUSTOMIZATION */

        goto invalid;
    }
    /* BEGIN CUSTOMIZATION: differs from default "server" implementation*/
    if (no_resolve == 0 && njt_parse_url(cf->pool, &u) != NJT_OK)
    {
        if (u.err && !no_resolve)
        {
            njt_conf_log_error(NJT_LOG_ERR, cf, 0,
                               "%s in upstream \"%V\"", u.err, &u.url);
            return NJT_CONF_ERROR;
        }
        if (u.no_port)
        {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "no port in upstream \"%V\"", &u.url);
            return NJT_CONF_ERROR;
        }
        /* If the domain fails to resolve on start up, mark this server as down,
         and assign a static IP that should never route. This is to account for
         various things inside njet that seem to expect a server to always have
         at least 1 IP.*/
        // us->down = 1;

        u.url = njt_stream_upstream_dynamic_server_null_route;
        u.default_port = u.port;
        u.no_resolve = 1;

        if (njt_parse_url(cf->pool, &u) != NJT_OK)
        {
            if (u.err && !no_resolve)
            {
                njt_conf_log_error(NJT_LOG_ERR, cf, 0,
                                   "%s in upstream \"%V\"", u.err, &u.url);
            }
            return NJT_CONF_ERROR;
        }
        // us->fake = 1;
    }
    if (u.no_port)
    {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "no port in upstream \"%V\"", &u.url);
        return NJT_CONF_ERROR;
    }
    /* END CUSTOMIZATION */

    us->max_conns = max_conns;
    us->name = u.url;
    us->addrs = u.addrs;
    us->naddrs = u.naddrs;
    us->weight = weight;
    us->max_fails = max_fails;
    us->fail_timeout = fail_timeout;
    us->slow_start = slow_start;
    if (u.naddrs == 1 && us->name.len <= u.addrs[0].name.len && njt_strncmp(us->name.data, u.addrs[0].name.data, us->name.len) == 0)
    {
        //ip
    }
    else
    {
        if (uscf->state_file.data != NULL && us->dynamic != 1)
        {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "\"server\" must have \"resolve\" parameter");
            return NJT_CONF_ERROR;
        }
    }

    return NJT_CONF_OK;

invalid:

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);

    return NJT_CONF_ERROR;

not_supported:

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "balancing method does not support parameter \"%V\"",
                       &value[i]);

    return NJT_CONF_ERROR;
}
static njt_int_t njt_stream_upstream_dynamic_server_init_zone(njt_shm_zone_t *shm_zone,
                                                              void *data)
{
    // njt_stream_upstream_api_loc_conf_t *olduclcf = data;
    njt_slab_pool_t *shpool;
    njt_stream_upstream_rr_peers_t *peers;
    njt_stream_upstream_dynamic_server_main_conf_t *uclcf;

    if (data)
    {
        shm_zone->data = data;
        return NJT_OK;
    }
    shpool = (njt_slab_pool_t *)shm_zone->shm.addr;
    uclcf = shm_zone->data;

    if (shm_zone->shm.exists)
    {

        peers = shpool->data;
        uclcf->peers = peers;
        return NJT_OK;
    }

    /* setup our shm zone */
    peers = njt_slab_alloc(shpool, sizeof(njt_stream_upstream_rr_peers_t));
    if (peers)
    {
        peers->number = 0;
        peers->peer = NULL;
        peers->shpool = shpool;
        shpool->data = peers;
        uclcf->peers = peers;
    }
    else
    {
        return NJT_ERROR;
    }
    // peers->shpool = shpool;

    return NJT_OK;
}
static void *njt_stream_upstream_dynamic_server_main_conf(njt_conf_t *cf)
{
    njt_stream_upstream_dynamic_server_main_conf_t *udsmcf;
    // njt_stream_upstream_srv_conf_t                  *uscf;
    udsmcf = njt_pcalloc(cf->pool,
                         sizeof(njt_stream_upstream_dynamic_server_main_conf_t));
    if (udsmcf == NULL)
    {
        return NULL;
    }

    if (njt_list_init(&udsmcf->cache_servers, cf->pool, 1,
                      sizeof(njt_stream_upstream_dynamic_server_conf_t)) != NJT_OK)
    {
        return NULL;
    }
    if (njt_list_init(&udsmcf->dy_servers, cf->pool, 1,
                      sizeof(njt_stream_upstream_dynamic_server_conf_t)) != NJT_OK)
    {
        return NULL;
    }
    udsmcf->dynamic_servers = &udsmcf->dy_servers;
    udsmcf->resolver_timeout = NJT_CONF_UNSET_MSEC;
    // SIGSEGV, Segmentation fault.
    // uscf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_upstream_module);
    // udsmcf->upstream_conf = uscf;
    return udsmcf;
}

static char *njt_stream_upstream_dynamic_servers_merge_conf(njt_conf_t *cf,
                                                            void *parent, void *child)
{
    /* If any dynamic servers are present, verify that a "resolver" is setup as
     the stream level.*/
    njt_stream_upstream_dynamic_server_main_conf_t *udsmcf;
    njt_stream_core_srv_conf_t *core_loc_conf;

    udsmcf = njt_stream_conf_get_module_main_conf(cf,
                                                  njt_stream_upstream_dynamic_servers_module);

    core_loc_conf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_core_module);
    udsmcf->valid = 0;
    if (udsmcf->resolver == NULL)
    {

        if (core_loc_conf->resolver != NULL && core_loc_conf->resolver->connections.nelts != 0)
        {
            udsmcf->resolver = core_loc_conf->resolver;
            if (core_loc_conf->resolver)
            {
                udsmcf->valid = core_loc_conf->resolver->valid;
            }
        }
    }

    udsmcf->conf_ctx = cf->ctx;

    njt_conf_merge_msec_value(udsmcf->resolver_timeout,
                              core_loc_conf->resolver_timeout, 30000);

    return NJT_CONF_OK;
}
static njt_int_t njt_stream_upstream_dynamic_servers_init_process(
    njt_cycle_t *cycle)
{
    return NJT_OK;
}
static char *njt_stream_upstream_check(njt_conf_t *cf, njt_command_t *cmd,
                                       void *conf)
{
    njt_uint_t i;
    njt_stream_upstream_srv_conf_t *uscf;
    njt_str_t *value;

    uscf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_upstream_module);
    if (uscf == NULL)
    {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "no find njt_http_upstream_module!");
        return NJT_CONF_ERROR;
    }
    uscf->hc_type = 0;
    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++)
    {
        if (njt_strncmp(value[i].data, "mandatory", 9) == 0)
        {
            uscf->mandatory = 1;
            continue;
        }
        if (njt_strncmp(value[i].data, "persistent", 10) == 0)
        {
            uscf->persistent = 1;
            continue;
        }
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "\"%V\" directive is not allowed here", &value[i]);
        return NJT_CONF_ERROR;
    }
    if (uscf->persistent == 1 && uscf->mandatory != 1)
    {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "persistent need mandatory seted !");
    }
    if (uscf->persistent == 1 && uscf->mandatory == 1)
    {
        uscf->hc_type = 2;
    }
    else if (uscf->mandatory == 1)
    {
        uscf->hc_type = 1;
    }
    return NJT_CONF_OK;
}
