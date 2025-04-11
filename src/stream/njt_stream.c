
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_stream.h>


static char *njt_stream_block(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static njt_int_t njt_stream_init_phases(njt_conf_t *cf,
    njt_stream_core_main_conf_t *cmcf);
static njt_int_t njt_stream_init_phase_handlers(njt_conf_t *cf,
    njt_stream_core_main_conf_t *cmcf);

static njt_int_t njt_stream_add_addresses(njt_conf_t *cf,
    njt_stream_core_srv_conf_t *cscf, njt_stream_conf_port_t *port,
    njt_stream_listen_opt_t *lsopt);
static njt_int_t njt_stream_add_address(njt_conf_t *cf,
    njt_stream_core_srv_conf_t *cscf, njt_stream_conf_port_t *port,
    njt_stream_listen_opt_t *lsopt);
static njt_int_t njt_stream_add_server(njt_conf_t *cf,
    njt_stream_core_srv_conf_t *cscf, njt_stream_conf_addr_t *addr);

static njt_int_t njt_stream_optimize_servers(njt_conf_t *cf,
    njt_stream_core_main_conf_t *cmcf, njt_array_t *ports);
static njt_int_t njt_stream_server_names(njt_conf_t *cf,
    njt_stream_core_main_conf_t *cmcf, njt_stream_conf_addr_t *addr);
static njt_int_t njt_stream_cmp_conf_addrs(const void *one, const void *two);
static int njt_libc_cdecl njt_stream_cmp_dns_wildcards(const void *one,
    const void *two);

static njt_int_t njt_stream_init_listening(njt_conf_t *cf,
    njt_stream_conf_port_t *port);
static njt_listening_t *njt_stream_add_listening(njt_conf_t *cf,
    njt_stream_conf_addr_t *addr);
static njt_int_t njt_stream_add_addrs(njt_conf_t *cf, njt_stream_port_t *stport,
    njt_stream_conf_addr_t *addr);
#if (NJT_HAVE_INET6)
static njt_int_t njt_stream_add_addrs6(njt_conf_t *cf,
    njt_stream_port_t *stport, njt_stream_conf_addr_t *addr);
#endif


njt_uint_t  njt_stream_max_module;


njt_stream_filter_pt  njt_stream_top_filter;


static njt_command_t  njt_stream_commands[] = {

    { njt_string("stream"),
      NJT_MAIN_CONF|NJT_CONF_BLOCK|NJT_CONF_NOARGS,
      njt_stream_block,
      0,
      0,
      NULL },

      njt_null_command
};


static njt_core_module_t  njt_stream_module_ctx = {
    njt_string("stream"),
    NULL,
    NULL
};


njt_module_t  njt_stream_module = {
    NJT_MODULE_V1,
    &njt_stream_module_ctx,                /* module context */
    njt_stream_commands,                   /* module directives */
    NJT_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


static char *
njt_stream_block(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char                          *rv;
    njt_uint_t                     mi, m, s;
    njt_conf_t                     pcf;
    njt_stream_module_t           *module;
    njt_stream_conf_ctx_t         *ctx;
    njt_stream_core_srv_conf_t   **cscfp;
    njt_stream_core_main_conf_t   *cmcf;

    if (*(njt_stream_conf_ctx_t **) conf) {
        return "is duplicate";
    }

    /* the main stream context */

    ctx = njt_pcalloc(cf->pool, sizeof(njt_stream_conf_ctx_t));
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }

    *(njt_stream_conf_ctx_t **) conf = ctx;

    /* count the number of the stream modules and set up their indices */

    njt_stream_max_module = njt_count_modules(cf->cycle, NJT_STREAM_MODULE);


    /* the stream main_conf context, it's the same in the all stream contexts */

    ctx->main_conf = njt_pcalloc(cf->pool,
                                 sizeof(void *) * njt_stream_max_module);
    if (ctx->main_conf == NULL) {
        return NJT_CONF_ERROR;
    }


    /*
     * the stream null srv_conf context, it is used to merge
     * the server{}s' srv_conf's
     */

    ctx->srv_conf = njt_pcalloc(cf->pool,
                                sizeof(void *) * njt_stream_max_module);
    if (ctx->srv_conf == NULL) {
        return NJT_CONF_ERROR;
    }


    /*
     * create the main_conf's and the null srv_conf's of the all stream modules
     */

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NJT_STREAM_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        mi = cf->cycle->modules[m]->ctx_index;

        if (module->create_main_conf) {
            ctx->main_conf[mi] = module->create_main_conf(cf);
            if (ctx->main_conf[mi] == NULL) {
                return NJT_CONF_ERROR;
            }
        }

        if (module->create_srv_conf) {
            ctx->srv_conf[mi] = module->create_srv_conf(cf);
            if (ctx->srv_conf[mi] == NULL) {
                return NJT_CONF_ERROR;
            }
        }
    }


    pcf = *cf;
    cf->ctx = ctx;

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NJT_STREAM_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->preconfiguration) {
            if (module->preconfiguration(cf) != NJT_OK) {
                return NJT_CONF_ERROR;
            }
        }
    }


    /* parse inside the stream{} block */

    cf->module_type = NJT_STREAM_MODULE;
    cf->cmd_type = NJT_STREAM_MAIN_CONF;
    rv = njt_conf_parse(cf, NULL);

    if (rv != NJT_CONF_OK) {
        *cf = pcf;
        return rv;
    }


    /* init stream{} main_conf's, merge the server{}s' srv_conf's */

    cmcf = ctx->main_conf[njt_stream_core_module.ctx_index];
    cscfp = cmcf->servers.elts;

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NJT_STREAM_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        mi = cf->cycle->modules[m]->ctx_index;

        /* init stream{} main_conf's */

        cf->ctx = ctx;

        if (module->init_main_conf) {
            rv = module->init_main_conf(cf, ctx->main_conf[mi]);
            if (rv != NJT_CONF_OK) {
                *cf = pcf;
                return rv;
            }
        }

        for (s = 0; s < cmcf->servers.nelts; s++) {

            /* merge the server{}s' srv_conf's */

            cf->ctx = cscfp[s]->ctx;

            if (module->merge_srv_conf) {
                rv = module->merge_srv_conf(cf,
                                            ctx->srv_conf[mi],
                                            cscfp[s]->ctx->srv_conf[mi]);
                if (rv != NJT_CONF_OK) {
                    *cf = pcf;
                    return rv;
                }
            }
        }
    }

    if (njt_stream_init_phases(cf, cmcf) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NJT_STREAM_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->postconfiguration) {
            if (module->postconfiguration(cf) != NJT_OK) {
                return NJT_CONF_ERROR;
            }
        }
    }

    if (njt_stream_variables_init_vars(cf) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    *cf = pcf;

    if (njt_stream_init_phase_handlers(cf, cmcf) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    /* optimize the lists of ports, addresses and server names */

    if (njt_stream_optimize_servers(cf, cmcf, cmcf->ports) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static njt_int_t
njt_stream_init_phases(njt_conf_t *cf, njt_stream_core_main_conf_t *cmcf)
{
    if (njt_array_init(&cmcf->phases[NJT_STREAM_POST_ACCEPT_PHASE].handlers,
                       cf->pool, 1, sizeof(njt_stream_handler_pt))
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    if (njt_array_init(&cmcf->phases[NJT_STREAM_PREACCESS_PHASE].handlers,
                       cf->pool, 1, sizeof(njt_stream_handler_pt))
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    if (njt_array_init(&cmcf->phases[NJT_STREAM_ACCESS_PHASE].handlers,
                       cf->pool, 1, sizeof(njt_stream_handler_pt))
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    if (njt_array_init(&cmcf->phases[NJT_STREAM_SSL_PHASE].handlers,
                       cf->pool, 1, sizeof(njt_stream_handler_pt))
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    if (njt_array_init(&cmcf->phases[NJT_STREAM_PREREAD_PHASE].handlers,
                       cf->pool, 1, sizeof(njt_stream_handler_pt))
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    if (njt_array_init(&cmcf->phases[NJT_STREAM_LOG_PHASE].handlers,
                       cf->pool, 1, sizeof(njt_stream_handler_pt))
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    return NJT_OK;
}


static njt_int_t
njt_stream_init_phase_handlers(njt_conf_t *cf,
    njt_stream_core_main_conf_t *cmcf)
{
    njt_int_t                     j;
    njt_uint_t                    i, n;
    njt_stream_handler_pt        *h;
    njt_stream_phase_handler_t   *ph;
    njt_stream_phase_handler_pt   checker;

    n = 1 /* content phase */;

    for (i = 0; i < NJT_STREAM_LOG_PHASE; i++) {
        n += cmcf->phases[i].handlers.nelts;
    }

    ph = njt_pcalloc(cf->pool,
                     n * sizeof(njt_stream_phase_handler_t) + sizeof(void *));
    if (ph == NULL) {
        return NJT_ERROR;
    }

    cmcf->phase_engine.handlers = ph;
    n = 0;

    for (i = 0; i < NJT_STREAM_LOG_PHASE; i++) {
        h = cmcf->phases[i].handlers.elts;

        switch (i) {

        case NJT_STREAM_PREREAD_PHASE:
            checker = njt_stream_core_preread_phase;
            break;

        case NJT_STREAM_CONTENT_PHASE:
            ph->checker = njt_stream_core_content_phase;
            n++;
            ph++;

            continue;

        default:
            checker = njt_stream_core_generic_phase;
        }

        n += cmcf->phases[i].handlers.nelts;

        for (j = cmcf->phases[i].handlers.nelts - 1; j >= 0; j--) {
            ph->checker = checker;
            ph->handler = h[j];
            ph->next = n;
            ph++;
        }
    }

    return NJT_OK;
}


njt_int_t
njt_stream_add_listen(njt_conf_t *cf, njt_stream_core_srv_conf_t *cscf,
    njt_stream_listen_opt_t *lsopt)
{
    in_port_t                     p;
    njt_uint_t                    i;
    struct sockaddr              *sa;
    njt_stream_conf_port_t       *port;
    njt_stream_core_main_conf_t  *cmcf;

    cmcf = njt_stream_conf_get_module_main_conf(cf, njt_stream_core_module);

    if (cmcf->ports == NULL) {
        cmcf->ports = njt_array_create(cf->temp_pool, 2,
                                       sizeof(njt_stream_conf_port_t));
        if (cmcf->ports == NULL) {
            return NJT_ERROR;
        }
    }

    sa = lsopt->sockaddr;
    p = njt_inet_get_port(sa);

    port = cmcf->ports->elts;
    for (i = 0; i < cmcf->ports->nelts; i++) {

        if (p != port[i].port
            || lsopt->type != port[i].type
            || sa->sa_family != port[i].family)
        {
            continue;
        }

        /* a port is already in the port list */

        return njt_stream_add_addresses(cf, cscf, &port[i], lsopt);
    }

    /* add a port to the port list */

    port = njt_array_push(cmcf->ports);
    if (port == NULL) {
        return NJT_ERROR;
    }

    port->family = sa->sa_family;
    port->type = lsopt->type;
    port->port = p;
    port->addrs.elts = NULL;

    return njt_stream_add_address(cf, cscf, port, lsopt);
}


static njt_int_t
njt_stream_add_addresses(njt_conf_t *cf, njt_stream_core_srv_conf_t *cscf,
    njt_stream_conf_port_t *port, njt_stream_listen_opt_t *lsopt)
{
    njt_uint_t               i, default_server, proxy_protocol,
                             protocols, protocols_prev;
    njt_stream_conf_addr_t  *addr;
#if (NJT_STREAM_SSL)
    njt_uint_t               ssl;
#endif

    /*
     * we cannot compare whole sockaddr struct's as kernel
     * may fill some fields in inherited sockaddr struct's
     */

    addr = port->addrs.elts;

    for (i = 0; i < port->addrs.nelts; i++) {

        if (njt_cmp_sockaddr(lsopt->sockaddr, lsopt->socklen,
                             addr[i].opt.sockaddr,
                             addr[i].opt.socklen, 0)
            != NJT_OK)
        {
            continue;
        }

        /* the address is already in the address list */

        if (njt_stream_add_server(cf, cscf, &addr[i]) != NJT_OK) {
            return NJT_ERROR;
        }

        /* preserve default_server bit during listen options overwriting */
        default_server = addr[i].opt.default_server;

        proxy_protocol = lsopt->proxy_protocol || addr[i].opt.proxy_protocol;
        protocols = lsopt->proxy_protocol;
        protocols_prev = addr[i].opt.proxy_protocol;

#if (NJT_STREAM_SSL)
        ssl = lsopt->ssl || addr[i].opt.ssl;
        protocols |= lsopt->ssl << 1;
        protocols_prev |= addr[i].opt.ssl << 1;
#endif

        if (lsopt->set) {

            if (addr[i].opt.set) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "duplicate listen options for %V",
                                   &addr[i].opt.addr_text);
                return NJT_ERROR;

            }

            addr[i].opt = *lsopt;
        }

        /* check the duplicate "default" server for this address:port */

        if (lsopt->default_server) {

            if (default_server) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "a duplicate default server for %V",
                                   &addr[i].opt.addr_text);
                return NJT_ERROR;
            }

            default_server = 1;
            addr[i].default_server = cscf;
        }

        /* check for conflicting protocol options */

        if ((protocols | protocols_prev) != protocols_prev) {

            /* options added */

            if ((addr[i].opt.set && !lsopt->set)
                || addr[i].protocols_changed
                || (protocols | protocols_prev) != protocols)
            {
                njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                                   "protocol options redefined for %V",
                                   &addr[i].opt.addr_text);
            }

            addr[i].protocols = protocols_prev;
            addr[i].protocols_set = 1;
            addr[i].protocols_changed = 1;

        } else if ((protocols_prev | protocols) != protocols) {

            /* options removed */

            if (lsopt->set
                || (addr[i].protocols_set && protocols != addr[i].protocols))
            {
                njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                                   "protocol options redefined for %V",
                                   &addr[i].opt.addr_text);
            }

            addr[i].protocols = protocols;
            addr[i].protocols_set = 1;
            addr[i].protocols_changed = 1;

        } else {

            /* the same options */

            if ((lsopt->set && addr[i].protocols_changed)
                || (addr[i].protocols_set && protocols != addr[i].protocols))
            {
                njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                                   "protocol options redefined for %V",
                                   &addr[i].opt.addr_text);
            }

            addr[i].protocols = protocols;
            addr[i].protocols_set = 1;
        }

        addr[i].opt.default_server = default_server;
        addr[i].opt.proxy_protocol = proxy_protocol;
#if (NJT_STREAM_SSL)
        addr[i].opt.ssl = ssl;
#endif
        return NJT_OK;
    }

    /* add the address to the addresses list that bound to this port */

    return njt_stream_add_address(cf, cscf, port, lsopt);
}


/*
 * add the server address, the server names and the server core module
 * configurations to the port list
 */

static njt_int_t
njt_stream_add_address(njt_conf_t *cf, njt_stream_core_srv_conf_t *cscf,
    njt_stream_conf_port_t *port, njt_stream_listen_opt_t *lsopt)
{
    njt_stream_conf_addr_t  *addr;

    if (port->addrs.elts == NULL) {
        if (njt_array_init(&port->addrs, cf->temp_pool, 4,
                           sizeof(njt_stream_conf_addr_t))
            != NJT_OK)
        {
            return NJT_ERROR;
        }
    }

    addr = njt_array_push(&port->addrs);
    if (addr == NULL) {
        return NJT_ERROR;
    }

    addr->opt = *lsopt;
    addr->protocols = 0;
    addr->protocols_set = 0;
    addr->protocols_changed = 0;
    addr->hash.buckets = NULL;
    addr->hash.size = 0;
    addr->wc_head = NULL;
    addr->wc_tail = NULL;
#if (NJT_PCRE)
    addr->nregex = 0;
    addr->regex = NULL;
#endif
    addr->default_server = cscf;
    addr->servers.elts = NULL;

    return njt_stream_add_server(cf, cscf, addr);
}


/* add the server core module configuration to the address:port */

static njt_int_t
njt_stream_add_server(njt_conf_t *cf, njt_stream_core_srv_conf_t *cscf,
    njt_stream_conf_addr_t *addr)
{
    njt_uint_t                    i;
    njt_stream_core_srv_conf_t  **server;

    if (addr->servers.elts == NULL) {
        if (njt_array_init(&addr->servers, cf->temp_pool, 4,
                           sizeof(njt_stream_core_srv_conf_t *))
            != NJT_OK)
        {
            return NJT_ERROR;
        }

    } else {
        server = addr->servers.elts;
        for (i = 0; i < addr->servers.nelts; i++) {
            if (server[i] == cscf) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "a duplicate listen %V",
                                   &addr->opt.addr_text);
                return NJT_ERROR;
            }
        }
    }

    server = njt_array_push(&addr->servers);
    if (server == NULL) {
        return NJT_ERROR;
    }

    *server = cscf;

    return NJT_OK;
}


njt_stream_listen_opt_t *
njt_stream_get_listen_opt(njt_cycle_t *cycle,
    njt_stream_core_srv_conf_t *cscf)
{
    njt_stream_core_main_conf_t   *cmcf;
    njt_stream_conf_port_t        *port;
    njt_uint_t                      i, j, k;
    njt_stream_conf_addr_t       **addr;
    njt_stream_core_srv_conf_t   **server;

    cmcf = njt_stream_cycle_get_module_main_conf(cycle, njt_stream_core_module);
    if (cmcf == NULL || cmcf->ports == NULL) {
        return NULL;
    }

    port = cmcf->ports->elts;
    for (i = 0; i < cmcf->ports->nelts; i++) {
        addr = port[i].addrs.elts;

        for (j = 0; j < port[i].addrs.nelts; j++) {
            server = addr[j]->servers.elts;

            for (k = 0; k < addr[j]->servers.nelts; k++) {
                if (server[k] == cscf) {
                    return &addr[j]->opt;
                }
            }
        }
    }

    return NULL;
}


static njt_int_t
njt_stream_optimize_servers(njt_conf_t *cf, njt_stream_core_main_conf_t *cmcf,
    njt_array_t *ports)
{
    njt_uint_t               p, a;
    njt_stream_conf_port_t  *port;
    njt_stream_conf_addr_t  *addr;

    if (ports == NULL) {
        return NJT_OK;
    }

    port = ports->elts;
    for (p = 0; p < ports->nelts; p++) {

        njt_sort(port[p].addrs.elts, (size_t) port[p].addrs.nelts,
                 sizeof(njt_stream_conf_addr_t), njt_stream_cmp_conf_addrs);

        /*
         * check whether all name-based servers have the same
         * configuration as a default server for given address:port
         */


        addr = port[p].addrs.elts;
        for (a = 0; a < port[p].addrs.nelts; a++) {

            if (addr[a].servers.nelts > 1
#if (NJT_PCRE)
                || addr[a].default_server->captures
#endif
               )
            {
                if (njt_stream_server_names(cf, cmcf, &addr[a]) != NJT_OK) {
                    return NJT_ERROR;
                }
            }
        }

        if (njt_stream_init_listening(cf, &port[p]) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


static njt_int_t
njt_stream_server_names(njt_conf_t *cf, njt_stream_core_main_conf_t *cmcf,
    njt_stream_conf_addr_t *addr)
{
    njt_int_t                     rc;
    njt_uint_t                    n, s;
    njt_hash_init_t               hash;
    njt_hash_keys_arrays_t        ha;
    njt_stream_server_name_t     *name;
    njt_stream_core_srv_conf_t  **cscfp;
#if (NJT_PCRE)
    njt_uint_t                    regex, i;
    regex = 0;
#endif

    njt_memzero(&ha, sizeof(njt_hash_keys_arrays_t));

    ha.temp_pool = njt_create_pool(NJT_DEFAULT_POOL_SIZE, cf->log);
    if (ha.temp_pool == NULL) {
        return NJT_ERROR;
    }

    ha.pool = cf->pool;

    if (njt_hash_keys_array_init(&ha, NJT_HASH_LARGE) != NJT_OK) {
        goto failed;
    }

    cscfp = addr->servers.elts;

    for (s = 0; s < addr->servers.nelts; s++) {

        name = cscfp[s]->server_names.elts;

        for (n = 0; n < cscfp[s]->server_names.nelts; n++) {

#if (NJT_PCRE)
            if (name[n].regex) {
                regex++;
                continue;
            }
#endif

            rc = njt_hash_add_key(&ha, &name[n].name, name[n].server,
                                  NJT_HASH_WILDCARD_KEY);

            if (rc == NJT_ERROR) {
                goto failed;
            }

            if (rc == NJT_DECLINED) {
                njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                              "invalid server name or wildcard \"%V\" on %V",
                              &name[n].name, &addr->opt.addr_text);
                goto failed;
            }

            if (rc == NJT_BUSY) {
                njt_log_error(NJT_LOG_WARN, cf->log, 0,
                              "conflicting server name \"%V\" on %V, ignored",
                              &name[n].name, &addr->opt.addr_text);
            }
        }
    }

    hash.key = njt_hash_key_lc;
    hash.max_size = cmcf->server_names_hash_max_size;
    hash.bucket_size = cmcf->server_names_hash_bucket_size;
    hash.name = "server_names_hash";
    hash.pool = cf->pool;

    if (ha.keys.nelts) {
        hash.hash = &addr->hash;
        hash.temp_pool = NULL;

        if (njt_hash_init(&hash, ha.keys.elts, ha.keys.nelts) != NJT_OK) {
            goto failed;
        }
    }

    if (ha.dns_wc_head.nelts) {

        njt_qsort(ha.dns_wc_head.elts, (size_t) ha.dns_wc_head.nelts,
                  sizeof(njt_hash_key_t), njt_stream_cmp_dns_wildcards);

        hash.hash = NULL;
        hash.temp_pool = ha.temp_pool;

        if (njt_hash_wildcard_init(&hash, ha.dns_wc_head.elts,
                                   ha.dns_wc_head.nelts)
            != NJT_OK)
        {
            goto failed;
        }

        addr->wc_head = (njt_hash_wildcard_t *) hash.hash;
    }

    if (ha.dns_wc_tail.nelts) {

        njt_qsort(ha.dns_wc_tail.elts, (size_t) ha.dns_wc_tail.nelts,
                  sizeof(njt_hash_key_t), njt_stream_cmp_dns_wildcards);

        hash.hash = NULL;
        hash.temp_pool = ha.temp_pool;

        if (njt_hash_wildcard_init(&hash, ha.dns_wc_tail.elts,
                                   ha.dns_wc_tail.nelts)
            != NJT_OK)
        {
            goto failed;
        }

        addr->wc_tail = (njt_hash_wildcard_t *) hash.hash;
    }

    njt_destroy_pool(ha.temp_pool);

#if (NJT_PCRE)

    if (regex == 0) {
        return NJT_OK;
    }

    addr->nregex = regex;
    addr->regex = njt_palloc(cf->pool,
                             regex * sizeof(njt_stream_server_name_t));
    if (addr->regex == NULL) {
        return NJT_ERROR;
    }

    i = 0;

    for (s = 0; s < addr->servers.nelts; s++) {

        name = cscfp[s]->server_names.elts;

        for (n = 0; n < cscfp[s]->server_names.nelts; n++) {
            if (name[n].regex) {
                addr->regex[i++] = name[n];
            }
        }
    }
#endif

    return NJT_OK;

failed:

    njt_destroy_pool(ha.temp_pool);

    return NJT_ERROR;
}


static njt_int_t
njt_stream_cmp_conf_addrs(const void *one, const void *two)
{
    njt_stream_conf_addr_t  *first, *second;

    first = (njt_stream_conf_addr_t *) one;
    second = (njt_stream_conf_addr_t *) two;

    if (first->opt.wildcard) {
        /* a wildcard address must be the last resort, shift it to the end */
        return 1;
    }

    if (second->opt.wildcard) {
        /* a wildcard address must be the last resort, shift it to the end */
        return -1;
    }

    if (first->opt.bind && !second->opt.bind) {
        /* shift explicit bind()ed addresses to the start */
        return -1;
    }

    if (!first->opt.bind && second->opt.bind) {
        /* shift explicit bind()ed addresses to the start */
        return 1;
    }

    /* do not sort by default */

    return 0;
}


static int njt_libc_cdecl
njt_stream_cmp_dns_wildcards(const void *one, const void *two)
{
    njt_hash_key_t  *first, *second;

    first = (njt_hash_key_t *) one;
    second = (njt_hash_key_t *) two;

    return njt_dns_strcmp(first->key.data, second->key.data);
}


static njt_int_t
njt_stream_init_listening(njt_conf_t *cf, njt_stream_conf_port_t *port)
{
    njt_uint_t               i, last, bind_wildcard;
    njt_listening_t         *ls;
    njt_stream_port_t       *stport;
    njt_stream_conf_addr_t  *addr;

    addr = port->addrs.elts;
    last = port->addrs.nelts;

    /*
     * If there is a binding to an "*:port" then we need to bind() to
     * the "*:port" only and ignore other implicit bindings.  The bindings
     * have been already sorted: explicit bindings are on the start, then
     * implicit bindings go, and wildcard binding is in the end.
     */

    if (addr[last - 1].opt.wildcard) {
        addr[last - 1].opt.bind = 1;
        bind_wildcard = 1;

    } else {
        bind_wildcard = 0;
    }

    i = 0;

    while (i < last) {

        if (bind_wildcard && !addr[i].opt.bind) {
            i++;
            continue;
        }

        ls = njt_stream_add_listening(cf, &addr[i]);
        if (ls == NULL) {
            return NJT_ERROR;
        }

        stport = njt_pcalloc(cf->pool, sizeof(njt_stream_port_t));
        if (stport == NULL) {
            return NJT_ERROR;
        }

        ls->servers = stport;

        stport->naddrs = i + 1;

        switch (ls->sockaddr->sa_family) {

#if (NJT_HAVE_INET6)
        case AF_INET6:
            if (njt_stream_add_addrs6(cf, stport, addr) != NJT_OK) {
                return NJT_ERROR;
            }
            break;
#endif
        default: /* AF_INET */
            if (njt_stream_add_addrs(cf, stport, addr) != NJT_OK) {
                return NJT_ERROR;
            }
            break;
        }

        addr++;
        last--;
    }

    return NJT_OK;
}


static njt_listening_t *
njt_stream_add_listening(njt_conf_t *cf, njt_stream_conf_addr_t *addr)
{
    njt_listening_t             *ls;
    njt_stream_core_srv_conf_t  *cscf;

    ls = njt_create_listening(cf, addr->opt.sockaddr, addr->opt.socklen);
    if (ls == NULL) {
        return NULL;
    }

    ls->addr_ntop = 1;

    ls->handler = njt_stream_init_connection;

    ls->pool_size = 256;

    cscf = addr->default_server;

    ls->logp = cscf->error_log;
    ls->log.data = &ls->addr_text;
    ls->log.handler = njt_accept_log_error;

    ls->type = addr->opt.type;
    ls->backlog = addr->opt.backlog;
    ls->rcvbuf = addr->opt.rcvbuf;
    ls->sndbuf = addr->opt.sndbuf;

    ls->keepalive = addr->opt.so_keepalive;
#if (NJT_HAVE_KEEPALIVE_TUNABLE)
    ls->keepidle = addr->opt.tcp_keepidle;
    ls->keepintvl = addr->opt.tcp_keepintvl;
    ls->keepcnt = addr->opt.tcp_keepcnt;
#endif

#if (NJT_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    ls->accept_filter = addr->opt.accept_filter;
#endif

#if (NJT_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
    ls->deferred_accept = addr->opt.deferred_accept;
#endif

#if (NJT_HAVE_INET6)
    ls->ipv6only = addr->opt.ipv6only;
#endif

#if (NJT_HAVE_TCP_FASTOPEN)
    ls->fastopen = addr->opt.fastopen;
#endif

#if (NJT_HAVE_REUSEPORT)
    ls->reuseport = addr->opt.reuseport;
#endif

    ls->wildcard = addr->opt.wildcard;

    return ls;
}


static njt_int_t
njt_stream_add_addrs(njt_conf_t *cf, njt_stream_port_t *stport,
    njt_stream_conf_addr_t *addr)
{
    njt_uint_t                   i;
    struct sockaddr_in          *sin;
    njt_stream_in_addr_t        *addrs;
    njt_stream_virtual_names_t  *vn;

    stport->addrs = njt_pcalloc(cf->pool,
                                stport->naddrs * sizeof(njt_stream_in_addr_t));
    if (stport->addrs == NULL) {
        return NJT_ERROR;
    }

    addrs = stport->addrs;

    for (i = 0; i < stport->naddrs; i++) {

        sin = (struct sockaddr_in *) addr[i].opt.sockaddr;
        addrs[i].addr = sin->sin_addr.s_addr;
        addrs[i].conf.default_server = addr[i].default_server;
#if (NJT_STREAM_SSL)
        addrs[i].conf.ssl = addr[i].opt.ssl;
#endif
        addrs[i].conf.proxy_protocol = addr[i].opt.proxy_protocol;

        if (addr[i].hash.buckets == NULL
            && (addr[i].wc_head == NULL
                || addr[i].wc_head->hash.buckets == NULL)
            && (addr[i].wc_tail == NULL
                || addr[i].wc_tail->hash.buckets == NULL)
#if (NJT_PCRE)
            && addr[i].nregex == 0
#endif
            )
        {
            continue;
        }

        vn = njt_palloc(cf->pool, sizeof(njt_stream_virtual_names_t));
        if (vn == NULL) {
            return NJT_ERROR;
        }

        addrs[i].conf.virtual_names = vn;

        vn->names.hash = addr[i].hash;
        vn->names.wc_head = addr[i].wc_head;
        vn->names.wc_tail = addr[i].wc_tail;
#if (NJT_PCRE)
        vn->nregex = addr[i].nregex;
        vn->regex = addr[i].regex;
#endif
    }

    return NJT_OK;
}

#if (NJT_HAVE_INET6)

static njt_int_t
njt_stream_add_addrs6(njt_conf_t *cf, njt_stream_port_t *stport,
    njt_stream_conf_addr_t *addr)
{
    njt_uint_t                   i;
    struct sockaddr_in6         *sin6;
    njt_stream_in6_addr_t       *addrs6;
    njt_stream_virtual_names_t  *vn;

    stport->addrs = njt_pcalloc(cf->pool,
                                stport->naddrs * sizeof(njt_stream_in6_addr_t));
    if (stport->addrs == NULL) {
        return NJT_ERROR;
    }

    addrs6 = stport->addrs;

    for (i = 0; i < stport->naddrs; i++) {

        sin6 = (struct sockaddr_in6 *) addr[i].opt.sockaddr;
        addrs6[i].addr6 = sin6->sin6_addr;
        addrs6[i].conf.default_server = addr[i].default_server;
#if (NJT_STREAM_SSL)
        addrs6[i].conf.ssl = addr[i].opt.ssl;
#endif
        addrs6[i].conf.proxy_protocol = addr[i].opt.proxy_protocol;

        if (addr[i].hash.buckets == NULL
            && (addr[i].wc_head == NULL
                || addr[i].wc_head->hash.buckets == NULL)
            && (addr[i].wc_tail == NULL
                || addr[i].wc_tail->hash.buckets == NULL)
#if (NJT_PCRE)
            && addr[i].nregex == 0
#endif
            )
        {
            continue;
        }

        vn = njt_palloc(cf->pool, sizeof(njt_stream_virtual_names_t));
        if (vn == NULL) {
            return NJT_ERROR;
        }

        addrs6[i].conf.virtual_names = vn;

        vn->names.hash = addr[i].hash;
        vn->names.wc_head = addr[i].wc_head;
        vn->names.wc_tail = addr[i].wc_tail;
#if (NJT_PCRE)
        vn->nregex = addr[i].nregex;
        vn->regex = addr[i].regex;
#endif
    }

    return NJT_OK;
}

#endif