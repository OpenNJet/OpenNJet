
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
static njt_int_t njt_stream_add_ports(njt_conf_t *cf, njt_array_t *ports,
    njt_stream_listen_t *listen);
static char *njt_stream_optimize_servers(njt_conf_t *cf, njt_array_t *ports);
static njt_int_t njt_stream_add_addrs(njt_conf_t *cf, njt_stream_port_t *stport,
    njt_stream_conf_addr_t *addr);
#if (NJT_HAVE_INET6)
static njt_int_t njt_stream_add_addrs6(njt_conf_t *cf,
    njt_stream_port_t *stport, njt_stream_conf_addr_t *addr);
#endif
static njt_int_t njt_stream_cmp_conf_addrs(const void *one, const void *two);


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
    njt_uint_t                     i, m, mi, s;
    njt_conf_t                     pcf;
    njt_array_t                    ports;
    njt_stream_listen_t           *listen;
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

    if (njt_array_init(&ports, cf->temp_pool, 4, sizeof(njt_stream_conf_port_t))
        != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    listen = cmcf->listen.elts;

    for (i = 0; i < cmcf->listen.nelts; i++) {
        if (njt_stream_add_ports(cf, &ports, &listen[i]) != NJT_OK) {
            return NJT_CONF_ERROR;
        }
    }

    return njt_stream_optimize_servers(cf, &ports);
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


static njt_int_t
njt_stream_add_ports(njt_conf_t *cf, njt_array_t *ports,
    njt_stream_listen_t *listen)
{
    in_port_t                p;
    njt_uint_t               i;
    struct sockaddr         *sa;
    njt_stream_conf_port_t  *port;
    njt_stream_conf_addr_t  *addr;

    sa = listen->sockaddr;
    p = njt_inet_get_port(sa);

    port = ports->elts;
    for (i = 0; i < ports->nelts; i++) {

        if (p == port[i].port
            && listen->type == port[i].type
            && sa->sa_family == port[i].family)
        {
            /* a port is already in the port list */

            port = &port[i];
            goto found;
        }
    }

    /* add a port to the port list */

    port = njt_array_push(ports);
    if (port == NULL) {
        return NJT_ERROR;
    }

    port->family = sa->sa_family;
    port->type = listen->type;
    port->port = p;

    if (njt_array_init(&port->addrs, cf->temp_pool, 2,
                       sizeof(njt_stream_conf_addr_t))
        != NJT_OK)
    {
        return NJT_ERROR;
    }

found:

    addr = njt_array_push(&port->addrs);
    if (addr == NULL) {
        return NJT_ERROR;
    }

    addr->opt = *listen;

    return NJT_OK;
}


static char *
njt_stream_optimize_servers(njt_conf_t *cf, njt_array_t *ports)
{
    njt_uint_t                   i, p, last, bind_wildcard;
    njt_listening_t             *ls;
    njt_stream_port_t           *stport;
    njt_stream_conf_port_t      *port;
    njt_stream_conf_addr_t      *addr;
    njt_stream_core_srv_conf_t  *cscf;

    port = ports->elts;
    for (p = 0; p < ports->nelts; p++) {

        njt_sort(port[p].addrs.elts, (size_t) port[p].addrs.nelts,
                 sizeof(njt_stream_conf_addr_t), njt_stream_cmp_conf_addrs);

        addr = port[p].addrs.elts;
        last = port[p].addrs.nelts;

        /*
         * if there is the binding to the "*:port" then we need to bind()
         * to the "*:port" only and ignore the other bindings
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

            ls = njt_create_listening(cf, addr[i].opt.sockaddr,
                                      addr[i].opt.socklen);
            if (ls == NULL) {
                return NJT_CONF_ERROR;
            }

            ls->addr_ntop = 1;
            ls->handler = njt_stream_init_connection;
            ls->pool_size = 256;
            ls->type = addr[i].opt.type;

            cscf = addr->opt.ctx->srv_conf[njt_stream_core_module.ctx_index];

            ls->logp = cscf->error_log;
            ls->log.data = &ls->addr_text;
            ls->log.handler = njt_accept_log_error;

            ls->backlog = addr[i].opt.backlog;
            ls->rcvbuf = addr[i].opt.rcvbuf;
            ls->sndbuf = addr[i].opt.sndbuf;

            ls->wildcard = addr[i].opt.wildcard;

            ls->keepalive = addr[i].opt.so_keepalive;
#if (NJT_HAVE_KEEPALIVE_TUNABLE)
            ls->keepidle = addr[i].opt.tcp_keepidle;
            ls->keepintvl = addr[i].opt.tcp_keepintvl;
            ls->keepcnt = addr[i].opt.tcp_keepcnt;
#endif

#if (NJT_HAVE_INET6)
            ls->ipv6only = addr[i].opt.ipv6only;
#endif

#if (NJT_HAVE_TCP_FASTOPEN)
            ls->fastopen = addr[i].opt.fastopen;
#endif

            //add by clb. used for tcp and udp traffic hack
            ls->mesh = addr[i].opt.mesh;
            //end add by clb

#if (NJT_HAVE_REUSEPORT)
            ls->reuseport = addr[i].opt.reuseport;
#endif

            stport = njt_palloc(cf->pool, sizeof(njt_stream_port_t));
            if (stport == NULL) {
                return NJT_CONF_ERROR;
            }

            ls->servers = stport;
            ls->server_type = NJT_STREAM_SERVER_TYPE;
            stport->naddrs = i + 1;

            switch (ls->sockaddr->sa_family) {
#if (NJT_HAVE_INET6)
            case AF_INET6:
                if (njt_stream_add_addrs6(cf, stport, addr) != NJT_OK) {
                    return NJT_CONF_ERROR;
                }
                break;
#endif
            default: /* AF_INET */
                if (njt_stream_add_addrs(cf, stport, addr) != NJT_OK) {
                    return NJT_CONF_ERROR;
                }
                break;
            }

            addr++;
            last--;
        }
    }

    return NJT_CONF_OK;
}


njt_int_t
njt_stream_add_addrs(njt_conf_t *cf, njt_stream_port_t *stport,
    njt_stream_conf_addr_t *addr)
{
    njt_uint_t             i;
    struct sockaddr_in    *sin;
    njt_stream_in_addr_t  *addrs;

    stport->addrs = njt_pcalloc(cf->pool,
                                stport->naddrs * sizeof(njt_stream_in_addr_t));
    if (stport->addrs == NULL) {
        return NJT_ERROR;
    }

    addrs = stport->addrs;

    for (i = 0; i < stport->naddrs; i++) {

        sin = (struct sockaddr_in *) addr[i].opt.sockaddr;
        addrs[i].addr = sin->sin_addr.s_addr;

        addrs[i].conf.ctx = addr[i].opt.ctx;
#if (NJT_STREAM_SSL)
        addrs[i].conf.ssl = addr[i].opt.ssl;
#endif
        addrs[i].conf.proxy_protocol = addr[i].opt.proxy_protocol;
        addrs[i].conf.addr_text = addr[i].opt.addr_text;
    }

    return NJT_OK;
}


#if (NJT_HAVE_INET6)

static njt_int_t
njt_stream_add_addrs6(njt_conf_t *cf, njt_stream_port_t *stport,
    njt_stream_conf_addr_t *addr)
{
    njt_uint_t              i;
    struct sockaddr_in6    *sin6;
    njt_stream_in6_addr_t  *addrs6;

    stport->addrs = njt_pcalloc(cf->pool,
                                stport->naddrs * sizeof(njt_stream_in6_addr_t));
    if (stport->addrs == NULL) {
        return NJT_ERROR;
    }

    addrs6 = stport->addrs;

    for (i = 0; i < stport->naddrs; i++) {

        sin6 = (struct sockaddr_in6 *) addr[i].opt.sockaddr;
        addrs6[i].addr6 = sin6->sin6_addr;

        addrs6[i].conf.ctx = addr[i].opt.ctx;
#if (NJT_STREAM_SSL)
        addrs6[i].conf.ssl = addr[i].opt.ssl;
#endif
        addrs6[i].conf.proxy_protocol = addr[i].opt.proxy_protocol;
        addrs6[i].conf.addr_text = addr[i].opt.addr_text;
    }

    return NJT_OK;
}

#endif


static njt_int_t
njt_stream_cmp_conf_addrs(const void *one, const void *two)
{
    njt_stream_conf_addr_t  *first, *second;

    first = (njt_stream_conf_addr_t *) one;
    second = (njt_stream_conf_addr_t *) two;

    if (first->opt.wildcard) {
        /* a wildcard must be the last resort, shift it to the end */
        return 1;
    }

    if (second->opt.wildcard) {
        /* a wildcard must be the last resort, shift it to the end */
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
