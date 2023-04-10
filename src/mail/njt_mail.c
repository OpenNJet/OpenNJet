
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_mail.h>


static char *njt_mail_block(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static njt_int_t njt_mail_add_ports(njt_conf_t *cf, njt_array_t *ports,
    njt_mail_listen_t *listen);
static char *njt_mail_optimize_servers(njt_conf_t *cf, njt_array_t *ports);
static njt_int_t njt_mail_add_addrs(njt_conf_t *cf, njt_mail_port_t *mport,
    njt_mail_conf_addr_t *addr);
#if (NJT_HAVE_INET6)
static njt_int_t njt_mail_add_addrs6(njt_conf_t *cf, njt_mail_port_t *mport,
    njt_mail_conf_addr_t *addr);
#endif
static njt_int_t njt_mail_cmp_conf_addrs(const void *one, const void *two);


njt_uint_t  njt_mail_max_module;


static njt_command_t  njt_mail_commands[] = {

    { njt_string("mail"),
      NJT_MAIN_CONF|NJT_CONF_BLOCK|NJT_CONF_NOARGS,
      njt_mail_block,
      0,
      0,
      NULL },

      njt_null_command
};


static njt_core_module_t  njt_mail_module_ctx = {
    njt_string("mail"),
    NULL,
    NULL
};


njt_module_t  njt_mail_module = {
    NJT_MODULE_V1,
    &njt_mail_module_ctx,                  /* module context */
    njt_mail_commands,                     /* module directives */
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
njt_mail_block(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char                        *rv;
    njt_uint_t                   i, m, mi, s;
    njt_conf_t                   pcf;
    njt_array_t                  ports;
    njt_mail_listen_t           *listen;
    njt_mail_module_t           *module;
    njt_mail_conf_ctx_t         *ctx;
    njt_mail_core_srv_conf_t   **cscfp;
    njt_mail_core_main_conf_t   *cmcf;

    if (*(njt_mail_conf_ctx_t **) conf) {
        return "is duplicate";
    }

    /* the main mail context */

    ctx = njt_pcalloc(cf->pool, sizeof(njt_mail_conf_ctx_t));
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }

    *(njt_mail_conf_ctx_t **) conf = ctx;

    /* count the number of the mail modules and set up their indices */

    njt_mail_max_module = njt_count_modules(cf->cycle, NJT_MAIL_MODULE);


    /* the mail main_conf context, it is the same in the all mail contexts */

    ctx->main_conf = njt_pcalloc(cf->pool,
                                 sizeof(void *) * njt_mail_max_module);
    if (ctx->main_conf == NULL) {
        return NJT_CONF_ERROR;
    }


    /*
     * the mail null srv_conf context, it is used to merge
     * the server{}s' srv_conf's
     */

    ctx->srv_conf = njt_pcalloc(cf->pool, sizeof(void *) * njt_mail_max_module);
    if (ctx->srv_conf == NULL) {
        return NJT_CONF_ERROR;
    }


    /*
     * create the main_conf's and the null srv_conf's of the all mail modules
     */

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NJT_MAIL_MODULE) {
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


    /* parse inside the mail{} block */

    pcf = *cf;
    cf->ctx = ctx;

    cf->module_type = NJT_MAIL_MODULE;
    cf->cmd_type = NJT_MAIL_MAIN_CONF;
    rv = njt_conf_parse(cf, NULL);

    if (rv != NJT_CONF_OK) {
        *cf = pcf;
        return rv;
    }


    /* init mail{} main_conf's, merge the server{}s' srv_conf's */

    cmcf = ctx->main_conf[njt_mail_core_module.ctx_index];
    cscfp = cmcf->servers.elts;

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NJT_MAIL_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        mi = cf->cycle->modules[m]->ctx_index;

        /* init mail{} main_conf's */

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

    *cf = pcf;


    if (njt_array_init(&ports, cf->temp_pool, 4, sizeof(njt_mail_conf_port_t))
        != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    listen = cmcf->listen.elts;

    for (i = 0; i < cmcf->listen.nelts; i++) {
        if (njt_mail_add_ports(cf, &ports, &listen[i]) != NJT_OK) {
            return NJT_CONF_ERROR;
        }
    }

    return njt_mail_optimize_servers(cf, &ports);
}


static njt_int_t
njt_mail_add_ports(njt_conf_t *cf, njt_array_t *ports,
    njt_mail_listen_t *listen)
{
    in_port_t              p;
    njt_uint_t             i;
    struct sockaddr       *sa;
    njt_mail_conf_port_t  *port;
    njt_mail_conf_addr_t  *addr;

    sa = listen->sockaddr;
    p = njt_inet_get_port(sa);

    port = ports->elts;
    for (i = 0; i < ports->nelts; i++) {
        if (p == port[i].port && sa->sa_family == port[i].family) {

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
    port->port = p;

    if (njt_array_init(&port->addrs, cf->temp_pool, 2,
                       sizeof(njt_mail_conf_addr_t))
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
njt_mail_optimize_servers(njt_conf_t *cf, njt_array_t *ports)
{
    njt_uint_t                 i, p, last, bind_wildcard;
    njt_listening_t           *ls;
    njt_mail_port_t           *mport;
    njt_mail_conf_port_t      *port;
    njt_mail_conf_addr_t      *addr;
    njt_mail_core_srv_conf_t  *cscf;

    port = ports->elts;
    for (p = 0; p < ports->nelts; p++) {

        njt_sort(port[p].addrs.elts, (size_t) port[p].addrs.nelts,
                 sizeof(njt_mail_conf_addr_t), njt_mail_cmp_conf_addrs);

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
            ls->handler = njt_mail_init_connection;
            ls->pool_size = 256;

            cscf = addr->opt.ctx->srv_conf[njt_mail_core_module.ctx_index];

            ls->logp = cscf->error_log;
            ls->log.data = &ls->addr_text;
            ls->log.handler = njt_accept_log_error;

            ls->backlog = addr[i].opt.backlog;
            ls->rcvbuf = addr[i].opt.rcvbuf;
            ls->sndbuf = addr[i].opt.sndbuf;

            ls->keepalive = addr[i].opt.so_keepalive;
#if (NJT_HAVE_KEEPALIVE_TUNABLE)
            ls->keepidle = addr[i].opt.tcp_keepidle;
            ls->keepintvl = addr[i].opt.tcp_keepintvl;
            ls->keepcnt = addr[i].opt.tcp_keepcnt;
#endif

#if (NJT_HAVE_INET6)
            ls->ipv6only = addr[i].opt.ipv6only;
#endif

            mport = njt_palloc(cf->pool, sizeof(njt_mail_port_t));
            if (mport == NULL) {
                return NJT_CONF_ERROR;
            }

            ls->servers = mport;
            ls->server_type = NJT_MAIL_SERVER_TYPE;
            mport->naddrs = i + 1;

            switch (ls->sockaddr->sa_family) {
#if (NJT_HAVE_INET6)
            case AF_INET6:
                if (njt_mail_add_addrs6(cf, mport, addr) != NJT_OK) {
                    return NJT_CONF_ERROR;
                }
                break;
#endif
            default: /* AF_INET */
                if (njt_mail_add_addrs(cf, mport, addr) != NJT_OK) {
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


static njt_int_t
njt_mail_add_addrs(njt_conf_t *cf, njt_mail_port_t *mport,
    njt_mail_conf_addr_t *addr)
{
    njt_uint_t           i;
    njt_mail_in_addr_t  *addrs;
    struct sockaddr_in  *sin;

    mport->addrs = njt_pcalloc(cf->pool,
                               mport->naddrs * sizeof(njt_mail_in_addr_t));
    if (mport->addrs == NULL) {
        return NJT_ERROR;
    }

    addrs = mport->addrs;

    for (i = 0; i < mport->naddrs; i++) {

        sin = (struct sockaddr_in *) addr[i].opt.sockaddr;
        addrs[i].addr = sin->sin_addr.s_addr;

        addrs[i].conf.ctx = addr[i].opt.ctx;
#if (NJT_MAIL_SSL)
        addrs[i].conf.ssl = addr[i].opt.ssl;
#endif
        addrs[i].conf.proxy_protocol = addr[i].opt.proxy_protocol;
        addrs[i].conf.addr_text = addr[i].opt.addr_text;
    }

    return NJT_OK;
}


#if (NJT_HAVE_INET6)

static njt_int_t
njt_mail_add_addrs6(njt_conf_t *cf, njt_mail_port_t *mport,
    njt_mail_conf_addr_t *addr)
{
    njt_uint_t            i;
    njt_mail_in6_addr_t  *addrs6;
    struct sockaddr_in6  *sin6;

    mport->addrs = njt_pcalloc(cf->pool,
                               mport->naddrs * sizeof(njt_mail_in6_addr_t));
    if (mport->addrs == NULL) {
        return NJT_ERROR;
    }

    addrs6 = mport->addrs;

    for (i = 0; i < mport->naddrs; i++) {

        sin6 = (struct sockaddr_in6 *) addr[i].opt.sockaddr;
        addrs6[i].addr6 = sin6->sin6_addr;

        addrs6[i].conf.ctx = addr[i].opt.ctx;
#if (NJT_MAIL_SSL)
        addrs6[i].conf.ssl = addr[i].opt.ssl;
#endif
        addrs6[i].conf.proxy_protocol = addr[i].opt.proxy_protocol;
        addrs6[i].conf.addr_text = addr[i].opt.addr_text;
    }

    return NJT_OK;
}

#endif


static njt_int_t
njt_mail_cmp_conf_addrs(const void *one, const void *two)
{
    njt_mail_conf_addr_t  *first, *second;

    first = (njt_mail_conf_addr_t *) one;
    second = (njt_mail_conf_addr_t *) two;

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
