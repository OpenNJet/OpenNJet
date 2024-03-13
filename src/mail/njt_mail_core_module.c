
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_mail.h>


static void *njt_mail_core_create_main_conf(njt_conf_t *cf);
static void *njt_mail_core_create_srv_conf(njt_conf_t *cf);
static char *njt_mail_core_merge_srv_conf(njt_conf_t *cf, void *parent,
    void *child);
static char *njt_mail_core_server(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_mail_core_listen(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_mail_core_protocol(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_mail_core_error_log(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_mail_core_resolver(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);


static njt_command_t  njt_mail_core_commands[] = {

    { njt_string("server"),
      NJT_MAIL_MAIN_CONF|NJT_CONF_BLOCK|NJT_CONF_NOARGS,
      njt_mail_core_server,
      0,
      0,
      NULL },

    { njt_string("listen"),
      NJT_MAIL_SRV_CONF|NJT_CONF_1MORE,
      njt_mail_core_listen,
      NJT_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("protocol"),
      NJT_MAIL_SRV_CONF|NJT_CONF_TAKE1,
      njt_mail_core_protocol,
      NJT_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("timeout"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_core_srv_conf_t, timeout),
      NULL },

    { njt_string("server_name"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_core_srv_conf_t, server_name),
      NULL },

    { njt_string("error_log"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_1MORE,
      njt_mail_core_error_log,
      NJT_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("resolver"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_1MORE,
      njt_mail_core_resolver,
      NJT_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("resolver_timeout"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_core_srv_conf_t, resolver_timeout),
      NULL },

    { njt_string("max_errors"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_core_srv_conf_t, max_errors),
      NULL },

      njt_null_command
};


static njt_mail_module_t  njt_mail_core_module_ctx = {
    NULL,                                  /* protocol */

    njt_mail_core_create_main_conf,        /* create main configuration */
    NULL,                                  /* init main configuration */

    njt_mail_core_create_srv_conf,         /* create server configuration */
    njt_mail_core_merge_srv_conf           /* merge server configuration */
};


njt_module_t  njt_mail_core_module = {
    NJT_MODULE_V1,
    &njt_mail_core_module_ctx,             /* module context */
    njt_mail_core_commands,                /* module directives */
    NJT_MAIL_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


static void *
njt_mail_core_create_main_conf(njt_conf_t *cf)
{
    njt_mail_core_main_conf_t  *cmcf;

    cmcf = njt_pcalloc(cf->pool, sizeof(njt_mail_core_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }

    if (njt_array_init(&cmcf->servers, cf->pool, 4,
                       sizeof(njt_mail_core_srv_conf_t *))
        != NJT_OK)
    {
        return NULL;
    }

    if (njt_array_init(&cmcf->listen, cf->pool, 4, sizeof(njt_mail_listen_t))
        != NJT_OK)
    {
        return NULL;
    }

    return cmcf;
}


static void *
njt_mail_core_create_srv_conf(njt_conf_t *cf)
{
    njt_mail_core_srv_conf_t  *cscf;

    cscf = njt_pcalloc(cf->pool, sizeof(njt_mail_core_srv_conf_t));
    if (cscf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     cscf->protocol = NULL;
     *     cscf->error_log = NULL;
     */

    cscf->timeout = NJT_CONF_UNSET_MSEC;
    cscf->resolver_timeout = NJT_CONF_UNSET_MSEC;

    cscf->max_errors = NJT_CONF_UNSET_UINT;

    cscf->resolver = NJT_CONF_UNSET_PTR;

    cscf->file_name = cf->conf_file->file.name.data;
    cscf->line = cf->conf_file->line;

    return cscf;
}


static char *
njt_mail_core_merge_srv_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_mail_core_srv_conf_t *prev = parent;
    njt_mail_core_srv_conf_t *conf = child;

    njt_conf_merge_msec_value(conf->timeout, prev->timeout, 60000);
    njt_conf_merge_msec_value(conf->resolver_timeout, prev->resolver_timeout,
                              30000);

    njt_conf_merge_uint_value(conf->max_errors, prev->max_errors, 5);

    njt_conf_merge_str_value(conf->server_name, prev->server_name, "");

    if (conf->server_name.len == 0) {
        conf->server_name = cf->cycle->hostname;
    }

    if (conf->protocol == NULL) {
        njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                      "unknown mail protocol for server in %s:%ui",
                      conf->file_name, conf->line);
        return NJT_CONF_ERROR;
    }

    if (conf->error_log == NULL) {
        if (prev->error_log) {
            conf->error_log = prev->error_log;
        } else {
            conf->error_log = &cf->cycle->new_log;
        }
    }

    njt_conf_merge_ptr_value(conf->resolver, prev->resolver, NULL);

    return NJT_CONF_OK;
}


static char *
njt_mail_core_server(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char                       *rv;
    void                       *mconf;
    njt_uint_t                  m;
    njt_conf_t                  pcf;
    njt_mail_module_t          *module;
    njt_mail_conf_ctx_t        *ctx, *mail_ctx;
    njt_mail_core_srv_conf_t   *cscf, **cscfp;
    njt_mail_core_main_conf_t  *cmcf;

    ctx = njt_pcalloc(cf->pool, sizeof(njt_mail_conf_ctx_t));
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }

    mail_ctx = cf->ctx;
    ctx->main_conf = mail_ctx->main_conf;

    /* the server{}'s srv_conf */

    ctx->srv_conf = njt_pcalloc(cf->pool, sizeof(void *) * njt_mail_max_module);
    if (ctx->srv_conf == NULL) {
        return NJT_CONF_ERROR;
    }

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NJT_MAIL_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return NJT_CONF_ERROR;
            }

            ctx->srv_conf[cf->cycle->modules[m]->ctx_index] = mconf;
        }
    }

    /* the server configuration context */

    cscf = ctx->srv_conf[njt_mail_core_module.ctx_index];
    cscf->ctx = ctx;

    cmcf = ctx->main_conf[njt_mail_core_module.ctx_index];

    cscfp = njt_array_push(&cmcf->servers);
    if (cscfp == NULL) {
        return NJT_CONF_ERROR;
    }

    *cscfp = cscf;


    /* parse inside server{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NJT_MAIL_SRV_CONF;

    rv = njt_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv == NJT_CONF_OK && !cscf->listen) {
        njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                      "no \"listen\" is defined for server in %s:%ui",
                      cscf->file_name, cscf->line);
        return NJT_CONF_ERROR;
    }

    return rv;
}


static char *
njt_mail_core_listen(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_mail_core_srv_conf_t  *cscf = conf;

    njt_str_t                  *value, size;
    njt_url_t                   u;
    njt_uint_t                  i, n, m;
    njt_mail_listen_t          *ls, *als, *nls;
    njt_mail_module_t          *module;
    njt_mail_core_main_conf_t  *cmcf;

    cscf->listen = 1;

    value = cf->args->elts;

    njt_memzero(&u, sizeof(njt_url_t));

    u.url = value[1];
    u.listen = 1;

    if (njt_parse_url(cf->pool, &u) != NJT_OK) {
        if (u.err) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "%s in \"%V\" of the \"listen\" directive",
                               u.err, &u.url);
        }

        return NJT_CONF_ERROR;
    }

    cmcf = njt_mail_conf_get_module_main_conf(cf, njt_mail_core_module);

    ls = njt_array_push(&cmcf->listen);
    if (ls == NULL) {
        return NJT_CONF_ERROR;
    }

    njt_memzero(ls, sizeof(njt_mail_listen_t));

    ls->backlog = NJT_LISTEN_BACKLOG;
    ls->rcvbuf = -1;
    ls->sndbuf = -1;
    ls->ctx = cf->ctx;

#if (NJT_HAVE_INET6)
    ls->ipv6only = 1;
#endif

    if (cscf->protocol == NULL) {
        for (m = 0; cf->cycle->modules[m]; m++) {
            if (cf->cycle->modules[m]->type != NJT_MAIL_MODULE) {
                continue;
            }

            module = cf->cycle->modules[m]->ctx;

            if (module->protocol == NULL) {
                continue;
            }

            for (i = 0; module->protocol->port[i]; i++) {
                if (module->protocol->port[i] == u.port) {
                    cscf->protocol = module->protocol;
                    break;
                }
            }
        }
    }

    for (i = 2; i < cf->args->nelts; i++) {

        if (njt_strcmp(value[i].data, "bind") == 0) {
            ls->bind = 1;
            continue;
        }

        if (njt_strncmp(value[i].data, "backlog=", 8) == 0) {
            ls->backlog = njt_atoi(value[i].data + 8, value[i].len - 8);
            ls->bind = 1;

            if (ls->backlog == NJT_ERROR || ls->backlog == 0) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid backlog \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "rcvbuf=", 7) == 0) {
            size.len = value[i].len - 7;
            size.data = value[i].data + 7;

            ls->rcvbuf = njt_parse_size(&size);
            ls->bind = 1;

            if (ls->rcvbuf == NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid rcvbuf \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "sndbuf=", 7) == 0) {
            size.len = value[i].len - 7;
            size.data = value[i].data + 7;

            ls->sndbuf = njt_parse_size(&size);
            ls->bind = 1;

            if (ls->sndbuf == NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid sndbuf \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "ipv6only=o", 10) == 0) {
#if (NJT_HAVE_INET6 && defined IPV6_V6ONLY)
            if (njt_strcmp(&value[i].data[10], "n") == 0) {
                ls->ipv6only = 1;

            } else if (njt_strcmp(&value[i].data[10], "ff") == 0) {
                ls->ipv6only = 0;

            } else {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid ipv6only flags \"%s\"",
                                   &value[i].data[9]);
                return NJT_CONF_ERROR;
            }

            ls->bind = 1;
            continue;
#else
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "bind ipv6only is not supported "
                               "on this platform");
            return NJT_CONF_ERROR;
#endif
        }

        if (njt_strcmp(value[i].data, "ssl") == 0) {
#if (NJT_MAIL_SSL)
            njt_mail_ssl_conf_t  *sslcf;

            sslcf = njt_mail_conf_get_module_srv_conf(cf, njt_mail_ssl_module);

            sslcf->listen = 1;
            sslcf->file = cf->conf_file->file.name.data;
            sslcf->line = cf->conf_file->line;

            ls->ssl = 1;

            continue;
#else
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "the \"ssl\" parameter requires "
                               "njt_mail_ssl_module");
            return NJT_CONF_ERROR;
#endif
        }

        if (njt_strncmp(value[i].data, "so_keepalive=", 13) == 0) {

            if (njt_strcmp(&value[i].data[13], "on") == 0) {
                ls->so_keepalive = 1;

            } else if (njt_strcmp(&value[i].data[13], "off") == 0) {
                ls->so_keepalive = 2;

            } else {

#if (NJT_HAVE_KEEPALIVE_TUNABLE)
                u_char     *p, *end;
                njt_str_t   s;

                end = value[i].data + value[i].len;
                s.data = value[i].data + 13;

                p = njt_strlchr(s.data, end, ':');
                if (p == NULL) {
                    p = end;
                }

                if (p > s.data) {
                    s.len = p - s.data;

                    ls->tcp_keepidle = njt_parse_time(&s, 1);
                    if (ls->tcp_keepidle == (time_t) NJT_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                p = njt_strlchr(s.data, end, ':');
                if (p == NULL) {
                    p = end;
                }

                if (p > s.data) {
                    s.len = p - s.data;

                    ls->tcp_keepintvl = njt_parse_time(&s, 1);
                    if (ls->tcp_keepintvl == (time_t) NJT_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                if (s.data < end) {
                    s.len = end - s.data;

                    ls->tcp_keepcnt = njt_atoi(s.data, s.len);
                    if (ls->tcp_keepcnt == NJT_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                if (ls->tcp_keepidle == 0 && ls->tcp_keepintvl == 0
                    && ls->tcp_keepcnt == 0)
                {
                    goto invalid_so_keepalive;
                }

                ls->so_keepalive = 1;

#else

                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "the \"so_keepalive\" parameter accepts "
                                   "only \"on\" or \"off\" on this platform");
                return NJT_CONF_ERROR;

#endif
            }

            ls->bind = 1;

            continue;

#if (NJT_HAVE_KEEPALIVE_TUNABLE)
        invalid_so_keepalive:

            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid so_keepalive value: \"%s\"",
                               &value[i].data[13]);
            return NJT_CONF_ERROR;
#endif
        }

        if (njt_strcmp(value[i].data, "proxy_protocol") == 0) {
            ls->proxy_protocol = 1;
            continue;
        }

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "the invalid \"%V\" parameter", &value[i]);
        return NJT_CONF_ERROR;
    }

    for (n = 0; n < u.naddrs; n++) {

        for (i = 0; i < n; i++) {
            if (njt_cmp_sockaddr(u.addrs[n].sockaddr, u.addrs[n].socklen,
                                 u.addrs[i].sockaddr, u.addrs[i].socklen, 1)
                == NJT_OK)
            {
                goto next;
            }
        }

        if (n != 0) {
            nls = njt_array_push(&cmcf->listen);
            if (nls == NULL) {
                return NJT_CONF_ERROR;
            }

            *nls = *ls;

        } else {
            nls = ls;
        }

        nls->sockaddr = u.addrs[n].sockaddr;
        nls->socklen = u.addrs[n].socklen;
        nls->addr_text = u.addrs[n].name;
        nls->wildcard = njt_inet_wildcard(nls->sockaddr);

        als = cmcf->listen.elts;

        for (i = 0; i < cmcf->listen.nelts - 1; i++) {

            if (njt_cmp_sockaddr(als[i].sockaddr, als[i].socklen,
                                 nls->sockaddr, nls->socklen, 1)
                != NJT_OK)
            {
                continue;
            }

            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "duplicate \"%V\" address and port pair",
                               &nls->addr_text);
            return NJT_CONF_ERROR;
        }

    next:
        continue;
    }

    return NJT_CONF_OK;
}


static char *
njt_mail_core_protocol(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_mail_core_srv_conf_t  *cscf = conf;

    njt_str_t          *value;
    njt_uint_t          m;
    njt_mail_module_t  *module;

    value = cf->args->elts;

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NJT_MAIL_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->protocol
            && njt_strcmp(module->protocol->name.data, value[1].data) == 0)
        {
            cscf->protocol = module->protocol;

            return NJT_CONF_OK;
        }
    }

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "unknown protocol \"%V\"", &value[1]);
    return NJT_CONF_ERROR;
}


static char *
njt_mail_core_error_log(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_mail_core_srv_conf_t  *cscf = conf;

    return njt_log_set_log(cf, &cscf->error_log);
}


static char *
njt_mail_core_resolver(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_mail_core_srv_conf_t  *cscf = conf;

    njt_str_t  *value;

    value = cf->args->elts;

    if (cscf->resolver != NJT_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    if (njt_strcmp(value[1].data, "off") == 0) {
        cscf->resolver = NULL;
        return NJT_CONF_OK;
    }

    cscf->resolver = njt_resolver_create(cf, &value[1], cf->args->nelts - 1);
    if (cscf->resolver == NULL) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


char *
njt_mail_capabilities(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    njt_str_t    *c, *value;
    njt_uint_t    i;
    njt_array_t  *a;

    a = (njt_array_t *) (p + cmd->offset);

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        c = njt_array_push(a);
        if (c == NULL) {
            return NJT_CONF_ERROR;
        }

        *c = value[i];
    }

    return NJT_CONF_OK;
}
