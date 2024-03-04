
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>


static njt_int_t njt_stream_core_preconfiguration(njt_conf_t *cf);
static void *njt_stream_core_create_main_conf(njt_conf_t *cf);
static char *njt_stream_core_init_main_conf(njt_conf_t *cf, void *conf);
static void *njt_stream_core_create_srv_conf(njt_conf_t *cf);
static char *njt_stream_core_merge_srv_conf(njt_conf_t *cf, void *parent,
    void *child);
static char *njt_stream_core_error_log(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_stream_core_server(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_stream_core_listen(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_stream_core_resolver(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);


static njt_command_t  njt_stream_core_commands[] = {

    { njt_string("variables_hash_max_size"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_STREAM_MAIN_CONF_OFFSET,
      offsetof(njt_stream_core_main_conf_t, variables_hash_max_size),
      NULL },

    { njt_string("variables_hash_bucket_size"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_STREAM_MAIN_CONF_OFFSET,
      offsetof(njt_stream_core_main_conf_t, variables_hash_bucket_size),
      NULL },

    { njt_string("server"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_BLOCK|NJT_CONF_NOARGS,
      njt_stream_core_server,
      0,
      0,
      NULL },

    { njt_string("listen"),
      NJT_STREAM_SRV_CONF|NJT_CONF_1MORE,
      njt_stream_core_listen,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("error_log"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_1MORE,
      njt_stream_core_error_log,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("resolver"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_1MORE,
      njt_stream_core_resolver,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("resolver_timeout"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_core_srv_conf_t, resolver_timeout),
      NULL },

    { njt_string("proxy_protocol_timeout"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_core_srv_conf_t, proxy_protocol_timeout),
      NULL },

    { njt_string("tcp_nodelay"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_core_srv_conf_t, tcp_nodelay),
      NULL },

    { njt_string("preread_buffer_size"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_core_srv_conf_t, preread_buffer_size),
      NULL },

    { njt_string("preread_timeout"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_core_srv_conf_t, preread_timeout),
      NULL },

      njt_null_command
};


static njt_stream_module_t  njt_stream_core_module_ctx = {
    njt_stream_core_preconfiguration,      /* preconfiguration */
    NULL,                                  /* postconfiguration */

    njt_stream_core_create_main_conf,      /* create main configuration */
    njt_stream_core_init_main_conf,        /* init main configuration */

    njt_stream_core_create_srv_conf,       /* create server configuration */
    njt_stream_core_merge_srv_conf         /* merge server configuration */
};


njt_module_t  njt_stream_core_module = {
    NJT_MODULE_V1,
    &njt_stream_core_module_ctx,           /* module context */
    njt_stream_core_commands,              /* module directives */
    NJT_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


void
njt_stream_core_run_phases(njt_stream_session_t *s)
{
    njt_int_t                     rc;
    njt_stream_phase_handler_t   *ph;
    njt_stream_core_main_conf_t  *cmcf;

    cmcf = njt_stream_get_module_main_conf(s, njt_stream_core_module);

    ph = cmcf->phase_engine.handlers;

    while (ph[s->phase_handler].checker) {

        rc = ph[s->phase_handler].checker(s, &ph[s->phase_handler]);

        if (rc == NJT_OK) {
            return;
        }
    }
}


njt_int_t
njt_stream_core_generic_phase(njt_stream_session_t *s,
    njt_stream_phase_handler_t *ph)
{
    njt_int_t  rc;

    /*
     * generic phase checker,
     * used by all phases, except for preread and content
     */

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "generic phase: %ui", s->phase_handler);

    rc = ph->handler(s);

    if (rc == NJT_OK) {
        s->phase_handler = ph->next;
        return NJT_AGAIN;
    }

    if (rc == NJT_DECLINED) {
        s->phase_handler++;
        return NJT_AGAIN;
    }

    if (rc == NJT_AGAIN || rc == NJT_DONE) {
        return NJT_OK;
    }

    if (rc == NJT_ERROR) {
        rc = NJT_STREAM_INTERNAL_SERVER_ERROR;
    }

    njt_stream_finalize_session(s, rc);

    return NJT_OK;
}


njt_int_t
njt_stream_core_preread_phase(njt_stream_session_t *s,
    njt_stream_phase_handler_t *ph)
{
    size_t                       size;
    ssize_t                      n;
    njt_int_t                    rc;
    njt_connection_t            *c;
    njt_stream_core_srv_conf_t  *cscf;

    c = s->connection;

    c->log->action = "prereading client data";

    cscf = njt_stream_get_module_srv_conf(s, njt_stream_core_module);

    if (c->read->timedout) {
        rc = NJT_STREAM_OK;

    } else if (c->read->timer_set) {
        rc = NJT_AGAIN;

    } else {
        rc = ph->handler(s);
    }

    while (rc == NJT_AGAIN) {

        if (c->buffer == NULL) {
            c->buffer = njt_create_temp_buf(c->pool, cscf->preread_buffer_size);
            if (c->buffer == NULL) {
                rc = NJT_ERROR;
                break;
            }
        }

        size = c->buffer->end - c->buffer->last;

        if (size == 0) {
            njt_log_error(NJT_LOG_ERR, c->log, 0, "preread buffer full");
            rc = NJT_STREAM_BAD_REQUEST;
            break;
        }

        if (c->read->eof) {
            rc = NJT_STREAM_OK;
            break;
        }

        if (!c->read->ready) {
            break;
        }

        n = c->recv(c, c->buffer->last, size);

        if (n == NJT_ERROR || n == 0) {
            rc = NJT_STREAM_OK;
            break;
        }

        if (n == NJT_AGAIN) {
            break;
        }

        c->buffer->last += n;

        rc = ph->handler(s);
    }

    if (rc == NJT_AGAIN) {
        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            njt_stream_finalize_session(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return NJT_OK;
        }

        if (!c->read->timer_set) {
            njt_add_timer(c->read, cscf->preread_timeout);
        }

        c->read->handler = njt_stream_session_handler;

        return NJT_OK;
    }

    if (c->read->timer_set) {
        njt_del_timer(c->read);
    }

    if (rc == NJT_OK) {
        s->phase_handler = ph->next;
        return NJT_AGAIN;
    }

    if (rc == NJT_DECLINED) {
        s->phase_handler++;
        return NJT_AGAIN;
    }

    if (rc == NJT_DONE) {
        return NJT_OK;
    }

    if (rc == NJT_ERROR) {
        rc = NJT_STREAM_INTERNAL_SERVER_ERROR;
    }

    njt_stream_finalize_session(s, rc);

    return NJT_OK;
}


njt_int_t
njt_stream_core_content_phase(njt_stream_session_t *s,
    njt_stream_phase_handler_t *ph)
{
    njt_connection_t            *c;
    njt_stream_core_srv_conf_t  *cscf;

    c = s->connection;

    c->log->action = NULL;

    cscf = njt_stream_get_module_srv_conf(s, njt_stream_core_module);

    if (c->type == SOCK_STREAM
        && cscf->tcp_nodelay
        && njt_tcp_nodelay(c) != NJT_OK)
    {
        njt_stream_finalize_session(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return NJT_OK;
    }

    cscf->handler(s);

    return NJT_OK;
}


static njt_int_t
njt_stream_core_preconfiguration(njt_conf_t *cf)
{
    return njt_stream_variables_add_core_vars(cf);
}


static void *
njt_stream_core_create_main_conf(njt_conf_t *cf)
{
    njt_stream_core_main_conf_t  *cmcf;

    cmcf = njt_pcalloc(cf->pool, sizeof(njt_stream_core_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }

    if (njt_array_init(&cmcf->servers, cf->pool, 4,
                       sizeof(njt_stream_core_srv_conf_t *))
        != NJT_OK)
    {
        return NULL;
    }

    if (njt_array_init(&cmcf->listen, cf->pool, 4, sizeof(njt_stream_listen_t))
        != NJT_OK)
    {
        return NULL;
    }

    cmcf->variables_hash_max_size = NJT_CONF_UNSET_UINT;
    cmcf->variables_hash_bucket_size = NJT_CONF_UNSET_UINT;

    return cmcf;
}


static char *
njt_stream_core_init_main_conf(njt_conf_t *cf, void *conf)
{
    njt_stream_core_main_conf_t *cmcf = conf;

    njt_conf_init_uint_value(cmcf->variables_hash_max_size, 1024);
    njt_conf_init_uint_value(cmcf->variables_hash_bucket_size, 64);

    cmcf->variables_hash_bucket_size =
               njt_align(cmcf->variables_hash_bucket_size, njt_cacheline_size);

    if (cmcf->ncaptures) {
        cmcf->ncaptures = (cmcf->ncaptures + 1) * 3;
    }

    return NJT_CONF_OK;
}


static void *
njt_stream_core_create_srv_conf(njt_conf_t *cf)
{
    njt_stream_core_srv_conf_t  *cscf;

    cscf = njt_pcalloc(cf->pool, sizeof(njt_stream_core_srv_conf_t));
    if (cscf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     cscf->handler = NULL;
     *     cscf->error_log = NULL;
     */

    cscf->file_name = cf->conf_file->file.name.data;
    cscf->line = cf->conf_file->line;
    cscf->resolver_timeout = NJT_CONF_UNSET_MSEC;
    cscf->proxy_protocol_timeout = NJT_CONF_UNSET_MSEC;
    cscf->tcp_nodelay = NJT_CONF_UNSET;
    cscf->preread_buffer_size = NJT_CONF_UNSET_SIZE;
    cscf->preread_timeout = NJT_CONF_UNSET_MSEC;

    return cscf;
}


static char *
njt_stream_core_merge_srv_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_stream_core_srv_conf_t *prev = parent;
    njt_stream_core_srv_conf_t *conf = child;

    njt_conf_merge_msec_value(conf->resolver_timeout,
                              prev->resolver_timeout, 30000);

    if (conf->resolver == NULL) {

        if (prev->resolver == NULL) {

            /*
             * create dummy resolver in stream {} context
             * to inherit it in all servers
             */

            prev->resolver = njt_resolver_create(cf, NULL, 0);
            if (prev->resolver == NULL) {
                return NJT_CONF_ERROR;
            }
        }

        conf->resolver = prev->resolver;
    }

    if (conf->handler == NULL) {
        njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                      "no handler for server in %s:%ui",
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

    njt_conf_merge_msec_value(conf->proxy_protocol_timeout,
                              prev->proxy_protocol_timeout, 30000);

    njt_conf_merge_value(conf->tcp_nodelay, prev->tcp_nodelay, 1);

    njt_conf_merge_size_value(conf->preread_buffer_size,
                              prev->preread_buffer_size, 16384);

    njt_conf_merge_msec_value(conf->preread_timeout,
                              prev->preread_timeout, 30000);

    return NJT_CONF_OK;
}


static char *
njt_stream_core_error_log(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_core_srv_conf_t  *cscf = conf;

    return njt_log_set_log(cf, &cscf->error_log);
}


static char *
njt_stream_core_server(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char                         *rv;
    void                         *mconf;
    njt_uint_t                    m;
    njt_conf_t                    pcf;
    njt_stream_module_t          *module;
    njt_stream_conf_ctx_t        *ctx, *stream_ctx;
    njt_stream_core_srv_conf_t   *cscf, **cscfp;
    njt_stream_core_main_conf_t  *cmcf;

    ctx = njt_pcalloc(cf->pool, sizeof(njt_stream_conf_ctx_t));
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }

    stream_ctx = cf->ctx;
    ctx->main_conf = stream_ctx->main_conf;

    /* the server{}'s srv_conf */

    ctx->srv_conf = njt_pcalloc(cf->pool,
                                sizeof(void *) * njt_stream_max_module);
    if (ctx->srv_conf == NULL) {
        return NJT_CONF_ERROR;
    }

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NJT_STREAM_MODULE) {
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

    cscf = ctx->srv_conf[njt_stream_core_module.ctx_index];
    cscf->ctx = ctx;

    cmcf = ctx->main_conf[njt_stream_core_module.ctx_index];

    cscfp = njt_array_push(&cmcf->servers);
    if (cscfp == NULL) {
        return NJT_CONF_ERROR;
    }

    *cscfp = cscf;


    /* parse inside server{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NJT_STREAM_SRV_CONF;

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
njt_stream_core_listen(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_core_srv_conf_t  *cscf = conf;

    njt_str_t                    *value, size;
    njt_url_t                     u;
    njt_uint_t                    i, n, backlog;
    njt_stream_listen_t          *ls, *als, *nls;
    njt_stream_core_main_conf_t  *cmcf;

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

    cmcf = njt_stream_conf_get_module_main_conf(cf, njt_stream_core_module);

    ls = njt_array_push(&cmcf->listen);
    if (ls == NULL) {
        return NJT_CONF_ERROR;
    }

    njt_memzero(ls, sizeof(njt_stream_listen_t));

    ls->backlog = NJT_LISTEN_BACKLOG;
    ls->rcvbuf = -1;
    ls->sndbuf = -1;
    ls->type = SOCK_STREAM;
    ls->ctx = cf->ctx;

#if (NJT_HAVE_TCP_FASTOPEN)
    ls->fastopen = -1;
#endif

#if (NJT_HAVE_INET6)
    ls->ipv6only = 1;
#endif

    backlog = 0;

    for (i = 2; i < cf->args->nelts; i++) {

#if !(NJT_WIN32)
        if (njt_strcmp(value[i].data, "udp") == 0) {
            ls->type = SOCK_DGRAM;
            continue;
        }
#endif

        if (njt_strcmp(value[i].data, "bind") == 0) {
            ls->bind = 1;
            continue;
        }

        //add by clb, used for udp and tcp traffic hack
        if (njt_strcmp(value[i].data, "mesh") == 0) {
            ls->mesh = 1;
            continue;
        }
        //end add by clb

#if (NJT_HAVE_TCP_FASTOPEN)
        if (njt_strncmp(value[i].data, "fastopen=", 9) == 0) {
            ls->fastopen = njt_atoi(value[i].data + 9, value[i].len - 9);
            ls->bind = 1;

            if (ls->fastopen == NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid fastopen \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }
#endif

        if (njt_strncmp(value[i].data, "backlog=", 8) == 0) {
            ls->backlog = njt_atoi(value[i].data + 8, value[i].len - 8);
            ls->bind = 1;

            if (ls->backlog == NJT_ERROR || ls->backlog == 0) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid backlog \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            backlog = 1;

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

        if (njt_strcmp(value[i].data, "reuseport") == 0) {
#if (NJT_HAVE_REUSEPORT)
            ls->reuseport = 1;
            ls->bind = 1;
#else
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "reuseport is not supported "
                               "on this platform, ignored");
#endif
            continue;
        }

        if (njt_strcmp(value[i].data, "ssl") == 0) {
#if (NJT_STREAM_SSL)
            njt_stream_ssl_conf_t  *sslcf;

            sslcf = njt_stream_conf_get_module_srv_conf(cf,
                                                        njt_stream_ssl_module);

            sslcf->listen = 1;
            sslcf->file = cf->conf_file->file.name.data;
            sslcf->line = cf->conf_file->line;

            ls->ssl = 1;

            continue;
#else
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "the \"ssl\" parameter requires "
                               "njt_stream_ssl_module");
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

    if (ls->type == SOCK_DGRAM) {
        if (backlog) {
            return "\"backlog\" parameter is incompatible with \"udp\"";
        }

#if (NJT_STREAM_SSL)
        if (ls->ssl) {
            return "\"ssl\" parameter is incompatible with \"udp\"";
        }
#endif

        if (ls->so_keepalive) {
            return "\"so_keepalive\" parameter is incompatible with \"udp\"";
        }

        if (ls->proxy_protocol) {
            return "\"proxy_protocol\" parameter is incompatible with \"udp\"";
        }

#if (NJT_HAVE_TCP_FASTOPEN)
        if (ls->fastopen != -1) {
            return "\"fastopen\" parameter is incompatible with \"udp\"";
        }
#endif
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
            if (nls->type != als[i].type) {
                continue;
            }

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
njt_stream_core_resolver(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_core_srv_conf_t  *cscf = conf;

    njt_str_t  *value;

    if (cscf->resolver) {
        return "is duplicate";
    }

    value = cf->args->elts;

    cscf->resolver = njt_resolver_create(cf, &value[1], cf->args->nelts - 1);
    if (cscf->resolver == NULL) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}
