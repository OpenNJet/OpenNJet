
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>


static njt_int_t njt_stream_upstream_add_variables(njt_conf_t *cf);
static njt_int_t njt_stream_upstream_addr_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_upstream_response_time_variable(
    njt_stream_session_t *s, njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_upstream_bytes_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);

static char *njt_stream_upstream(njt_conf_t *cf, njt_command_t *cmd,
    void *dummy);
//static char *njt_stream_upstream_server(njt_conf_t *cf, njt_command_t *cmd,
//    void *conf);
static void *njt_stream_upstream_create_main_conf(njt_conf_t *cf);
static char *njt_stream_upstream_init_main_conf(njt_conf_t *cf, void *conf);


static njt_command_t  njt_stream_upstream_commands[] = {

    { njt_string("upstream"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_BLOCK|NJT_CONF_TAKE1,
      njt_stream_upstream,
      0,
      0,
      NULL },
/* by zyg  add njt_stream_upstream_dynamic_servers.c
    { njt_string("server"),
      NJT_STREAM_UPS_CONF|NJT_CONF_1MORE,
      njt_stream_upstream_server,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },
*/
      njt_null_command
};


static njt_stream_module_t  njt_stream_upstream_module_ctx = {
    njt_stream_upstream_add_variables,     /* preconfiguration */
    NULL,                                  /* postconfiguration */

    njt_stream_upstream_create_main_conf,  /* create main configuration */
    njt_stream_upstream_init_main_conf,    /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL                                   /* merge server configuration */
};


njt_module_t  njt_stream_upstream_module = {
    NJT_MODULE_V1,
    &njt_stream_upstream_module_ctx,       /* module context */
    njt_stream_upstream_commands,          /* module directives */
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


static njt_stream_variable_t  njt_stream_upstream_vars[] = {

    { njt_string("upstream_addr"), NULL,
      njt_stream_upstream_addr_variable, 0,
      NJT_STREAM_VAR_NOCACHEABLE, 0 },

    { njt_string("upstream_bytes_sent"), NULL,
      njt_stream_upstream_bytes_variable, 0,
      NJT_STREAM_VAR_NOCACHEABLE, 0 },

    { njt_string("upstream_connect_time"), NULL,
      njt_stream_upstream_response_time_variable, 2,
      NJT_STREAM_VAR_NOCACHEABLE, 0 },

    { njt_string("upstream_first_byte_time"), NULL,
      njt_stream_upstream_response_time_variable, 1,
      NJT_STREAM_VAR_NOCACHEABLE, 0 },

    { njt_string("upstream_session_time"), NULL,
      njt_stream_upstream_response_time_variable, 0,
      NJT_STREAM_VAR_NOCACHEABLE, 0 },

    { njt_string("upstream_bytes_received"), NULL,
      njt_stream_upstream_bytes_variable, 1,
      NJT_STREAM_VAR_NOCACHEABLE, 0 },

      njt_stream_null_variable
};


static njt_int_t
njt_stream_upstream_add_variables(njt_conf_t *cf)
{
    njt_stream_variable_t  *var, *v;

    for (v = njt_stream_upstream_vars; v->name.len; v++) {
        var = njt_stream_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NJT_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NJT_OK;
}


static njt_int_t
njt_stream_upstream_addr_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    u_char                       *p;
    size_t                        len;
    njt_uint_t                    i;
    njt_stream_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (s->upstream_states == NULL || s->upstream_states->nelts == 0) {
        v->not_found = 1;
        return NJT_OK;
    }

    len = 0;
    state = s->upstream_states->elts;

    for (i = 0; i < s->upstream_states->nelts; i++) {
        if (state[i].peer) {
            len += state[i].peer->len;
        }

        len += 2;
    }

    p = njt_pnalloc(s->connection->pool, len);
    if (p == NULL) {
        return NJT_ERROR;
    }

    v->data = p;

    i = 0;

    for ( ;; ) {
        if (state[i].peer) {
            p = njt_cpymem(p, state[i].peer->data, state[i].peer->len);
        }

        if (++i == s->upstream_states->nelts) {
            break;
        }

        *p++ = ',';
        *p++ = ' ';
    }

    v->len = p - v->data;

    return NJT_OK;
}


static njt_int_t
njt_stream_upstream_bytes_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    u_char                       *p;
    size_t                        len;
    njt_uint_t                    i;
    njt_stream_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (s->upstream_states == NULL || s->upstream_states->nelts == 0) {
        v->not_found = 1;
        return NJT_OK;
    }

    len = s->upstream_states->nelts * (NJT_OFF_T_LEN + 2);

    p = njt_pnalloc(s->connection->pool, len);
    if (p == NULL) {
        return NJT_ERROR;
    }

    v->data = p;

    i = 0;
    state = s->upstream_states->elts;

    for ( ;; ) {

        if (data == 1) {
            p = njt_sprintf(p, "%O", state[i].bytes_received);

        } else {
            p = njt_sprintf(p, "%O", state[i].bytes_sent);
        }

        if (++i == s->upstream_states->nelts) {
            break;
        }

        *p++ = ',';
        *p++ = ' ';
    }

    v->len = p - v->data;

    return NJT_OK;
}


static njt_int_t
njt_stream_upstream_response_time_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    u_char                       *p;
    size_t                        len;
    njt_uint_t                    i;
    njt_msec_int_t                ms;
    njt_stream_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (s->upstream_states == NULL || s->upstream_states->nelts == 0) {
        v->not_found = 1;
        return NJT_OK;
    }

    len = s->upstream_states->nelts * (NJT_TIME_T_LEN + 4 + 2);

    p = njt_pnalloc(s->connection->pool, len);
    if (p == NULL) {
        return NJT_ERROR;
    }

    v->data = p;

    i = 0;
    state = s->upstream_states->elts;

    for ( ;; ) {

        if (data == 1) {
            ms = state[i].first_byte_time;

        } else if (data == 2) {
            ms = state[i].connect_time;

        } else {
            ms = state[i].response_time;
        }

        if (ms != -1) {
            ms = njt_max(ms, 0);
            p = njt_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000);

        } else {
            *p++ = '-';
        }

        if (++i == s->upstream_states->nelts) {
            break;
        }

        *p++ = ',';
        *p++ = ' ';
    }

    v->len = p - v->data;

    return NJT_OK;
}


static char *
njt_stream_upstream(njt_conf_t *cf, njt_command_t *cmd, void *dummy)
{
    char                            *rv;
    void                            *mconf;
    njt_str_t                       *value;
    njt_url_t                        u;
    njt_uint_t                       m;
    njt_conf_t                       pcf;
    njt_stream_module_t             *module;
    njt_stream_conf_ctx_t           *ctx, *stream_ctx;
    njt_stream_upstream_srv_conf_t  *uscf;

    njt_memzero(&u, sizeof(njt_url_t));

    value = cf->args->elts;
    u.host = value[1];
    u.no_resolve = 1;
    u.no_port = 1;

    uscf = njt_stream_upstream_add(cf, &u, NJT_STREAM_UPSTREAM_CREATE
                                           |NJT_STREAM_UPSTREAM_WEIGHT
                                           |NJT_STREAM_UPSTREAM_MAX_CONNS
                                           |NJT_STREAM_UPSTREAM_MAX_FAILS
                                           |NJT_STREAM_UPSTREAM_FAIL_TIMEOUT
                                           |NJT_STREAM_UPSTREAM_DOWN
                                           |NJT_STREAM_UPSTREAM_BACKUP
					   |NJT_STREAM_UPSTREAM_SLOW_START);
    if (uscf == NULL) {
        return NJT_CONF_ERROR;
    }


    ctx = njt_pcalloc(cf->pool, sizeof(njt_stream_conf_ctx_t));
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }

    stream_ctx = cf->ctx;
    ctx->main_conf = stream_ctx->main_conf;

    /* the upstream{}'s srv_conf */

    ctx->srv_conf = njt_pcalloc(cf->pool,
                                sizeof(void *) * njt_stream_max_module);
    if (ctx->srv_conf == NULL) {
        return NJT_CONF_ERROR;
    }

    ctx->srv_conf[njt_stream_upstream_module.ctx_index] = uscf;

    uscf->srv_conf = ctx->srv_conf;

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

    uscf->servers = njt_array_create(cf->pool, 4,
                                     sizeof(njt_stream_upstream_server_t));
    if (uscf->servers == NULL) {
        return NJT_CONF_ERROR;
    }


    /* parse inside upstream{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NJT_STREAM_UPS_CONF;

    rv = njt_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv != NJT_CONF_OK) {
        return rv;
    }
    /*
    if (uscf->servers->nelts == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "no servers are inside upstream");
        return NJT_CONF_ERROR;
    }*/

    return rv;
}

/*
static char *
njt_stream_upstream_server(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_upstream_srv_conf_t  *uscf = conf;

    time_t                         fail_timeout;
    njt_str_t                     *value, s;
    njt_url_t                      u;
    njt_int_t                      weight, max_conns, max_fails;
    njt_uint_t                     i;
    njt_stream_upstream_server_t  *us;

    us = njt_array_push(uscf->servers);
    if (us == NULL) {
        return NJT_CONF_ERROR;
    }

    njt_memzero(us, sizeof(njt_stream_upstream_server_t));

    value = cf->args->elts;

    weight = 1;
    max_conns = 0;
    max_fails = 1;
    fail_timeout = 10;

    for (i = 2; i < cf->args->nelts; i++) {

        if (njt_strncmp(value[i].data, "weight=", 7) == 0) {

            if (!(uscf->flags & NJT_STREAM_UPSTREAM_WEIGHT)) {
                goto not_supported;
            }

            weight = njt_atoi(&value[i].data[7], value[i].len - 7);

            if (weight == NJT_ERROR || weight == 0) {
                goto invalid;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "max_conns=", 10) == 0) {

            if (!(uscf->flags & NJT_STREAM_UPSTREAM_MAX_CONNS)) {
                goto not_supported;
            }

            max_conns = njt_atoi(&value[i].data[10], value[i].len - 10);

            if (max_conns == NJT_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "max_fails=", 10) == 0) {

            if (!(uscf->flags & NJT_STREAM_UPSTREAM_MAX_FAILS)) {
                goto not_supported;
            }

            max_fails = njt_atoi(&value[i].data[10], value[i].len - 10);

            if (max_fails == NJT_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "fail_timeout=", 13) == 0) {

            if (!(uscf->flags & NJT_STREAM_UPSTREAM_FAIL_TIMEOUT)) {
                goto not_supported;
            }

            s.len = value[i].len - 13;
            s.data = &value[i].data[13];

            fail_timeout = njt_parse_time(&s, 1);

            if (fail_timeout == (time_t) NJT_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (njt_strcmp(value[i].data, "backup") == 0) {

            if (!(uscf->flags & NJT_STREAM_UPSTREAM_BACKUP)) {
                goto not_supported;
            }

            us->backup = 1;

            continue;
        }

        if (njt_strcmp(value[i].data, "down") == 0) {

            if (!(uscf->flags & NJT_STREAM_UPSTREAM_DOWN)) {
                goto not_supported;
            }

            us->down = 1;

            continue;
        }

        goto invalid;
    }

    njt_memzero(&u, sizeof(njt_url_t));

    u.url = value[1];

    if (njt_parse_url(cf->pool, &u) != NJT_OK) {
        if (u.err) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "%s in upstream \"%V\"", u.err, &u.url);
        }

        return NJT_CONF_ERROR;
    }

    if (u.no_port) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "no port in upstream \"%V\"", &u.url);
        return NJT_CONF_ERROR;
    }

    us->name = u.url;
    us->addrs = u.addrs;
    us->naddrs = u.naddrs;
    us->weight = weight;
    us->max_conns = max_conns;
    us->max_fails = max_fails;
    us->fail_timeout = fail_timeout;

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
}*/


njt_stream_upstream_srv_conf_t *
njt_stream_upstream_add(njt_conf_t *cf, njt_url_t *u, njt_uint_t flags)
{
    njt_uint_t                        i;
    njt_stream_upstream_server_t     *us;
    njt_stream_upstream_srv_conf_t   *uscf, **uscfp;
    njt_stream_upstream_main_conf_t  *umcf;

    if (!(flags & NJT_STREAM_UPSTREAM_CREATE)) {

        if (njt_parse_url(cf->pool, u) != NJT_OK) {
            if (u->err) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "%s in upstream \"%V\"", u->err, &u->url);
            }

            return NULL;
        }
    }

    umcf = njt_stream_conf_get_module_main_conf(cf, njt_stream_upstream_module);

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        if (uscfp[i]->host.len != u->host.len
            || njt_strncasecmp(uscfp[i]->host.data, u->host.data, u->host.len)
               != 0)
        {
            continue;
        }

        if ((flags & NJT_STREAM_UPSTREAM_CREATE)
             && (uscfp[i]->flags & NJT_STREAM_UPSTREAM_CREATE))
        {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "duplicate upstream \"%V\"", &u->host);
            return NULL;
        }

        if ((uscfp[i]->flags & NJT_STREAM_UPSTREAM_CREATE) && !u->no_port) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "upstream \"%V\" may not have port %d",
                               &u->host, u->port);
            return NULL;
        }

        if ((flags & NJT_STREAM_UPSTREAM_CREATE) && !uscfp[i]->no_port) {
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "upstream \"%V\" may not have port %d in %s:%ui",
                          &u->host, uscfp[i]->port,
                          uscfp[i]->file_name, uscfp[i]->line);
            return NULL;
        }

        if (uscfp[i]->port != u->port) {
            continue;
        }

        if (flags & NJT_STREAM_UPSTREAM_CREATE) {
            uscfp[i]->flags = flags;
        }

        return uscfp[i];
    }

    uscf = njt_pcalloc(cf->pool, sizeof(njt_stream_upstream_srv_conf_t));
    if (uscf == NULL) {
        return NULL;
    }

    uscf->flags = flags;
    uscf->host = u->host;
    uscf->file_name = cf->conf_file->file.name.data;
    uscf->line = cf->conf_file->line;
    uscf->port = u->port;
    uscf->no_port = u->no_port;

    if (u->naddrs == 1 && (u->port || u->family == AF_UNIX)) {
        uscf->servers = njt_array_create(cf->pool, 1,
                                         sizeof(njt_stream_upstream_server_t));
        if (uscf->servers == NULL) {
            return NULL;
        }

        us = njt_array_push(uscf->servers);
        if (us == NULL) {
            return NULL;
        }

        njt_memzero(us, sizeof(njt_stream_upstream_server_t));

        us->addrs = u->addrs;
        us->naddrs = 1;
    }

    uscfp = njt_array_push(&umcf->upstreams);
    if (uscfp == NULL) {
        return NULL;
    }

    *uscfp = uscf;

    return uscf;
}


static void *
njt_stream_upstream_create_main_conf(njt_conf_t *cf)
{
    njt_stream_upstream_main_conf_t  *umcf;

    umcf = njt_pcalloc(cf->pool, sizeof(njt_stream_upstream_main_conf_t));
    if (umcf == NULL) {
        return NULL;
    }

    if (njt_array_init(&umcf->upstreams, cf->pool, 4,
                       sizeof(njt_stream_upstream_srv_conf_t *))
        != NJT_OK)
    {
        return NULL;
    }

    return umcf;
}


static char *
njt_stream_upstream_init_main_conf(njt_conf_t *cf, void *conf)
{
    njt_stream_upstream_main_conf_t *umcf = conf;

    njt_uint_t                        i;
    njt_stream_upstream_init_pt       init;
    njt_stream_upstream_srv_conf_t  **uscfp;

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        init = uscfp[i]->peer.init_upstream
                                         ? uscfp[i]->peer.init_upstream
                                         : njt_stream_upstream_init_round_robin;

        if (init(cf, uscfp[i]) != NJT_OK) {
            return NJT_CONF_ERROR;
        }
    }

    return NJT_CONF_OK;
}
