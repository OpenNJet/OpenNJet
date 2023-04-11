
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>


typedef struct {
    njt_array_t       *from;     /* array of njt_cidr_t */
} njt_stream_realip_srv_conf_t;


typedef struct {
    struct sockaddr   *sockaddr;
    socklen_t          socklen;
    njt_str_t          addr_text;
} njt_stream_realip_ctx_t;


static njt_int_t njt_stream_realip_handler(njt_stream_session_t *s);
static njt_int_t njt_stream_realip_set_addr(njt_stream_session_t *s,
    njt_addr_t *addr);
static char *njt_stream_realip_from(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static void *njt_stream_realip_create_srv_conf(njt_conf_t *cf);
static char *njt_stream_realip_merge_srv_conf(njt_conf_t *cf, void *parent,
    void *child);
static njt_int_t njt_stream_realip_add_variables(njt_conf_t *cf);
static njt_int_t njt_stream_realip_init(njt_conf_t *cf);


static njt_int_t njt_stream_realip_remote_addr_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_realip_remote_port_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);


static njt_command_t  njt_stream_realip_commands[] = {

    { njt_string("set_real_ip_from"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_stream_realip_from,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      njt_null_command
};


static njt_stream_module_t  njt_stream_realip_module_ctx = {
    njt_stream_realip_add_variables,       /* preconfiguration */
    njt_stream_realip_init,                /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    njt_stream_realip_create_srv_conf,     /* create server configuration */
    njt_stream_realip_merge_srv_conf       /* merge server configuration */
};


njt_module_t  njt_stream_realip_module = {
    NJT_MODULE_V1,
    &njt_stream_realip_module_ctx,         /* module context */
    njt_stream_realip_commands,            /* module directives */
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


static njt_stream_variable_t  njt_stream_realip_vars[] = {

    { njt_string("realip_remote_addr"), NULL,
      njt_stream_realip_remote_addr_variable, 0, 0, 0 },

    { njt_string("realip_remote_port"), NULL,
      njt_stream_realip_remote_port_variable, 0, 0, 0 },

      njt_stream_null_variable
};


static njt_int_t
njt_stream_realip_handler(njt_stream_session_t *s)
{
    njt_addr_t                     addr;
    njt_connection_t              *c;
    njt_stream_realip_srv_conf_t  *rscf;

    rscf = njt_stream_get_module_srv_conf(s, njt_stream_realip_module);

    if (rscf->from == NULL) {
        return NJT_DECLINED;
    }

    c = s->connection;

    if (c->proxy_protocol == NULL) {
        return NJT_DECLINED;
    }

    if (njt_cidr_match(c->sockaddr, rscf->from) != NJT_OK) {
        return NJT_DECLINED;
    }

    if (njt_parse_addr(c->pool, &addr, c->proxy_protocol->src_addr.data,
                       c->proxy_protocol->src_addr.len)
        != NJT_OK)
    {
        return NJT_DECLINED;
    }

    njt_inet_set_port(addr.sockaddr, c->proxy_protocol->src_port);

    return njt_stream_realip_set_addr(s, &addr);
}


static njt_int_t
njt_stream_realip_set_addr(njt_stream_session_t *s, njt_addr_t *addr)
{
    size_t                    len;
    u_char                   *p;
    u_char                    text[NJT_SOCKADDR_STRLEN];
    njt_connection_t         *c;
    njt_stream_realip_ctx_t  *ctx;

    c = s->connection;

    ctx = njt_palloc(c->pool, sizeof(njt_stream_realip_ctx_t));
    if (ctx == NULL) {
        return NJT_ERROR;
    }

    len = njt_sock_ntop(addr->sockaddr, addr->socklen, text,
                        NJT_SOCKADDR_STRLEN, 0);
    if (len == 0) {
        return NJT_ERROR;
    }

    p = njt_pnalloc(c->pool, len);
    if (p == NULL) {
        return NJT_ERROR;
    }

    njt_memcpy(p, text, len);

    njt_stream_set_ctx(s, ctx, njt_stream_realip_module);

    ctx->sockaddr = c->sockaddr;
    ctx->socklen = c->socklen;
    ctx->addr_text = c->addr_text;

    c->sockaddr = addr->sockaddr;
    c->socklen = addr->socklen;
    c->addr_text.len = len;
    c->addr_text.data = p;

    return NJT_DECLINED;
}


static char *
njt_stream_realip_from(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_realip_srv_conf_t *rscf = conf;

    njt_int_t             rc;
    njt_str_t            *value;
    njt_url_t             u;
    njt_cidr_t            c, *cidr;
    njt_uint_t            i;
    struct sockaddr_in   *sin;
#if (NJT_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    value = cf->args->elts;

    if (rscf->from == NULL) {
        rscf->from = njt_array_create(cf->pool, 2,
                                      sizeof(njt_cidr_t));
        if (rscf->from == NULL) {
            return NJT_CONF_ERROR;
        }
    }

#if (NJT_HAVE_UNIX_DOMAIN)

    if (njt_strcmp(value[1].data, "unix:") == 0) {
        cidr = njt_array_push(rscf->from);
        if (cidr == NULL) {
            return NJT_CONF_ERROR;
        }

        cidr->family = AF_UNIX;
        return NJT_CONF_OK;
    }

#endif

    rc = njt_ptocidr(&value[1], &c);

    if (rc != NJT_ERROR) {
        if (rc == NJT_DONE) {
            njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                               "low address bits of %V are meaningless",
                               &value[1]);
        }

        cidr = njt_array_push(rscf->from);
        if (cidr == NULL) {
            return NJT_CONF_ERROR;
        }

        *cidr = c;

        return NJT_CONF_OK;
    }

    njt_memzero(&u, sizeof(njt_url_t));
    u.host = value[1];

    if (njt_inet_resolve_host(cf->pool, &u) != NJT_OK) {
        if (u.err) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "%s in set_real_ip_from \"%V\"",
                               u.err, &u.host);
        }

        return NJT_CONF_ERROR;
    }

    cidr = njt_array_push_n(rscf->from, u.naddrs);
    if (cidr == NULL) {
        return NJT_CONF_ERROR;
    }

    njt_memzero(cidr, u.naddrs * sizeof(njt_cidr_t));

    for (i = 0; i < u.naddrs; i++) {
        cidr[i].family = u.addrs[i].sockaddr->sa_family;

        switch (cidr[i].family) {

#if (NJT_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) u.addrs[i].sockaddr;
            cidr[i].u.in6.addr = sin6->sin6_addr;
            njt_memset(cidr[i].u.in6.mask.s6_addr, 0xff, 16);
            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) u.addrs[i].sockaddr;
            cidr[i].u.in.addr = sin->sin_addr.s_addr;
            cidr[i].u.in.mask = 0xffffffff;
            break;
        }
    }

    return NJT_CONF_OK;
}


static void *
njt_stream_realip_create_srv_conf(njt_conf_t *cf)
{
    njt_stream_realip_srv_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_stream_realip_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->from = NULL;
     */

    return conf;
}


static char *
njt_stream_realip_merge_srv_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_stream_realip_srv_conf_t *prev = parent;
    njt_stream_realip_srv_conf_t *conf = child;

    if (conf->from == NULL) {
        conf->from = prev->from;
    }

    return NJT_CONF_OK;
}


static njt_int_t
njt_stream_realip_add_variables(njt_conf_t *cf)
{
    njt_stream_variable_t  *var, *v;

    for (v = njt_stream_realip_vars; v->name.len; v++) {
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
njt_stream_realip_init(njt_conf_t *cf)
{
    njt_stream_handler_pt        *h;
    njt_stream_core_main_conf_t  *cmcf;

    cmcf = njt_stream_conf_get_module_main_conf(cf, njt_stream_core_module);

    h = njt_array_push(&cmcf->phases[NJT_STREAM_POST_ACCEPT_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_stream_realip_handler;

    return NJT_OK;
}


static njt_int_t
njt_stream_realip_remote_addr_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    njt_str_t                *addr_text;
    njt_stream_realip_ctx_t  *ctx;

    ctx = njt_stream_get_module_ctx(s, njt_stream_realip_module);

    addr_text = ctx ? &ctx->addr_text : &s->connection->addr_text;

    v->len = addr_text->len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = addr_text->data;

    return NJT_OK;
}


static njt_int_t
njt_stream_realip_remote_port_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    njt_uint_t                port;
    struct sockaddr          *sa;
    njt_stream_realip_ctx_t  *ctx;

    ctx = njt_stream_get_module_ctx(s, njt_stream_realip_module);

    sa = ctx ? ctx->sockaddr : s->connection->sockaddr;

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = njt_pnalloc(s->connection->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return NJT_ERROR;
    }

    port = njt_inet_get_port(sa);

    if (port > 0 && port < 65536) {
        v->len = njt_sprintf(v->data, "%ui", port) - v->data;
    }

    return NJT_OK;
}
