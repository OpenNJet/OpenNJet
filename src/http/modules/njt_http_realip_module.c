
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


#define NJT_HTTP_REALIP_XREALIP  0
#define NJT_HTTP_REALIP_XFWD     1
#define NJT_HTTP_REALIP_HEADER   2
#define NJT_HTTP_REALIP_PROXY    3


typedef struct {
    njt_array_t       *from;     /* array of njt_cidr_t */
    njt_uint_t         type;
    njt_uint_t         hash;
    njt_str_t          header;
    njt_flag_t         recursive;
} njt_http_realip_loc_conf_t;


typedef struct {
    njt_connection_t  *connection;
    struct sockaddr   *sockaddr;
    socklen_t          socklen;
    njt_str_t          addr_text;
} njt_http_realip_ctx_t;


static njt_int_t njt_http_realip_handler(njt_http_request_t *r);
static njt_int_t njt_http_realip_set_addr(njt_http_request_t *r,
    njt_addr_t *addr);
static void njt_http_realip_cleanup(void *data);
static char *njt_http_realip_from(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_realip(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static void *njt_http_realip_create_loc_conf(njt_conf_t *cf);
static char *njt_http_realip_merge_loc_conf(njt_conf_t *cf,
    void *parent, void *child);
static njt_int_t njt_http_realip_add_variables(njt_conf_t *cf);
static njt_int_t njt_http_realip_init(njt_conf_t *cf);
static njt_http_realip_ctx_t *njt_http_realip_get_module_ctx(
    njt_http_request_t *r);


static njt_int_t njt_http_realip_remote_addr_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_realip_remote_port_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);


static njt_command_t  njt_http_realip_commands[] = {

    { njt_string("set_real_ip_from"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_realip_from,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("real_ip_header"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_realip,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("real_ip_recursive"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_realip_loc_conf_t, recursive),
      NULL },

      njt_null_command
};



static njt_http_module_t  njt_http_realip_module_ctx = {
    njt_http_realip_add_variables,         /* preconfiguration */
    njt_http_realip_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_realip_create_loc_conf,       /* create location configuration */
    njt_http_realip_merge_loc_conf         /* merge location configuration */
};


njt_module_t  njt_http_realip_module = {
    NJT_MODULE_V1,
    &njt_http_realip_module_ctx,           /* module context */
    njt_http_realip_commands,              /* module directives */
    NJT_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_http_variable_t  njt_http_realip_vars[] = {

    { njt_string("realip_remote_addr"), NULL,
      njt_http_realip_remote_addr_variable, 0, 0, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("realip_remote_port"), NULL,
      njt_http_realip_remote_port_variable, 0, 0, 0, NJT_VAR_INIT_REF_COUNT },

      njt_http_null_variable
};


static njt_int_t
njt_http_realip_handler(njt_http_request_t *r)
{
    u_char                      *p;
    size_t                       len;
    njt_str_t                   *value;
    njt_uint_t                   i, hash;
    njt_addr_t                   addr;
    njt_list_part_t             *part;
    njt_table_elt_t             *header, *xfwd;
    njt_connection_t            *c;
    njt_http_realip_ctx_t       *ctx;
    njt_http_realip_loc_conf_t  *rlcf;

    rlcf = njt_http_get_module_loc_conf(r, njt_http_realip_module);

    if (rlcf->from == NULL) {
        return NJT_DECLINED;
    }

    ctx = njt_http_realip_get_module_ctx(r);

    if (ctx) {
        return NJT_DECLINED;
    }

    switch (rlcf->type) {

    case NJT_HTTP_REALIP_XREALIP:

        if (r->headers_in.x_real_ip == NULL) {
            return NJT_DECLINED;
        }

        value = &r->headers_in.x_real_ip->value;
        xfwd = NULL;

        break;

    case NJT_HTTP_REALIP_XFWD:

        xfwd = r->headers_in.x_forwarded_for;

        if (xfwd == NULL) {
            return NJT_DECLINED;
        }

        value = NULL;

        break;

    case NJT_HTTP_REALIP_PROXY:

        if (r->connection->proxy_protocol == NULL) {
            return NJT_DECLINED;
        }

        value = &r->connection->proxy_protocol->src_addr;
        xfwd = NULL;

        break;

    default: /* NJT_HTTP_REALIP_HEADER */

        part = &r->headers_in.headers.part;
        header = part->elts;

        hash = rlcf->hash;
        len = rlcf->header.len;
        p = rlcf->header.data;

        for (i = 0; /* void */ ; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (hash == header[i].hash
                && len == header[i].key.len
                && njt_strncmp(p, header[i].lowcase_key, len) == 0)
            {
                value = &header[i].value;
                xfwd = NULL;

                goto found;
            }
        }

        return NJT_DECLINED;
    }

found:

    c = r->connection;

    addr.sockaddr = c->sockaddr;
    addr.socklen = c->socklen;
    /* addr.name = c->addr_text; */

    if (njt_http_get_forwarded_addr(r, &addr, xfwd, value, rlcf->from,
                                    rlcf->recursive)
        != NJT_DECLINED)
    {
        if (rlcf->type == NJT_HTTP_REALIP_PROXY) {
            njt_inet_set_port(addr.sockaddr, c->proxy_protocol->src_port);
        }

        return njt_http_realip_set_addr(r, &addr);
    }

    return NJT_DECLINED;
}


static njt_int_t
njt_http_realip_set_addr(njt_http_request_t *r, njt_addr_t *addr)
{
    size_t                  len;
    u_char                 *p;
    u_char                  text[NJT_SOCKADDR_STRLEN];
    njt_connection_t       *c;
    njt_pool_cleanup_t     *cln;
    njt_http_realip_ctx_t  *ctx;

    cln = njt_pool_cleanup_add(r->pool, sizeof(njt_http_realip_ctx_t));
    if (cln == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = cln->data;

    c = r->connection;

    len = njt_sock_ntop(addr->sockaddr, addr->socklen, text,
                        NJT_SOCKADDR_STRLEN, 0);
    if (len == 0) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = njt_pnalloc(c->pool, len);
    if (p == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    njt_memcpy(p, text, len);

    cln->handler = njt_http_realip_cleanup;
    njt_http_set_ctx(r, ctx, njt_http_realip_module);

    ctx->connection = c;
    ctx->sockaddr = c->sockaddr;
    ctx->socklen = c->socklen;
    ctx->addr_text = c->addr_text;

    c->sockaddr = addr->sockaddr;
    c->socklen = addr->socklen;
    c->addr_text.len = len;
    c->addr_text.data = p;

    return NJT_DECLINED;
}


static void
njt_http_realip_cleanup(void *data)
{
    njt_http_realip_ctx_t *ctx = data;

    njt_connection_t  *c;

    c = ctx->connection;

    c->sockaddr = ctx->sockaddr;
    c->socklen = ctx->socklen;
    c->addr_text = ctx->addr_text;
}


static char *
njt_http_realip_from(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_realip_loc_conf_t *rlcf = conf;

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

    if (rlcf->from == NULL) {
        rlcf->from = njt_array_create(cf->pool, 2,
                                      sizeof(njt_cidr_t));
        if (rlcf->from == NULL) {
            return NJT_CONF_ERROR;
        }
    }

#if (NJT_HAVE_UNIX_DOMAIN)

    if (njt_strcmp(value[1].data, "unix:") == 0) {
        cidr = njt_array_push(rlcf->from);
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

        cidr = njt_array_push(rlcf->from);
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

    cidr = njt_array_push_n(rlcf->from, u.naddrs);
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


static char *
njt_http_realip(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_realip_loc_conf_t *rlcf = conf;

    njt_str_t  *value;

    if (rlcf->type != NJT_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (njt_strcmp(value[1].data, "X-Real-IP") == 0) {
        rlcf->type = NJT_HTTP_REALIP_XREALIP;
        return NJT_CONF_OK;
    }

    if (njt_strcmp(value[1].data, "X-Forwarded-For") == 0) {
        rlcf->type = NJT_HTTP_REALIP_XFWD;
        return NJT_CONF_OK;
    }

    if (njt_strcmp(value[1].data, "proxy_protocol") == 0) {
        rlcf->type = NJT_HTTP_REALIP_PROXY;
        return NJT_CONF_OK;
    }

    rlcf->type = NJT_HTTP_REALIP_HEADER;
    rlcf->hash = njt_hash_strlow(value[1].data, value[1].data, value[1].len);
    rlcf->header = value[1];

    return NJT_CONF_OK;
}


static void *
njt_http_realip_create_loc_conf(njt_conf_t *cf)
{
    njt_http_realip_loc_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_realip_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->from = NULL;
     *     conf->hash = 0;
     *     conf->header = { 0, NULL };
     */

    conf->type = NJT_CONF_UNSET_UINT;
    conf->recursive = NJT_CONF_UNSET;

    return conf;
}


static char *
njt_http_realip_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_realip_loc_conf_t  *prev = parent;
    njt_http_realip_loc_conf_t  *conf = child;

    if (conf->from == NULL) {
        conf->from = prev->from;
    }

    njt_conf_merge_uint_value(conf->type, prev->type, NJT_HTTP_REALIP_XREALIP);
    njt_conf_merge_value(conf->recursive, prev->recursive, 0);

    if (conf->header.len == 0) {
        conf->hash = prev->hash;
        conf->header = prev->header;
    }

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_realip_add_variables(njt_conf_t *cf)
{
    njt_http_variable_t  *var, *v;

    for (v = njt_http_realip_vars; v->name.len; v++) {
        var = njt_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NJT_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_realip_init(njt_conf_t *cf)
{
    njt_http_handler_pt        *h;
    njt_http_core_main_conf_t  *cmcf;

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);

    h = njt_array_push(&cmcf->phases[NJT_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_http_realip_handler;

    h = njt_array_push(&cmcf->phases[NJT_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_http_realip_handler;

    return NJT_OK;
}


static njt_http_realip_ctx_t *
njt_http_realip_get_module_ctx(njt_http_request_t *r)
{
    njt_pool_cleanup_t     *cln;
    njt_http_realip_ctx_t  *ctx;

    ctx = njt_http_get_module_ctx(r, njt_http_realip_module);

    if (ctx == NULL && (r->internal || r->filter_finalize)) {

        /*
         * if module context was reset, the original address
         * can still be found in the cleanup handler
         */

        for (cln = r->pool->cleanup; cln; cln = cln->next) {
            if (cln->handler == njt_http_realip_cleanup) {
                ctx = cln->data;
                break;
            }
        }
    }

    return ctx;
}


static njt_int_t
njt_http_realip_remote_addr_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_str_t              *addr_text;
    njt_http_realip_ctx_t  *ctx;

    ctx = njt_http_realip_get_module_ctx(r);

    addr_text = ctx ? &ctx->addr_text : &r->connection->addr_text;

    v->len = addr_text->len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = addr_text->data;

    return NJT_OK;
}


static njt_int_t
njt_http_realip_remote_port_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_uint_t              port;
    struct sockaddr        *sa;
    njt_http_realip_ctx_t  *ctx;

    ctx = njt_http_realip_get_module_ctx(r);

    sa = ctx ? ctx->sockaddr : r->connection->sockaddr;

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = njt_pnalloc(r->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return NJT_ERROR;
    }

    port = njt_inet_get_port(sa);

    if (port > 0 && port < 65536) {
        v->len = njt_sprintf(v->data, "%ui", port) - v->data;
    }

    return NJT_OK;
}
