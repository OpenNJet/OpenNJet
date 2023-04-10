
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_http_dyn_module.h>

static njt_int_t njt_http_access_handler(njt_http_request_t *r);
static njt_int_t njt_http_access_inet(njt_http_request_t *r,
    njt_http_access_loc_conf_t *alcf, in_addr_t addr);
#if (NJT_HAVE_INET6)
static njt_int_t njt_http_access_inet6(njt_http_request_t *r,
    njt_http_access_loc_conf_t *alcf, u_char *p);
#endif
#if (NJT_HAVE_UNIX_DOMAIN)
static njt_int_t njt_http_access_unix(njt_http_request_t *r,
    njt_http_access_loc_conf_t *alcf);
#endif
static njt_int_t njt_http_access_found(njt_http_request_t *r, njt_uint_t deny);
static char *njt_http_access_rule(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static void *njt_http_access_create_loc_conf(njt_conf_t *cf);
static char *njt_http_access_merge_loc_conf(njt_conf_t *cf,
    void *parent, void *child);
static njt_int_t njt_http_access_init(njt_conf_t *cf);


static njt_command_t  njt_http_access_commands[] = {

    { njt_string("allow"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LMT_CONF
                        |NJT_CONF_TAKE1,
      njt_http_access_rule,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("deny"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LMT_CONF
                        |NJT_CONF_TAKE1,
      njt_http_access_rule,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      njt_null_command
};



static njt_http_module_t  njt_http_access_module_ctx = {
    NULL,                                  /* preconfiguration */
    njt_http_access_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_access_create_loc_conf,       /* create location configuration */
    njt_http_access_merge_loc_conf         /* merge location configuration */
};


njt_module_t  njt_http_access_module = {
    NJT_MODULE_V1,
    &njt_http_access_module_ctx,           /* module context */
    njt_http_access_commands,              /* module directives */
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


static njt_int_t
njt_http_access_handler(njt_http_request_t *r)
{
    struct sockaddr_in          *sin;
    njt_http_access_loc_conf_t  *alcf;
#if (NJT_HAVE_INET6)
    u_char                      *p;
    in_addr_t                    addr;
    struct sockaddr_in6         *sin6;
#endif

    alcf = njt_http_get_module_loc_conf(r, njt_http_access_module);

    switch (r->connection->sockaddr->sa_family) {

    case AF_INET:
        if (alcf->rules) {
            sin = (struct sockaddr_in *) r->connection->sockaddr;
            return njt_http_access_inet(r, alcf, sin->sin_addr.s_addr);
        }
        break;

#if (NJT_HAVE_INET6)

    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
        p = sin6->sin6_addr.s6_addr;

        if (alcf->rules && IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            addr = p[12] << 24;
            addr += p[13] << 16;
            addr += p[14] << 8;
            addr += p[15];
            return njt_http_access_inet(r, alcf, htonl(addr));
        }

        if (alcf->rules6) {
            return njt_http_access_inet6(r, alcf, p);
        }

        break;

#endif

#if (NJT_HAVE_UNIX_DOMAIN)

    case AF_UNIX:
        if (alcf->rules_un) {
            return njt_http_access_unix(r, alcf);
        }

        break;

#endif
    }

    return NJT_DECLINED;
}


static njt_int_t
njt_http_access_inet(njt_http_request_t *r, njt_http_access_loc_conf_t *alcf,
    in_addr_t addr)
{
    njt_uint_t               i;
    njt_http_access_rule_t  *rule;

    rule = alcf->rules->elts;
    for (i = 0; i < alcf->rules->nelts; i++) {

        njt_log_debug3(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "access: %08XD %08XD %08XD",
                       addr, rule[i].mask, rule[i].addr);

        if ((addr & rule[i].mask) == rule[i].addr) {
            return njt_http_access_found(r, rule[i].deny);
        }
    }

    return NJT_DECLINED;
}


#if (NJT_HAVE_INET6)

static njt_int_t
njt_http_access_inet6(njt_http_request_t *r, njt_http_access_loc_conf_t *alcf,
    u_char *p)
{
    njt_uint_t                n;
    njt_uint_t                i;
    njt_http_access_rule6_t  *rule6;

    rule6 = alcf->rules6->elts;
    for (i = 0; i < alcf->rules6->nelts; i++) {

#if (NJT_DEBUG)
        {
        size_t  cl, ml, al;
        u_char  ct[NJT_INET6_ADDRSTRLEN];
        u_char  mt[NJT_INET6_ADDRSTRLEN];
        u_char  at[NJT_INET6_ADDRSTRLEN];

        cl = njt_inet6_ntop(p, ct, NJT_INET6_ADDRSTRLEN);
        ml = njt_inet6_ntop(rule6[i].mask.s6_addr, mt, NJT_INET6_ADDRSTRLEN);
        al = njt_inet6_ntop(rule6[i].addr.s6_addr, at, NJT_INET6_ADDRSTRLEN);

        njt_log_debug6(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "access: %*s %*s %*s", cl, ct, ml, mt, al, at);
        }
#endif

        for (n = 0; n < 16; n++) {
            if ((p[n] & rule6[i].mask.s6_addr[n]) != rule6[i].addr.s6_addr[n]) {
                goto next;
            }
        }

        return njt_http_access_found(r, rule6[i].deny);

    next:
        continue;
    }

    return NJT_DECLINED;
}

#endif


#if (NJT_HAVE_UNIX_DOMAIN)

static njt_int_t
njt_http_access_unix(njt_http_request_t *r, njt_http_access_loc_conf_t *alcf)
{
    njt_uint_t                  i;
    njt_http_access_rule_un_t  *rule_un;

    rule_un = alcf->rules_un->elts;
    for (i = 0; i < alcf->rules_un->nelts; i++) {

        /* TODO: check path */
        if (1) {
            return njt_http_access_found(r, rule_un[i].deny);
        }
    }

    return NJT_DECLINED;
}

#endif


static njt_int_t
njt_http_access_found(njt_http_request_t *r, njt_uint_t deny)
{
    njt_http_core_loc_conf_t  *clcf;

    if (deny) {
        clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

        if (clcf->satisfy == NJT_HTTP_SATISFY_ALL) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "access forbidden by rule");
        }

        return NJT_HTTP_FORBIDDEN;
    }

    return NJT_OK;
}


static char *
njt_http_access_rule(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_access_loc_conf_t *alcf = conf;

    njt_int_t                   rc;
    njt_uint_t                  all;
    njt_str_t                  *value;
    njt_cidr_t                  cidr;
    njt_http_access_rule_t     *rule;
#if (NJT_HAVE_INET6)
    njt_http_access_rule6_t    *rule6;
#endif
#if (NJT_HAVE_UNIX_DOMAIN)
    njt_http_access_rule_un_t  *rule_un;
#endif

    all = 0;
    njt_memzero(&cidr, sizeof(njt_cidr_t));

    value = cf->args->elts;

    if (value[1].len == 3 && njt_strcmp(value[1].data, "all") == 0) {
        all = 1;

#if (NJT_HAVE_UNIX_DOMAIN)
    } else if (value[1].len == 5 && njt_strcmp(value[1].data, "unix:") == 0) {
        cidr.family = AF_UNIX;
#endif

    } else {
        rc = njt_ptocidr(&value[1], &cidr);

        if (rc == NJT_ERROR) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                         "invalid parameter \"%V\"", &value[1]);
            return NJT_CONF_ERROR;
        }

        if (rc == NJT_DONE) {
            njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                         "low address bits of %V are meaningless", &value[1]);
        }
    }

    if (cidr.family == AF_INET || all) {

        if (alcf->rules == NULL) {
            alcf->rules = njt_array_create(cf->pool, 4,
                                           sizeof(njt_http_access_rule_t));
            if (alcf->rules == NULL) {
                return NJT_CONF_ERROR;
            }
        }

        rule = njt_array_push(alcf->rules);
        if (rule == NULL) {
            return NJT_CONF_ERROR;
        }

        rule->mask = cidr.u.in.mask;
        rule->addr = cidr.u.in.addr;
        rule->deny = (value[0].data[0] == 'd') ? 1 : 0;
    }

#if (NJT_HAVE_INET6)
    if (cidr.family == AF_INET6 || all) {

        if (alcf->rules6 == NULL) {
            alcf->rules6 = njt_array_create(cf->pool, 4,
                                            sizeof(njt_http_access_rule6_t));
            if (alcf->rules6 == NULL) {
                return NJT_CONF_ERROR;
            }
        }

        rule6 = njt_array_push(alcf->rules6);
        if (rule6 == NULL) {
            return NJT_CONF_ERROR;
        }

        rule6->mask = cidr.u.in6.mask;
        rule6->addr = cidr.u.in6.addr;
        rule6->deny = (value[0].data[0] == 'd') ? 1 : 0;
    }
#endif

#if (NJT_HAVE_UNIX_DOMAIN)
    if (cidr.family == AF_UNIX || all) {

        if (alcf->rules_un == NULL) {
            alcf->rules_un = njt_array_create(cf->pool, 1,
                                            sizeof(njt_http_access_rule_un_t));
            if (alcf->rules_un == NULL) {
                return NJT_CONF_ERROR;
            }
        }

        rule_un = njt_array_push(alcf->rules_un);
        if (rule_un == NULL) {
            return NJT_CONF_ERROR;
        }

        rule_un->deny = (value[0].data[0] == 'd') ? 1 : 0;
    }
#endif

    return NJT_CONF_OK;
}


static void *
njt_http_access_create_loc_conf(njt_conf_t *cf)
{
    njt_http_access_loc_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_access_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
njt_http_access_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_access_loc_conf_t  *prev = parent;
    njt_http_access_loc_conf_t  *conf = child;

    if (conf->rules == NULL
#if (NJT_HAVE_INET6)
        && conf->rules6 == NULL
#endif
#if (NJT_HAVE_UNIX_DOMAIN)
        && conf->rules_un == NULL
#endif
    ) {
        conf->rules = prev->rules;
#if (NJT_HAVE_INET6)
        conf->rules6 = prev->rules6;
#endif
#if (NJT_HAVE_UNIX_DOMAIN)
        conf->rules_un = prev->rules_un;
#endif
    }

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_access_init(njt_conf_t *cf)
{
    njt_http_handler_pt        *h;
    njt_http_core_main_conf_t  *cmcf;

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);

    h = njt_array_push(&cmcf->phases[NJT_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_http_access_handler;

    return NJT_OK;
}
