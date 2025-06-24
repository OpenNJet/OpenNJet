
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) NJet, Inc.
 * Copyright (C) 2021-2025  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>


#define NJT_STREAM_PASS_MAX_PASSES  10


typedef struct {
    njt_addr_t                  *addr;
    njt_stream_complex_value_t  *addr_value;
} njt_stream_pass_srv_conf_t;


static void njt_stream_pass_handler(njt_stream_session_t *s);
static njt_int_t njt_stream_pass_check_cycle(njt_connection_t *c);
static void njt_stream_pass_cleanup(void *data);
static njt_int_t njt_stream_pass_match(njt_listening_t *ls, njt_addr_t *addr);
static void *njt_stream_pass_create_srv_conf(njt_conf_t *cf);
static char *njt_stream_pass(njt_conf_t *cf, njt_command_t *cmd, void *conf);


static njt_command_t  njt_stream_pass_commands[] = {

    { njt_string("pass"),
      NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_stream_pass,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      njt_null_command
};


static njt_stream_module_t  njt_stream_pass_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    njt_stream_pass_create_srv_conf,       /* create server configuration */
    NULL                                   /* merge server configuration */
};


njt_module_t  njt_stream_pass_module = {
    NJT_MODULE_V1,
    &njt_stream_pass_module_ctx,           /* module context */
    njt_stream_pass_commands,              /* module directives */
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


static void
njt_stream_pass_handler(njt_stream_session_t *s)
{
    njt_url_t                    u;
    njt_str_t                    url;
    njt_addr_t                  *addr;
    njt_uint_t                   i;
    njt_listening_t             *ls;
    njt_connection_t            *c;
    njt_stream_pass_srv_conf_t  *pscf;

    c = s->connection;

    c->log->action = "passing connection to port";

    if (c->type == SOCK_DGRAM) {
        njt_log_error(NJT_LOG_ERR, c->log, 0, "cannot pass udp connection");
        goto failed;
    }

    if (c->buffer && c->buffer->pos != c->buffer->last) {
        njt_log_error(NJT_LOG_ERR, c->log, 0,
                      "cannot pass connection with preread data");
        goto failed;
    }

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_pass_module);

    addr = pscf->addr;

    if (addr == NULL) {
        if (njt_stream_complex_value(s, pscf->addr_value, &url) != NJT_OK) {
            goto failed;
        }

        njt_memzero(&u, sizeof(njt_url_t));

        u.url = url;
        u.no_resolve = 1;

        if (njt_parse_url(c->pool, &u) != NJT_OK) {
            if (u.err) {
                njt_log_error(NJT_LOG_ERR, c->log, 0,
                              "%s in pass \"%V\"", u.err, &u.url);
            }

            goto failed;
        }

        if (u.naddrs == 0) {
            njt_log_error(NJT_LOG_ERR, c->log, 0,
                          "no addresses in pass \"%V\"", &u.url);
            goto failed;
        }

        if (u.no_port) {
            njt_log_error(NJT_LOG_ERR, c->log, 0,
                          "no port in pass \"%V\"", &u.url);
            goto failed;
        }

        addr = &u.addrs[0];
    }

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "stream pass addr: \"%V\"", &addr->name);

    if (njt_stream_pass_check_cycle(c) != NJT_OK) {
        goto failed;
    }

    ls = njt_cycle->listening.elts;

    for (i = 0; i < njt_cycle->listening.nelts; i++) {

        if (njt_stream_pass_match(&ls[i], addr) != NJT_OK) {
            continue;
        }

        c->listening = &ls[i];

        c->data = NULL;
        c->buffer = NULL;

        *c->log = c->listening->log;
        c->log->handler = NULL;
        c->log->data = NULL;

        c->local_sockaddr = addr->sockaddr;
        c->local_socklen = addr->socklen;

        c->listening->handler(c);

        return;
    }

    njt_log_error(NJT_LOG_ERR, c->log, 0,
                  "port not found for \"%V\"", &addr->name);

    njt_stream_finalize_session(s, NJT_STREAM_OK);

    return;

failed:

    njt_stream_finalize_session(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
}


static njt_int_t
njt_stream_pass_check_cycle(njt_connection_t *c)
{
    njt_uint_t          *num;
    njt_pool_cleanup_t  *cln;

    for (cln = c->pool->cleanup; cln; cln = cln->next) {
        if (cln->handler != njt_stream_pass_cleanup) {
            continue;
        }

        num = cln->data;

        if (++(*num) > NJT_STREAM_PASS_MAX_PASSES) {
            njt_log_error(NJT_LOG_ERR, c->log, 0, "stream pass cycle");
            return NJT_ERROR;
        }

        return NJT_OK;
    }

    cln = njt_pool_cleanup_add(c->pool, sizeof(njt_uint_t));
    if (cln == NULL) {
        return NJT_ERROR;
    }

    cln->handler = njt_stream_pass_cleanup;

    num = cln->data;
    *num = 1;

    return NJT_OK;
}


static void
njt_stream_pass_cleanup(void *data)
{
    return;
}


static njt_int_t
njt_stream_pass_match(njt_listening_t *ls, njt_addr_t *addr)
{
    if (ls->type == SOCK_DGRAM) {
        return NJT_DECLINED;
    }

    if (!ls->wildcard) {
        return njt_cmp_sockaddr(ls->sockaddr, ls->socklen,
                                addr->sockaddr, addr->socklen, 1);
    }

    if (ls->sockaddr->sa_family == addr->sockaddr->sa_family
        && njt_inet_get_port(ls->sockaddr) == njt_inet_get_port(addr->sockaddr))
    {
        return NJT_OK;
    }

    return NJT_DECLINED;
}


static void *
njt_stream_pass_create_srv_conf(njt_conf_t *cf)
{
    njt_stream_pass_srv_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_stream_pass_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->addr = NULL;
     *     conf->addr_value = NULL;
     */

    return conf;
}


static char *
njt_stream_pass(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_pass_srv_conf_t *pscf = conf;

    njt_url_t                            u;
    njt_str_t                           *value, *url;
    njt_stream_complex_value_t           cv;
    njt_stream_core_srv_conf_t          *cscf;
    njt_stream_compile_complex_value_t   ccv;

    if (pscf->addr || pscf->addr_value) {
        return "is duplicate";
    }

    cscf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_core_module);

    cscf->handler = njt_stream_pass_handler;

    value = cf->args->elts;

    url = &value[1];

    njt_memzero(&ccv, sizeof(njt_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = url;
    ccv.complex_value = &cv;

    if (njt_stream_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    if (cv.lengths) {
        pscf->addr_value = njt_palloc(cf->pool,
                                      sizeof(njt_stream_complex_value_t));
        if (pscf->addr_value == NULL) {
            return NJT_CONF_ERROR;
        }

        *pscf->addr_value = cv;

        return NJT_CONF_OK;
    }

    njt_memzero(&u, sizeof(njt_url_t));

    u.url = *url;
    u.no_resolve = 1;

    if (njt_parse_url(cf->pool, &u) != NJT_OK) {
        if (u.err) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "%s in \"%V\" of the \"pass\" directive",
                               u.err, &u.url);
        }

        return NJT_CONF_ERROR;
    }

    if (u.naddrs == 0) {
        return "has no addresses";
    }

    if (u.no_port) {
        return "has no port";
    }

    pscf->addr = &u.addrs[0];

    return NJT_CONF_OK;
}
