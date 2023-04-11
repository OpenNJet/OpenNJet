
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


#define NJT_HTTP_USERID_OFF   0
#define NJT_HTTP_USERID_LOG   1
#define NJT_HTTP_USERID_V1    2
#define NJT_HTTP_USERID_ON    3

#define NJT_HTTP_USERID_COOKIE_OFF              0x0002
#define NJT_HTTP_USERID_COOKIE_SECURE           0x0004
#define NJT_HTTP_USERID_COOKIE_HTTPONLY         0x0008
#define NJT_HTTP_USERID_COOKIE_SAMESITE         0x0010
#define NJT_HTTP_USERID_COOKIE_SAMESITE_STRICT  0x0020
#define NJT_HTTP_USERID_COOKIE_SAMESITE_LAX     0x0040
#define NJT_HTTP_USERID_COOKIE_SAMESITE_NONE    0x0080

/* 31 Dec 2037 23:55:55 GMT */
#define NJT_HTTP_USERID_MAX_EXPIRES  2145916555


typedef struct {
    njt_uint_t  enable;
    njt_uint_t  flags;

    njt_int_t   service;

    njt_str_t   name;
    njt_str_t   domain;
    njt_str_t   path;
    njt_str_t   p3p;

    time_t      expires;

    u_char      mark;
} njt_http_userid_conf_t;


typedef struct {
    uint32_t    uid_got[4];
    uint32_t    uid_set[4];
    njt_str_t   cookie;
    njt_uint_t  reset;
} njt_http_userid_ctx_t;


static njt_http_userid_ctx_t *njt_http_userid_get_uid(njt_http_request_t *r,
    njt_http_userid_conf_t *conf);
static njt_int_t njt_http_userid_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, njt_str_t *name, uint32_t *uid);
static njt_int_t njt_http_userid_set_uid(njt_http_request_t *r,
    njt_http_userid_ctx_t *ctx, njt_http_userid_conf_t *conf);
static njt_int_t njt_http_userid_create_uid(njt_http_request_t *r,
    njt_http_userid_ctx_t *ctx, njt_http_userid_conf_t *conf);

static njt_int_t njt_http_userid_add_variables(njt_conf_t *cf);
static njt_int_t njt_http_userid_init(njt_conf_t *cf);
static void *njt_http_userid_create_conf(njt_conf_t *cf);
static char *njt_http_userid_merge_conf(njt_conf_t *cf, void *parent,
    void *child);
static char *njt_http_userid_domain(njt_conf_t *cf, void *post, void *data);
static char *njt_http_userid_path(njt_conf_t *cf, void *post, void *data);
static char *njt_http_userid_expires(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_userid_p3p(njt_conf_t *cf, void *post, void *data);
static char *njt_http_userid_mark(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static njt_int_t njt_http_userid_init_worker(njt_cycle_t *cycle);



static uint32_t  start_value;
static uint32_t  sequencer_v1 = 1;
static uint32_t  sequencer_v2 = 0x03030302;


static u_char expires[] = "; expires=Thu, 31-Dec-37 23:55:55 GMT";


static njt_http_output_header_filter_pt  njt_http_next_header_filter;


static njt_conf_enum_t  njt_http_userid_state[] = {
    { njt_string("off"), NJT_HTTP_USERID_OFF },
    { njt_string("log"), NJT_HTTP_USERID_LOG },
    { njt_string("v1"), NJT_HTTP_USERID_V1 },
    { njt_string("on"), NJT_HTTP_USERID_ON },
    { njt_null_string, 0 }
};


static njt_conf_bitmask_t  njt_http_userid_flags[] = {
    { njt_string("off"), NJT_HTTP_USERID_COOKIE_OFF },
    { njt_string("secure"), NJT_HTTP_USERID_COOKIE_SECURE },
    { njt_string("httponly"), NJT_HTTP_USERID_COOKIE_HTTPONLY },
    { njt_string("samesite=strict"),
      NJT_HTTP_USERID_COOKIE_SAMESITE|NJT_HTTP_USERID_COOKIE_SAMESITE_STRICT },
    { njt_string("samesite=lax"),
      NJT_HTTP_USERID_COOKIE_SAMESITE|NJT_HTTP_USERID_COOKIE_SAMESITE_LAX },
    { njt_string("samesite=none"),
      NJT_HTTP_USERID_COOKIE_SAMESITE|NJT_HTTP_USERID_COOKIE_SAMESITE_NONE },
    { njt_null_string, 0 }
};


static njt_conf_post_handler_pt  njt_http_userid_domain_p =
    njt_http_userid_domain;
static njt_conf_post_handler_pt  njt_http_userid_path_p = njt_http_userid_path;
static njt_conf_post_handler_pt  njt_http_userid_p3p_p = njt_http_userid_p3p;


static njt_command_t  njt_http_userid_commands[] = {

    { njt_string("userid"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_enum_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_userid_conf_t, enable),
      njt_http_userid_state },

    { njt_string("userid_service"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_userid_conf_t, service),
      NULL },

    { njt_string("userid_name"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_userid_conf_t, name),
      NULL },

    { njt_string("userid_domain"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_userid_conf_t, domain),
      &njt_http_userid_domain_p },

    { njt_string("userid_path"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_userid_conf_t, path),
      &njt_http_userid_path_p },

    { njt_string("userid_expires"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_userid_expires,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("userid_flags"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE123,
      njt_conf_set_bitmask_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_userid_conf_t, flags),
      &njt_http_userid_flags },

    { njt_string("userid_p3p"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_userid_conf_t, p3p),
      &njt_http_userid_p3p_p },

    { njt_string("userid_mark"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_userid_mark,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_userid_filter_module_ctx = {
    njt_http_userid_add_variables,         /* preconfiguration */
    njt_http_userid_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_userid_create_conf,           /* create location configuration */
    njt_http_userid_merge_conf             /* merge location configuration */
};


njt_module_t  njt_http_userid_filter_module = {
    NJT_MODULE_V1,
    &njt_http_userid_filter_module_ctx,    /* module context */
    njt_http_userid_commands,              /* module directives */
    NJT_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    njt_http_userid_init_worker,           /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_str_t   njt_http_userid_got = njt_string("uid_got");
static njt_str_t   njt_http_userid_set = njt_string("uid_set");
static njt_str_t   njt_http_userid_reset = njt_string("uid_reset");
static njt_uint_t  njt_http_userid_reset_index;


static njt_int_t
njt_http_userid_filter(njt_http_request_t *r)
{
    njt_http_userid_ctx_t   *ctx;
    njt_http_userid_conf_t  *conf;

    if (r != r->main) {
        return njt_http_next_header_filter(r);
    }

    conf = njt_http_get_module_loc_conf(r, njt_http_userid_filter_module);

    if (conf->enable < NJT_HTTP_USERID_V1) {
        return njt_http_next_header_filter(r);
    }

    ctx = njt_http_userid_get_uid(r, conf);

    if (ctx == NULL) {
        return NJT_ERROR;
    }

    if (njt_http_userid_set_uid(r, ctx, conf) == NJT_OK) {
        return njt_http_next_header_filter(r);
    }

    return NJT_ERROR;
}


static njt_int_t
njt_http_userid_got_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_http_userid_ctx_t   *ctx;
    njt_http_userid_conf_t  *conf;

    conf = njt_http_get_module_loc_conf(r->main, njt_http_userid_filter_module);

    if (conf->enable == NJT_HTTP_USERID_OFF) {
        v->not_found = 1;
        return NJT_OK;
    }

    ctx = njt_http_userid_get_uid(r->main, conf);

    if (ctx == NULL) {
        return NJT_ERROR;
    }

    if (ctx->uid_got[3] != 0) {
        return njt_http_userid_variable(r->main, v, &conf->name, ctx->uid_got);
    }

    v->not_found = 1;

    return NJT_OK;
}


static njt_int_t
njt_http_userid_set_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_http_userid_ctx_t   *ctx;
    njt_http_userid_conf_t  *conf;

    conf = njt_http_get_module_loc_conf(r->main, njt_http_userid_filter_module);

    if (conf->enable < NJT_HTTP_USERID_V1) {
        v->not_found = 1;
        return NJT_OK;
    }

    ctx = njt_http_userid_get_uid(r->main, conf);

    if (ctx == NULL) {
        return NJT_ERROR;
    }

    if (njt_http_userid_create_uid(r->main, ctx, conf) != NJT_OK) {
        return NJT_ERROR;
    }

    if (ctx->uid_set[3] == 0) {
        v->not_found = 1;
        return NJT_OK;
    }

    return njt_http_userid_variable(r->main, v, &conf->name, ctx->uid_set);
}


static njt_http_userid_ctx_t *
njt_http_userid_get_uid(njt_http_request_t *r, njt_http_userid_conf_t *conf)
{
    njt_str_t               src, dst;
    njt_table_elt_t        *cookie;
    njt_http_userid_ctx_t  *ctx;

    ctx = njt_http_get_module_ctx(r, njt_http_userid_filter_module);

    if (ctx) {
        return ctx;
    }

    if (ctx == NULL) {
        ctx = njt_pcalloc(r->pool, sizeof(njt_http_userid_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }

        njt_http_set_ctx(r, ctx, njt_http_userid_filter_module);
    }

    cookie = njt_http_parse_multi_header_lines(r, r->headers_in.cookie,
                                               &conf->name, &ctx->cookie);
    if (cookie == NULL) {
        return ctx;
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "uid cookie: \"%V\"", &ctx->cookie);

    if (ctx->cookie.len < 22) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "client sent too short userid cookie \"%V\"",
                      &cookie->value);
        return ctx;
    }

    src = ctx->cookie;

    /*
     * we have to limit the encoded string to 22 characters because
     *  1) cookie may be marked by "userid_mark",
     *  2) and there are already the millions cookies with a garbage
     *     instead of the correct base64 trail "=="
     */

    src.len = 22;

    dst.data = (u_char *) ctx->uid_got;

    if (njt_decode_base64(&dst, &src) == NJT_ERROR) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "client sent invalid userid cookie \"%V\"",
                      &cookie->value);
        return ctx;
    }

    njt_log_debug4(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "uid: %08XD%08XD%08XD%08XD",
                   ctx->uid_got[0], ctx->uid_got[1],
                   ctx->uid_got[2], ctx->uid_got[3]);

    return ctx;
}


static njt_int_t
njt_http_userid_set_uid(njt_http_request_t *r, njt_http_userid_ctx_t *ctx,
    njt_http_userid_conf_t *conf)
{
    u_char           *cookie, *p;
    size_t            len;
    njt_str_t         src, dst;
    njt_table_elt_t  *set_cookie, *p3p;

    if (njt_http_userid_create_uid(r, ctx, conf) != NJT_OK) {
        return NJT_ERROR;
    }

    if (ctx->uid_set[3] == 0) {
        return NJT_OK;
    }

    len = conf->name.len + 1 + njt_base64_encoded_length(16) + conf->path.len;

    if (conf->expires) {
        len += sizeof(expires) - 1 + 2;
    }

    if (conf->domain.len) {
        len += conf->domain.len;
    }

    if (conf->flags & NJT_HTTP_USERID_COOKIE_SECURE) {
        len += sizeof("; secure") - 1;
    }

    if (conf->flags & NJT_HTTP_USERID_COOKIE_HTTPONLY) {
        len += sizeof("; httponly") - 1;
    }

    if (conf->flags & NJT_HTTP_USERID_COOKIE_SAMESITE_STRICT) {
        len += sizeof("; samesite=strict") - 1;
    }

    if (conf->flags & NJT_HTTP_USERID_COOKIE_SAMESITE_LAX) {
        len += sizeof("; samesite=lax") - 1;
    }

    if (conf->flags & NJT_HTTP_USERID_COOKIE_SAMESITE_NONE) {
        len += sizeof("; samesite=none") - 1;
    }

    cookie = njt_pnalloc(r->pool, len);
    if (cookie == NULL) {
        return NJT_ERROR;
    }

    p = njt_copy(cookie, conf->name.data, conf->name.len);
    *p++ = '=';

    if (ctx->uid_got[3] == 0 || ctx->reset) {
        src.len = 16;
        src.data = (u_char *) ctx->uid_set;
        dst.data = p;

        njt_encode_base64(&dst, &src);

        p += dst.len;

        if (conf->mark) {
            *(p - 2) = conf->mark;
        }

    } else {
        p = njt_cpymem(p, ctx->cookie.data, 22);
        *p++ = conf->mark;
        *p++ = '=';
    }

    if (conf->expires == NJT_HTTP_USERID_MAX_EXPIRES) {
        p = njt_cpymem(p, expires, sizeof(expires) - 1);

    } else if (conf->expires) {
        p = njt_cpymem(p, expires, sizeof("; expires=") - 1);
        p = njt_http_cookie_time(p, njt_time() + conf->expires);
    }

    p = njt_copy(p, conf->domain.data, conf->domain.len);

    p = njt_copy(p, conf->path.data, conf->path.len);

    if (conf->flags & NJT_HTTP_USERID_COOKIE_SECURE) {
        p = njt_cpymem(p, "; secure", sizeof("; secure") - 1);
    }

    if (conf->flags & NJT_HTTP_USERID_COOKIE_HTTPONLY) {
        p = njt_cpymem(p, "; httponly", sizeof("; httponly") - 1);
    }

    if (conf->flags & NJT_HTTP_USERID_COOKIE_SAMESITE_STRICT) {
        p = njt_cpymem(p, "; samesite=strict", sizeof("; samesite=strict") - 1);
    }

    if (conf->flags & NJT_HTTP_USERID_COOKIE_SAMESITE_LAX) {
        p = njt_cpymem(p, "; samesite=lax", sizeof("; samesite=lax") - 1);
    }

    if (conf->flags & NJT_HTTP_USERID_COOKIE_SAMESITE_NONE) {
        p = njt_cpymem(p, "; samesite=none", sizeof("; samesite=none") - 1);
    }

    set_cookie = njt_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        return NJT_ERROR;
    }

    set_cookie->hash = 1;
    njt_str_set(&set_cookie->key, "Set-Cookie");
    set_cookie->value.len = p - cookie;
    set_cookie->value.data = cookie;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "uid cookie: \"%V\"", &set_cookie->value);

    if (conf->p3p.len == 0) {
        return NJT_OK;
    }

    p3p = njt_list_push(&r->headers_out.headers);
    if (p3p == NULL) {
        return NJT_ERROR;
    }

    p3p->hash = 1;
    njt_str_set(&p3p->key, "P3P");
    p3p->value = conf->p3p;

    return NJT_OK;
}


static njt_int_t
njt_http_userid_create_uid(njt_http_request_t *r, njt_http_userid_ctx_t *ctx,
    njt_http_userid_conf_t *conf)
{
    njt_connection_t           *c;
    struct sockaddr_in         *sin;
    njt_http_variable_value_t  *vv;
#if (NJT_HAVE_INET6)
    u_char                     *p;
    struct sockaddr_in6        *sin6;
#endif

    if (ctx->uid_set[3] != 0) {
        return NJT_OK;
    }

    if (ctx->uid_got[3] != 0) {

        vv = njt_http_get_indexed_variable(r, njt_http_userid_reset_index);

        if (vv == NULL || vv->not_found) {
            return NJT_ERROR;
        }

        if (vv->len == 0 || (vv->len == 1 && vv->data[0] == '0')) {

            if (conf->mark == '\0'
                || (ctx->cookie.len > 23
                    && ctx->cookie.data[22] == conf->mark
                    && ctx->cookie.data[23] == '='))
            {
                return NJT_OK;
            }

            ctx->uid_set[0] = ctx->uid_got[0];
            ctx->uid_set[1] = ctx->uid_got[1];
            ctx->uid_set[2] = ctx->uid_got[2];
            ctx->uid_set[3] = ctx->uid_got[3];

            return NJT_OK;

        } else {
            ctx->reset = 1;

            if (vv->len == 3 && njt_strncmp(vv->data, "log", 3) == 0) {
                njt_log_error(NJT_LOG_NOTICE, r->connection->log, 0,
                        "userid cookie \"%V=%08XD%08XD%08XD%08XD\" was reset",
                        &conf->name, ctx->uid_got[0], ctx->uid_got[1],
                        ctx->uid_got[2], ctx->uid_got[3]);
            }
        }
    }

    /*
     * TODO: in the threaded mode the sequencers should be in TLS and their
     * ranges should be divided between threads
     */

    if (conf->enable == NJT_HTTP_USERID_V1) {
        if (conf->service == NJT_CONF_UNSET) {
            ctx->uid_set[0] = 0;
        } else {
            ctx->uid_set[0] = conf->service;
        }
        ctx->uid_set[1] = (uint32_t) njt_time();
        ctx->uid_set[2] = start_value;
        ctx->uid_set[3] = sequencer_v1;
        sequencer_v1 += 0x100;

    } else {
        if (conf->service == NJT_CONF_UNSET) {

            c = r->connection;

            if (njt_connection_local_sockaddr(c, NULL, 0) != NJT_OK) {
                return NJT_ERROR;
            }

            switch (c->local_sockaddr->sa_family) {

#if (NJT_HAVE_INET6)
            case AF_INET6:
                sin6 = (struct sockaddr_in6 *) c->local_sockaddr;

                p = (u_char *) &ctx->uid_set[0];

                *p++ = sin6->sin6_addr.s6_addr[12];
                *p++ = sin6->sin6_addr.s6_addr[13];
                *p++ = sin6->sin6_addr.s6_addr[14];
                *p = sin6->sin6_addr.s6_addr[15];

                break;
#endif

#if (NJT_HAVE_UNIX_DOMAIN)
            case AF_UNIX:
                ctx->uid_set[0] = 0;
                break;
#endif

            default: /* AF_INET */
                sin = (struct sockaddr_in *) c->local_sockaddr;
                ctx->uid_set[0] = sin->sin_addr.s_addr;
                break;
            }

        } else {
            ctx->uid_set[0] = htonl(conf->service);
        }

        ctx->uid_set[1] = htonl((uint32_t) njt_time());
        ctx->uid_set[2] = htonl(start_value);
        ctx->uid_set[3] = htonl(sequencer_v2);
        sequencer_v2 += 0x100;
        if (sequencer_v2 < 0x03030302) {
            sequencer_v2 = 0x03030302;
        }
    }

    return NJT_OK;
}


static njt_int_t
njt_http_userid_variable(njt_http_request_t *r, njt_http_variable_value_t *v,
    njt_str_t *name, uint32_t *uid)
{
    v->len = name->len + sizeof("=00001111222233334444555566667777") - 1;
    v->data = njt_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        return NJT_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    njt_sprintf(v->data, "%V=%08XD%08XD%08XD%08XD",
                name, uid[0], uid[1], uid[2], uid[3]);

    return NJT_OK;
}


static njt_int_t
njt_http_userid_reset_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    *v = njt_http_variable_null_value;

    return NJT_OK;
}


static njt_int_t
njt_http_userid_add_variables(njt_conf_t *cf)
{
    njt_int_t             n;
    njt_http_variable_t  *var;

    var = njt_http_add_variable(cf, &njt_http_userid_got, 0);
    if (var == NULL) {
        return NJT_ERROR;
    }

    var->get_handler = njt_http_userid_got_variable;

    var = njt_http_add_variable(cf, &njt_http_userid_set, 0);
    if (var == NULL) {
        return NJT_ERROR;
    }

    var->get_handler = njt_http_userid_set_variable;

    var = njt_http_add_variable(cf, &njt_http_userid_reset,
                                NJT_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return NJT_ERROR;
    }

    var->get_handler = njt_http_userid_reset_variable;

    n = njt_http_get_variable_index(cf, &njt_http_userid_reset);
    if (n == NJT_ERROR) {
        return NJT_ERROR;
    }

    njt_http_userid_reset_index = n;

    return NJT_OK;
}


static void *
njt_http_userid_create_conf(njt_conf_t *cf)
{
    njt_http_userid_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_userid_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->flags = 0;
     *     conf->name = { 0, NULL };
     *     conf->domain = { 0, NULL };
     *     conf->path = { 0, NULL };
     *     conf->p3p = { 0, NULL };
     */

    conf->enable = NJT_CONF_UNSET_UINT;
    conf->service = NJT_CONF_UNSET;
    conf->expires = NJT_CONF_UNSET;
    conf->mark = (u_char) '\xFF';

    return conf;
}


static char *
njt_http_userid_merge_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_userid_conf_t *prev = parent;
    njt_http_userid_conf_t *conf = child;

    njt_conf_merge_uint_value(conf->enable, prev->enable,
                              NJT_HTTP_USERID_OFF);

    njt_conf_merge_bitmask_value(conf->flags, prev->flags,
                            (NJT_CONF_BITMASK_SET|NJT_HTTP_USERID_COOKIE_OFF));

    njt_conf_merge_str_value(conf->name, prev->name, "uid");
    njt_conf_merge_str_value(conf->domain, prev->domain, "");
    njt_conf_merge_str_value(conf->path, prev->path, "; path=/");
    njt_conf_merge_str_value(conf->p3p, prev->p3p, "");

    njt_conf_merge_value(conf->service, prev->service, NJT_CONF_UNSET);
    njt_conf_merge_sec_value(conf->expires, prev->expires, 0);

    if (conf->mark == (u_char) '\xFF') {
        if (prev->mark == (u_char) '\xFF') {
            conf->mark = '\0';
        } else {
            conf->mark = prev->mark;
        }
    }

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_userid_init(njt_conf_t *cf)
{
    njt_http_next_header_filter = njt_http_top_header_filter;
    njt_http_top_header_filter = njt_http_userid_filter;

    return NJT_OK;
}


static char *
njt_http_userid_domain(njt_conf_t *cf, void *post, void *data)
{
    njt_str_t  *domain = data;

    u_char  *p, *new;

    if (njt_strcmp(domain->data, "none") == 0) {
        njt_str_set(domain, "");
        return NJT_CONF_OK;
    }

    new = njt_pnalloc(cf->pool, sizeof("; domain=") - 1 + domain->len);
    if (new == NULL) {
        return NJT_CONF_ERROR;
    }

    p = njt_cpymem(new, "; domain=", sizeof("; domain=") - 1);
    njt_memcpy(p, domain->data, domain->len);

    domain->len += sizeof("; domain=") - 1;
    domain->data = new;

    return NJT_CONF_OK;
}


static char *
njt_http_userid_path(njt_conf_t *cf, void *post, void *data)
{
    njt_str_t  *path = data;

    u_char  *p, *new;

    new = njt_pnalloc(cf->pool, sizeof("; path=") - 1 + path->len);
    if (new == NULL) {
        return NJT_CONF_ERROR;
    }

    p = njt_cpymem(new, "; path=", sizeof("; path=") - 1);
    njt_memcpy(p, path->data, path->len);

    path->len += sizeof("; path=") - 1;
    path->data = new;

    return NJT_CONF_OK;
}


static char *
njt_http_userid_expires(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_userid_conf_t *ucf = conf;

    njt_str_t  *value;

    if (ucf->expires != NJT_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (njt_strcmp(value[1].data, "max") == 0) {
        ucf->expires = NJT_HTTP_USERID_MAX_EXPIRES;
        return NJT_CONF_OK;
    }

    if (njt_strcmp(value[1].data, "off") == 0) {
        ucf->expires = 0;
        return NJT_CONF_OK;
    }

    ucf->expires = njt_parse_time(&value[1], 1);
    if (ucf->expires == (time_t) NJT_ERROR) {
        return "invalid value";
    }

    return NJT_CONF_OK;
}


static char *
njt_http_userid_p3p(njt_conf_t *cf, void *post, void *data)
{
    njt_str_t  *p3p = data;

    if (njt_strcmp(p3p->data, "none") == 0) {
        njt_str_set(p3p, "");
    }

    return NJT_CONF_OK;
}


static char *
njt_http_userid_mark(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_userid_conf_t *ucf = conf;

    njt_str_t  *value;

    if (ucf->mark != (u_char) '\xFF') {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (njt_strcmp(value[1].data, "off") == 0) {
        ucf->mark = '\0';
        return NJT_CONF_OK;
    }

    if (value[1].len != 1
        || !((value[1].data[0] >= '0' && value[1].data[0] <= '9')
              || (value[1].data[0] >= 'A' && value[1].data[0] <= 'Z')
              || (value[1].data[0] >= 'a' && value[1].data[0] <= 'z')
              || value[1].data[0] == '='))
    {
        return "value must be \"off\" or a single letter, digit or \"=\"";
    }

    ucf->mark = value[1].data[0];

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_userid_init_worker(njt_cycle_t *cycle)
{
    struct timeval  tp;

    njt_gettimeofday(&tp);

    /* use the most significant usec part that fits to 16 bits */
    start_value = (((uint32_t) tp.tv_usec / 20) << 16) | njt_pid;

    return NJT_OK;
}
