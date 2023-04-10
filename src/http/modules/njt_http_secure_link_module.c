
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_md5.h>


typedef struct {
    njt_http_complex_value_t  *variable;
    njt_http_complex_value_t  *md5;
    njt_str_t                  secret;
} njt_http_secure_link_conf_t;


typedef struct {
    njt_str_t                  expires;
} njt_http_secure_link_ctx_t;


static njt_int_t njt_http_secure_link_old_variable(njt_http_request_t *r,
    njt_http_secure_link_conf_t *conf, njt_http_variable_value_t *v,
    uintptr_t data);
static njt_int_t njt_http_secure_link_expires_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static void *njt_http_secure_link_create_conf(njt_conf_t *cf);
static char *njt_http_secure_link_merge_conf(njt_conf_t *cf, void *parent,
    void *child);
static njt_int_t njt_http_secure_link_add_variables(njt_conf_t *cf);


static njt_command_t  njt_http_secure_link_commands[] = {

    { njt_string("secure_link"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_set_complex_value_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_secure_link_conf_t, variable),
      NULL },

    { njt_string("secure_link_md5"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_set_complex_value_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_secure_link_conf_t, md5),
      NULL },

    { njt_string("secure_link_secret"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_secure_link_conf_t, secret),
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_secure_link_module_ctx = {
    njt_http_secure_link_add_variables,    /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_secure_link_create_conf,      /* create location configuration */
    njt_http_secure_link_merge_conf        /* merge location configuration */
};


njt_module_t  njt_http_secure_link_module = {
    NJT_MODULE_V1,
    &njt_http_secure_link_module_ctx,      /* module context */
    njt_http_secure_link_commands,         /* module directives */
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


static njt_str_t  njt_http_secure_link_name = njt_string("secure_link");
static njt_str_t  njt_http_secure_link_expires_name =
    njt_string("secure_link_expires");


static njt_int_t
njt_http_secure_link_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char                       *p, *last;
    njt_str_t                     val, hash;
    time_t                        expires;
    njt_md5_t                     md5;
    njt_http_secure_link_ctx_t   *ctx;
    njt_http_secure_link_conf_t  *conf;
    u_char                        hash_buf[18], md5_buf[16];

    conf = njt_http_get_module_loc_conf(r, njt_http_secure_link_module);

    if (conf->secret.data) {
        return njt_http_secure_link_old_variable(r, conf, v, data);
    }

    if (conf->variable == NULL || conf->md5 == NULL) {
        goto not_found;
    }

    if (njt_http_complex_value(r, conf->variable, &val) != NJT_OK) {
        return NJT_ERROR;
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "secure link: \"%V\"", &val);

    last = val.data + val.len;

    p = njt_strlchr(val.data, last, ',');
    expires = 0;

    if (p) {
        val.len = p++ - val.data;

        expires = njt_atotm(p, last - p);
        if (expires <= 0) {
            goto not_found;
        }

        ctx = njt_pcalloc(r->pool, sizeof(njt_http_secure_link_ctx_t));
        if (ctx == NULL) {
            return NJT_ERROR;
        }

        njt_http_set_ctx(r, ctx, njt_http_secure_link_module);

        ctx->expires.len = last - p;
        ctx->expires.data = p;
    }

    if (val.len > 24) {
        goto not_found;
    }

    hash.data = hash_buf;

    if (njt_decode_base64url(&hash, &val) != NJT_OK) {
        goto not_found;
    }

    if (hash.len != 16) {
        goto not_found;
    }

    if (njt_http_complex_value(r, conf->md5, &val) != NJT_OK) {
        return NJT_ERROR;
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "secure link md5: \"%V\"", &val);

    njt_md5_init(&md5);
    njt_md5_update(&md5, val.data, val.len);
    njt_md5_final(md5_buf, &md5);

    if (njt_memcmp(hash_buf, md5_buf, 16) != 0) {
        goto not_found;
    }

    v->data = (u_char *) ((expires && expires < njt_time()) ? "0" : "1");
    v->len = 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NJT_OK;

not_found:

    v->not_found = 1;

    return NJT_OK;
}


static njt_int_t
njt_http_secure_link_old_variable(njt_http_request_t *r,
    njt_http_secure_link_conf_t *conf, njt_http_variable_value_t *v,
    uintptr_t data)
{
    u_char      *p, *start, *end, *last;
    size_t       len;
    njt_int_t    n;
    njt_uint_t   i;
    njt_md5_t    md5;
    u_char       hash[16];

    p = &r->unparsed_uri.data[1];
    last = r->unparsed_uri.data + r->unparsed_uri.len;

    while (p < last) {
        if (*p++ == '/') {
            start = p;
            goto md5_start;
        }
    }

    goto not_found;

md5_start:

    while (p < last) {
        if (*p++ == '/') {
            end = p - 1;
            goto url_start;
        }
    }

    goto not_found;

url_start:

    len = last - p;

    if (end - start != 32 || len == 0) {
        goto not_found;
    }

    njt_md5_init(&md5);
    njt_md5_update(&md5, p, len);
    njt_md5_update(&md5, conf->secret.data, conf->secret.len);
    njt_md5_final(hash, &md5);

    for (i = 0; i < 16; i++) {
        n = njt_hextoi(&start[2 * i], 2);
        if (n == NJT_ERROR || n != hash[i]) {
            goto not_found;
        }
    }

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NJT_OK;

not_found:

    v->not_found = 1;

    return NJT_OK;
}


static njt_int_t
njt_http_secure_link_expires_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_http_secure_link_ctx_t  *ctx;

    ctx = njt_http_get_module_ctx(r, njt_http_secure_link_module);

    if (ctx) {
        v->len = ctx->expires.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = ctx->expires.data;

    } else {
        v->not_found = 1;
    }

    return NJT_OK;
}


static void *
njt_http_secure_link_create_conf(njt_conf_t *cf)
{
    njt_http_secure_link_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_secure_link_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->secret = { 0, NULL };
     */

    conf->variable = NJT_CONF_UNSET_PTR;
    conf->md5 = NJT_CONF_UNSET_PTR;

    return conf;
}


static char *
njt_http_secure_link_merge_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_secure_link_conf_t *prev = parent;
    njt_http_secure_link_conf_t *conf = child;

    if (conf->secret.data) {
        njt_conf_init_ptr_value(conf->variable, NULL);
        njt_conf_init_ptr_value(conf->md5, NULL);

        if (conf->variable || conf->md5) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "\"secure_link_secret\" cannot be mixed with "
                               "\"secure_link\" and \"secure_link_md5\"");
            return NJT_CONF_ERROR;
        }

        return NJT_CONF_OK;
    }

    njt_conf_merge_ptr_value(conf->variable, prev->variable, NULL);
    njt_conf_merge_ptr_value(conf->md5, prev->md5, NULL);

    if (conf->variable == NULL && conf->md5 == NULL) {
        conf->secret = prev->secret;
    }

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_secure_link_add_variables(njt_conf_t *cf)
{
    njt_http_variable_t  *var;

    var = njt_http_add_variable(cf, &njt_http_secure_link_name, 0);
    if (var == NULL) {
        return NJT_ERROR;
    }

    var->get_handler = njt_http_secure_link_variable;

    var = njt_http_add_variable(cf, &njt_http_secure_link_expires_name, 0);
    if (var == NULL) {
        return NJT_ERROR;
    }

    var->get_handler = njt_http_secure_link_expires_variable;

    return NJT_OK;
}
