
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_mail.h>
#include <njt_mail_pop3_module.h>


static void *njt_mail_pop3_create_srv_conf(njt_conf_t *cf);
static char *njt_mail_pop3_merge_srv_conf(njt_conf_t *cf, void *parent,
    void *child);


static njt_str_t  njt_mail_pop3_default_capabilities[] = {
    njt_string("TOP"),
    njt_string("USER"),
    njt_string("UIDL"),
    njt_null_string
};


static njt_conf_bitmask_t  njt_mail_pop3_auth_methods[] = {
    { njt_string("plain"), NJT_MAIL_AUTH_PLAIN_ENABLED },
    { njt_string("apop"), NJT_MAIL_AUTH_APOP_ENABLED },
    { njt_string("cram-md5"), NJT_MAIL_AUTH_CRAM_MD5_ENABLED },
    { njt_string("external"), NJT_MAIL_AUTH_EXTERNAL_ENABLED },
    { njt_null_string, 0 }
};


static njt_str_t  njt_mail_pop3_auth_methods_names[] = {
    njt_string("PLAIN"),
    njt_string("LOGIN"),
    njt_null_string,  /* APOP */
    njt_string("CRAM-MD5"),
    njt_string("EXTERNAL"),
    njt_null_string   /* NONE */
};


static njt_mail_protocol_t  njt_mail_pop3_protocol = {
    njt_string("pop3"),
    njt_string("\x04pop3"),
    { 110, 995, 0, 0 },
    NJT_MAIL_POP3_PROTOCOL,

    njt_mail_pop3_init_session,
    njt_mail_pop3_init_protocol,
    njt_mail_pop3_parse_command,
    njt_mail_pop3_auth_state,

    njt_string("-ERR internal server error" CRLF),
    njt_string("-ERR SSL certificate error" CRLF),
    njt_string("-ERR No required SSL certificate" CRLF)
};


static njt_command_t  njt_mail_pop3_commands[] = {

    { njt_string("pop3_capabilities"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_1MORE,
      njt_mail_capabilities,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_pop3_srv_conf_t, capabilities),
      NULL },

    { njt_string("pop3_auth"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_pop3_srv_conf_t, auth_methods),
      &njt_mail_pop3_auth_methods },

      njt_null_command
};


static njt_mail_module_t  njt_mail_pop3_module_ctx = {
    &njt_mail_pop3_protocol,               /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    njt_mail_pop3_create_srv_conf,         /* create server configuration */
    njt_mail_pop3_merge_srv_conf           /* merge server configuration */
};


njt_module_t  njt_mail_pop3_module = {
    NJT_MODULE_V1,
    &njt_mail_pop3_module_ctx,             /* module context */
    njt_mail_pop3_commands,                /* module directives */
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
njt_mail_pop3_create_srv_conf(njt_conf_t *cf)
{
    njt_mail_pop3_srv_conf_t  *pscf;

    pscf = njt_pcalloc(cf->pool, sizeof(njt_mail_pop3_srv_conf_t));
    if (pscf == NULL) {
        return NULL;
    }

    if (njt_array_init(&pscf->capabilities, cf->pool, 4, sizeof(njt_str_t))
        != NJT_OK)
    {
        return NULL;
    }

    return pscf;
}


static char *
njt_mail_pop3_merge_srv_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_mail_pop3_srv_conf_t *prev = parent;
    njt_mail_pop3_srv_conf_t *conf = child;

    u_char      *p;
    size_t       size, stls_only_size;
    njt_str_t   *c, *d;
    njt_uint_t   i, m;

    njt_conf_merge_bitmask_value(conf->auth_methods,
                                 prev->auth_methods,
                                 (NJT_CONF_BITMASK_SET
                                  |NJT_MAIL_AUTH_PLAIN_ENABLED));

    if (conf->auth_methods & NJT_MAIL_AUTH_PLAIN_ENABLED) {
        conf->auth_methods |= NJT_MAIL_AUTH_LOGIN_ENABLED;
    }

    if (conf->capabilities.nelts == 0) {
        conf->capabilities = prev->capabilities;
    }

    if (conf->capabilities.nelts == 0) {

        for (d = njt_mail_pop3_default_capabilities; d->len; d++) {
            c = njt_array_push(&conf->capabilities);
            if (c == NULL) {
                return NJT_CONF_ERROR;
            }

            *c = *d;
        }
    }

    size = sizeof("+OK Capability list follows" CRLF) - 1
           + sizeof("." CRLF) - 1;

    stls_only_size = size + sizeof("STLS" CRLF) - 1;

    c = conf->capabilities.elts;
    for (i = 0; i < conf->capabilities.nelts; i++) {
        size += c[i].len + sizeof(CRLF) - 1;

        if (njt_strcasecmp(c[i].data, (u_char *) "USER") == 0) {
            continue;
        }

        stls_only_size += c[i].len + sizeof(CRLF) - 1;
    }

    size += sizeof("SASL") - 1 + sizeof(CRLF) - 1;

    for (m = NJT_MAIL_AUTH_PLAIN_ENABLED, i = 0;
         m <= NJT_MAIL_AUTH_EXTERNAL_ENABLED;
         m <<= 1, i++)
    {
        if (njt_mail_pop3_auth_methods_names[i].len == 0) {
            continue;
        }

        if (m & conf->auth_methods) {
            size += 1 + njt_mail_pop3_auth_methods_names[i].len;
        }
    }

    p = njt_pnalloc(cf->pool, size);
    if (p == NULL) {
        return NJT_CONF_ERROR;
    }

    conf->capability.len = size;
    conf->capability.data = p;

    p = njt_cpymem(p, "+OK Capability list follows" CRLF,
                   sizeof("+OK Capability list follows" CRLF) - 1);

    for (i = 0; i < conf->capabilities.nelts; i++) {
        p = njt_cpymem(p, c[i].data, c[i].len);
        *p++ = CR; *p++ = LF;
    }

    p = njt_cpymem(p, "SASL", sizeof("SASL") - 1);

    for (m = NJT_MAIL_AUTH_PLAIN_ENABLED, i = 0;
         m <= NJT_MAIL_AUTH_EXTERNAL_ENABLED;
         m <<= 1, i++)
    {
        if (njt_mail_pop3_auth_methods_names[i].len == 0) {
            continue;
        }

        if (m & conf->auth_methods) {
            *p++ = ' ';
            p = njt_cpymem(p, njt_mail_pop3_auth_methods_names[i].data,
                           njt_mail_pop3_auth_methods_names[i].len);
        }
    }

    *p++ = CR; *p++ = LF;

    *p++ = '.'; *p++ = CR; *p = LF;


    size += sizeof("STLS" CRLF) - 1;

    p = njt_pnalloc(cf->pool, size);
    if (p == NULL) {
        return NJT_CONF_ERROR;
    }

    conf->starttls_capability.len = size;
    conf->starttls_capability.data = p;

    p = njt_cpymem(p, conf->capability.data,
                   conf->capability.len - (sizeof("." CRLF) - 1));

    p = njt_cpymem(p, "STLS" CRLF, sizeof("STLS" CRLF) - 1);
    *p++ = '.'; *p++ = CR; *p = LF;


    size = sizeof("+OK methods supported:" CRLF) - 1
           + sizeof("." CRLF) - 1;

    for (m = NJT_MAIL_AUTH_PLAIN_ENABLED, i = 0;
         m <= NJT_MAIL_AUTH_EXTERNAL_ENABLED;
         m <<= 1, i++)
    {
        if (njt_mail_pop3_auth_methods_names[i].len == 0) {
            continue;
        }

        if (m & conf->auth_methods) {
            size += njt_mail_pop3_auth_methods_names[i].len
                    + sizeof(CRLF) - 1;
        }
    }

    p = njt_pnalloc(cf->pool, size);
    if (p == NULL) {
        return NJT_CONF_ERROR;
    }

    conf->auth_capability.data = p;
    conf->auth_capability.len = size;

    p = njt_cpymem(p, "+OK methods supported:" CRLF,
                   sizeof("+OK methods supported:" CRLF) - 1);

    for (m = NJT_MAIL_AUTH_PLAIN_ENABLED, i = 0;
         m <= NJT_MAIL_AUTH_EXTERNAL_ENABLED;
         m <<= 1, i++)
    {
        if (njt_mail_pop3_auth_methods_names[i].len == 0) {
            continue;
        }

        if (m & conf->auth_methods) {
            p = njt_cpymem(p, njt_mail_pop3_auth_methods_names[i].data,
                           njt_mail_pop3_auth_methods_names[i].len);
            *p++ = CR; *p++ = LF;
        }
    }

    *p++ = '.'; *p++ = CR; *p = LF;


    p = njt_pnalloc(cf->pool, stls_only_size);
    if (p == NULL) {
        return NJT_CONF_ERROR;
    }

    conf->starttls_only_capability.len = stls_only_size;
    conf->starttls_only_capability.data = p;

    p = njt_cpymem(p, "+OK Capability list follows" CRLF,
                   sizeof("+OK Capability list follows" CRLF) - 1);

    for (i = 0; i < conf->capabilities.nelts; i++) {
        if (njt_strcasecmp(c[i].data, (u_char *) "USER") == 0) {
            continue;
        }

        p = njt_cpymem(p, c[i].data, c[i].len);
        *p++ = CR; *p++ = LF;
    }

    p = njt_cpymem(p, "STLS" CRLF, sizeof("STLS" CRLF) - 1);
    *p++ = '.'; *p++ = CR; *p = LF;

    return NJT_CONF_OK;
}
