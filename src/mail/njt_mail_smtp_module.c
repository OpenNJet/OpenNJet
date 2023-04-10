
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_mail.h>
#include <njt_mail_smtp_module.h>


static void *njt_mail_smtp_create_srv_conf(njt_conf_t *cf);
static char *njt_mail_smtp_merge_srv_conf(njt_conf_t *cf, void *parent,
    void *child);


static njt_conf_bitmask_t  njt_mail_smtp_auth_methods[] = {
    { njt_string("plain"), NJT_MAIL_AUTH_PLAIN_ENABLED },
    { njt_string("login"), NJT_MAIL_AUTH_LOGIN_ENABLED },
    { njt_string("cram-md5"), NJT_MAIL_AUTH_CRAM_MD5_ENABLED },
    { njt_string("external"), NJT_MAIL_AUTH_EXTERNAL_ENABLED },
    { njt_string("none"), NJT_MAIL_AUTH_NONE_ENABLED },
    { njt_null_string, 0 }
};


static njt_str_t  njt_mail_smtp_auth_methods_names[] = {
    njt_string("PLAIN"),
    njt_string("LOGIN"),
    njt_null_string,  /* APOP */
    njt_string("CRAM-MD5"),
    njt_string("EXTERNAL"),
    njt_null_string   /* NONE */
};


static njt_mail_protocol_t  njt_mail_smtp_protocol = {
    njt_string("smtp"),
    njt_string("\x04smtp"),
    { 25, 465, 587, 0 },
    NJT_MAIL_SMTP_PROTOCOL,

    njt_mail_smtp_init_session,
    njt_mail_smtp_init_protocol,
    njt_mail_smtp_parse_command,
    njt_mail_smtp_auth_state,

    njt_string("451 4.3.2 Internal server error" CRLF),
    njt_string("421 4.7.1 SSL certificate error" CRLF),
    njt_string("421 4.7.1 No required SSL certificate" CRLF)
};


static njt_command_t  njt_mail_smtp_commands[] = {

    { njt_string("smtp_client_buffer"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_smtp_srv_conf_t, client_buffer_size),
      NULL },

    { njt_string("smtp_greeting_delay"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_smtp_srv_conf_t, greeting_delay),
      NULL },

    { njt_string("smtp_capabilities"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_1MORE,
      njt_mail_capabilities,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_smtp_srv_conf_t, capabilities),
      NULL },

    { njt_string("smtp_auth"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_smtp_srv_conf_t, auth_methods),
      &njt_mail_smtp_auth_methods },

      njt_null_command
};


static njt_mail_module_t  njt_mail_smtp_module_ctx = {
    &njt_mail_smtp_protocol,               /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    njt_mail_smtp_create_srv_conf,         /* create server configuration */
    njt_mail_smtp_merge_srv_conf           /* merge server configuration */
};


njt_module_t  njt_mail_smtp_module = {
    NJT_MODULE_V1,
    &njt_mail_smtp_module_ctx,             /* module context */
    njt_mail_smtp_commands,                /* module directives */
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
njt_mail_smtp_create_srv_conf(njt_conf_t *cf)
{
    njt_mail_smtp_srv_conf_t  *sscf;

    sscf = njt_pcalloc(cf->pool, sizeof(njt_mail_smtp_srv_conf_t));
    if (sscf == NULL) {
        return NULL;
    }

    sscf->client_buffer_size = NJT_CONF_UNSET_SIZE;
    sscf->greeting_delay = NJT_CONF_UNSET_MSEC;

    if (njt_array_init(&sscf->capabilities, cf->pool, 4, sizeof(njt_str_t))
        != NJT_OK)
    {
        return NULL;
    }

    return sscf;
}


static char *
njt_mail_smtp_merge_srv_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_mail_smtp_srv_conf_t *prev = parent;
    njt_mail_smtp_srv_conf_t *conf = child;

    u_char                    *p, *auth, *last;
    size_t                     size;
    njt_str_t                 *c;
    njt_uint_t                 i, m, auth_enabled;
    njt_mail_core_srv_conf_t  *cscf;

    njt_conf_merge_size_value(conf->client_buffer_size,
                              prev->client_buffer_size,
                              (size_t) njt_pagesize);

    njt_conf_merge_msec_value(conf->greeting_delay,
                              prev->greeting_delay, 0);

    njt_conf_merge_bitmask_value(conf->auth_methods,
                              prev->auth_methods,
                              (NJT_CONF_BITMASK_SET
                               |NJT_MAIL_AUTH_PLAIN_ENABLED
                               |NJT_MAIL_AUTH_LOGIN_ENABLED));


    cscf = njt_mail_conf_get_module_srv_conf(cf, njt_mail_core_module);

    size = sizeof("220  ESMTP ready" CRLF) - 1 + cscf->server_name.len;

    p = njt_pnalloc(cf->pool, size);
    if (p == NULL) {
        return NJT_CONF_ERROR;
    }

    conf->greeting.len = size;
    conf->greeting.data = p;

    *p++ = '2'; *p++ = '2'; *p++ = '0'; *p++ = ' ';
    p = njt_cpymem(p, cscf->server_name.data, cscf->server_name.len);
    njt_memcpy(p, " ESMTP ready" CRLF, sizeof(" ESMTP ready" CRLF) - 1);


    size = sizeof("250 " CRLF) - 1 + cscf->server_name.len;

    p = njt_pnalloc(cf->pool, size);
    if (p == NULL) {
        return NJT_CONF_ERROR;
    }

    conf->server_name.len = size;
    conf->server_name.data = p;

    *p++ = '2'; *p++ = '5'; *p++ = '0'; *p++ = ' ';
    p = njt_cpymem(p, cscf->server_name.data, cscf->server_name.len);
    *p++ = CR; *p = LF;


    if (conf->capabilities.nelts == 0) {
        conf->capabilities = prev->capabilities;
    }

    size = sizeof("250-") - 1 + cscf->server_name.len + sizeof(CRLF) - 1;

    c = conf->capabilities.elts;
    for (i = 0; i < conf->capabilities.nelts; i++) {
        size += sizeof("250 ") - 1 + c[i].len + sizeof(CRLF) - 1;
    }

    auth_enabled = 0;

    for (m = NJT_MAIL_AUTH_PLAIN_ENABLED, i = 0;
         m <= NJT_MAIL_AUTH_EXTERNAL_ENABLED;
         m <<= 1, i++)
    {
        if (m & conf->auth_methods) {
            size += 1 + njt_mail_smtp_auth_methods_names[i].len;
            auth_enabled = 1;
        }
    }

    if (auth_enabled) {
        size += sizeof("250 AUTH") - 1 + sizeof(CRLF) - 1;
    }

    p = njt_pnalloc(cf->pool, size);
    if (p == NULL) {
        return NJT_CONF_ERROR;
    }

    conf->capability.len = size;
    conf->capability.data = p;

    last = p;

    *p++ = '2'; *p++ = '5'; *p++ = '0'; *p++ = '-';
    p = njt_cpymem(p, cscf->server_name.data, cscf->server_name.len);
    *p++ = CR; *p++ = LF;

    for (i = 0; i < conf->capabilities.nelts; i++) {
        last = p;
        *p++ = '2'; *p++ = '5'; *p++ = '0'; *p++ = '-';
        p = njt_cpymem(p, c[i].data, c[i].len);
        *p++ = CR; *p++ = LF;
    }

    auth = p;

    if (auth_enabled) {
        last = p;

        *p++ = '2'; *p++ = '5'; *p++ = '0'; *p++ = ' ';
        *p++ = 'A'; *p++ = 'U'; *p++ = 'T'; *p++ = 'H';

        for (m = NJT_MAIL_AUTH_PLAIN_ENABLED, i = 0;
             m <= NJT_MAIL_AUTH_EXTERNAL_ENABLED;
             m <<= 1, i++)
        {
            if (m & conf->auth_methods) {
                *p++ = ' ';
                p = njt_cpymem(p, njt_mail_smtp_auth_methods_names[i].data,
                               njt_mail_smtp_auth_methods_names[i].len);
            }
        }

        *p++ = CR; *p = LF;

    } else {
        last[3] = ' ';
    }

    size += sizeof("250 STARTTLS" CRLF) - 1;

    p = njt_pnalloc(cf->pool, size);
    if (p == NULL) {
        return NJT_CONF_ERROR;
    }

    conf->starttls_capability.len = size;
    conf->starttls_capability.data = p;

    p = njt_cpymem(p, conf->capability.data, conf->capability.len);

    njt_memcpy(p, "250 STARTTLS" CRLF, sizeof("250 STARTTLS" CRLF) - 1);

    p = conf->starttls_capability.data
        + (last - conf->capability.data) + 3;
    *p = '-';

    size = (auth - conf->capability.data)
            + sizeof("250 STARTTLS" CRLF) - 1;

    p = njt_pnalloc(cf->pool, size);
    if (p == NULL) {
        return NJT_CONF_ERROR;
    }

    conf->starttls_only_capability.len = size;
    conf->starttls_only_capability.data = p;

    p = njt_cpymem(p, conf->capability.data, auth - conf->capability.data);

    njt_memcpy(p, "250 STARTTLS" CRLF, sizeof("250 STARTTLS" CRLF) - 1);

    if (last < auth) {
        p = conf->starttls_only_capability.data
            + (last - conf->capability.data) + 3;
        *p = '-';
    }

    return NJT_CONF_OK;
}
