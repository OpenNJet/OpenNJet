
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_mail.h>
#include <njt_mail_imap_module.h>


static void *njt_mail_imap_create_srv_conf(njt_conf_t *cf);
static char *njt_mail_imap_merge_srv_conf(njt_conf_t *cf, void *parent,
    void *child);


static njt_str_t  njt_mail_imap_default_capabilities[] = {
    njt_string("IMAP4"),
    njt_string("IMAP4rev1"),
    njt_string("UIDPLUS"),
    njt_null_string
};


static njt_conf_bitmask_t  njt_mail_imap_auth_methods[] = {
    { njt_string("plain"), NJT_MAIL_AUTH_PLAIN_ENABLED },
    { njt_string("login"), NJT_MAIL_AUTH_LOGIN_ENABLED },
    { njt_string("cram-md5"), NJT_MAIL_AUTH_CRAM_MD5_ENABLED },
    { njt_string("external"), NJT_MAIL_AUTH_EXTERNAL_ENABLED },
    { njt_null_string, 0 }
};


static njt_str_t  njt_mail_imap_auth_methods_names[] = {
    njt_string("AUTH=PLAIN"),
    njt_string("AUTH=LOGIN"),
    njt_null_string,  /* APOP */
    njt_string("AUTH=CRAM-MD5"),
    njt_string("AUTH=EXTERNAL"),
    njt_null_string   /* NONE */
};


static njt_mail_protocol_t  njt_mail_imap_protocol = {
    njt_string("imap"),
    njt_string("\x04imap"),
    { 143, 993, 0, 0 },
    NJT_MAIL_IMAP_PROTOCOL,

    njt_mail_imap_init_session,
    njt_mail_imap_init_protocol,
    njt_mail_imap_parse_command,
    njt_mail_imap_auth_state,

    njt_string("* BAD internal server error" CRLF),
    njt_string("* BYE SSL certificate error" CRLF),
    njt_string("* BYE No required SSL certificate" CRLF)
};


static njt_command_t  njt_mail_imap_commands[] = {

    { njt_string("imap_client_buffer"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_imap_srv_conf_t, client_buffer_size),
      NULL },

    { njt_string("imap_capabilities"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_1MORE,
      njt_mail_capabilities,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_imap_srv_conf_t, capabilities),
      NULL },

    { njt_string("imap_auth"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_imap_srv_conf_t, auth_methods),
      &njt_mail_imap_auth_methods },

      njt_null_command
};


static njt_mail_module_t  njt_mail_imap_module_ctx = {
    &njt_mail_imap_protocol,               /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    njt_mail_imap_create_srv_conf,         /* create server configuration */
    njt_mail_imap_merge_srv_conf           /* merge server configuration */
};


njt_module_t  njt_mail_imap_module = {
    NJT_MODULE_V1,
    &njt_mail_imap_module_ctx,             /* module context */
    njt_mail_imap_commands,                /* module directives */
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
njt_mail_imap_create_srv_conf(njt_conf_t *cf)
{
    njt_mail_imap_srv_conf_t  *iscf;

    iscf = njt_pcalloc(cf->pool, sizeof(njt_mail_imap_srv_conf_t));
    if (iscf == NULL) {
        return NULL;
    }

    iscf->client_buffer_size = NJT_CONF_UNSET_SIZE;

    if (njt_array_init(&iscf->capabilities, cf->pool, 4, sizeof(njt_str_t))
        != NJT_OK)
    {
        return NULL;
    }

    return iscf;
}


static char *
njt_mail_imap_merge_srv_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_mail_imap_srv_conf_t *prev = parent;
    njt_mail_imap_srv_conf_t *conf = child;

    u_char      *p, *auth;
    size_t       size;
    njt_str_t   *c, *d;
    njt_uint_t   i, m;

    njt_conf_merge_size_value(conf->client_buffer_size,
                              prev->client_buffer_size,
                              (size_t) njt_pagesize);

    njt_conf_merge_bitmask_value(conf->auth_methods,
                              prev->auth_methods,
                              (NJT_CONF_BITMASK_SET
                               |NJT_MAIL_AUTH_PLAIN_ENABLED));


    if (conf->capabilities.nelts == 0) {
        conf->capabilities = prev->capabilities;
    }

    if (conf->capabilities.nelts == 0) {

        for (d = njt_mail_imap_default_capabilities; d->len; d++) {
            c = njt_array_push(&conf->capabilities);
            if (c == NULL) {
                return NJT_CONF_ERROR;
            }

            *c = *d;
        }
    }

    size = sizeof("* CAPABILITY" CRLF) - 1;

    c = conf->capabilities.elts;
    for (i = 0; i < conf->capabilities.nelts; i++) {
        size += 1 + c[i].len;
    }

    for (m = NJT_MAIL_AUTH_PLAIN_ENABLED, i = 0;
         m <= NJT_MAIL_AUTH_EXTERNAL_ENABLED;
         m <<= 1, i++)
    {
        if (m & conf->auth_methods) {
            size += 1 + njt_mail_imap_auth_methods_names[i].len;
        }
    }

    p = njt_pnalloc(cf->pool, size);
    if (p == NULL) {
        return NJT_CONF_ERROR;
    }

    conf->capability.len = size;
    conf->capability.data = p;

    p = njt_cpymem(p, "* CAPABILITY", sizeof("* CAPABILITY") - 1);

    for (i = 0; i < conf->capabilities.nelts; i++) {
        *p++ = ' ';
        p = njt_cpymem(p, c[i].data, c[i].len);
    }

    auth = p;

    for (m = NJT_MAIL_AUTH_PLAIN_ENABLED, i = 0;
         m <= NJT_MAIL_AUTH_EXTERNAL_ENABLED;
         m <<= 1, i++)
    {
        if (m & conf->auth_methods) {
            *p++ = ' ';
            p = njt_cpymem(p, njt_mail_imap_auth_methods_names[i].data,
                           njt_mail_imap_auth_methods_names[i].len);
        }
    }

    *p++ = CR; *p = LF;


    size += sizeof(" STARTTLS") - 1;

    p = njt_pnalloc(cf->pool, size);
    if (p == NULL) {
        return NJT_CONF_ERROR;
    }

    conf->starttls_capability.len = size;
    conf->starttls_capability.data = p;

    p = njt_cpymem(p, conf->capability.data,
                   conf->capability.len - (sizeof(CRLF) - 1));
    p = njt_cpymem(p, " STARTTLS", sizeof(" STARTTLS") - 1);
    *p++ = CR; *p = LF;


    size = (auth - conf->capability.data) + sizeof(CRLF) - 1
            + sizeof(" STARTTLS LOGINDISABLED") - 1;

    p = njt_pnalloc(cf->pool, size);
    if (p == NULL) {
        return NJT_CONF_ERROR;
    }

    conf->starttls_only_capability.len = size;
    conf->starttls_only_capability.data = p;

    p = njt_cpymem(p, conf->capability.data,
                   auth - conf->capability.data);
    p = njt_cpymem(p, " STARTTLS LOGINDISABLED",
                   sizeof(" STARTTLS LOGINDISABLED") - 1);
    *p++ = CR; *p = LF;

    return NJT_CONF_OK;
}
