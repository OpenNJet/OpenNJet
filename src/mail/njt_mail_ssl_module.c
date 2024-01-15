
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_mail.h>


#define NJT_DEFAULT_CIPHERS     "HIGH:!aNULL:!MD5"
#define NJT_DEFAULT_ECDH_CURVE  "auto"


#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
static int njt_mail_ssl_alpn_select(njt_ssl_conn_t *ssl_conn,
    const unsigned char **out, unsigned char *outlen,
    const unsigned char *in, unsigned int inlen, void *arg);
#endif

static void *njt_mail_ssl_create_conf(njt_conf_t *cf);
static char *njt_mail_ssl_merge_conf(njt_conf_t *cf, void *parent, void *child);

static char *njt_mail_ssl_starttls(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_mail_ssl_password_file(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_mail_ssl_session_cache(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);

static char *njt_mail_ssl_conf_command_check(njt_conf_t *cf, void *post,
    void *data);


static njt_conf_enum_t  njt_mail_starttls_state[] = {
    { njt_string("off"), NJT_MAIL_STARTTLS_OFF },
    { njt_string("on"), NJT_MAIL_STARTTLS_ON },
    { njt_string("only"), NJT_MAIL_STARTTLS_ONLY },
    { njt_null_string, 0 }
};



static njt_conf_bitmask_t  njt_mail_ssl_protocols[] = {
    { njt_string("SSLv2"), NJT_SSL_SSLv2 },
    { njt_string("SSLv3"), NJT_SSL_SSLv3 },
    { njt_string("TLSv1"), NJT_SSL_TLSv1 },
    { njt_string("TLSv1.1"), NJT_SSL_TLSv1_1 },
    { njt_string("TLSv1.2"), NJT_SSL_TLSv1_2 },
    { njt_string("TLSv1.3"), NJT_SSL_TLSv1_3 },
    { njt_null_string, 0 }
};


static njt_conf_enum_t  njt_mail_ssl_verify[] = {
    { njt_string("off"), 0 },
    { njt_string("on"), 1 },
    { njt_string("optional"), 2 },
    { njt_string("optional_no_ca"), 3 },
    { njt_null_string, 0 }
};


static njt_conf_post_t  njt_mail_ssl_conf_command_post =
    { njt_mail_ssl_conf_command_check };


static njt_command_t  njt_mail_ssl_commands[] = {

    { njt_string("starttls"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_TAKE1,
      njt_mail_ssl_starttls,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_ssl_conf_t, starttls),
      njt_mail_starttls_state },

    { njt_string("ssl_certificate"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_array_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_ssl_conf_t, certificates),
      NULL },

    { njt_string("ssl_certificate_key"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_array_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_ssl_conf_t, certificate_keys),
      NULL },

    { njt_string("ssl_password_file"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_TAKE1,
      njt_mail_ssl_password_file,
      NJT_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("ssl_dhparam"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_ssl_conf_t, dhparam),
      NULL },

    { njt_string("ssl_ecdh_curve"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_ssl_conf_t, ecdh_curve),
      NULL },

    { njt_string("ssl_protocols"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_ssl_conf_t, protocols),
      &njt_mail_ssl_protocols },

    { njt_string("ssl_ciphers"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_ssl_conf_t, ciphers),
      NULL },

    { njt_string("ssl_prefer_server_ciphers"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_ssl_conf_t, prefer_server_ciphers),
      NULL },

    { njt_string("ssl_session_cache"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_TAKE12,
      njt_mail_ssl_session_cache,
      NJT_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("ssl_session_tickets"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_ssl_conf_t, session_tickets),
      NULL },

    { njt_string("ssl_session_ticket_key"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_array_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_ssl_conf_t, session_ticket_keys),
      NULL },

    { njt_string("ssl_session_timeout"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_sec_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_ssl_conf_t, session_timeout),
      NULL },

    { njt_string("ssl_verify_client"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_enum_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_ssl_conf_t, verify),
      &njt_mail_ssl_verify },

    { njt_string("ssl_verify_depth"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_ssl_conf_t, verify_depth),
      NULL },

    { njt_string("ssl_client_certificate"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_ssl_conf_t, client_certificate),
      NULL },

    { njt_string("ssl_trusted_certificate"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_ssl_conf_t, trusted_certificate),
      NULL },

    { njt_string("ssl_crl"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_ssl_conf_t, crl),
      NULL },

    { njt_string("ssl_conf_command"),
      NJT_MAIL_MAIN_CONF|NJT_MAIL_SRV_CONF|NJT_CONF_TAKE2,
      njt_conf_set_keyval_slot,
      NJT_MAIL_SRV_CONF_OFFSET,
      offsetof(njt_mail_ssl_conf_t, conf_commands),
      &njt_mail_ssl_conf_command_post },

      njt_null_command
};


static njt_mail_module_t  njt_mail_ssl_module_ctx = {
    NULL,                                  /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    njt_mail_ssl_create_conf,              /* create server configuration */
    njt_mail_ssl_merge_conf                /* merge server configuration */
};


njt_module_t  njt_mail_ssl_module = {
    NJT_MODULE_V1,
    &njt_mail_ssl_module_ctx,              /* module context */
    njt_mail_ssl_commands,                 /* module directives */
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


static njt_str_t njt_mail_ssl_sess_id_ctx = njt_string("MAIL");


#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation

static int
njt_mail_ssl_alpn_select(njt_ssl_conn_t *ssl_conn, const unsigned char **out,
    unsigned char *outlen, const unsigned char *in, unsigned int inlen,
    void *arg)
{
    unsigned int               srvlen;
    unsigned char             *srv;
    njt_connection_t          *c;
    njt_mail_session_t        *s;
    njt_mail_core_srv_conf_t  *cscf;
#if (NJT_DEBUG)
    unsigned int               i;
#endif

    c = njt_ssl_get_connection(ssl_conn);
    s = c->data;

#if (NJT_DEBUG)
    for (i = 0; i < inlen; i += in[i] + 1) {
        njt_log_debug2(NJT_LOG_DEBUG_MAIL, c->log, 0,
                       "SSL ALPN supported by client: %*s",
                       (size_t) in[i], &in[i + 1]);
    }
#endif

    cscf = njt_mail_get_module_srv_conf(s, njt_mail_core_module);

    srv = cscf->protocol->alpn.data;
    srvlen = cscf->protocol->alpn.len;

    if (SSL_select_next_proto((unsigned char **) out, outlen, srv, srvlen,
                              in, inlen)
        != OPENSSL_NPN_NEGOTIATED)
    {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    njt_log_debug2(NJT_LOG_DEBUG_MAIL, c->log, 0,
                   "SSL ALPN selected: %*s", (size_t) *outlen, *out);

    return SSL_TLSEXT_ERR_OK;
}

#endif


static void *
njt_mail_ssl_create_conf(njt_conf_t *cf)
{
    njt_mail_ssl_conf_t  *scf;

    scf = njt_pcalloc(cf->pool, sizeof(njt_mail_ssl_conf_t));
    if (scf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     scf->listen = 0;
     *     scf->protocols = 0;
     *     scf->dhparam = { 0, NULL };
     *     scf->ecdh_curve = { 0, NULL };
     *     scf->client_certificate = { 0, NULL };
     *     scf->trusted_certificate = { 0, NULL };
     *     scf->crl = { 0, NULL };
     *     scf->ciphers = { 0, NULL };
     *     scf->shm_zone = NULL;
     */

    scf->starttls = NJT_CONF_UNSET_UINT;
    scf->certificates = NJT_CONF_UNSET_PTR;
    scf->certificate_keys = NJT_CONF_UNSET_PTR;
    scf->passwords = NJT_CONF_UNSET_PTR;
    scf->conf_commands = NJT_CONF_UNSET_PTR;
    scf->prefer_server_ciphers = NJT_CONF_UNSET;
    scf->verify = NJT_CONF_UNSET_UINT;
    scf->verify_depth = NJT_CONF_UNSET_UINT;
    scf->builtin_session_cache = NJT_CONF_UNSET;
    scf->session_timeout = NJT_CONF_UNSET;
    scf->session_tickets = NJT_CONF_UNSET;
    scf->session_ticket_keys = NJT_CONF_UNSET_PTR;

    return scf;
}


static char *
njt_mail_ssl_merge_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_mail_ssl_conf_t *prev = parent;
    njt_mail_ssl_conf_t *conf = child;

    char                *mode;
    njt_pool_cleanup_t  *cln;

    njt_conf_merge_uint_value(conf->starttls, prev->starttls,
                         NJT_MAIL_STARTTLS_OFF);

    njt_conf_merge_value(conf->session_timeout,
                         prev->session_timeout, 300);

    njt_conf_merge_value(conf->prefer_server_ciphers,
                         prev->prefer_server_ciphers, 0);

    njt_conf_merge_bitmask_value(conf->protocols, prev->protocols,
                         (NJT_CONF_BITMASK_SET
                          |NJT_SSL_TLSv1|NJT_SSL_TLSv1_1
                          |NJT_SSL_TLSv1_2|NJT_SSL_TLSv1_3));

    njt_conf_merge_uint_value(conf->verify, prev->verify, 0);
    njt_conf_merge_uint_value(conf->verify_depth, prev->verify_depth, 1);

    njt_conf_merge_ptr_value(conf->certificates, prev->certificates, NULL);
    njt_conf_merge_ptr_value(conf->certificate_keys, prev->certificate_keys,
                         NULL);

    njt_conf_merge_ptr_value(conf->passwords, prev->passwords, NULL);

    njt_conf_merge_str_value(conf->dhparam, prev->dhparam, "");

    njt_conf_merge_str_value(conf->ecdh_curve, prev->ecdh_curve,
                         NJT_DEFAULT_ECDH_CURVE);

    njt_conf_merge_str_value(conf->client_certificate,
                         prev->client_certificate, "");
    njt_conf_merge_str_value(conf->trusted_certificate,
                         prev->trusted_certificate, "");
    njt_conf_merge_str_value(conf->crl, prev->crl, "");

    njt_conf_merge_str_value(conf->ciphers, prev->ciphers, NJT_DEFAULT_CIPHERS);

    njt_conf_merge_ptr_value(conf->conf_commands, prev->conf_commands, NULL);


    conf->ssl.log = cf->log;

    if (conf->listen) {
        mode = "listen ... ssl";

    } else if (conf->starttls != NJT_MAIL_STARTTLS_OFF) {
        mode = "starttls";

    } else {
        return NJT_CONF_OK;
    }

    if (conf->file == NULL) {
        conf->file = prev->file;
        conf->line = prev->line;
    }

    if (conf->certificates == NULL) {
        njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                      "no \"ssl_certificate\" is defined for "
                      "the \"%s\" directive in %s:%ui",
                      mode, conf->file, conf->line);
        return NJT_CONF_ERROR;
    }

    if (conf->certificate_keys == NULL) {
        njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                      "no \"ssl_certificate_key\" is defined for "
                      "the \"%s\" directive in %s:%ui",
                      mode, conf->file, conf->line);
        return NJT_CONF_ERROR;
    }

    if (conf->certificate_keys->nelts < conf->certificates->nelts) {
        njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                      "no \"ssl_certificate_key\" is defined "
                      "for certificate \"%V\" and "
                      "the \"%s\" directive in %s:%ui",
                      ((njt_str_t *) conf->certificates->elts)
                      + conf->certificates->nelts - 1,
                      mode, conf->file, conf->line);
        return NJT_CONF_ERROR;
    }

    if (njt_ssl_create(&conf->ssl, conf->protocols, NULL) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    cln = njt_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        njt_ssl_cleanup_ctx(&conf->ssl);
        return NJT_CONF_ERROR;
    }

    cln->handler = njt_ssl_cleanup_ctx;
    cln->data = &conf->ssl;

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
    SSL_CTX_set_alpn_select_cb(conf->ssl.ctx, njt_mail_ssl_alpn_select, NULL);
#endif

    if (njt_ssl_ciphers(cf, &conf->ssl, &conf->ciphers,
                        conf->prefer_server_ciphers)
        != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    if (njt_ssl_certificates(cf, &conf->ssl, conf->certificates,
                             conf->certificate_keys, conf->passwords)
        != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    if (conf->verify) {

        if (conf->client_certificate.len == 0 && conf->verify != 3) {
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "no ssl_client_certificate for ssl_verify_client");
            return NJT_CONF_ERROR;
        }

        if (njt_ssl_client_certificate(cf, &conf->ssl,
                                       &conf->client_certificate,
                                       conf->verify_depth)
            != NJT_OK)
        {
            return NJT_CONF_ERROR;
        }

        if (njt_ssl_trusted_certificate(cf, &conf->ssl,
                                        &conf->trusted_certificate,
                                        conf->verify_depth)
            != NJT_OK)
        {
            return NJT_CONF_ERROR;
        }

        if (njt_ssl_crl(cf, &conf->ssl, &conf->crl) != NJT_OK) {
            return NJT_CONF_ERROR;
        }
    }

    if (njt_ssl_dhparam(cf, &conf->ssl, &conf->dhparam) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    if (njt_ssl_ecdh_curve(cf, &conf->ssl, &conf->ecdh_curve) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    njt_conf_merge_value(conf->builtin_session_cache,
                         prev->builtin_session_cache, NJT_SSL_NONE_SCACHE);

    if (conf->shm_zone == NULL) {
        conf->shm_zone = prev->shm_zone;
    }

    if (njt_ssl_session_cache(&conf->ssl, &njt_mail_ssl_sess_id_ctx,
                              conf->certificates, conf->builtin_session_cache,
                              conf->shm_zone, conf->session_timeout)
        != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    njt_conf_merge_value(conf->session_tickets,
                         prev->session_tickets, 1);

#ifdef SSL_OP_NO_TICKET
    if (!conf->session_tickets) {
        SSL_CTX_set_options(conf->ssl.ctx, SSL_OP_NO_TICKET);
    }
#endif

    njt_conf_merge_ptr_value(conf->session_ticket_keys,
                         prev->session_ticket_keys, NULL);

    if (njt_ssl_session_ticket_keys(cf, &conf->ssl, conf->session_ticket_keys)
        != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    if (njt_ssl_conf_commands(cf, &conf->ssl, conf->conf_commands) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static char *
njt_mail_ssl_starttls(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_mail_ssl_conf_t  *scf = conf;

    char  *rv;

    rv = njt_conf_set_enum_slot(cf, cmd, conf);

    if (rv != NJT_CONF_OK) {
        return rv;
    }

    if (!scf->listen) {
        scf->file = cf->conf_file->file.name.data;
        scf->line = cf->conf_file->line;
    }

    return NJT_CONF_OK;
}


static char *
njt_mail_ssl_password_file(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_mail_ssl_conf_t  *scf = conf;

    njt_str_t  *value;

    if (scf->passwords != NJT_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    scf->passwords = njt_ssl_read_password_file(cf, &value[1]);

    if (scf->passwords == NULL) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static char *
njt_mail_ssl_session_cache(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_mail_ssl_conf_t  *scf = conf;

    size_t       len;
    njt_str_t   *value, name, size;
    njt_int_t    n;
    njt_uint_t   i, j;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (njt_strcmp(value[i].data, "off") == 0) {
            scf->builtin_session_cache = NJT_SSL_NO_SCACHE;
            continue;
        }

        if (njt_strcmp(value[i].data, "none") == 0) {
            scf->builtin_session_cache = NJT_SSL_NONE_SCACHE;
            continue;
        }

        if (njt_strcmp(value[i].data, "builtin") == 0) {
            scf->builtin_session_cache = NJT_SSL_DFLT_BUILTIN_SCACHE;
            continue;
        }

        if (value[i].len > sizeof("builtin:") - 1
            && njt_strncmp(value[i].data, "builtin:", sizeof("builtin:") - 1)
               == 0)
        {
            n = njt_atoi(value[i].data + sizeof("builtin:") - 1,
                         value[i].len - (sizeof("builtin:") - 1));

            if (n == NJT_ERROR) {
                goto invalid;
            }

            scf->builtin_session_cache = n;

            continue;
        }

        if (value[i].len > sizeof("shared:") - 1
            && njt_strncmp(value[i].data, "shared:", sizeof("shared:") - 1)
               == 0)
        {
            len = 0;

            for (j = sizeof("shared:") - 1; j < value[i].len; j++) {
                if (value[i].data[j] == ':') {
                    break;
                }

                len++;
            }

            if (len == 0 || j == value[i].len) {
                goto invalid;
            }

            name.len = len;
            name.data = value[i].data + sizeof("shared:") - 1;

            size.len = value[i].len - j - 1;
            size.data = name.data + len + 1;

            n = njt_parse_size(&size);

            if (n == NJT_ERROR) {
                goto invalid;
            }

            if (n < (njt_int_t) (8 * njt_pagesize)) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "session cache \"%V\" is too small",
                                   &value[i]);

                return NJT_CONF_ERROR;
            }

            scf->shm_zone = njt_shared_memory_add(cf, &name, n,
                                                   &njt_mail_ssl_module);
            if (scf->shm_zone == NULL) {
                return NJT_CONF_ERROR;
            }

            scf->shm_zone->init = njt_ssl_session_cache_init;

            continue;
        }

        goto invalid;
    }

    if (scf->shm_zone && scf->builtin_session_cache == NJT_CONF_UNSET) {
        scf->builtin_session_cache = NJT_SSL_NO_BUILTIN_SCACHE;
    }

    return NJT_CONF_OK;

invalid:

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "invalid session cache \"%V\"", &value[i]);

    return NJT_CONF_ERROR;
}


static char *
njt_mail_ssl_conf_command_check(njt_conf_t *cf, void *post, void *data)
{
#ifndef SSL_CONF_FLAG_FILE
    return "is not supported on this platform";
#else
    return NJT_CONF_OK;
#endif
}
