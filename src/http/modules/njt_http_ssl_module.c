
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>

#if (NJT_QUIC_OPENSSL_COMPAT)
#include <njt_event_quic_openssl_compat.h>
#endif


typedef njt_int_t (*njt_ssl_variable_handler_pt)(njt_connection_t *c,
    njt_pool_t *pool, njt_str_t *s);


#define NJT_DEFAULT_CIPHERS     "HIGH:!aNULL:!MD5"
#define NJT_DEFAULT_ECDH_CURVE  "auto"

#define NJT_HTTP_ALPN_PROTOS    "\x08http/1.1\x08http/1.0\x08http/0.9"


#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
static int njt_http_ssl_alpn_select(njt_ssl_conn_t *ssl_conn,
    const unsigned char **out, unsigned char *outlen,
    const unsigned char *in, unsigned int inlen, void *arg);
#endif

static njt_int_t njt_http_ssl_static_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_ssl_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);

static njt_int_t njt_http_ssl_add_variables(njt_conf_t *cf);
static void *njt_http_ssl_create_srv_conf(njt_conf_t *cf);
static char *njt_http_ssl_merge_srv_conf(njt_conf_t *cf,
    void *parent, void *child);

#if (!defined(NJT_HTTP_MULTICERT))
static njt_int_t njt_http_ssl_compile_certificates(njt_conf_t *cf,
    njt_http_ssl_srv_conf_t *conf);
#endif

#if (NJT_HAVE_SET_ALPN)
static char *
njt_http_ssl_alpn(njt_conf_t *cf, njt_command_t *cmd, void *conf);
#endif


static char *njt_http_ssl_password_file(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_ssl_session_cache(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_ssl_ocsp_cache(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);

static char *njt_http_ssl_conf_command_check(njt_conf_t *cf, void *post,
    void *data);

static njt_int_t njt_http_ssl_init(njt_conf_t *cf);
#if (NJT_QUIC_OPENSSL_COMPAT)
static njt_int_t njt_http_ssl_quic_compat_init(njt_conf_t *cf,
    njt_http_conf_addr_t *addr);
static njt_int_t
njt_http_ssl_quic_compat_dynamic_init(njt_conf_t *cf, njt_http_conf_addr_t *addr);    
#endif


static njt_conf_bitmask_t  njt_http_ssl_protocols[] = {
    { njt_string("SSLv2"), NJT_SSL_SSLv2 },
    { njt_string("SSLv3"), NJT_SSL_SSLv3 },
    { njt_string("TLSv1"), NJT_SSL_TLSv1 },
    { njt_string("TLSv1.1"), NJT_SSL_TLSv1_1 },
    { njt_string("TLSv1.2"), NJT_SSL_TLSv1_2 },
    { njt_string("TLSv1.3"), NJT_SSL_TLSv1_3 },
    { njt_null_string, 0 }
};


static njt_conf_enum_t  njt_http_ssl_verify[] = {
    { njt_string("off"), 0 },
    { njt_string("on"), 1 },
    { njt_string("optional"), 2 },
    { njt_string("optional_no_ca"), 3 },
    { njt_null_string, 0 }
};


static njt_conf_enum_t  njt_http_ssl_ocsp[] = {
    { njt_string("off"), 0 },
    { njt_string("on"), 1 },
    { njt_string("leaf"), 2 },
    { njt_null_string, 0 }
};


static njt_conf_post_t  njt_http_ssl_conf_command_post =
    { njt_http_ssl_conf_command_check };


static njt_command_t  njt_http_ssl_commands[] = {

#if (NJT_HTTP_MULTICERT)
    { njt_string("ssl_certificate"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE12,
       njt_ssl_certificate_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_ssl_srv_conf_t, certificates),
      NULL },

    { njt_string("ssl_certificate_key"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE12,
      njt_ssl_certificate_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_ssl_srv_conf_t, certificate_keys),
      NULL },
#else

    { njt_string("ssl_certificate"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_array_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_ssl_srv_conf_t, certificates),
      NULL },

    { njt_string("ssl_certificate_key"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_array_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_ssl_srv_conf_t, certificate_keys),
      NULL },

#endif

    { njt_string("ssl_password_file"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_http_ssl_password_file,
      NJT_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("ssl_dhparam"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_ssl_srv_conf_t, dhparam),
      NULL },

    { njt_string("ssl_ecdh_curve"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_ssl_srv_conf_t, ecdh_curve),
      NULL },

    { njt_string("ssl_protocols"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_ssl_srv_conf_t, protocols),
      &njt_http_ssl_protocols },

    { njt_string("ssl_ciphers"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_ssl_srv_conf_t, ciphers),
      NULL },

    { njt_string("ssl_buffer_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_ssl_srv_conf_t, buffer_size),
      NULL },

    { njt_string("ssl_verify_client"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_enum_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_ssl_srv_conf_t, verify),
      &njt_http_ssl_verify },

    { njt_string("ssl_verify_depth"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_ssl_srv_conf_t, verify_depth),
      NULL },

    { njt_string("ssl_client_certificate"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_ssl_srv_conf_t, client_certificate),
      NULL },

    { njt_string("ssl_trusted_certificate"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_ssl_srv_conf_t, trusted_certificate),
      NULL },

    { njt_string("ssl_prefer_server_ciphers"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_ssl_srv_conf_t, prefer_server_ciphers),
      NULL },

    { njt_string("ssl_session_cache"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE12,
      njt_http_ssl_session_cache,
      NJT_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("ssl_session_tickets"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_ssl_srv_conf_t, session_tickets),
      NULL },

    { njt_string("ssl_session_ticket_key"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_array_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_ssl_srv_conf_t, session_ticket_keys),
      NULL },

    { njt_string("ssl_session_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_sec_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_ssl_srv_conf_t, session_timeout),
      NULL },

    { njt_string("ssl_crl"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_ssl_srv_conf_t, crl),
      NULL },

    { njt_string("ssl_ocsp"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_enum_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_ssl_srv_conf_t, ocsp),
      &njt_http_ssl_ocsp },

    { njt_string("ssl_ocsp_responder"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_ssl_srv_conf_t, ocsp_responder),
      NULL },

    { njt_string("ssl_ocsp_cache"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_http_ssl_ocsp_cache,
      NJT_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("ssl_stapling"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_ssl_srv_conf_t, stapling),
      NULL },

    { njt_string("ssl_stapling_file"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_ssl_srv_conf_t, stapling_file),
      NULL },

    { njt_string("ssl_stapling_responder"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_ssl_srv_conf_t, stapling_responder),
      NULL },

    { njt_string("ssl_stapling_verify"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_ssl_srv_conf_t, stapling_verify),
      NULL },

    { njt_string("ssl_early_data"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_ssl_srv_conf_t, early_data),
      NULL },

    { njt_string("ssl_conf_command"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE2,
      njt_conf_set_keyval_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_ssl_srv_conf_t, conf_commands),
      &njt_http_ssl_conf_command_post },

    { njt_string("ssl_reject_handshake"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_ssl_srv_conf_t, reject_handshake),
      NULL },

#if (NJT_HAVE_NTLS)
    { njt_string("ssl_ntls"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_ssl_srv_conf_t, ntls),
      NULL },
#endif
#if (NJT_HAVE_SET_ALPN)
    { njt_string("ssl_alpn"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_1MORE,
      njt_http_ssl_alpn,
      NJT_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },
#endif

      njt_null_command
};


static njt_http_module_t  njt_http_ssl_module_ctx = {
    njt_http_ssl_add_variables,            /* preconfiguration */
    njt_http_ssl_init,                     /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    njt_http_ssl_create_srv_conf,          /* create server configuration */
    njt_http_ssl_merge_srv_conf,           /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


njt_module_t  njt_http_ssl_module = {
    NJT_MODULE_V1,
    &njt_http_ssl_module_ctx,              /* module context */
    njt_http_ssl_commands,                 /* module directives */
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


static njt_http_variable_t  njt_http_ssl_vars[] = {

    { njt_string("ssl_protocol"), NULL, njt_http_ssl_static_variable,
      (uintptr_t) njt_ssl_get_protocol, NJT_HTTP_VAR_CHANGEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("ssl_cipher"), NULL, njt_http_ssl_static_variable,
      (uintptr_t) njt_ssl_get_cipher_name, NJT_HTTP_VAR_CHANGEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("ssl_ciphers"), NULL, njt_http_ssl_variable,
      (uintptr_t) njt_ssl_get_ciphers, NJT_HTTP_VAR_CHANGEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("ssl_curve"), NULL, njt_http_ssl_variable,
      (uintptr_t) njt_ssl_get_curve, NJT_HTTP_VAR_CHANGEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("ssl_curves"), NULL, njt_http_ssl_variable,
      (uintptr_t) njt_ssl_get_curves, NJT_HTTP_VAR_CHANGEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("ssl_session_id"), NULL, njt_http_ssl_variable,
      (uintptr_t) njt_ssl_get_session_id, NJT_HTTP_VAR_CHANGEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("ssl_session_reused"), NULL, njt_http_ssl_variable,
      (uintptr_t) njt_ssl_get_session_reused, NJT_HTTP_VAR_CHANGEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("ssl_early_data"), NULL, njt_http_ssl_variable,
      (uintptr_t) njt_ssl_get_early_data,
      NJT_HTTP_VAR_CHANGEABLE|NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("ssl_server_name"), NULL, njt_http_ssl_variable,
      (uintptr_t) njt_ssl_get_server_name, NJT_HTTP_VAR_CHANGEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("ssl_alpn_protocol"), NULL, njt_http_ssl_variable,
      (uintptr_t) njt_ssl_get_alpn_protocol, NJT_HTTP_VAR_CHANGEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("ssl_client_cert"), NULL, njt_http_ssl_variable,
      (uintptr_t) njt_ssl_get_certificate, NJT_HTTP_VAR_CHANGEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("ssl_client_raw_cert"), NULL, njt_http_ssl_variable,
      (uintptr_t) njt_ssl_get_raw_certificate,
      NJT_HTTP_VAR_CHANGEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("ssl_client_escaped_cert"), NULL, njt_http_ssl_variable,
      (uintptr_t) njt_ssl_get_escaped_certificate,
      NJT_HTTP_VAR_CHANGEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("ssl_client_s_dn"), NULL, njt_http_ssl_variable,
      (uintptr_t) njt_ssl_get_subject_dn, NJT_HTTP_VAR_CHANGEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("ssl_client_i_dn"), NULL, njt_http_ssl_variable,
      (uintptr_t) njt_ssl_get_issuer_dn, NJT_HTTP_VAR_CHANGEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("ssl_client_s_dn_legacy"), NULL, njt_http_ssl_variable,
      (uintptr_t) njt_ssl_get_subject_dn_legacy, NJT_HTTP_VAR_CHANGEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("ssl_client_i_dn_legacy"), NULL, njt_http_ssl_variable,
      (uintptr_t) njt_ssl_get_issuer_dn_legacy, NJT_HTTP_VAR_CHANGEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("ssl_client_serial"), NULL, njt_http_ssl_variable,
      (uintptr_t) njt_ssl_get_serial_number, NJT_HTTP_VAR_CHANGEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("ssl_client_fingerprint"), NULL, njt_http_ssl_variable,
      (uintptr_t) njt_ssl_get_fingerprint, NJT_HTTP_VAR_CHANGEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("ssl_client_verify"), NULL, njt_http_ssl_variable,
      (uintptr_t) njt_ssl_get_client_verify, NJT_HTTP_VAR_CHANGEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("ssl_client_v_start"), NULL, njt_http_ssl_variable,
      (uintptr_t) njt_ssl_get_client_v_start, NJT_HTTP_VAR_CHANGEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("ssl_client_v_end"), NULL, njt_http_ssl_variable,
      (uintptr_t) njt_ssl_get_client_v_end, NJT_HTTP_VAR_CHANGEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("ssl_client_v_remain"), NULL, njt_http_ssl_variable,
      (uintptr_t) njt_ssl_get_client_v_remain, NJT_HTTP_VAR_CHANGEABLE, 0, NJT_VAR_INIT_REF_COUNT },

      njt_http_null_variable
};


static njt_str_t njt_http_ssl_sess_id_ctx = njt_string("HTTP");


#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation

static int
njt_http_ssl_alpn_select(njt_ssl_conn_t *ssl_conn, const unsigned char **out,
    unsigned char *outlen, const unsigned char *in, unsigned int inlen,
    void *arg)
{
    unsigned int             srvlen;
    unsigned char           *srv;
#if (NJT_DEBUG)
    unsigned int             i;
#endif
#if (NJT_HTTP_V2 || NJT_HTTP_V3)
    njt_http_connection_t   *hc;
#endif
#if (NJT_HTTP_V2) 
    njt_http_v2_srv_conf_t  *h2scf;
#endif
#if (NJT_HTTP_V3)
    njt_http_v3_srv_conf_t  *h3scf;
#endif
#if (NJT_HTTP_V2 || HTTP_V3_|| NJT_DEBUG)
    njt_connection_t       *c;

    c = njt_ssl_get_connection(ssl_conn);
#endif

#if (NJT_DEBUG)
    for (i = 0; i < inlen; i += in[i] + 1) {
        njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "SSL ALPN supported by client: %*s",
                       (size_t) in[i], &in[i + 1]);
    }
#endif

#if (NJT_HTTP_V2 || NJT_HTTP_V3)
    hc = c->data;
#endif

#if (NJT_HTTP_V3)
    if (hc->addr_conf->quic) {

        h3scf = njt_http_get_module_srv_conf(hc->conf_ctx, njt_http_v3_module);

        if (h3scf->enable && h3scf->enable_hq) {
            srv = (unsigned char *) NJT_HTTP_V3_ALPN_PROTO
                                    NJT_HTTP_V3_HQ_ALPN_PROTO;
            srvlen = sizeof(NJT_HTTP_V3_ALPN_PROTO NJT_HTTP_V3_HQ_ALPN_PROTO)
                     - 1;

        } else if (h3scf->enable_hq) {
            srv = (unsigned char *) NJT_HTTP_V3_HQ_ALPN_PROTO;
            srvlen = sizeof(NJT_HTTP_V3_HQ_ALPN_PROTO) - 1;

        } else if (h3scf->enable || hc->addr_conf->http3) {
            srv = (unsigned char *) NJT_HTTP_V3_ALPN_PROTO;
            srvlen = sizeof(NJT_HTTP_V3_ALPN_PROTO) - 1;

        } else {
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }

    } else
#endif
    {
#if (NJT_HTTP_V2)
        h2scf = njt_http_get_module_srv_conf(hc->conf_ctx, njt_http_v2_module);

        if (h2scf->enable || hc->addr_conf->http2) {
            srv = (unsigned char *) NJT_HTTP_V2_ALPN_PROTO NJT_HTTP_ALPN_PROTOS;
            srvlen = sizeof(NJT_HTTP_V2_ALPN_PROTO NJT_HTTP_ALPN_PROTOS) - 1;

        } else
#endif
        {
            srv = (unsigned char *) NJT_HTTP_ALPN_PROTOS;
            srvlen = sizeof(NJT_HTTP_ALPN_PROTOS) - 1;
        }
    }
#if (NJT_HAVE_SET_ALPN)
    njt_http_ssl_srv_conf_t  *sscf;
    sscf = njt_http_get_module_srv_conf(hc->conf_ctx, njt_http_ssl_module);
    if(sscf != NULL && sscf->alpn.len > 0) {
        srv = sscf->alpn.data;
        srvlen = sscf->alpn.len;

    }
#endif
    if (SSL_select_next_proto((unsigned char **) out, outlen, srv, srvlen,
                              in, inlen)
        != OPENSSL_NPN_NEGOTIATED)
    {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "SSL ALPN selected: %*s", (size_t) *outlen, *out);

    return SSL_TLSEXT_ERR_OK;
}

#endif


static njt_int_t
njt_http_ssl_static_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_ssl_variable_handler_pt  handler = (njt_ssl_variable_handler_pt) data;

    size_t     len;
    njt_str_t  s;

    if (r->connection->ssl) {

        (void) handler(r->connection, NULL, &s);

        v->data = s.data;

        for (len = 0; v->data[len]; len++) { /* void */ }

        v->len = len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;

        return NJT_OK;
    }

    v->not_found = 1;

    return NJT_OK;
}


static njt_int_t
njt_http_ssl_variable(njt_http_request_t *r, njt_http_variable_value_t *v,
    uintptr_t data)
{
    njt_ssl_variable_handler_pt  handler = (njt_ssl_variable_handler_pt) data;

    njt_str_t  s;

    if (r->connection->ssl) {

        if (handler(r->connection, r->pool, &s) != NJT_OK) {
            return NJT_ERROR;
        }

        v->len = s.len;
        v->data = s.data;

        if (v->len) {
            v->valid = 1;
            v->no_cacheable = 0;
            v->not_found = 0;

            return NJT_OK;
        }
    }

    v->not_found = 1;

    return NJT_OK;
}


static njt_int_t
njt_http_ssl_add_variables(njt_conf_t *cf)
{
    njt_http_variable_t  *var, *v;

    for (v = njt_http_ssl_vars; v->name.len; v++) {
        var = njt_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NJT_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NJT_OK;
}


static void *
njt_http_ssl_create_srv_conf(njt_conf_t *cf)
{
    njt_http_ssl_srv_conf_t  *sscf;

    sscf = njt_pcalloc(cf->pool, sizeof(njt_http_ssl_srv_conf_t));
    if (sscf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     sscf->protocols = 0;
     *     sscf->certificate_values = NULL;
     *     sscf->dhparam = { 0, NULL };
     *     sscf->ecdh_curve = { 0, NULL };
     *     sscf->client_certificate = { 0, NULL };
     *     sscf->trusted_certificate = { 0, NULL };
     *     sscf->crl = { 0, NULL };
     *     sscf->ciphers = { 0, NULL };
     *     sscf->shm_zone = NULL;
     *     sscf->ocsp_responder = { 0, NULL };
     *     sscf->stapling_file = { 0, NULL };
     *     sscf->stapling_responder = { 0, NULL };
     */

    sscf->prefer_server_ciphers = NJT_CONF_UNSET;
    sscf->early_data = NJT_CONF_UNSET;
    sscf->reject_handshake = NJT_CONF_UNSET;
    sscf->buffer_size = NJT_CONF_UNSET_SIZE;
    sscf->verify = NJT_CONF_UNSET_UINT;
    sscf->verify_depth = NJT_CONF_UNSET_UINT;
    sscf->certificates = NJT_CONF_UNSET_PTR;
    sscf->certificate_keys = NJT_CONF_UNSET_PTR;
    sscf->dyn_cert_crc32 = NJT_CONF_UNSET_PTR;   //add by clb
    sscf->cert_types = NJT_CONF_UNSET_PTR;   //add by clb
    sscf->passwords = NJT_CONF_UNSET_PTR;
    sscf->conf_commands = NJT_CONF_UNSET_PTR;
    sscf->builtin_session_cache = NJT_CONF_UNSET;
    sscf->session_timeout = NJT_CONF_UNSET;
    sscf->session_tickets = NJT_CONF_UNSET;
    sscf->session_ticket_keys = NJT_CONF_UNSET_PTR;
    sscf->ocsp = NJT_CONF_UNSET_UINT;
    sscf->ocsp_cache_zone = NJT_CONF_UNSET_PTR;
    sscf->stapling = NJT_CONF_UNSET;
    sscf->stapling_verify = NJT_CONF_UNSET;
#if (NJT_HAVE_NTLS)
    sscf->ntls = NJT_CONF_UNSET;
#endif

#if NJT_HTTP_DYNAMIC_SERVER
   sscf->pool = cf->pool;
#endif
    return sscf;
}


static char *
njt_http_ssl_merge_srv_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_ssl_srv_conf_t *prev = parent;
    njt_http_ssl_srv_conf_t *conf = child;

    njt_pool_cleanup_t  *cln;

    njt_conf_merge_value(conf->session_timeout,
                         prev->session_timeout, 300);

    njt_conf_merge_value(conf->prefer_server_ciphers,
                         prev->prefer_server_ciphers, 0);

    njt_conf_merge_value(conf->early_data, prev->early_data, 0);
    njt_conf_merge_value(conf->reject_handshake, prev->reject_handshake, 0);

    njt_conf_merge_bitmask_value(conf->protocols, prev->protocols,
                         (NJT_CONF_BITMASK_SET
                          |NJT_SSL_TLSv1|NJT_SSL_TLSv1_1
                          |NJT_SSL_TLSv1_2|NJT_SSL_TLSv1_3));

    njt_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                         NJT_SSL_BUFSIZE);

    njt_conf_merge_uint_value(conf->verify, prev->verify, 0);
    njt_conf_merge_uint_value(conf->verify_depth, prev->verify_depth, 1);

    njt_conf_merge_ptr_value(conf->certificates, prev->certificates, NULL);
    njt_conf_merge_ptr_value(conf->certificate_keys, prev->certificate_keys,
                         NULL);

    //add by clb
    njt_conf_merge_ptr_value(conf->dyn_cert_crc32, prev->dyn_cert_crc32,
                         NULL);
    njt_conf_merge_ptr_value(conf->cert_types, prev->cert_types,
                         NULL);

    njt_conf_merge_ptr_value(conf->passwords, prev->passwords, NULL);

    njt_conf_merge_str_value(conf->dhparam, prev->dhparam, "");

    njt_conf_merge_str_value(conf->client_certificate, prev->client_certificate,
                         "");
    njt_conf_merge_str_value(conf->trusted_certificate,
                         prev->trusted_certificate, "");
    njt_conf_merge_str_value(conf->crl, prev->crl, "");

    njt_conf_merge_str_value(conf->ecdh_curve, prev->ecdh_curve,
                         NJT_DEFAULT_ECDH_CURVE);

    njt_conf_merge_str_value(conf->ciphers, prev->ciphers, NJT_DEFAULT_CIPHERS);

    njt_conf_merge_ptr_value(conf->conf_commands, prev->conf_commands, NULL);

    njt_conf_merge_uint_value(conf->ocsp, prev->ocsp, 0);
    njt_conf_merge_str_value(conf->ocsp_responder, prev->ocsp_responder, "");
    njt_conf_merge_ptr_value(conf->ocsp_cache_zone,
                         prev->ocsp_cache_zone, NULL);

    njt_conf_merge_value(conf->stapling, prev->stapling, 0);
    njt_conf_merge_value(conf->stapling_verify, prev->stapling_verify, 0);
    njt_conf_merge_str_value(conf->stapling_file, prev->stapling_file, "");
    njt_conf_merge_str_value(conf->stapling_responder,
                         prev->stapling_responder, "");

#if (NJT_HAVE_NTLS)
    njt_conf_merge_value(conf->ntls, prev->ntls, 0);
#endif

    conf->ssl.log = cf->log;

    if (conf->certificates) {
        if (conf->certificate_keys == NULL
            || conf->certificate_keys->nelts < conf->certificates->nelts)
        {
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "no \"ssl_certificate_key\" is defined "
                          "for certificate \"%V\"",
                          ((njt_str_t *) conf->certificates->elts)
                          + conf->certificates->nelts - 1);
            return NJT_CONF_ERROR;
        }

    } else if (!conf->reject_handshake) {
        return NJT_CONF_OK;
    }

    if (njt_ssl_create(&conf->ssl, conf->protocols, conf) != NJT_OK) {
        return NJT_CONF_ERROR;
    }
#if NJT_HTTP_DYNAMIC_SERVER
    cln = njt_pool_cleanup_add(conf->pool, 0);
#else
    cln = njt_pool_cleanup_add(cf->pool, 0);
#endif
    if (cln == NULL) {
        njt_ssl_cleanup_ctx(&conf->ssl);
        return NJT_CONF_ERROR;
    }

    cln->handler = njt_ssl_cleanup_ctx;
    cln->data = &conf->ssl;
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

    if (SSL_CTX_set_tlsext_servername_callback(conf->ssl.ctx,
                                               njt_http_ssl_servername)
        == 0)
    {
        njt_log_error(NJT_LOG_WARN, cf->log, 0,
            "njet was built with SNI support, however, now it is linked "
            "dynamically to an OpenSSL library which has no tlsext support, "
            "therefore SNI is not available");
    }

#endif

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
    SSL_CTX_set_alpn_select_cb(conf->ssl.ctx, njt_http_ssl_alpn_select, NULL);
#endif

    if (njt_ssl_ciphers(cf, &conf->ssl, &conf->ciphers,
                        conf->prefer_server_ciphers)
        != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    if (njt_http_ssl_compile_certificates(cf, conf) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    if (conf->certificate_values) {

#ifdef SSL_R_CERT_CB_ERROR

        /* install callback to lookup certificates */

        SSL_CTX_set_cert_cb(conf->ssl.ctx, njt_http_ssl_certificate, conf);

#else
        njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                      "variables in "
                      "\"ssl_certificate\" and \"ssl_certificate_key\" "
                      "directives are not supported on this platform");
        return NJT_CONF_ERROR;
#endif

    } else if (conf->certificates) {

        /* configure certificates */

        if (njt_ssl_certificates(cf, &conf->ssl, conf->certificates,
                                 conf->certificate_keys, conf->passwords)
            != NJT_OK)
        {
            return NJT_CONF_ERROR;
        }

        if(conf->cert_types == NULL){
            conf->cert_types = njt_array_create(cf->pool, 4, sizeof(njt_uint_t));
            if(conf->cert_types == NULL){
                njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                    " ssl config, cert_type create error");

                return NJT_CONF_ERROR;
            }
        }

        if (njt_ssl_set_certificates_type(cf, &conf->ssl, conf->certificates,
                                 conf->certificate_keys, conf->cert_types)
            != NJT_OK)
        {
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                    " ssl config, cert_type set error");
            return NJT_CONF_ERROR;
        }
    }

    conf->ssl.buffer_size = conf->buffer_size;

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

    if (conf->ocsp) {

        if (conf->verify == 3) {
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "\"ssl_ocsp\" is incompatible with "
                          "\"ssl_verify_client optional_no_ca\"");
            return NJT_CONF_ERROR;
        }

        if (njt_ssl_ocsp(cf, &conf->ssl, &conf->ocsp_responder, conf->ocsp,
                         conf->ocsp_cache_zone)
            != NJT_OK)
        {
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

    if (njt_ssl_session_cache(&conf->ssl, &njt_http_ssl_sess_id_ctx,
                              conf->certificates, conf->builtin_session_cache,
                              conf->shm_zone, conf->session_timeout)
        != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    njt_conf_merge_value(conf->session_tickets, prev->session_tickets, 1);

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

    if (conf->stapling) {

        if (njt_ssl_stapling(cf, &conf->ssl, &conf->stapling_file,
                             &conf->stapling_responder, conf->stapling_verify)
            != NJT_OK)
        {
            return NJT_CONF_ERROR;
        }

    }

    if (njt_ssl_early_data(cf, &conf->ssl, conf->early_data) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    if (njt_ssl_conf_commands(cf, &conf->ssl, conf->conf_commands) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}

#if (NJT_HTTP_MULTICERT)
njt_int_t
#else
static njt_int_t
#endif
njt_http_ssl_compile_certificates(njt_conf_t *cf,
    njt_http_ssl_srv_conf_t *conf)
{
    njt_str_t                         *cert, *key;
    njt_uint_t                         i, nelts;
    njt_http_complex_value_t          *cv;
    njt_http_compile_complex_value_t   ccv;

    if (conf->certificates == NULL) {
        return NJT_OK;
    }

    cert = conf->certificates->elts;
    key = conf->certificate_keys->elts;
    nelts = conf->certificates->nelts;

    for (i = 0; i < nelts; i++) {
        if (njt_http_script_variables_count(&cert[i])) {
            goto found;
        }

        if (njt_http_script_variables_count(&key[i])) {
            goto found;
        }
    }

    return NJT_OK;

found:

    conf->certificate_values = njt_array_create(cf->pool, nelts,
                                             sizeof(njt_http_complex_value_t));
    if (conf->certificate_values == NULL) {
        return NJT_ERROR;
    }

    conf->certificate_key_values = njt_array_create(cf->pool, nelts,
                                             sizeof(njt_http_complex_value_t));
    if (conf->certificate_key_values == NULL) {
        return NJT_ERROR;
    }

    for (i = 0; i < nelts; i++) {

        cv = njt_array_push(conf->certificate_values);
        if (cv == NULL) {
            return NJT_ERROR;
        }

        njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &cert[i];
        ccv.complex_value = cv;
        ccv.zero = 1;

        if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
            return NJT_ERROR;
        }

        cv = njt_array_push(conf->certificate_key_values);
        if (cv == NULL) {
            return NJT_ERROR;
        }

        njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &key[i];
        ccv.complex_value = cv;
        ccv.zero = 1;

        if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    conf->passwords = njt_ssl_preserve_passwords(cf, conf->passwords);
    if (conf->passwords == NULL) {
        return NJT_ERROR;
    }

    return NJT_OK;
}


static char *
njt_http_ssl_password_file(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_ssl_srv_conf_t *sscf = conf;

    njt_str_t  *value;

    if (sscf->passwords != NJT_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    sscf->passwords = njt_ssl_read_password_file(cf, &value[1]);

    if (sscf->passwords == NULL) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static char *
njt_http_ssl_session_cache(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_ssl_srv_conf_t *sscf = conf;

    size_t       len;
    njt_str_t   *value, name, size;
    njt_int_t    n;
    njt_uint_t   i, j;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (njt_strcmp(value[i].data, "off") == 0) {
            sscf->builtin_session_cache = NJT_SSL_NO_SCACHE;
            continue;
        }

        if (njt_strcmp(value[i].data, "none") == 0) {
            sscf->builtin_session_cache = NJT_SSL_NONE_SCACHE;
            continue;
        }

        if (njt_strcmp(value[i].data, "builtin") == 0) {
            sscf->builtin_session_cache = NJT_SSL_DFLT_BUILTIN_SCACHE;
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

            sscf->builtin_session_cache = n;

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

            sscf->shm_zone = njt_shared_memory_add(cf, &name, n,
                                                   &njt_http_ssl_module);
            if (sscf->shm_zone == NULL) {
                return NJT_CONF_ERROR;
            }

            sscf->shm_zone->init = njt_ssl_session_cache_init;

            continue;
        }

        goto invalid;
    }

    if (sscf->shm_zone && sscf->builtin_session_cache == NJT_CONF_UNSET) {
        sscf->builtin_session_cache = NJT_SSL_NO_BUILTIN_SCACHE;
    }

    return NJT_CONF_OK;

invalid:

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "invalid session cache \"%V\"", &value[i]);

    return NJT_CONF_ERROR;
}


static char *
njt_http_ssl_ocsp_cache(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_ssl_srv_conf_t *sscf = conf;

    size_t       len;
    njt_int_t    n;
    njt_str_t   *value, name, size;
    njt_uint_t   j;

    if (sscf->ocsp_cache_zone != NJT_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (njt_strcmp(value[1].data, "off") == 0) {
        sscf->ocsp_cache_zone = NULL;
        return NJT_CONF_OK;
    }

    if (value[1].len <= sizeof("shared:") - 1
        || njt_strncmp(value[1].data, "shared:", sizeof("shared:") - 1) != 0)
    {
        goto invalid;
    }

    len = 0;

    for (j = sizeof("shared:") - 1; j < value[1].len; j++) {
        if (value[1].data[j] == ':') {
            break;
        }

        len++;
    }

    if (len == 0 || j == value[1].len) {
        goto invalid;
    }

    name.len = len;
    name.data = value[1].data + sizeof("shared:") - 1;

    size.len = value[1].len - j - 1;
    size.data = name.data + len + 1;

    n = njt_parse_size(&size);

    if (n == NJT_ERROR) {
        goto invalid;
    }

    if (n < (njt_int_t) (8 * njt_pagesize)) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "OCSP cache \"%V\" is too small", &value[1]);

        return NJT_CONF_ERROR;
    }

    sscf->ocsp_cache_zone = njt_shared_memory_add(cf, &name, n,
                                                  &njt_http_ssl_module_ctx);
    if (sscf->ocsp_cache_zone == NULL) {
        return NJT_CONF_ERROR;
    }

    sscf->ocsp_cache_zone->init = njt_ssl_ocsp_cache_init;

    return NJT_CONF_OK;

invalid:

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "invalid OCSP cache \"%V\"", &value[1]);

    return NJT_CONF_ERROR;
}


static char *
njt_http_ssl_conf_command_check(njt_conf_t *cf, void *post, void *data)
{
#ifndef SSL_CONF_FLAG_FILE
    return "is not supported on this platform";
#else
    return NJT_CONF_OK;
#endif
}


static njt_int_t
njt_http_ssl_init(njt_conf_t *cf)
{
    njt_uint_t                   a, p, s;
    const char                  *name;
    njt_http_conf_addr_t        *addr;
    njt_http_conf_port_t        *port;
    njt_http_ssl_srv_conf_t     *sscf;
    njt_http_core_loc_conf_t    *clcf;
    njt_http_core_srv_conf_t   **cscfp, *cscf;
    njt_http_core_main_conf_t   *cmcf;

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);
    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {

        sscf = cscfp[s]->ctx->srv_conf[njt_http_ssl_module.ctx_index];

        if (sscf->ssl.ctx == NULL) {
            continue;
        }

        clcf = cscfp[s]->ctx->loc_conf[njt_http_core_module.ctx_index];

        if (sscf->stapling) {
            if (njt_ssl_stapling_resolver(cf, &sscf->ssl, clcf->resolver,
                                          clcf->resolver_timeout)
                != NJT_OK)
            {
                return NJT_ERROR;
            }
        }

        if (sscf->ocsp) {
            if (njt_ssl_ocsp_resolver(cf, &sscf->ssl, clcf->resolver,
                                      clcf->resolver_timeout)
                != NJT_OK)
            {
                return NJT_ERROR;
            }
        }
    }

    if (cmcf->ports == NULL) {
        return NJT_OK;
    }

    port = cmcf->ports->elts;
    for (p = 0; p < cmcf->ports->nelts; p++) {

        addr = port[p].addrs.elts;
        for (a = 0; a < port[p].addrs.nelts; a++) {

            if (!addr[a].opt.ssl && !addr[a].opt.quic) {
                continue;
            }

            if (addr[a].opt.quic) {
                name = "quic";

#if (NJT_QUIC_OPENSSL_COMPAT)
                if (njt_http_ssl_quic_compat_init(cf, &addr[a]) != NJT_OK) {
                    return NJT_ERROR;
                }
#endif

            } else {
                name = "ssl";
            }

            cscf = addr[a].default_server;
            sscf = cscf->ctx->srv_conf[njt_http_ssl_module.ctx_index];

            if (sscf->certificates) {

                if (addr[a].opt.quic && !(sscf->protocols & NJT_SSL_TLSv1_3)) {
                    njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                                  "\"ssl_protocols\" must enable TLSv1.3 for "
                                  "the \"listen ... %s\" directive in %s:%ui",
                                  name, cscf->file_name, cscf->line);
                    return NJT_ERROR;
                }

                continue;
            }

            if (!sscf->reject_handshake) {
                njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                              "no \"ssl_certificate\" is defined for "
                              "the \"listen ... %s\" directive in %s:%ui",
                              name, cscf->file_name, cscf->line);
                return NJT_ERROR;
            }

            /*
             * if no certificates are defined in the default server,
             * check all non-default server blocks
             */

            cscfp = addr[a].servers.elts;
            for (s = 0; s < addr[a].servers.nelts; s++) {

                cscf = cscfp[s];
                sscf = cscf->ctx->srv_conf[njt_http_ssl_module.ctx_index];

                if (sscf->certificates || sscf->reject_handshake) {
                    continue;
                }

                njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                              "no \"ssl_certificate\" is defined for "
                              "the \"listen ... %s\" directive in %s:%ui",
                              name, cscf->file_name, cscf->line);
                return NJT_ERROR;
            }
        }
    }

    return NJT_OK;
}

njt_int_t
njt_http_ssl_dynamic_init(njt_conf_t *cf,njt_http_addr_conf_t *addr_conf)
{
    const char                  *name;
    njt_http_ssl_srv_conf_t     *sscf;
    njt_http_core_loc_conf_t    *clcf;
    njt_http_core_srv_conf_t   **cscfp, *cscf,*cscf_default;
    njt_http_core_main_conf_t   *cmcf;

    if(addr_conf == NULL) {
	return NJT_OK;
    }
    cmcf = njt_http_cycle_get_module_main_conf(njt_cycle, njt_http_core_module);
    cscfp = cmcf->servers.elts;
    cscf = NULL;
    if(cmcf->servers.nelts > 0 && cscfp[cmcf->servers.nelts-1]->dynamic_status == 1) {
	cscf = cscfp[cmcf->servers.nelts-1];
    } else {
	    njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0,"njt_http_ssl_dynamic_init no find server!");
	return NJT_OK;
    }
    

        sscf = cscf->ctx->srv_conf[njt_http_ssl_module.ctx_index];
        clcf = cscf->ctx->loc_conf[njt_http_core_module.ctx_index];

        if (sscf->stapling) {
            if (njt_ssl_stapling_resolver(cf, &sscf->ssl, clcf->resolver,
                                          clcf->resolver_timeout)
                != NJT_OK)
            {
                return NJT_ERROR;
            }
        }

        if (sscf->ocsp) {
            if (njt_ssl_ocsp_resolver(cf, &sscf->ssl, clcf->resolver,
                                      clcf->resolver_timeout)
                != NJT_OK)
            {
                return NJT_ERROR;
            }
        }
 	if(!addr_conf->ssl && !addr_conf->quic) {
		return NJT_OK;
	}   

            if (addr_conf->quic) {
                name = "quic";

#if (NJT_QUIC_OPENSSL_COMPAT)
                if (njt_http_ssl_quic_compat_dynamic_init(cf, cscf) != NJT_OK) {
                    return NJT_ERROR;
                }
#endif

            } else {
                name = "ssl";
            }

            cscf_default = addr_conf->default_server;
            sscf = cscf_default->ctx->srv_conf[njt_http_ssl_module.ctx_index];

            if (sscf->certificates) {

                if (addr_conf->quic && !(sscf->protocols & NJT_SSL_TLSv1_3)) {
                    njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                                  "\"ssl_protocols\" must enable TLSv1.3 for "
                                  "the \"listen ... %s\" directive in %s:%ui",
                                  name, cscf->file_name, cscf->line);
                    return NJT_ERROR;
                }

                return NJT_OK;
            }

            if (!sscf->reject_handshake) {
                njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                              "no \"ssl_certificate\" is defined for "
                              "the \"listen ... %s\" directive in %s:%ui",
                              name, cscf->file_name, cscf->line);
                return NJT_ERROR;
            }

            /*
             * if no certificates are defined in the default server,
             * check all non-default server blocks
             */


                sscf = cscf->ctx->srv_conf[njt_http_ssl_module.ctx_index];

                if (sscf->certificates || sscf->reject_handshake) {
                    return NJT_OK;
                }

                njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                              "no \"ssl_certificate\" is defined for "
                              "the \"listen ... %s\" directive in %s:%ui",
                              name, cscf->file_name, cscf->line);
                return NJT_ERROR;

    return NJT_OK;
}


#if (NJT_QUIC_OPENSSL_COMPAT)

static njt_int_t
njt_http_ssl_quic_compat_init(njt_conf_t *cf, njt_http_conf_addr_t *addr)
{
    njt_uint_t                  s;
    njt_http_ssl_srv_conf_t    *sscf;
    njt_http_core_srv_conf_t  **cscfp, *cscf;

    cscfp = addr->servers.elts;
    for (s = 0; s < addr->servers.nelts; s++) {

        cscf = cscfp[s];
        sscf = cscf->ctx->srv_conf[njt_http_ssl_module.ctx_index];

        if (sscf->certificates || sscf->reject_handshake) {
            if (njt_quic_compat_init(cf, sscf->ssl.ctx) != NJT_OK) {
                return NJT_ERROR;
            }
        }
    }

    return NJT_OK;
}

static njt_int_t
njt_http_ssl_quic_compat_dynamic_init(njt_conf_t *cf, njt_http_core_srv_conf_t *cscf)
{
	njt_http_ssl_srv_conf_t    *sscf;
	sscf = cscf->ctx->srv_conf[njt_http_ssl_module.ctx_index];
	if(sscf != NULL) {
		if (sscf->certificates || sscf->reject_handshake) {
			if (njt_quic_compat_init(cf, sscf->ssl.ctx) != NJT_OK) {
				return NJT_ERROR;
			}
		}
	}

	return NJT_OK;
}

#endif


#if (NJT_HAVE_SET_ALPN)
static char *
njt_http_ssl_alpn(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation

    njt_http_ssl_srv_conf_t  *scf = conf;

    u_char      *p;
    size_t       len;
    njt_str_t   *value;
    njt_uint_t   i;

    if (scf->alpn.len) {
        return "is duplicate";
    }

    value = cf->args->elts;

    len = 0;

    for (i = 1; i < cf->args->nelts; i++) {

        if (value[i].len > 255) {
            return "protocol too long";
        }

        len += value[i].len + 1;
    }

    scf->alpn.data = njt_pnalloc(cf->pool, len);
    if (scf->alpn.data == NULL) {
        return NJT_CONF_ERROR;
    }

    p = scf->alpn.data;

    for (i = 1; i < cf->args->nelts; i++) {
        *p++ = value[i].len;
        p = njt_cpymem(p, value[i].data, value[i].len);
    }

    scf->alpn.len = len;

    return NJT_CONF_OK;

#else
    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "the \"ssl_alpn\" directive requires OpenSSL "
                       "with ALPN support");
    return NJT_CONF_ERROR;
#endif
}
#endif
