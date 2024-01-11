
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>

extern njt_module_t njt_stream_proto_module;
typedef njt_int_t (*njt_ssl_variable_handler_pt)(njt_connection_t *c,
    njt_pool_t *pool, njt_str_t *s);


#define NJT_DEFAULT_CIPHERS     "HIGH:!aNULL:!MD5"
#define NJT_DEFAULT_ECDH_CURVE  "auto"


static njt_int_t njt_stream_ssl_handler(njt_stream_session_t *s);
static njt_int_t njt_stream_ssl_init_connection(njt_ssl_t *ssl,
    njt_connection_t *c);
static void njt_stream_ssl_handshake_handler(njt_connection_t *c);
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
static int njt_stream_ssl_servername(njt_ssl_conn_t *ssl_conn, int *ad,
    void *arg);
#endif
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
static int njt_stream_ssl_alpn_select(njt_ssl_conn_t *ssl_conn,
    const unsigned char **out, unsigned char *outlen,
    const unsigned char *in, unsigned int inlen, void *arg);
#endif
#ifdef SSL_R_CERT_CB_ERROR
static int njt_stream_ssl_certificate(njt_ssl_conn_t *ssl_conn, void *arg);
#endif
static njt_int_t njt_stream_ssl_static_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_ssl_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);

static njt_int_t njt_stream_ssl_add_variables(njt_conf_t *cf);
static void *njt_stream_ssl_create_conf(njt_conf_t *cf);
static char *njt_stream_ssl_merge_conf(njt_conf_t *cf, void *parent,
    void *child);

#if (!defined(NJT_STREAM_MULTICERT))
static njt_int_t njt_stream_ssl_compile_certificates(njt_conf_t *cf,
    njt_stream_ssl_conf_t *conf);
#endif

static char *njt_stream_ssl_password_file(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_stream_ssl_session_cache(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_stream_ssl_alpn(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);

static char *njt_stream_ssl_conf_command_check(njt_conf_t *cf, void *post,
    void *data);

static njt_int_t njt_stream_ssl_init(njt_conf_t *cf);
extern njt_int_t njt_stream_proto_handler(njt_stream_session_t *s);


static njt_conf_bitmask_t  njt_stream_ssl_protocols[] = {
    { njt_string("SSLv2"), NJT_SSL_SSLv2 },
    { njt_string("SSLv3"), NJT_SSL_SSLv3 },
    { njt_string("TLSv1"), NJT_SSL_TLSv1 },
    { njt_string("TLSv1.1"), NJT_SSL_TLSv1_1 },
    { njt_string("TLSv1.2"), NJT_SSL_TLSv1_2 },
    { njt_string("TLSv1.3"), NJT_SSL_TLSv1_3 },
    { njt_null_string, 0 }
};


static njt_conf_enum_t  njt_stream_ssl_verify[] = {
    { njt_string("off"), 0 },
    { njt_string("on"), 1 },
    { njt_string("optional"), 2 },
    { njt_string("optional_no_ca"), 3 },
    { njt_null_string, 0 }
};


static njt_conf_post_t  njt_stream_ssl_conf_command_post =
    { njt_stream_ssl_conf_command_check };


static njt_command_t  njt_stream_ssl_commands[] = {

    { njt_string("ssl_handshake_timeout"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_ssl_conf_t, handshake_timeout),
      NULL },

#if (NJT_STREAM_MULTICERT)

    { njt_string("ssl_certificate"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE12,
      njt_ssl_certificate_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_ssl_conf_t, certificates),
      NULL },

    { njt_string("ssl_certificate_key"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE12,
      njt_ssl_certificate_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_ssl_conf_t, certificate_keys),
      NULL },

#else
    { njt_string("ssl_certificate"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_array_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_ssl_conf_t, certificates),
      NULL },

    { njt_string("ssl_certificate_key"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_array_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_ssl_conf_t, certificate_keys),
      NULL },
#endif

    { njt_string("ssl_password_file"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_stream_ssl_password_file,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("ssl_dhparam"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_ssl_conf_t, dhparam),
      NULL },

    { njt_string("ssl_ecdh_curve"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_ssl_conf_t, ecdh_curve),
      NULL },

    { njt_string("ssl_protocols"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_ssl_conf_t, protocols),
      &njt_stream_ssl_protocols },

    { njt_string("ssl_ciphers"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_ssl_conf_t, ciphers),
      NULL },

    { njt_string("ssl_verify_client"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_enum_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_ssl_conf_t, verify),
      &njt_stream_ssl_verify },

    { njt_string("ssl_verify_depth"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_ssl_conf_t, verify_depth),
      NULL },

    { njt_string("ssl_client_certificate"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_ssl_conf_t, client_certificate),
      NULL },

    { njt_string("ssl_trusted_certificate"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_ssl_conf_t, trusted_certificate),
      NULL },

    { njt_string("ssl_prefer_server_ciphers"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_ssl_conf_t, prefer_server_ciphers),
      NULL },

    { njt_string("ssl_session_cache"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE12,
      njt_stream_ssl_session_cache,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("ssl_session_tickets"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_ssl_conf_t, session_tickets),
      NULL },

    { njt_string("ssl_session_ticket_key"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_array_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_ssl_conf_t, session_ticket_keys),
      NULL },

    { njt_string("ssl_session_timeout"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_sec_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_ssl_conf_t, session_timeout),
      NULL },

    { njt_string("ssl_crl"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_ssl_conf_t, crl),
      NULL },

    { njt_string("ssl_conf_command"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE2,
      njt_conf_set_keyval_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_ssl_conf_t, conf_commands),
      &njt_stream_ssl_conf_command_post },

    { njt_string("ssl_alpn"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_1MORE,
      njt_stream_ssl_alpn,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

#if (NJT_HAVE_NTLS)
    { njt_string("ssl_ntls"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_ssl_conf_t, ntls),
      NULL },
#endif

      njt_null_command
};


static njt_stream_module_t  njt_stream_ssl_module_ctx = {
    njt_stream_ssl_add_variables,          /* preconfiguration */
    njt_stream_ssl_init,                   /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    njt_stream_ssl_create_conf,            /* create server configuration */
    njt_stream_ssl_merge_conf              /* merge server configuration */
};


njt_module_t  njt_stream_ssl_module = {
    NJT_MODULE_V1,
    &njt_stream_ssl_module_ctx,            /* module context */
    njt_stream_ssl_commands,               /* module directives */
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


static njt_stream_variable_t  njt_stream_ssl_vars[] = {

    { njt_string("ssl_protocol"), NULL, njt_stream_ssl_static_variable,
      (uintptr_t) njt_ssl_get_protocol, NJT_STREAM_VAR_CHANGEABLE, 0 },

    { njt_string("ssl_cipher"), NULL, njt_stream_ssl_static_variable,
      (uintptr_t) njt_ssl_get_cipher_name, NJT_STREAM_VAR_CHANGEABLE, 0 },

    { njt_string("ssl_ciphers"), NULL, njt_stream_ssl_variable,
      (uintptr_t) njt_ssl_get_ciphers, NJT_STREAM_VAR_CHANGEABLE, 0 },

    { njt_string("ssl_curve"), NULL, njt_stream_ssl_variable,
      (uintptr_t) njt_ssl_get_curve, NJT_STREAM_VAR_CHANGEABLE, 0 },

    { njt_string("ssl_curves"), NULL, njt_stream_ssl_variable,
      (uintptr_t) njt_ssl_get_curves, NJT_STREAM_VAR_CHANGEABLE, 0 },

    { njt_string("ssl_session_id"), NULL, njt_stream_ssl_variable,
      (uintptr_t) njt_ssl_get_session_id, NJT_STREAM_VAR_CHANGEABLE, 0 },

    { njt_string("ssl_session_reused"), NULL, njt_stream_ssl_variable,
      (uintptr_t) njt_ssl_get_session_reused, NJT_STREAM_VAR_CHANGEABLE, 0 },

    { njt_string("ssl_server_name"), NULL, njt_stream_ssl_variable,
      (uintptr_t) njt_ssl_get_server_name, NJT_STREAM_VAR_CHANGEABLE, 0 },

    { njt_string("ssl_alpn_protocol"), NULL, njt_stream_ssl_variable,
      (uintptr_t) njt_ssl_get_alpn_protocol, NJT_STREAM_VAR_CHANGEABLE, 0 },

    { njt_string("ssl_client_cert"), NULL, njt_stream_ssl_variable,
      (uintptr_t) njt_ssl_get_certificate, NJT_STREAM_VAR_CHANGEABLE, 0 },

    { njt_string("ssl_client_raw_cert"), NULL, njt_stream_ssl_variable,
      (uintptr_t) njt_ssl_get_raw_certificate,
      NJT_STREAM_VAR_CHANGEABLE, 0 },

    { njt_string("ssl_client_escaped_cert"), NULL, njt_stream_ssl_variable,
      (uintptr_t) njt_ssl_get_escaped_certificate,
      NJT_STREAM_VAR_CHANGEABLE, 0 },

    { njt_string("ssl_client_s_dn"), NULL, njt_stream_ssl_variable,
      (uintptr_t) njt_ssl_get_subject_dn, NJT_STREAM_VAR_CHANGEABLE, 0 },

    { njt_string("ssl_client_i_dn"), NULL, njt_stream_ssl_variable,
      (uintptr_t) njt_ssl_get_issuer_dn, NJT_STREAM_VAR_CHANGEABLE, 0 },

    { njt_string("ssl_client_serial"), NULL, njt_stream_ssl_variable,
      (uintptr_t) njt_ssl_get_serial_number, NJT_STREAM_VAR_CHANGEABLE, 0 },

    { njt_string("ssl_client_fingerprint"), NULL, njt_stream_ssl_variable,
      (uintptr_t) njt_ssl_get_fingerprint, NJT_STREAM_VAR_CHANGEABLE, 0 },

    { njt_string("ssl_client_verify"), NULL, njt_stream_ssl_variable,
      (uintptr_t) njt_ssl_get_client_verify, NJT_STREAM_VAR_CHANGEABLE, 0 },

    { njt_string("ssl_client_v_start"), NULL, njt_stream_ssl_variable,
      (uintptr_t) njt_ssl_get_client_v_start, NJT_STREAM_VAR_CHANGEABLE, 0 },

    { njt_string("ssl_client_v_end"), NULL, njt_stream_ssl_variable,
      (uintptr_t) njt_ssl_get_client_v_end, NJT_STREAM_VAR_CHANGEABLE, 0 },

    { njt_string("ssl_client_v_remain"), NULL, njt_stream_ssl_variable,
      (uintptr_t) njt_ssl_get_client_v_remain, NJT_STREAM_VAR_CHANGEABLE, 0 },

      njt_stream_null_variable
};


static njt_str_t njt_stream_ssl_sess_id_ctx = njt_string("STREAM");


static njt_int_t
njt_stream_preread_phase(njt_stream_session_t *s,
    njt_stream_handler_pt handler)
{
    size_t                       size;
    ssize_t                      n;
    njt_int_t                    rc;
    njt_connection_t            *c;
    njt_stream_core_srv_conf_t  *cscf;

    c = s->connection;

    c->log->action = "prereading client data";

    cscf = njt_stream_get_module_srv_conf(s, njt_stream_core_module);

    if (c->read->timedout) {
        rc = NJT_STREAM_OK;

    } else if (c->read->timer_set) {
        rc = NJT_AGAIN;

    } else {
        rc = handler(s);
    }

    while (rc == NJT_AGAIN) {

        if (c->buffer == NULL) {
            c->buffer = njt_create_temp_buf(c->pool, cscf->preread_buffer_size);
            if (c->buffer == NULL) {
                rc = NJT_ERROR;
                break;
            }
        }

        size = c->buffer->end - c->buffer->last;

        if (size == 0) {
            rc = NJT_STREAM_BAD_REQUEST;
            break;
        }

        if (c->read->eof) {
            rc = NJT_STREAM_OK;
            break;
        }

        if (!c->read->ready) {
            break;
        }

        //n = c->recv(c, c->buffer->last, size);
		n = recv(c->fd,c->buffer->last, size, MSG_PEEK);

        if (n == NJT_ERROR || n == 0) {
            rc = NJT_STREAM_OK;
            break;
        }

        if (n == NJT_AGAIN) {
            break;
        }

        c->buffer->last += n;

        rc = handler(s);
    }

    if (rc == NJT_AGAIN) {
        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            return NJT_OK;
        }

        if (!c->read->timer_set) {
            njt_add_timer(c->read, 10000);
        }

        c->read->handler = njt_stream_session_handler;

        return NJT_AGAIN;
    }

    if (c->read->timer_set) {
        njt_del_timer(c->read);
    }

    if (rc == NJT_OK) {
       
        return NJT_OK;
    }

    if (rc == NJT_DECLINED) {
        return NJT_DECLINED;
    }

    if (rc == NJT_DONE) {
        return NJT_OK;
    }

    return NJT_DECLINED;
}


static njt_int_t
njt_stream_ssl_handler(njt_stream_session_t *s)
{
    long                    rc;
    X509                   *cert;
    njt_int_t               rv;
    njt_connection_t       *c;
    njt_stream_ssl_conf_t  *sslcf;

    njt_str_t  strict = njt_string("STRICT");
    njt_str_t  disable = njt_string("DISABLE");
    njt_str_t  both = njt_string("PERMISSIVE");
	
	njt_stream_proto_ctx_t *ctx;
	njt_stream_proto_srv_conf_t  *cf;

	c = s->connection;

	cf = njt_stream_get_module_srv_conf(s, njt_stream_proto_module);
	if(cf != NULL && (cf->proto_enabled || (cf->proto_ports != NULL && cf->proto_ports->nelts != 0))) {
		ctx = njt_stream_get_module_ctx(s, njt_stream_proto_module);
		if(ctx == NULL || ctx->complete == 0) {
			rc = njt_stream_preread_phase(s,njt_stream_proto_handler);
			if(rc == NJT_AGAIN) {
				return NJT_AGAIN;
			} else if( rc == NJT_DECLINED) {
				c->buffer = NULL;
				ctx = njt_stream_get_module_ctx(s, njt_stream_proto_module);
				if (ctx != NULL && (ctx->port_mode.len == 0 && ctx->port_mode.data == NULL)) {
				   if(!s->ssl) {
                                  	 return NJT_OK;
				  }
                                }
				else if (ctx != NULL && ctx->ssl == 0) {
					if((ctx->port_mode.len == disable.len && njt_strncmp(ctx->port_mode.data,disable.data,disable.len) == 0) ||
					 (ctx->port_mode.len == both.len && njt_strncmp(ctx->port_mode.data,both.data,both.len) == 0)) {
					        njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0, "sidecar: not ssl port_mode %V,ok!",&ctx->port_mode);
						return NJT_OK;
					} else {
					        njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0, "sidecar: not ssl port_mode %V,reject!",&ctx->port_mode);
						return NJT_ERROR;
					}
				} else if (ctx != NULL){
					if((ctx->port_mode.len == strict.len && njt_strncmp(ctx->port_mode.data,strict.data,strict.len) == 0) ||
                                         (ctx->port_mode.len == both.len && njt_strncmp(ctx->port_mode.data,both.data,both.len) == 0)) {
                                                //return NJT_OK;
					        njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0, "sidecar:ssl port_mode %V,ok!",&ctx->port_mode);
                                        } else {
					        njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0, "sidecar: ssl port_mode %V,reject!",&ctx->port_mode);
                                                return NJT_ERROR;
                                        }
				}
			} else {
				c->buffer = NULL;
			}
		}
	}
	
    if (!s->ssl) {
        return NJT_OK;
    }


	
    sslcf = njt_stream_get_module_srv_conf(s, njt_stream_ssl_module);

    if (c->ssl == NULL) {
        c->log->action = "SSL handshaking";

        rv = njt_stream_ssl_init_connection(&sslcf->ssl, c);

        if (rv != NJT_OK) {
            return rv;
        }
    }

    if (sslcf->verify) {
        rc = SSL_get_verify_result(c->ssl->connection);

        if (rc != X509_V_OK
            && (sslcf->verify != 3 || !njt_ssl_verify_error_optional(rc)))
        {
            njt_log_error(NJT_LOG_INFO, c->log, 0,
                          "client SSL certificate verify error: (%l:%s)",
                          rc, X509_verify_cert_error_string(rc));

            njt_ssl_remove_cached_session(c->ssl->session_ctx,
                                       (SSL_get0_session(c->ssl->connection)));
            return NJT_ERROR;
        }

        if (sslcf->verify == 1) {
            cert = SSL_get_peer_certificate(c->ssl->connection);

            if (cert == NULL) {
                njt_log_error(NJT_LOG_INFO, c->log, 0,
                              "client sent no required SSL certificate");

                njt_ssl_remove_cached_session(c->ssl->session_ctx,
                                       (SSL_get0_session(c->ssl->connection)));
                return NJT_ERROR;
            }

            X509_free(cert);
        }
    }

    return NJT_OK;
}


static njt_int_t
njt_stream_ssl_init_connection(njt_ssl_t *ssl, njt_connection_t *c)
{
    njt_int_t                    rc;
    njt_stream_session_t        *s;
    njt_stream_ssl_conf_t       *sslcf;
    njt_stream_core_srv_conf_t  *cscf;

    s = c->data;

    cscf = njt_stream_get_module_srv_conf(s, njt_stream_core_module);

    if (cscf->tcp_nodelay && njt_tcp_nodelay(c) != NJT_OK) {
        return NJT_ERROR;
    }

    if (njt_ssl_create_connection(ssl, c, 0) != NJT_OK) {
        return NJT_ERROR;
    }

#if (NJT_HAVE_NTLS)
    sslcf = njt_stream_get_module_srv_conf(s, njt_stream_ssl_module);

    if (sslcf->ntls) {
        SSL_enable_ntls(c->ssl->connection);
    }
#endif

    rc = njt_ssl_handshake(c);

    if (rc == NJT_ERROR) {
        return NJT_ERROR;
    }

    if (rc == NJT_AGAIN) {
        sslcf = njt_stream_get_module_srv_conf(s, njt_stream_ssl_module);

        njt_add_timer(c->read, sslcf->handshake_timeout);

        c->ssl->handler = njt_stream_ssl_handshake_handler;

        return NJT_AGAIN;
    }

    /* rc == NJT_OK */

    return NJT_OK;
}


static void
njt_stream_ssl_handshake_handler(njt_connection_t *c)
{
    njt_stream_session_t  *s;

    s = c->data;

    if (!c->ssl->handshaked) {
        njt_stream_finalize_session(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (c->read->timer_set) {
        njt_del_timer(c->read);
    }

    njt_stream_core_run_phases(s);
}


#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

static int
njt_stream_ssl_servername(njt_ssl_conn_t *ssl_conn, int *ad, void *arg)
{
    return SSL_TLSEXT_ERR_OK;
}

#endif


#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation

static int
njt_stream_ssl_alpn_select(njt_ssl_conn_t *ssl_conn, const unsigned char **out,
    unsigned char *outlen, const unsigned char *in, unsigned int inlen,
    void *arg)
{
    njt_str_t         *alpn;
#if (NJT_DEBUG)
    unsigned int       i;
    njt_connection_t  *c;

    c = njt_ssl_get_connection(ssl_conn);

    for (i = 0; i < inlen; i += in[i] + 1) {
        njt_log_debug2(NJT_LOG_DEBUG_STREAM, c->log, 0,
                       "SSL ALPN supported by client: %*s",
                       (size_t) in[i], &in[i + 1]);
    }

#endif

    alpn = arg;

    if (SSL_select_next_proto((unsigned char **) out, outlen, alpn->data,
                              alpn->len, in, inlen)
        != OPENSSL_NPN_NEGOTIATED)
    {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    njt_log_debug2(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "SSL ALPN selected: %*s", (size_t) *outlen, *out);

    return SSL_TLSEXT_ERR_OK;
}

#endif


#ifdef SSL_R_CERT_CB_ERROR

static int
njt_stream_ssl_certificate(njt_ssl_conn_t *ssl_conn, void *arg)
{
    njt_str_t                    cert, key;
    njt_uint_t                   i, nelts;
    njt_connection_t            *c;
    njt_stream_session_t        *s;
    njt_stream_ssl_conf_t       *sslcf;
    njt_stream_complex_value_t  *certs, *keys;

    c = njt_ssl_get_connection(ssl_conn);

    if (c->ssl->handshaked) {
        return 0;
    }

    s = c->data;

    sslcf = arg;

    nelts = sslcf->certificate_values->nelts;
    certs = sslcf->certificate_values->elts;
    keys = sslcf->certificate_key_values->elts;

    for (i = 0; i < nelts; i++) {

        if (njt_stream_complex_value(s, &certs[i], &cert) != NJT_OK) {
            return 0;
        }

        njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                       "ssl cert: \"%s\"", cert.data);

        if (njt_stream_complex_value(s, &keys[i], &key) != NJT_OK) {
            return 0;
        }

        njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                       "ssl key: \"%s\"", key.data);

        if (njt_ssl_connection_certificate(c, c->pool, &cert, &key,
                                           sslcf->passwords)
            != NJT_OK)
        {
            return 0;
        }
    }

    return 1;
}

#endif


static njt_int_t
njt_stream_ssl_static_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    njt_ssl_variable_handler_pt  handler = (njt_ssl_variable_handler_pt) data;

    size_t     len;
    njt_str_t  str;

    if (s->connection->ssl) {

        (void) handler(s->connection, NULL, &str);

        v->data = str.data;

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
njt_stream_ssl_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    njt_ssl_variable_handler_pt  handler = (njt_ssl_variable_handler_pt) data;

    njt_str_t  str;

    if (s->connection->ssl) {

        if (handler(s->connection, s->connection->pool, &str) != NJT_OK) {
            return NJT_ERROR;
        }

        v->len = str.len;
        v->data = str.data;

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
njt_stream_ssl_add_variables(njt_conf_t *cf)
{
    njt_stream_variable_t  *var, *v;

    for (v = njt_stream_ssl_vars; v->name.len; v++) {
        var = njt_stream_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NJT_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NJT_OK;
}


static void *
njt_stream_ssl_create_conf(njt_conf_t *cf)
{
    njt_stream_ssl_conf_t  *scf;

    scf = njt_pcalloc(cf->pool, sizeof(njt_stream_ssl_conf_t));
    if (scf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     scf->listen = 0;
     *     scf->protocols = 0;
     *     scf->certificate_values = NULL;
     *     scf->dhparam = { 0, NULL };
     *     scf->ecdh_curve = { 0, NULL };
     *     scf->client_certificate = { 0, NULL };
     *     scf->trusted_certificate = { 0, NULL };
     *     scf->crl = { 0, NULL };
     *     scf->alpn = { 0, NULL };
     *     scf->ciphers = { 0, NULL };
     *     scf->shm_zone = NULL;
     */

    scf->handshake_timeout = NJT_CONF_UNSET_MSEC;
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
#if (NJT_HAVE_NTLS)
    scf->ntls = NJT_CONF_UNSET;
#endif
    return scf;
}


static char *
njt_stream_ssl_merge_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_stream_ssl_conf_t *prev = parent;
    njt_stream_ssl_conf_t *conf = child;

    njt_pool_cleanup_t  *cln;

    njt_conf_merge_msec_value(conf->handshake_timeout,
                         prev->handshake_timeout, 60000);

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

    njt_conf_merge_str_value(conf->client_certificate, prev->client_certificate,
                         "");
    njt_conf_merge_str_value(conf->trusted_certificate,
                         prev->trusted_certificate, "");
    njt_conf_merge_str_value(conf->crl, prev->crl, "");
    njt_conf_merge_str_value(conf->alpn, prev->alpn, "");

    njt_conf_merge_str_value(conf->ecdh_curve, prev->ecdh_curve,
                         NJT_DEFAULT_ECDH_CURVE);

    njt_conf_merge_str_value(conf->ciphers, prev->ciphers, NJT_DEFAULT_CIPHERS);

    njt_conf_merge_ptr_value(conf->conf_commands, prev->conf_commands, NULL);

#if (NJT_HAVE_NTLS)
    njt_conf_merge_value(conf->ntls, prev->ntls, 0);
#endif

    conf->ssl.log = cf->log;

    if (!conf->listen) {
        return NJT_CONF_OK;
    }

    if (conf->certificates == NULL) {
        njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                      "no \"ssl_certificate\" is defined for "
                      "the \"listen ... ssl\" directive in %s:%ui",
                      conf->file, conf->line);
        return NJT_CONF_ERROR;
    }

    if (conf->certificate_keys == NULL) {
        njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                      "no \"ssl_certificate_key\" is defined for "
                      "the \"listen ... ssl\" directive in %s:%ui",
                      conf->file, conf->line);
        return NJT_CONF_ERROR;
    }

    if (conf->certificate_keys->nelts < conf->certificates->nelts) {
        njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                      "no \"ssl_certificate_key\" is defined "
                      "for certificate \"%V\" and "
                      "the \"listen ... ssl\" directive in %s:%ui",
                      ((njt_str_t *) conf->certificates->elts)
                      + conf->certificates->nelts - 1,
                      conf->file, conf->line);
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

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    SSL_CTX_set_tlsext_servername_callback(conf->ssl.ctx,
                                           njt_stream_ssl_servername);
#endif

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
    if (conf->alpn.len) {
        SSL_CTX_set_alpn_select_cb(conf->ssl.ctx, njt_stream_ssl_alpn_select,
                                   &conf->alpn);
    }
#endif

    if (njt_ssl_ciphers(cf, &conf->ssl, &conf->ciphers,
                        conf->prefer_server_ciphers)
        != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    if (njt_stream_ssl_compile_certificates(cf, conf) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    if (conf->certificate_values) {

#ifdef SSL_R_CERT_CB_ERROR

        /* install callback to lookup certificates */

        SSL_CTX_set_cert_cb(conf->ssl.ctx, njt_stream_ssl_certificate, conf);

#else
        njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                      "variables in "
                      "\"ssl_certificate\" and \"ssl_certificate_key\" "
                      "directives are not supported on this platform");
        return NJT_CONF_ERROR;
#endif

    } else {

        /* configure certificates */

        if (njt_ssl_certificates(cf, &conf->ssl, conf->certificates,
                                 conf->certificate_keys, conf->passwords)
            != NJT_OK)
        {
            return NJT_CONF_ERROR;
        }
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

    if (njt_ssl_session_cache(&conf->ssl, &njt_stream_ssl_sess_id_ctx,
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

#if (NJT_STREAM_MULTICERT)
njt_int_t
#else
static njt_int_t
#endif
njt_stream_ssl_compile_certificates(njt_conf_t *cf,
    njt_stream_ssl_conf_t *conf)
{
    njt_str_t                           *cert, *key;
    njt_uint_t                           i, nelts;
    njt_stream_complex_value_t          *cv;
    njt_stream_compile_complex_value_t   ccv;

    cert = conf->certificates->elts;
    key = conf->certificate_keys->elts;
    nelts = conf->certificates->nelts;

    for (i = 0; i < nelts; i++) {

        if (njt_stream_script_variables_count(&cert[i])) {
            goto found;
        }

        if (njt_stream_script_variables_count(&key[i])) {
            goto found;
        }
    }

    return NJT_OK;

found:

    conf->certificate_values = njt_array_create(cf->pool, nelts,
                                           sizeof(njt_stream_complex_value_t));
    if (conf->certificate_values == NULL) {
        return NJT_ERROR;
    }

    conf->certificate_key_values = njt_array_create(cf->pool, nelts,
                                           sizeof(njt_stream_complex_value_t));
    if (conf->certificate_key_values == NULL) {
        return NJT_ERROR;
    }

    for (i = 0; i < nelts; i++) {

        cv = njt_array_push(conf->certificate_values);
        if (cv == NULL) {
            return NJT_ERROR;
        }

        njt_memzero(&ccv, sizeof(njt_stream_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &cert[i];
        ccv.complex_value = cv;
        ccv.zero = 1;

        if (njt_stream_compile_complex_value(&ccv) != NJT_OK) {
            return NJT_ERROR;
        }

        cv = njt_array_push(conf->certificate_key_values);
        if (cv == NULL) {
            return NJT_ERROR;
        }

        njt_memzero(&ccv, sizeof(njt_stream_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &key[i];
        ccv.complex_value = cv;
        ccv.zero = 1;

        if (njt_stream_compile_complex_value(&ccv) != NJT_OK) {
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
njt_stream_ssl_password_file(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_ssl_conf_t  *scf = conf;

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
njt_stream_ssl_session_cache(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_ssl_conf_t  *scf = conf;

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
                                                   &njt_stream_ssl_module);
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
njt_stream_ssl_alpn(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation

    njt_stream_ssl_conf_t  *scf = conf;

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


static char *
njt_stream_ssl_conf_command_check(njt_conf_t *cf, void *post, void *data)
{
#ifndef SSL_CONF_FLAG_FILE
    return "is not supported on this platform";
#else
    return NJT_CONF_OK;
#endif
}


static njt_int_t
njt_stream_ssl_init(njt_conf_t *cf)
{
    njt_stream_handler_pt        *h;
    njt_stream_core_main_conf_t  *cmcf;

    cmcf = njt_stream_conf_get_module_main_conf(cf, njt_stream_core_module);

    h = njt_array_push(&cmcf->phases[NJT_STREAM_SSL_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_stream_ssl_handler;

    return NJT_OK;
}
