
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>
#include <njt_stream_proxy_module.h>
#if (NJT_STREAM_PROTOCOL_V2)
#include <njt_stream_proxy_protocol_tlv_module.h>
#endif
#if (NJT_STREAM_FTP_PROXY)
#include <njt_stream_ftp_proxy_module.h>
#endif

struct pp2_tlv {
            uint8_t type;
            uint16_t length;
            uint8_t value[0];
        };
// static void njt_stream_proxy_handler(njt_stream_session_t *s);
static njt_int_t njt_stream_proxy_eval(njt_stream_session_t *s,
    njt_stream_proxy_srv_conf_t *pscf);
static njt_int_t njt_stream_proxy_set_local(njt_stream_session_t *s,
    njt_stream_upstream_t *u, njt_stream_upstream_local_t *local);
static void njt_stream_proxy_connect(njt_stream_session_t *s);
static void njt_stream_proxy_init_upstream(njt_stream_session_t *s);
static void njt_stream_proxy_resolve_handler(njt_resolver_ctx_t *ctx);
static void njt_stream_proxy_upstream_handler(njt_event_t *ev);
static void njt_stream_proxy_downstream_handler(njt_event_t *ev);
static void njt_stream_proxy_process_connection(njt_event_t *ev,
    njt_uint_t from_upstream);
static void njt_stream_proxy_connect_handler(njt_event_t *ev);
static njt_int_t njt_stream_proxy_test_connect(njt_connection_t *c);
static void njt_stream_proxy_process(njt_stream_session_t *s,
    njt_uint_t from_upstream, njt_uint_t do_write);
static njt_int_t njt_stream_proxy_test_finalize(njt_stream_session_t *s,
    njt_uint_t from_upstream);
static void njt_stream_proxy_next_upstream(njt_stream_session_t *s);
static void njt_stream_proxy_finalize(njt_stream_session_t *s, njt_uint_t rc);
static u_char *njt_stream_proxy_log_error(njt_log_t *log, u_char *buf,
    size_t len);

static void *njt_stream_proxy_create_srv_conf(njt_conf_t *cf);
static char *njt_stream_proxy_merge_srv_conf(njt_conf_t *cf, void *parent,
    void *child);
static char *njt_stream_proxy_pass(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_stream_proxy_bind(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);

#if (NJT_STREAM_SSL)

static njt_int_t njt_stream_proxy_send_proxy_protocol(njt_stream_session_t *s);
static char *njt_stream_proxy_ssl_password_file(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);
static char *njt_stream_proxy_ssl_conf_command_check(njt_conf_t *cf, void *post,
    void *data);
static void njt_stream_proxy_ssl_init_connection(njt_stream_session_t *s);
static void njt_stream_proxy_ssl_handshake(njt_connection_t *pc);
static void njt_stream_proxy_ssl_save_session(njt_connection_t *c);
static njt_int_t njt_stream_proxy_ssl_name(njt_stream_session_t *s);
#if (NJT_STREAM_MULTICERT)
static njt_int_t njt_stream_proxy_ssl_certificates(njt_stream_session_t *s);
#else
static njt_int_t njt_stream_proxy_ssl_certificate(njt_stream_session_t *s);
#endif
static njt_int_t njt_stream_proxy_merge_ssl(njt_conf_t *cf,
    njt_stream_proxy_srv_conf_t *conf, njt_stream_proxy_srv_conf_t *prev);
static njt_int_t njt_stream_proxy_set_ssl(njt_conf_t *cf,
    njt_stream_proxy_srv_conf_t *pscf);
u_char *
njt_proxy_protocol_v2_write(njt_stream_session_t *s, u_char *buf, u_char *last);


#if (NJT_HAVE_SET_ALPN)
static char *
njt_stream_proxy_ssl_alpn(njt_conf_t *cf, njt_command_t *cmd, void *conf);
#endif

static njt_conf_bitmask_t  njt_stream_proxy_ssl_protocols[] = {
    { njt_string("SSLv2"), NJT_SSL_SSLv2 },
    { njt_string("SSLv3"), NJT_SSL_SSLv3 },
    { njt_string("TLSv1"), NJT_SSL_TLSv1 },
    { njt_string("TLSv1.1"), NJT_SSL_TLSv1_1 },
    { njt_string("TLSv1.2"), NJT_SSL_TLSv1_2 },
    { njt_string("TLSv1.3"), NJT_SSL_TLSv1_3 },
    { njt_null_string, 0 }
};

static njt_conf_post_t  njt_stream_proxy_ssl_conf_command_post =
    { njt_stream_proxy_ssl_conf_command_check };

#endif


static njt_conf_deprecated_t  njt_conf_deprecated_proxy_downstream_buffer = {
    njt_conf_deprecated, "proxy_downstream_buffer", "proxy_buffer_size"
};

static njt_conf_deprecated_t  njt_conf_deprecated_proxy_upstream_buffer = {
    njt_conf_deprecated, "proxy_upstream_buffer", "proxy_buffer_size"
};


static njt_command_t  njt_stream_proxy_commands[] = {

    { njt_string("proxy_pass"),
      NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_stream_proxy_pass,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("proxy_bind"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE12,
      njt_stream_proxy_bind,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("proxy_socket_keepalive"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, socket_keepalive),
      NULL },

    { njt_string("proxy_connect_timeout"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, connect_timeout),
      NULL },

    { njt_string("proxy_timeout"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, timeout),
      NULL },

    { njt_string("proxy_buffer_size"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, buffer_size),
      NULL },

    { njt_string("proxy_downstream_buffer"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, buffer_size),
      &njt_conf_deprecated_proxy_downstream_buffer },

    { njt_string("proxy_upstream_buffer"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, buffer_size),
      &njt_conf_deprecated_proxy_upstream_buffer },

    { njt_string("proxy_upload_rate"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_stream_set_complex_value_size_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, upload_rate),
      NULL },

    { njt_string("proxy_download_rate"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_stream_set_complex_value_size_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, download_rate),
      NULL },

    { njt_string("proxy_requests"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, requests),
      NULL },

    { njt_string("proxy_responses"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, responses),
      NULL },

    { njt_string("proxy_next_upstream"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, next_upstream),
      NULL },

    { njt_string("proxy_next_upstream_tries"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, next_upstream_tries),
      NULL },

    { njt_string("proxy_next_upstream_timeout"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, next_upstream_timeout),
      NULL },

    { njt_string("proxy_protocol"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, proxy_protocol),
      NULL },

    { njt_string("proxy_half_close"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, half_close),
      NULL },

#if (NJT_STREAM_SSL)

    { njt_string("proxy_ssl"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, ssl_enable),
      NULL },

    { njt_string("proxy_ssl_session_reuse"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, ssl_session_reuse),
      NULL },

    { njt_string("proxy_ssl_protocols"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, ssl_protocols),
      &njt_stream_proxy_ssl_protocols },

    { njt_string("proxy_ssl_ciphers"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, ssl_ciphers),
      NULL },

    { njt_string("proxy_ssl_name"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_stream_set_complex_value_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, ssl_name),
      NULL },

    { njt_string("proxy_ssl_server_name"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, ssl_server_name),
      NULL },

    { njt_string("proxy_ssl_verify"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, ssl_verify),
      NULL },

    { njt_string("proxy_ssl_verify_depth"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, ssl_verify_depth),
      NULL },

    { njt_string("proxy_ssl_trusted_certificate"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, ssl_trusted_certificate),
      NULL },

    { njt_string("proxy_ssl_crl"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, ssl_crl),
      NULL },

#if (NJT_STREAM_MULTICERT)

    { njt_string("proxy_ssl_certificate"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE12,
      njt_ssl_certificate_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, ssl_certificates),
      NULL },

    { njt_string("proxy_ssl_certificate_key"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE12,
      njt_ssl_certificate_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, ssl_certificate_keys),
      NULL },

#else

    { njt_string("proxy_ssl_certificate"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_stream_set_complex_value_zero_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, ssl_certificate),
      NULL },

    { njt_string("proxy_ssl_certificate_key"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_stream_set_complex_value_zero_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, ssl_certificate_key),
      NULL },

#endif

    { njt_string("proxy_ssl_password_file"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_stream_proxy_ssl_password_file,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("proxy_ssl_conf_command"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE2,
      njt_conf_set_keyval_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, ssl_conf_commands),
      &njt_stream_proxy_ssl_conf_command_post },

#if (NJT_HAVE_NTLS)
    { njt_string("proxy_ssl_ntls"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proxy_srv_conf_t, ssl_ntls),
      NULL },
#endif
#if (NJT_HAVE_SET_ALPN)
     { njt_string("proxy_ssl_alpn"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_1MORE,
      njt_stream_proxy_ssl_alpn,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },
#endif
#endif

      njt_null_command
};


static njt_stream_module_t  njt_stream_proxy_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    njt_stream_proxy_create_srv_conf,      /* create server configuration */
    njt_stream_proxy_merge_srv_conf        /* merge server configuration */
};


njt_module_t  njt_stream_proxy_module = {
    NJT_MODULE_V1,
    &njt_stream_proxy_module_ctx,          /* module context */
    njt_stream_proxy_commands,             /* module directives */
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


void
njt_stream_proxy_handler(njt_stream_session_t *s)
{
    u_char                           *p;
    njt_str_t                        *host;
    njt_uint_t                        i;
    njt_connection_t                 *c;
    njt_resolver_ctx_t               *ctx, temp;
    njt_stream_upstream_t            *u;
    njt_stream_core_srv_conf_t       *cscf;
    njt_stream_proxy_srv_conf_t      *pscf;
    njt_stream_upstream_srv_conf_t   *uscf, **uscfp;
    njt_stream_upstream_main_conf_t  *umcf;
    njt_stream_proxy_ctx_t           *pctx; // openresty patch

    c = s->connection;

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_module);

    // openresty patch
    pctx = njt_palloc(c->pool, sizeof(njt_stream_proxy_ctx_t));
    if (pctx == NULL) {
        njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    pctx->connect_timeout = pscf->connect_timeout;
    pctx->timeout = pscf->timeout;

    njt_stream_set_ctx(s, pctx, njt_stream_proxy_module);
    // openresty patch end

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "proxy connection handler");

    u = njt_pcalloc(c->pool, sizeof(njt_stream_upstream_t));
    if (u == NULL) {
        njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    s->upstream = u;

    s->log_handler = njt_stream_proxy_log_error;

    u->requests = 1;

    u->peer.log = c->log;
    u->peer.log_error = NJT_ERROR_ERR;

    if (njt_stream_proxy_set_local(s, u, pscf->local) != NJT_OK) {
        njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (pscf->socket_keepalive) {
        u->peer.so_keepalive = 1;
    }

    u->peer.type = c->type;
    u->start_sec = njt_time();

    c->write->handler = njt_stream_proxy_downstream_handler;
    c->read->handler = njt_stream_proxy_downstream_handler;

    s->upstream_states = njt_array_create(c->pool, 1,
                                          sizeof(njt_stream_upstream_state_t));
    if (s->upstream_states == NULL) {
        njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    p = njt_pnalloc(c->pool, pscf->buffer_size);
    if (p == NULL) {
        njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->downstream_buf.start = p;
    u->downstream_buf.end = p + pscf->buffer_size;
    u->downstream_buf.pos = p;
    u->downstream_buf.last = p;

    if (c->read->ready) {
        njt_post_event(c->read, &njt_posted_events);
    }

    if (pscf->upstream_value) {
        if (njt_stream_proxy_eval(s, pscf) != NJT_OK) {
            njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (u->resolved == NULL) {
#if (NJT_STREAM_FTP_PROXY)
        if(NJT_OK != njt_stream_ftp_proxy_replace_upstream(s, &uscf)){
            uscf = pscf->upstream;
        }
#else
        uscf = pscf->upstream;
#endif
    } else {

#if (NJT_STREAM_SSL)
        u->ssl_name = u->resolved->host;
#endif

        host = &u->resolved->host;

        umcf = njt_stream_get_module_main_conf(s, njt_stream_upstream_module);

        uscfp = umcf->upstreams.elts;

        for (i = 0; i < umcf->upstreams.nelts; i++) {

            uscf = uscfp[i];

            if (uscf->host.len == host->len
                && ((uscf->port == 0 && u->resolved->no_port)
                     || uscf->port == u->resolved->port)
                && njt_strncasecmp(uscf->host.data, host->data, host->len) == 0)
            {
                goto found;
            }
        }

        if (u->resolved->sockaddr) {

            if (u->resolved->port == 0
                && u->resolved->sockaddr->sa_family != AF_UNIX)
            {
                njt_log_error(NJT_LOG_ERR, c->log, 0,
                              "no port in upstream \"%V\"", host);
                njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }

            if (njt_stream_upstream_create_round_robin_peer(s, u->resolved)
                != NJT_OK)
            {
                njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }

            njt_stream_proxy_connect(s);

            return;
        }

        if (u->resolved->port == 0) {
            njt_log_error(NJT_LOG_ERR, c->log, 0,
                          "no port in upstream \"%V\"", host);
            njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        temp.name = *host;

        cscf = njt_stream_get_module_srv_conf(s, njt_stream_core_module);

        ctx = njt_resolve_start(cscf->resolver, &temp);
        if (ctx == NULL) {
            njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        if (ctx == NJT_NO_RESOLVER) {
            njt_log_error(NJT_LOG_ERR, c->log, 0,
                          "no resolver defined to resolve %V", host);
            njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        ctx->name = *host;
        ctx->handler = njt_stream_proxy_resolve_handler;
        ctx->data = s;
        ctx->timeout = cscf->resolver_timeout;

        u->resolved->ctx = ctx;

        if (njt_resolve_name(ctx) != NJT_OK) {
            u->resolved->ctx = NULL;
            njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        return;
    }

found:

    if (uscf == NULL) {
        njt_log_error(NJT_LOG_ALERT, c->log, 0, "no upstream configuration");
        njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->upstream = uscf;

#if (NJT_STREAM_SSL)
    u->ssl_name = uscf->host;
#endif

    if (uscf->peer.init(s, uscf) != NJT_OK) {
        njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->peer.start_time = njt_current_msec;

    if (pscf->next_upstream_tries
        && u->peer.tries > pscf->next_upstream_tries)
    {
        u->peer.tries = pscf->next_upstream_tries;
    }

    njt_stream_proxy_connect(s);
}


static njt_int_t
njt_stream_proxy_eval(njt_stream_session_t *s,
    njt_stream_proxy_srv_conf_t *pscf)
{
    njt_str_t               host;
    njt_url_t               url;
    njt_stream_upstream_t  *u;

    if (njt_stream_complex_value(s, pscf->upstream_value, &host) != NJT_OK) {
        return NJT_ERROR;
    }

    njt_memzero(&url, sizeof(njt_url_t));

    url.url = host;
    url.no_resolve = 1;

    if (njt_parse_url(s->connection->pool, &url) != NJT_OK) {
        if (url.err) {
            njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                          "%s in upstream \"%V\"", url.err, &url.url);
        }

        return NJT_ERROR;
    }

    u = s->upstream;

    u->resolved = njt_pcalloc(s->connection->pool,
                              sizeof(njt_stream_upstream_resolved_t));
    if (u->resolved == NULL) {
        return NJT_ERROR;
    }

    if (url.addrs) {
        u->resolved->sockaddr = url.addrs[0].sockaddr;
        u->resolved->socklen = url.addrs[0].socklen;
        u->resolved->name = url.addrs[0].name;
        u->resolved->naddrs = 1;
    }

    u->resolved->host = url.host;
    u->resolved->port = url.port;
    u->resolved->no_port = url.no_port;

    return NJT_OK;
}


static njt_int_t
njt_stream_proxy_set_local(njt_stream_session_t *s, njt_stream_upstream_t *u,
    njt_stream_upstream_local_t *local)
{
    njt_int_t    rc;
    njt_str_t    val;
    njt_addr_t  *addr;

    if (local == NULL) {
        u->peer.local = NULL;
        return NJT_OK;
    }

#if (NJT_HAVE_TRANSPARENT_PROXY)
    u->peer.transparent = local->transparent;
#endif

    if (local->value == NULL) {
        u->peer.local = local->addr;
        return NJT_OK;
    }

    if (njt_stream_complex_value(s, local->value, &val) != NJT_OK) {
        return NJT_ERROR;
    }

    if (val.len == 0) {
        return NJT_OK;
    }

    addr = njt_palloc(s->connection->pool, sizeof(njt_addr_t));
    if (addr == NULL) {
        return NJT_ERROR;
    }

    rc = njt_parse_addr_port(s->connection->pool, addr, val.data, val.len);
    if (rc == NJT_ERROR) {
        return NJT_ERROR;
    }

    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                      "invalid local address \"%V\"", &val);
        return NJT_OK;
    }

    addr->name = val;
    u->peer.local = addr;

    return NJT_OK;
}


static void
njt_stream_proxy_connect(njt_stream_session_t *s)
{
    njt_int_t                     rc;
    njt_connection_t             *c, *pc;
    njt_stream_upstream_t        *u;
    njt_stream_proxy_srv_conf_t  *pscf;
    njt_stream_proxy_ctx_t       *ctx; // openresty patch
#if (NJT_STREAM_PROTOCOL_V2)
    njt_flag_t                     flag;
    njt_stream_variable_value_t  *value;
    njt_stream_proxy_protocol_tlv_srv_conf_t *scf = njt_stream_get_module_srv_conf(s,njt_stream_proxy_protocol_tlv_module);
    flag = NJT_CONF_UNSET;
    if(scf != NULL &&  scf->var_index != NJT_CONF_UNSET_UINT) {
        value = njt_stream_get_indexed_variable(s, scf->var_index);
        if (value != NULL &&  value->not_found == 0 && value->len == 1 && value->data[0] == '1') {
           flag = 1; 
        } else {
            flag = 0;
        }
    }
#endif

    c = s->connection;

    c->log->action = "connecting to upstream";

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_module);

    ctx = njt_stream_get_module_ctx(s, njt_stream_proxy_module); // openresty patch

    u = s->upstream;

    u->connected = 0;
    u->proxy_protocol = pscf->proxy_protocol;
#if (NJT_STREAM_PROTOCOL_V2)
    u->proxy_protocol = (flag != NJT_CONF_UNSET ? flag:pscf->proxy_protocol);
#endif

    if (u->state) {
        u->state->response_time = njt_current_msec - u->start_time;
    }

    u->state = njt_array_push(s->upstream_states);
    if (u->state == NULL) {
        njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    njt_memzero(u->state, sizeof(njt_stream_upstream_state_t));

    u->start_time = njt_current_msec;

    u->state->connect_time = (njt_msec_t) -1;
    u->state->first_byte_time = (njt_msec_t) -1;
    u->state->response_time = (njt_msec_t) -1;

    rc = njt_event_connect_peer(&u->peer);

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0, "proxy connect: %i", rc);

    if (rc == NJT_ERROR) {
        njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    // openresy patch
    if (rc >= NJT_STREAM_SPECIAL_RESPONSE) {
        njt_stream_proxy_finalize(s, rc);
        return;
    }
    // openresy patch end



    u->state->peer = u->peer.name;

    if (rc == NJT_BUSY) {
        njt_log_error(NJT_LOG_ERR, c->log, 0, "no live upstreams");
        njt_stream_proxy_finalize(s, NJT_STREAM_BAD_GATEWAY);
        return;
    }

    if (rc == NJT_DECLINED) {
        njt_stream_proxy_next_upstream(s);
        return;
    }

    /* rc == NJT_OK || rc == NJT_AGAIN || rc == NJT_DONE */

    pc = u->peer.connection;

    pc->data = s;
    pc->log = c->log;
    pc->pool = c->pool;
    pc->read->log = c->log;
    pc->write->log = c->log;

    if (rc != NJT_AGAIN) {
        njt_stream_proxy_init_upstream(s);
        return;
    }

    pc->read->handler = njt_stream_proxy_connect_handler;
    pc->write->handler = njt_stream_proxy_connect_handler;

    // njt_add_timer(pc->write, pscf->connect_timeout); openresty patch
    njt_add_timer(pc->write, ctx->connect_timeout); // openresty patch
}


static void
njt_stream_proxy_init_upstream(njt_stream_session_t *s)
{
    u_char                       *p;
    njt_chain_t                  *cl;
    njt_connection_t             *c, *pc;
    njt_log_handler_pt            handler;
    njt_stream_upstream_t        *u;
    njt_stream_core_srv_conf_t   *cscf;
    njt_stream_proxy_srv_conf_t  *pscf;

    u = s->upstream;
    pc = u->peer.connection;

    cscf = njt_stream_get_module_srv_conf(s, njt_stream_core_module);

    if (pc->type == SOCK_STREAM
        && cscf->tcp_nodelay
        && njt_tcp_nodelay(pc) != NJT_OK)
    {
        njt_stream_proxy_next_upstream(s);
        return;
    }

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_module);

#if (NJT_STREAM_SSL)

    if (pc->type == SOCK_STREAM && pscf->ssl_enable) {

        if (u->proxy_protocol) {
            if (njt_stream_proxy_send_proxy_protocol(s) != NJT_OK) {
                return;
            }

            u->proxy_protocol = 0;
        }

        if (pc->ssl == NULL) {
            njt_stream_proxy_ssl_init_connection(s);
            return;
        }
    }

#endif

    c = s->connection;

    if (c->log->log_level >= NJT_LOG_INFO) {
        njt_str_t  str;
        u_char     addr[NJT_SOCKADDR_STRLEN];

        str.len = NJT_SOCKADDR_STRLEN;
        str.data = addr;

        if (njt_connection_local_sockaddr(pc, &str, 1) == NJT_OK) {
            handler = c->log->handler;
            c->log->handler = NULL;

            njt_log_error(NJT_LOG_INFO, c->log, 0,
                          "%sproxy %V connected to %V",
                          pc->type == SOCK_DGRAM ? "udp " : "",
                          &str, u->peer.name);

            c->log->handler = handler;
        }
    }

    u->state->connect_time = njt_current_msec - u->start_time;

    if (u->peer.notify) {
        u->peer.notify(&u->peer, u->peer.data,
                       NJT_STREAM_UPSTREAM_NOTIFY_CONNECT);
    }

    if (u->upstream_buf.start == NULL) {
        p = njt_pnalloc(c->pool, pscf->buffer_size);
        if (p == NULL) {
            njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        u->upstream_buf.start = p;
        u->upstream_buf.end = p + pscf->buffer_size;
        u->upstream_buf.pos = p;
        u->upstream_buf.last = p;
    }

    if (c->buffer && c->buffer->pos <= c->buffer->last) {
        njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                       "stream proxy add preread buffer: %uz",
                       c->buffer->last - c->buffer->pos);

        cl = njt_chain_get_free_buf(c->pool, &u->free);
        if (cl == NULL) {
            njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        *cl->buf = *c->buffer;

        cl->buf->tag = (njt_buf_tag_t) &njt_stream_proxy_module;
        cl->buf->temporary = (cl->buf->pos == cl->buf->last) ? 0 : 1;
        cl->buf->flush = 1;

        cl->next = u->upstream_out;
        u->upstream_out = cl;
    }

    if (u->proxy_protocol) {
        njt_log_debug0(NJT_LOG_DEBUG_STREAM, c->log, 0,
                       "stream proxy add PROXY protocol header");

        cl = njt_chain_get_free_buf(c->pool, &u->free);
        if (cl == NULL) {
            njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        p = njt_pnalloc(c->pool, NJT_PROXY_PROTOCOL_MAX_HEADER);
        if (p == NULL) {
            njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        cl->buf->pos = p;

        p = njt_proxy_protocol_v2_write(s, p, p + NJT_PROXY_PROTOCOL_MAX_HEADER);
        if (p == NULL) {
            njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        cl->buf->last = p;
        cl->buf->temporary = 1;
        cl->buf->flush = 0;
        cl->buf->last_buf = 0;
        cl->buf->tag = (njt_buf_tag_t) &njt_stream_proxy_module;

        cl->next = u->upstream_out;
        u->upstream_out = cl;

        u->proxy_protocol = 0;
    }

    u->upload_rate = njt_stream_complex_value_size(s, pscf->upload_rate, 0);
    u->download_rate = njt_stream_complex_value_size(s, pscf->download_rate, 0);

    u->connected = 1;

    pc->read->handler = njt_stream_proxy_upstream_handler;
    pc->write->handler = njt_stream_proxy_upstream_handler;

    if (pc->read->ready) {
        njt_post_event(pc->read, &njt_posted_events);
    }

    njt_stream_proxy_process(s, 0, 1);
}


#if (NJT_STREAM_SSL)

static njt_int_t
njt_stream_proxy_send_proxy_protocol(njt_stream_session_t *s)
{
    // openresty patch
    // u_char                       *p;
    // ssize_t                       n, size;
    // njt_connection_t             *c, *pc;
    // njt_stream_upstream_t        *u;
    // njt_stream_proxy_srv_conf_t  *pscf;
    // u_char                        buf[NJT_PROXY_PROTOCOL_MAX_HEADER];
    u_char                  *p;
    u_char                   buf[NJT_PROXY_PROTOCOL_MAX_HEADER];
    ssize_t                  n, size;
    njt_connection_t        *c, *pc;
    njt_stream_upstream_t   *u;
    njt_stream_proxy_ctx_t  *ctx;

    ctx = njt_stream_get_module_ctx(s, njt_stream_proxy_module);
    // openresty patch end


    c = s->connection;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "stream proxy send PROXY protocol header");

    p = njt_proxy_protocol_v2_write(s, buf, buf + NJT_PROXY_PROTOCOL_MAX_HEADER);
    if (p == NULL) {
        njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return NJT_ERROR;
    }

    u = s->upstream;

    pc = u->peer.connection;

    size = p - buf;

    n = pc->send(pc, buf, size);

    if (n == NJT_AGAIN) {
        if (njt_handle_write_event(pc->write, 0) != NJT_OK) {
            njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return NJT_ERROR;
        }

        // openresty patch
        // pscf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_module);

        // njt_add_timer(pc->write, pscf->timeout);
        njt_add_timer(pc->write, ctx->timeout);
        // openresty patch end

        pc->write->handler = njt_stream_proxy_connect_handler;

        return NJT_AGAIN;
    }

    if (n == NJT_ERROR) {
        njt_stream_proxy_finalize(s, NJT_STREAM_OK);
        return NJT_ERROR;
    }

    if (n != size) {

        /*
         * PROXY protocol specification:
         * The sender must always ensure that the header
         * is sent at once, so that the transport layer
         * maintains atomicity along the path to the receiver.
         */

        njt_log_error(NJT_LOG_ERR, c->log, 0,
                      "could not send PROXY protocol header at once");

        njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);

        return NJT_ERROR;
    }

    return NJT_OK;
}


static char *
njt_stream_proxy_ssl_password_file(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    njt_stream_proxy_srv_conf_t *pscf = conf;

    njt_str_t  *value;

    if (pscf->ssl_passwords != NJT_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    pscf->ssl_passwords = njt_ssl_read_password_file(cf, &value[1]);

    if (pscf->ssl_passwords == NULL) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static char *
njt_stream_proxy_ssl_conf_command_check(njt_conf_t *cf, void *post, void *data)
{
#ifndef SSL_CONF_FLAG_FILE
    return "is not supported on this platform";
#else
    return NJT_CONF_OK;
#endif
}


static void
njt_stream_proxy_ssl_init_connection(njt_stream_session_t *s)
{
    njt_int_t                     rc;
    njt_connection_t             *pc;
    njt_stream_upstream_t        *u;
    njt_stream_proxy_srv_conf_t  *pscf;
    njt_stream_proxy_ctx_t       *ctx; // openresy patch

    ctx = njt_stream_get_module_ctx(s, njt_stream_proxy_module); // openresty patch


    u = s->upstream;

    pc = u->peer.connection;

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_module);

#if (NJT_HAVE_NTLS)
    if (pscf->ssl_ntls) {

        SSL_CTX_set_ssl_version(pscf->ssl->ctx, NTLS_method());
        SSL_CTX_set_cipher_list(pscf->ssl->ctx,
                                (char *) pscf->ssl_ciphers.data);
        SSL_CTX_enable_ntls(pscf->ssl->ctx);
    }
#endif

    if (njt_ssl_create_connection(pscf->ssl, pc, NJT_SSL_BUFFER|NJT_SSL_CLIENT)
        != NJT_OK)
    {
        njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (pscf->ssl_server_name || pscf->ssl_verify) {
        if (njt_stream_proxy_ssl_name(s) != NJT_OK) {
            njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

#if (NJT_STREAM_MULTICERT)

    if (pscf->ssl_certificate_values) {
        if (njt_stream_proxy_ssl_certificates(s) != NJT_OK) {
            njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

#else

    if (pscf->ssl_certificate
        && pscf->ssl_certificate->value.len
        && (pscf->ssl_certificate->lengths
            || pscf->ssl_certificate_key->lengths))
    {
        if (njt_stream_proxy_ssl_certificate(s) != NJT_OK) {
            njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

#endif

    if (pscf->ssl_session_reuse) {
        pc->ssl->save_session = njt_stream_proxy_ssl_save_session;

        if (u->peer.set_session(&u->peer, u->peer.data) != NJT_OK) {
            njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    s->connection->log->action = "SSL handshaking to upstream";

    rc = njt_ssl_handshake(pc);

    if (rc == NJT_AGAIN) {

        if (!pc->write->timer_set) {
            // njt_add_timer(pc->write, pscf->connect_timeout); openresty patch
            njt_add_timer(pc->write, ctx->connect_timeout); // openresty patch
        }

        pc->ssl->handler = njt_stream_proxy_ssl_handshake;
        return;
    }

    njt_stream_proxy_ssl_handshake(pc);
}


static void
njt_stream_proxy_ssl_handshake(njt_connection_t *pc)
{
    long                          rc;
    njt_stream_session_t         *s;
    njt_stream_upstream_t        *u;
    njt_stream_proxy_srv_conf_t  *pscf;

    s = pc->data;

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_module);

    if (pc->ssl->handshaked) {

        if (pscf->ssl_verify) {
            rc = SSL_get_verify_result(pc->ssl->connection);

            if (rc != X509_V_OK) {
                njt_log_error(NJT_LOG_ERR, pc->log, 0,
                              "upstream SSL certificate verify error: (%l:%s)",
                              rc, X509_verify_cert_error_string(rc));
                goto failed;
            }

            u = s->upstream;

            if (njt_ssl_check_host(pc, &u->ssl_name) != NJT_OK) {
                njt_log_error(NJT_LOG_ERR, pc->log, 0,
                              "upstream SSL certificate does not match \"%V\"",
                              &u->ssl_name);
                goto failed;
            }
        }

        if (pc->write->timer_set) {
            njt_del_timer(pc->write);
        }

        njt_stream_proxy_init_upstream(s);

        return;
    }

failed:

    njt_stream_proxy_next_upstream(s);
}


static void
njt_stream_proxy_ssl_save_session(njt_connection_t *c)
{
    njt_stream_session_t   *s;
    njt_stream_upstream_t  *u;

    s = c->data;
    u = s->upstream;

    u->peer.save_session(&u->peer, u->peer.data);
}


static njt_int_t
njt_stream_proxy_ssl_name(njt_stream_session_t *s)
{
    u_char                       *p, *last;
    njt_str_t                     name;
    njt_stream_upstream_t        *u;
    njt_stream_proxy_srv_conf_t  *pscf;

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_module);

    u = s->upstream;

    if (pscf->ssl_name) {
        if (njt_stream_complex_value(s, pscf->ssl_name, &name) != NJT_OK) {
            return NJT_ERROR;
        }

    } else {
        name = u->ssl_name;
    }

    if (name.len == 0) {
        goto done;
    }

    /*
     * ssl name here may contain port, strip it for compatibility
     * with the http module
     */

    p = name.data;
    last = name.data + name.len;

    if (*p == '[') {
        p = njt_strlchr(p, last, ']');

        if (p == NULL) {
            p = name.data;
        }
    }

    p = njt_strlchr(p, last, ':');

    if (p != NULL) {
        name.len = p - name.data;
    }

    if (!pscf->ssl_server_name) {
        goto done;
    }

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

    /* as per RFC 6066, literal IPv4 and IPv6 addresses are not permitted */

    if (name.len == 0 || *name.data == '[') {
        goto done;
    }

    if (njt_inet_addr(name.data, name.len) != INADDR_NONE) {
        goto done;
    }

    /*
     * SSL_set_tlsext_host_name() needs a null-terminated string,
     * hence we explicitly null-terminate name here
     */

    p = njt_pnalloc(s->connection->pool, name.len + 1);
    if (p == NULL) {
        return NJT_ERROR;
    }

    (void) njt_cpystrn(p, name.data, name.len + 1);

    name.data = p;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "upstream SSL server name: \"%s\"", name.data);

    if (SSL_set_tlsext_host_name(u->peer.connection->ssl->connection,
                                 (char *) name.data)
        == 0)
    {
        njt_ssl_error(NJT_LOG_ERR, s->connection->log, 0,
                      "SSL_set_tlsext_host_name(\"%s\") failed", name.data);
        return NJT_ERROR;
    }

#endif

done:

    u->ssl_name = name;

    return NJT_OK;
}


#if (NJT_STREAM_MULTICERT)

static njt_int_t
njt_stream_proxy_ssl_certificates(njt_stream_session_t *s)
{
    njt_str_t                    *certp, *keyp, cert, key;
    njt_uint_t                    i, nelts;
#if (NJT_HAVE_NTLS)
    njt_str_t                     tcert, tkey;
#endif
    njt_connection_t             *c;
    njt_stream_complex_value_t   *certs, *keys;
    njt_stream_proxy_srv_conf_t  *pscf;

    c = s->upstream->peer.connection;

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_module);


    nelts = pscf->ssl_certificate_values->nelts;
    certs = pscf->ssl_certificate_values->elts;
    keys = pscf->ssl_certificate_key_values->elts;

    for (i = 0; i < nelts; i++) {
        certp = &cert;
        keyp = &key;

        if (njt_stream_complex_value(s, &certs[i], certp) != NJT_OK) {
            return NJT_ERROR;
        }

#if (NJT_HAVE_NTLS)
        tcert = *certp;
        njt_ssl_ntls_prefix_strip(&tcert);
        certp = &cert;
#endif

        if (*certp->data == 0) {
            continue;
        }

        njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                       "stream upstream ssl cert: \"%s\"", certp->data);

        if (njt_stream_complex_value(s, &keys[i], keyp) != NJT_OK) {
            return NJT_ERROR;
        }

#if (NJT_HAVE_NTLS)
        tkey = *keyp;
        njt_ssl_ntls_prefix_strip(&tkey);
        keyp = &key;
#endif

        njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                       "stream upstream ssl key: \"%s\"", keyp->data);

        if (njt_ssl_connection_certificate(c, s->connection->pool, certp, keyp,
                                           pscf->ssl_passwords)
            != NJT_OK)
        {
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}

#else

static njt_int_t
njt_stream_proxy_ssl_certificate(njt_stream_session_t *s)
{
    njt_str_t                     cert, key;
    njt_connection_t             *c;
    njt_stream_proxy_srv_conf_t  *pscf;

    c = s->upstream->peer.connection;

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_module);

    if (njt_stream_complex_value(s, pscf->ssl_certificate, &cert)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "stream upstream ssl cert: \"%s\"", cert.data);

    if (*cert.data == '\0') {
        return NJT_OK;
    }

    if (njt_stream_complex_value(s, pscf->ssl_certificate_key, &key)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "stream upstream ssl key: \"%s\"", key.data);

    if (njt_ssl_connection_certificate(c, c->pool, &cert, &key,
                                       pscf->ssl_passwords)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    return NJT_OK;
}

#endif

#endif


static void
njt_stream_proxy_downstream_handler(njt_event_t *ev)
{
    njt_stream_proxy_process_connection(ev, ev->write);
}


static void
njt_stream_proxy_resolve_handler(njt_resolver_ctx_t *ctx)
{
    njt_stream_session_t            *s;
    njt_stream_upstream_t           *u;
    njt_stream_proxy_srv_conf_t     *pscf;
    njt_stream_upstream_resolved_t  *ur;

    s = ctx->data;

    u = s->upstream;
    ur = u->resolved;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream upstream resolve");

    if (ctx->state) {
        njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &ctx->name, ctx->state,
                      njt_resolver_strerror(ctx->state));

        njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ur->naddrs = ctx->naddrs;
    ur->addrs = ctx->addrs;

#if (NJT_DEBUG)
    {
    u_char      text[NJT_SOCKADDR_STRLEN];
    njt_str_t   addr;
    njt_uint_t  i;

    addr.data = text;

    for (i = 0; i < ctx->naddrs; i++) {
        addr.len = njt_sock_ntop(ur->addrs[i].sockaddr, ur->addrs[i].socklen,
                                 text, NJT_SOCKADDR_STRLEN, 0);

        njt_log_debug1(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "name was resolved to %V", &addr);
    }
    }
#endif

    if (njt_stream_upstream_create_round_robin_peer(s, ur) != NJT_OK) {
        njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    njt_resolve_name_done(ctx);
    ur->ctx = NULL;

    u->peer.start_time = njt_current_msec;

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_module);

    if (pscf->next_upstream_tries
        && u->peer.tries > pscf->next_upstream_tries)
    {
        u->peer.tries = pscf->next_upstream_tries;
    }

    njt_stream_proxy_connect(s);
}


static void
njt_stream_proxy_upstream_handler(njt_event_t *ev)
{
    njt_stream_proxy_process_connection(ev, !ev->write);
}


static void
njt_stream_proxy_process_connection(njt_event_t *ev, njt_uint_t from_upstream)
{
    njt_connection_t             *c, *pc;
    njt_log_handler_pt            handler;
    njt_stream_session_t         *s;
    njt_stream_upstream_t        *u;
    njt_stream_proxy_srv_conf_t  *pscf;
    njt_stream_proxy_ctx_t       *ctx; // openresty patch

    c = ev->data;
    s = c->data;
    u = s->upstream;

    if (c->close) {
        njt_log_error(NJT_LOG_INFO, c->log, 0, "shutdown timeout");
        njt_stream_proxy_finalize(s, NJT_STREAM_OK);
        return;
    }

    ctx = njt_stream_get_module_ctx(s, njt_stream_proxy_module); // openresty patch

    c = s->connection;
    pc = u->peer.connection;

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_module);

    if (ev->timedout) {
        ev->timedout = 0;

        if (ev->delayed) {
            ev->delayed = 0;

            if (!ev->ready) {
                if (njt_handle_read_event(ev, 0) != NJT_OK) {
                    njt_stream_proxy_finalize(s,
                                              NJT_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                if (u->connected && !c->read->delayed && !pc->read->delayed) {
                    // njt_add_timer(c->write, pscf->timeout); openresty patch
                    njt_add_timer(c->write, ctx->timeout); // openresty patch
                }

                return;
            }

        } else {
            if (s->connection->type == SOCK_DGRAM) {

                if (pscf->responses == NJT_MAX_INT32_VALUE
                    || (u->responses >= pscf->responses * u->requests))
                {

                    /*
                     * successfully terminate timed out UDP session
                     * if expected number of responses was received
                     */

                    handler = c->log->handler;
                    c->log->handler = NULL;

                    njt_log_error(NJT_LOG_INFO, c->log, 0,
                                  "udp timed out"
                                  ", packets from/to client:%ui/%ui"
                                  ", bytes from/to client:%O/%O"
                                  ", bytes from/to upstream:%O/%O",
                                  u->requests, u->responses,
                                  s->received, c->sent, u->received,
                                  pc ? pc->sent : 0);

                    c->log->handler = handler;

                    njt_stream_proxy_finalize(s, NJT_STREAM_OK);
                    return;
                }

                njt_connection_error(pc, NJT_ETIMEDOUT, "upstream timed out");

                pc->read->error = 1;

                njt_stream_proxy_finalize(s, NJT_STREAM_BAD_GATEWAY);

                return;
            }

            njt_connection_error(c, NJT_ETIMEDOUT, "connection timed out");

            njt_stream_proxy_finalize(s, NJT_STREAM_OK);

            return;
        }

    } else if (ev->delayed) {

        njt_log_debug0(NJT_LOG_DEBUG_STREAM, c->log, 0,
                       "stream connection delayed");

        if (njt_handle_read_event(ev, 0) != NJT_OK) {
            njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        }

        return;
    }

    if (from_upstream && !u->connected) {
        return;
    }

    njt_stream_proxy_process(s, from_upstream, ev->write);
}


static void
njt_stream_proxy_connect_handler(njt_event_t *ev)
{
    njt_connection_t      *c;
    njt_stream_session_t  *s;

    c = ev->data;
    s = c->data;

    if (ev->timedout) {
        njt_log_error(NJT_LOG_ERR, c->log, NJT_ETIMEDOUT, "upstream timed out");
        njt_stream_proxy_next_upstream(s);
        return;
    }

    njt_del_timer(c->write);

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "stream proxy connect upstream");

    if (njt_stream_proxy_test_connect(c) != NJT_OK) {
        njt_stream_proxy_next_upstream(s);
        return;
    }

    njt_stream_proxy_init_upstream(s);
}


static njt_int_t
njt_stream_proxy_test_connect(njt_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (NJT_HAVE_KQUEUE)

    if (njt_event_flags & NJT_USE_KQUEUE_EVENT)  {
        err = c->write->kq_errno ? c->write->kq_errno : c->read->kq_errno;

        if (err) {
            (void) njt_connection_error(c, err,
                                    "kevent() reported that connect() failed");
            return NJT_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = njt_socket_errno;
        }

        if (err) {
            (void) njt_connection_error(c, err, "connect() failed");
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


static void
njt_stream_proxy_process(njt_stream_session_t *s, njt_uint_t from_upstream,
    njt_uint_t do_write)
{
    char                         *recv_action, *send_action;
    off_t                        *received, limit;
    size_t                        size, limit_rate;
    ssize_t                       n;
    njt_buf_t                    *b;
    njt_int_t                     rc;
    njt_uint_t                    flags, *packets;
    njt_msec_t                    delay;
    njt_chain_t                  *cl, **ll, **out, **busy;
    njt_connection_t             *c, *pc, *src, *dst;
    njt_log_handler_pt            handler;
    njt_stream_upstream_t        *u;
    njt_stream_proxy_srv_conf_t  *pscf;
    njt_stream_proxy_ctx_t       *ctx; // openresty patch

    ctx = njt_stream_get_module_ctx(s, njt_stream_proxy_module); // openresty patch

    u = s->upstream;

    c = s->connection;
    pc = u->connected ? u->peer.connection : NULL;

    if (c->type == SOCK_DGRAM && (njt_terminate || njt_exiting)) {

        /* socket is already closed on worker shutdown */

        handler = c->log->handler;
        c->log->handler = NULL;

        njt_log_error(NJT_LOG_INFO, c->log, 0, "disconnected on shutdown");

        c->log->handler = handler;

        njt_stream_proxy_finalize(s, NJT_STREAM_OK);
        return;
    }

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_module);

    if (from_upstream) {
        src = pc;
        dst = c;
        b = &u->upstream_buf;
        limit_rate = u->download_rate;
        received = &u->received;
        packets = &u->responses;
        out = &u->downstream_out;
        busy = &u->downstream_busy;
        recv_action = "proxying and reading from upstream";
        send_action = "proxying and sending to client";

    } else {
        src = c;
        dst = pc;
        b = &u->downstream_buf;
        limit_rate = u->upload_rate;
        received = &s->received;
        packets = &u->requests;
        out = &u->upstream_out;
        busy = &u->upstream_busy;
        recv_action = "proxying and reading from client";
        send_action = "proxying and sending to upstream";
    }

    for ( ;; ) {

        if (do_write && dst) {

            if (*out || *busy || dst->buffered) {
                c->log->action = send_action;

                rc = njt_stream_top_filter(s, *out, from_upstream);

                if (rc == NJT_ERROR) {
                    njt_stream_proxy_finalize(s, NJT_STREAM_OK);
                    return;
                }

                njt_chain_update_chains(c->pool, &u->free, busy, out,
                                      (njt_buf_tag_t) &njt_stream_proxy_module);

                if (*busy == NULL) {
                    b->pos = b->start;
                    b->last = b->start;
                }
            }
        }

        size = b->end - b->last;

        if (size && src != NULL && src->read->ready && !src->read->delayed ) {

            if (limit_rate) {
                limit = (off_t) limit_rate * (njt_time() - u->start_sec + 1)
                        - *received;

                if (limit <= 0) {
                    src->read->delayed = 1;
                    delay = (njt_msec_t) (- limit * 1000 / limit_rate + 1);
                    njt_add_timer(src->read, delay);
                    break;
                }

                if (c->type == SOCK_STREAM && (off_t) size > limit) {
                    size = (size_t) limit;
                }
            }

            c->log->action = recv_action;

            n = src->recv(src, b->last, size);

            if (n == NJT_AGAIN) {
                break;
            }

            if (n == NJT_ERROR) {
                src->read->eof = 1;
                n = 0;
            }

            if (n >= 0) {
#ifdef NJT_STREAM_FTP_PROXY
                //if ftp_proxy, need replace data port
                if(from_upstream){
                    njt_stream_ftp_proxy_filter_pasv(s, b->last, &n);
                }
#endif

                if (limit_rate) {
                    delay = (njt_msec_t) (n * 1000 / limit_rate);

                    if (delay > 0) {
                        src->read->delayed = 1;
                        njt_add_timer(src->read, delay);
                    }
                }

                if (from_upstream) {
                    if (u->state->first_byte_time == (njt_msec_t) -1) {
                        u->state->first_byte_time = njt_current_msec
                                                    - u->start_time;
                    }
                }

                for (ll = out; *ll; ll = &(*ll)->next) { /* void */ }

                cl = njt_chain_get_free_buf(c->pool, &u->free);
                if (cl == NULL) {
                    njt_stream_proxy_finalize(s,
                                              NJT_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                *ll = cl;

                cl->buf->pos = b->last;
                cl->buf->last = b->last + n;
                cl->buf->tag = (njt_buf_tag_t) &njt_stream_proxy_module;

                cl->buf->temporary = (n ? 1 : 0);
                cl->buf->last_buf = src->read->eof;
                cl->buf->flush = !src->read->eof;

                (*packets)++;
                *received += n;
                b->last += n;
                do_write = 1;

                continue;
            }
        }

        break;
    }

    c->log->action = "proxying connection";

    if (njt_stream_proxy_test_finalize(s, from_upstream) == NJT_OK) {
        return;
    }
    if(src == NULL || src->read == NULL) {
	njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                      "src or src->read is null");
	return;
    }
    flags = src->read->eof ? NJT_CLOSE_EVENT : 0;

    if (njt_handle_read_event(src->read, flags) != NJT_OK) {
        njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (dst) {

        if (dst->type == SOCK_STREAM && pscf->half_close
            && src != NULL &&  src->read->eof && !u->half_closed && !dst->buffered)
        {

            if (njt_shutdown_socket(dst->fd, NJT_WRITE_SHUTDOWN) == -1) {
                njt_connection_error(c, njt_socket_errno,
                                     njt_shutdown_socket_n " failed");

                njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }

            u->half_closed = 1;
            njt_log_debug1(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                           "stream proxy %s socket shutdown",
                           from_upstream ? "client" : "upstream");
        }

        if (njt_handle_write_event(dst->write, 0) != NJT_OK) {
            njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        if (!c->read->delayed && !pc->read->delayed) {
            // njt_add_timer(c->write, pscf->timeout); openresty patch
            njt_add_timer(c->write, ctx->timeout); // openresty patch

        } else if (c->write->timer_set) {
            njt_del_timer(c->write);
        }
    }
}


static njt_int_t
njt_stream_proxy_test_finalize(njt_stream_session_t *s,
    njt_uint_t from_upstream)
{
    njt_connection_t             *c, *pc;
    njt_log_handler_pt            handler;
    njt_stream_upstream_t        *u;
    njt_stream_proxy_srv_conf_t  *pscf;

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_module);

    c = s->connection;
    u = s->upstream;
    pc = u->connected ? u->peer.connection : NULL;

    if (c->type == SOCK_DGRAM) {

        if (pscf->requests && u->requests < pscf->requests) {
            return NJT_DECLINED;
        }

        if (pscf->requests) {
            njt_delete_udp_connection(c);
        }

        if (pscf->responses == NJT_MAX_INT32_VALUE
            || u->responses < pscf->responses * u->requests)
        {
            return NJT_DECLINED;
        }

        if (pc == NULL || c->buffered || pc->buffered) {
            return NJT_DECLINED;
        }

        handler = c->log->handler;
        c->log->handler = NULL;

        njt_log_error(NJT_LOG_INFO, c->log, 0,
                      "udp done"
                      ", packets from/to client:%ui/%ui"
                      ", bytes from/to client:%O/%O"
                      ", bytes from/to upstream:%O/%O",
                      u->requests, u->responses,
                      s->received, c->sent, u->received, pc ? pc->sent : 0);

        c->log->handler = handler;

        njt_stream_proxy_finalize(s, NJT_STREAM_OK);

        return NJT_OK;
    }

    /* c->type == SOCK_STREAM */

    if (pc == NULL
        || (!c->read->eof && !pc->read->eof)
        || (!c->read->eof && c->buffered)
        || (!pc->read->eof && pc->buffered))
    {
        return NJT_DECLINED;
    }

    if (pscf->half_close) {
        /* avoid closing live connections until both read ends get EOF */
        if (!(c->read->eof && pc->read->eof && !c->buffered && !pc->buffered)) {
             return NJT_DECLINED;
        }
    }

    handler = c->log->handler;
    c->log->handler = NULL;

    njt_log_error(NJT_LOG_INFO, c->log, 0,
                  "%s disconnected"
                  ", bytes from/to client:%O/%O"
                  ", bytes from/to upstream:%O/%O",
                  from_upstream ? "upstream" : "client",
                  s->received, c->sent, u->received, pc ? pc->sent : 0);

    c->log->handler = handler;

    njt_stream_proxy_finalize(s, NJT_STREAM_OK);

    return NJT_OK;
}


static void
njt_stream_proxy_next_upstream(njt_stream_session_t *s)
{
    njt_msec_t                    timeout;
    njt_connection_t             *pc;
    njt_stream_upstream_t        *u;
    njt_stream_proxy_srv_conf_t  *pscf;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream proxy next upstream");

    u = s->upstream;
    pc = u->peer.connection;

    if (pc && pc->buffered) {
        njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                      "buffered data on next upstream");
        njt_stream_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (s->connection->type == SOCK_DGRAM) {
        u->upstream_out = NULL;
    }

    if (u->peer.sockaddr) {
        u->peer.free(&u->peer, u->peer.data, NJT_PEER_FAILED);
        u->peer.sockaddr = NULL;
    }

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_module);

    timeout = pscf->next_upstream_timeout;

    if (u->peer.tries == 0
        || !pscf->next_upstream
        || (timeout && njt_current_msec - u->peer.start_time >= timeout))
    {
        njt_stream_proxy_finalize(s, NJT_STREAM_BAD_GATEWAY);
        return;
    }

    if (pc) {
        njt_log_debug1(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "close proxy upstream connection: %d", pc->fd);

#if (NJT_STREAM_SSL)
        if (pc->ssl) {
            pc->ssl->no_wait_shutdown = 1;
            pc->ssl->no_send_shutdown = 1;

            (void) njt_ssl_shutdown(pc);
        }
#endif

        u->state->bytes_received = u->received;
        u->state->bytes_sent = pc->sent;

        njt_close_connection(pc);
        u->peer.connection = NULL;
    }

    njt_stream_proxy_connect(s);
}


static void
njt_stream_proxy_finalize(njt_stream_session_t *s, njt_uint_t rc)
{
    njt_uint_t              state;
    njt_connection_t       *pc;
    njt_stream_upstream_t  *u;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "finalize stream proxy: %i", rc);

    u = s->upstream;

    if (u == NULL) {
        goto noupstream;
    }

    if (u->resolved && u->resolved->ctx) {
        njt_resolve_name_done(u->resolved->ctx);
        u->resolved->ctx = NULL;
    }

    pc = u->peer.connection;

    if (u->state) {
        if (u->state->response_time == (njt_msec_t) -1) {
            u->state->response_time = njt_current_msec - u->start_time;
        }

        if (pc) {
            u->state->bytes_received = u->received;
            u->state->bytes_sent = pc->sent;
        }
    }

    if (u->peer.free && u->peer.sockaddr) {
        state = 0;

        if (pc && pc->type == SOCK_DGRAM
            && (pc->read->error || pc->write->error))
        {
            state = NJT_PEER_FAILED;
        }

        u->peer.free(&u->peer, u->peer.data, state);
        u->peer.sockaddr = NULL;
    }

    if (pc) {
        njt_log_debug1(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "close stream proxy upstream connection: %d", pc->fd);

#if (NJT_STREAM_SSL)
        if (pc->ssl) {
            pc->ssl->no_wait_shutdown = 1;
            (void) njt_ssl_shutdown(pc);
        }
#endif

        njt_close_connection(pc);
        u->peer.connection = NULL;
    }


noupstream:

    njt_stream_finalize_session(s, rc);
}


static u_char *
njt_stream_proxy_log_error(njt_log_t *log, u_char *buf, size_t len)
{
    u_char                 *p;
    njt_connection_t       *pc;
    njt_stream_session_t   *s;
    njt_stream_upstream_t  *u;

    s = log->data;

    u = s->upstream;

    p = buf;

    if (u->peer.name) {
        p = njt_snprintf(p, len, ", upstream: \"%V\"", u->peer.name);
        len -= p - buf;
    }

    pc = u->peer.connection;

    p = njt_snprintf(p, len,
                     ", bytes from/to client:%O/%O"
                     ", bytes from/to upstream:%O/%O",
                     s->received, s->connection->sent,
                     u->received, pc ? pc->sent : 0);

    return p;
}


static void *
njt_stream_proxy_create_srv_conf(njt_conf_t *cf)
{
    njt_stream_proxy_srv_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_stream_proxy_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->ssl_protocols = 0;
     *     conf->ssl_ciphers = { 0, NULL };
     *     conf->ssl_trusted_certificate = { 0, NULL };
     *     conf->ssl_crl = { 0, NULL };
     *
     *     conf->ssl = NULL;
     *     conf->upstream = NULL;
     *     conf->upstream_value = NULL;
     */

    conf->connect_timeout = NJT_CONF_UNSET_MSEC;
    conf->timeout = NJT_CONF_UNSET_MSEC;
    conf->next_upstream_timeout = NJT_CONF_UNSET_MSEC;
    conf->buffer_size = NJT_CONF_UNSET_SIZE;
    conf->upload_rate = NJT_CONF_UNSET_PTR;
    conf->download_rate = NJT_CONF_UNSET_PTR;
    conf->requests = NJT_CONF_UNSET_UINT;
    conf->responses = NJT_CONF_UNSET_UINT;
    conf->next_upstream_tries = NJT_CONF_UNSET_UINT;
    conf->next_upstream = NJT_CONF_UNSET;
    conf->proxy_protocol = NJT_CONF_UNSET;
    conf->local = NJT_CONF_UNSET_PTR;
    conf->socket_keepalive = NJT_CONF_UNSET;
    conf->half_close = NJT_CONF_UNSET;

#if (NJT_STREAM_SSL)
    conf->ssl_enable = NJT_CONF_UNSET;
    conf->ssl_session_reuse = NJT_CONF_UNSET;
    conf->ssl_name = NJT_CONF_UNSET_PTR;
    conf->ssl_server_name = NJT_CONF_UNSET;
    conf->ssl_verify = NJT_CONF_UNSET;
    conf->ssl_verify_depth = NJT_CONF_UNSET_UINT;
#if (NJT_STREAM_MULTICERT)
    conf->ssl_certificates = NJT_CONF_UNSET_PTR;
    conf->ssl_certificate_keys = NJT_CONF_UNSET_PTR;
#else
    conf->ssl_certificate = NJT_CONF_UNSET_PTR;
    conf->ssl_certificate_key = NJT_CONF_UNSET_PTR;
#endif
    conf->ssl_passwords = NJT_CONF_UNSET_PTR;
    conf->ssl_conf_commands = NJT_CONF_UNSET_PTR;
#if (NJT_HAVE_NTLS)
    conf->ssl_ntls = NJT_CONF_UNSET;
#endif

#endif

    return conf;
}


static char *
njt_stream_proxy_merge_srv_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_stream_proxy_srv_conf_t *prev = parent;
    njt_stream_proxy_srv_conf_t *conf = child;

    njt_conf_merge_msec_value(conf->connect_timeout,
                              prev->connect_timeout, 60000);

    njt_conf_merge_msec_value(conf->timeout,
                              prev->timeout, 10 * 60000);

    njt_conf_merge_msec_value(conf->next_upstream_timeout,
                              prev->next_upstream_timeout, 0);

    njt_conf_merge_size_value(conf->buffer_size,
                              prev->buffer_size, 16384);

    njt_conf_merge_ptr_value(conf->upload_rate, prev->upload_rate, NULL);

    njt_conf_merge_ptr_value(conf->download_rate, prev->download_rate, NULL);

    njt_conf_merge_uint_value(conf->requests,
                              prev->requests, 0);

    njt_conf_merge_uint_value(conf->responses,
                              prev->responses, NJT_MAX_INT32_VALUE);

    njt_conf_merge_uint_value(conf->next_upstream_tries,
                              prev->next_upstream_tries, 0);

    njt_conf_merge_value(conf->next_upstream, prev->next_upstream, 1);

    njt_conf_merge_value(conf->proxy_protocol, prev->proxy_protocol, 0);

    njt_conf_merge_ptr_value(conf->local, prev->local, NULL);

    njt_conf_merge_value(conf->socket_keepalive,
                              prev->socket_keepalive, 0);

    njt_conf_merge_value(conf->half_close, prev->half_close, 0);

#if (NJT_STREAM_SSL)

    if (njt_stream_proxy_merge_ssl(cf, conf, prev) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    njt_conf_merge_value(conf->ssl_enable, prev->ssl_enable, 0);

    njt_conf_merge_value(conf->ssl_session_reuse,
                              prev->ssl_session_reuse, 1);

    njt_conf_merge_bitmask_value(conf->ssl_protocols, prev->ssl_protocols,
                              (NJT_CONF_BITMASK_SET
                               |NJT_SSL_TLSv1|NJT_SSL_TLSv1_1
                               |NJT_SSL_TLSv1_2|NJT_SSL_TLSv1_3));

    njt_conf_merge_str_value(conf->ssl_ciphers, prev->ssl_ciphers, "DEFAULT");

    njt_conf_merge_ptr_value(conf->ssl_name, prev->ssl_name, NULL);

    njt_conf_merge_value(conf->ssl_server_name, prev->ssl_server_name, 0);

    njt_conf_merge_value(conf->ssl_verify, prev->ssl_verify, 0);

    njt_conf_merge_uint_value(conf->ssl_verify_depth,
                              prev->ssl_verify_depth, 1);

    njt_conf_merge_str_value(conf->ssl_trusted_certificate,
                              prev->ssl_trusted_certificate, "");

    njt_conf_merge_str_value(conf->ssl_crl, prev->ssl_crl, "");

#if (NJT_STREAM_MULTICERT)
    njt_conf_merge_ptr_value(conf->ssl_certificates,
                              prev->ssl_certificates, NULL);
    njt_conf_merge_ptr_value(conf->ssl_certificate_keys,
                              prev->ssl_certificate_keys, NULL);
#else
    njt_conf_merge_ptr_value(conf->ssl_certificate,
                              prev->ssl_certificate, NULL);

    njt_conf_merge_ptr_value(conf->ssl_certificate_key,
                              prev->ssl_certificate_key, NULL);
#endif

    njt_conf_merge_ptr_value(conf->ssl_passwords, prev->ssl_passwords, NULL);

    njt_conf_merge_ptr_value(conf->ssl_conf_commands,
                              prev->ssl_conf_commands, NULL);

#if (NJT_HAVE_NTLS)
    njt_conf_merge_value(conf->ssl_ntls, prev->ssl_ntls, 0);
#endif

#if (NJT_HAVE_SET_ALPN)
    njt_conf_merge_str_value(conf->proxy_ssl_alpn, prev->proxy_ssl_alpn, "");
#endif
    if (conf->ssl_enable && njt_stream_proxy_set_ssl(cf, conf) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

#endif

    return NJT_CONF_OK;
}


#if (NJT_STREAM_SSL)

static njt_int_t
njt_stream_proxy_merge_ssl(njt_conf_t *cf, njt_stream_proxy_srv_conf_t *conf,
    njt_stream_proxy_srv_conf_t *prev)
{
    njt_uint_t  preserve;

    if (conf->ssl_protocols == 0
        && conf->ssl_ciphers.data == NULL
#if (NJT_STREAM_MULTICERT)
        && conf->ssl_certificates == NJT_CONF_UNSET_PTR
        && conf->ssl_certificate_keys == NJT_CONF_UNSET_PTR
#else
        && conf->ssl_certificate == NJT_CONF_UNSET_PTR
        && conf->ssl_certificate_key == NJT_CONF_UNSET_PTR
#endif
        && conf->ssl_passwords == NJT_CONF_UNSET_PTR
        && conf->ssl_verify == NJT_CONF_UNSET
        && conf->ssl_verify_depth == NJT_CONF_UNSET_UINT
        && conf->ssl_trusted_certificate.data == NULL
        && conf->ssl_crl.data == NULL
        && conf->ssl_session_reuse == NJT_CONF_UNSET
#if (NJT_HAVE_NTLS)
        && conf->ssl_ntls == NJT_CONF_UNSET
#endif
#if (NJT_HAVE_SET_ALPN)
    && conf->proxy_ssl_alpn.data == NULL
#endif
        && conf->ssl_conf_commands == NJT_CONF_UNSET_PTR)
    {
        if (prev->ssl) {
            conf->ssl = prev->ssl;
            return NJT_OK;
        }

        preserve = 1;

    } else {
        preserve = 0;
    }

    conf->ssl = njt_pcalloc(cf->pool, sizeof(njt_ssl_t));
    if (conf->ssl == NULL) {
        return NJT_ERROR;
    }

    conf->ssl->log = cf->log;

    /*
     * special handling to preserve conf->ssl
     * in the "stream" section to inherit it to all servers
     */

    if (preserve) {
        prev->ssl = conf->ssl;
    }

    return NJT_OK;
}


static njt_int_t
njt_stream_proxy_set_ssl(njt_conf_t *cf, njt_stream_proxy_srv_conf_t *pscf)
{
    njt_pool_cleanup_t  *cln;

    if (pscf->ssl->ctx) {
        return NJT_OK;
    }

    if (njt_ssl_create(pscf->ssl, pscf->ssl_protocols, NULL) != NJT_OK) {
        return NJT_ERROR;
    }

    cln = njt_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        njt_ssl_cleanup_ctx(pscf->ssl);
        return NJT_ERROR;
    }

    cln->handler = njt_ssl_cleanup_ctx;
    cln->data = pscf->ssl;

    if (njt_ssl_ciphers(cf, pscf->ssl, &pscf->ssl_ciphers, 0) != NJT_OK) {
        return NJT_ERROR;
    }

#if (NJT_STREAM_MULTICERT)

    if (pscf->ssl_certificates) {
        njt_stream_ssl_conf_t  scf;

        if (pscf->ssl_certificate_keys == NULL) {
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "no \"proxy_ssl_certificate_key\" is defined");
            return NJT_ERROR;
        }

        if (pscf->ssl_certificate_keys->nelts < pscf->ssl_certificates->nelts) {
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "number of \"proxy_ssl_certificate_key\" does not "
                          "correspond \"proxy_ssl_ssl_certificate\"");
            return NJT_ERROR;
        }

        njt_memzero(&scf, sizeof(njt_stream_ssl_conf_t));

        scf.certificates = pscf->ssl_certificates;
        scf.certificate_keys = pscf->ssl_certificate_keys;
        scf.passwords = pscf->ssl_passwords;

        if (njt_stream_ssl_compile_certificates(cf, &scf) != NJT_OK) {
            return NJT_ERROR;
        }
        pscf->ssl_passwords = scf.passwords;
        pscf->ssl_certificate_values = scf.certificate_values;
        pscf->ssl_certificate_key_values = scf.certificate_key_values;

        if (pscf->ssl_certificate_values == NULL) {

            if (njt_ssl_certificates(cf, pscf->ssl, pscf->ssl_certificates,
                                     pscf->ssl_certificate_keys,
                                     pscf->ssl_passwords)
                != NJT_OK)
            {
                return NJT_ERROR;
            }
        }
    }
#else

    if (pscf->ssl_certificate
        && pscf->ssl_certificate->value.len)
    {
        if (pscf->ssl_certificate_key == NULL) {
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "no \"proxy_ssl_certificate_key\" is defined "
                          "for certificate \"%V\"",
                          &pscf->ssl_certificate->value);
            return NJT_ERROR;
        }

        if (pscf->ssl_certificate->lengths
            || pscf->ssl_certificate_key->lengths)
        {
            pscf->ssl_passwords =
                           njt_ssl_preserve_passwords(cf, pscf->ssl_passwords);
            if (pscf->ssl_passwords == NULL) {
                return NJT_ERROR;
            }

        } else {
            if (njt_ssl_certificate(cf, pscf->ssl,
                                    &pscf->ssl_certificate->value,
                                    &pscf->ssl_certificate_key->value,
                                    pscf->ssl_passwords)
                != NJT_OK)
            {
                return NJT_ERROR;
            }
        }
    }
#endif

    if (pscf->ssl_verify) {
        if (pscf->ssl_trusted_certificate.len == 0) {
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                      "no proxy_ssl_trusted_certificate for proxy_ssl_verify");
            return NJT_ERROR;
        }

        if (njt_ssl_trusted_certificate(cf, pscf->ssl,
                                        &pscf->ssl_trusted_certificate,
                                        pscf->ssl_verify_depth)
            != NJT_OK)
        {
            return NJT_ERROR;
        }

        if (njt_ssl_crl(cf, pscf->ssl, &pscf->ssl_crl) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    if (njt_ssl_client_session_cache(cf, pscf->ssl, pscf->ssl_session_reuse)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    if (njt_ssl_conf_commands(cf, pscf->ssl, pscf->ssl_conf_commands)
        != NJT_OK)
    {
        return NJT_ERROR;
    }
#if (NJT_HAVE_SET_ALPN)
    if(pscf->proxy_ssl_alpn.len > 0) {
        if (SSL_CTX_set_alpn_protos(pscf->ssl->ctx,
                                    pscf->proxy_ssl_alpn.data, pscf->proxy_ssl_alpn.len)
            != 0)
        {
            njt_ssl_error(NJT_LOG_EMERG, cf->log, 0,
                        "SSL_CTX_set_alpn_protos() failed");
            return NJT_ERROR;
        }
    }
#endif

    return NJT_OK;
}

#endif


static char *
njt_stream_proxy_pass(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_proxy_srv_conf_t *pscf = conf;

    njt_url_t                            u;
    njt_str_t                           *value, *url;
    njt_stream_complex_value_t           cv;
    njt_stream_core_srv_conf_t          *cscf;
    njt_stream_compile_complex_value_t   ccv;

    if (pscf->upstream || pscf->upstream_value) {
        return "is duplicate";
    }

    cscf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_core_module);

    cscf->handler = njt_stream_proxy_handler;

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
        pscf->upstream_value = njt_palloc(cf->pool,
                                          sizeof(njt_stream_complex_value_t));
        if (pscf->upstream_value == NULL) {
            return NJT_CONF_ERROR;
        }

        *pscf->upstream_value = cv;

        return NJT_CONF_OK;
    }

    njt_memzero(&u, sizeof(njt_url_t));

    u.url = *url;
    u.no_resolve = 1;

    pscf->upstream = njt_stream_upstream_add(cf, &u, 0);
    if (pscf->upstream == NULL) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static char *
njt_stream_proxy_bind(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_proxy_srv_conf_t *pscf = conf;

    njt_int_t                            rc;
    njt_str_t                           *value;
    njt_stream_complex_value_t           cv;
    njt_stream_upstream_local_t         *local;
    njt_stream_compile_complex_value_t   ccv;

    if (pscf->local != NJT_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2 && njt_strcmp(value[1].data, "off") == 0) {
        pscf->local = NULL;
        return NJT_CONF_OK;
    }

    njt_memzero(&ccv, sizeof(njt_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (njt_stream_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    local = njt_pcalloc(cf->pool, sizeof(njt_stream_upstream_local_t));
    if (local == NULL) {
        return NJT_CONF_ERROR;
    }

    pscf->local = local;

    if (cv.lengths) {
        local->value = njt_palloc(cf->pool, sizeof(njt_stream_complex_value_t));
        if (local->value == NULL) {
            return NJT_CONF_ERROR;
        }

        *local->value = cv;

    } else {
        local->addr = njt_palloc(cf->pool, sizeof(njt_addr_t));
        if (local->addr == NULL) {
            return NJT_CONF_ERROR;
        }

        rc = njt_parse_addr_port(cf->pool, local->addr, value[1].data,
                                 value[1].len);

        switch (rc) {
        case NJT_OK:
            local->addr->name = value[1];
            break;

        case NJT_DECLINED:
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid address \"%V\"", &value[1]);
            /* fall through */

        default:
            return NJT_CONF_ERROR;
        }
    }

    if (cf->args->nelts > 2) {
        if (njt_strcmp(value[2].data, "transparent") == 0) {
#if (NJT_HAVE_TRANSPARENT_PROXY)
            njt_core_conf_t  *ccf;

            ccf = (njt_core_conf_t *) njt_get_conf(cf->cycle->conf_ctx,
                                                   njt_core_module);

            ccf->transparent = 1;
            local->transparent = 1;
#else
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "transparent proxying is not supported "
                               "on this platform, ignored");
#endif
        } else {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return NJT_CONF_ERROR;
        }
    }

    return NJT_CONF_OK;
}


u_char *
njt_proxy_protocol_v2_write(njt_stream_session_t *s, u_char *buf, u_char *last)
{
    njt_uint_t  cnf_version = 1;
    njt_connection_t  *c = s->connection;

#if (NJT_STREAM_PROTOCOL_V2)
#if (NJT_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif
    njt_uint_t                    i;
    struct pp2_tlv                ptlv;
    u_char                        *p;
    uint16_t                       len;
    in_port_t  port, lport;
    njt_proxy_protocol_header_t        *header;
    static const u_char signature[] = "\r\n\r\n\0\r\nQUIT\n";
    void * pscf  = NULL;
    njt_uint_t  roxy_addr_len = 0;
    struct sockaddr_in   *sin;
    njt_stream_proxy_protocol_tlv_cmd_t *cmds;
     pscf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_protocol_tlv_module);
     if(pscf != NULL && ((njt_stream_proxy_protocol_tlv_srv_conf_t *)pscf)->enable == 1) {
       cnf_version = 2;
     }

#endif
    if(cnf_version == 1) {  //v1
       return  njt_proxy_protocol_write(c,buf,last);
    } else {
#if (NJT_STREAM_PROTOCOL_V2)
        if (njt_connection_local_sockaddr(c, NULL, 0) != NJT_OK) {
            return NULL;
        }
       header = (njt_proxy_protocol_header_t *)buf;
       p = (buf + sizeof(njt_proxy_protocol_header_t));

       njt_memcpy(header->signature,signature,sizeof(header->signature));
       header->version_command = 0x21;
        switch (c->sockaddr->sa_family) {
            case AF_INET:
                header->family_transport = (0x1 << 4);
		sin = (struct sockaddr_in *) c->sockaddr;
                njt_memcpy(p,&sin->sin_addr,4);
                p += 4;
		sin = (struct sockaddr_in *) c->local_sockaddr;
                njt_memcpy(p,&sin->sin_addr,4);
                p += 4;
                port = njt_inet_get_port(c->sockaddr);
                lport = njt_inet_get_port(c->local_sockaddr);
                port = htons(port);
                lport = htons(lport);
                njt_memcpy(p,&port,sizeof(port));
                p += sizeof(port);
                njt_memcpy(p,&lport,sizeof(lport));
                 p += sizeof(lport);
                roxy_addr_len = 12;
                break;

        #if (NJT_HAVE_INET6)
            case AF_INET6:
                header->family_transport = (0x2 << 4);
		sin6 = (struct sockaddr_in6 *) c->sockaddr;
                njt_memcpy(p,&sin6->sin6_addr,16);
                p += 16;
		sin6 = (struct sockaddr_in6 *) c->local_sockaddr;
                njt_memcpy(p,&sin6->sin6_addr,16);
                 p += 16;
                port = njt_inet_get_port(c->sockaddr);
                lport = njt_inet_get_port(c->local_sockaddr);
                port = htons(port);
                lport = htons(lport);
                njt_memcpy(p,&port,sizeof(port));
                 p += sizeof(port);
                njt_memcpy(p,&lport,sizeof(lport));
                 p += sizeof(lport);
                roxy_addr_len = 36;
                break;
        #endif
            default:
                header->family_transport = (0xF << 4);
       }
       header->family_transport = (header->family_transport|0x01);

        p = (buf + sizeof(njt_proxy_protocol_header_t) + roxy_addr_len);
        cmds = ((njt_stream_proxy_protocol_tlv_srv_conf_t *)pscf)->commands.elts;
        for (i = 0; i < ((njt_stream_proxy_protocol_tlv_srv_conf_t *)pscf)->commands.nelts; i++) {

            if(p + sizeof(ptlv.type) + sizeof(ptlv.length) + s->variables[cmds[i].index].len > last) {
                njt_log_error(NJT_LOG_ERR, c->log, 0,
                              "too long value of  proxy_pp2_set_tlv");
                 return NULL;
            }
            if (cmds[i].name.len >= 2 && cmds[i].name.data[0] == '0' && cmds[i].name.data[1] == 'x') {
                ptlv.type = njt_hextoi(cmds[i].name.data + 2, cmds[i].name.len - 2);
                njt_memcpy(p,&ptlv.type,sizeof(ptlv.type));
                p += sizeof(ptlv.type);

                ptlv.length = s->variables[cmds[i].index].len;
                ptlv.length = htons(ptlv.length);
                njt_memcpy(p,&ptlv.length,sizeof(ptlv.length));
                p += sizeof(ptlv.length);

                njt_memcpy(p,s->variables[cmds[i].index].data,s->variables[cmds[i].index].len);
                p = p + s->variables[cmds[i].index].len;
            } 
           

        }
	len = htons(p - buf - sizeof(njt_proxy_protocol_header_t));
	njt_memcpy(&header->len,&len,sizeof(uint16_t));
        //*(uint16_t*)(&header->len) = htons(p - buf - sizeof(njt_proxy_protocol_header_t));
        return p;
#endif
        return NULL;
    }
}




#if (NJT_HAVE_SET_ALPN)
static char *
njt_stream_proxy_ssl_alpn(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation

    njt_stream_proxy_srv_conf_t  *scf = conf;

    u_char      *p;
    size_t       len;
    njt_str_t   *value;
    njt_uint_t   i;

    if (scf->proxy_ssl_alpn.len) {
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

    scf->proxy_ssl_alpn.data = njt_pnalloc(cf->pool, len);
    if (scf->proxy_ssl_alpn.data == NULL) {
        return NJT_CONF_ERROR;
    }

    p = scf->proxy_ssl_alpn.data;

    for (i = 1; i < cf->args->nelts; i++) {
        *p++ = value[i].len;
        p = njt_cpymem(p, value[i].data, value[i].len);
    }

    scf->proxy_ssl_alpn.len = len;

    return NJT_CONF_OK;

#else
    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "the \"proxy_ssl_alpn\" directive requires OpenSSL "
                       "with ALPN support");
    return NJT_CONF_ERROR;
#endif
}
#endif

// openresty patch
njt_uint_t
njt_stream_proxy_get_next_upstream_tries(njt_stream_session_t *s)
{
    njt_stream_proxy_srv_conf_t      *pscf;

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_proxy_module);

    return pscf->next_upstream_tries;
}

// openresty patch end