
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>
#include <njt_http_kv_module.h>
#include <njt_stream_mqtt_proxy_module.h>


#define MIN_MQTT_CONNECT_PKT_LEN 14
#define MIN_MQTT_SUBSCRIBE_PACKET_ID 1


struct pp2_tlv {
            uint8_t type;
            uint16_t length;
            uint8_t value[0];
        };
// static void njt_stream_mqtt_proxy_handler(njt_stream_session_t *s);
static njt_int_t njt_stream_mqtt_proxy_eval(njt_stream_session_t *s,
    njt_stream_mqtt_proxy_srv_conf_t *pscf);
static njt_int_t njt_stream_mqtt_proxy_set_local(njt_stream_session_t *s,
    njt_stream_upstream_t *u, njt_stream_upstream_local_t *local);
static njt_int_t njt_stream_mqtt_proxy_connect(njt_stream_session_t *s);
static void njt_stream_mqtt_proxy_init_upstream(njt_stream_session_t *s);
static void njt_stream_mqtt_proxy_resolve_handler(njt_resolver_ctx_t *ctx);
static void njt_stream_mqtt_proxy_upstream_handler(njt_event_t *ev);
static void njt_stream_mqtt_proxy_downstream_handler(njt_event_t *ev);
static void njt_stream_mqtt_proxy_process_connection(njt_event_t *ev,
    njt_uint_t from_upstream);
static void njt_stream_mqtt_proxy_connect_handler(njt_event_t *ev);
static njt_int_t njt_stream_mqtt_proxy_test_connect(njt_connection_t *c);
static void njt_stream_mqtt_proxy_process(njt_stream_session_t *s,
    njt_uint_t from_upstream, njt_uint_t do_write);
static njt_int_t njt_stream_mqtt_proxy_test_finalize(njt_stream_session_t *s,
    njt_stream_mqtt_proxy_ctx_t *ctx, njt_uint_t from_upstream);
static void njt_stream_mqtt_proxy_next_upstream(njt_stream_session_t *s);
static void njt_stream_mqtt_proxy_finalize(njt_stream_session_t *s, njt_uint_t rc);
static u_char *njt_stream_mqtt_proxy_log_error(njt_log_t *log, u_char *buf,
    size_t len);

static void *njt_stream_mqtt_proxy_create_srv_conf(njt_conf_t *cf);
static char *njt_stream_mqtt_proxy_merge_srv_conf(njt_conf_t *cf, void *parent,
    void *child);
static char *njt_stream_mqtt_proxy_pass(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_stream_mqtt_proxy_bind(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
void
njt_stream_mqtt_proxy_chain_clean_chains(njt_pool_t *p, njt_chain_t **free, njt_chain_t **busy,
    njt_chain_t **out, njt_buf_tag_t tag);
static njt_int_t
njt_stream_mqtt_proxy_set_variable(njt_stream_session_t *s,
    njt_variable_value_t *v, uintptr_t data);
static njt_int_t
njt_stream_mqtt_proxy_add_variables(njt_conf_t *cf);
static void
njt_stream_mqtt_client_pkt_info(njt_stream_mqtt_proxy_pkt_info_t *pkt_info);

njt_uint_t
njt_stream_mqtt_send_pingresp_to_client(njt_stream_session_t *s, njt_connection_t *dst,
    njt_stream_mqtt_proxy_ctx_t *ctx);

#if (NJT_STREAM_SSL)

static njt_int_t njt_stream_mqtt_proxy_send_proxy_protocol(njt_stream_session_t *s);
static char *njt_stream_mqtt_proxy_ssl_password_file(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);
static char *njt_stream_mqtt_proxy_ssl_conf_command_check(njt_conf_t *cf, void *post,
    void *data);
static void njt_stream_mqtt_proxy_ssl_init_connection(njt_stream_session_t *s);
static void njt_stream_mqtt_proxy_ssl_handshake(njt_connection_t *pc);
static void njt_stream_mqtt_proxy_ssl_save_session(njt_connection_t *c);
static njt_int_t njt_stream_mqtt_proxy_ssl_name(njt_stream_session_t *s);
#if (NJT_STREAM_MULTICERT)
static njt_int_t njt_stream_mqtt_proxy_ssl_certificates(njt_stream_session_t *s);
#else
static njt_int_t njt_stream_mqtt_proxy_ssl_certificate(njt_stream_session_t *s);
#endif
static njt_int_t njt_stream_mqtt_proxy_merge_ssl(njt_conf_t *cf,
    njt_stream_mqtt_proxy_srv_conf_t *conf, njt_stream_mqtt_proxy_srv_conf_t *prev);
static njt_int_t njt_stream_mqtt_proxy_set_ssl(njt_conf_t *cf,
    njt_stream_mqtt_proxy_srv_conf_t *pscf);
u_char *
njt_proxy_protocol_v2_write(njt_stream_session_t *s, u_char *buf, u_char *last);


#if (NJT_HAVE_SET_ALPN)
static char *
njt_stream_mqtt_proxy_ssl_alpn(njt_conf_t *cf, njt_command_t *cmd, void *conf);
#endif

static njt_conf_bitmask_t  njt_stream_mqtt_proxy_ssl_protocols[] = {
    { njt_string("SSLv2"), NJT_SSL_SSLv2 },
    { njt_string("SSLv3"), NJT_SSL_SSLv3 },
    { njt_string("TLSv1"), NJT_SSL_TLSv1 },
    { njt_string("TLSv1.1"), NJT_SSL_TLSv1_1 },
    { njt_string("TLSv1.2"), NJT_SSL_TLSv1_2 },
    { njt_string("TLSv1.3"), NJT_SSL_TLSv1_3 },
    { njt_null_string, 0 }
};



static njt_conf_post_t  njt_stream_mqtt_proxy_ssl_conf_command_post =
    { njt_stream_mqtt_proxy_ssl_conf_command_check };

#endif


// static njt_conf_deprecated_t  njt_conf_deprecated_proxy_downstream_buffer = {
//     njt_conf_deprecated, "proxy_downstream_buffer", "proxy_buffer_size"
// };

// static njt_conf_deprecated_t  njt_conf_deprecated_proxy_upstream_buffer = {
//     njt_conf_deprecated, "proxy_upstream_buffer", "proxy_buffer_size"
// };


static njt_command_t  njt_stream_mqtt_proxy_commands[] = {

    { njt_string("mqtt_pass"),
      NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_stream_mqtt_proxy_pass,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("mqtt_proxy_bind"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE12,
      njt_stream_mqtt_proxy_bind,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("mqtt_proxy_socket_keepalive"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_mqtt_proxy_srv_conf_t, socket_keepalive),
      NULL },

    { njt_string("mqtt_proxy_connect_timeout"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_mqtt_proxy_srv_conf_t, connect_timeout),
      NULL },

    { njt_string("mqtt_proxy_timeout"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_mqtt_proxy_srv_conf_t, timeout),
      NULL },

    { njt_string("mqtt_proxy_buffer_size"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_mqtt_proxy_srv_conf_t, buffer_size),
      NULL },

    // { njt_string("mqtt_proxy_downstream_buffer"),
    //   NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
    //   njt_conf_set_size_slot,
    //   NJT_STREAM_SRV_CONF_OFFSET,
    //   offsetof(njt_stream_mqtt_proxy_srv_conf_t, buffer_size),
    //   &njt_conf_deprecated_proxy_downstream_buffer },

    // { njt_string("mqtt_proxy_upstream_buffer"),
    //   NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
    //   njt_conf_set_size_slot,
    //   NJT_STREAM_SRV_CONF_OFFSET,
    //   offsetof(njt_stream_mqtt_proxy_srv_conf_t, buffer_size),
    //   &njt_conf_deprecated_proxy_upstream_buffer },

    { njt_string("mqtt_proxy_upload_rate"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_stream_set_complex_value_size_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_mqtt_proxy_srv_conf_t, upload_rate),
      NULL },

    { njt_string("mqtt_proxy_download_rate"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_stream_set_complex_value_size_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_mqtt_proxy_srv_conf_t, download_rate),
      NULL },

    { njt_string("mqtt_proxy_requests"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_mqtt_proxy_srv_conf_t, requests),
      NULL },

    { njt_string("mqtt_proxy_responses"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_mqtt_proxy_srv_conf_t, responses),
      NULL },

    { njt_string("mqtt_proxy_next_upstream"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_mqtt_proxy_srv_conf_t, next_upstream),
      NULL },

    { njt_string("mqtt_proxy_next_upstream_tries"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_mqtt_proxy_srv_conf_t, next_upstream_tries),
      NULL },

    { njt_string("mqtt_proxy_next_upstream_timeout"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_mqtt_proxy_srv_conf_t, next_upstream_timeout),
      NULL },

    { njt_string("mqtt_proxy_protocol"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_mqtt_proxy_srv_conf_t, proxy_protocol),
      NULL },

    { njt_string("mqtt_proxy_half_close"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_mqtt_proxy_srv_conf_t, half_close),
      NULL },

#if (NJT_STREAM_SSL)

    { njt_string("mqtt_proxy_ssl"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_mqtt_proxy_srv_conf_t, ssl_enable),
      NULL },

    { njt_string("mqtt_proxy_ssl_session_reuse"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_mqtt_proxy_srv_conf_t, ssl_session_reuse),
      NULL },

    { njt_string("mqtt_proxy_ssl_protocols"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_mqtt_proxy_srv_conf_t, ssl_protocols),
      &njt_stream_mqtt_proxy_ssl_protocols },

    { njt_string("mqtt_proxy_ssl_ciphers"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_mqtt_proxy_srv_conf_t, ssl_ciphers),
      NULL },

    { njt_string("mqtt_proxy_ssl_name"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_stream_set_complex_value_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_mqtt_proxy_srv_conf_t, ssl_name),
      NULL },

    { njt_string("mqtt_proxy_ssl_server_name"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_mqtt_proxy_srv_conf_t, ssl_server_name),
      NULL },

    { njt_string("mqtt_proxy_ssl_verify"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_mqtt_proxy_srv_conf_t, ssl_verify),
      NULL },

    { njt_string("mqtt_proxy_ssl_verify_depth"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_mqtt_proxy_srv_conf_t, ssl_verify_depth),
      NULL },

    { njt_string("mqtt_proxy_ssl_trusted_certificate"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_mqtt_proxy_srv_conf_t, ssl_trusted_certificate),
      NULL },

    { njt_string("mqtt_proxy_ssl_crl"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_mqtt_proxy_srv_conf_t, ssl_crl),
      NULL },

#if (NJT_STREAM_MULTICERT)

    { njt_string("mqtt_proxy_ssl_certificate"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE12,
      njt_ssl_certificate_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_mqtt_proxy_srv_conf_t, ssl_certificates),
      NULL },

    { njt_string("mqtt_proxy_ssl_certificate_key"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE12,
      njt_ssl_certificate_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_mqtt_proxy_srv_conf_t, ssl_certificate_keys),
      NULL },

#else

    { njt_string("mqtt_proxy_ssl_certificate"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_stream_set_complex_value_zero_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_mqtt_proxy_srv_conf_t, ssl_certificate),
      NULL },

    { njt_string("mqtt_proxy_ssl_certificate_key"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_stream_set_complex_value_zero_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_mqtt_proxy_srv_conf_t, ssl_certificate_key),
      NULL },

#endif

    { njt_string("mqtt_proxy_ssl_password_file"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_stream_mqtt_proxy_ssl_password_file,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("mqtt_proxy_ssl_conf_command"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE2,
      njt_conf_set_keyval_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_mqtt_proxy_srv_conf_t, ssl_conf_commands),
      &njt_stream_mqtt_proxy_ssl_conf_command_post },

#if (NJT_HAVE_NTLS)
    { njt_string("mqtt_proxy_ssl_ntls"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_mqtt_proxy_srv_conf_t, ssl_ntls),
      NULL },
#endif
#if (NJT_HAVE_SET_ALPN)
     { njt_string("mqtt_proxy_ssl_alpn"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_1MORE,
      njt_stream_mqtt_proxy_ssl_alpn,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },
#endif
#endif

      njt_null_command
};


static njt_stream_variable_t  njt_stream_mqtt_proxy_vars[] = {

    { njt_string("mqtt_proxy_clientid"), NULL,
      njt_stream_mqtt_proxy_set_variable,
      offsetof(njt_stream_mqtt_proxy_ctx_t, client_id), 0, 0 },

    { njt_string("mqtt_proxy_username"), NULL,
      njt_stream_mqtt_proxy_set_variable,
      offsetof(njt_stream_mqtt_proxy_ctx_t, username), 0, 0 },

      njt_stream_null_variable
};


static njt_stream_module_t  njt_stream_mqtt_proxy_module_ctx = {
    njt_stream_mqtt_proxy_add_variables,   /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    njt_stream_mqtt_proxy_create_srv_conf,      /* create server configuration */
    njt_stream_mqtt_proxy_merge_srv_conf        /* merge server configuration */
};


njt_module_t  njt_stream_mqtt_proxy_module = {
    NJT_MODULE_V1,
    &njt_stream_mqtt_proxy_module_ctx,          /* module context */
    njt_stream_mqtt_proxy_commands,             /* module directives */
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




static njt_int_t
njt_stream_mqtt_proxy_set_variable(njt_stream_session_t *s,
    njt_variable_value_t *v, uintptr_t data)
{
    njt_str_t                      *variable;
    njt_stream_mqtt_proxy_ctx_t  *ctx;

    ctx = njt_stream_get_module_ctx(s, njt_stream_mqtt_proxy_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NJT_OK;
    }

    variable = (njt_str_t *) ((char *) ctx + data);

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = variable->len;
    v->data = variable->data;


    return NJT_OK;
}


static njt_int_t
njt_stream_mqtt_proxy_add_variables(njt_conf_t *cf)
{
    njt_stream_variable_t  *var, *v;

    for (v = njt_stream_mqtt_proxy_vars; v->name.len; v++) {
        var = njt_stream_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NJT_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NJT_OK;
}

void
njt_stream_mqtt_proxy_handler(njt_stream_session_t *s)
{
    u_char                           *p;
    njt_str_t                        *host;
    njt_uint_t                        i;
    njt_connection_t                 *c;
    njt_resolver_ctx_t               *ctx, temp;
    njt_stream_upstream_t            *u;
    njt_stream_core_srv_conf_t       *cscf;
    njt_stream_mqtt_proxy_srv_conf_t      *pscf;
    njt_stream_upstream_srv_conf_t   *uscf, **uscfp;
    njt_stream_upstream_main_conf_t  *umcf;
    njt_stream_mqtt_proxy_ctx_t           *pctx; // openresty patch

    c = s->connection;
    if(c->type != SOCK_STREAM){
        njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_mqtt_proxy_module);

    // openresty patch
    pctx = njt_pcalloc(c->pool, sizeof(njt_stream_mqtt_proxy_ctx_t));
    if (pctx == NULL) {
        njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    pctx->connect_timeout = pscf->connect_timeout;
    pctx->timeout = pscf->timeout;
    pctx->client_first_pkt = 1;
    pctx->next_upstream_tries = pscf->next_upstream_tries;
    pctx->pingresp = 0;
    pctx->pingresp = pctx->pingresp | 0xD000;

    pctx->pool = c->pool;

    // njt_sub_pool(njt_cycle->pool, pctx->pool);
    njt_array_init(&pctx->sub_topics, pctx->pool, 2, sizeof(njt_stream_mqtt_proxy_sub_topics_item_t));

    njt_stream_set_ctx(s, pctx, njt_stream_mqtt_proxy_module);
    // openresty patch end

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   " mqtt proxy connection handler");

    u = njt_pcalloc(c->pool, sizeof(njt_stream_upstream_t));
    if (u == NULL) {
        njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    s->upstream = u;

    s->log_handler = njt_stream_mqtt_proxy_log_error;

    u->requests = 1;

    u->peer.log = c->log;
    u->peer.log_error = NJT_ERROR_ERR;

    if (njt_stream_mqtt_proxy_set_local(s, u, pscf->local) != NJT_OK) {
        njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (pscf->socket_keepalive) {
        u->peer.so_keepalive = 1;
    }

    u->peer.type = c->type;
    u->start_sec = njt_time();

    c->write->handler = njt_stream_mqtt_proxy_downstream_handler;
    c->read->handler = njt_stream_mqtt_proxy_downstream_handler;

    s->upstream_states = njt_array_create(c->pool, 1,
                                          sizeof(njt_stream_upstream_state_t));
    if (s->upstream_states == NULL) {
        njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    p = njt_pnalloc(c->pool, pscf->buffer_size);
    if (p == NULL) {
        njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    //in mqtt, not use this buffer
    // u->downstream_buf.start = p;
    // u->downstream_buf.end = p + pscf->buffer_size;
    // u->downstream_buf.pos = p;
    // u->downstream_buf.last = p;

    // if (c->read->ready) {
        njt_post_event(c->read, &njt_posted_events);
    // }

    if (pscf->upstream_value) {
        if (njt_stream_mqtt_proxy_eval(s, pscf) != NJT_OK) {
            njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (u->resolved == NULL) {
        uscf = pscf->upstream;
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
                njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }

            if (njt_stream_upstream_create_round_robin_peer(s, u->resolved)
                != NJT_OK)
            {
                njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }

            pctx->not_wait_conn_pkt = 1;
            njt_stream_mqtt_proxy_connect(s);

            return;
        }

        if (u->resolved->port == 0) {
            njt_log_error(NJT_LOG_ERR, c->log, 0,
                          "no port in upstream \"%V\"", host);
            njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        temp.name = *host;

        cscf = njt_stream_get_module_srv_conf(s, njt_stream_core_module);

        ctx = njt_resolve_start(cscf->resolver, &temp);
        if (ctx == NULL) {
            njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        if (ctx == NJT_NO_RESOLVER) {
            njt_log_error(NJT_LOG_ERR, c->log, 0,
                          "no resolver defined to resolve %V", host);
            njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        pctx->not_wait_conn_pkt = 1;
        ctx->name = *host;
        ctx->handler = njt_stream_mqtt_proxy_resolve_handler;
        ctx->data = s;
        ctx->timeout = cscf->resolver_timeout;

        u->resolved->ctx = ctx;

        if (njt_resolve_name(ctx) != NJT_OK) {
            u->resolved->ctx = NULL;
            njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        return;
    }

found:

    if (uscf == NULL) {
        njt_log_error(NJT_LOG_ALERT, c->log, 0, "no upstream configuration");
        njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->upstream = uscf;

#if (NJT_STREAM_SSL)
    u->ssl_name = uscf->host;
#endif

    //init after get connpkt
    // if (uscf->peer.init(s, uscf) != NJT_OK) {
    //     njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
    //     return;
    // }

    u->peer.start_time = njt_current_msec;

    if (pscf->next_upstream_tries
        && u->peer.tries > pscf->next_upstream_tries)
    {
        u->peer.tries = pscf->next_upstream_tries;
    }

    njt_stream_mqtt_proxy_connect(s);
}


static njt_int_t
njt_stream_mqtt_proxy_eval(njt_stream_session_t *s,
    njt_stream_mqtt_proxy_srv_conf_t *pscf)
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
njt_stream_mqtt_proxy_set_local(njt_stream_session_t *s, njt_stream_upstream_t *u,
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


static njt_int_t
njt_stream_mqtt_proxy_connect(njt_stream_session_t *s)
{
    njt_int_t                     rc;
    njt_connection_t             *c, *pc;
    njt_stream_upstream_t        *u;
    njt_stream_mqtt_proxy_srv_conf_t  *pscf;
    njt_stream_mqtt_proxy_ctx_t       *ctx; // openresty patch

    c = s->connection;

    c->log->action = "connecting to upstream";

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_mqtt_proxy_module);

    ctx = njt_stream_get_module_ctx(s, njt_stream_mqtt_proxy_module); // openresty patch

    u = s->upstream;

    u->connected = 0;
    u->proxy_protocol = pscf->proxy_protocol;

    if(!ctx->not_wait_conn_pkt){
        // njt_log_error(NJT_LOG_ERR, c->log, 0, "===================has not get connpkt, wait connect");
        return NJT_OK;
    }

    if (u->state) {
        u->state->response_time = njt_current_msec - u->start_time;
    }

    u->state = njt_array_push(s->upstream_states);
    if (u->state == NULL) {
        njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return NJT_DONE;
    }

    njt_memzero(u->state, sizeof(njt_stream_upstream_state_t));

    u->start_time = njt_current_msec;

    u->state->connect_time = (njt_msec_t) -1;
    u->state->first_byte_time = (njt_msec_t) -1;
    u->state->response_time = (njt_msec_t) -1;

    rc = njt_event_connect_peer(&u->peer);

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0, "proxy connect: %i", rc);

    if (rc == NJT_ERROR) {
        njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return NJT_DONE;
    }

    // openresy patch
    if (rc >= NJT_STREAM_SPECIAL_RESPONSE) {
        njt_stream_mqtt_proxy_finalize(s, rc);
        return NJT_DONE;
    }
    // openresy patch end

    u->state->peer = u->peer.name;

    //this use next upstream too
    if (rc == NJT_BUSY) {
        njt_log_error(NJT_LOG_ERR, c->log, 0, "no live upstreams");
        njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_BAD_GATEWAY);
        // njt_stream_mqtt_proxy_next_upstream(s);
        return NJT_DONE;
    }

    if (rc == NJT_DECLINED) {
        njt_stream_mqtt_proxy_next_upstream(s);
        return NJT_DONE;
    }

    /* rc == NJT_OK || rc == NJT_AGAIN || rc == NJT_DONE */

    pc = u->peer.connection;

    pc->data = s;
    pc->log = c->log;
    pc->pool = c->pool;
    pc->read->log = c->log;
    pc->write->log = c->log;

    if (rc != NJT_AGAIN) {
        njt_stream_mqtt_proxy_init_upstream(s);
        return NJT_OK;
    }

    pc->read->handler = njt_stream_mqtt_proxy_connect_handler;
    pc->write->handler = njt_stream_mqtt_proxy_connect_handler;

    // njt_add_timer(pc->write, pscf->connect_timeout); openresty patch
    njt_add_timer(pc->write, ctx->connect_timeout); // openresty patch

    return NJT_OK;
}


static void
njt_stream_mqtt_proxy_init_upstream(njt_stream_session_t *s)
{
    u_char                       *p;
    njt_chain_t                  *cl;
    njt_connection_t             *c, *pc;
    njt_log_handler_pt            handler;
    njt_stream_upstream_t        *u;
    njt_stream_core_srv_conf_t   *cscf;
    njt_stream_mqtt_proxy_srv_conf_t  *pscf;

    u = s->upstream;
    pc = u->peer.connection;

    cscf = njt_stream_get_module_srv_conf(s, njt_stream_core_module);

    if (pc->type == SOCK_STREAM
        && cscf->tcp_nodelay
        && njt_tcp_nodelay(pc) != NJT_OK)
    {
        njt_stream_mqtt_proxy_next_upstream(s);
        return;
    }

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_mqtt_proxy_module);

#if (NJT_STREAM_SSL)

    if (pc->type == SOCK_STREAM && pscf->ssl_enable) {

        if (u->proxy_protocol) {
            if (njt_stream_mqtt_proxy_send_proxy_protocol(s) != NJT_OK) {
                return;
            }

            u->proxy_protocol = 0;
        }

        if (pc->ssl == NULL) {
            njt_stream_mqtt_proxy_ssl_init_connection(s);
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

    // if (u->upstream_buf.start == NULL) {
    //     p = njt_pnalloc(c->pool, pscf->buffer_size);
    //     if (p == NULL) {
    //         njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
    //         return;
    //     }

    //     u->upstream_buf.start = p;
    //     u->upstream_buf.end = p + pscf->buffer_size;
    //     u->upstream_buf.pos = p;
    //     u->upstream_buf.last = p;
    // }

    if (c->buffer && c->buffer->pos <= c->buffer->last) {
        njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                       "stream proxy add proxy buffer: %uz",
                       c->buffer->last - c->buffer->pos);

        cl = njt_chain_get_free_buf(c->pool, &u->free);
        if (cl == NULL) {
            njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        *cl->buf = *c->buffer;

        cl->buf->tag = (njt_buf_tag_t) &njt_stream_mqtt_proxy_module;
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
            njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        p = njt_pnalloc(c->pool, NJT_PROXY_PROTOCOL_MAX_HEADER);
        if (p == NULL) {
            njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        cl->buf->pos = p;

        p = njt_proxy_protocol_v2_write(s, p, p + NJT_PROXY_PROTOCOL_MAX_HEADER);
        if (p == NULL) {
            njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        cl->buf->last = p;
        cl->buf->temporary = 1;
        cl->buf->flush = 0;
        cl->buf->last_buf = 0;
        cl->buf->tag = (njt_buf_tag_t) &njt_stream_mqtt_proxy_module;

        cl->next = u->upstream_out;
        u->upstream_out = cl;

        u->proxy_protocol = 0;
    }

    u->upload_rate = njt_stream_complex_value_size(s, pscf->upload_rate, 0);
    u->download_rate = njt_stream_complex_value_size(s, pscf->download_rate, 0);

    u->connected = 1;

    pc->read->handler = njt_stream_mqtt_proxy_upstream_handler;
    pc->write->handler = njt_stream_mqtt_proxy_upstream_handler;

    if (pc->read->ready) {
        njt_post_event(pc->read, &njt_posted_events);
    }

    njt_stream_mqtt_proxy_process(s, 0, 1);
}


#if (NJT_STREAM_SSL)

static njt_int_t
njt_stream_mqtt_proxy_send_proxy_protocol(njt_stream_session_t *s)
{
    // openresty patch
    // u_char                       *p;
    // ssize_t                       n, size;
    // njt_connection_t             *c, *pc;
    // njt_stream_upstream_t        *u;
    // njt_stream_mqtt_proxy_srv_conf_t  *pscf;
    // u_char                        buf[NJT_PROXY_PROTOCOL_MAX_HEADER];
    u_char                  *p;
    u_char                   buf[NJT_PROXY_PROTOCOL_MAX_HEADER];
    ssize_t                  n, size;
    njt_connection_t        *c, *pc;
    njt_stream_upstream_t   *u;
    njt_stream_mqtt_proxy_ctx_t  *ctx;

    ctx = njt_stream_get_module_ctx(s, njt_stream_mqtt_proxy_module);
    // openresty patch end


    c = s->connection;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "stream proxy send PROXY protocol header");

    p = njt_proxy_protocol_v2_write(s, buf, buf + NJT_PROXY_PROTOCOL_MAX_HEADER);
    if (p == NULL) {
        njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return NJT_ERROR;
    }

    u = s->upstream;

    pc = u->peer.connection;

    size = p - buf;

    n = pc->send(pc, buf, size);

    if (n == NJT_AGAIN) {
        if (njt_handle_write_event(pc->write, 0) != NJT_OK) {
            njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return NJT_ERROR;
        }

        // openresty patch
        // pscf = njt_stream_get_module_srv_conf(s, njt_stream_mqtt_proxy_module);

        // njt_add_timer(pc->write, pscf->timeout);
        njt_add_timer(pc->write, ctx->timeout);
        // openresty patch end

        pc->write->handler = njt_stream_mqtt_proxy_connect_handler;

        return NJT_AGAIN;
    }

    if (n == NJT_ERROR) {
        njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_OK);
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

        njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);

        return NJT_ERROR;
    }

    return NJT_OK;
}


static char *
njt_stream_mqtt_proxy_ssl_password_file(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    njt_stream_mqtt_proxy_srv_conf_t *pscf = conf;

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
njt_stream_mqtt_proxy_ssl_conf_command_check(njt_conf_t *cf, void *post, void *data)
{
#ifndef SSL_CONF_FLAG_FILE
    return "is not supported on this platform";
#else
    return NJT_CONF_OK;
#endif
}


static void
njt_stream_mqtt_proxy_ssl_init_connection(njt_stream_session_t *s)
{
    njt_int_t                     rc;
    njt_connection_t             *pc;
    njt_stream_upstream_t        *u;
    njt_stream_mqtt_proxy_srv_conf_t  *pscf;
    njt_stream_mqtt_proxy_ctx_t       *ctx; // openresy patch

    ctx = njt_stream_get_module_ctx(s, njt_stream_mqtt_proxy_module); // openresty patch


    u = s->upstream;

    pc = u->peer.connection;

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_mqtt_proxy_module);

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
        njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (pscf->ssl_server_name || pscf->ssl_verify) {
        if (njt_stream_mqtt_proxy_ssl_name(s) != NJT_OK) {
            njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

#if (NJT_STREAM_MULTICERT)

    if (pscf->ssl_certificate_values) {
        if (njt_stream_mqtt_proxy_ssl_certificates(s) != NJT_OK) {
            njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

#else

    if (pscf->ssl_certificate
        && pscf->ssl_certificate->value.len
        && (pscf->ssl_certificate->lengths
            || pscf->ssl_certificate_key->lengths))
    {
        if (njt_stream_mqtt_proxy_ssl_certificate(s) != NJT_OK) {
            njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

#endif

    if (pscf->ssl_session_reuse) {
        pc->ssl->save_session = njt_stream_mqtt_proxy_ssl_save_session;

        if (u->peer.set_session(&u->peer, u->peer.data) != NJT_OK) {
            njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
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

        pc->ssl->handler = njt_stream_mqtt_proxy_ssl_handshake;
        return;
    }

    njt_stream_mqtt_proxy_ssl_handshake(pc);
}


static void
njt_stream_mqtt_proxy_ssl_handshake(njt_connection_t *pc)
{
    long                          rc;
    njt_stream_session_t         *s;
    njt_stream_upstream_t        *u;
    njt_stream_mqtt_proxy_srv_conf_t  *pscf;

    s = pc->data;

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_mqtt_proxy_module);

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

        njt_stream_mqtt_proxy_init_upstream(s);

        return;
    }

failed:

    njt_stream_mqtt_proxy_next_upstream(s);
}


static void
njt_stream_mqtt_proxy_ssl_save_session(njt_connection_t *c)
{
    njt_stream_session_t   *s;
    njt_stream_upstream_t  *u;

    s = c->data;
    u = s->upstream;

    u->peer.save_session(&u->peer, u->peer.data);
}


static njt_int_t
njt_stream_mqtt_proxy_ssl_name(njt_stream_session_t *s)
{
    u_char                       *p, *last;
    njt_str_t                     name;
    njt_stream_upstream_t        *u;
    njt_stream_mqtt_proxy_srv_conf_t  *pscf;

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_mqtt_proxy_module);

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
njt_stream_mqtt_proxy_ssl_certificates(njt_stream_session_t *s)
{
    njt_str_t                    *certp, *keyp, cert, key;
    njt_uint_t                    i, nelts;
#if (NJT_HAVE_NTLS)
    njt_str_t                     tcert, tkey;
#endif
    njt_connection_t             *c;
    njt_stream_complex_value_t   *certs, *keys;
    njt_stream_mqtt_proxy_srv_conf_t  *pscf;

    c = s->upstream->peer.connection;

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_mqtt_proxy_module);


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
njt_stream_mqtt_proxy_ssl_certificate(njt_stream_session_t *s)
{
    njt_str_t                     cert, key;
    njt_connection_t             *c;
    njt_stream_mqtt_proxy_srv_conf_t  *pscf;

    c = s->upstream->peer.connection;

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_mqtt_proxy_module);

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


void
njt_stream_mqtt_proxy_chain_clean_chains(njt_pool_t *p, njt_chain_t **free, njt_chain_t **busy,
    njt_chain_t **out, njt_buf_tag_t tag)
{
    njt_chain_t  *cl;

    if (*out) {
        if (*busy == NULL) {
            *busy = *out;

        } else {
            for (cl = *busy; cl->next; cl = cl->next) { /* void */ }

            cl->next = *out;
        }

        *out = NULL;
    }

    while (*busy) {
        cl = *busy;

        if (cl->buf->tag != tag) {
            *busy = cl->next;
            njt_free_chain(p, cl);
            continue;
        }

        cl->buf->pos = cl->buf->start;
        cl->buf->last = cl->buf->start;

        *busy = cl->next;
        cl->next = *free;
        *free = cl;
    }
}



static void
njt_stream_mqtt_proxy_downstream_handler(njt_event_t *ev)
{
    njt_stream_mqtt_proxy_process_connection(ev, ev->write);
}


static void
njt_stream_mqtt_proxy_resolve_handler(njt_resolver_ctx_t *ctx)
{
    njt_stream_session_t            *s;
    njt_stream_upstream_t           *u;
    njt_stream_mqtt_proxy_srv_conf_t     *pscf;
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

        njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
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
        njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    njt_resolve_name_done(ctx);
    ur->ctx = NULL;

    u->peer.start_time = njt_current_msec;

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_mqtt_proxy_module);

    if (pscf->next_upstream_tries
        && u->peer.tries > pscf->next_upstream_tries)
    {
        u->peer.tries = pscf->next_upstream_tries;
    }

    njt_stream_mqtt_proxy_connect(s);
}


static void
njt_stream_mqtt_proxy_upstream_handler(njt_event_t *ev)
{
    njt_stream_mqtt_proxy_process_connection(ev, !ev->write);
}


static void
njt_stream_mqtt_proxy_process_connection(njt_event_t *ev, njt_uint_t from_upstream)
{
    njt_connection_t             *c, *pc;
    njt_log_handler_pt            handler;
    njt_stream_session_t         *s;
    njt_stream_upstream_t        *u;
    njt_stream_mqtt_proxy_srv_conf_t  *pscf;
    njt_stream_mqtt_proxy_ctx_t       *ctx; // openresty patch

    c = ev->data;
    s = c->data;
    u = s->upstream;

    if (c->close) {
        njt_log_error(NJT_LOG_INFO, c->log, 0, "shutdown timeout");
        njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_OK);
        return;
    }

    ctx = njt_stream_get_module_ctx(s, njt_stream_mqtt_proxy_module); // openresty patch

    c = s->connection;
    pc = u->peer.connection;

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_mqtt_proxy_module);

    if (ev->timedout) {
        ev->timedout = 0;

        if (ev->delayed) {
            ev->delayed = 0;

            if (!ev->ready) {
                if (njt_handle_read_event(ev, 0) != NJT_OK) {
                    njt_stream_mqtt_proxy_finalize(s,
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

                    njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_OK);
                    return;
                }

                njt_connection_error(pc, NJT_ETIMEDOUT, "upstream timed out");

                pc->read->error = 1;

                njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_BAD_GATEWAY);

                return;
            }

            njt_connection_error(c, NJT_ETIMEDOUT, "connection timed out");

            njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_OK);

            return;
        }

    } else if (ev->delayed) {

        njt_log_debug0(NJT_LOG_DEBUG_STREAM, c->log, 0,
                       "stream connection delayed");

        if (njt_handle_read_event(ev, 0) != NJT_OK) {
            njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        }

        return;
    }

    if (from_upstream && !u->connected) {
        return;
    }

    njt_stream_mqtt_proxy_process(s, from_upstream, ev->write);
}


static void
njt_stream_mqtt_proxy_connect_handler(njt_event_t *ev)
{
    njt_connection_t      *c;
    njt_stream_session_t  *s;

    c = ev->data;
    s = c->data;

    if (ev->timedout) {
        njt_log_error(NJT_LOG_ERR, c->log, NJT_ETIMEDOUT, "upstream timed out");
        njt_stream_mqtt_proxy_next_upstream(s);
        return;
    }

    njt_del_timer(c->write);

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "stream proxy connect upstream");

    if (njt_stream_mqtt_proxy_test_connect(c) != NJT_OK) {
        njt_stream_mqtt_proxy_next_upstream(s);
        return;
    }

    njt_stream_mqtt_proxy_init_upstream(s);
}


static njt_int_t
njt_stream_mqtt_proxy_test_connect(njt_connection_t *c)
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


static STREAM_MQTT_PROXY_MQTT_TYPE
njt_stream_mqtt_proxy_get_packet_type(u_char packet_head){

    STREAM_MQTT_PROXY_MQTT_TYPE mqtt_type;
    mqtt_type = (packet_head & 0xF0) >> 4;

    return mqtt_type;
}



static u_char *
njt_stream_mqtt_proxy_parse_next_varbyte(size_t *value, u_char *pos,
    u_char *end)
{
    njt_uint_t  octet, shift;

    *value = 0;

    if (end - pos > 4) {
        end = pos + 4;
    }

    for (shift = 0; pos != end; shift += 7) {
        octet = *pos++;

        *value += (octet & 0x7f) << shift;

        if (octet < 128) {
            return pos;
        }
    }

    return NULL;
}


static u_char *
njt_stream_mqtt_proxy_parse_next_str(njt_str_t *str, u_char *pos, u_char *end)
{
    size_t  len;

    if (end - pos < 2) {
        return NULL;
    }

    len = (pos[0] << 8) | pos[1];
    
    pos += 2;
    if ((size_t) (end - pos) < len) {
        return NULL;
    }

    str->len = len;
    str->data = pos;

    pos += len;

    return pos;
}


static u_char *
njt_stream_mqtt_proxy_parse_next_shortbyte(u_int16_t *pack, u_char *pos, u_char *end)
{
    if (end - pos < 2) {
        return NULL;
    }

    *pack = (pos[0] << 8) | pos[1];
    pos += 2;

    return pos;
}


static njt_uint_t
njt_stream_mqtt_proxy_parse_sub_topics(njt_stream_mqtt_proxy_pkt_info_t *pkt_info,
        njt_array_t *topics, size_t *total_len, njt_log_t *log){
    u_char                               *last, *p;
    u_int16_t                            packet_id;
    njt_stream_mqtt_proxy_sub_topics_item_t *item;

    p = pkt_info->pkt_data.data + pkt_info->cur_pkt_head_len;
    last = pkt_info->pkt_data.data + pkt_info->pkt_data.len;

    *total_len = 0;

    //parse packet id
    p = njt_stream_mqtt_proxy_parse_next_shortbyte(&packet_id, p, last);
    if (p == NULL) {
        njt_log_error(NJT_LOG_ERR, log, 0,
                    "mqtt proxy failed to parse packetid in subscribe");

        return NJT_ERROR;
    }

    while(p < last){
        item = njt_array_push(topics);

        p = njt_stream_mqtt_proxy_parse_next_str(&item->topic, p, last);
        if (p == NULL)
        {
            njt_log_error(NJT_LOG_ERR, log, 0,
                        "mqtt proxy failed to parse topic in subscribe");

            return NJT_ERROR;
        }

        *total_len = *total_len + item->topic.len;

        item->qos = (njt_uint_t) *p++;
        if(item->qos > 2){
            njt_log_error(NJT_LOG_ERR, log, 0,
                        "mqtt proxy bad qos \"%ui\" of topic:%V", item->qos, &item->topic);
            return NJT_ERROR;
        }

        *total_len = *total_len + 1;
    }

    if(topics->nelts < 1){
        njt_log_error(NJT_LOG_ERR, log, 0,
                "mqtt proxy has no topic info in subscribe msg");
        return NJT_ERROR;
    }

    return NJT_OK;
}


static njt_uint_t
njt_stream_mqtt_proxy_parse_unsub_topics(njt_stream_mqtt_proxy_pkt_info_t *pkt_info,
        njt_array_t *topics, size_t *total_len, njt_log_t *log){
    u_char                               *last, *p;
    u_int16_t                            packet_id;
    njt_stream_mqtt_proxy_sub_topics_item_t *item;

    *total_len = 0;

    p = pkt_info->pkt_data.data + pkt_info->cur_pkt_head_len;
    last = pkt_info->pkt_data.data + pkt_info->pkt_data.len;


    //parse packet id
    p = njt_stream_mqtt_proxy_parse_next_shortbyte(&packet_id, p, last);
    if (p == NULL) {
        njt_log_error(NJT_LOG_ERR, log, 0,
                    "mqtt proxy failed to parse packetid in subscribe");

        return NJT_ERROR;
    }

    while(p < last){
        item = njt_array_push(topics);

        p = njt_stream_mqtt_proxy_parse_next_str(&item->topic, p, last);
        if (p == NULL)
        {
            njt_log_error(NJT_LOG_ERR, log, 0,
                        "mqtt proxy failed to parse topic in subscribe");

            return NJT_ERROR;
        }

        *total_len = *total_len + item->topic.len;
    }

    if(topics->nelts < 1){
        njt_log_error(NJT_LOG_ERR, log, 0,
                "mqtt proxy has no topic info in subscribe msg");
        return NJT_ERROR;
    }

    return NJT_OK;
}



static njt_uint_t
njt_stream_mqtt_proxy_parse_clientid(njt_stream_mqtt_proxy_ctx_t *ctx,
    njt_log_t *log){
    u_char                               flags, *last, *p;
    size_t                               len;
    njt_str_t                            protocol, tmp;
    njt_uint_t                           version;

    p = ctx->conn_pkt.data + 1;
    last = ctx->conn_pkt.data + ctx->conn_pkt.len;

    p = njt_stream_mqtt_proxy_parse_next_varbyte(&len, p, last);
    if (p == NULL) {
        njt_log_error(NJT_LOG_ERR, log, 0,
                    "mqtt proxy failed to parse remaining length");

        return NJT_ERROR;
    }

    p = njt_stream_mqtt_proxy_parse_next_str(&protocol, p, last);
    if (p == NULL
        || protocol.len != 4 || njt_memcmp(protocol.data, "MQTT", 4) != 0)
    {
        njt_log_error(NJT_LOG_ERR, log, 0,
                    "mqtt proxy bad protocol name");

        return NJT_ERROR;
    }

    version = (njt_uint_t) *p++;

    switch (version) {
    case 4:
    case 5:
        break;
    default:
        njt_log_error(NJT_LOG_ERR, log, 0,
                    "mqtt proxy bad protocol version \"%ui\"", version);
        return NJT_ERROR;
    }

    flags = (u_char) *p++;

    if (flags & NJT_STREAM_MQTT_PROXY_MQTT_RESERVED_FLAG) {
        njt_log_error(NJT_LOG_ERR, log, 0,
                    "mqtt proxy \"reserved\" flag set to 1");
        return NJT_ERROR;
    }

    if(flags & NJT_STREAM_MQTT_PROXY_MQTT_CLEAN_SESSION_FLAG){
        ctx->clean_session = 1;
    }

    /* skip keep alive */
    p += 2;

    /* skip properties */
    if (version == 5) {
        p = njt_stream_mqtt_proxy_parse_next_varbyte(&len, p, last);
        if (p == NULL || (size_t) (last - p) < len) {
            njt_log_error(NJT_LOG_ERR, log, 0,
                    "mqtt proxy failed to parse properties length");
            return NJT_ERROR;
        }

        p += len;
    }

    /* parse clientid */
    p = njt_stream_mqtt_proxy_parse_next_str(&tmp, p, last);
    if (p == NULL) {
        njt_log_error(NJT_LOG_ERR, log, 0,
                "mqtt proxy failed to parse client id");
        return NJT_ERROR;
    }

    njt_log_error(NJT_LOG_DEBUG, log, 0,
        "mqtt proxy client id:%V", &tmp);

    if(tmp.len > 0){
        ctx->client_id.len = tmp.len;
        ctx->client_id.data = njt_pstrdup(ctx->pool, &tmp);
        if (ctx->client_id.data == NULL) {
            njt_log_error(NJT_LOG_ERR, log, 0,
                    "mqtt proxy malloc client id error");
            return NJT_ERROR;
        }
    }


    if (!(flags & NJT_STREAM_MQTT_PROXY_MQTT_USERNAME_FLAG)) {
        njt_str_null(&ctx->username);
        return NJT_OK;
    }

    /* skip will properties */
    if (flags & NJT_STREAM_MQTT_PROXY_MQTT_WILL_FLAG) {
        if (version == 5) {
            p = njt_stream_mqtt_proxy_parse_next_varbyte(&len, p, last);
            if (p == NULL || (size_t) (last - p) < len) {
                njt_log_debug0(NJT_LOG_DEBUG_STREAM, log, 0,
                               "mqtt proxy: failed to parse "
                               "\"will properties\"");
                return NJT_ERROR;
            }

            p += len;
        }

        p = njt_stream_mqtt_proxy_parse_next_str(&tmp, p, last);
        if (p == NULL) {
            njt_log_debug0(NJT_LOG_DEBUG_STREAM, log, 0,
                           "mqtt proxy: failed to parse \"will topic\"");
            return NJT_ERROR;
        }

        p = njt_stream_mqtt_proxy_parse_next_str(&tmp, p, last);
        if (p == NULL) {
            njt_log_debug0(NJT_LOG_DEBUG_STREAM, log, 0,
                           "mqtt proxy: failed to parse \"will payload\"");
            return NJT_ERROR;
        }
    }

    p = njt_stream_mqtt_proxy_parse_next_str(&tmp, p, last);
    if (p == NULL) {
        njt_log_debug0(NJT_LOG_DEBUG_STREAM, log, 0,
                       "mqtt proxy: failed to parse username");
        return NJT_ERROR;
    }

    ctx->username.len = tmp.len;
    ctx->username.data = njt_pstrdup(ctx->pool, &tmp);
    if (ctx->username.data == NULL) {
        return NJT_ERROR;
    }

    return NJT_OK;
}



static njt_uint_t
njt_stream_mqtt_proxy_filter_connack_packet(njt_uint_t from_upstream, njt_stream_session_t *s, 
        njt_stream_mqtt_proxy_ctx_t *ctx, njt_stream_mqtt_proxy_pkt_info_t *pkt_info,
        njt_log_t *log){
    // STREAM_MQTT_PROXY_MQTT_CONNECTION_TYPE conn_type;
    u_char                                  *p;

    if(from_upstream && pkt_info->cur_pkt_type == STREAM_MQTT_PROXY_MQTT_TYPE_CONNACK){
        //conn ack len is 2, head len is type(1 byte) + len(1 bytes)
        if(pkt_info->cur_pkt_head_len != 2){
            njt_log_error(NJT_LOG_ERR, log, 0,
                    "mqtt proxy connack len is not 1");
            return NJT_ERROR;
        }

        p = pkt_info->pkt_data.data + pkt_info->cur_pkt_head_len + 1;
        if(*p != 0x00){
            njt_log_error(NJT_LOG_ERR, log, 0,
                    "mqtt proxy connack return code error:%d, should be 0", *p);
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


static njt_uint_t
njt_stream_mqtt_proxy_filter_connect_packet(njt_uint_t from_upstream, njt_stream_session_t *s, 
        njt_stream_mqtt_proxy_ctx_t *ctx, njt_stream_mqtt_proxy_pkt_info_t *pkt_info,
        njt_log_t *log){
    if(!from_upstream && pkt_info->cur_pkt_type == STREAM_MQTT_PROXY_MQTT_TYPE_CONNECT){
        //save CONNECT packet, if has old, update connect packet
        // if(ctx->conn_pkt.data != NULL){
        //     njt_pfree(ctx->pool, ctx->conn_pkt.data);
        //     njt_str_null(&ctx->conn_pkt);
        // }

        ctx->conn_pkt.len = pkt_info->cur_pkt_head_len + pkt_info->cur_pkt_data_len;
        ctx->conn_pkt.data = njt_pcalloc(ctx->pool, ctx->conn_pkt.len);
        if (ctx->conn_pkt.data == NULL) {
            njt_log_error(NJT_LOG_ERR, log, 0,
                        "mqtt proxy malloc error for save connect packet");

            return NJT_ERROR;
        }

        njt_memcpy(ctx->conn_pkt.data, pkt_info->pkt_data.data, ctx->conn_pkt.len);

        //parse clientid and cleansession important info
        if(NJT_OK != njt_stream_mqtt_proxy_parse_clientid(ctx, log)){
            njt_log_error(NJT_LOG_ERR, log, 0,
                "mqtt proxy parse connect packet error");

            return NJT_ERROR;
        }

        if(!ctx->not_wait_conn_pkt){
            ctx->not_wait_conn_pkt = 1;

            if (s->upstream->upstream->peer.init(s, s->upstream->upstream) != NJT_OK) {
                njt_log_error(NJT_LOG_ERR, log, 0,
                    "mqtt proxy peer init error");
                // njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
                return NJT_ERROR;
            }

            //when first get connection, and connect upstream
            s->upstream->peer.start_time = njt_current_msec;

            if (ctx->next_upstream_tries
                && s->upstream->peer.tries > ctx->next_upstream_tries)
            {
                s->upstream->peer.tries = ctx->next_upstream_tries;
            }

            //when first get connection, and connect upstream
            if(NJT_DONE == njt_stream_mqtt_proxy_connect(s)){
                return NJT_DONE;
            }else{
                return NJT_DECLINED;
            }
        }

    }

    return NJT_OK;
}


static njt_uint_t
njt_stream_mqtt_proxy_get_subscribe_topics(njt_str_t *client_id, njt_str_t *topics){
    u_char          *p, tmpbuf[1024];
    njt_str_t       tmp_str;

    p = njt_snprintf(tmpbuf, 1024, "mqtt_proxy_sub_%V", client_id);
    tmp_str.data = tmpbuf;
    tmp_str.len = p - tmpbuf;

    return njt_db_kv_get(&tmp_str, topics);
}



static njt_uint_t
njt_stream_mqtt_proxy_set_subscribe_topics(njt_str_t *client_id, njt_str_t *topics){
    u_char          *p, tmpbuf[1024];
    njt_str_t       tmp_str;

    p = njt_snprintf(tmpbuf, 1024, "mqtt_proxy_sub_%V", client_id);
    tmp_str.data = tmpbuf;
    tmp_str.len = p - tmpbuf;

    return njt_db_kv_set(&tmp_str, topics);
}


static njt_uint_t
njt_stream_mqtt_proxy_del_subscribe_topics(njt_str_t *client_id){
    u_char          *p, tmpbuf[1024];
    njt_str_t       tmp_str;

    p = njt_snprintf(tmpbuf, 1024, "mqtt_proxy_sub_%V", client_id);
    tmp_str.data = tmpbuf;
    tmp_str.len = p - tmpbuf;

    return njt_db_kv_del(&tmp_str);
}


static njt_uint_t
njt_stream_mqtt_proxy_filter_subscribe_packet(njt_uint_t from_upstream, njt_stream_session_t *s, 
        njt_stream_mqtt_proxy_ctx_t *ctx, njt_stream_mqtt_proxy_pkt_info_t *pkt_info,
        njt_log_t *log){
    njt_str_t                   kv_topics, new_kv_topics;
    njt_stream_mqtt_proxy_sub_topics_item_t *tmp_topics_item;
    njt_array_t                 sub_topics;
    njt_uint_t                  i;
    size_t                      total_len, new_kv_topics_len = 0;
    u_char                      tmp_topic[1024];
    u_char                      *p, *p1, *p2;
    size_t                      tmp_len;


    if(!from_upstream && pkt_info->cur_pkt_type == STREAM_MQTT_PROXY_MQTT_TYPE_SUBSCRIBE){
        if(ctx->client_id.len == 0){
            //in this case, not need to save to kv or get kv
            //just save all topic in ctx, and used for reconnect server

            //parse subscribe topic
            //head + packet id + n * {topic(len+value) + qos(1bytes)}
            if(NJT_OK != njt_stream_mqtt_proxy_parse_sub_topics(pkt_info, &ctx->sub_topics, &total_len, log)){
                njt_log_error(NJT_LOG_ERR, log, 0, 
                        "mqtt proxy parse subscribe topics error");
                return NJT_ERROR;
            }
        }else{
            //in this case, need update kv of this clientid's subscribe topics
            njt_array_init(&sub_topics, ctx->pool, 2, sizeof(njt_stream_mqtt_proxy_sub_topics_item_t));
            //parse subscribe topic
            //head + packet id + n * {topic(len+value) + qos(1bytes)}
            if(NJT_OK != njt_stream_mqtt_proxy_parse_sub_topics(pkt_info, &sub_topics, &total_len, log)){
                njt_log_error(NJT_LOG_ERR, log, 0, 
                        "mqtt proxy parse subscribe topics error");
                return NJT_ERROR;
            }

            if(sub_topics.nelts > 0){
                //every topic use two common char
                new_kv_topics_len += (total_len + sub_topics.nelts * 2);
            }

            if(NJT_OK != njt_stream_mqtt_proxy_get_subscribe_topics(&ctx->client_id, &kv_topics)){
                njt_log_error(NJT_LOG_DEBUG, log, 0, 
                    "mqtt proxy get topics from kv none");
            }

            //append current topic to topics
            if(kv_topics.len > 0){
                njt_log_error(NJT_LOG_DEBUG, log, 0, 
                    "mqtt proxy get topics from kv clientid:%V  topics:%V len:%d",&ctx->client_id, &kv_topics, kv_topics.len);
                //remove repeated topic
                tmp_topics_item = sub_topics.elts;
                for(i = 0; i < sub_topics.nelts; i++){
                    p = njt_snprintf(tmp_topic, 1024, "%V:", &tmp_topics_item[i].topic);
                    tmp_len = p - tmp_topic;
                    do{
                        p1 = njt_strlcasestrn(kv_topics.data, (kv_topics.data + kv_topics.len), tmp_topic, tmp_len-1);
                        if(p1 == NULL){
                            continue;
                        }

                        //remove repeated topic
                        p2 = p1 + tmp_len + 1;
                        if(p2 == (kv_topics.data + kv_topics.len)){
                            //last
                            kv_topics.len = kv_topics.len - tmp_len - 1;
                        }else{
                            //need remove more ','
                            p2++;
                            while(p2 < (kv_topics.data + kv_topics.len)){
                                *(p2 - tmp_len - 1 - 1) = *p2;
                                p2++;
                            }
                            // njt_memcpy(p1, p2+1, kv_topics.data + kv_topics.len - p2 - 1);
                            kv_topics.len = kv_topics.len - tmp_len - 1 - 1;
                        }
                    }while(p1 != NULL);
                }
                njt_log_error(NJT_LOG_DEBUG, log, 0, 
                    "mqtt proxy topics after remove repeated from kv clientid:%V  topics:%V len:%d",&ctx->client_id, &kv_topics, kv_topics.len);

                new_kv_topics_len += kv_topics.len;
            }else{
                new_kv_topics_len -= 1;    //
            }

            new_kv_topics.data = njt_pcalloc(ctx->pool, new_kv_topics_len);
            if(new_kv_topics.data == NULL){
                njt_log_error(NJT_LOG_ERR, log, 0, 
                    "mqtt proxy malloc subscribe(kv) topic error");
                return NJT_ERROR;
            }

            if(kv_topics.len > 0){
                //format topic1:qos1,topic2:qos2
                njt_memcpy(new_kv_topics.data, kv_topics.data, kv_topics.len);
                new_kv_topics.len = kv_topics.len;
                tmp_topics_item = sub_topics.elts;
                for(i = 0; i < sub_topics.nelts; i++){
                    new_kv_topics.data[new_kv_topics.len] = ',';
                    new_kv_topics.len++;
                    njt_memcpy(new_kv_topics.data + new_kv_topics.len, tmp_topics_item[i].topic.data, tmp_topics_item[i].topic.len);
                    new_kv_topics.len += tmp_topics_item[i].topic.len;
                    new_kv_topics.data[new_kv_topics.len] = ':';
                    new_kv_topics.len++;
                    new_kv_topics.data[new_kv_topics.len] = tmp_topics_item[i].qos;
                    new_kv_topics.len++;
                }
            }else{
                new_kv_topics.len = 0;
                tmp_topics_item = sub_topics.elts;
                njt_memcpy(new_kv_topics.data, tmp_topics_item[0].topic.data, tmp_topics_item[0].topic.len);
                new_kv_topics.len += tmp_topics_item[0].topic.len;
                new_kv_topics.data[new_kv_topics.len] = ':';
                new_kv_topics.len++;
                new_kv_topics.data[new_kv_topics.len] = tmp_topics_item[0].qos;
                new_kv_topics.len++;

                for(i = 1; i < sub_topics.nelts; i++){
                    new_kv_topics.data[new_kv_topics.len] = ',';
                    new_kv_topics.len++;
                    njt_memcpy(new_kv_topics.data + new_kv_topics.len, tmp_topics_item[i].topic.data, tmp_topics_item[i].topic.len);
                    new_kv_topics.len += tmp_topics_item[i].topic.len;
                    new_kv_topics.data[new_kv_topics.len] = ':';
                    new_kv_topics.len++;
                    new_kv_topics.data[new_kv_topics.len] = tmp_topics_item[i].qos;
                    new_kv_topics.len++;
                }  
            }

            njt_log_error(NJT_LOG_DEBUG, log, 0, 
                    "mqtt proxy set topics to kv clientid:%V  topics:%V",&ctx->client_id, &new_kv_topics);

            if(NJT_OK != njt_stream_mqtt_proxy_set_subscribe_topics(&ctx->client_id, &new_kv_topics)){
                //just print log info
                njt_log_error(NJT_LOG_ERR, log, 0, 
                    "mqtt proxy set topics to kv error");
            }
        }
    }

    return NJT_OK;
}



static njt_uint_t
njt_stream_mqtt_proxy_filter_unsubscribe_packet(njt_uint_t from_upstream, njt_stream_session_t *s, 
        njt_stream_mqtt_proxy_ctx_t *ctx, njt_stream_mqtt_proxy_pkt_info_t *pkt_info,
        njt_log_t *log){
    njt_str_t                   kv_topics, new_kv_topics;
    njt_stream_mqtt_proxy_sub_topics_item_t *tmp_topics_item_i, *tmp_topics_item_j, *tmp_topics_item;
    njt_array_t                 sub_topics, new_kv_sub_topics;
    njt_uint_t                  i, j;
    size_t                      total_len, new_kv_topics_len = 0;
    u_char                      *p, *last, *start;


    if(!from_upstream && pkt_info->cur_pkt_type == STREAM_MQTT_PROXY_MQTT_TYPE_UNSUBSCRIBE){
        njt_array_init(&sub_topics, ctx->pool, 2, sizeof(njt_stream_mqtt_proxy_sub_topics_item_t));
        
        //parse unsubscribe topic
        //head + packet id + n * {topic(len+value)}
        if(NJT_OK != njt_stream_mqtt_proxy_parse_unsub_topics(pkt_info, &sub_topics, &total_len, log)){
            njt_log_error(NJT_LOG_ERR, log, 0, 
                    "mqtt proxy parse subscribe topics error");
            return NJT_ERROR;
        }

        if(ctx->client_id.len == 0){
            //in this case, not need to save to kv or get kv
            //just update local topic info, and used for reconnect
            tmp_topics_item_i = sub_topics.elts;
            for(i = 0; i < sub_topics.nelts; i++){
                tmp_topics_item_j = ctx->sub_topics.elts;
                for(j = 0; j < ctx->sub_topics.nelts; j++){
                    if(tmp_topics_item_i[i].topic.len == tmp_topics_item_j[j].topic.len
                        && njt_memcmp(tmp_topics_item_i[i].topic.data, tmp_topics_item_j[j].topic.data,
                            tmp_topics_item_j[j].topic.len) == 0){
                        njt_array_delete_idx(&ctx->sub_topics, j);
                        njt_log_error(NJT_LOG_INFO, log, 0, 
                                "mqtt proxy unsubscribe topic:%V", &tmp_topics_item_i[i].topic);
                        break;
                    }
                }
            }
        }else{
            if(NJT_OK != njt_stream_mqtt_proxy_get_subscribe_topics(&ctx->client_id, &kv_topics)){
                njt_log_error(NJT_LOG_DEBUG, log, 0, 
                    "mqtt proxy get topics none from kv in get unsubscribe");
            }

            if(kv_topics.len < 1){
                //just print log 
                njt_log_error(NJT_LOG_DEBUG, log, 0, 
                    "mqtt proxy get topics from kv, but is zero in get unsubscribe msg");
                return NJT_OK;
            }

            njt_array_init(&new_kv_sub_topics, ctx->pool, 2, sizeof(njt_stream_mqtt_proxy_sub_topics_item_t));
            p = kv_topics.data;
            start = p;
            last = kv_topics.data + kv_topics.len;
            new_kv_topics_len = 0;
            while(p < last){
                if(*p == ':'){
                    tmp_topics_item = njt_array_push(&new_kv_sub_topics);
                    if(tmp_topics_item == NULL){
                        njt_log_error(NJT_LOG_ERR, log, 0, 
                            "mqtt proxy malloc subscribe(kv) topic error");
                        return NJT_ERROR;
                    }

                    tmp_topics_item->topic.len = p - start;
                    tmp_topics_item->topic.data = start;
                    tmp_topics_item->qos = *(p+1);
                    new_kv_topics_len += tmp_topics_item->topic.len;
                }else if(*p == ','){
                    start = p + 1;
                }
                p++;
            }

            tmp_topics_item_i = sub_topics.elts;
            for(i = 0; i < sub_topics.nelts; i++){
                tmp_topics_item_j = new_kv_sub_topics.elts;
                for(j = 0; j < new_kv_sub_topics.nelts; j++){
                    if(tmp_topics_item_i[i].topic.len == tmp_topics_item_j[j].topic.len
                        && njt_memcmp(tmp_topics_item_i[i].topic.data, tmp_topics_item_j[j].topic.data,
                            tmp_topics_item_j[j].topic.len) == 0){
                        new_kv_topics_len -= tmp_topics_item_j[j].topic.len;
                        njt_array_delete_idx(&new_kv_sub_topics, j);
                        
                        njt_log_error(NJT_LOG_DEBUG, log, 0, 
                                "mqtt proxy unsubscribe topic:%V", &tmp_topics_item_i[i].topic);
                        break;
                    }
                }
            }

            if(new_kv_sub_topics.nelts < 1){
                //just delete from kv
                if(NJT_OK != njt_stream_mqtt_proxy_del_subscribe_topics(&ctx->client_id)){
                    //just print log info
                    njt_log_error(NJT_LOG_DEBUG, log, 0, 
                        "mqtt proxy del topics none from kv");
                }
            }else{
                //recalc new topic len
                new_kv_topics_len += (new_kv_sub_topics.nelts * 2 - 1);
                new_kv_topics.data = njt_pcalloc(ctx->pool, new_kv_topics_len);
                if(new_kv_topics.data == NULL){
                    njt_log_error(NJT_LOG_ERR, log, 0, 
                        "mqtt proxy malloc subscribe(kv) topic error");
                    return NJT_ERROR;
                }

                new_kv_topics.len = 0;
                tmp_topics_item = new_kv_sub_topics.elts;
                njt_memcpy(new_kv_topics.data, tmp_topics_item[0].topic.data, tmp_topics_item[0].topic.len);
                new_kv_topics.len += tmp_topics_item[0].topic.len;
                new_kv_topics.data[new_kv_topics.len] = ':';
                new_kv_topics.len++;
                new_kv_topics.data[new_kv_topics.len] = tmp_topics_item[0].qos;
                new_kv_topics.len++;

                for(i = 1; i < new_kv_sub_topics.nelts; i++){
                    new_kv_topics.data[new_kv_topics.len] = ',';
                    new_kv_topics.len++;
                    njt_memcpy(new_kv_topics.data + new_kv_topics.len, tmp_topics_item[i].topic.data, tmp_topics_item[i].topic.len);
                    new_kv_topics.len += tmp_topics_item[i].topic.len;
                    new_kv_topics.data[new_kv_topics.len] = ':';
                    new_kv_topics.len++;
                    new_kv_topics.data[new_kv_topics.len] = tmp_topics_item[i].qos;
                    new_kv_topics.len++;
                }

                njt_log_error(NJT_LOG_DEBUG, log, 0, 
                    "mqtt proxy set topics in unsbscirbe clientid:%V  topics:%V", &ctx->client_id, &new_kv_topics);

                if(NJT_OK != njt_stream_mqtt_proxy_set_subscribe_topics(&ctx->client_id, &new_kv_topics)){
                    //just print log info
                    njt_log_error(NJT_LOG_ERR, log, 0, 
                        "mqtt proxy set topics to kv error");
                }
            }
        }
    }

    return NJT_OK;
}


static njt_uint_t
njt_stream_mqtt_proxy_filter_packet(njt_uint_t from_upstream, njt_stream_session_t *s, 
        njt_stream_mqtt_proxy_ctx_t *ctx, njt_stream_mqtt_proxy_pkt_info_t *pkt_info,
        njt_log_t *log){
    njt_uint_t      rc;

    if(!from_upstream && ctx->reconnecting){
        //ignore all packet but pingreq pkt
        if(pkt_info->cur_pkt_type == STREAM_MQTT_PROXY_MQTT_TYPE_PINGREQ){
            //send pingresp to client
            njt_stream_mqtt_send_pingresp_to_client(s, s->connection, ctx);
        }

        njt_stream_mqtt_client_pkt_info(pkt_info);

        return NJT_AGAIN;
    }

    //filter client connect packet and save connect packet for multi connect server
    rc = njt_stream_mqtt_proxy_filter_connect_packet(from_upstream, s, ctx, pkt_info, log);
    if(rc != NJT_OK){
        return rc;
    }

    //filter client subscribe packet and get topic info
    rc = njt_stream_mqtt_proxy_filter_subscribe_packet(from_upstream, s, ctx, pkt_info, log);
    if(rc != NJT_OK){
        return rc;
    }

    //filter unsubscribe packet
    rc = njt_stream_mqtt_proxy_filter_unsubscribe_packet(from_upstream, s, ctx, pkt_info, log);
    if(rc != NJT_OK){
        return rc;
    }

    //filter connack packet, whether has error
    rc = njt_stream_mqtt_proxy_filter_connack_packet(from_upstream, s, ctx, pkt_info, log);
    if(rc != NJT_OK){
        return rc;
    }

    return NJT_OK;
}

static void njt_stream_mqtt_proxy_print_mqtt_type(njt_uint_t from_upstream, 
        STREAM_MQTT_PROXY_MQTT_TYPE mqtt_type, njt_log_t *log){
    switch (mqtt_type)
    {
    case STREAM_MQTT_PROXY_MQTT_TYPE_RESERVE_MIN:
        njt_log_error(NJT_LOG_DEBUG, log, 0, 
                    "mqtt proxy recv msg type 0(reserve)  upstream:%d", from_upstream);
        break;
    case STREAM_MQTT_PROXY_MQTT_TYPE_CONNECT:
        njt_log_error(NJT_LOG_DEBUG, log, 0, 
                    "mqtt proxy recv msg type CONNECT  upstream:%d", from_upstream);
        break;
    case STREAM_MQTT_PROXY_MQTT_TYPE_CONNACK:
        njt_log_error(NJT_LOG_DEBUG, log, 0, 
                    "mqtt proxy recv msg type CONNACK  upstream:%d", from_upstream);
        break;
    case STREAM_MQTT_PROXY_MQTT_TYPE_PUBLISH:
        njt_log_error(NJT_LOG_DEBUG, log, 0, 
                    "mqtt proxy recv msg type PUBLISH  upstream:%d", from_upstream);
        break;
    case STREAM_MQTT_PROXY_MQTT_TYPE_PUBACK:
        njt_log_error(NJT_LOG_DEBUG, log, 0, 
                    "mqtt proxy recv msg type PUBACK  upstream:%d", from_upstream);
        break;
    case STREAM_MQTT_PROXY_MQTT_TYPE_PUBREC:
        njt_log_error(NJT_LOG_DEBUG, log, 0, 
                    "mqtt proxy recv msg type PUBREC  upstream:%d", from_upstream);
        break;
    case STREAM_MQTT_PROXY_MQTT_TYPE_PUBREL:
        njt_log_error(NJT_LOG_DEBUG, log, 0, 
                    "mqtt proxy recv msg type PUBREL  upstream:%d", from_upstream);
        break;
    case STREAM_MQTT_PROXY_MQTT_TYPE_PUBCOMP:
        njt_log_error(NJT_LOG_DEBUG, log, 0, 
                    "mqtt proxy recv msg type PUBCOMP  upstream:%d", from_upstream);
        break;
    case STREAM_MQTT_PROXY_MQTT_TYPE_SUBSCRIBE:
        njt_log_error(NJT_LOG_DEBUG, log, 0, 
                    "mqtt proxy recv msg type SUBSCRIBE  upstream:%d", from_upstream);
        break;
    case STREAM_MQTT_PROXY_MQTT_TYPE_SUBACK:
        njt_log_error(NJT_LOG_DEBUG, log, 0, 
                    "mqtt proxy recv msg type SUBACK  upstream:%d", from_upstream);
        break;
    case STREAM_MQTT_PROXY_MQTT_TYPE_UNSUBSCRIBE:
        njt_log_error(NJT_LOG_DEBUG, log, 0, 
                    "mqtt proxy recv msg type UNSUBSCRIBE  upstream:%d", from_upstream);
        break;
    case STREAM_MQTT_PROXY_MQTT_TYPE_UNSUBACK:
        njt_log_error(NJT_LOG_DEBUG, log, 0, 
                    "mqtt proxy recv msg type UNSUBACK  upstream:%d", from_upstream);
        break;
    case STREAM_MQTT_PROXY_MQTT_TYPE_PINGREQ:
        njt_log_error(NJT_LOG_DEBUG, log, 0, 
                    "mqtt proxy recv msg type PINGREQ  upstream:%d", from_upstream);
        break;
    case STREAM_MQTT_PROXY_MQTT_TYPE_PINGRESP:
        njt_log_error(NJT_LOG_DEBUG, log, 0, 
                    "mqtt proxy recv msg type PINGRESP  upstream:%d", from_upstream);
        break;
    case STREAM_MQTT_PROXY_MQTT_TYPE_DISCONNECT:
        njt_log_error(NJT_LOG_DEBUG, log, 0, 
                    "mqtt proxy recv msg type DISCONNECT  upstream:%d", from_upstream);
        break;
    case STREAM_MQTT_PROXY_MQTT_TYPE_RESERVE_MAX:
        njt_log_error(NJT_LOG_DEBUG, log, 0, 
                    "mqtt proxy recv msg type 16(reserve)  upstream:%d", from_upstream);
        break;

    default:
        njt_log_error(NJT_LOG_ERR, log, 0, 
            "mqtt proxy, recv msg type:%d  error, upstream:%d", mqtt_type, from_upstream);
    }
}

static njt_uint_t
njt_stream_mqtt_proxy_parse_packet(njt_uint_t from_upstream, njt_stream_session_t *s, 
        njt_stream_mqtt_proxy_ctx_t *ctx, njt_stream_mqtt_proxy_pkt_info_t *pkt_info,
        size_t recv_len, njt_log_t *log){
    njt_uint_t                          octet;
    STREAM_MQTT_PROXY_MQTT_TYPE         mqtt_type;

    switch (pkt_info->pkt_state)
    {
    case NJT_STREAM_MQTT_PROXY_PKT_WAIT_TYPE:

        mqtt_type = njt_stream_mqtt_proxy_get_packet_type(pkt_info->head_buf[0]);
        if(!from_upstream && ctx->client_first_pkt && mqtt_type != STREAM_MQTT_PROXY_MQTT_TYPE_CONNECT){
            njt_log_error(NJT_LOG_ERR, log, 0, 
                    "mqtt proxy, first client pkt must be CONNECT PACKET(0x10), now type:%d", mqtt_type);
            return NJT_ERROR;
        }

        njt_stream_mqtt_proxy_print_mqtt_type(from_upstream, mqtt_type, log);

        ctx->client_first_pkt = 0;
        pkt_info->cur_pkt_type = mqtt_type;
        pkt_info->pkt_state = NJT_STREAM_MQTT_PROXY_PKT_WAIT_LEN;
            // njt_log_error(NJT_LOG_ERR, log, 0, 
            //         "mqtt proxy, set state to wait len");
        break;
    case NJT_STREAM_MQTT_PROXY_PKT_WAIT_LEN:
        pkt_info->head_len++;
        //check wether head len has next byte, max 4 bytes
        octet = pkt_info->head_buf[pkt_info->head_len];
        pkt_info->cur_pkt_data_len += (octet & 0x7f) << pkt_info->shift;
        octet = pkt_info->head_buf[pkt_info->head_len];
                    // njt_log_error(NJT_LOG_ERR, log, 0, 
                    // "mqtt proxy, parse len:%d  datalen:%d", octet, pkt_info->cur_pkt_data_len);
        pkt_info->shift += 7;
        if (octet < 128) {
            pkt_info->cur_pkt_head_len = 1 + pkt_info->head_len;
            //malloc pkt memory
            if(pkt_info->max_buffer_len <  (pkt_info->cur_pkt_data_len + pkt_info->cur_pkt_head_len)){
                pkt_info->max_buffer_len = 2 * (pkt_info->cur_pkt_data_len + pkt_info->cur_pkt_head_len);
                // if(pkt_info->pkt_data.data != NULL){
                //     njt_pfree(ctx->pool, pkt_info->pkt_data.data);
                //     njt_str_null(&pkt_info->pkt_data);
                // }
                // if(pkt_info->pkt_data.data == NULL){
                    pkt_info->pkt_data.data = njt_pcalloc(ctx->pool, pkt_info->max_buffer_len);
                    
                    if(pkt_info->pkt_data.data == NULL){
                        njt_log_error(NJT_LOG_ERR, log, 0, 
                            "mqtt proxy, client pkt malloc error");
                        
                        return NJT_ERROR;
                    }
                // }
            }

            //copy type and head to pkt data
            pkt_info->pkt_data.len = pkt_info->cur_pkt_head_len;
            njt_memcpy(pkt_info->pkt_data.data, pkt_info->head_buf, pkt_info->cur_pkt_head_len);

            //now all len bytes has read, enter next state
            if(pkt_info->cur_pkt_data_len > 0){
                pkt_info->pkt_state = NJT_STREAM_MQTT_PROXY_PKT_WAIT_DATA;
                pkt_info->cur_pkt_left_data_len = pkt_info->cur_pkt_data_len;
                // njt_log_error(NJT_LOG_ERR, log, 0, 
                //     "mqtt proxy, set state to wait data");
            }else{
                pkt_info->pkt_state = NJT_STREAM_MQTT_PROXY_PKT_WAIT_TYPE;
                pkt_info->wait_send = 1;
                    //             njt_log_error(NJT_LOG_ERR, log, 0, 
                    // "mqtt proxy, data len is zero, set state to wait type, and set wait_send to 1");
            }
        }
        
        if(octet >= 128 && pkt_info->head_len == 3){
            njt_log_error(NJT_LOG_ERR, log, 0, 
                    "mqtt proxy, client pkt len error, len pos:%d", pkt_info->head_len);
            return NJT_ERROR;
        }

        break;
    case NJT_STREAM_MQTT_PROXY_PKT_WAIT_DATA:
            // njt_log_error(NJT_LOG_ERR, log, 0, 
            //         "mqtt proxy, parse data");
        if(recv_len == pkt_info->cur_pkt_left_data_len){
            // pkt_info->cur_pkt_left_data_len = 0;
            //             njt_log_error(NJT_LOG_ERR, log, 0, 
            //         "mqtt proxy, set waitsend to 1");
            pkt_info->wait_send = 1;
        }else{
            pkt_info->cur_pkt_left_data_len -= recv_len;
        }
        
        break;
    }

    return NJT_OK;
}


static void
njt_stream_mqtt_client_pkt_info(njt_stream_mqtt_proxy_pkt_info_t *pkt_info){
    pkt_info->wait_send = 0;
    pkt_info->head_len = 0;
    pkt_info->shift = 0;
    pkt_info->pkt_state = NJT_STREAM_MQTT_PROXY_PKT_WAIT_TYPE;
    pkt_info->cur_pkt_head_len = 0;
    pkt_info->cur_pkt_data_len = 0;
    pkt_info->cur_pkt_left_data_len = 0;
}


njt_uint_t
njt_stream_mqtt_send_pingresp_to_client(njt_stream_session_t *s, njt_connection_t *dst,
    njt_stream_mqtt_proxy_ctx_t *ctx){
    njt_chain_t                  **out, **busy;
    njt_int_t                     rc;
    
    if(ctx->client_out == NULL && ctx->client_busy == NULL){
        ctx->client_out = njt_chain_get_free_buf(ctx->pool, &s->upstream->free);
        if (ctx->out == NULL) {
            njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                                "mqtt proxy send conn get free buff error");

            return NJT_ERROR;
        }

        ctx->client_out->buf->pos = (u_char *)&ctx->pingresp;
        ctx->client_out->buf->last = ctx->client_out->buf->pos + 2;
        ctx->client_out->buf->tag = (njt_buf_tag_t) &njt_stream_mqtt_proxy_module;

        ctx->client_out->buf->temporary = 1;
        ctx->client_out->buf->last_buf = 0;
        ctx->client_out->buf->flush = 1;
    }

    out = &ctx->client_out;
    busy = &ctx->client_busy;

    s->connection->log->action = "mqtt proxying and sending conn to upstream";

    rc = njt_stream_top_filter(s, *out, 1);
    if (rc == NJT_ERROR) {
        //if has error, here not close
        // njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_OK);
        njt_log_error(NJT_LOG_INFO, s->connection->log, 0,
                "mqtt proxy send pingresp error");
        return NJT_ERROR;
    }

    njt_chain_update_chains(ctx->pool, &s->upstream->free, busy, out,
                        (njt_buf_tag_t) &njt_stream_mqtt_proxy_module);

    if(*busy){
        njt_log_error(NJT_LOG_DEBUG, s->connection->log, 0,
                "mqtt proxy send pingresp busy");
    }else{
        njt_log_error(NJT_LOG_DEBUG, s->connection->log, 0,
                "mqtt proxy send pingresp ok");
    }

    return NJT_OK;
}


//return NJT_ERROR: close session
//return NJT_DECLINE: next upstream
//return NJT_AGAIN: continue
//return NJT_OK
njt_uint_t
njt_stream_mqtt_reconnect_send_conn(njt_stream_session_t *s, njt_connection_t *dst,
    njt_stream_mqtt_proxy_ctx_t *ctx){
    njt_chain_t                  **out, **busy;
    njt_int_t                     rc;
    
    if(ctx->out == NULL && ctx->busy == NULL){
        ctx->out = njt_chain_get_free_buf(ctx->pool, &s->upstream->free);
        if (ctx->out == NULL) {
            njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                                "mqtt proxy send conn get free buff error");

            return NJT_ERROR;
        }

        ctx->out->buf->pos = ctx->conn_pkt.data;
        ctx->out->buf->last = ctx->conn_pkt.data + ctx->conn_pkt.len;
        ctx->out->buf->tag = (njt_buf_tag_t) &njt_stream_mqtt_proxy_module;

        ctx->out->buf->temporary = 1;
        ctx->out->buf->last_buf = 0;
        ctx->out->buf->flush = 1;
    }

    out = &ctx->out;
    busy = &ctx->busy;

    s->connection->log->action = "mqtt proxying and sending conn to upstream";

    rc = njt_stream_top_filter(s, *out, 0);
    if (rc == NJT_ERROR) {
        //todo if from_upstream, need try connect new server
        //and first is send saved connect packet and all subscribe packet, then enter this process
        if(ctx->next_upstream_tries){
            //need reconnect new server
            return NJT_DECLINED;
        }else{
            njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_OK);
            return NJT_ERROR;
        }
    }

    njt_chain_update_chains(ctx->pool, &s->upstream->free, busy, out,
                        (njt_buf_tag_t) &njt_stream_mqtt_proxy_module);

    if(*busy){
        njt_log_error(NJT_LOG_DEBUG, s->connection->log, 0,
                "mqtt proxy send conn busy, state still is conn");
    }else{
        njt_log_error(NJT_LOG_DEBUG, s->connection->log, 0,
                "mqtt proxy send conn ok, set next state to recv connack");
        ctx->reconnect_state = STREAM_MQTT_PROXY_MQTT_RECONNECTE_RECV_CONNACK;
    }

    return NJT_OK;
}

njt_uint_t
njt_stream_mqtt_pack_len(u_char *buf, uint32_t tmp_size, njt_uint_t *len_count){
    *len_count = 0;
    do{
        buf[*len_count] = tmp_size & 0x7F;
        if(tmp_size > 127) buf[*len_count] |= 0x80;
        tmp_size = tmp_size >> 7;
        *len_count = *len_count + 1;
        if(*len_count > 4){
            return NJT_ERROR;
        }
    }while(buf[(*len_count)-1] & 0x80);
    
    return NJT_OK;
}


njt_uint_t
njt_stream_mqtt_reconnect_send_subscribe(njt_stream_session_t *s, njt_connection_t *dst,
    njt_stream_mqtt_proxy_ctx_t *ctx){
    njt_chain_t                     **out, **busy;
    njt_int_t                       rc;
    njt_str_t                       kv_topics;
    u_char                          *p, *start, *last;
    uint32_t                        remaining_size, tmp_size, tmp_size2;
    u_char                          len_space[4];     //max size is 4
    njt_uint_t                      len_count = 0;
    uint16_t                        packet_id = MIN_MQTT_SUBSCRIBE_PACKET_ID, tmp_packet_id;
    size_t                          pkt_off;
    njt_stream_mqtt_proxy_sub_topics_item_t *item;
    njt_uint_t                      i;
    u_char                          mqtt_type_char = (u_char)STREAM_MQTT_PROXY_MQTT_TYPE_SUBSCRIBE;

    njt_str_null(&kv_topics);

    if(ctx->out == NULL && ctx->busy == NULL){
        if(ctx->client_id.len > 0){
            //first get all subscribe topics from kv
            if(NJT_OK != njt_stream_mqtt_proxy_get_subscribe_topics(&ctx->client_id, &kv_topics)){
                njt_log_error(NJT_LOG_DEBUG, s->connection->log, 0, 
                    "mqtt proxy get topics none from kv in send subscribe");
                
                //just consider has no subscribe topic
                goto has_no_subscribe;
            }

            if(kv_topics.len < 1){
                //just print log 
                njt_log_error(NJT_LOG_DEBUG, s->connection->log, 0, 
                    "mqtt proxy get topics from kv, but is zero in get unsubscribe msg in send subscribe");
                goto has_no_subscribe;
            }

            //calc topic count and size
            p = kv_topics.data;
            start = p;
            last = kv_topics.data + kv_topics.len;
            remaining_size = 2;         /* size of variable header , packet id */
            while(p < last){
                if(*p == ':'){
                    //2 bytes is len and 1 is qos, and middle is topic
                    remaining_size += 2 + (p - start) + 1;
                    // tmp_topics_item->topic.len = p - start;
                    // tmp_topics_item->topic.data = start;
                    // tmp_topics_item->qos = *(p+1);
                    // new_kv_topics_len += tmp_topics_item->topic.len;
                }else if(*p == ','){
                    start = p + 1;
                }
                p++;
            }
        }else{
            //get local tmp topics
            if(ctx->sub_topics.nelts < 1){
                njt_log_error(NJT_LOG_DEBUG, s->connection->log, 0, 
                        "mqtt proxy local has no subscribe topic");
                goto has_no_subscribe;
            }

            remaining_size = 2;         /* size of variable header , packet id */
            item = ctx->sub_topics.elts;
            for(i = 0; i < ctx->sub_topics.nelts; i++){
                remaining_size += 2 + item[i].topic.len + 1;
            }
        }

        if(remaining_size >= 256*1024*1024){
            njt_log_error(NJT_LOG_DEBUG, s->connection->log, 0, 
                "mqtt proxy remaining len is too long, just not use");
            goto has_no_subscribe;
        }

        //calc len use space
        tmp_size = remaining_size;

        if(NJT_OK != njt_stream_mqtt_pack_len(len_space, tmp_size, &len_count)){
            njt_log_error(NJT_LOG_DEBUG, s->connection->log, 0, 
                    "mqtt proxy remaining len is too long(2), just not use");
            goto has_no_subscribe;
        }

        //create subscirbe packet
        njt_str_null(&ctx->subscribe_pkt);
        ctx->subscribe_pkt.len = 1 + len_count + remaining_size;

        ctx->subscribe_pkt.data = njt_pcalloc(ctx->pool, ctx->subscribe_pkt.len);
        if(ctx->subscribe_pkt.data == NULL){
            njt_log_error(NJT_LOG_ERR, s->connection->log, 0, 
                    "mqtt proxy subscribe malloc error");
            return NJT_ERROR;
        }

        //fit subscribe pkt,  0x82, flag must is 2
        pkt_off = 0;
        //type
        ctx->subscribe_pkt.data[pkt_off] = (u_char)((mqtt_type_char << 4) & 0xF0);
        ctx->subscribe_pkt.data[pkt_off] |= 0x02;
        njt_stream_mqtt_proxy_print_mqtt_type(1, njt_stream_mqtt_proxy_get_packet_type(ctx->subscribe_pkt.data[0]), s->connection->log);
        pkt_off++;

        //remaining size
        njt_memcpy(ctx->subscribe_pkt.data + pkt_off, len_space, len_count);
        pkt_off += len_count;

        //packet id(2 bytes)
        tmp_packet_id = htons(packet_id);
        njt_memcpy(ctx->subscribe_pkt.data + pkt_off, &tmp_packet_id, 2uL);
        pkt_off += 2;

        if(ctx->client_id.len > 0){
            //topic:qos
            p = kv_topics.data;
            start = p;
            last = kv_topics.data + kv_topics.len;
            while(p < last){
                if(*p == ':'){
                    // tmp_topics_item->topic.len = p - start;
                    // tmp_topics_item->topic.data = start;
                    // tmp_topics_item->qos = *(p+1);

                    //pack len, fixed 2 bytes
                    tmp_size = p - start;
                    tmp_size2 = htons(tmp_size);
                    njt_memcpy(ctx->subscribe_pkt.data + pkt_off, &tmp_size2, 2uL);
                    pkt_off += 2;

                    //pack topic info
                    njt_memcpy(ctx->subscribe_pkt.data + pkt_off, start, p - start);
                    pkt_off += (p - start);

                    //pack qos
                    ctx->subscribe_pkt.data[pkt_off] = *(p+1);
                    pkt_off++;
                }else if(*p == ','){
                    start = p + 1;
                }
                p++;
            }
        }else{
            item = ctx->sub_topics.elts;
            for(i = 0; i < ctx->sub_topics.nelts; i++){
                //pack len, fixed 2 bytes
                tmp_size = item[i].topic.len;
                tmp_size2 = htons(tmp_size);
                njt_memcpy(ctx->subscribe_pkt.data + pkt_off, &tmp_size2, 2uL);
                pkt_off += 2;

                //pack topic info
                njt_memcpy(ctx->subscribe_pkt.data + pkt_off, item[i].topic.data, item[i].topic.len);
                pkt_off += item[i].topic.len;

                //pack qos
                ctx->subscribe_pkt.data[pkt_off] = item[i].qos;
                pkt_off++;
            }
        }
        
        ctx->out = njt_chain_get_free_buf(ctx->pool, &s->upstream->free);
        if (ctx->out == NULL) {
            njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                                "mqtt proxy send subscribe get free buff error");

            return NJT_ERROR;
        }

        ctx->out->buf->pos = ctx->subscribe_pkt.data;
        ctx->out->buf->last = ctx->subscribe_pkt.data + ctx->subscribe_pkt.len;
        ctx->out->buf->tag = (njt_buf_tag_t) &njt_stream_mqtt_proxy_module;

        ctx->out->buf->temporary = 1;
        ctx->out->buf->last_buf = 0;
        ctx->out->buf->flush = 1;
    }

    out = &ctx->out;
    busy = &ctx->busy;

    s->connection->log->action = "mqtt proxying and sending subscribe to upstream";

    rc = njt_stream_top_filter(s, *out, 0);
    if (rc == NJT_ERROR) {
        if(ctx->next_upstream_tries){
            //need reconnect new server
            return NJT_DECLINED;
        }else{
            njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_OK);
            return NJT_ERROR;
        }
    }

    njt_chain_update_chains(ctx->pool, &s->upstream->free, busy, out,
                        (njt_buf_tag_t) &njt_stream_mqtt_proxy_module);

    if(*busy){
        njt_log_error(NJT_LOG_DEBUG, s->connection->log, 0,
                "mqtt proxy send subscribe busy, state still is subscribe");
    }else{
        njt_log_error(NJT_LOG_DEBUG, s->connection->log, 0,
                "mqtt proxy send subscribe ok, set next state to recv suback");
        ctx->reconnect_state = STREAM_MQTT_PROXY_MQTT_RECONNECTE_RECV_SUBACK;
    }
    

    return NJT_OK;

has_no_subscribe:
    ctx->reconnect_state = STREAM_MQTT_PROXY_MQTT_RECONNECTE_OK;

    //reconnect success
    ctx->reconnecting = 0;

    if(kv_topics.len > 0){
        //del subscribe data, because has error
        njt_log_error(NJT_LOG_DEBUG, s->connection->log, 0,
                "mqtt proxy del subscribe info of kv, may has error");
        njt_stream_mqtt_proxy_del_subscribe_topics(&ctx->client_id);
    }

    return NJT_OK;
}


njt_uint_t
njt_stream_mqtt_reconnect_recv_connack(njt_stream_session_t *s, njt_connection_t *dst,
    njt_stream_mqtt_proxy_pkt_info_t *pkt_info, njt_stream_mqtt_proxy_ctx_t *ctx){
    njt_log_error(NJT_LOG_DEBUG, s->connection->log, 0, "mqtt proxy reconnect recv connack, next state send subscribe");

    njt_stream_mqtt_proxy_filter_connack_packet(1, s, ctx, pkt_info, s->connection->log);

    //just ignore this packet
    njt_stream_mqtt_client_pkt_info(pkt_info);

    //set state to send subsribe
    ctx->reconnect_state = STREAM_MQTT_PROXY_MQTT_RECONNECTE_SEND_SUBSCRIBE;

    return NJT_OK;
}

njt_uint_t
njt_stream_mqtt_reconnect_recv_suback(njt_stream_session_t *s, njt_connection_t *dst,
    njt_stream_mqtt_proxy_pkt_info_t *pkt_info, njt_stream_mqtt_proxy_ctx_t *ctx){
    njt_log_error(NJT_LOG_DEBUG, s->connection->log, 0, "mqtt proxy reconnect recv suback, reconnect ok");
    //just ignore this packet
    njt_stream_mqtt_client_pkt_info(pkt_info);
    
    ctx->reconnect_state = STREAM_MQTT_PROXY_MQTT_RECONNECTE_OK;

    //reconnect success
    ctx->reconnecting = 0;

    return NJT_OK;
}


static void
njt_stream_mqtt_proxy_reconnect_upstream(njt_stream_session_t *s, njt_stream_mqtt_proxy_ctx_t *ctx){
    //first clean current pc info
   njt_uint_t              state;
    njt_connection_t       *pc;
    njt_stream_upstream_t  *u;

    njt_log_error(NJT_LOG_DEBUG, s->connection->log, 0, "mqtt proxy reconnect upstream");

    u = s->upstream;

    if (u == NULL) {
        return;
    }

    if (u->resolved && u->resolved->ctx) {
        njt_resolve_name_done(u->resolved->ctx);
        u->resolved->ctx = NULL;
    }

    pc = u->peer.connection;

    if (u->state && pc) {
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

        u->connected = 0;
    }

    //set multi connect flag is 1
    ctx->multi_connect_server = 1;
    // ctx->connect_has_send = 0;
    // ctx->topic_has_send = 0;
    ctx->reconnecting = 1;
    ctx->reconnect_state = STREAM_MQTT_PROXY_MQTT_RECONNECTE_SEND_CONN;

    //init retry count and start time
    u->peer.tries = ctx->next_upstream_tries;
    u->peer.start_time = njt_current_msec;

    //clean out
    njt_stream_mqtt_proxy_chain_clean_chains(s->connection->pool, &s->upstream->free, &s->upstream->upstream_busy,
            &s->upstream->upstream_out,
            (njt_buf_tag_t) &njt_stream_mqtt_proxy_module);

    //proxy connect
    njt_stream_mqtt_proxy_next_upstream(s);
}


static void
njt_stream_mqtt_proxy_process(njt_stream_session_t *s, njt_uint_t from_upstream,
    njt_uint_t do_write)
{
    char                         *recv_action, *send_action;
    off_t                        *received, limit;
    // off_t                        *received;
    size_t                        size, limit_rate;
    // size_t                        size;
    ssize_t                       n = 0;
    njt_int_t                     rc;
    njt_uint_t                    flags, *packets;
    njt_msec_t                    delay;
    njt_chain_t                  *cl, **ll, **out, **busy;
    njt_connection_t             *c, *pc, *src, *dst;
    njt_log_handler_pt            handler;
    njt_stream_upstream_t        *u;
    njt_stream_mqtt_proxy_srv_conf_t  *pscf;
    njt_stream_mqtt_proxy_ctx_t       *ctx; // openresty patch
    njt_stream_mqtt_proxy_pkt_info_t *pkt_info;



    ctx = njt_stream_get_module_ctx(s, njt_stream_mqtt_proxy_module); // openresty patch

    u = s->upstream;

    c = s->connection;
    pc = u->connected ? u->peer.connection : NULL;

    if (c->type == SOCK_DGRAM && (njt_terminate || njt_exiting)) {

        /* socket is already closed on worker shutdown */

        handler = c->log->handler;
        c->log->handler = NULL;

        c->log->handler = handler;

        njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_OK);
        return;
    }

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_mqtt_proxy_module);

    if (from_upstream) {
        src = pc;
        dst = c;
        limit_rate = u->download_rate;
        received = &u->received;
        packets = &u->responses;
        out = &u->downstream_out;
        busy = &u->downstream_busy;
        pkt_info = &ctx->upstream_pkt;
        recv_action = "proxying and reading from upstream";
        send_action = "proxying and sending to client";

    } else {
        src = c;
        dst = pc;
        limit_rate = u->upload_rate;
        received = &s->received;
        packets = &u->requests;
        out = &u->upstream_out;
        busy = &u->upstream_busy;
        pkt_info = &ctx->downstream_pkt;
        recv_action = "proxying and reading from client";
        send_action = "proxying and sending to upstream";
    }

    for ( ;; ) {
        if(ctx->reconnecting && !from_upstream && pc){
            switch (ctx->reconnect_state)
            {
            case STREAM_MQTT_PROXY_MQTT_RECONNECTE_SEND_CONN:
                rc = njt_stream_mqtt_reconnect_send_conn(s, pc, ctx);
                if(NJT_DECLINED == rc){
                    njt_stream_mqtt_proxy_reconnect_upstream(s, ctx);
                }else if(NJT_ERROR == rc){
                    njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }
                break;
            case STREAM_MQTT_PROXY_MQTT_RECONNECTE_SEND_SUBSCRIBE:
                rc = njt_stream_mqtt_reconnect_send_subscribe(s, pc, ctx);
                if(NJT_DECLINED == rc){

                    njt_stream_mqtt_proxy_reconnect_upstream(s, ctx);
                }else if(NJT_ERROR == rc){
                    njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                break;

            default:
                break;
            } 
        }

        if(!from_upstream && ctx->reconnecting){
            //temp not send info
        }
        else{
            if (pkt_info->wait_send && dst) {
                if (*out || *busy || dst->buffered) {
                    c->log->action = send_action;

                    rc = njt_stream_top_filter(s, *out, from_upstream);
                    if (rc == NJT_ERROR) {
                        //todo if from_upstream, need try connect new server
                        //and first is send saved connect packet and all subscribe packet, then enter this process
                        if(!from_upstream && ctx->next_upstream_tries){
                            //need reconnect new server
                            njt_stream_mqtt_proxy_reconnect_upstream(s, ctx);
                            break;
                        }else{
                            njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_OK);
                            return;
                        }
                    }

                    njt_chain_update_chains(c->pool, &u->free, busy, out,
                                        (njt_buf_tag_t) &njt_stream_mqtt_proxy_module);

                    if(*busy){
                    }else{
                        njt_stream_mqtt_client_pkt_info(pkt_info);
                    }
                }
            }
        }

        switch (pkt_info->pkt_state)
        {
        case NJT_STREAM_MQTT_PROXY_PKT_WAIT_TYPE:
            size = 1;        //type is 1 byte
            break;
        case NJT_STREAM_MQTT_PROXY_PKT_WAIT_LEN:
            size = 1;        //len max 4 bytes, and higt bit is 1 means has next byte is len
            break;
        case NJT_STREAM_MQTT_PROXY_PKT_WAIT_DATA:
            size = pkt_info->cur_pkt_left_data_len;   //real pkt left data len, and will set later
            break;
        default:
            njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);

            njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                            "mqtt proxy packet state error");
            return;
        }

        if (size && src != NULL && src->read->ready && !src->read->delayed && !pkt_info->wait_send) {
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

            switch (pkt_info->pkt_state)
            {
            case NJT_STREAM_MQTT_PROXY_PKT_WAIT_TYPE:
                n = src->recv(src, pkt_info->head_buf, size);
                break;
            case NJT_STREAM_MQTT_PROXY_PKT_WAIT_LEN:
                n = src->recv(src, pkt_info->head_buf + 1 + pkt_info->head_len, size);
                break;
            case NJT_STREAM_MQTT_PROXY_PKT_WAIT_DATA:

                n = src->recv(src, pkt_info->pkt_data.data + pkt_info->pkt_data.len, size);
                if(n > 0){
                    pkt_info->pkt_data.len += n;
                }
                
                break;
            }
            

            if (n == NJT_AGAIN) {
                break;
            }

            if (n == NJT_ERROR) {
                src->read->eof = 1;
                n = 0;
            }

            if (n >= 0) {
                if (limit_rate) {
                    delay = (njt_msec_t) (n * 1000 / limit_rate);

                    if (delay > 0) {
                        src->read->delayed = 1;
                        njt_add_timer(src->read, delay);
                    }
                }

                (*packets)++;
                *received += n;

                if(n > 0){
                    //filter  data
                    if(NJT_OK != njt_stream_mqtt_proxy_parse_packet(from_upstream, s, ctx, pkt_info, n, c->log)){
                        njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                                        "mqtt proxy downstream packet parse error");
                        
                        njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);

                        return;
                    }
                }

                if (from_upstream) {
                    if (u->state->first_byte_time == (njt_msec_t) -1) {
                        u->state->first_byte_time = njt_current_msec
                                                    - u->start_time;
                    }
                }

                if(n > 0){
                    if(ctx->reconnecting && from_upstream && src && pkt_info->wait_send){
                        switch (ctx->reconnect_state)
                        {
                        case STREAM_MQTT_PROXY_MQTT_RECONNECTE_RECV_CONNACK:
                            if(NJT_OK != njt_stream_mqtt_reconnect_recv_connack(s, dst, pkt_info, ctx)){
                                njt_stream_mqtt_client_pkt_info(pkt_info);
                                njt_stream_mqtt_proxy_reconnect_upstream(s, ctx);
                            }

                            njt_stream_mqtt_client_pkt_info(pkt_info);
                            //send subscribe
                            rc = njt_stream_mqtt_reconnect_send_subscribe(s, pc, ctx);
                            if(NJT_DECLINED == rc){
                                njt_stream_mqtt_proxy_reconnect_upstream(s, ctx);
                            }else if(NJT_ERROR == rc){
                                njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
                                return;
                            }

                            break;
                        case STREAM_MQTT_PROXY_MQTT_RECONNECTE_RECV_SUBACK:
                            if(NJT_OK != njt_stream_mqtt_reconnect_recv_suback(s, dst, pkt_info, ctx)){
                                njt_stream_mqtt_client_pkt_info(pkt_info);
                                njt_stream_mqtt_proxy_reconnect_upstream(s, ctx);
                            }

                            njt_stream_mqtt_client_pkt_info(pkt_info);
                            break;

                        default:
                            break;
                        } 

                        continue;
                    }


                    if(pkt_info->wait_send){
                        //now need filter packet, such as save connect packet and subscribe packet, and so an
                        rc = njt_stream_mqtt_proxy_filter_packet(from_upstream, s, ctx, pkt_info, c->log);
                        //continue read client data,and ignore, because now is connectioning
                        if(NJT_AGAIN == rc){

                            continue;
                        }

                        //session has destroy, just return
                        if(NJT_DONE == rc){
                            return;
                        }

                        //in this case, first connect upstream
                        if(NJT_DECLINED == rc){
                            //need append to send queue, wait send conn pkt to upstream
                            for (ll = out; *ll; ll = &(*ll)->next) { /* void */ }

                            cl = njt_chain_get_free_buf(c->pool, &u->free);
                            if (cl == NULL) {
                                njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                                                    "mqtt proxy chain get buff error");

                                njt_stream_mqtt_proxy_finalize(s,
                                                        NJT_STREAM_INTERNAL_SERVER_ERROR);
                                return;
                            }

                            *ll = cl;

                            cl->buf->pos = pkt_info->pkt_data.data;
                            cl->buf->last = pkt_info->pkt_data.data + pkt_info->cur_pkt_head_len + pkt_info->cur_pkt_data_len;
                            cl->buf->tag = (njt_buf_tag_t) &njt_stream_mqtt_proxy_module;

                            cl->buf->temporary = (n ? 1 : 0);
                            cl->buf->last_buf = src->read->eof;
                            cl->buf->flush = !src->read->eof;

                            break;
                        }

                        if(NJT_OK != rc){
                            njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                                                "mqtt proxy filter packet error");

                            njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);

                            return;
                        }

                        for (ll = out; *ll; ll = &(*ll)->next) { /* void */ }

                        cl = njt_chain_get_free_buf(c->pool, &u->free);
                        if (cl == NULL) {
                            njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                                                "mqtt proxy chain get buff error");

                            njt_stream_mqtt_proxy_finalize(s,
                                                    NJT_STREAM_INTERNAL_SERVER_ERROR);
                            return;
                        }

                        *ll = cl;

                        cl->buf->pos = pkt_info->pkt_data.data;
                        cl->buf->last = pkt_info->pkt_data.data + pkt_info->cur_pkt_head_len + pkt_info->cur_pkt_data_len;
                        cl->buf->tag = (njt_buf_tag_t) &njt_stream_mqtt_proxy_module;

                        cl->buf->temporary = (n ? 1 : 0);
                        cl->buf->last_buf = src->read->eof;
                        cl->buf->flush = !src->read->eof;
                    }
                }else{
                    for (ll = out; *ll; ll = &(*ll)->next) { /* void */ }

                    cl = njt_chain_get_free_buf(c->pool, &u->free);
                    if (cl == NULL) {
                        njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                                                "mqtt proxy chain get buff error");
                        njt_stream_mqtt_proxy_finalize(s,
                                                NJT_STREAM_INTERNAL_SERVER_ERROR);
                        return;
                    }

                    *ll = cl;

                    cl->buf->pos = pkt_info->pkt_data.data;
                    cl->buf->last = pkt_info->pkt_data.data + n;
                    cl->buf->tag = (njt_buf_tag_t) &njt_stream_mqtt_proxy_module;

                    cl->buf->temporary = (n ? 1 : 0);
                    cl->buf->last_buf = src->read->eof;
                    cl->buf->flush = !src->read->eof;

                    pkt_info->wait_send = 1;

                    njt_log_error(NJT_LOG_DEBUG, s->connection->log, 0,
                                    "mqtt proxy recv is zero, now send last buf");
                }

                continue;
            }
        }

        break;
    }

    c->log->action = "proxying connection";

    if (njt_stream_mqtt_proxy_test_finalize(s, ctx, from_upstream) == NJT_OK) {
        return;
    }

    if(src == NULL || src->read == NULL) {
        njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                        "src or src->read is null");
        return;
    }
    flags = src->read->eof ? NJT_CLOSE_EVENT : 0;

    if(from_upstream && u->connected && ctx->next_upstream_tries){
        //if upstream, src is pc
        if (njt_handle_read_event(src->read, flags) != NJT_OK) {
            njt_stream_mqtt_proxy_reconnect_upstream(s, ctx);
            return;
        }
    }else{
        if (njt_handle_read_event(src->read, flags) != NJT_OK) {
            njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (dst) {
        if (dst->type == SOCK_STREAM && pscf->half_close
            && src != NULL &&  src->read->eof && !u->half_closed && !dst->buffered)
        {

            if (njt_shutdown_socket(dst->fd, NJT_WRITE_SHUTDOWN) == -1) {
                njt_connection_error(c, njt_socket_errno,
                                     njt_shutdown_socket_n " failed");
                if(!from_upstream && ctx->next_upstream_tries){
                    njt_stream_mqtt_proxy_reconnect_upstream(s, ctx);
                }else{
                    njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
                }
                
                return;
            }

            u->half_closed = 1;
            njt_log_debug1(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                           "stream proxy %s socket shutdown",
                           from_upstream ? "client" : "upstream");
        }

        if (njt_handle_write_event(dst->write, 0) != NJT_OK) {
            if(!from_upstream && ctx->next_upstream_tries){
                njt_stream_mqtt_proxy_reconnect_upstream(s, ctx);
            }else{
                njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
            }
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
njt_stream_mqtt_proxy_test_finalize(njt_stream_session_t *s, njt_stream_mqtt_proxy_ctx_t *ctx,
    njt_uint_t from_upstream)
{
    njt_connection_t             *c, *pc;
    njt_log_handler_pt            handler;
    njt_stream_upstream_t        *u;
    njt_stream_mqtt_proxy_srv_conf_t  *pscf;

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_mqtt_proxy_module);

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

        njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_OK);

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

    if(c->read->eof){
        njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_OK);
    }else if(pc != NULL && pc->read->eof && ctx->next_upstream_tries){
        njt_stream_mqtt_proxy_reconnect_upstream(s, ctx);
    }else{
        njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_OK);
    }

    return NJT_OK;
}


static void
njt_stream_mqtt_proxy_next_upstream(njt_stream_session_t *s)
{
    njt_msec_t                    timeout;
    njt_connection_t             *pc;
    njt_stream_upstream_t        *u;
    njt_stream_mqtt_proxy_srv_conf_t  *pscf;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream proxy next upstream");

    u = s->upstream;
    pc = u->peer.connection;

    if (pc && pc->buffered) {
        njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                      "buffered data on next upstream");
        njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (s->connection->type == SOCK_DGRAM) {
        u->upstream_out = NULL;
    }

    if (u->peer.sockaddr) {
        u->peer.free(&u->peer, u->peer.data, NJT_PEER_FAILED);
        u->peer.sockaddr = NULL;
    }

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_mqtt_proxy_module);

    timeout = pscf->next_upstream_timeout;

    if (u->peer.tries == 0
        || !pscf->next_upstream
        || (timeout && njt_current_msec - u->peer.start_time >= timeout))
    {
        njt_stream_mqtt_proxy_finalize(s, NJT_STREAM_BAD_GATEWAY);
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

    njt_stream_mqtt_proxy_connect(s);
}


static void
njt_stream_mqtt_proxy_finalize(njt_stream_session_t *s, njt_uint_t rc)
{
    njt_uint_t              state;
    njt_connection_t       *pc;
    njt_stream_upstream_t  *u;
    njt_stream_mqtt_proxy_ctx_t       *ctx;

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

    ctx = njt_stream_get_module_ctx(s, njt_stream_mqtt_proxy_module);
    if(ctx != NULL){
        //if has connect clean session info, need clean kv data
        if(ctx->client_id.len > 0 && ctx->clean_session){
            njt_stream_mqtt_proxy_del_subscribe_topics(&ctx->client_id);
            njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                      "mqtt proxy, cliendid:%V need clean seesion, clean kv data", &ctx->client_id);
        }
    }
    njt_stream_finalize_session(s, rc);
}


static u_char *
njt_stream_mqtt_proxy_log_error(njt_log_t *log, u_char *buf, size_t len)
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
njt_stream_mqtt_proxy_create_srv_conf(njt_conf_t *cf)
{
    njt_stream_mqtt_proxy_srv_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_stream_mqtt_proxy_srv_conf_t));
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
njt_stream_mqtt_proxy_merge_srv_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_stream_mqtt_proxy_srv_conf_t *prev = parent;
    njt_stream_mqtt_proxy_srv_conf_t *conf = child;

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

    if (njt_stream_mqtt_proxy_merge_ssl(cf, conf, prev) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    njt_conf_merge_value(conf->ssl_enable, prev->ssl_enable, 0);

    njt_conf_merge_value(conf->ssl_session_reuse,
                              prev->ssl_session_reuse, 1);

    njt_conf_merge_bitmask_value(conf->ssl_protocols, prev->ssl_protocols,
                            (NJT_CONF_BITMASK_SET|NJT_SSL_DEFAULT_PROTOCOLS));

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
    if (conf->ssl_enable && njt_stream_mqtt_proxy_set_ssl(cf, conf) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

#endif

    return NJT_CONF_OK;
}


#if (NJT_STREAM_SSL)

static njt_int_t
njt_stream_mqtt_proxy_merge_ssl(njt_conf_t *cf, njt_stream_mqtt_proxy_srv_conf_t *conf,
    njt_stream_mqtt_proxy_srv_conf_t *prev)
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
njt_stream_mqtt_proxy_set_ssl(njt_conf_t *cf, njt_stream_mqtt_proxy_srv_conf_t *pscf)
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
        njt_stream_ssl_srv_conf_t  sscf;

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

        njt_memzero(&sscf, sizeof(njt_stream_ssl_srv_conf_t));

        sscf.certificates = pscf->ssl_certificates;
        sscf.certificate_keys = pscf->ssl_certificate_keys;
        sscf.passwords = pscf->ssl_passwords;

        if (njt_stream_ssl_compile_certificates(cf, &sscf) != NJT_OK) {
            return NJT_ERROR;
        }
        pscf->ssl_passwords = sscf.passwords;
        pscf->ssl_certificate_values = sscf.certificate_values;
        pscf->ssl_certificate_key_values = sscf.certificate_key_values;

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
njt_stream_mqtt_proxy_pass(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_mqtt_proxy_srv_conf_t *pscf = conf;

    njt_url_t                            u;
    njt_str_t                           *value, *url;
    njt_stream_complex_value_t           cv;
    njt_stream_core_srv_conf_t          *cscf;
    njt_stream_compile_complex_value_t   ccv;

    if (pscf->upstream || pscf->upstream_value) {
        return "is duplicate";
    }

    cscf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_core_module);

    cscf->handler = njt_stream_mqtt_proxy_handler;

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
njt_stream_mqtt_proxy_bind(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_stream_mqtt_proxy_srv_conf_t *pscf = conf;

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



#if (NJT_HAVE_SET_ALPN)
static char *
njt_stream_mqtt_proxy_ssl_alpn(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation

    njt_stream_mqtt_proxy_srv_conf_t  *scf = conf;

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
njt_stream_mqtt_proxy_get_next_upstream_tries(njt_stream_session_t *s)
{
    njt_stream_mqtt_proxy_srv_conf_t      *pscf;

    pscf = njt_stream_get_module_srv_conf(s, njt_stream_mqtt_proxy_module);

    return pscf->next_upstream_tries;
}

// openresty patch end