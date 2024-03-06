
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


static njt_int_t njt_http_v3_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_v3_add_variables(njt_conf_t *cf);
static void *njt_http_v3_create_srv_conf(njt_conf_t *cf);
static char *njt_http_v3_merge_srv_conf(njt_conf_t *cf, void *parent,
    void *child);
static char *njt_http_quic_host_key(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);


static njt_command_t  njt_http_v3_commands[] = {

    { njt_string("http3"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_v3_srv_conf_t, enable),
      NULL },

    { njt_string("http3_hq"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_v3_srv_conf_t, enable_hq),
      NULL },

    { njt_string("http3_max_concurrent_streams"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_v3_srv_conf_t, max_concurrent_streams),
      NULL },

    { njt_string("http3_stream_buffer_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_v3_srv_conf_t, quic.stream_buffer_size),
      NULL },

    { njt_string("quic_retry"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_v3_srv_conf_t, quic.retry),
      NULL },

    { njt_string("quic_gso"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_v3_srv_conf_t, quic.gso_enabled),
      NULL },

    { njt_string("quic_host_key"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_http_quic_host_key,
      NJT_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("quic_active_connection_id_limit"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_v3_srv_conf_t, quic.active_connection_id_limit),
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_v3_module_ctx = {
    njt_http_v3_add_variables,             /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    njt_http_v3_create_srv_conf,           /* create server configuration */
    njt_http_v3_merge_srv_conf,            /* merge server configuration */

    NULL,
    NULL
};


njt_module_t  njt_http_v3_module = {
    NJT_MODULE_V1,
    &njt_http_v3_module_ctx,               /* module context */
    njt_http_v3_commands,                  /* module directives */
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



static njt_http_variable_t  njt_http_v3_vars[] = {

    { njt_string("http3"), NULL, njt_http_v3_variable, 0, 0, 0, 0 },

      njt_http_null_variable
};

static njt_str_t  njt_http_quic_salt = njt_string("njt_quic");


static njt_int_t
njt_http_v3_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_http_v3_session_t  *h3c;

    if (r->connection->quic) {
        h3c = njt_http_v3_get_session(r->connection);

        if (h3c->hq) {
            v->len = sizeof("hq") - 1;
            v->valid = 1;
            v->no_cacheable = 0;
            v->not_found = 0;
            v->data = (u_char *) "hq";

            return NJT_OK;
        }

        v->len = sizeof("h3") - 1;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (u_char *) "h3";

        return NJT_OK;
    }

    *v = njt_http_variable_null_value;

    return NJT_OK;
}


static njt_int_t
njt_http_v3_add_variables(njt_conf_t *cf)
{
    njt_http_variable_t  *var, *v;

    for (v = njt_http_v3_vars; v->name.len; v++) {
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
njt_http_v3_create_srv_conf(njt_conf_t *cf)
{
    njt_http_v3_srv_conf_t  *h3scf;

    h3scf = njt_pcalloc(cf->pool, sizeof(njt_http_v3_srv_conf_t));
    if (h3scf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     h3scf->quic.host_key = { 0, NULL }
     *     h3scf->quic.stream_reject_code_uni = 0;
     *     h3scf->quic.disable_active_migration = 0;
     *     h3scf->quic.idle_timeout = 0;
     *     h3scf->max_blocked_streams = 0;
     */

    h3scf->enable = NJT_CONF_UNSET;
    h3scf->enable_hq = NJT_CONF_UNSET;
    h3scf->max_table_capacity = NJT_HTTP_V3_MAX_TABLE_CAPACITY;
    h3scf->max_concurrent_streams = NJT_CONF_UNSET_UINT;

    h3scf->quic.stream_buffer_size = NJT_CONF_UNSET_SIZE;
    h3scf->quic.max_concurrent_streams_bidi = NJT_CONF_UNSET_UINT;
    h3scf->quic.max_concurrent_streams_uni = NJT_HTTP_V3_MAX_UNI_STREAMS;
    h3scf->quic.retry = NJT_CONF_UNSET;
    h3scf->quic.gso_enabled = NJT_CONF_UNSET;
    h3scf->quic.stream_close_code = NJT_HTTP_V3_ERR_NO_ERROR;
    h3scf->quic.stream_reject_code_bidi = NJT_HTTP_V3_ERR_REQUEST_REJECTED;
    h3scf->quic.active_connection_id_limit = NJT_CONF_UNSET_UINT;

    h3scf->quic.init = njt_http_v3_init;
    h3scf->quic.shutdown = njt_http_v3_shutdown;

    return h3scf;
}


static char *
njt_http_v3_merge_srv_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_v3_srv_conf_t *prev = parent;
    njt_http_v3_srv_conf_t *conf = child;

    njt_http_ssl_srv_conf_t   *sscf;
    njt_http_core_srv_conf_t  *cscf;

    njt_conf_merge_value(conf->enable, prev->enable, 1);

    njt_conf_merge_value(conf->enable_hq, prev->enable_hq, 0);

    njt_conf_merge_uint_value(conf->max_concurrent_streams,
                              prev->max_concurrent_streams, 128);

    conf->max_blocked_streams = conf->max_concurrent_streams;

    njt_conf_merge_size_value(conf->quic.stream_buffer_size,
                              prev->quic.stream_buffer_size,
                              65536);

    conf->quic.max_concurrent_streams_bidi = conf->max_concurrent_streams;

    njt_conf_merge_value(conf->quic.retry, prev->quic.retry, 0);
    njt_conf_merge_value(conf->quic.gso_enabled, prev->quic.gso_enabled, 0);

    njt_conf_merge_str_value(conf->quic.host_key, prev->quic.host_key, "");

    njt_conf_merge_uint_value(conf->quic.active_connection_id_limit,
                              prev->quic.active_connection_id_limit,
                              2);

    if (conf->quic.host_key.len == 0) {

        conf->quic.host_key.len = NJT_QUIC_DEFAULT_HOST_KEY_LEN;
        conf->quic.host_key.data = njt_palloc(cf->pool,
                                              conf->quic.host_key.len);
        if (conf->quic.host_key.data == NULL) {
            return NJT_CONF_ERROR;
        }

        if (RAND_bytes(conf->quic.host_key.data, NJT_QUIC_DEFAULT_HOST_KEY_LEN)
            <= 0)
        {
            return NJT_CONF_ERROR;
        }
    }

    if (njt_quic_derive_key(cf->log, "av_token_key",
                            &conf->quic.host_key, &njt_http_quic_salt,
                            conf->quic.av_token_key, NJT_QUIC_AV_KEY_LEN)
        != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    if (njt_quic_derive_key(cf->log, "sr_token_key",
                            &conf->quic.host_key, &njt_http_quic_salt,
                            conf->quic.sr_token_key, NJT_QUIC_SR_KEY_LEN)
        != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    cscf = njt_http_conf_get_module_srv_conf(cf, njt_http_core_module);
    conf->quic.handshake_timeout = cscf->client_header_timeout;

    sscf = njt_http_conf_get_module_srv_conf(cf, njt_http_ssl_module);
    conf->quic.ssl = &sscf->ssl;

    return NJT_CONF_OK;
}


static char *
njt_http_quic_host_key(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_v3_srv_conf_t  *h3scf = conf;

    u_char           *buf;
    size_t            size;
    ssize_t           n;
    njt_str_t        *value;
    njt_file_t        file;
    njt_file_info_t   fi;
    njt_quic_conf_t  *qcf;

    qcf = &h3scf->quic;

    if (qcf->host_key.len) {
        return "is duplicate";
    }

    buf = NULL;
#if (NJT_SUPPRESS_WARN)
    size = 0;
#endif

    value = cf->args->elts;

    if (njt_conf_full_name(cf->cycle, &value[1], 1) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    njt_memzero(&file, sizeof(njt_file_t));
    file.name = value[1];
    file.log = cf->log;

    file.fd = njt_open_file(file.name.data, NJT_FILE_RDONLY, NJT_FILE_OPEN, 0);

    if (file.fd == NJT_INVALID_FILE) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, njt_errno,
                           njt_open_file_n " \"%V\" failed", &file.name);
        return NJT_CONF_ERROR;
    }

    if (njt_fd_info(file.fd, &fi) == NJT_FILE_ERROR) {
        njt_conf_log_error(NJT_LOG_CRIT, cf, njt_errno,
                           njt_fd_info_n " \"%V\" failed", &file.name);
        goto failed;
    }

    size = njt_file_size(&fi);

    if (size == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "\"%V\" zero key size", &file.name);
        goto failed;
    }

    buf = njt_pnalloc(cf->pool, size);
    if (buf == NULL) {
        goto failed;
    }

    n = njt_read_file(&file, buf, size, 0);

    if (n == NJT_ERROR) {
        njt_conf_log_error(NJT_LOG_CRIT, cf, njt_errno,
                           njt_read_file_n " \"%V\" failed", &file.name);
        goto failed;
    }

    if ((size_t) n != size) {
        njt_conf_log_error(NJT_LOG_CRIT, cf, 0,
                           njt_read_file_n " \"%V\" returned only "
                           "%z bytes instead of %uz", &file.name, n, size);
        goto failed;
    }

    qcf->host_key.data = buf;
    qcf->host_key.len = n;

    if (njt_close_file(file.fd) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_ALERT, cf->log, njt_errno,
                      njt_close_file_n " \"%V\" failed", &file.name);
    }

    return NJT_CONF_OK;

failed:

    if (njt_close_file(file.fd) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_ALERT, cf->log, njt_errno,
                      njt_close_file_n " \"%V\" failed", &file.name);
    }

    if (buf) {
        njt_explicit_memzero(buf, size);
    }

    return NJT_CONF_ERROR;
}