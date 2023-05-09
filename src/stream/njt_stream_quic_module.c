
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>


static njt_int_t njt_stream_variable_quic(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_quic_add_variables(njt_conf_t *cf);
static void *njt_stream_quic_create_srv_conf(njt_conf_t *cf);
static char *njt_stream_quic_merge_srv_conf(njt_conf_t *cf, void *parent,
    void *child);
static char *njt_stream_quic_mtu(njt_conf_t *cf, void *post, void *data);
static char *njt_stream_quic_host_key(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);

static njt_conf_post_t  njt_stream_quic_mtu_post =
    { njt_stream_quic_mtu };

static njt_command_t  njt_stream_quic_commands[] = {

    { njt_string("quic_timeout"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_quic_conf_t, timeout),
      NULL },

    { njt_string("quic_mtu"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_quic_conf_t, mtu),
      &njt_stream_quic_mtu_post },

    { njt_string("quic_stream_buffer_size"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_quic_conf_t, stream_buffer_size),
      NULL },

    { njt_string("quic_retry"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_quic_conf_t, retry),
      NULL },

    { njt_string("quic_gso"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_quic_conf_t, gso_enabled),
      NULL },

    { njt_string("quic_host_key"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_stream_quic_host_key,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("quic_active_connection_id_limit"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_quic_conf_t, active_connection_id_limit),
      NULL },

      njt_null_command
};


static njt_stream_module_t  njt_stream_quic_module_ctx = {
    njt_stream_quic_add_variables,         /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    njt_stream_quic_create_srv_conf,       /* create server configuration */
    njt_stream_quic_merge_srv_conf,        /* merge server configuration */
};


njt_module_t  njt_stream_quic_module = {
    NJT_MODULE_V1,
    &njt_stream_quic_module_ctx,           /* module context */
    njt_stream_quic_commands,              /* module directives */
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


static njt_stream_variable_t  njt_stream_quic_vars[] = {

    { njt_string("quic"), NULL, njt_stream_variable_quic, 0, 0, 0 },

      njt_stream_null_variable
};

static njt_str_t  njt_stream_quic_salt = njt_string("njt_quic");


static njt_int_t
njt_stream_variable_quic(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    if (s->connection->quic) {

        v->len = 4;
        v->valid = 1;
        v->no_cacheable = 1;
        v->not_found = 0;
        v->data = (u_char *) "quic";
        return NJT_OK;
    }

    v->not_found = 1;

    return NJT_OK;
}


static njt_int_t
njt_stream_quic_add_variables(njt_conf_t *cf)
{
    njt_stream_variable_t  *var, *v;

    for (v = njt_stream_quic_vars; v->name.len; v++) {
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
njt_stream_quic_create_srv_conf(njt_conf_t *cf)
{
    njt_quic_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_quic_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->host_key = { 0, NULL }
     *     conf->stream_close_code = 0;
     *     conf->stream_reject_code_uni = 0;
     *     conf->stream_reject_code_bidi= 0;
     */

    conf->timeout = NJT_CONF_UNSET_MSEC;
    conf->mtu = NJT_CONF_UNSET_SIZE;
    conf->stream_buffer_size = NJT_CONF_UNSET_SIZE;
    conf->max_concurrent_streams_bidi = NJT_CONF_UNSET_UINT;
    conf->max_concurrent_streams_uni = NJT_CONF_UNSET_UINT;

    conf->retry = NJT_CONF_UNSET;
    conf->gso_enabled = NJT_CONF_UNSET;

    conf->active_connection_id_limit = NJT_CONF_UNSET_UINT;

    return conf;
}


static char *
njt_stream_quic_merge_srv_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_quic_conf_t *prev = parent;
    njt_quic_conf_t *conf = child;

    njt_stream_ssl_conf_t  *scf;

    njt_conf_merge_msec_value(conf->timeout, prev->timeout, 60000);

    njt_conf_merge_size_value(conf->mtu, prev->mtu,
                              NJT_QUIC_MAX_UDP_PAYLOAD_SIZE);

    njt_conf_merge_size_value(conf->stream_buffer_size,
                              prev->stream_buffer_size,
                              65536);

    njt_conf_merge_uint_value(conf->max_concurrent_streams_bidi,
                              prev->max_concurrent_streams_bidi, 16);

    njt_conf_merge_uint_value(conf->max_concurrent_streams_uni,
                              prev->max_concurrent_streams_uni, 3);

    njt_conf_merge_value(conf->retry, prev->retry, 0);
    njt_conf_merge_value(conf->gso_enabled, prev->gso_enabled, 0);

    njt_conf_merge_str_value(conf->host_key, prev->host_key, "");

    njt_conf_merge_uint_value(conf->active_connection_id_limit,
                              conf->active_connection_id_limit,
                              2);

    if (conf->host_key.len == 0) {

        conf->host_key.len = NJT_QUIC_DEFAULT_HOST_KEY_LEN;
        conf->host_key.data = njt_palloc(cf->pool, conf->host_key.len);
        if (conf->host_key.data == NULL) {
            return NJT_CONF_ERROR;
        }

        if (RAND_bytes(conf->host_key.data, NJT_QUIC_DEFAULT_HOST_KEY_LEN)
            <= 0)
        {
            return NJT_CONF_ERROR;
        }
    }

    if (njt_quic_derive_key(cf->log, "av_token_key",
                            &conf->host_key, &njt_stream_quic_salt,
                            conf->av_token_key, NJT_QUIC_AV_KEY_LEN)
        != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    if (njt_quic_derive_key(cf->log, "sr_token_key",
                            &conf->host_key, &njt_stream_quic_salt,
                            conf->sr_token_key, NJT_QUIC_SR_KEY_LEN)
        != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    scf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_ssl_module);
    conf->ssl = &scf->ssl;

    return NJT_CONF_OK;
}


static char *
njt_stream_quic_mtu(njt_conf_t *cf, void *post, void *data)
{
    size_t *sp = data;

    if (*sp < NJT_QUIC_MIN_INITIAL_SIZE
        || *sp > NJT_QUIC_MAX_UDP_PAYLOAD_SIZE)
    {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "\"quic_mtu\" must be between %d and %d",
                           NJT_QUIC_MIN_INITIAL_SIZE,
                           NJT_QUIC_MAX_UDP_PAYLOAD_SIZE);

        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static char *
njt_stream_quic_host_key(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_quic_conf_t  *qcf = conf;

    u_char           *buf;
    size_t            size;
    ssize_t           n;
    njt_str_t        *value;
    njt_file_t        file;
    njt_file_info_t   fi;

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
