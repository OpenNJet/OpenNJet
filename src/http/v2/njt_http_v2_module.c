
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 * Copyright (C) Valentin V. Bartenev
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_http_v2_module.h>


static njt_int_t njt_http_v2_add_variables(njt_conf_t *cf);

static njt_int_t njt_http_v2_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);

static njt_int_t njt_http_v2_module_init(njt_cycle_t *cycle);

static void *njt_http_v2_create_main_conf(njt_conf_t *cf);
static char *njt_http_v2_init_main_conf(njt_conf_t *cf, void *conf);
static void *njt_http_v2_create_srv_conf(njt_conf_t *cf);
static char *njt_http_v2_merge_srv_conf(njt_conf_t *cf, void *parent,
    void *child);
static void *njt_http_v2_create_loc_conf(njt_conf_t *cf);
static char *njt_http_v2_merge_loc_conf(njt_conf_t *cf, void *parent,
    void *child);

static char *njt_http_v2_recv_buffer_size(njt_conf_t *cf, void *post,
    void *data);
static char *njt_http_v2_pool_size(njt_conf_t *cf, void *post, void *data);
static char *njt_http_v2_preread_size(njt_conf_t *cf, void *post, void *data);
static char *njt_http_v2_streams_index_mask(njt_conf_t *cf, void *post,
    void *data);
static char *njt_http_v2_chunk_size(njt_conf_t *cf, void *post, void *data);
static char *njt_http_v2_obsolete(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);


static njt_conf_deprecated_t  njt_http_v2_recv_timeout_deprecated = {
    njt_conf_deprecated, "http2_recv_timeout", "client_header_timeout"
};

static njt_conf_deprecated_t  njt_http_v2_idle_timeout_deprecated = {
    njt_conf_deprecated, "http2_idle_timeout", "keepalive_timeout"
};

static njt_conf_deprecated_t  njt_http_v2_max_requests_deprecated = {
    njt_conf_deprecated, "http2_max_requests", "keepalive_requests"
};

static njt_conf_deprecated_t  njt_http_v2_max_field_size_deprecated = {
    njt_conf_deprecated, "http2_max_field_size", "large_client_header_buffers"
};

static njt_conf_deprecated_t  njt_http_v2_max_header_size_deprecated = {
    njt_conf_deprecated, "http2_max_header_size", "large_client_header_buffers"
};


static njt_conf_post_t  njt_http_v2_recv_buffer_size_post =
    { njt_http_v2_recv_buffer_size };
static njt_conf_post_t  njt_http_v2_pool_size_post =
    { njt_http_v2_pool_size };
static njt_conf_post_t  njt_http_v2_preread_size_post =
    { njt_http_v2_preread_size };
static njt_conf_post_t  njt_http_v2_streams_index_mask_post =
    { njt_http_v2_streams_index_mask };
static njt_conf_post_t  njt_http_v2_chunk_size_post =
    { njt_http_v2_chunk_size };


static njt_command_t  njt_http_v2_commands[] = {

    { njt_string("http2"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_v2_srv_conf_t, enable),
      NULL },

    { njt_string("http2_recv_buffer_size"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_MAIN_CONF_OFFSET,
      offsetof(njt_http_v2_main_conf_t, recv_buffer_size),
      &njt_http_v2_recv_buffer_size_post },

    { njt_string("http2_pool_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_v2_srv_conf_t, pool_size),
      &njt_http_v2_pool_size_post },

    { njt_string("http2_max_concurrent_streams"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_v2_srv_conf_t, concurrent_streams),
      NULL },

    { njt_string("http2_max_concurrent_pushes"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_http_v2_obsolete,
      0,
      0,
      NULL },

    { njt_string("http2_max_requests"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_http_v2_obsolete,
      0,
      0,
      &njt_http_v2_max_requests_deprecated },

    { njt_string("http2_max_field_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_http_v2_obsolete,
      0,
      0,
      &njt_http_v2_max_field_size_deprecated },

    { njt_string("http2_max_header_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_http_v2_obsolete,
      0,
      0,
      &njt_http_v2_max_header_size_deprecated },

    { njt_string("http2_body_preread_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_v2_srv_conf_t, preread_size),
      &njt_http_v2_preread_size_post },

    { njt_string("http2_streams_index_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_v2_srv_conf_t, streams_index_mask),
      &njt_http_v2_streams_index_mask_post },

    { njt_string("http2_recv_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_http_v2_obsolete,
      0,
      0,
      &njt_http_v2_recv_timeout_deprecated },

    { njt_string("http2_idle_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_http_v2_obsolete,
      0,
      0,
      &njt_http_v2_idle_timeout_deprecated },

    { njt_string("http2_chunk_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_v2_loc_conf_t, chunk_size),
      &njt_http_v2_chunk_size_post },

    { njt_string("http2_push_preload"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_http_v2_obsolete,
      0,
      0,
      NULL },

    { njt_string("http2_push"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_v2_obsolete,
      0,
      0,
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_v2_module_ctx = {
    njt_http_v2_add_variables,             /* preconfiguration */
    NULL,                                  /* postconfiguration */

    njt_http_v2_create_main_conf,          /* create main configuration */
    njt_http_v2_init_main_conf,            /* init main configuration */

    njt_http_v2_create_srv_conf,           /* create server configuration */
    njt_http_v2_merge_srv_conf,            /* merge server configuration */

    njt_http_v2_create_loc_conf,           /* create location configuration */
    njt_http_v2_merge_loc_conf             /* merge location configuration */
};


njt_module_t  njt_http_v2_module = {
    NJT_MODULE_V1,
    &njt_http_v2_module_ctx,               /* module context */
    njt_http_v2_commands,                  /* module directives */
    NJT_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    njt_http_v2_module_init,               /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_http_variable_t  njt_http_v2_vars[] = {

    { njt_string("http2"), NULL,
      njt_http_v2_variable, 0, 0, 0, NJT_VAR_INIT_REF_COUNT },

      njt_http_null_variable
};


static njt_int_t
njt_http_v2_add_variables(njt_conf_t *cf)
{
    njt_http_variable_t  *var, *v;

    for (v = njt_http_v2_vars; v->name.len; v++) {
        var = njt_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NJT_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_v2_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{

    if (r->stream) {
#if (NJT_HTTP_SSL)

        if (r->connection->ssl) {
            v->len = sizeof("h2") - 1;
            v->valid = 1;
            v->no_cacheable = 0;
            v->not_found = 0;
            v->data = (u_char *) "h2";

            return NJT_OK;
        }

#endif
        v->len = sizeof("h2c") - 1;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (u_char *) "h2c";

        return NJT_OK;
    }

    *v = njt_http_variable_null_value;

    return NJT_OK;
}


static njt_int_t
njt_http_v2_module_init(njt_cycle_t *cycle)
{
    return NJT_OK;
}


static void *
njt_http_v2_create_main_conf(njt_conf_t *cf)
{
    njt_http_v2_main_conf_t  *h2mcf;

    h2mcf = njt_pcalloc(cf->pool, sizeof(njt_http_v2_main_conf_t));
    if (h2mcf == NULL) {
        return NULL;
    }

    h2mcf->recv_buffer_size = NJT_CONF_UNSET_SIZE;

    return h2mcf;
}


static char *
njt_http_v2_init_main_conf(njt_conf_t *cf, void *conf)
{
    njt_http_v2_main_conf_t *h2mcf = conf;

    njt_conf_init_size_value(h2mcf->recv_buffer_size, 256 * 1024);

    return NJT_CONF_OK;
}


static void *
njt_http_v2_create_srv_conf(njt_conf_t *cf)
{
    njt_http_v2_srv_conf_t  *h2scf;

    h2scf = njt_pcalloc(cf->pool, sizeof(njt_http_v2_srv_conf_t));
    if (h2scf == NULL) {
        return NULL;
    }

    h2scf->enable = NJT_CONF_UNSET;

    h2scf->pool_size = NJT_CONF_UNSET_SIZE;

    h2scf->concurrent_streams = NJT_CONF_UNSET_UINT;

    h2scf->preread_size = NJT_CONF_UNSET_SIZE;

    h2scf->streams_index_mask = NJT_CONF_UNSET_UINT;

    return h2scf;
}


static char *
njt_http_v2_merge_srv_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_v2_srv_conf_t *prev = parent;
    njt_http_v2_srv_conf_t *conf = child;

    njt_conf_merge_value(conf->enable, prev->enable, 0);

    njt_conf_merge_size_value(conf->pool_size, prev->pool_size, 4096);

    njt_conf_merge_uint_value(conf->concurrent_streams,
                              prev->concurrent_streams, 128);

    njt_conf_merge_size_value(conf->preread_size, prev->preread_size, 65536);

    njt_conf_merge_uint_value(conf->streams_index_mask,
                              prev->streams_index_mask, 32 - 1);

    return NJT_CONF_OK;
}


static void *
njt_http_v2_create_loc_conf(njt_conf_t *cf)
{
    njt_http_v2_loc_conf_t  *h2lcf;

    h2lcf = njt_pcalloc(cf->pool, sizeof(njt_http_v2_loc_conf_t));
    if (h2lcf == NULL) {
        return NULL;
    }

    h2lcf->chunk_size = NJT_CONF_UNSET_SIZE;

    return h2lcf;
}


static char *
njt_http_v2_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_v2_loc_conf_t *prev = parent;
    njt_http_v2_loc_conf_t *conf = child;

    njt_conf_merge_size_value(conf->chunk_size, prev->chunk_size, 8 * 1024);

    return NJT_CONF_OK;
}


static char *
njt_http_v2_recv_buffer_size(njt_conf_t *cf, void *post, void *data)
{
    size_t *sp = data;

    if (*sp <= NJT_HTTP_V2_STATE_BUFFER_SIZE) {
        return "value is too small";
    }

    return NJT_CONF_OK;
}


static char *
njt_http_v2_pool_size(njt_conf_t *cf, void *post, void *data)
{
    size_t *sp = data;

    if (*sp < NJT_MIN_POOL_SIZE) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "the pool size must be no less than %uz",
                           NJT_MIN_POOL_SIZE);

        return NJT_CONF_ERROR;
    }

    if (*sp % NJT_POOL_ALIGNMENT) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "the pool size must be a multiple of %uz",
                           NJT_POOL_ALIGNMENT);

        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static char *
njt_http_v2_preread_size(njt_conf_t *cf, void *post, void *data)
{
    size_t *sp = data;

    if (*sp > NJT_HTTP_V2_MAX_WINDOW) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "the maximum body preread buffer size is %uz",
                           NJT_HTTP_V2_MAX_WINDOW);

        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static char *
njt_http_v2_streams_index_mask(njt_conf_t *cf, void *post, void *data)
{
    njt_uint_t *np = data;

    njt_uint_t  mask;

    mask = *np - 1;

    if (*np == 0 || (*np & mask)) {
        return "must be a power of two";
    }

    *np = mask;

    return NJT_CONF_OK;
}


static char *
njt_http_v2_chunk_size(njt_conf_t *cf, void *post, void *data)
{
    size_t *sp = data;

    if (*sp == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "the http2 chunk size cannot be zero");

        return NJT_CONF_ERROR;
    }

    if (*sp > NJT_HTTP_V2_MAX_FRAME_SIZE) {
        *sp = NJT_HTTP_V2_MAX_FRAME_SIZE;
    }

    return NJT_CONF_OK;
}


static char *
njt_http_v2_obsolete(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_conf_deprecated_t  *d = cmd->post;

    if (d) {
        njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                           "the \"%s\" directive is obsolete, "
                           "use the \"%s\" directive instead",
                           d->old_name, d->new_name);

    } else {
        njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                           "the \"%V\" directive is obsolete, ignored",
                           &cmd->name);
    }

    return NJT_CONF_OK;
}
