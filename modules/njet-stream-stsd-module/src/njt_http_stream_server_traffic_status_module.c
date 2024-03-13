
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#include <njt_config.h>

#include "njt_http_stream_server_traffic_status_module.h"
#include "njt_http_stream_server_traffic_status_display.h"


static char *njt_http_stream_server_traffic_status_zone(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);
static char *njt_http_stream_server_traffic_status_average_method(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);

static void *njt_http_stream_server_traffic_status_create_main_conf(njt_conf_t *cf);
static char *njt_http_stream_server_traffic_status_init_main_conf(njt_conf_t *cf,
    void *conf);
static void *njt_http_stream_server_traffic_status_create_loc_conf(njt_conf_t *cf);
static char *njt_http_stream_server_traffic_status_merge_loc_conf(njt_conf_t *cf,
    void *parent, void *child);


static njt_conf_enum_t  njt_http_stream_server_traffic_status_display_format[] = {
    { njt_string("json"), NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_FORMAT_JSON },
    { njt_string("html"), NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_FORMAT_HTML },
    { njt_string("jsonp"), NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_FORMAT_JSONP },
    { njt_string("prometheus"), NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_FORMAT_PROMETHEUS },
    { njt_null_string, 0 }
};


static njt_conf_enum_t  njt_http_stream_server_traffic_status_average_method_post[] = {
    { njt_string("AMM"), NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_AVERAGE_METHOD_AMM },
    { njt_string("WMA"), NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_AVERAGE_METHOD_WMA },
    { njt_null_string, 0 }
};


static njt_command_t njt_http_stream_server_traffic_status_commands[] = {

    { njt_string("stream_server_traffic_status"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_stream_server_traffic_status_loc_conf_t, enable),
      NULL },

    { njt_string("stream_server_traffic_status_zone"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_NOARGS|NJT_CONF_TAKE1,
      njt_http_stream_server_traffic_status_zone,
      0,
      0,
      NULL },

    { njt_string("stream_server_traffic_status_display"),
      NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_NOARGS|NJT_CONF_TAKE1,
      njt_http_stream_server_traffic_status_display,
      0,
      0,
      NULL },

    { njt_string("stream_server_traffic_status_display_format"),
      NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_enum_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_stream_server_traffic_status_loc_conf_t, format),
      &njt_http_stream_server_traffic_status_display_format },

    { njt_string("stream_server_traffic_status_display_jsonp"),
      NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_stream_server_traffic_status_loc_conf_t, jsonp),
      NULL },

    { njt_string("stream_server_traffic_status_average_method"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE12,
      njt_http_stream_server_traffic_status_average_method,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    njt_null_command
};


static njt_http_module_t njt_http_stream_server_traffic_status_module_ctx = {
    NULL,                                                    /* preconfiguration */
    NULL,                                                    /* postconfiguration */

    njt_http_stream_server_traffic_status_create_main_conf,  /* create main configuration */
    njt_http_stream_server_traffic_status_init_main_conf,    /* init main configuration */

    NULL,                                                    /* create server configuration */
    NULL,                                                    /* merge server configuration */

    njt_http_stream_server_traffic_status_create_loc_conf,   /* create location configuration */
    njt_http_stream_server_traffic_status_merge_loc_conf,    /* merge location configuration */
};


njt_module_t njt_stream_stsd_module = {
    NJT_MODULE_V1,
    &njt_http_stream_server_traffic_status_module_ctx,       /* module context */
    njt_http_stream_server_traffic_status_commands,          /* module directives */
    NJT_HTTP_MODULE,                                         /* module type */
    NULL,                                                    /* init master */
    NULL,                                                    /* init module */
    NULL,                                                    /* init process */
    NULL,                                                    /* init thread */
    NULL,                                                    /* exit thread */
    NULL,                                                    /* exit process */
    NULL,                                                    /* exit master */
    NJT_MODULE_V1_PADDING
};


static char *
njt_http_stream_server_traffic_status_zone(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t                                    *value, name;
    njt_uint_t                                    i;
    njt_http_stream_server_traffic_status_ctx_t  *ctx;

    value = cf->args->elts;

    ctx = njt_http_conf_get_module_main_conf(cf, njt_stream_stsd_module);
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }

    ctx->enable = 1;

    njt_str_set(&name, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_DEFAULT_SHM_NAME);

    for (i = 1; i < cf->args->nelts; i++) {
        if (njt_strncmp(value[i].data, "shared:", 7) == 0) {
            name.data = value[i].data + 7;
            name.len = value[i].len - 7;
            continue;
        }

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NJT_CONF_ERROR;
    }

    ctx->shm_name = name;

    return NJT_CONF_OK;
}


static char *
njt_http_stream_server_traffic_status_average_method(njt_conf_t *cf,
    njt_command_t *cmd, void *conf)
{
    njt_http_stream_server_traffic_status_loc_conf_t *stscf = conf;

    char       *rv;
    njt_int_t   rc;
    njt_str_t  *value;

    value = cf->args->elts;

    cmd->offset = offsetof(njt_http_stream_server_traffic_status_loc_conf_t, average_method);
    cmd->post = &njt_http_stream_server_traffic_status_average_method_post;

    rv = njt_conf_set_enum_slot(cf, cmd, conf);
    if (rv != NJT_CONF_OK) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &value[1]);
        goto invalid;
    }

    /* second argument process */
    if (cf->args->nelts == 3) {
        rc = njt_parse_time(&value[2], 0);
        if (rc == NJT_ERROR) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &value[2]);
            goto invalid;
        }
        stscf->average_period = (njt_msec_t) rc;
    }

    return NJT_CONF_OK;

invalid:

    return NJT_CONF_ERROR;
}


static void *
njt_http_stream_server_traffic_status_create_main_conf(njt_conf_t *cf)
{
    njt_http_stream_server_traffic_status_ctx_t  *ctx;

    ctx = njt_pcalloc(cf->pool, sizeof(njt_http_stream_server_traffic_status_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->enable = NJT_CONF_UNSET;

    return ctx;
}


static char *
njt_http_stream_server_traffic_status_init_main_conf(njt_conf_t *cf, void *conf)
{
    njt_http_stream_server_traffic_status_ctx_t  *ctx = conf;
    njt_cycle_t  *cycle;
    njt_str_t     name;
    njt_stream_server_traffic_status_ctx_t  *sctx;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, cf->log, 0,
                   "http stream sts init main conf");

    njt_conf_init_value(ctx->enable, 1);
    njt_str_set(&name, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_DEFAULT_SHM_NAME);
    ctx->shm_name = name;

    if (njet_master_cycle) {
        cycle = njet_master_cycle;
    } else {
        cycle = (njt_cycle_t *)njt_cycle;
    }
    sctx = njt_stream_cycle_get_module_main_conf(cycle, njt_stream_stsc_module);
    if (sctx) {
        ctx->shm_name = sctx->shm_name;
    }

    return NJT_CONF_OK;
}


static void *
njt_http_stream_server_traffic_status_create_loc_conf(njt_conf_t *cf)
{
    njt_http_stream_server_traffic_status_loc_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_stream_server_traffic_status_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->shm_zone = { NULL, ... };
     *     conf->enable = 0;
     *     conf->shm_name = { 0, NULL };
     *     conf->stats = { 0, ... };
     *     conf->start_msec = 0;
     *     conf->format = 0;
     *     conf->jsonp = { 1, NULL };
     *     conf->average_method = 0;
     *     conf->average_period = 0;
     */

    conf->start_msec = njt_http_stream_server_traffic_status_current_msec();
    conf->enable = NJT_CONF_UNSET;
    conf->shm_zone = NJT_CONF_UNSET_PTR;
    conf->format = NJT_CONF_UNSET;
    conf->average_method = NJT_CONF_UNSET;
    conf->average_period = NJT_CONF_UNSET_MSEC;

    conf->node_caches = njt_pcalloc(cf->pool, sizeof(njt_rbtree_node_t *)
                                    * (NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_FG + 1));
    conf->node_caches[NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_NO] = NULL;
    conf->node_caches[NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_UA] = NULL;
    conf->node_caches[NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_UG] = NULL;
    conf->node_caches[NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_FG] = NULL;

    return conf;
}


static char *
njt_http_stream_server_traffic_status_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_stream_server_traffic_status_loc_conf_t *prev = parent;
    njt_http_stream_server_traffic_status_loc_conf_t *conf = child;

    njt_http_stream_server_traffic_status_ctx_t  *ctx;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, cf->log, 0,
                   "http stream sts merge loc conf");

    ctx = njt_http_conf_get_module_main_conf(cf, njt_stream_stsd_module);

    if (!ctx->enable) {
        return NJT_CONF_OK;
    }

    njt_conf_merge_value(conf->enable, prev->enable, 1);
    njt_conf_merge_ptr_value(conf->shm_zone, prev->shm_zone, NULL);
    njt_conf_merge_value(conf->format, prev->format,
                         NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_FORMAT_JSON);
    njt_conf_merge_str_value(conf->jsonp, prev->jsonp,
                             NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_DEFAULT_JSONP);
    njt_conf_merge_value(conf->average_method, prev->average_method,
                         NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_AVERAGE_METHOD_AMM);
    njt_conf_merge_msec_value(conf->average_period, prev->average_period,
                              NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_DEFAULT_AVG_PERIOD * 1000);

    conf->shm_name = ctx->shm_name;

    return NJT_CONF_OK;
}


njt_msec_t
njt_http_stream_server_traffic_status_current_msec(void)
{
    time_t           sec;
    njt_uint_t       msec;
    struct timeval   tv;

    njt_gettimeofday(&tv);

    sec = tv.tv_sec;
    msec = tv.tv_usec / 1000;

    return (njt_msec_t) sec * 1000 + msec;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
