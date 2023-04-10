
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 * Copyright (C), 2021-2023, TMLake(Beijing) Technology Co., Ltd.
 */


#include "njt_http_vhost_traffic_status_module.h"
#include "njt_http_vhost_traffic_status_variables.h"
#include "njt_http_vhost_traffic_status_shm.h"
#include "njt_http_vhost_traffic_status_filter.h"
#include "njt_http_vhost_traffic_status_limit.h"
#include "njt_http_vhost_traffic_status_display.h"
#include "njt_http_vhost_traffic_status_set.h"
#include "njt_http_vhost_traffic_status_dump.h"


static void *njt_http_vtsd_create_main_conf(njt_conf_t *cf);
static char *njnjt_http_vtsd_init_main_conf(njt_conf_t *cf,
    void *conf);
static void *njt_http_vtsd_create_loc_conf(njt_conf_t *cf);
static char *njt_http_vtsd_merge_loc_conf(njt_conf_t *cf,
    void *parent, void *child);

static njt_conf_enum_t  njt_http_vtsd_display_format[] = {
    { njt_string("json"), NJT_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSON },
    { njt_string("html"), NJT_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_HTML },
    { njt_string("jsonp"), NJT_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSONP },
    { njt_string("prometheus"), NJT_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_PROMETHEUS },
    { njt_null_string, 0 }
};


static njt_command_t njt_http_vtsd_commands[] = {

    { njt_string("vhost_traffic_status_display"),
      NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_NOARGS|NJT_CONF_TAKE1,
      njt_http_vhost_traffic_status_display,
      0,
      0,
      NULL },

    { njt_string("vhost_traffic_status_display_format"),
      NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_enum_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_vhost_traffic_status_loc_conf_t, format),
      &njt_http_vtsd_display_format },

    { njt_string("vhost_traffic_status_display_jsonp"),
      NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_vhost_traffic_status_loc_conf_t, jsonp),
      NULL },

    { njt_string("vhost_traffic_status_display_sum_key"),
      NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_vhost_traffic_status_loc_conf_t, sum_key),
      NULL },

    njt_null_command
};


static njt_http_module_t njt_http_vtsd_module_ctx = {
    NULL,                           /* preconfiguration */
    NULL,                           /* postconfiguration */

    njt_http_vtsd_create_main_conf, /* create main configuration */
    njnjt_http_vtsd_init_main_conf, /* init main configuration */

    NULL,                           /* create server configuration */
    NULL,                           /* merge server configuration */

    njt_http_vtsd_create_loc_conf,  /* create location configuration */
    njt_http_vtsd_merge_loc_conf,   /* merge location configuration */
};


njt_module_t njt_http_vtsd_module = {
    NJT_MODULE_V1,
    &njt_http_vtsd_module_ctx,   /* module context */
    njt_http_vtsd_commands,      /* module directives */
    NJT_HTTP_MODULE,             /* module type */
    NULL,                        /* init master */
    NULL,                        /* init module */
    NULL,                        /* init process */
    NULL,                        /* init thread */
    NULL,                        /* exit thread */
    NULL,                        /* exit process */
    NULL,                        /* exit master */
    NJT_MODULE_V1_PADDING
};


static void *
njt_http_vtsd_create_main_conf(njt_conf_t *cf)
{
    njt_http_vhost_traffic_status_ctx_t  *ctx;

    njt_http_vtsp_module = &njt_http_vtsd_module;
    njt_http_vtsdp_module = &njt_http_vtsd_module;
    njt_http_vtsp_cycle = njet_master_cycle;

    ctx = njt_pcalloc(cf->pool, sizeof(njt_http_vhost_traffic_status_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     ctx->rbtree = { NULL, ... };
     *     ctx->filter_keys = { NULL, ... };
     *     ctx->limit_traffics = { NULL, ... };
     *     ctx->limit_filter_traffics = { NULL, ... };
     *
     *     ctx->filter_max_node_matches = { NULL, ... };
     *     ctx->filter_max_node = 0;
     *
     *     ctx->enable = 0;
     *     ctx->filter_check_duplicate = 0;
     *     ctx->limit_check_duplicate = 0;
     *     ctx->shm_zone = { NULL, ... };
     *     ctx->shm_name = { 0, NULL };
     *     ctx->shm_size = 0;
     *
     *     ctx->dump = 0;
     *     ctx->dump_file = { 0, NULL };
     *     ctx->dump_period = 0;
     *     ctx->dump_event = { NULL, ... };
     */

    ctx->filter_max_node = NJT_CONF_UNSET_UINT;
    ctx->enable = NJT_CONF_UNSET;
    ctx->filter_check_duplicate = NJT_CONF_UNSET;
    ctx->limit_check_duplicate = NJT_CONF_UNSET;
    ctx->dump = NJT_CONF_UNSET;
    ctx->dump_period = NJT_CONF_UNSET_MSEC;

    return ctx;
}


static char *
njnjt_http_vtsd_init_main_conf(njt_conf_t *cf, void *conf)
{
    njt_http_vhost_traffic_status_ctx_t  *ctx = conf;

    njt_int_t                                  rc;
    njt_http_vhost_traffic_status_loc_conf_t  *vtsdf;

    njt_http_vtsp_module = &njt_http_vtsd_module;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, cf->log, 0,
                   "http vts init main conf");

    vtsdf = njt_http_conf_get_module_loc_conf(cf, njt_http_vtsd_module);

    if (vtsdf->filter_check_duplicate != 0) {
        rc = njt_http_vhost_traffic_status_filter_unique(cf->pool, &ctx->filter_keys);
        if (rc != NJT_OK) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "init_main_conf::filter_unique() failed");
            return NJT_CONF_ERROR;
        }
    }

    if (vtsdf->limit_check_duplicate != 0) {
        rc = njt_http_vhost_traffic_status_limit_traffic_unique(cf->pool, &ctx->limit_traffics);
        if (rc != NJT_OK) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "init_main_conf::limit_traffic_unique(server) failed");
            return NJT_CONF_ERROR;
        }

        rc = njt_http_vhost_traffic_status_limit_traffic_unique(cf->pool,
                                                                &ctx->limit_filter_traffics);
        if (rc != NJT_OK) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "init_main_conf::limit_traffic_unique(filter) failed");
            return NJT_CONF_ERROR;
        }
    }

    njt_conf_init_uint_value(ctx->filter_max_node, 0);
    njt_conf_init_value(ctx->enable, 0);
    njt_conf_init_value(ctx->filter_check_duplicate, vtsdf->filter_check_duplicate);
    njt_conf_init_value(ctx->limit_check_duplicate, vtsdf->limit_check_duplicate);
    njt_conf_init_value(ctx->dump, 0);
    njt_conf_merge_msec_value(ctx->dump_period, ctx->dump_period,
                              NJT_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_DUMP_PERIOD * 1000);

    return NJT_CONF_OK;
}


static void *
njt_http_vtsd_create_loc_conf(njt_conf_t *cf)
{
    njt_http_vhost_traffic_status_loc_conf_t  *conf;

    njt_http_vtsp_module = &njt_http_vtsd_module;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_vhost_traffic_status_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->shm_zone = { NULL, ... };
     *     conf->shm_name = { 0, NULL };
     *     conf->enable = 0;
     *     conf->filter = 0;
     *     conf->filter_host = 0;
     *     conf->filter_check_duplicate = 0;
     *     conf->filter_keys = { NULL, ... };
     *     conf->filter_vars = { NULL, ... };
     *
     *     conf->limit = 0;
     *     conf->limit_check_duplicate = 0;
     *     conf->limit_traffics = { NULL, ... };
     *     conf->limit_filter_traffics = { NULL, ... };
     *
     *     conf->stats = { 0, ... };
     *     conf->start_msec = 0;
     *     conf->format = 0;
     *     conf->jsonp = { 0, NULL };
     *     conf->sum_key = { 0, NULL };
     *     conf->average_method = 0;
     *     conf->average_period = 0;
     *     conf->histogram_buckets = { NULL, ... };
     *     conf->bypass_limit = 0;
     *     conf->bypass_stats = 0;
     */

    conf->shm_zone = NJT_CONF_UNSET_PTR;
    conf->enable = NJT_CONF_UNSET;
    conf->filter = NJT_CONF_UNSET;
    conf->filter_host = NJT_CONF_UNSET;
    conf->filter_check_duplicate = NJT_CONF_UNSET;
    conf->filter_vars = NJT_CONF_UNSET_PTR;

    conf->limit = NJT_CONF_UNSET;
    conf->limit_check_duplicate = NJT_CONF_UNSET;

    conf->start_msec = njt_http_vhost_traffic_status_current_msec();
    conf->format = NJT_CONF_UNSET;
    conf->average_method = NJT_CONF_UNSET;
    conf->average_period = NJT_CONF_UNSET_MSEC;
    conf->histogram_buckets = NJT_CONF_UNSET_PTR;
    conf->bypass_limit = NJT_CONF_UNSET;
    conf->bypass_stats = NJT_CONF_UNSET;

    conf->node_caches = njt_pcalloc(cf->pool, sizeof(njt_rbtree_node_t *)
                                    * (NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG + 1));
    conf->node_caches[NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO] = NULL;
    conf->node_caches[NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA] = NULL;
    conf->node_caches[NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG] = NULL;
    conf->node_caches[NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC] = NULL;
    conf->node_caches[NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG] = NULL;

    return conf;
}


static char *
njt_http_vtsd_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_vhost_traffic_status_loc_conf_t *prev = parent;
    njt_http_vhost_traffic_status_loc_conf_t *conf = child;

    njt_int_t                             rc;
    njt_http_vhost_traffic_status_ctx_t  *ctx;

    njt_http_vtsp_module = &njt_http_vtsd_module;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, cf->log, 0,
                   "http vts merge loc conf");

    ctx = njt_http_conf_get_module_main_conf(cf, njt_http_vtsd_module);

    if (!njt_http_vts_enable) {// old !ctx->enable
        return NJT_CONF_OK;
    }

    if (conf->filter_keys == NULL) {
        conf->filter_keys = prev->filter_keys;

    } else {
        if (conf->filter_check_duplicate == NJT_CONF_UNSET) {
            conf->filter_check_duplicate = ctx->filter_check_duplicate;
        }
        if (conf->filter_check_duplicate != 0) {
            rc = njt_http_vhost_traffic_status_filter_unique(cf->pool, &conf->filter_keys);
            if (rc != NJT_OK) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "mere_loc_conf::filter_unique() failed");
                return NJT_CONF_ERROR;
            }
        }
    }

    if (conf->limit_traffics == NULL) {
        conf->limit_traffics = prev->limit_traffics;

    } else {
        if (conf->limit_check_duplicate == NJT_CONF_UNSET) {
            conf->limit_check_duplicate = ctx->limit_check_duplicate;
        }

        if (conf->limit_check_duplicate != 0) {
            rc = njt_http_vhost_traffic_status_limit_traffic_unique(cf->pool,
                                                                    &conf->limit_traffics);
            if (rc != NJT_OK) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "mere_loc_conf::limit_traffic_unique(server) failed");
                return NJT_CONF_ERROR;
            }
        }
    }

    if (conf->limit_filter_traffics == NULL) {
        conf->limit_filter_traffics = prev->limit_filter_traffics;

    } else {
        if (conf->limit_check_duplicate == NJT_CONF_UNSET) {
            conf->limit_check_duplicate = ctx->limit_check_duplicate;
        }

        if (conf->limit_check_duplicate != 0) {
            rc = njt_http_vhost_traffic_status_limit_traffic_unique(cf->pool,
                                                                    &conf->limit_filter_traffics);
            if (rc != NJT_OK) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "mere_loc_conf::limit_traffic_unique(filter) failed");
                return NJT_CONF_ERROR;
            }
        }
    }

    njt_conf_merge_ptr_value(conf->shm_zone, prev->shm_zone, NULL);
    njt_conf_merge_value(conf->enable, prev->enable, 1);
    njt_conf_merge_value(conf->filter, prev->filter, 1);
    njt_conf_merge_value(conf->filter_host, prev->filter_host, 0);
    njt_conf_merge_value(conf->filter_check_duplicate, prev->filter_check_duplicate, 1);
    njt_conf_merge_value(conf->limit, prev->limit, 1);
    njt_conf_merge_value(conf->limit_check_duplicate, prev->limit_check_duplicate, 1);
    njt_conf_merge_ptr_value(conf->filter_vars, prev->filter_vars, NULL);

    njt_conf_merge_value(conf->format, prev->format,
                         NJT_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSON);
    njt_conf_merge_str_value(conf->jsonp, prev->jsonp,
                             NJT_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_JSONP);
    njt_conf_merge_str_value(conf->sum_key, prev->sum_key,
                             NJT_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_SUM_KEY);
    njt_conf_merge_value(conf->average_method, prev->average_method,
                         NJT_HTTP_VHOST_TRAFFIC_STATUS_AVERAGE_METHOD_AMM);
    njt_conf_merge_msec_value(conf->average_period, prev->average_period,
                              NJT_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_AVG_PERIOD * 1000);
    njt_conf_merge_ptr_value(conf->histogram_buckets, prev->histogram_buckets, NULL);

    njt_conf_merge_value(conf->bypass_limit, prev->bypass_limit, 0);
    njt_conf_merge_value(conf->bypass_stats, prev->bypass_stats, 0);

    return NJT_CONF_OK;
}
