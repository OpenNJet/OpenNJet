
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
#include <njt_http_kv_module.h>
#include <njt_http_util.h>
#include "njt_http_vtsc_parser.h"
#include <njt_rpc_result_util.h>

static njt_int_t njt_http_vtsc_handler(njt_http_request_t *r);

static void njt_http_vtsc_rbtree_insert_value(
    njt_rbtree_node_t *temp, njt_rbtree_node_t *node,
    njt_rbtree_node_t *sentinel);
static njt_int_t njt_http_vtsc_init_zone(
    njt_shm_zone_t *shm_zone, void *data);
static char *njt_http_vtsc_zone(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);
static char *njt_http_vtsc_dump(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);
static char *njt_http_vtsc_filter_max_node(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);
static char *njt_http_vtsc_average_method(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);
static char *njt_http_vtsc_histogram_buckets(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);

static njt_int_t njt_http_vtsc_preconfiguration(njt_conf_t *cf);
static njt_int_t njt_http_vtsc_init(njt_conf_t *cf);
static void *njt_http_vtsc_create_main_conf(njt_conf_t *cf);
static char *njnjt_http_vtsc_init_main_conf(njt_conf_t *cf,
    void *conf);
static void *njt_http_vtsc_create_loc_conf(njt_conf_t *cf);
static char *njt_http_vtsc_merge_loc_conf(njt_conf_t *cf,
    void *parent, void *child);
static njt_int_t njt_http_vtsc_init_worker(njt_cycle_t *cycle);
static void njt_http_vtsc_exit_worker(njt_cycle_t *cycle);


static njt_conf_enum_t  njt_http_vtsc_average_method_post[] = {
    { njt_string("AMM"), NJT_HTTP_VHOST_TRAFFIC_STATUS_AVERAGE_METHOD_AMM },
    { njt_string("WMA"), NJT_HTTP_VHOST_TRAFFIC_STATUS_AVERAGE_METHOD_WMA },
    { njt_null_string, 0 }
};


static njt_command_t njt_http_vtsc_commands[] = {

    { njt_string("vhost_traffic_status"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_vhost_traffic_status_loc_conf_t, enable),
      NULL },

    { njt_string("vhost_traffic_status_filter"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_vhost_traffic_status_loc_conf_t, filter),
      NULL },

    { njt_string("vhost_traffic_status_filter_by_host"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_vhost_traffic_status_loc_conf_t, filter_host),
      NULL },

    { njt_string("vhost_traffic_status_filter_check_duplicate"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_vhost_traffic_status_loc_conf_t, filter_check_duplicate),
      NULL },

    { njt_string("vhost_traffic_status_filter_by_set_key"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE12,
      njt_http_vhost_traffic_status_filter_by_set_key,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("vhost_traffic_status_filter_max_node"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_1MORE,
      njt_http_vtsc_filter_max_node,
      0,
      0,
      NULL },

    { njt_string("vhost_traffic_status_limit"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_vhost_traffic_status_loc_conf_t, limit),
      NULL },

    { njt_string("vhost_traffic_status_limit_check_duplicate"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_vhost_traffic_status_loc_conf_t, limit_check_duplicate),
      NULL },

    { njt_string("vhost_traffic_status_limit_traffic"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE12,
      njt_http_vhost_traffic_status_limit_traffic,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("vhost_traffic_status_limit_traffic_by_set_key"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE23,
      njt_http_vhost_traffic_status_limit_traffic_by_set_key,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("vhost_traffic_status_zone"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_NOARGS|NJT_CONF_TAKE1,
      njt_http_vtsc_zone,
      0,
      0,
      NULL },

    { njt_string("vhost_traffic_status_dump"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE12,
      njt_http_vtsc_dump,
      0,
      0,
      NULL },

    { njt_string("vhost_traffic_status_set_by_filter"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF
                        |NJT_HTTP_LIF_CONF|NJT_CONF_TAKE2,
      njt_http_vhost_traffic_status_set_by_filter,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("vhost_traffic_status_average_method"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE12,
      njt_http_vtsc_average_method,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("vhost_traffic_status_histogram_buckets"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_http_vtsc_histogram_buckets,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("vhost_traffic_status_bypass_limit"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_vhost_traffic_status_loc_conf_t, bypass_limit),
      NULL },

    { njt_string("vhost_traffic_status_bypass_stats"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_vhost_traffic_status_loc_conf_t, bypass_stats),
      NULL },

    njt_null_command
};


static njt_http_module_t njt_http_vtsc_module_ctx = {
    njt_http_vtsc_preconfiguration, /* preconfiguration */
    njt_http_vtsc_init,             /* postconfiguration */

    njt_http_vtsc_create_main_conf, /* create main configuration */
    njnjt_http_vtsc_init_main_conf, /* init main configuration */

    NULL,                           /* create server configuration */
    NULL,                           /* merge server configuration */

    njt_http_vtsc_create_loc_conf,  /* create location configuration */
    njt_http_vtsc_merge_loc_conf,   /* merge location configuration */
};


njt_module_t njt_http_vtsc_module = {
    NJT_MODULE_V1,
    &njt_http_vtsc_module_ctx,   /* module context */
    njt_http_vtsc_commands,      /* module directives */
    NJT_HTTP_MODULE,             /* module type */
    NULL,                        /* init master */
    NULL,                        /* init module */
    njt_http_vtsc_init_worker,   /* init process */
    NULL,                        /* init thread */
    NULL,                        /* exit thread */
    njt_http_vtsc_exit_worker,   /* exit process */
    NULL,                        /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_int_t
njt_http_vtsc_handler(njt_http_request_t *r)
{
    njt_int_t                                  rc;
    njt_http_vhost_traffic_status_ctx_t       *ctx;
    njt_http_vhost_traffic_status_loc_conf_t  *vtscf;

    njt_http_vtsp_module = &njt_http_vtsc_module;
    njt_http_vtsp_cycle = (njt_cycle_t *)njt_cycle;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http vts handler");

    ctx = njt_http_get_module_main_conf(r, njt_http_vtsc_module);
    vtscf = njt_http_get_module_loc_conf(r, njt_http_vtsc_module);

    if (njt_process == NJT_PROCESS_HELPER)  {
        return NJT_DECLINED;
    }

    if (!ctx->enable || !vtscf->enable || vtscf->bypass_stats) {
        return NJT_DECLINED;
    }
    if (vtscf->shm_zone == NULL) {
        return NJT_DECLINED;
    }

    rc = njt_http_vhost_traffic_status_shm_add_server(r);
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "handler::shm_add_server() failed");
    }

    rc = njt_http_vhost_traffic_status_shm_add_upstream(r);
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "handler::shm_add_upstream() failed");
    }

    rc = njt_http_vhost_traffic_status_shm_add_filter(r);
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "handler::shm_add_filter() failed");
    }

#if (NJT_HTTP_CACHE)
    rc = njt_http_vhost_traffic_status_shm_add_cache(r);
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "handler::shm_add_cache() failed");
    }
#endif

    return NJT_DECLINED;
}


static void
njt_http_vtsc_rbtree_insert_value(njt_rbtree_node_t *temp,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel)
{
    njt_rbtree_node_t                     **p;
    njt_http_vhost_traffic_status_node_t   *vtsn, *vtsnt;

    njt_http_vtsp_module = &njt_http_vtsc_module;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            vtsn = njt_http_vhost_traffic_status_get_node(node);
            vtsnt = njt_http_vhost_traffic_status_get_node(temp);

            p = (njt_memn2cmp(vtsn->data, vtsnt->data, vtsn->len, vtsnt->len) < 0)
                ? &temp->left
                : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    njt_rbt_red(node);
}


static njt_int_t
njt_http_vtsc_init_zone(njt_shm_zone_t *shm_zone, void *data)
{
    njt_http_vhost_traffic_status_ctx_t  *octx = data;

    size_t                                len;
    njt_slab_pool_t                      *shpool;
    njt_rbtree_node_t                    *sentinel;
    njt_http_vhost_traffic_status_ctx_t  *ctx;

    njt_http_vtsp_module = &njt_http_vtsc_module;

    ctx = shm_zone->data;

    if (octx) {
        ctx->rbtree = octx->rbtree;
        return NJT_OK;
    }

    shpool = (njt_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->rbtree = shpool->data;
        return NJT_OK;
    }

    ctx->rbtree = njt_slab_alloc(shpool, sizeof(njt_rbtree_t));
    if (ctx->rbtree == NULL) {
        return NJT_ERROR;
    }

    shpool->data = ctx->rbtree;

    sentinel = njt_slab_alloc(shpool, sizeof(njt_rbtree_node_t));
    if (sentinel == NULL) {
        return NJT_ERROR;
    }

    njt_rbtree_init(ctx->rbtree, sentinel,
                    njt_http_vtsc_rbtree_insert_value);

    len = sizeof(" in vhost_traffic_status_zone \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = njt_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NJT_ERROR;
    }

    njt_http_vts_rbtree = ctx->rbtree;
    njt_sprintf(shpool->log_ctx, " in vhost_traffic_status_zone \"%V\"%Z",
                &shm_zone->shm.name);

    int njt_http_vts_hdr_init(njt_slab_pool_t *shpool);
    njt_http_vts_hdr_init(shpool);
    
    njt_shrwlock_create(&shpool->rwlock, &shpool->lock, NULL);

    return NJT_OK;
}


static char *
njt_http_vtsc_zone(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    u_char                               *p;
    ssize_t                               size;
    njt_str_t                            *value, name, s;
    njt_uint_t                            i;
    njt_shm_zone_t                       *shm_zone;
    njt_http_vhost_traffic_status_ctx_t  *ctx;

    njt_http_vtsp_module = &njt_http_vtsc_module;
    njt_http_vtscp_module = &njt_http_vtsc_module;

    value = cf->args->elts;

    ctx = njt_http_conf_get_module_main_conf(cf, njt_http_vtsc_module);
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }

    ctx->enable = 1;
    njt_http_vts_enable = 1;

    njt_str_set(&name, NJT_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_SHM_NAME);

    size = NJT_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_SHM_SIZE;

    for (i = 1; i < cf->args->nelts; i++) {
        if (njt_strncmp(value[i].data, "shared:", 7) == 0) {

            name.data = value[i].data + 7;

            p = (u_char *) njt_strlchr(name.data, name.data + name.len, ':');
            if (p == NULL) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid shared size \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            name.len = p - name.data;

            s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;

            size = njt_parse_size(&s);
            if (size == NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid shared size \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            if (size < (ssize_t) (8 * njt_pagesize)) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "shared \"%V\" is too small", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NJT_CONF_ERROR;
    }

    shm_zone = njt_shared_memory_add(cf, &name, size,
                                     &njt_http_vtsc_module);
    if (shm_zone == NULL) {
        return NJT_CONF_ERROR;
    }

    if (shm_zone->data) {
        ctx = shm_zone->data;

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "vhost_traffic_status: \"%V\" is already bound to key",
                           &name);

        return NJT_CONF_ERROR;
    }

    ctx->shm_zone = shm_zone;
    ctx->shm_name = name;
    ctx->shm_size = size;
    shm_zone->init = njt_http_vtsc_init_zone;
    shm_zone->data = ctx;
    njt_http_vts_shm_zone = shm_zone;
    njt_http_vts_shm_name = ctx->shm_name;
    njt_http_vts_shm_size = ctx->shm_size;

    return NJT_CONF_OK;
}


static char *
njt_http_vtsc_dump(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_vhost_traffic_status_ctx_t  *ctx = conf;

    njt_int_t   rc;
    njt_str_t  *value;

    njt_http_vtsp_module = &njt_http_vtsc_module;

    value = cf->args->elts;

    ctx->dump = 1;

    ctx->dump_file = value[1];

    /* second argument process */
    if (cf->args->nelts == 3) {
        rc = njt_parse_time(&value[2], 0);
        if (rc == NJT_ERROR) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &value[2]);
            goto invalid;
        }
        ctx->dump_period = (njt_msec_t) rc;
    }

    return NJT_CONF_OK;

invalid:

    return NJT_CONF_ERROR;
}


static char *
njt_http_vtsc_filter_max_node(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    njt_http_vhost_traffic_status_ctx_t  *ctx = conf;

    njt_str_t                                     *value;
    njt_int_t                                      n;
    njt_uint_t                                     i;
    njt_array_t                                   *filter_max_node_matches;
    njt_http_vhost_traffic_status_filter_match_t  *matches;

    njt_http_vtsp_module = &njt_http_vtsc_module;

    filter_max_node_matches = njt_array_create(cf->pool, 1,
                                  sizeof(njt_http_vhost_traffic_status_filter_match_t));
    if (filter_max_node_matches == NULL) {
        goto invalid;
    }

    value = cf->args->elts;

    n = njt_atoi(value[1].data, value[1].len);
    if (n < 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid number of filter_max_node \"%V\"", &value[1]);
        return NJT_CONF_ERROR;
    }

    ctx->filter_max_node = (njt_uint_t) n;

    /* arguments process */
    for (i = 2; i < cf->args->nelts; i++) {
        matches = njt_array_push(filter_max_node_matches);
        if (matches == NULL) {
            goto invalid;
        }

        matches->match.data = value[i].data;
        matches->match.len = value[i].len;
    }

    ctx->filter_max_node_matches = filter_max_node_matches;

    return NJT_CONF_OK;

invalid:

    return NJT_CONF_ERROR;
}


static char *
njt_http_vtsc_average_method(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    njt_http_vhost_traffic_status_loc_conf_t *vtscf = conf;

    char       *rv;
    njt_int_t   rc;
    njt_str_t  *value;

    njt_http_vtsp_module = &njt_http_vtsc_module;

    value = cf->args->elts;

    cmd->offset = offsetof(njt_http_vhost_traffic_status_loc_conf_t, average_method);
    cmd->post = &njt_http_vtsc_average_method_post;

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
        vtscf->average_period = (njt_msec_t) rc;
    }

    return NJT_CONF_OK;

invalid:

    return NJT_CONF_ERROR;
}


static char *
njt_http_vtsc_histogram_buckets(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    njt_http_vhost_traffic_status_loc_conf_t *vtscf = conf;

    njt_str_t                                       *value;
    njt_int_t                                        n;
    njt_uint_t                                       i;
    njt_array_t                                     *histogram_buckets;
    njt_http_vhost_traffic_status_node_histogram_t  *buckets;

    njt_http_vtsp_module = &njt_http_vtsc_module;

    histogram_buckets = njt_array_create(cf->pool, 1,
                            sizeof(njt_http_vhost_traffic_status_node_histogram_t));
    if (histogram_buckets == NULL) {
        goto invalid;
    }

    value = cf->args->elts;

    /* arguments process */
    for (i = 1; i < cf->args->nelts; i++) {
        if (i > NJT_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_BUCKET_LEN) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "histogram bucket size exceeds %d",
                               NJT_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_BUCKET_LEN);
            break;
        }

        n = njt_atofp(value[i].data, value[i].len, 3);
        if (n == NJT_ERROR || n == 0) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &value[i]);
            goto invalid;
        }

        buckets = njt_array_push(histogram_buckets);
        if (buckets == NULL) {
            goto invalid;
        }

        buckets->msec = (njt_msec_int_t) n;
    }

    vtscf->histogram_buckets = histogram_buckets;

    return NJT_CONF_OK;

invalid:

    return NJT_CONF_ERROR;
}


static njt_int_t
njt_http_vtsc_preconfiguration(njt_conf_t *cf)
{
    njt_http_vtsp_module = &njt_http_vtsc_module;
    return njt_http_vhost_traffic_status_add_variables(cf);
}


static njt_int_t
njt_http_vtsc_init(njt_conf_t *cf)
{
    njt_http_handler_pt        *h;
    njt_http_core_main_conf_t  *cmcf;

    njt_http_vtsp_module = &njt_http_vtsc_module;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, cf->log, 0,
                   "http vts init");

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);

    /* limit handler */
    h = njt_array_push(&cmcf->phases[NJT_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_http_vhost_traffic_status_limit_handler;

    /* set handler */
    h = njt_array_push(&cmcf->phases[NJT_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_http_vhost_traffic_status_set_handler;

    /* vts handler */
    h = njt_array_push(&cmcf->phases[NJT_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_http_vtsc_handler;

    return NJT_OK;
}


static void *
njt_http_vtsc_create_main_conf(njt_conf_t *cf)
{
    njt_http_vhost_traffic_status_ctx_t  *ctx;

    njt_http_vtsp_module = &njt_http_vtsc_module;

    ctx = njt_pcalloc(cf->pool, sizeof(njt_http_vhost_traffic_status_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    njt_http_vts_enable = 0;

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
njnjt_http_vtsc_init_main_conf(njt_conf_t *cf, void *conf)
{
    njt_http_vhost_traffic_status_ctx_t  *ctx = conf;

    njt_int_t                                  rc;
    njt_http_vhost_traffic_status_loc_conf_t  *vtscf;

    njt_http_vtsp_module = &njt_http_vtsc_module;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, cf->log, 0,
                   "http vts init main conf");

    vtscf = njt_http_conf_get_module_loc_conf(cf, njt_http_vtsc_module);

    if (vtscf->filter_check_duplicate != 0) {
        rc = njt_http_vhost_traffic_status_filter_unique(cf->pool, &ctx->filter_keys);
        if (rc != NJT_OK) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "init_main_conf::filter_unique() failed");
            return NJT_CONF_ERROR;
        }
    }

    if (vtscf->limit_check_duplicate != 0) {
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
    njt_conf_init_value(ctx->filter_check_duplicate, vtscf->filter_check_duplicate);
    njt_conf_init_value(ctx->limit_check_duplicate, vtscf->limit_check_duplicate);
    njt_conf_init_value(ctx->dump, 0);
    njt_conf_merge_msec_value(ctx->dump_period, ctx->dump_period,
                              NJT_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_DUMP_PERIOD * 1000);

    return NJT_CONF_OK;
}


static void *
njt_http_vtsc_create_loc_conf(njt_conf_t *cf)
{
    njt_http_vhost_traffic_status_loc_conf_t  *conf;

    njt_http_vtsp_module = &njt_http_vtsc_module;

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
njt_http_vtsc_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_vhost_traffic_status_loc_conf_t *prev = parent;
    njt_http_vhost_traffic_status_loc_conf_t *conf = child;

    njt_int_t                             rc;
    njt_str_t                             name;
    njt_shm_zone_t                       *shm_zone;
    njt_http_vhost_traffic_status_ctx_t  *ctx;

    njt_http_vtsp_module = &njt_http_vtsc_module;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, cf->log, 0,
                   "http vts merge loc conf");

    ctx = njt_http_conf_get_module_main_conf(cf, njt_http_vtsc_module);

    if (!ctx->enable) {
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

    name = ctx->shm_name;

    shm_zone = njt_shared_memory_add(cf, &name, 0,
                                     &njt_http_vtsc_module);
    if (shm_zone == NULL) {
        return NJT_CONF_ERROR;
    }

    conf->shm_zone = shm_zone;
    conf->shm_name = name;

    return NJT_CONF_OK;
}


#if (NJT_HTTP_VTS_DYNCONF)
static njt_int_t njt_agent_vts_init_process(njt_cycle_t* cycle);
#endif


static njt_int_t
njt_http_vtsc_init_worker(njt_cycle_t *cycle)
{
    njt_event_t                          *dump_event;
    njt_http_vhost_traffic_status_ctx_t  *ctx;

    njt_http_vtsp_module = &njt_http_vtsc_module;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, cycle->log, 0,
                   "http vts init worker");

    ctx = njt_http_cycle_get_module_main_conf(cycle, njt_http_vtsc_module);

    if (ctx == NULL) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, cycle->log, 0,
                       "vts::init_worker(): is bypassed due to no http block in configure file");
        return NJT_OK;
    }

#if (NJT_HTTP_VTS_DYNCONF)
    if (ctx->enable) {
        njt_agent_vts_init_process(cycle);
    }
#endif

    if (!(ctx->enable & ctx->dump) || ctx->rbtree == NULL) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, cycle->log, 0,
                       "vts::init_worker(): is bypassed");
        return NJT_OK;
    }

    if (njt_worker != 0)  {
        return NJT_OK;
    }

    /* dumper */
    dump_event = &ctx->dump_event;
    dump_event->handler = njt_http_vhost_traffic_status_dump_handler;
    dump_event->log = njt_cycle->log;
    dump_event->data = ctx;
    njt_add_timer(dump_event, 1000);

    /* restore */
    njt_http_vhost_traffic_status_dump_restore(dump_event);

    return NJT_OK;
}


static void
njt_http_vtsc_exit_worker(njt_cycle_t *cycle)
{
    njt_event_t                          *dump_event;
    njt_http_vhost_traffic_status_ctx_t  *ctx;

    njt_http_vtsp_module = &njt_http_vtsc_module;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, cycle->log, 0,
                   "http vts exit worker");

    ctx = njt_http_cycle_get_module_main_conf(cycle, njt_http_vtsc_module);

    if (ctx == NULL) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, cycle->log, 0,
                       "vts::exit_worker(): is bypassed due to no http block in configure file");
        return;
    }

    if (!(ctx->enable & ctx->dump) || ctx->rbtree == NULL) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, cycle->log, 0,
                       "vts::exit_worker(): is bypassed");
        return;
    }

    /* dump */
    dump_event = &ctx->dump_event;
    dump_event->log = njt_cycle->log;
    dump_event->data = ctx;
    njt_http_vhost_traffic_status_dump_execute(dump_event);
}


#if (NJT_HTTP_VTS_DYNCONF)

#define njt_json_fast_key(key) (u_char*)key,sizeof(key)-1
#define njt_json_null_key NULL,0


typedef struct {
    njt_str_t location;
    bool vhost_traffic_status_enable;
    njt_array_t locations;//of njt_http_vts_dynapi_loc_item_t *
} njt_http_vts_dynapi_loc_item_t;


typedef struct {
    njt_array_t listens;//of njt_str_t *
    njt_array_t server_names;//of njt_str_t *
    njt_array_t locations;//of njt_http_vts_dynapi_loc_item_t *
} njt_http_vts_dynapi_svr_t;


typedef struct {
    njt_str_t   filter;
    njt_array_t servers;//of njt_http_vts_dynapi_svr_t *
    njt_int_t   rc;
    unsigned    success:1;
} njt_http_vts_dynapi_main_t;


static njt_str_t njt_http_vts_dynapi_update_svr_err_msg = njt_string("{\"code\":500,\"msg\":\"server error\"}");


static void njt_vts_dynapi_dump_locs_json(njt_pool_t *pool, 
        njt_queue_t *locations, dyn_vts_servers_item_locations_t *loc_items)
{
    njt_http_core_loc_conf_t                    *clcf;
    njt_http_location_queue_t                   *locq;
    njt_queue_t                                 *q,*tq;
    njt_http_vhost_traffic_status_loc_conf_t    *llcf;
    dyn_vts_servers_item_locations_item_t     *loc_item;

    if(locations == NULL){
        return;
    }

    q = locations;
    if (njt_queue_empty(q)) {
        return;
    }

    tq = njt_queue_head(q);
    for (; tq!= njt_queue_sentinel(q); tq = njt_queue_next(tq)){
        locq = njt_queue_data(tq, njt_http_location_queue_t, queue);
        clcf = locq->exact == NULL ? locq->inclusive : locq->exact;
        if(clcf == NULL){
            continue;
        }

        llcf = njt_http_get_module_loc_conf(clcf, njt_http_vtsc_module);
        if(llcf == NULL){
            continue;
        }

        loc_item = create_dyn_vts_locationDef(pool);
        if(loc_item == NULL){
            continue;
        }

        set_dyn_vts_locationDef_location(loc_item, &clcf->full_name);

        if(llcf->enable){
            set_dyn_vts_locationDef_vhost_traffic_status(loc_item, true);
        }else{
            set_dyn_vts_locationDef_vhost_traffic_status(loc_item, false);
        }

        if (clcf->old_locations) {
            set_dyn_vts_locationDef_locations(loc_item, create_dyn_vts_locationDef_locations(pool, 4));
            if(loc_item->locations != NULL){
                njt_vts_dynapi_dump_locs_json(pool, clcf->old_locations, loc_item->locations);
            }
        }

        add_item_dyn_vts_servers_item_locations(loc_items, loc_item);
    }
}


static void njt_vts_dynapi_dump_vts_filter_conf(njt_cycle_t *cycle, njt_str_t *vtsfilter, njt_pool_t *pool)
{
    njt_http_vhost_traffic_status_ctx_t     *ctx;
    njt_array_t                             *filter_keys;
    njt_http_vhost_traffic_status_filter_t  *key;
    njt_uint_t                               i;
    u_char                                  *data;

    ctx = njt_http_cycle_get_module_main_conf(cycle, njt_http_vhost_traffic_status_module);
    if (ctx == NULL) {
        return;
    }

    filter_keys = ctx->filter_keys_dyn;
    if (filter_keys == NULL) {
        filter_keys = ctx->filter_keys;
        if (filter_keys == NULL) {
            return;
        }
    }

    key = filter_keys->elts;
    for (i=0; i<filter_keys->nelts; i++) {
        data = njt_pcalloc(pool, key[i].filter_key.value.len + key[i].filter_name.value.len + 16);

        vtsfilter->data = data;
        data = njt_snprintf(data, key[i].filter_key.value.len+2, "\"%s\"", key[i].filter_key.value.data);

        if (key[i].filter_name.value.len > 0) {
            *data++=' ';
            data = njt_snprintf(data, key[i].filter_name.value.len+2, "\"%s\"", key[i].filter_name.value.data);
        }

        vtsfilter->len = data - vtsfilter->data;
    }
}


static njt_str_t *njt_vts_dynapi_dump_vts_conf(njt_cycle_t *cycle, njt_pool_t *pool)
{
    njt_http_core_loc_conf_t    *clcf;
    njt_http_core_main_conf_t   *hcmcf;
    njt_http_core_srv_conf_t   **cscfp;
    njt_uint_t                   i,j;
    njt_array_t                 *array;
    njt_str_t                   *tmp_str;
    njt_http_server_name_t      *server_name;
    dyn_vts_t                   dynjson_obj;
    dyn_vts_servers_item_t      *server_item;
    dyn_vts_vhost_traffic_status_filter_by_set_key_t fitler_set_by_key_filed;
    
    njt_memzero(&dynjson_obj, sizeof(dyn_vts_t));
    hcmcf = njt_http_cycle_get_module_main_conf(cycle, njt_http_core_module);
    if(hcmcf == NULL){
        goto err;
    }

    njt_str_null(&fitler_set_by_key_filed);
    njt_vts_dynapi_dump_vts_filter_conf(cycle, &fitler_set_by_key_filed, pool);
    if(fitler_set_by_key_filed.len > 0){
        set_dyn_vts_vhost_traffic_status_filter_by_set_key(&dynjson_obj, &fitler_set_by_key_filed);
    }
    
    set_dyn_vts_servers(&dynjson_obj, create_dyn_vts_servers(pool, 4));
    if(dynjson_obj.servers == NULL){
        goto err;
    }

    cscfp = hcmcf->servers.elts;
    for( i = 0; i < hcmcf->servers.nelts; i++){
        server_item = create_dyn_vts_servers_item(pool);
        if(server_item == NULL){
            goto err;
        }
        set_dyn_vts_servers_item_listens(server_item, create_dyn_vts_servers_item_listens(pool, 4));
        set_dyn_vts_servers_item_serverNames(server_item, create_dyn_vts_servers_item_serverNames(pool, 4));
        set_dyn_vts_servers_item_locations(server_item, create_dyn_vts_servers_item_locations(pool, 4));

        array = njt_array_create(pool, 4, sizeof(njt_str_t));
        if(array == NULL){
            goto err;
        }
        njt_http_get_listens_by_server(array, cscfp[i]);

        for (j = 0; j < array->nelts; ++j) {
            tmp_str = (njt_str_t *)(array->elts)+ j;
            add_item_dyn_vts_servers_item_listens(server_item->listens, tmp_str);
        }

        server_name = cscfp[i]->server_names.elts;
        for (j = 0; j < cscfp[i]->server_names.nelts; ++j) {
            tmp_str = &server_name[j].full_name;
            add_item_dyn_vts_servers_item_serverNames(server_item->serverNames,tmp_str);
        }

        clcf = njt_http_get_module_loc_conf(cscfp[i]->ctx, njt_http_core_module);
        if(clcf != NULL){
            njt_vts_dynapi_dump_locs_json(pool, clcf->old_locations, server_item->locations);
        }

        add_item_dyn_vts_servers(dynjson_obj.servers, server_item);
    }

    return to_json_dyn_vts(pool, &dynjson_obj, OMIT_NULL_ARRAY | OMIT_NULL_OBJ | OMIT_NULL_STR);

err:
    return &njt_http_vts_dynapi_update_svr_err_msg;
}


static njt_int_t njt_dynvts_update_locs(njt_array_t *locs, njt_queue_t *q, njt_rpc_result_t *rpc_result)
{
    njt_http_core_loc_conf_t    *clcf;
    njt_http_location_queue_t   *hlq;
    dyn_vts_servers_item_locations_item_t            *dlil;
    njt_uint_t                   j;
    njt_queue_t                 *tq;
    u_char                       data_buf[128];
    u_char                      *end;
    njt_str_t                    rpc_data_str;
    bool                         loc_found;
    njt_str_t                    parent_conf_path;
    njt_http_vhost_traffic_status_loc_conf_t *llcf;
    njt_str_t                           *name;

    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;

    if(q == NULL){
        return NJT_OK;
    }

    if (rpc_result) {
        parent_conf_path = rpc_result->conf_path;
    }

    for(j = 0; j < locs->nelts ; ++j){
        dlil = get_dyn_vts_servers_item_locations_item(locs, j);
        if(dlil == NULL || !dlil->is_location_set){
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " index %d not set location name", j);
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            continue;
        }

        name = get_dyn_vts_locationDef_location(dlil);
        loc_found = false;
        tq = njt_queue_head(q);
        for (; tq!= njt_queue_sentinel(q); tq = njt_queue_next(tq)) {
            hlq = njt_queue_data(tq, njt_http_location_queue_t, queue);
            clcf = hlq->exact == NULL ? hlq->inclusive : hlq->exact;
            if (clcf != NULL && njt_http_location_full_name_cmp(clcf->full_name, *name) == 0) {
                if(rpc_result){
                    njt_rpc_result_set_conf_path(rpc_result, &parent_conf_path);
                    end = njt_snprintf(data_buf,sizeof(data_buf) - 1, ".locations[%V]", &clcf->full_name);
                    rpc_data_str.len = end - data_buf;
                    njt_rpc_result_append_conf_path(rpc_result, &rpc_data_str);
                }
                
                loc_found = true;
                llcf = njt_http_get_module_loc_conf(clcf, njt_http_vtsc_module);
                if(dlil->is_vhost_traffic_status_set){
                    llcf->enable = dlil->vhost_traffic_status;
                    njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "change location %V vhost_traffic_status to %i", &dlil->location, dlil->vhost_traffic_status);
                }
                njt_rpc_result_add_success_count(rpc_result);
          
                if (dlil->is_locations_set && dlil->locations && dlil->locations->nelts > 0) {
                    njt_dynvts_update_locs(dlil->locations, clcf->old_locations, rpc_result);
                }
            }
        }

        if (!loc_found) {
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " location[%V] not found", name);
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        }
    }

    return NJT_OK;
}


static void njt_dynvts_update_filter(njt_cycle_t *cycle, njt_str_t *dynconf, njt_rpc_result_t *rpc_result)
{
    njt_http_vhost_traffic_status_ctx_t     *ctx;
    njt_array_t                             *filter_keys;
    njt_http_vhost_traffic_status_filter_t  *filter;
    njt_http_compile_complex_value_t         ccv;
    njt_str_t                                first, second;
    u_char                                  *data;
    njt_conf_t                               conf;
    njt_pool_t                              *dyn_pool;
    u_char                                  *filter_data;
    size_t                                   len;
    njt_uint_t                               flag;
    njt_uint_t                               i;
    njt_http_core_main_conf_t               *cmcf;
    njt_hash_key_t                          *key, *pkey;
    njt_str_t                                flt;
    njt_str_t                                fk;
    u_char                                   data_buf[128];
    u_char                                  *end;
    njt_str_t                                rpc_data_str;

    rpc_data_str.data = data_buf;
    rpc_data_str.len = 0;

    flt.data = dynconf->data;
    flt.len = dynconf->len;
    cmcf = njt_http_cycle_get_module_main_conf(cycle, njt_http_core_module);
    key = cmcf->variables_keys->keys.elts;
    pkey = cmcf->prefix_variables.elts;

    while (flt.len > 0) {
        while (flt.len>0  && *flt.data!='$') {
            flt.len--;
            flt.data++;
        }

        if (flt.len>0  && *flt.data=='$') {
            fk.data = flt.data;
            fk.len = 1;
            flt.len--;
            flt.data++;
        } else {
            continue;
        }

        while (flt.len>0  && ((*flt.data >= 'A' && *flt.data <= 'Z')
                    || (*flt.data >= 'a' && *flt.data <= 'z')
                    || (*flt.data >= '0' && *flt.data <= '9')
                    || *flt.data == '_')) {
            flt.len--;
            flt.data++;
            fk.len++;
        }

        flag = 0;
        for (i = 0; i < cmcf->variables_keys->keys.nelts; i++) {
            if (fk.len-1 == key[i].key.len && njt_strncasecmp(fk.data+1, key[i].key.data, fk.len-1) == 0) {
                flag = 1;
            }
        }

        if (!flag) {
            for (i = 0; i < cmcf->prefix_variables.nelts; i++) {
                if (pkey[i].key.len > 0 && pkey[i].key.len < fk.len-1 && njt_strncasecmp(fk.data+1, pkey[i].key.data, pkey[i].key.len) == 0) {
                    flag = 1;
                }
            }
        }

        if (!flag) {
            njt_log_error(NJT_LOG_INFO, cycle->pool->log, 0, "found unknown var %V in filter key", &fk);
            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " found unknown var %V in filter key", &fk);
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
            return;
        }
    }

    ctx = njt_http_cycle_get_module_main_conf(cycle, njt_http_vhost_traffic_status_module);
    if (ctx == NULL) {
        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " get module main conf error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        goto FAIL;
    }

    if (ctx->dyn_pool != NULL) {
        njt_destroy_pool(ctx->dyn_pool);
    }

    ctx->filter_keys_dyn = NULL;
    ctx->dyn_pool = njt_create_dynamic_pool(NJT_MIN_POOL_SIZE, cycle->log);
    if(ctx->dyn_pool == NULL || NJT_OK != njt_sub_pool(cycle->pool, ctx->dyn_pool)) {
        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " create pool error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        goto FAIL;
    }
    dyn_pool = ctx->dyn_pool;

    filter_keys = njt_array_create(dyn_pool, 1,
                                   sizeof(njt_http_vhost_traffic_status_filter_t));
    if (filter_keys == NULL) {
        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " create array error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        goto FAIL;
    }

    filter = njt_array_push(filter_keys);
    if (filter == NULL) {
        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " push array error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        goto FAIL;
    }

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));
    njt_memzero(&first, sizeof(njt_str_t));
    njt_memzero(&second, sizeof(njt_str_t));

    len = dynconf->len;
    filter_data = njt_pcalloc(dyn_pool, len+1);
    njt_memcpy(filter_data, dynconf->data, len);

    /* first argument */
    data = filter_data;
    while (data < filter_data + len) {
        if (*data++ == '\"') {
            break;
        }
    }
    if (data < filter_data + len) {
        first.data = data;
    }

    while (data < filter_data + len) {
        if (*data++ == '\"') {
            break;
        }
    }
    if (data <= filter_data + len) {
        first.len = data - first.data - 1;
    }

    /* second argument */
    while (data <= filter_data + len) {
        if (*data++ == '\"') {
            break;
        }
    }
    if (data < filter_data + len) {
        second.data = data;
    }

    while (data < filter_data + len) {
        if (*data++ == '\"') {
            break;
        }
    }
    if (data <= filter_data + len) {
        second.len = data - second.data - 1;
    }

    //check whther has two param at least
    if (first.data == NULL || first.len < 1
        || second.data == NULL || second.len < 1) {
        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " need at least two param in filter key");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        goto FAIL;
    }

    flag = 0;

    while (data < filter_data + len) {
        if (*data++ != ' ') {
            flag = 1;
            break;
        }
    }

    if (flag) {
        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " found too much data in filter key");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        goto FAIL;
    }

    njt_memzero(&conf, sizeof(njt_conf_t));
    conf.args = njt_array_create(dyn_pool, 10, sizeof(njt_str_t));
    if (conf.args == NULL) {
        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " create array error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        goto FAIL;
    }

    conf.temp_pool = dyn_pool;
    conf.ctx = (njt_http_conf_ctx_t *)njt_get_conf(cycle->conf_ctx, njt_http_module);
    conf.cycle = cycle;
    conf.pool = dyn_pool;
    conf.log = cycle->log;
    conf.module_type = NJT_HTTP_MODULE;
    conf.cmd_type = NJT_HTTP_MAIN_CONF;
    conf.dynamic = 1;

    /* first argument process */
    ccv.cf = &conf;
    ccv.value = &first;
    ccv.complex_value = &filter->filter_key;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " compile complex value error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        goto FAIL;
    }

    /* second argument process */
    ccv.value = &second;
    ccv.complex_value = &filter->filter_name;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " compile complex value error");
        rpc_data_str.len = end - data_buf;
        njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
        goto FAIL;
    }

    ctx->filter_keys_dyn = filter_keys;
    njt_http_variables_init_vars_dyn(&conf);
    njt_rpc_result_add_success_count(rpc_result);
    return;

FAIL:
    njt_log_error(NJT_LOG_INFO, cycle->pool->log, 0, "failed to update vts filter: %V", dynconf);
    return;
}


static njt_int_t njt_dynvts_update(njt_pool_t *pool, dyn_vts_t *api_data, njt_rpc_result_t *rpc_result)
{
    njt_cycle_t                 *cycle;
    njt_http_core_srv_conf_t    *cscf;
    njt_http_core_loc_conf_t    *clcf;
    dyn_vts_servers_item_t      *dsi;
    njt_uint_t                   i;
    u_char                       data_buf[128];
    u_char                      *end;
    njt_str_t                    rpc_data_str;
    njt_str_t                   *port, *serverName;
    njt_int_t                    rc;

    rpc_data_str.len = 0;
    rpc_data_str.data = data_buf;
    njt_rpc_result_set_conf_path(rpc_result, &rpc_data_str);

    cycle = (njt_cycle_t*)njt_cycle;

    if (api_data->is_vhost_traffic_status_filter_by_set_key_set && api_data->vhost_traffic_status_filter_by_set_key.len > 0) {
        njt_dynvts_update_filter(cycle, &api_data->vhost_traffic_status_filter_by_set_key, rpc_result);
    }

    if(api_data->is_servers_set && api_data->servers != NULL){
        for (i = 0; i < api_data->servers->nelts; ++i) {
            dsi = get_dyn_vts_servers_item(api_data->servers, i);
            if (dsi == NULL || !dsi->is_listens_set || !dsi->is_serverNames_set 
                    || dsi->listens->nelts < 1 
                    || dsi->serverNames->nelts < 1) {
                // listens or server_names is empty
                end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
                    " server parameters error, listens or serverNames is empty,at position %d", i);
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                continue;
            }

            port = get_dyn_vts_servers_item_listens_item(dsi->listens, 0);
            serverName = get_dyn_vts_servers_item_serverNames_item(dsi->serverNames, 0);
            njt_str_null(&rpc_result->conf_path);

            cscf = njt_http_get_srv_by_port(cycle, port, serverName);
            if (cscf == NULL)
            {
                njt_log_error(NJT_LOG_INFO, pool->log, 0, "can`t find server by listen:%V server_name:%V ",
                            port, serverName);
                end = njt_snprintf(data_buf, sizeof(data_buf) - 1, 
                    " can`t find server by listen[%V] server_name[%V]", port, serverName);
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                continue;
            }

            njt_log_error(NJT_LOG_INFO, pool->log, 0, "dyn vts start update listen:%V server_name:%V",
                    port, serverName);

            end = njt_snprintf(data_buf, sizeof(data_buf) - 1, "listen[%V] server_name[%V]", port, serverName);
            rpc_data_str.len = end - data_buf;
            njt_rpc_result_set_conf_path(rpc_result, &rpc_data_str);
                    
            clcf = njt_http_get_module_loc_conf(cscf->ctx, njt_http_core_module);
            if(clcf == NULL){
                njt_log_error(NJT_LOG_INFO, pool->log, 0, "can`t find location config by listen:%V server_name:%V ",
                            port, serverName);
                end = njt_snprintf(data_buf, sizeof(data_buf) - 1, " can`t find location config by listen[%V] server_name[%V]", port, serverName);
                rpc_data_str.len = end - data_buf;
                njt_rpc_result_add_error_data(rpc_result, &rpc_data_str);
                continue;
            }

            if(dsi->is_locations_set && dsi->locations->nelts > 0){
                rc = njt_dynvts_update_locs(dsi->locations, clcf->old_locations, rpc_result);
                if(rc != NJT_OK){
                    njt_log_error(NJT_LOG_INFO, pool->log, 0, "update vts error, listen:%V server_name:%V",
                        port, serverName);
                }
            }
        }
    }

    njt_rpc_result_update_code(rpc_result);
    return NJT_OK;
}


static u_char* njt_agent_vts_rpc_get_handler(njt_str_t *topic, njt_str_t *request, int* len, void *data)
{
    njt_cycle_t     *cycle;
    njt_str_t        *msg;
    u_char          *buf;
    njt_pool_t      *pool = NULL;

    buf = NULL;
    cycle = (njt_cycle_t*) njt_cycle;
    *len = 0 ;
    
    pool = njt_create_pool(njt_pagesize, njt_cycle->log);
    if(pool == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_agent_vts_rpc_get_handler create pool error");
        goto out;
    }

    msg = njt_vts_dynapi_dump_vts_conf(cycle, pool);
    buf = njt_calloc(msg->len, cycle->log);
    if(buf == NULL){
        goto out;
    }

    njt_log_error(NJT_LOG_INFO, pool->log, 0, "send json : %V", msg);
    njt_memcpy(buf, msg->data, msg->len);
    *len = msg->len;

out:
    if(pool != NULL) {
        njt_destroy_pool(pool);
    }

    return buf;
}


static int  njt_agent_vts_change_handler_internal(njt_str_t *key, njt_str_t *value, void *data, njt_str_t *out_msg)
{
    njt_int_t                    rc = NJT_ERROR;
    njt_pool_t                  *pool = NULL;
    njt_rpc_result_t            *rpc_result = NULL;
    js2c_parse_error_t          err_info;
    dyn_vts_t                   *api_data = NULL;

    if (value->len < 2) {
        return NJT_OK;
    }

    rpc_result = njt_rpc_result_create();
    if (!rpc_result) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "can't create rpc result");
        goto out;
    }
    njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_SUCCESS);

    pool = njt_create_pool(njt_pagesize,njt_cycle->log);
    if(pool == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_agent_vts_change_handler create pool error");
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_MEM_ALLOC);
        return NJT_OK;
    }

    api_data = json_parse_dyn_vts(pool, value, &err_info);
    if (api_data == NULL)
    {
        njt_log_error(NJT_LOG_ERR, pool->log, 0, 
                "json_parse_dyn_vts err: %V",  &err_info.err_str);
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR_JSON);
        njt_rpc_result_set_msg2(rpc_result, &err_info.err_str);

        rc = NJT_ERROR;
        goto out;
    }

    njt_rpc_result_set_code(rpc_result,NJT_RPC_RSP_SUCCESS);

    rc = njt_dynvts_update(pool, api_data, rpc_result);
    if(rc != NJT_OK){
        njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_ERR);
        njt_rpc_result_set_msg(rpc_result, (u_char *)" vts update fail");
    }else{
        if(rpc_result->data != NULL && rpc_result->data->nelts > 0){
            njt_rpc_result_set_code(rpc_result, NJT_RPC_RSP_PARTIAL_SUCCESS);
        }
    }

    if (rc != NJT_OK) {
        njt_str_t msg = njt_string("");
        njt_kv_sendmsg(key, &msg, 0);
    }

out:
    if (out_msg) {
        njt_rpc_result_to_json_str(rpc_result, out_msg);
    }

    if(pool != NULL){
        njt_destroy_pool(pool);
    }
    if (rpc_result) {
        njt_rpc_result_destroy(rpc_result);
    }
    return rc;
}


static int  njt_agent_vts_change_handler(njt_str_t *key, njt_str_t *value, void *data)
{
    return njt_agent_vts_change_handler_internal(key, value, data, NULL);
}

static u_char* njt_agent_vts_rpc_put_handler(njt_str_t *topic, njt_str_t *request, int* len, void *data)
{
    njt_str_t err_json_msg;
    njt_str_null(&err_json_msg);
    njt_agent_vts_change_handler_internal(topic, request, data, &err_json_msg);
    *len = err_json_msg.len;
    return err_json_msg.data;
}


static njt_int_t njt_agent_vts_init_process(njt_cycle_t* cycle)
{
    njt_str_t  vts_rpc_key = njt_string("http_vts");
    njt_kv_reg_handler_t h;
    njt_memzero(&h, sizeof(njt_kv_reg_handler_t));
    h.key = &vts_rpc_key;
    h.rpc_get_handler = njt_agent_vts_rpc_get_handler;
    h.rpc_put_handler = njt_agent_vts_rpc_put_handler;
    h.handler = njt_agent_vts_change_handler;
    h.api_type = NJT_KV_API_TYPE_DECLATIVE;
    njt_kv_reg_handler(&h);
    return NJT_OK;
}

#endif
