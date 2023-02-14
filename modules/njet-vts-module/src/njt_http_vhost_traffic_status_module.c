
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 * Copyright (C) TMLake, Inc.
 */


#include "njt_http_vhost_traffic_status_module.h"
#include "njt_http_vhost_traffic_status_variables.h"
#include "njt_http_vhost_traffic_status_shm.h"
#include "njt_http_vhost_traffic_status_filter.h"
#include "njt_http_vhost_traffic_status_limit.h"
#include "njt_http_vhost_traffic_status_display.h"
#include "njt_http_vhost_traffic_status_set.h"
#include "njt_http_vhost_traffic_status_dump.h"


static njt_int_t njt_http_vhost_traffic_status_handler(njt_http_request_t *r);

static void njt_http_vhost_traffic_status_rbtree_insert_value(
    njt_rbtree_node_t *temp, njt_rbtree_node_t *node,
    njt_rbtree_node_t *sentinel);
static njt_int_t njt_http_vhost_traffic_status_init_zone(
    njt_shm_zone_t *shm_zone, void *data);
static char *njt_http_vhost_traffic_status_zone(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);
static char *njt_http_vhost_traffic_status_dump(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);
static char *njt_http_vhost_traffic_status_filter_max_node(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);
static char *njt_http_vhost_traffic_status_average_method(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);
static char *njt_http_vhost_traffic_status_histogram_buckets(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);

static njt_int_t njt_http_vhost_traffic_status_preconfiguration(njt_conf_t *cf);
static njt_int_t njt_http_vhost_traffic_status_init(njt_conf_t *cf);
static void *njt_http_vhost_traffic_status_create_main_conf(njt_conf_t *cf);
static char *njt_http_vhost_traffic_status_init_main_conf(njt_conf_t *cf,
    void *conf);
static void *njt_http_vhost_traffic_status_create_loc_conf(njt_conf_t *cf);
static char *njt_http_vhost_traffic_status_merge_loc_conf(njt_conf_t *cf,
    void *parent, void *child);
static njt_int_t njt_http_vhost_traffic_status_init_worker(njt_cycle_t *cycle);
static void njt_http_vhost_traffic_status_exit_worker(njt_cycle_t *cycle);


static njt_conf_enum_t  njt_http_vhost_traffic_status_display_format[] = {
    { njt_string("json"), NJT_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSON },
    { njt_string("html"), NJT_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_HTML },
    { njt_string("jsonp"), NJT_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_JSONP },
    { njt_string("prometheus"), NJT_HTTP_VHOST_TRAFFIC_STATUS_FORMAT_PROMETHEUS },
    { njt_null_string, 0 }
};


static njt_conf_enum_t  njt_http_vhost_traffic_status_average_method_post[] = {
    { njt_string("AMM"), NJT_HTTP_VHOST_TRAFFIC_STATUS_AVERAGE_METHOD_AMM },
    { njt_string("WMA"), NJT_HTTP_VHOST_TRAFFIC_STATUS_AVERAGE_METHOD_WMA },
    { njt_null_string, 0 }
};


static njt_command_t njt_http_vhost_traffic_status_commands[] = {

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
      njt_http_vhost_traffic_status_filter_max_node,
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
      njt_http_vhost_traffic_status_zone,
      0,
      0,
      NULL },

    { njt_string("vhost_traffic_status_dump"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE12,
      njt_http_vhost_traffic_status_dump,
      0,
      0,
      NULL },

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
      &njt_http_vhost_traffic_status_display_format },

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

    { njt_string("vhost_traffic_status_set_by_filter"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF
                        |NJT_HTTP_LIF_CONF|NJT_CONF_TAKE2,
      njt_http_vhost_traffic_status_set_by_filter,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("vhost_traffic_status_average_method"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE12,
      njt_http_vhost_traffic_status_average_method,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("vhost_traffic_status_histogram_buckets"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_http_vhost_traffic_status_histogram_buckets,
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


static njt_http_module_t njt_http_vhost_traffic_status_module_ctx = {
    njt_http_vhost_traffic_status_preconfiguration, /* preconfiguration */
    njt_http_vhost_traffic_status_init,             /* postconfiguration */

    njt_http_vhost_traffic_status_create_main_conf, /* create main configuration */
    njt_http_vhost_traffic_status_init_main_conf,   /* init main configuration */

    NULL,                                           /* create server configuration */
    NULL,                                           /* merge server configuration */

    njt_http_vhost_traffic_status_create_loc_conf,  /* create location configuration */
    njt_http_vhost_traffic_status_merge_loc_conf,   /* merge location configuration */
};


njt_module_t njt_http_vhost_traffic_status_module = {
    NJT_MODULE_V1,
    &njt_http_vhost_traffic_status_module_ctx,   /* module context */
    njt_http_vhost_traffic_status_commands,      /* module directives */
    NJT_HTTP_MODULE,                             /* module type */
    NULL,                                        /* init master */
    NULL,                                        /* init module */
    njt_http_vhost_traffic_status_init_worker,   /* init process */
    NULL,                                        /* init thread */
    NULL,                                        /* exit thread */
    njt_http_vhost_traffic_status_exit_worker,   /* exit process */
    NULL,                                        /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_int_t
njt_http_vhost_traffic_status_handler(njt_http_request_t *r)
{
    njt_int_t                                  rc;
    njt_http_vhost_traffic_status_ctx_t       *ctx;
    njt_http_vhost_traffic_status_loc_conf_t  *vtscf;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http vts handler");

    ctx = njt_http_get_module_main_conf(r, njt_http_vhost_traffic_status_module);
    vtscf = njt_http_get_module_loc_conf(r, njt_http_vhost_traffic_status_module);

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


njt_msec_t
njt_http_vhost_traffic_status_current_msec(void)
{
    time_t           sec;
    njt_uint_t       msec;
    struct timeval   tv;

    njt_gettimeofday(&tv);

    sec = tv.tv_sec;
    msec = tv.tv_usec / 1000;

    return (njt_msec_t) sec * 1000 + msec;
}


njt_msec_int_t
njt_http_vhost_traffic_status_request_time(njt_http_request_t *r)
{
    njt_time_t      *tp;
    njt_msec_int_t   ms;

    tp = njt_timeofday();

    ms = (njt_msec_int_t)
             ((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));
    return njt_max(ms, 0);
}


njt_msec_int_t
njt_http_vhost_traffic_status_upstream_response_time(njt_http_request_t *r)
{
    njt_uint_t                  i;
    njt_msec_int_t              ms;
    njt_http_upstream_state_t  *state;

    state = r->upstream_states->elts;

    i = 0;
    ms = 0;
    for ( ;; ) {
        if (state[i].status) {

#if !defined(njet_version) || njet_version < 1009001
            ms += (njt_msec_int_t)
                  (state[i].response_sec * 1000 + state[i].response_msec);
#else
            ms += state[i].response_time;
#endif

        }
        if (++i == r->upstream_states->nelts) {
            break;
        }
    }
    return njt_max(ms, 0);
}


static void
njt_http_vhost_traffic_status_rbtree_insert_value(njt_rbtree_node_t *temp,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel)
{
    njt_rbtree_node_t                     **p;
    njt_http_vhost_traffic_status_node_t   *vtsn, *vtsnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            vtsn = (njt_http_vhost_traffic_status_node_t *) &node->color;
            vtsnt = (njt_http_vhost_traffic_status_node_t *) &temp->color;

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
njt_http_vhost_traffic_status_init_zone(njt_shm_zone_t *shm_zone, void *data)
{
    njt_http_vhost_traffic_status_ctx_t  *octx = data;

    size_t                                len;
    njt_slab_pool_t                      *shpool;
    njt_rbtree_node_t                    *sentinel;
    njt_http_vhost_traffic_status_ctx_t  *ctx;

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
                    njt_http_vhost_traffic_status_rbtree_insert_value);

    len = sizeof(" in vhost_traffic_status_zone \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = njt_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NJT_ERROR;
    }

    njt_sprintf(shpool->log_ctx, " in vhost_traffic_status_zone \"%V\"%Z",
                &shm_zone->shm.name);

    return NJT_OK;
}


static char *
njt_http_vhost_traffic_status_zone(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    u_char                               *p;
    ssize_t                               size;
    njt_str_t                            *value, name, s;
    njt_uint_t                            i;
    njt_shm_zone_t                       *shm_zone;
    njt_http_vhost_traffic_status_ctx_t  *ctx;

    value = cf->args->elts;

    ctx = njt_http_conf_get_module_main_conf(cf, njt_http_vhost_traffic_status_module);
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }

    ctx->enable = 1;

    njt_str_set(&name, NJT_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_SHM_NAME);

    size = NJT_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_SHM_SIZE;

    for (i = 1; i < cf->args->nelts; i++) {
        if (njt_strncmp(value[i].data, "shared:", 7) == 0) {

            name.data = value[i].data + 7;

            p = (u_char *) njt_strchr(name.data, ':');
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
                                     &njt_http_vhost_traffic_status_module);
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
    shm_zone->init = njt_http_vhost_traffic_status_init_zone;
    shm_zone->data = ctx;

    return NJT_CONF_OK;
}


static char *
njt_http_vhost_traffic_status_dump(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_vhost_traffic_status_ctx_t  *ctx = conf;

    njt_int_t   rc;
    njt_str_t  *value;

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
njt_http_vhost_traffic_status_filter_max_node(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    njt_http_vhost_traffic_status_ctx_t  *ctx = conf;

    njt_str_t                                     *value;
    njt_int_t                                      n;
    njt_uint_t                                     i;
    njt_array_t                                   *filter_max_node_matches;
    njt_http_vhost_traffic_status_filter_match_t  *matches;

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
njt_http_vhost_traffic_status_average_method(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    njt_http_vhost_traffic_status_loc_conf_t *vtscf = conf;

    char       *rv;
    njt_int_t   rc;
    njt_str_t  *value;

    value = cf->args->elts;

    cmd->offset = offsetof(njt_http_vhost_traffic_status_loc_conf_t, average_method);
    cmd->post = &njt_http_vhost_traffic_status_average_method_post;

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
njt_http_vhost_traffic_status_histogram_buckets(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    njt_http_vhost_traffic_status_loc_conf_t *vtscf = conf;

    njt_str_t                                       *value;
    njt_int_t                                        n;
    njt_uint_t                                       i;
    njt_array_t                                     *histogram_buckets;
    njt_http_vhost_traffic_status_node_histogram_t  *buckets;

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
njt_http_vhost_traffic_status_preconfiguration(njt_conf_t *cf)
{
    return njt_http_vhost_traffic_status_add_variables(cf);
}


static njt_int_t
njt_http_vhost_traffic_status_init(njt_conf_t *cf)
{
    njt_http_handler_pt        *h;
    njt_http_core_main_conf_t  *cmcf;

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

    *h = njt_http_vhost_traffic_status_handler;

    return NJT_OK;
}


static void *
njt_http_vhost_traffic_status_create_main_conf(njt_conf_t *cf)
{
    njt_http_vhost_traffic_status_ctx_t  *ctx;

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
njt_http_vhost_traffic_status_init_main_conf(njt_conf_t *cf, void *conf)
{
    njt_http_vhost_traffic_status_ctx_t  *ctx = conf;

    njt_int_t                                  rc;
    njt_http_vhost_traffic_status_loc_conf_t  *vtscf;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, cf->log, 0,
                   "http vts init main conf");

    vtscf = njt_http_conf_get_module_loc_conf(cf, njt_http_vhost_traffic_status_module);

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
njt_http_vhost_traffic_status_create_loc_conf(njt_conf_t *cf)
{
    njt_http_vhost_traffic_status_loc_conf_t  *conf;

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
njt_http_vhost_traffic_status_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_vhost_traffic_status_loc_conf_t *prev = parent;
    njt_http_vhost_traffic_status_loc_conf_t *conf = child;

    njt_int_t                             rc;
    njt_str_t                             name;
    njt_shm_zone_t                       *shm_zone;
    njt_http_vhost_traffic_status_ctx_t  *ctx;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, cf->log, 0,
                   "http vts merge loc conf");

    ctx = njt_http_conf_get_module_main_conf(cf, njt_http_vhost_traffic_status_module);

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
                                     &njt_http_vhost_traffic_status_module);
    if (shm_zone == NULL) {
        return NJT_CONF_ERROR;
    }

    conf->shm_zone = shm_zone;
    conf->shm_name = name;

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_vhost_traffic_status_init_worker(njt_cycle_t *cycle)
{
    njt_event_t                          *dump_event;
    njt_http_vhost_traffic_status_ctx_t  *ctx;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, cycle->log, 0,
                   "http vts init worker");

    ctx = njt_http_cycle_get_module_main_conf(cycle, njt_http_vhost_traffic_status_module);

    if (ctx == NULL) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, cycle->log, 0,
                       "vts::init_worker(): is bypassed due to no http block in configure file");
        return NJT_OK;
    }

    if (!(ctx->enable & ctx->dump) || ctx->rbtree == NULL) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, cycle->log, 0,
                       "vts::init_worker(): is bypassed");
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
njt_http_vhost_traffic_status_exit_worker(njt_cycle_t *cycle)
{
    njt_event_t                          *dump_event;
    njt_http_vhost_traffic_status_ctx_t  *ctx;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, cycle->log, 0,
                   "http vts exit worker");

    ctx = njt_http_cycle_get_module_main_conf(cycle, njt_http_vhost_traffic_status_module);

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

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
