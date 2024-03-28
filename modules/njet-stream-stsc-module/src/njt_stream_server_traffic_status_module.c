
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#include <njt_config.h>

#include "njt_stream_server_traffic_status_module.h"
#include "njt_stream_server_traffic_status_variables.h"
#include "njt_stream_server_traffic_status_shm.h"
#include "njt_stream_server_traffic_status_filter.h"
#include "njt_stream_server_traffic_status_limit.h"


static njt_int_t njt_stream_server_traffic_status_handler(njt_stream_session_t *s);

static void njt_stream_server_traffic_status_rbtree_insert_value(
    njt_rbtree_node_t *temp, njt_rbtree_node_t *node,
    njt_rbtree_node_t *sentinel);
static njt_int_t njt_stream_server_traffic_status_init_zone(
    njt_shm_zone_t *shm_zone, void *data);
static char *njt_stream_server_traffic_status_zone(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);
static char *njt_stream_server_traffic_status_average_method(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);
static char *njt_stream_server_traffic_status_histogram_buckets(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);

static njt_int_t njt_stream_server_traffic_status_preconfiguration(njt_conf_t *cf);
static void *njt_stream_server_traffic_status_create_main_conf(njt_conf_t *cf);
static char *njt_stream_server_traffic_status_init_main_conf(njt_conf_t *cf,
    void *conf);
static void *njt_stream_server_traffic_status_create_loc_conf(njt_conf_t *cf);
static char *njt_stream_server_traffic_status_merge_loc_conf(njt_conf_t *cf,
    void *parent, void *child);
static njt_int_t njt_stream_server_traffic_status_init(njt_conf_t *cf);


static njt_conf_enum_t  njt_stream_server_traffic_status_average_method_post[] = {
    { njt_string("AMM"), NJT_STREAM_SERVER_TRAFFIC_STATUS_AVERAGE_METHOD_AMM },
    { njt_string("WMA"), NJT_STREAM_SERVER_TRAFFIC_STATUS_AVERAGE_METHOD_WMA },
    { njt_null_string, 0 }
};


static njt_command_t njt_stream_server_traffic_status_commands[] = {

    { njt_string("server_traffic_status"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_server_traffic_status_conf_t, enable),
      NULL },

    { njt_string("server_traffic_status_filter"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_server_traffic_status_conf_t, filter),
      NULL },

    { njt_string("server_traffic_status_filter_check_duplicate"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_server_traffic_status_conf_t, filter_check_duplicate),
      NULL },

    { njt_string("server_traffic_status_filter_by_set_key"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE12,
      njt_stream_server_traffic_status_filter_by_set_key,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("server_traffic_status_limit"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_server_traffic_status_conf_t, limit),
      NULL },

    { njt_string("server_traffic_status_limit_check_duplicate"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_server_traffic_status_conf_t, limit_check_duplicate),
      NULL },

    { njt_string("server_traffic_status_limit_traffic"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE12,
      njt_stream_server_traffic_status_limit_traffic,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("server_traffic_status_limit_traffic_by_set_key"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE23,
      njt_stream_server_traffic_status_limit_traffic_by_set_key,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("server_traffic_status_zone"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_NOARGS|NJT_CONF_TAKE1,
      njt_stream_server_traffic_status_zone,
      0,
      0,
      NULL },

    { njt_string("server_traffic_status_average_method"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE12,
      njt_stream_server_traffic_status_average_method,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("server_traffic_status_histogram_buckets"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_1MORE,
      njt_stream_server_traffic_status_histogram_buckets,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    njt_null_command
};


static njt_stream_module_t njt_stream_server_traffic_status_module_ctx = {
    njt_stream_server_traffic_status_preconfiguration, /* preconfiguration */
    njt_stream_server_traffic_status_init,             /* postconfiguration */

    njt_stream_server_traffic_status_create_main_conf, /* create main configuration */
    njt_stream_server_traffic_status_init_main_conf,   /* init main configuration */

    njt_stream_server_traffic_status_create_loc_conf,  /* create server configuration */
    njt_stream_server_traffic_status_merge_loc_conf,   /* merge server configuration */
};


njt_module_t njt_stream_stsc_module = {
    NJT_MODULE_V1,
    &njt_stream_server_traffic_status_module_ctx,      /* module context */
    njt_stream_server_traffic_status_commands,         /* module directives */
    NJT_STREAM_MODULE,                                 /* module type */
    NULL,                                              /* init master */
    NULL,                                              /* init module */
    NULL,                                              /* init process */
    NULL,                                              /* init thread */
    NULL,                                              /* exit thread */
    NULL,                                              /* exit process */
    NULL,                                              /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_int_t
njt_stream_server_traffic_status_handler(njt_stream_session_t *s)
{
    njt_int_t                                 rc;
    njt_stream_server_traffic_status_ctx_t   *ctx;
    njt_stream_server_traffic_status_conf_t  *stscf;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream sts handler");

    ctx = njt_stream_get_module_main_conf(s, njt_stream_stsc_module);
    stscf = njt_stream_get_module_srv_conf(s, njt_stream_stsc_module);

    if (!ctx->enable || !stscf->enable) {
        return NJT_DECLINED;
    }
    if (stscf->shm_zone == NULL) {
        return NJT_DECLINED;
    }

    rc = njt_stream_server_traffic_status_shm_add_server(s);
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                      "handler::shm_add_server() failed");
    }

    rc = njt_stream_server_traffic_status_shm_add_upstream(s);
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                      "handler::shm_add_upstream() failed");
    }

    rc = njt_stream_server_traffic_status_shm_add_filter(s);
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                      "handler::shm_add_filter() failed");
    }

    return NJT_DECLINED;
}


njt_msec_t
njt_stream_server_traffic_status_current_msec(void)
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
njt_stream_server_traffic_status_session_time(njt_stream_session_t *s)
{
    njt_time_t      *tp;
    njt_msec_int_t   ms;

    tp = njt_timeofday();

    ms = (njt_msec_int_t)
             ((tp->sec - s->start_sec) * 1000 + (tp->msec - s->start_msec));
    return njt_max(ms, 0);
}


njt_msec_int_t
njt_stream_server_traffic_status_upstream_response_time(njt_stream_session_t *s, uintptr_t data)
{
    njt_uint_t                    i;
    njt_msec_int_t                ms;
    njt_stream_upstream_state_t  *state;

    i = 0;
    ms = 0;
    state = s->upstream_states->elts;

    for ( ;; ) {

        if (data == 1) {
            if (state[i].first_byte_time == (njt_msec_t) -1) {
                goto next;
            }

            ms += state[i].first_byte_time;

        } else if (data == 2 && state[i].connect_time != (njt_msec_t) -1) {
            ms += state[i].connect_time;

        } else {
            ms += state[i].response_time;
        }

    next:

        if (++i == s->upstream_states->nelts) {
            break;
        }
    }

    return njt_max(ms, 0);
}


static void
njt_stream_server_traffic_status_rbtree_insert_value(njt_rbtree_node_t *temp,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel)
{
    njt_rbtree_node_t                        **p;
    njt_stream_server_traffic_status_node_t   *stsn, *stsnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            stsn = (njt_stream_server_traffic_status_node_t *) &node->color;
            stsnt = (njt_stream_server_traffic_status_node_t *) &temp->color;

            p = (njt_memn2cmp(stsn->data, stsnt->data, stsn->len, stsnt->len) < 0)
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
njt_stream_server_traffic_status_init_zone(njt_shm_zone_t *shm_zone, void *data)
{
    njt_stream_server_traffic_status_ctx_t  *octx = data;

    size_t                                   len;
    njt_slab_pool_t                         *shpool;
    njt_rbtree_node_t                       *sentinel;
    njt_stream_server_traffic_status_ctx_t  *ctx;

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
                    njt_stream_server_traffic_status_rbtree_insert_value);

    len = sizeof(" in server_traffic_status_zone \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = njt_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NJT_ERROR;
    }

    njt_sprintf(shpool->log_ctx, " in server_traffic_status_zone \"%V\"%Z",
                &shm_zone->shm.name);

    return NJT_OK;
}


static char *
njt_stream_server_traffic_status_zone(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    u_char                                  *p;
    ssize_t                                  size;
    njt_str_t                               *value, name, s;
    njt_uint_t                               i;
    njt_shm_zone_t                          *shm_zone;
    njt_stream_server_traffic_status_ctx_t  *ctx;

    value = cf->args->elts;

    ctx = njt_stream_conf_get_module_main_conf(cf, njt_stream_stsc_module);
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }

    ctx->enable = 1;

    njt_str_set(&name, NJT_STREAM_SERVER_TRAFFIC_STATUS_DEFAULT_SHM_NAME);

    size = NJT_STREAM_SERVER_TRAFFIC_STATUS_DEFAULT_SHM_SIZE;

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
                                     &njt_stream_stsc_module);
    if (shm_zone == NULL) {
        return NJT_CONF_ERROR;
    }

    if (shm_zone->data) {
        ctx = shm_zone->data;

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "server_traffic_status: \"%V\" is already bound to key",
                           &name);

        return NJT_CONF_ERROR;
    }

    ctx->shm_name = name;
    ctx->shm_size = size;
    shm_zone->init = njt_stream_server_traffic_status_init_zone;
    shm_zone->data = ctx;

    return NJT_CONF_OK;
}


static char *
njt_stream_server_traffic_status_average_method(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    njt_stream_server_traffic_status_conf_t *stscf = conf;

    char       *rv;
    njt_int_t   rc;
    njt_str_t  *value;

    value = cf->args->elts;

    cmd->offset = offsetof(njt_stream_server_traffic_status_conf_t, average_method);
    cmd->post = &njt_stream_server_traffic_status_average_method_post;

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


static char *
njt_stream_server_traffic_status_histogram_buckets(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    njt_stream_server_traffic_status_conf_t *stscf = conf;

    njt_str_t                                          *value;
    njt_int_t                                           n;
    njt_uint_t                                          i;
    njt_array_t                                        *histogram_buckets;
    njt_stream_server_traffic_status_node_histogram_t  *buckets;

    histogram_buckets = njt_array_create(cf->pool, 1,
                            sizeof(njt_stream_server_traffic_status_node_histogram_t));
    if (histogram_buckets == NULL) {
        goto invalid;
    }

    value = cf->args->elts;

    /* arguments process */
    for (i = 1; i < cf->args->nelts; i++) {
        if (i > NJT_STREAM_SERVER_TRAFFIC_STATUS_DEFAULT_BUCKET_LEN) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "histogram bucket size exceeds %d",
                               NJT_STREAM_SERVER_TRAFFIC_STATUS_DEFAULT_BUCKET_LEN);
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

    stscf->histogram_buckets = histogram_buckets;

    return NJT_CONF_OK;

invalid:

    return NJT_CONF_ERROR;
}


static njt_int_t
njt_stream_server_traffic_status_preconfiguration(njt_conf_t *cf)
{
    return njt_stream_server_traffic_status_add_variables(cf);
}


static void *
njt_stream_server_traffic_status_create_main_conf(njt_conf_t *cf)
{
    njt_stream_server_traffic_status_ctx_t  *ctx;

    ctx = njt_pcalloc(cf->pool, sizeof(njt_stream_server_traffic_status_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->enable = NJT_CONF_UNSET;
    ctx->filter_check_duplicate = NJT_CONF_UNSET;
    ctx->limit_check_duplicate = NJT_CONF_UNSET;
    ctx->upstream = NJT_CONF_UNSET_PTR;

    return ctx;
}


static char *
njt_stream_server_traffic_status_init_main_conf(njt_conf_t *cf, void *conf)
{
    njt_stream_server_traffic_status_ctx_t  *ctx = conf;

    njt_int_t                                 rc;
    njt_stream_server_traffic_status_conf_t  *stscf;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, cf->log, 0,
                   "stream sts init main conf");

    stscf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_stsc_module);

    if (stscf->filter_check_duplicate != 0) {
        rc = njt_stream_server_traffic_status_filter_unique(cf->pool, &ctx->filter_keys);
        if (rc != NJT_OK) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "init_main_conf::filter_unique() failed");
            return NJT_CONF_ERROR;
        }
    }

    if (stscf->limit_check_duplicate != 0) {
        rc = njt_stream_server_traffic_status_limit_traffic_unique(cf->pool, &ctx->limit_traffics);
        if (rc != NJT_OK) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "init_main_conf::limit_traffic_unique(server) failed");
            return NJT_CONF_ERROR;
        }

        rc = njt_stream_server_traffic_status_limit_traffic_unique(cf->pool,
                                                                &ctx->limit_filter_traffics);
        if (rc != NJT_OK) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "init_main_conf::limit_traffic_unique(filter) failed");
            return NJT_CONF_ERROR;
        }
    }

    njt_conf_init_value(ctx->enable, 0);
    njt_conf_init_value(ctx->filter_check_duplicate, stscf->filter_check_duplicate);
    njt_conf_init_value(ctx->limit_check_duplicate, stscf->limit_check_duplicate);
    njt_conf_init_ptr_value(ctx->upstream, njt_stream_conf_get_module_main_conf(cf,
                                           njt_stream_upstream_module));

    return NJT_CONF_OK;
}


static void *
njt_stream_server_traffic_status_create_loc_conf(njt_conf_t *cf)
{
    njt_stream_server_traffic_status_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_stream_server_traffic_status_conf_t));
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
     *     conf->filter_check_duplicate = 0;
     *     conf->filter_keys = { NULL, ... };
     *
     *     conf->limit = 0;
     *     conf->limit_check_duplicate = 0;
     *     conf->limit_traffics = { NULL, ... };
     *     conf->limit_filter_traffics = { NULL, ... };
     *
     *     conf->stats = { 0, ... };
     *     conf->start_msec = 0;
     *
     *     conf->average_method = 0;
     *     conf->average_period = 0;
     *     conf->histogram_buckets = { NULL, ... };
     */

    conf->shm_zone = NJT_CONF_UNSET_PTR;
    conf->enable = NJT_CONF_UNSET;
    conf->filter = NJT_CONF_UNSET;
    conf->filter_check_duplicate = NJT_CONF_UNSET;
    conf->limit = NJT_CONF_UNSET;
    conf->limit_check_duplicate = NJT_CONF_UNSET;
    conf->start_msec = njt_stream_server_traffic_status_current_msec();

    conf->average_method = NJT_CONF_UNSET;
    conf->average_period = NJT_CONF_UNSET_MSEC;
    conf->histogram_buckets = NJT_CONF_UNSET_PTR;

    conf->node_caches = njt_pcalloc(cf->pool, sizeof(njt_rbtree_node_t *)
                                    * (NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_FG + 1));
    conf->node_caches[NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_NO] = NULL;
    conf->node_caches[NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_UA] = NULL;
    conf->node_caches[NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_UG] = NULL;
    conf->node_caches[NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_FG] = NULL;

    return conf;
}


static char *
njt_stream_server_traffic_status_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_stream_server_traffic_status_conf_t *prev = parent;
    njt_stream_server_traffic_status_conf_t *conf = child;

    njt_int_t                                rc;
    njt_str_t                                name;
    njt_shm_zone_t                          *shm_zone;
    njt_stream_server_traffic_status_ctx_t  *ctx;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, cf->log, 0,
                   "stream sts merge loc conf");

    ctx = njt_stream_conf_get_module_main_conf(cf, njt_stream_stsc_module);

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
            rc = njt_stream_server_traffic_status_filter_unique(cf->pool, &conf->filter_keys);
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
            rc = njt_stream_server_traffic_status_limit_traffic_unique(cf->pool,
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
            rc = njt_stream_server_traffic_status_limit_traffic_unique(cf->pool,
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
    njt_conf_merge_value(conf->filter_check_duplicate, prev->filter_check_duplicate, 1);
    njt_conf_merge_value(conf->limit, prev->limit, 1);
    njt_conf_merge_value(conf->limit_check_duplicate, prev->limit_check_duplicate, 1);

    njt_conf_merge_value(conf->average_method, prev->average_method,
                         NJT_STREAM_SERVER_TRAFFIC_STATUS_AVERAGE_METHOD_AMM);
    njt_conf_merge_msec_value(conf->average_period, prev->average_period,
                              NJT_STREAM_SERVER_TRAFFIC_STATUS_DEFAULT_AVG_PERIOD * 1000);
    njt_conf_merge_ptr_value(conf->histogram_buckets, prev->histogram_buckets, NULL);

    name = ctx->shm_name;

    shm_zone = njt_shared_memory_add(cf, &name, 0,
                                     &njt_stream_stsc_module);
    if (shm_zone == NULL) {
        return NJT_CONF_ERROR;
    }

    conf->shm_zone = shm_zone;
    conf->shm_name = name;

    return NJT_CONF_OK;
}


static njt_int_t
njt_stream_server_traffic_status_init(njt_conf_t *cf)
{
    njt_stream_handler_pt        *h;
    njt_stream_core_main_conf_t  *cmcf;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, cf->log, 0,
                   "stream sts init");

    cmcf = njt_stream_conf_get_module_main_conf(cf, njt_stream_core_module);

    h = njt_array_push(&cmcf->phases[NJT_STREAM_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_stream_server_traffic_status_limit_handler;

    h = njt_array_push(&cmcf->phases[NJT_STREAM_LOG_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_stream_server_traffic_status_handler;

    return NJT_OK;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
