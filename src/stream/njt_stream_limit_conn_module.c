
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>


#define NJT_STREAM_LIMIT_CONN_PASSED            1
#define NJT_STREAM_LIMIT_CONN_REJECTED          2
#define NJT_STREAM_LIMIT_CONN_REJECTED_DRY_RUN  3


typedef struct {
    u_char                          color;
    u_char                          len;
    u_short                         conn;
    u_char                          data[1];
} njt_stream_limit_conn_node_t;


typedef struct {
    njt_shm_zone_t                 *shm_zone;
    njt_rbtree_node_t              *node;
} njt_stream_limit_conn_cleanup_t;


typedef struct {
    njt_rbtree_t                    rbtree;
    njt_rbtree_node_t               sentinel;
} njt_stream_limit_conn_shctx_t;


typedef struct {
    njt_stream_limit_conn_shctx_t  *sh;
    njt_slab_pool_t                *shpool;
    njt_stream_complex_value_t      key;
} njt_stream_limit_conn_ctx_t;


typedef struct {
    njt_shm_zone_t                 *shm_zone;
    njt_uint_t                      conn;
} njt_stream_limit_conn_limit_t;


typedef struct {
    njt_array_t                     limits;
    njt_uint_t                      log_level;
    njt_flag_t                      dry_run;
} njt_stream_limit_conn_conf_t;


static njt_rbtree_node_t *njt_stream_limit_conn_lookup(njt_rbtree_t *rbtree,
    njt_str_t *key, uint32_t hash);
static void njt_stream_limit_conn_cleanup(void *data);
static njt_inline void njt_stream_limit_conn_cleanup_all(njt_pool_t *pool);

static njt_int_t njt_stream_limit_conn_status_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data);
static void *njt_stream_limit_conn_create_conf(njt_conf_t *cf);
static char *njt_stream_limit_conn_merge_conf(njt_conf_t *cf, void *parent,
    void *child);
static char *njt_stream_limit_conn_zone(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_stream_limit_conn(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static njt_int_t njt_stream_limit_conn_add_variables(njt_conf_t *cf);
static njt_int_t njt_stream_limit_conn_init(njt_conf_t *cf);


static njt_conf_enum_t  njt_stream_limit_conn_log_levels[] = {
    { njt_string("info"), NJT_LOG_INFO },
    { njt_string("notice"), NJT_LOG_NOTICE },
    { njt_string("warn"), NJT_LOG_WARN },
    { njt_string("error"), NJT_LOG_ERR },
    { njt_null_string, 0 }
};


static njt_command_t  njt_stream_limit_conn_commands[] = {

    { njt_string("limit_conn_zone"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_TAKE2,
      njt_stream_limit_conn_zone,
      0,
      0,
      NULL },

    { njt_string("limit_conn"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE2,
      njt_stream_limit_conn,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("limit_conn_log_level"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_enum_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_limit_conn_conf_t, log_level),
      &njt_stream_limit_conn_log_levels },

    { njt_string("limit_conn_dry_run"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_limit_conn_conf_t, dry_run),
      NULL },

      njt_null_command
};


static njt_stream_module_t  njt_stream_limit_conn_module_ctx = {
    njt_stream_limit_conn_add_variables,   /* preconfiguration */
    njt_stream_limit_conn_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    njt_stream_limit_conn_create_conf,     /* create server configuration */
    njt_stream_limit_conn_merge_conf       /* merge server configuration */
};


njt_module_t  njt_stream_limit_conn_module = {
    NJT_MODULE_V1,
    &njt_stream_limit_conn_module_ctx,     /* module context */
    njt_stream_limit_conn_commands,        /* module directives */
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


static njt_stream_variable_t  njt_stream_limit_conn_vars[] = {

    { njt_string("limit_conn_status"), NULL,
      njt_stream_limit_conn_status_variable, 0, NJT_STREAM_VAR_NOCACHEABLE, 0 },

      njt_stream_null_variable
};


static njt_str_t  njt_stream_limit_conn_status[] = {
    njt_string("PASSED"),
    njt_string("REJECTED"),
    njt_string("REJECTED_DRY_RUN")
};


static njt_int_t
njt_stream_limit_conn_handler(njt_stream_session_t *s)
{
    size_t                            n;
    uint32_t                          hash;
    njt_str_t                         key;
    njt_uint_t                        i;
    njt_rbtree_node_t                *node;
    njt_pool_cleanup_t               *cln;
    njt_stream_limit_conn_ctx_t      *ctx;
    njt_stream_limit_conn_node_t     *lc;
    njt_stream_limit_conn_conf_t     *lccf;
    njt_stream_limit_conn_limit_t    *limits;
    njt_stream_limit_conn_cleanup_t  *lccln;

    lccf = njt_stream_get_module_srv_conf(s, njt_stream_limit_conn_module);
    limits = lccf->limits.elts;

    for (i = 0; i < lccf->limits.nelts; i++) {
        ctx = limits[i].shm_zone->data;

        if (njt_stream_complex_value(s, &ctx->key, &key) != NJT_OK) {
            return NJT_ERROR;
        }

        if (key.len == 0) {
            continue;
        }

        if (key.len > 255) {
            njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                          "the value of the \"%V\" key "
                          "is more than 255 bytes: \"%V\"",
                          &ctx->key.value, &key);
            continue;
        }

        s->limit_conn_status = NJT_STREAM_LIMIT_CONN_PASSED;

        hash = njt_crc32_short(key.data, key.len);

        njt_shmtx_lock(&ctx->shpool->mutex);

        node = njt_stream_limit_conn_lookup(&ctx->sh->rbtree, &key, hash);

        if (node == NULL) {

            n = offsetof(njt_rbtree_node_t, color)
                + offsetof(njt_stream_limit_conn_node_t, data)
                + key.len;

            node = njt_slab_alloc_locked(ctx->shpool, n);

            if (node == NULL) {
                njt_shmtx_unlock(&ctx->shpool->mutex);
                njt_stream_limit_conn_cleanup_all(s->connection->pool);

                if (lccf->dry_run) {
                    s->limit_conn_status =
                                        NJT_STREAM_LIMIT_CONN_REJECTED_DRY_RUN;
                    return NJT_DECLINED;
                }

                s->limit_conn_status = NJT_STREAM_LIMIT_CONN_REJECTED;

                return NJT_STREAM_SERVICE_UNAVAILABLE;
            }

            lc = (njt_stream_limit_conn_node_t *) &node->color;

            node->key = hash;
            lc->len = (u_char) key.len;
            lc->conn = 1;
            njt_memcpy(lc->data, key.data, key.len);

            njt_rbtree_insert(&ctx->sh->rbtree, node);

        } else {

            lc = (njt_stream_limit_conn_node_t *) &node->color;

            if ((njt_uint_t) lc->conn >= limits[i].conn) {

                njt_shmtx_unlock(&ctx->shpool->mutex);

                njt_log_error(lccf->log_level, s->connection->log, 0,
                              "limiting connections%s by zone \"%V\"",
                              lccf->dry_run ? ", dry run," : "",
                              &limits[i].shm_zone->shm.name);

                njt_stream_limit_conn_cleanup_all(s->connection->pool);

                if (lccf->dry_run) {
                    s->limit_conn_status =
                                        NJT_STREAM_LIMIT_CONN_REJECTED_DRY_RUN;
                    return NJT_DECLINED;
                }

                s->limit_conn_status = NJT_STREAM_LIMIT_CONN_REJECTED;

                return NJT_STREAM_SERVICE_UNAVAILABLE;
            }

            lc->conn++;
        }

        njt_log_debug2(NJT_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "limit conn: %08Xi %d", node->key, lc->conn);

        njt_shmtx_unlock(&ctx->shpool->mutex);

        cln = njt_pool_cleanup_add(s->connection->pool,
                                   sizeof(njt_stream_limit_conn_cleanup_t));
        if (cln == NULL) {
            return NJT_ERROR;
        }

        cln->handler = njt_stream_limit_conn_cleanup;
        lccln = cln->data;

        lccln->shm_zone = limits[i].shm_zone;
        lccln->node = node;
    }

    return NJT_DECLINED;
}


static void
njt_stream_limit_conn_rbtree_insert_value(njt_rbtree_node_t *temp,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel)
{
    njt_rbtree_node_t             **p;
    njt_stream_limit_conn_node_t   *lcn, *lcnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            lcn = (njt_stream_limit_conn_node_t *) &node->color;
            lcnt = (njt_stream_limit_conn_node_t *) &temp->color;

            p = (njt_memn2cmp(lcn->data, lcnt->data, lcn->len, lcnt->len) < 0)
                ? &temp->left : &temp->right;
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


static njt_rbtree_node_t *
njt_stream_limit_conn_lookup(njt_rbtree_t *rbtree, njt_str_t *key,
    uint32_t hash)
{
    njt_int_t                      rc;
    njt_rbtree_node_t             *node, *sentinel;
    njt_stream_limit_conn_node_t  *lcn;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        lcn = (njt_stream_limit_conn_node_t *) &node->color;

        rc = njt_memn2cmp(key->data, lcn->data, key->len, (size_t) lcn->len);

        if (rc == 0) {
            return node;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


static void
njt_stream_limit_conn_cleanup(void *data)
{
    njt_stream_limit_conn_cleanup_t  *lccln = data;

    njt_rbtree_node_t             *node;
    njt_stream_limit_conn_ctx_t   *ctx;
    njt_stream_limit_conn_node_t  *lc;

    ctx = lccln->shm_zone->data;
    node = lccln->node;
    lc = (njt_stream_limit_conn_node_t *) &node->color;

    njt_shmtx_lock(&ctx->shpool->mutex);

    njt_log_debug2(NJT_LOG_DEBUG_STREAM, lccln->shm_zone->shm.log, 0,
                   "limit conn cleanup: %08Xi %d", node->key, lc->conn);

    lc->conn--;

    if (lc->conn == 0) {
        njt_rbtree_delete(&ctx->sh->rbtree, node);
        njt_slab_free_locked(ctx->shpool, node);
    }

    njt_shmtx_unlock(&ctx->shpool->mutex);
}


static njt_inline void
njt_stream_limit_conn_cleanup_all(njt_pool_t *pool)
{
    njt_pool_cleanup_t  *cln;

    cln = pool->cleanup;

    while (cln && cln->handler == njt_stream_limit_conn_cleanup) {
        njt_stream_limit_conn_cleanup(cln->data);
        cln = cln->next;
    }

    pool->cleanup = cln;
}


static njt_int_t
njt_stream_limit_conn_init_zone(njt_shm_zone_t *shm_zone, void *data)
{
    njt_stream_limit_conn_ctx_t  *octx = data;

    size_t                        len;
    njt_stream_limit_conn_ctx_t  *ctx;

    ctx = shm_zone->data;

    if (octx) {
        if (ctx->key.value.len != octx->key.value.len
            || njt_strncmp(ctx->key.value.data, octx->key.value.data,
                           ctx->key.value.len)
               != 0)
        {
            njt_log_error(NJT_LOG_EMERG, shm_zone->shm.log, 0,
                          "limit_conn_zone \"%V\" uses the \"%V\" key "
                          "while previously it used the \"%V\" key",
                          &shm_zone->shm.name, &ctx->key.value,
                          &octx->key.value);
            return NJT_ERROR;
        }

        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;

        return NJT_OK;
    }

    ctx->shpool = (njt_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;

        return NJT_OK;
    }

    ctx->sh = njt_slab_alloc(ctx->shpool,
                             sizeof(njt_stream_limit_conn_shctx_t));
    if (ctx->sh == NULL) {
        return NJT_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    njt_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    njt_stream_limit_conn_rbtree_insert_value);

    len = sizeof(" in limit_conn_zone \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = njt_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NJT_ERROR;
    }

    njt_sprintf(ctx->shpool->log_ctx, " in limit_conn_zone \"%V\"%Z",
                &shm_zone->shm.name);

    return NJT_OK;
}


static njt_int_t
njt_stream_limit_conn_status_variable(njt_stream_session_t *s,
    njt_stream_variable_value_t *v, uintptr_t data)
{
    if (s->limit_conn_status == 0) {
        v->not_found = 1;
        return NJT_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = njt_stream_limit_conn_status[s->limit_conn_status - 1].len;
    v->data = njt_stream_limit_conn_status[s->limit_conn_status - 1].data;

    return NJT_OK;
}


static void *
njt_stream_limit_conn_create_conf(njt_conf_t *cf)
{
    njt_stream_limit_conn_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_stream_limit_conn_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->limits.elts = NULL;
     */

    conf->log_level = NJT_CONF_UNSET_UINT;
    conf->dry_run = NJT_CONF_UNSET;

    return conf;
}


static char *
njt_stream_limit_conn_merge_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_stream_limit_conn_conf_t *prev = parent;
    njt_stream_limit_conn_conf_t *conf = child;

    if (conf->limits.elts == NULL) {
        conf->limits = prev->limits;
    }

    njt_conf_merge_uint_value(conf->log_level, prev->log_level, NJT_LOG_ERR);

    njt_conf_merge_value(conf->dry_run, prev->dry_run, 0);

    return NJT_CONF_OK;
}


static char *
njt_stream_limit_conn_zone(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    u_char                              *p;
    ssize_t                              size;
    njt_str_t                           *value, name, s;
    njt_uint_t                           i;
    njt_shm_zone_t                      *shm_zone;
    njt_stream_limit_conn_ctx_t         *ctx;
    njt_stream_compile_complex_value_t   ccv;

    value = cf->args->elts;

    ctx = njt_pcalloc(cf->pool, sizeof(njt_stream_limit_conn_ctx_t));
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }

    njt_memzero(&ccv, sizeof(njt_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &ctx->key;

    if (njt_stream_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    size = 0;
    name.len = 0;

    for (i = 2; i < cf->args->nelts; i++) {

        if (njt_strncmp(value[i].data, "zone=", 5) == 0) {

            name.data = value[i].data + 5;

            p = (u_char *) njt_strchr(name.data, ':');

            if (p == NULL) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            name.len = p - name.data;

            s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;

            size = njt_parse_size(&s);

            if (size == NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            if (size < (ssize_t) (8 * njt_pagesize)) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "zone \"%V\" is too small", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NJT_CONF_ERROR;
    }

    if (name.len == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NJT_CONF_ERROR;
    }

    shm_zone = njt_shared_memory_add(cf, &name, size,
                                     &njt_stream_limit_conn_module);
    if (shm_zone == NULL) {
        return NJT_CONF_ERROR;
    }

    if (shm_zone->data) {
        ctx = shm_zone->data;

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "%V \"%V\" is already bound to key \"%V\"",
                           &cmd->name, &name, &ctx->key.value);
        return NJT_CONF_ERROR;
    }

    shm_zone->init = njt_stream_limit_conn_init_zone;
    shm_zone->data = ctx;

    return NJT_CONF_OK;
}


static char *
njt_stream_limit_conn(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_shm_zone_t                 *shm_zone;
    njt_stream_limit_conn_conf_t   *lccf = conf;
    njt_stream_limit_conn_limit_t  *limit, *limits;

    njt_str_t   *value;
    njt_int_t    n;
    njt_uint_t   i;

    value = cf->args->elts;

    shm_zone = njt_shared_memory_add(cf, &value[1], 0,
                                     &njt_stream_limit_conn_module);
    if (shm_zone == NULL) {
        return NJT_CONF_ERROR;
    }

    limits = lccf->limits.elts;

    if (limits == NULL) {
        if (njt_array_init(&lccf->limits, cf->pool, 1,
                           sizeof(njt_stream_limit_conn_limit_t))
            != NJT_OK)
        {
            return NJT_CONF_ERROR;
        }
    }

    for (i = 0; i < lccf->limits.nelts; i++) {
        if (shm_zone == limits[i].shm_zone) {
            return "is duplicate";
        }
    }

    n = njt_atoi(value[2].data, value[2].len);
    if (n <= 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid number of connections \"%V\"", &value[2]);
        return NJT_CONF_ERROR;
    }

    if (n > 65535) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "connection limit must be less 65536");
        return NJT_CONF_ERROR;
    }

    limit = njt_array_push(&lccf->limits);
    if (limit == NULL) {
        return NJT_CONF_ERROR;
    }

    limit->conn = n;
    limit->shm_zone = shm_zone;

    return NJT_CONF_OK;
}


static njt_int_t
njt_stream_limit_conn_add_variables(njt_conf_t *cf)
{
    njt_stream_variable_t  *var, *v;

    for (v = njt_stream_limit_conn_vars; v->name.len; v++) {
        var = njt_stream_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NJT_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NJT_OK;
}


static njt_int_t
njt_stream_limit_conn_init(njt_conf_t *cf)
{
    njt_stream_handler_pt        *h;
    njt_stream_core_main_conf_t  *cmcf;

    cmcf = njt_stream_conf_get_module_main_conf(cf, njt_stream_core_module);

    h = njt_array_push(&cmcf->phases[NJT_STREAM_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_stream_limit_conn_handler;

    return NJT_OK;
}
