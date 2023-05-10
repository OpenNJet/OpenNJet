
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_http_dyn_module.h>


#define NJT_HTTP_LIMIT_REQ_PASSED            1
#define NJT_HTTP_LIMIT_REQ_DELAYED           2
#define NJT_HTTP_LIMIT_REQ_REJECTED          3
#define NJT_HTTP_LIMIT_REQ_DELAYED_DRY_RUN   4
#define NJT_HTTP_LIMIT_REQ_REJECTED_DRY_RUN  5



static void njt_http_limit_req_delay(njt_http_request_t *r);
static njt_int_t njt_http_limit_req_lookup(njt_http_limit_req_limit_t *limit,
    njt_uint_t hash, njt_str_t *key, njt_uint_t *ep, njt_uint_t account);
static njt_msec_t njt_http_limit_req_account(njt_http_limit_req_limit_t *limits,
    njt_uint_t n, njt_uint_t *ep, njt_http_limit_req_limit_t **limit);
static void njt_http_limit_req_unlock(njt_http_limit_req_limit_t *limits,
    njt_uint_t n);
static void njt_http_limit_req_expire(njt_http_limit_req_ctx_t *ctx,
    njt_uint_t n);

static njt_int_t njt_http_limit_req_status_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static void *njt_http_limit_req_create_conf(njt_conf_t *cf);
static char *njt_http_limit_req_merge_conf(njt_conf_t *cf, void *parent,
    void *child);
static char *njt_http_limit_req_zone(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_limit_req(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static njt_int_t njt_http_limit_req_add_variables(njt_conf_t *cf);
static njt_int_t njt_http_limit_req_init(njt_conf_t *cf);



static njt_conf_enum_t  njt_http_limit_req_log_levels[] = {
    { njt_string("info"), NJT_LOG_INFO },
    { njt_string("notice"), NJT_LOG_NOTICE },
    { njt_string("warn"), NJT_LOG_WARN },
    { njt_string("error"), NJT_LOG_ERR },
    { njt_null_string, 0 }
};


static njt_conf_num_bounds_t  njt_http_limit_req_status_bounds = {
    njt_conf_check_num_bounds, 400, 599
};


static njt_command_t  njt_http_limit_req_commands[] = {

    { njt_string("limit_req_zone"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE3,
      njt_http_limit_req_zone,
      0,
      0,
      NULL },

    { njt_string("limit_req"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE123,
      njt_http_limit_req,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("limit_req_log_level"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_enum_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_limit_req_conf_t, limit_log_level),
      &njt_http_limit_req_log_levels },

    { njt_string("limit_req_status"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_limit_req_conf_t, status_code),
      &njt_http_limit_req_status_bounds },

    { njt_string("limit_req_dry_run"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_limit_req_conf_t, dry_run),
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_limit_req_module_ctx = {
    njt_http_limit_req_add_variables,      /* preconfiguration */
    njt_http_limit_req_init,               /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_limit_req_create_conf,        /* create location configuration */
    njt_http_limit_req_merge_conf          /* merge location configuration */
};


njt_module_t  njt_http_limit_req_module = {
    NJT_MODULE_V1,
    &njt_http_limit_req_module_ctx,        /* module context */
    njt_http_limit_req_commands,           /* module directives */
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


static njt_http_variable_t  njt_http_limit_req_vars[] = {

    { njt_string("limit_req_status"), NULL,
      njt_http_limit_req_status_variable, 0, NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

      njt_http_null_variable
};


static njt_str_t  njt_http_limit_req_status[] = {
    njt_string("PASSED"),
    njt_string("DELAYED"),
    njt_string("REJECTED"),
    njt_string("DELAYED_DRY_RUN"),
    njt_string("REJECTED_DRY_RUN")
};


static njt_int_t
njt_http_limit_req_handler(njt_http_request_t *r)
{
    uint32_t                     hash;
    njt_str_t                    key;
    njt_int_t                    rc;
    njt_uint_t                   n, excess;
    njt_msec_t                   delay;
    njt_http_limit_req_ctx_t    *ctx;
    njt_http_limit_req_conf_t   *lrcf;
    njt_http_limit_req_limit_t  *limit, *limits;

    if (r->main->limit_req_status) {
        return NJT_DECLINED;
    }

    lrcf = njt_http_get_module_loc_conf(r, njt_http_limit_req_module);
    limits = lrcf->limits.elts;

    excess = 0;

    rc = NJT_DECLINED;

#if (NJT_SUPPRESS_WARN)
    limit = NULL;
#endif

    for (n = 0; n < lrcf->limits.nelts; n++) {

        limit = &limits[n];

        ctx = limit->shm_zone->data;

        if (njt_http_complex_value(r, &ctx->key, &key) != NJT_OK) {
            njt_http_limit_req_unlock(limits, n);
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (key.len == 0) {
            continue;
        }

        if (key.len > 65535) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "the value of the \"%V\" key "
                          "is more than 65535 bytes: \"%V\"",
                          &ctx->key.value, &key);
            continue;
        }

        hash = njt_crc32_short(key.data, key.len);

        njt_shmtx_lock(&ctx->shpool->mutex);

        rc = njt_http_limit_req_lookup(limit, hash, &key, &excess,
                                       (n == lrcf->limits.nelts - 1));

        njt_shmtx_unlock(&ctx->shpool->mutex);

        njt_log_debug4(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "limit_req[%ui]: %i %ui.%03ui",
                       n, rc, excess / 1000, excess % 1000);

        if (rc != NJT_AGAIN) {
            break;
        }
    }

    if (rc == NJT_DECLINED) {
        return NJT_DECLINED;
    }

    if (rc == NJT_BUSY || rc == NJT_ERROR) {

        if (rc == NJT_BUSY) {
            njt_log_error(lrcf->limit_log_level, r->connection->log, 0,
                        "limiting requests%s, excess: %ui.%03ui by zone \"%V\"",
                        lrcf->dry_run ? ", dry run" : "",
                        excess / 1000, excess % 1000,
                        &limit->shm_zone->shm.name);
        }

        njt_http_limit_req_unlock(limits, n);

        if (lrcf->dry_run) {
            r->main->limit_req_status = NJT_HTTP_LIMIT_REQ_REJECTED_DRY_RUN;
            return NJT_DECLINED;
        }

        r->main->limit_req_status = NJT_HTTP_LIMIT_REQ_REJECTED;

        return lrcf->status_code;
    }

    /* rc == NJT_AGAIN || rc == NJT_OK */

    if (rc == NJT_AGAIN) {
        excess = 0;
    }

    delay = njt_http_limit_req_account(limits, n, &excess, &limit);

    if (!delay) {
        r->main->limit_req_status = NJT_HTTP_LIMIT_REQ_PASSED;
        return NJT_DECLINED;
    }

    njt_log_error(lrcf->delay_log_level, r->connection->log, 0,
                  "delaying request%s, excess: %ui.%03ui, by zone \"%V\"",
                  lrcf->dry_run ? ", dry run" : "",
                  excess / 1000, excess % 1000, &limit->shm_zone->shm.name);

    if (lrcf->dry_run) {
        r->main->limit_req_status = NJT_HTTP_LIMIT_REQ_DELAYED_DRY_RUN;
        return NJT_DECLINED;
    }

    r->main->limit_req_status = NJT_HTTP_LIMIT_REQ_DELAYED;

    if (r->connection->read->ready) {
        njt_post_event(r->connection->read, &njt_posted_events);

    } else {
        if (njt_handle_read_event(r->connection->read, 0) != NJT_OK) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    r->read_event_handler = njt_http_test_reading;
    r->write_event_handler = njt_http_limit_req_delay;

    r->connection->write->delayed = 1;
    njt_add_timer(r->connection->write, delay);

    return NJT_AGAIN;
}


static void
njt_http_limit_req_delay(njt_http_request_t *r)
{
    njt_event_t  *wev;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "limit_req delay");

    wev = r->connection->write;

    if (wev->delayed) {

        if (njt_handle_write_event(wev, 0) != NJT_OK) {
            njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        }

        return;
    }

    if (njt_handle_read_event(r->connection->read, 0) != NJT_OK) {
        njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    r->read_event_handler = njt_http_block_reading;
    r->write_event_handler = njt_http_core_run_phases;

    njt_http_core_run_phases(r);
}


static void
njt_http_limit_req_rbtree_insert_value(njt_rbtree_node_t *temp,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel)
{
    njt_rbtree_node_t          **p;
    njt_http_limit_req_node_t   *lrn, *lrnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            lrn = (njt_http_limit_req_node_t *) &node->color;
            lrnt = (njt_http_limit_req_node_t *) &temp->color;

            p = (njt_memn2cmp(lrn->data, lrnt->data, lrn->len, lrnt->len) < 0)
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


static njt_int_t
njt_http_limit_req_lookup(njt_http_limit_req_limit_t *limit, njt_uint_t hash,
    njt_str_t *key, njt_uint_t *ep, njt_uint_t account)
{
    size_t                      size;
    njt_int_t                   rc, excess;
    njt_msec_t                  now;
    njt_msec_int_t              ms;
    njt_rbtree_node_t          *node, *sentinel;
    njt_http_limit_req_ctx_t   *ctx;
    njt_http_limit_req_node_t  *lr;

    now = njt_current_msec;

    ctx = limit->shm_zone->data;

    node = ctx->sh->rbtree.root;
    sentinel = ctx->sh->rbtree.sentinel;

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

        lr = (njt_http_limit_req_node_t *) &node->color;

        rc = njt_memn2cmp(key->data, lr->data, key->len, (size_t) lr->len);

        if (rc == 0) {
            njt_queue_remove(&lr->queue);
            njt_queue_insert_head(&ctx->sh->queue, &lr->queue);

            ms = (njt_msec_int_t) (now - lr->last);

            if (ms < -60000) {
                ms = 1;

            } else if (ms < 0) {
                ms = 0;
            }

            excess = lr->excess - ctx->rate * ms / 1000 + 1000;

            if (excess < 0) {
                excess = 0;
            }

            *ep = excess;

            if ((njt_uint_t) excess > limit->burst) {
                return NJT_BUSY;
            }

            if (account) {
                lr->excess = excess;

                if (ms) {
                    lr->last = now;
                }

                return NJT_OK;
            }

            lr->count++;

            ctx->node = lr;

            return NJT_AGAIN;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    *ep = 0;

    size = offsetof(njt_rbtree_node_t, color)
           + offsetof(njt_http_limit_req_node_t, data)
           + key->len;

    njt_http_limit_req_expire(ctx, 1);

    node = njt_slab_alloc_locked(ctx->shpool, size);

    if (node == NULL) {
        njt_http_limit_req_expire(ctx, 0);

        node = njt_slab_alloc_locked(ctx->shpool, size);
        if (node == NULL) {
            njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
                          "could not allocate node%s", ctx->shpool->log_ctx);
            return NJT_ERROR;
        }
    }

    node->key = hash;

    lr = (njt_http_limit_req_node_t *) &node->color;

    lr->len = (u_short) key->len;
    lr->excess = 0;

    njt_memcpy(lr->data, key->data, key->len);

    njt_rbtree_insert(&ctx->sh->rbtree, node);

    njt_queue_insert_head(&ctx->sh->queue, &lr->queue);

    if (account) {
        lr->last = now;
        lr->count = 0;
        return NJT_OK;
    }

    lr->last = 0;
    lr->count = 1;

    ctx->node = lr;

    return NJT_AGAIN;
}


static njt_msec_t
njt_http_limit_req_account(njt_http_limit_req_limit_t *limits, njt_uint_t n,
    njt_uint_t *ep, njt_http_limit_req_limit_t **limit)
{
    njt_int_t                   excess;
    njt_msec_t                  now, delay, max_delay;
    njt_msec_int_t              ms;
    njt_http_limit_req_ctx_t   *ctx;
    njt_http_limit_req_node_t  *lr;

    excess = *ep;

    if ((njt_uint_t) excess <= (*limit)->delay) {
        max_delay = 0;

    } else {
        ctx = (*limit)->shm_zone->data;
        max_delay = (excess - (*limit)->delay) * 1000 / ctx->rate;
    }

    while (n--) {
        ctx = limits[n].shm_zone->data;
        lr = ctx->node;

        if (lr == NULL) {
            continue;
        }

        njt_shmtx_lock(&ctx->shpool->mutex);

        now = njt_current_msec;
        ms = (njt_msec_int_t) (now - lr->last);

        if (ms < -60000) {
            ms = 1;

        } else if (ms < 0) {
            ms = 0;
        }

        excess = lr->excess - ctx->rate * ms / 1000 + 1000;

        if (excess < 0) {
            excess = 0;
        }

        if (ms) {
            lr->last = now;
        }

        lr->excess = excess;
        lr->count--;

        njt_shmtx_unlock(&ctx->shpool->mutex);

        ctx->node = NULL;

        if ((njt_uint_t) excess <= limits[n].delay) {
            continue;
        }

        delay = (excess - limits[n].delay) * 1000 / ctx->rate;

        if (delay > max_delay) {
            max_delay = delay;
            *ep = excess;
            *limit = &limits[n];
        }
    }

    return max_delay;
}


static void
njt_http_limit_req_unlock(njt_http_limit_req_limit_t *limits, njt_uint_t n)
{
    njt_http_limit_req_ctx_t  *ctx;

    while (n--) {
        ctx = limits[n].shm_zone->data;

        if (ctx->node == NULL) {
            continue;
        }

        njt_shmtx_lock(&ctx->shpool->mutex);

        ctx->node->count--;

        njt_shmtx_unlock(&ctx->shpool->mutex);

        ctx->node = NULL;
    }
}


static void
njt_http_limit_req_expire(njt_http_limit_req_ctx_t *ctx, njt_uint_t n)
{
    njt_int_t                   excess;
    njt_msec_t                  now;
    njt_queue_t                *q;
    njt_msec_int_t              ms;
    njt_rbtree_node_t          *node;
    njt_http_limit_req_node_t  *lr;

    now = njt_current_msec;

    /*
     * n == 1 deletes one or two zero rate entries
     * n == 0 deletes oldest entry by force
     *        and one or two zero rate entries
     */

    while (n < 3) {

        if (njt_queue_empty(&ctx->sh->queue)) {
            return;
        }

        q = njt_queue_last(&ctx->sh->queue);

        lr = njt_queue_data(q, njt_http_limit_req_node_t, queue);

        if (lr->count) {

            /*
             * There is not much sense in looking further,
             * because we bump nodes on the lookup stage.
             */

            return;
        }

        if (n++ != 0) {

            ms = (njt_msec_int_t) (now - lr->last);
            ms = njt_abs(ms);

            if (ms < 60000) {
                return;
            }

            excess = lr->excess - ctx->rate * ms / 1000;

            if (excess > 0) {
                return;
            }
        }

        njt_queue_remove(q);

        node = (njt_rbtree_node_t *)
                   ((u_char *) lr - offsetof(njt_rbtree_node_t, color));

        njt_rbtree_delete(&ctx->sh->rbtree, node);

        njt_slab_free_locked(ctx->shpool, node);
    }
}


static njt_int_t
njt_http_limit_req_init_zone(njt_shm_zone_t *shm_zone, void *data)
{
    njt_http_limit_req_ctx_t  *octx = data;

    size_t                     len;
    njt_http_limit_req_ctx_t  *ctx;

    ctx = shm_zone->data;

    if (octx) {
        if (ctx->key.value.len != octx->key.value.len
            || njt_strncmp(ctx->key.value.data, octx->key.value.data,
                           ctx->key.value.len)
               != 0)
        {
            njt_log_error(NJT_LOG_EMERG, shm_zone->shm.log, 0,
                          "limit_req \"%V\" uses the \"%V\" key "
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

    ctx->sh = njt_slab_alloc(ctx->shpool, sizeof(njt_http_limit_req_shctx_t));
    if (ctx->sh == NULL) {
        return NJT_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    njt_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    njt_http_limit_req_rbtree_insert_value);

    njt_queue_init(&ctx->sh->queue);

    len = sizeof(" in limit_req zone \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = njt_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NJT_ERROR;
    }

    njt_sprintf(ctx->shpool->log_ctx, " in limit_req zone \"%V\"%Z",
                &shm_zone->shm.name);

    ctx->shpool->log_nomem = 0;

    return NJT_OK;
}


static njt_int_t
njt_http_limit_req_status_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    if (r->main->limit_req_status == 0) {
        v->not_found = 1;
        return NJT_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = njt_http_limit_req_status[r->main->limit_req_status - 1].len;
    v->data = njt_http_limit_req_status[r->main->limit_req_status - 1].data;

    return NJT_OK;
}


static void *
njt_http_limit_req_create_conf(njt_conf_t *cf)
{
    njt_http_limit_req_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_limit_req_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->limits.elts = NULL;
     */

    conf->limit_log_level = NJT_CONF_UNSET_UINT;
    conf->status_code = NJT_CONF_UNSET_UINT;
    conf->dry_run = NJT_CONF_UNSET;
    conf->from_up = 0;

    return conf;
}


static char *
njt_http_limit_req_merge_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_limit_req_conf_t *prev = parent;
    njt_http_limit_req_conf_t *conf = child;

    if (conf->limits.elts == NULL) {
        conf->limits = prev->limits;
        conf->from_up = 1;
    }

    njt_conf_merge_uint_value(conf->limit_log_level, prev->limit_log_level,
                              NJT_LOG_ERR);

    conf->delay_log_level = (conf->limit_log_level == NJT_LOG_INFO) ?
                                NJT_LOG_INFO : conf->limit_log_level + 1;

    njt_conf_merge_uint_value(conf->status_code, prev->status_code,
                              NJT_HTTP_SERVICE_UNAVAILABLE);

    njt_conf_merge_value(conf->dry_run, prev->dry_run, 0);

    return NJT_CONF_OK;
}


static char *
njt_http_limit_req_zone(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    u_char                            *p;
    size_t                             len;
    ssize_t                            size;
    njt_str_t                         *value, name, s;
    njt_int_t                          rate, scale;
    njt_uint_t                         i;
    njt_shm_zone_t                    *shm_zone;
    njt_http_limit_req_ctx_t          *ctx;
    njt_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    ctx = njt_pcalloc(cf->pool, sizeof(njt_http_limit_req_ctx_t));
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &ctx->key;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    size = 0;
    rate = 1;
    scale = 1;
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

        if (njt_strncmp(value[i].data, "rate=", 5) == 0) {

            len = value[i].len;
            p = value[i].data + len - 3;

            if (njt_strncmp(p, "r/s", 3) == 0) {
                scale = 1;
                len -= 3;

            } else if (njt_strncmp(p, "r/m", 3) == 0) {
                scale = 60;
                len -= 3;
            }

            rate = njt_atoi(value[i].data + 5, len - 5);
            if (rate <= 0) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid rate \"%V\"", &value[i]);
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

    ctx->rate = rate * 1000 / scale;
#if (NJT_HTTP_DYNAMIC_LOC)
    ctx->scale = scale;
    ctx->ori_rate = rate;
#endif

    shm_zone = njt_shared_memory_add(cf, &name, size,
                                     &njt_http_limit_req_module);
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

    shm_zone->init = njt_http_limit_req_init_zone;
    shm_zone->data = ctx;

    return NJT_CONF_OK;
}


static char *
njt_http_limit_req(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_limit_req_conf_t  *lrcf = conf;

    njt_int_t                    burst, delay;
    njt_str_t                   *value, s;
    njt_uint_t                   i;
    njt_shm_zone_t              *shm_zone;
    njt_http_limit_req_limit_t  *limit, *limits;

    value = cf->args->elts;

    shm_zone = NULL;
    burst = 0;
    delay = 0;

    for (i = 1; i < cf->args->nelts; i++) {

        if (njt_strncmp(value[i].data, "zone=", 5) == 0) {

            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            shm_zone = njt_shared_memory_add(cf, &s, 0,
                                             &njt_http_limit_req_module);
            if (shm_zone == NULL) {
                return NJT_CONF_ERROR;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "burst=", 6) == 0) {

            burst = njt_atoi(value[i].data + 6, value[i].len - 6);
            if (burst <= 0) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid burst value \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "delay=", 6) == 0) {

            delay = njt_atoi(value[i].data + 6, value[i].len - 6);
            if (delay <= 0) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid delay value \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }

        if (njt_strcmp(value[i].data, "nodelay") == 0) {
            delay = NJT_MAX_INT_T_VALUE / 1000;
            continue;
        }

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NJT_CONF_ERROR;
    }

    if (shm_zone == NULL) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NJT_CONF_ERROR;
    }

    limits = lrcf->limits.elts;

    if (limits == NULL) {
        if (njt_array_init(&lrcf->limits, cf->pool, 1,
                           sizeof(njt_http_limit_req_limit_t))
            != NJT_OK)
        {
            return NJT_CONF_ERROR;
        }
    }

    for (i = 0; i < lrcf->limits.nelts; i++) {
        if (shm_zone == limits[i].shm_zone) {
            return "is duplicate";
        }
    }

    limit = njt_array_push(&lrcf->limits);
    if (limit == NULL) {
        return NJT_CONF_ERROR;
    }

    limit->shm_zone = shm_zone;
    limit->burst = burst * 1000;
    limit->delay = delay * 1000;

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_limit_req_add_variables(njt_conf_t *cf)
{
    njt_http_variable_t  *var, *v;

    for (v = njt_http_limit_req_vars; v->name.len; v++) {
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
njt_http_limit_req_init(njt_conf_t *cf)
{
    njt_http_handler_pt        *h;
    njt_http_core_main_conf_t  *cmcf;

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);

    h = njt_array_push(&cmcf->phases[NJT_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_http_limit_req_handler;

    return NJT_OK;
}
