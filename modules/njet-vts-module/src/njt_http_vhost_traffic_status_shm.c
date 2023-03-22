
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 * Copyright (C) TMLake, Inc.
 */


#include "njt_http_vhost_traffic_status_module.h"
#include "njt_http_vhost_traffic_status_filter.h"
#include "njt_http_vhost_traffic_status_shm.h"


static njt_int_t njt_http_vhost_traffic_status_shm_add_node(njt_http_request_t *r,
    njt_str_t *key, unsigned type);
static njt_int_t njt_http_vhost_traffic_status_shm_add_node_upstream(njt_http_request_t *r,
    njt_http_vhost_traffic_status_node_t *vtsn, unsigned init);

#if (NJT_HTTP_CACHE)
static njt_int_t njt_http_vhost_traffic_status_shm_add_node_cache(njt_http_request_t *r,
    njt_http_vhost_traffic_status_node_t *vtsn, unsigned init);
#endif

static njt_int_t njt_http_vhost_traffic_status_shm_add_filter_node(njt_http_request_t *r,
    njt_array_t *filter_keys);


void
njt_http_vhost_traffic_status_shm_info_node(njt_http_request_t *r,
    njt_http_vhost_traffic_status_shm_info_t *shm_info,
    njt_rbtree_node_t *node)
{
    njt_str_t                              filter;
    njt_uint_t                             size;
    njt_http_vhost_traffic_status_ctx_t   *ctx;
    njt_http_vhost_traffic_status_node_t  *vtsn;

    ctx = njt_http_get_module_main_conf(r, njt_http_vhost_traffic_status_module);

    if (node != ctx->rbtree->sentinel) {
        vtsn = (njt_http_vhost_traffic_status_node_t *) &node->color;

        size = offsetof(njt_rbtree_node_t, color)
               + offsetof(njt_http_vhost_traffic_status_node_t, data)
               + vtsn->len;

        shm_info->used_size += size;
        shm_info->used_node++;

        if (vtsn->stat_upstream.type == NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG) {
            filter.data = vtsn->data;
            filter.len = vtsn->len;

            (void) njt_http_vhost_traffic_status_node_position_key(&filter, 1);

            if (njt_http_vhost_traffic_status_filter_max_node_match(r, &filter) == NJT_OK) {
                shm_info->filter_used_size += size;
                shm_info->filter_used_node++;
            }
        }

        njt_http_vhost_traffic_status_shm_info_node(r, shm_info, node->left);
        njt_http_vhost_traffic_status_shm_info_node(r, shm_info, node->right);
    }
}


void
njt_http_vhost_traffic_status_shm_info(njt_http_request_t *r,
    njt_http_vhost_traffic_status_shm_info_t *shm_info)
{
    njt_http_vhost_traffic_status_ctx_t  *ctx;

    ctx = njt_http_get_module_main_conf(r, njt_http_vhost_traffic_status_module);
    ctx->rbtree = njt_http_vts_rbtree;

    njt_memzero(shm_info, sizeof(njt_http_vhost_traffic_status_shm_info_t));

    shm_info->name = &njt_http_vts_shm_name;//&ctx->shm_name;
    shm_info->max_size = njt_http_vts_shm_size;//ctx->shm_size;

    njt_http_vhost_traffic_status_shm_info_node(r, shm_info, ctx->rbtree->root);
}


static njt_int_t
njt_http_vhost_traffic_status_shm_add_node(njt_http_request_t *r,
    njt_str_t *key, unsigned type)
{
    size_t                                     size;
    unsigned                                   init;
    uint32_t                                   hash;
    njt_slab_pool_t                           *shpool;
    njt_rbtree_node_t                         *node, *lrun;
    njt_http_vhost_traffic_status_ctx_t       *ctx;
    njt_http_vhost_traffic_status_node_t      *vtsn;
    njt_http_vhost_traffic_status_loc_conf_t  *vtscf;
    njt_http_vhost_traffic_status_shm_info_t  *shm_info;

    ctx = njt_http_get_module_main_conf(r, njt_http_vhost_traffic_status_module);

    vtscf = njt_http_get_module_loc_conf(r, njt_http_vhost_traffic_status_module);

    if (key->len == 0) {
        return NJT_ERROR;
    }

    shpool = (njt_slab_pool_t *) vtscf->shm_zone->shm.addr;

    njt_shmtx_lock(&shpool->mutex);

    /* find node */
    hash = njt_crc32_short(key->data, key->len);

    node = njt_http_vhost_traffic_status_find_node(r, key, type, hash);

    /* set common */
    if (node == NULL) {
        init = NJT_HTTP_VHOST_TRAFFIC_STATUS_NODE_NONE;

        /* delete lru node */
        lrun = njt_http_vhost_traffic_status_find_lru(r);
        if (lrun != NULL) {
            njt_rbtree_delete(ctx->rbtree, lrun);
            njt_slab_free_locked(shpool, lrun);
        }

        size = offsetof(njt_rbtree_node_t, color)
               + offsetof(njt_http_vhost_traffic_status_node_t, data)
               + key->len;

        node = njt_slab_alloc_locked(shpool, size);
        if (node == NULL) {
            shm_info = njt_pcalloc(r->pool, sizeof(njt_http_vhost_traffic_status_shm_info_t));
            if (shm_info == NULL) {
                njt_shmtx_unlock(&shpool->mutex);
                return NJT_ERROR;
            }

            njt_http_vhost_traffic_status_shm_info(r, shm_info);

            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "shm_add_node::njt_slab_alloc_locked() failed: "
                          "used_size[%ui], used_node[%ui]",
                          shm_info->used_size, shm_info->used_node);

            njt_shmtx_unlock(&shpool->mutex);
            return NJT_ERROR;
        }

        vtsn = (njt_http_vhost_traffic_status_node_t *) &node->color;

        node->key = hash;
        vtsn->len = (u_short) key->len;
        njt_http_vhost_traffic_status_node_init(r, vtsn);
        vtsn->stat_upstream.type = type;
        njt_memcpy(vtsn->data, key->data, key->len);

        njt_rbtree_insert(ctx->rbtree, node);

    } else {
        init = NJT_HTTP_VHOST_TRAFFIC_STATUS_NODE_FIND;
        vtsn = (njt_http_vhost_traffic_status_node_t *) &node->color;
        njt_http_vhost_traffic_status_node_set(r, vtsn);
    }

    /* set addition */
    switch(type) {
    case NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO:
        break;

    case NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA:
    case NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG:
        (void) njt_http_vhost_traffic_status_shm_add_node_upstream(r, vtsn, init);
        break;

#if (NJT_HTTP_CACHE)
    case NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC:
        (void) njt_http_vhost_traffic_status_shm_add_node_cache(r, vtsn, init);
        break;
#endif

    case NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG:
        break;
    }

    vtscf->node_caches[type] = node;

    njt_shmtx_unlock(&shpool->mutex);

    return NJT_OK;
}


static njt_int_t
njt_http_vhost_traffic_status_shm_add_node_upstream(njt_http_request_t *r,
    njt_http_vhost_traffic_status_node_t *vtsn, unsigned init)
{
    njt_msec_int_t                             ms;
    njt_http_vhost_traffic_status_node_t       ovtsn;
    njt_http_vhost_traffic_status_loc_conf_t  *vtscf;

    vtscf = njt_http_get_module_loc_conf(r, njt_http_vhost_traffic_status_module);

    ovtsn = *vtsn;
    ms = njt_http_vhost_traffic_status_upstream_response_time(r);

    njt_http_vhost_traffic_status_node_time_queue_insert(&vtsn->stat_upstream.response_times,
                                                         ms);
    njt_http_vhost_traffic_status_node_histogram_observe(&vtsn->stat_upstream.response_buckets,
                                                         ms);

    if (init == NJT_HTTP_VHOST_TRAFFIC_STATUS_NODE_NONE) {
        vtsn->stat_upstream.response_time_counter = (njt_atomic_uint_t) ms;
        vtsn->stat_upstream.response_time = (njt_msec_t) ms;

    } else {
        vtsn->stat_upstream.response_time_counter += (njt_atomic_uint_t) ms;
        vtsn->stat_upstream.response_time = njt_http_vhost_traffic_status_node_time_queue_average(
                                                &vtsn->stat_upstream.response_times,
                                                vtscf->average_method, vtscf->average_period);

        if (ovtsn.stat_upstream.response_time_counter > vtsn->stat_upstream.response_time_counter)
        { 
            vtsn->stat_response_time_counter_oc++;
        }
    }

    return NJT_OK;
}


#if (NJT_HTTP_CACHE)

static njt_int_t
njt_http_vhost_traffic_status_shm_add_node_cache(njt_http_request_t *r,
    njt_http_vhost_traffic_status_node_t *vtsn, unsigned init)
{
    njt_http_cache_t       *c;
    njt_http_upstream_t    *u;
    njt_http_file_cache_t  *cache;

    u = r->upstream;

    if (u != NULL && u->cache_status != 0 && r->cache != NULL) {
        c = r->cache;
        cache = c->file_cache;

    } else {
        return NJT_OK;
    }

    /*
     * If max_size in proxy_cache_path directive is not specified,
     * the system dependent value NJT_MAX_OFF_T_VALUE is assigned by default.
     *
     * proxy_cache_path ... keys_zone=name:size [max_size=size] ...
     *
     *     keys_zone's shared memory size:
     *         cache->shm_zone->shm.size
     *
     *     max_size's size:
     *         cache->max_size
     */

    if (init == NJT_HTTP_VHOST_TRAFFIC_STATUS_NODE_NONE) {
        vtsn->stat_cache_max_size = (njt_atomic_uint_t) (cache->max_size * cache->bsize);

    } else {
        njt_shmtx_lock(&cache->shpool->mutex);

        vtsn->stat_cache_used_size = (njt_atomic_uint_t) (cache->sh->size * cache->bsize);

        njt_shmtx_unlock(&cache->shpool->mutex);
    }

    return NJT_OK;
}

#endif


static njt_int_t
njt_http_vhost_traffic_status_shm_add_filter_node(njt_http_request_t *r,
    njt_array_t *filter_keys)
{
    u_char                                  *p;
    unsigned                                 type;
    njt_int_t                                rc;
    njt_str_t                                key, dst, filter_key, filter_name;
    njt_uint_t                               i, n;
    njt_http_vhost_traffic_status_filter_t  *filters;

    if (filter_keys == NULL) {
        return NJT_OK;
    }

    filters = filter_keys->elts;
    n = filter_keys->nelts;

    for (i = 0; i < n; i++) {
        if (filters[i].filter_key.value.len <= 0) {
            continue;
        }

        if (njt_http_complex_value(r, &filters[i].filter_key, &filter_key) != NJT_OK) {
            return NJT_ERROR;
        }

        if (njt_http_complex_value(r, &filters[i].filter_name, &filter_name) != NJT_OK) {
            return NJT_ERROR;
        }

        if (filter_key.len == 0) {
            continue;
        }

        if (filter_name.len == 0) {
            type = NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO;

            rc = njt_http_vhost_traffic_status_node_generate_key(r->pool, &key, &filter_key, type);
            if (rc != NJT_OK) {
                return NJT_ERROR;
            }

        } else {
            type = filter_name.len
                   ? NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG
                   : NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO;

            dst.len = filter_name.len + sizeof("@") - 1 + filter_key.len;
            dst.data = njt_pnalloc(r->pool, dst.len);
            if (dst.data == NULL) {
                return NJT_ERROR;
            }

            p = dst.data;
            p = njt_cpymem(p, filter_name.data, filter_name.len);
            *p++ = NJT_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR;
            p = njt_cpymem(p, filter_key.data, filter_key.len);

            rc = njt_http_vhost_traffic_status_node_generate_key(r->pool, &key, &dst, type);
            if (rc != NJT_OK) {
                return NJT_ERROR;
            }
        }

        rc = njt_http_vhost_traffic_status_shm_add_node(r, &key, type);
        if (rc != NJT_OK) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "shm_add_filter_node::shm_add_node(\"%V\") failed", &key);
        }
    }

    return NJT_OK;
}


njt_int_t
njt_http_vhost_traffic_status_shm_add_server(njt_http_request_t *r)
{
    unsigned                                   type;
    njt_int_t                                  rc;
    njt_str_t                                  key, dst;
    njt_http_core_srv_conf_t                  *cscf;
    njt_http_vhost_traffic_status_loc_conf_t  *vtscf;

    vtscf = njt_http_get_module_loc_conf(r, njt_http_vhost_traffic_status_module);

    cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);

    if (vtscf->filter && vtscf->filter_host && r->headers_in.server.len) {
        /* set the key by host header */
        dst = r->headers_in.server;

    } else {
        /* set the key by server_name variable */
        dst = cscf->server_name;
        if (dst.len == 0) {
            dst.len = 1;
            dst.data = (u_char *) "_";
        }
    }

    type = NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO;

    rc = njt_http_vhost_traffic_status_node_generate_key(r->pool, &key, &dst, type);
    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    return njt_http_vhost_traffic_status_shm_add_node(r, &key, type);
}


njt_int_t
njt_http_vhost_traffic_status_shm_add_filter(njt_http_request_t *r)
{
    njt_int_t                                  rc;
    njt_http_vhost_traffic_status_ctx_t       *ctx;
    njt_http_vhost_traffic_status_loc_conf_t  *vtscf;
    njt_array_t                               *filter_keys;

    ctx = njt_http_get_module_main_conf(r, njt_http_vhost_traffic_status_module);

    vtscf = njt_http_get_module_loc_conf(r, njt_http_vhost_traffic_status_module);

    if (!vtscf->filter) {
        return NJT_OK;
    }

#if (NJT_HTTP_VTS_DYNCONF)
    filter_keys = ctx->filter_keys_dyn;
    if (filter_keys == NULL) {
        filter_keys = ctx->filter_keys;
        if (filter_keys == NULL) {
            return NJT_OK;
        }
    }
#else
    filter_keys = ctx->filter_keys;
    if (filter_keys == NULL) {
        return NJT_OK;
    }
#endif

    if (filter_keys != NULL) {
        rc = njt_http_vhost_traffic_status_shm_add_filter_node(r, filter_keys);
        if (rc != NJT_OK) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "shm_add_filter::shm_add_filter_node(\"http\") failed");
        }
    }

    if (vtscf->filter_keys != NULL) {
        rc = njt_http_vhost_traffic_status_shm_add_filter_node(r, vtscf->filter_keys);
        if (rc != NJT_OK) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "shm_add_filter::shm_add_filter_node(\"server\") failed");
        }
    }

    return NJT_OK;
}


njt_int_t
njt_http_vhost_traffic_status_shm_add_upstream(njt_http_request_t *r)
{
    u_char                         *p;
    unsigned                        type;
    njt_int_t                       rc;
    njt_str_t                      *host, key, dst;
    njt_uint_t                      i;
    njt_http_upstream_t            *u;
    njt_http_upstream_state_t      *state;
    njt_http_upstream_srv_conf_t   *uscf, **uscfp;
    njt_http_upstream_main_conf_t  *umcf;

    if (r->upstream_states == NULL || r->upstream_states->nelts == 0
        || r->upstream->state == NULL)
    {
        return NJT_OK;
    }

    u = r->upstream;

    if (u->resolved == NULL) {
        uscf = u->conf->upstream;

    } else {
        host = &u->resolved->host;

        umcf = njt_http_cycle_get_module_main_conf(njt_http_vtsp_cycle, njt_http_upstream_module);

        uscfp = umcf->upstreams.elts;

        for (i = 0; i < umcf->upstreams.nelts; i++) {

            uscf = uscfp[i];

            if (uscf->host.len == host->len
                && ((uscf->port == 0 && u->resolved->no_port)
                     || uscf->port == u->resolved->port)
                && njt_strncasecmp(uscf->host.data, host->data, host->len) == 0)
            {
                goto found;
            }
        }

        /* routine for proxy_pass|fastcgi_pass|... $variables */
        uscf = njt_pcalloc(r->pool, sizeof(njt_http_upstream_srv_conf_t));
        if (uscf == NULL) {
            return NJT_ERROR;
        }

        uscf->host = u->resolved->host;
        uscf->port = u->resolved->port;
    }

found:

    state = u->state;
    if (state->peer == NULL) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "shm_add_upstream::peer failed");
        return NJT_ERROR;
    }

    dst.len = (uscf->port ? 0 : uscf->host.len + sizeof("@") - 1) + state->peer->len;
    dst.data = njt_pnalloc(r->pool, dst.len);
    if (dst.data == NULL) {
        return NJT_ERROR;
    }

    p = dst.data;
    if (uscf->port) {
        p = njt_cpymem(p, state->peer->data, state->peer->len);
        type = NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA;

    } else {
        p = njt_cpymem(p, uscf->host.data, uscf->host.len);
        *p++ = NJT_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR;
        p = njt_cpymem(p, state->peer->data, state->peer->len);
        type = NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG;
    }

    rc = njt_http_vhost_traffic_status_node_generate_key(r->pool, &key, &dst, type);
    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    rc = njt_http_vhost_traffic_status_shm_add_node(r, &key, type);
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "shm_add_upstream::shm_add_node(\"%V\") failed", &key);
    }

    return NJT_OK;
}


#if (NJT_HTTP_CACHE)

njt_int_t
njt_http_vhost_traffic_status_shm_add_cache(njt_http_request_t *r)
{
    unsigned                type;
    njt_int_t               rc;
    njt_str_t               key;
    njt_http_cache_t       *c;
    njt_http_upstream_t    *u;
    njt_http_file_cache_t  *cache;

    u = r->upstream;

    if (u != NULL && u->cache_status != 0 && r->cache != NULL) {
        c = r->cache;
        cache = c->file_cache;

    } else {
        return NJT_OK;
    }

    type = NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC;

    rc = njt_http_vhost_traffic_status_node_generate_key(r->pool, &key, &cache->shm_zone->shm.name,
                                                         type);
    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    rc = njt_http_vhost_traffic_status_shm_add_node(r, &key, type);
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "shm_add_cache::shm_add_node(\"%V\") failed", &key);
    }

    return NJT_OK;
}

#endif

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
