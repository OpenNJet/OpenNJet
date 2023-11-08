
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 * Copyright (C), 2021-2023, TMLake(Beijing) Technology Co., Ltd.
 */


#include "njt_http_vhost_traffic_status_module.h"
#include "njt_http_vhost_traffic_status_filter.h"
#include "njt_http_vhost_traffic_status_shm.h"


static njt_int_t njt_http_vhost_traffic_status_shm_add_node(njt_http_request_t *r,
    njt_str_t *key, unsigned type, unsigned upto);
static njt_int_t njt_http_vhost_traffic_status_shm_add_node_upstream(njt_http_request_t *r,
    njt_http_vhost_traffic_status_node_t *vtsn, unsigned init, unsigned upto);

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
        vtsn = njt_http_vhost_traffic_status_get_node(node);

        size = offsetof(njt_rbtree_node_t, color)
               + offsetof(njt_http_vhost_traffic_status_node_t, data) * (1 + njt_ncpu)
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


njt_http_vhost_traffic_status_node_t *
njt_http_vhost_traffic_status_get_node(njt_rbtree_node_t *node)
{
    njt_http_vhost_traffic_status_node_t *vtsn;

    vtsn = (njt_http_vhost_traffic_status_node_t *) &node->color;
    vtsn += njt_ncpu;

    return vtsn;
}

static njt_int_t    njt_cpu_id = -1;

njt_http_vhost_traffic_status_node_t *
njt_http_vhost_traffic_status_map_node(njt_slab_pool_t *shpool, njt_http_vhost_traffic_status_node_t *vtsn)
{
    njt_atomic_uint_t   n;

    if (njt_cpu_id == -1) {
        n = njt_atomic_fetch_add(&shpool->rwlock.want, 1);
        njt_cpu_id = n % njt_ncpu;
    }

    vtsn -= (njt_ncpu - njt_cpu_id);

    return vtsn;
}

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <math.h>
#include <string.h>
#include <inttypes.h>

bool njt_http_vts_hdr_record(njt_int_t value);


static njt_int_t
njt_http_vhost_traffic_status_shm_add_node(njt_http_request_t *r,
    njt_str_t *key, unsigned type, unsigned upto)
{
    size_t                                     size;
    unsigned                                   init;
    uint32_t                                   hash;
    njt_slab_pool_t                           *shpool;
    njt_rbtree_node_t                         *node, *lrun;
    njt_http_vhost_traffic_status_ctx_t       *ctx;
    njt_http_vhost_traffic_status_node_t      *vtsnd;
    njt_http_vhost_traffic_status_node_t      *vtsn;
    njt_http_vhost_traffic_status_loc_conf_t  *vtscf;
    njt_http_vhost_traffic_status_shm_info_t  *shm_info;
    njt_int_t                                  ret = NJT_OK;

    ctx = njt_http_get_module_main_conf(r, njt_http_vhost_traffic_status_module);

    vtscf = njt_http_get_module_loc_conf(r, njt_http_vhost_traffic_status_module);

    if (key->len == 0) {
        return NJT_ERROR;
    }

    shpool = (njt_slab_pool_t *) vtscf->shm_zone->shm.addr;

    njt_shrwlock_rdlock(&shpool->rwlock);

    /* find node */
    hash = njt_crc32_short(key->data, key->len);

    node = njt_http_vhost_traffic_status_find_node(r, key, type, hash);

    /* set common */
    if (node == NULL) {
        njt_shrwlock_rd2wrlock(&shpool->rwlock);

        node = njt_http_vhost_traffic_status_find_node(r, key, type, hash);

        if (node == NULL) {
            init = NJT_HTTP_VHOST_TRAFFIC_STATUS_NODE_NONE;

            /* delete lru node */
            lrun = njt_http_vhost_traffic_status_find_lru(r);
            if (lrun != NULL) {
                njt_rbtree_delete(ctx->rbtree, lrun);
                njt_slab_free_locked(shpool, lrun);
            }

            size = offsetof(njt_rbtree_node_t, color)
                + offsetof(njt_http_vhost_traffic_status_node_t, data) * (1 + njt_ncpu)
                + key->len;
            
            node = njt_slab_calloc_locked(shpool, size);
            if (node == NULL) {
                shm_info = njt_pcalloc(r->pool, sizeof(njt_http_vhost_traffic_status_shm_info_t));
                if (shm_info == NULL) {
                    ret = NJT_ERROR;
                    goto OUT;
                }

                njt_http_vhost_traffic_status_shm_info(r, shm_info);

                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                            "shm_add_node::njt_slab_alloc_locked() failed: "
                            "used_size[%ui], used_node[%ui]",
                            shm_info->used_size, shm_info->used_node);

                ret = NJT_ERROR;
                goto OUT;
            }

            vtsnd = njt_http_vhost_traffic_status_get_node(node);

            node->key = hash;
            vtsnd->len = (u_short) key->len;
            njt_http_vhost_traffic_status_nodes_init(r, vtsnd);

            vtsnd->stat_upstream.type = type;
            njt_memcpy(vtsnd->data, key->data, key->len);

            njt_rbtree_insert(ctx->rbtree, node);
            njt_shrwlock_wr2rdlock(&shpool->rwlock);

            vtsn = njt_http_vhost_traffic_status_map_node(shpool, vtsnd);
            njt_rwlock_wlock(&vtsn->lock);
            if (!upto) {
                njt_http_vhost_traffic_status_node_init_update(r, vtsn);
            }
        } else {
            init = NJT_HTTP_VHOST_TRAFFIC_STATUS_NODE_FIND;
            vtsnd = njt_http_vhost_traffic_status_get_node(node);
            njt_shrwlock_wr2rdlock(&shpool->rwlock);
            vtsn = njt_http_vhost_traffic_status_map_node(shpool, vtsnd);          
            njt_rwlock_wlock(&vtsn->lock);
            if (!upto) {
                njt_http_vhost_traffic_status_node_set(r, vtsn);
            }
        }
    } else {
        init = NJT_HTTP_VHOST_TRAFFIC_STATUS_NODE_FIND;
        vtsnd = njt_http_vhost_traffic_status_get_node(node);        
        vtsn = njt_http_vhost_traffic_status_map_node(shpool, vtsnd);
        njt_rwlock_wlock(&vtsn->lock);
        if (!upto) {
            njt_http_vhost_traffic_status_node_set(r, vtsn);
        }
    }

    /* set addition */
    switch(type) {
    case NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO:
        break;

    case NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA:
    case NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG:
        (void) njt_http_vhost_traffic_status_shm_add_node_upstream(r, vtsn, init, upto);

        int record = 1;

        if (record) {
            njt_http_vts_hdr_record(r->upstream->req_delay);
        }
        break;

#if (NJT_HTTP_CACHE)
    case NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC:
        njt_rwlock_wlock(&vtsnd->lock);
        (void) njt_http_vhost_traffic_status_shm_add_node_cache(r, vtsnd, init);
        njt_rwlock_unlock(&vtsnd->lock);
        break;
#endif

    case NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG:
        break;
    }

    vtscf->node_caches[type] = node;

    njt_rwlock_unlock(&vtsn->lock);

OUT:
    njt_shrwlock_unlock(&shpool->rwlock);

    return ret;
}


static njt_int_t
njt_http_vhost_traffic_status_shm_add_node_upstream(njt_http_request_t *r,
    njt_http_vhost_traffic_status_node_t *vtsn, unsigned init, unsigned upto)
{
    njt_msec_int_t                             ms;
    njt_http_vhost_traffic_status_node_t       ovtsn;
    njt_http_vhost_traffic_status_loc_conf_t  *vtscf;
    njt_uint_t                                 idx;
    njt_http_upstream_state_t                 *upstate;
    njt_http_upstream_state_t                 *state;

    vtscf = njt_http_get_module_loc_conf(r, njt_http_vhost_traffic_status_module);
    upstate = r->upstream_states->elts;

    if (upto) {
        idx = --upto;
        state = &upstate[idx];
        if (state->status == NJT_HTTP_GATEWAY_TIME_OUT) {
            vtsn->stat_timeo_counter_oc++;
        }
        return NJT_OK;
    }

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

    if (r->upstream->state->status == NJT_HTTP_GATEWAY_TIME_OUT) {
        vtsn->stat_timeo_counter_oc++;
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

        rc = njt_http_vhost_traffic_status_shm_add_node(r, &key, type, 0);
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

    return njt_http_vhost_traffic_status_shm_add_node(r, &key, type, 0);
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

    // njt_log_error(NJT_LOG_DEBUG, r->connection->log, 0, "dst[last] = %V", &dst);

    rc = njt_http_vhost_traffic_status_node_generate_key(r->pool, &key, &dst, type);
    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    rc = njt_http_vhost_traffic_status_shm_add_node(r, &key, type, 0);
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "shm_add_upstream::shm_add_node(\"%V\") failed", &key);
    }

    if (r->upstream_states->nelts > 1) {
        njt_uint_t idx;
        njt_http_upstream_state_t *upstate;

        upstate = r->upstream_states->elts;

        for (idx = 0; idx < r->upstream_states->nelts - 1; idx++) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "up server %ui status %ui", idx, upstate[idx].status);

            state = &upstate[idx];
            if (state->peer == NULL) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                            "shm_add_upstream::peer failed");
                continue;
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

            njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "dst[%ud] = %V", idx, &dst);

            rc = njt_http_vhost_traffic_status_node_generate_key(r->pool, &key, &dst, type);
            if (rc != NJT_OK) {
                continue;
            }

            rc = njt_http_vhost_traffic_status_shm_add_node(r, &key, type, idx+1);
            if (rc != NJT_OK) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                            "shm_add_upstream::shm_add_node(\"%V\") failed", &key);
            }
        }
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

    rc = njt_http_vhost_traffic_status_shm_add_node(r, &key, type, 0);
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "shm_add_cache::shm_add_node(\"%V\") failed", &key);
    }

    return NJT_OK;
}

#endif


struct hdr_histogram
{
    int64_t lowest_discernible_value;
    int64_t highest_trackable_value;
    int32_t unit_magnitude;
    int32_t significant_figures;
    int32_t sub_bucket_half_count_magnitude;
    int32_t sub_bucket_half_count;
    int64_t sub_bucket_mask;
    int32_t sub_bucket_count;
    int32_t bucket_count;
    njt_atomic_t min_value;
    njt_atomic_t max_value;
    int32_t normalizing_index_offset;
    double conversion_ratio;
    int32_t counts_len;
    njt_atomic_t total_count;
    njt_atomic_t* total_counts;
    njt_atomic_t* counts;
    njt_atomic_t* count0s;
};


struct hdr_iter_percentiles
{
    bool seen_last_value;
    int32_t ticks_per_half_distance;
    double percentile_to_iterate_to;
    double percentile;
};


struct hdr_iter_recorded
{
    int64_t count_added_in_this_iteration_step;
};


struct hdr_iter
{
    const struct hdr_histogram* h;
    /** raw index into the counts array */
    int32_t counts_index;
    /** snapshot of the length at the time the iterator is created */
    int64_t total_count;
    /** value directly from array for the current counts_index */
    int64_t count;
    /** sum of all of the counts up to and including the count at this index */
    int64_t cumulative_count;
    /** The current value based on counts_index */
    int64_t value;
    int64_t highest_equivalent_value;
    int64_t lowest_equivalent_value;
    int64_t median_equivalent_value;
    int64_t value_iterated_from;
    int64_t value_iterated_to;

    union
    {
        struct hdr_iter_percentiles percentiles;
        struct hdr_iter_recorded recorded;
    } specifics;

    bool (* _next_fp)(struct hdr_iter* iter);

};


struct hdr_histogram_bucket_config
{
    int64_t lowest_discernible_value;
    int64_t highest_trackable_value;
    int64_t unit_magnitude;
    int64_t significant_figures;
    int32_t sub_bucket_half_count_magnitude;
    int32_t sub_bucket_half_count;
    int64_t sub_bucket_mask;
    int32_t sub_bucket_count;
    int32_t bucket_count;
    int32_t counts_len;
};



#define hdr_free free


static int32_t normalize_index(const struct hdr_histogram* h, int32_t index)
{
    int32_t normalized_index;
    int32_t adjustment = 0;
    if (h->normalizing_index_offset == 0)
    {
        return index;
    }

    normalized_index = index - h->normalizing_index_offset;

    if (normalized_index < 0)
    {
        adjustment = h->counts_len;
    }
    else if (normalized_index >= h->counts_len)
    {
        adjustment = -h->counts_len;
    }

    return normalized_index + adjustment;
}

static int64_t counts_get_direct(const struct hdr_histogram* h, int32_t index)
{
    return h->counts[index];
}

static int64_t counts_get_normalised(const struct hdr_histogram* h, int32_t index)
{
    return counts_get_direct(h, normalize_index(h, index));
}

static void counts_inc_normalised(
    struct hdr_histogram* h, int32_t index, int64_t value)
{
    int32_t normalised_index = normalize_index(h, index);

    if ((njt_cpu_id != -1) || normalised_index) {
        njt_atomic_fetch_add(&h->counts[normalised_index], value);
    } else {
        njt_atomic_fetch_add(&h->count0s[njt_cpu_id], value);
    }

    if (njt_cpu_id != -1) {
        njt_atomic_fetch_add(&h->total_counts[njt_cpu_id], value);
    } else {
        njt_atomic_fetch_add(&h->total_count, value);
    }
}

static void update_min(struct hdr_histogram* h, uint64_t value)
{
    uint64_t old;

    old = h->min_value;
    if (!value || value >= old) {
        return;
    }

    // h->min_value = (value < h->min_value && value != 0) ? value : h->min_value;

    for ( ;; ) {
        if (value < old) {
            if (njt_atomic_cmp_set(&h->min_value, old, value)) {
                return;
            }
        } else {
            return;
        }
        old = h->min_value;
    }
}


static void update_max(struct hdr_histogram* h, uint64_t value)
{
    uint64_t old;

    old = h->max_value;
    if (value <= old) {
        return;
    }

    // h->max_value = (value > h->max_value) ? value : h->max_value;

    for ( ;; ) {
        if (value > old) {
            if (njt_atomic_cmp_set(&h->max_value, old, value)) {
                return;
            }
        } else {
            return;
        }
        old = h->max_value;
    }
}



static void update_min_max(struct hdr_histogram* h, uint64_t value)
{
     update_min(h, value);
     update_max(h, value);
}


/* ##     ## ######## #### ##       #### ######## ##    ## */
/* ##     ##    ##     ##  ##        ##     ##     ##  ##  */
/* ##     ##    ##     ##  ##        ##     ##      ####   */
/* ##     ##    ##     ##  ##        ##     ##       ##    */
/* ##     ##    ##     ##  ##        ##     ##       ##    */
/* ##     ##    ##     ##  ##        ##     ##       ##    */
/*  #######     ##    #### ######## ####    ##       ##    */

static int64_t power(int64_t base, int64_t exp)
{
    int64_t result = 1;
    while(exp)
    {
        result *= base; exp--;
    }
    return result;
}


static int32_t count_leading_zeros_64(int64_t value)
{
    int32_t ret = __builtin_clzll(value);
    // return __builtin_clzll(value); /* smallest power of 2 containing value */
    return ret;

}

static int32_t get_bucket_index(const struct hdr_histogram* h, int64_t value)
{
    int32_t pow2ceiling = 64 - count_leading_zeros_64(value | h->sub_bucket_mask); /* smallest power of 2 containing value */
    return pow2ceiling - h->unit_magnitude - (h->sub_bucket_half_count_magnitude + 1);
}

static int32_t get_sub_bucket_index(int64_t value, int32_t bucket_index, int32_t unit_magnitude)
{
    return (int32_t)(value >> (bucket_index + unit_magnitude));
}

static int32_t counts_index(const struct hdr_histogram* h, int32_t bucket_index, int32_t sub_bucket_index)
{
    /* Calculate the index for the first entry in the bucket: */
    /* (The following is the equivalent of ((bucket_index + 1) * subBucketHalfCount) ): */
    int32_t bucket_base_index = (bucket_index + 1) << h->sub_bucket_half_count_magnitude;
    /* Calculate the offset in the bucket: */
    int32_t offset_in_bucket = sub_bucket_index - h->sub_bucket_half_count;
    /* The following is the equivalent of ((sub_bucket_index  - subBucketHalfCount) + bucketBaseIndex; */
    return bucket_base_index + offset_in_bucket;
}

static int64_t value_from_index(int32_t bucket_index, int32_t sub_bucket_index, int32_t unit_magnitude)
{
    return ((int64_t) sub_bucket_index) << (bucket_index + unit_magnitude);
}

int32_t counts_index_for(const struct hdr_histogram* h, int64_t value)
{
    int32_t bucket_index     = get_bucket_index(h, value);
    int32_t sub_bucket_index = get_sub_bucket_index(value, bucket_index, h->unit_magnitude);

    return counts_index(h, bucket_index, sub_bucket_index);
}

int64_t hdr_value_at_index(const struct hdr_histogram *h, int32_t index)
{
    int32_t bucket_index = (index >> h->sub_bucket_half_count_magnitude) - 1;
    int32_t sub_bucket_index = (index & (h->sub_bucket_half_count - 1)) + h->sub_bucket_half_count;

    if (bucket_index < 0)
    {
        sub_bucket_index -= h->sub_bucket_half_count;
        bucket_index = 0;
    }

    return value_from_index(bucket_index, sub_bucket_index, h->unit_magnitude);
}

int64_t hdr_size_of_equivalent_value_range(const struct hdr_histogram* h, int64_t value)
{
    int32_t bucket_index     = get_bucket_index(h, value);
    int32_t sub_bucket_index = get_sub_bucket_index(value, bucket_index, h->unit_magnitude);
    int32_t adjusted_bucket  = (sub_bucket_index >= h->sub_bucket_count) ? (bucket_index + 1) : bucket_index;
    return INT64_C(1) << (h->unit_magnitude + adjusted_bucket);
}

static int64_t size_of_equivalent_value_range_given_bucket_indices(
    const struct hdr_histogram *h,
    int32_t bucket_index,
    int32_t sub_bucket_index)
{
    const int32_t adjusted_bucket  = (sub_bucket_index >= h->sub_bucket_count) ? (bucket_index + 1) : bucket_index;
    return INT64_C(1) << (h->unit_magnitude + adjusted_bucket);
}

static int64_t lowest_equivalent_value(const struct hdr_histogram* h, int64_t value)
{
    int32_t bucket_index     = get_bucket_index(h, value);
    int32_t sub_bucket_index = get_sub_bucket_index(value, bucket_index, h->unit_magnitude);
    return value_from_index(bucket_index, sub_bucket_index, h->unit_magnitude);
}

static int64_t lowest_equivalent_value_given_bucket_indices(
    const struct hdr_histogram *h,
    int32_t bucket_index,
    int32_t sub_bucket_index)
{
    return value_from_index(bucket_index, sub_bucket_index, h->unit_magnitude);
}

int64_t hdr_next_non_equivalent_value(const struct hdr_histogram *h, int64_t value)
{
    return lowest_equivalent_value(h, value) + hdr_size_of_equivalent_value_range(h, value);
}

static int64_t highest_equivalent_value(const struct hdr_histogram* h, int64_t value)
{
    return hdr_next_non_equivalent_value(h, value) - 1;
}

int64_t hdr_median_equivalent_value(const struct hdr_histogram *h, int64_t value)
{
    return lowest_equivalent_value(h, value) + (hdr_size_of_equivalent_value_range(h, value) >> 1);
}

static int64_t non_zero_min(const struct hdr_histogram* h)
{
    if (INT64_MAX == h->min_value)
    {
        return INT64_MAX;
    }

    return lowest_equivalent_value(h, h->min_value);
}


static int32_t buckets_needed_to_cover_value(int64_t value, int32_t sub_bucket_count, int32_t unit_magnitude)
{
    int64_t smallest_untrackable_value = ((int64_t) sub_bucket_count) << unit_magnitude;
    int32_t buckets_needed = 1;
    while (smallest_untrackable_value <= value)
    {
        if (smallest_untrackable_value > INT64_MAX / 2)
        {
            return buckets_needed + 1;
        }
        smallest_untrackable_value <<= 1;
        buckets_needed++;
    }

    return buckets_needed;
}

/* ##     ## ######## ##     ##  #######  ########  ##    ## */
/* ###   ### ##       ###   ### ##     ## ##     ##  ##  ##  */
/* #### #### ##       #### #### ##     ## ##     ##   ####   */
/* ## ### ## ######   ## ### ## ##     ## ########     ##    */
/* ##     ## ##       ##     ## ##     ## ##   ##      ##    */
/* ##     ## ##       ##     ## ##     ## ##    ##     ##    */
/* ##     ## ######## ##     ##  #######  ##     ##    ##    */

int hdr_calculate_bucket_config(
        int64_t lowest_discernible_value,
        int64_t highest_trackable_value,
        int significant_figures,
        struct hdr_histogram_bucket_config* cfg)
{
    int32_t sub_bucket_count_magnitude;
    int64_t largest_value_with_single_unit_resolution;

    if (lowest_discernible_value < 1 ||
            significant_figures < 1 || 5 < significant_figures ||
            lowest_discernible_value * 2 > highest_trackable_value)
    {
        return EINVAL;
    }

    cfg->lowest_discernible_value = lowest_discernible_value;
    cfg->significant_figures = significant_figures;
    cfg->highest_trackable_value = highest_trackable_value;

    largest_value_with_single_unit_resolution = 2 * power(10, significant_figures);
    sub_bucket_count_magnitude = (int32_t) ceil(log((double)largest_value_with_single_unit_resolution) / log(2));
    cfg->sub_bucket_half_count_magnitude = ((sub_bucket_count_magnitude > 1) ? sub_bucket_count_magnitude : 1) - 1;

    double unit_magnitude = log((double)lowest_discernible_value) / log(2);
    if (INT32_MAX < unit_magnitude)
    {
        return EINVAL;
    }

    cfg->unit_magnitude = (int32_t) unit_magnitude;
    cfg->sub_bucket_count      = (int32_t) pow(2, (cfg->sub_bucket_half_count_magnitude + 1));
    cfg->sub_bucket_half_count = cfg->sub_bucket_count / 2;
    cfg->sub_bucket_mask       = ((int64_t) cfg->sub_bucket_count - 1) << cfg->unit_magnitude;

    if (cfg->unit_magnitude + cfg->sub_bucket_half_count_magnitude > 61)
    {
        return EINVAL;
    }

    cfg->bucket_count = buckets_needed_to_cover_value(highest_trackable_value, cfg->sub_bucket_count, (int32_t)cfg->unit_magnitude);
    cfg->counts_len = (cfg->bucket_count + 1) * (cfg->sub_bucket_count / 2);

    return 0;
}

void hdr_init_preallocated(struct hdr_histogram* h, struct hdr_histogram_bucket_config* cfg)
{
    h->lowest_discernible_value        = cfg->lowest_discernible_value;
    h->highest_trackable_value         = cfg->highest_trackable_value;
    h->unit_magnitude                  = (int32_t)cfg->unit_magnitude;
    h->significant_figures             = (int32_t)cfg->significant_figures;
    h->sub_bucket_half_count_magnitude = cfg->sub_bucket_half_count_magnitude;
    h->sub_bucket_half_count           = cfg->sub_bucket_half_count;
    h->sub_bucket_mask                 = cfg->sub_bucket_mask;
    h->sub_bucket_count                = cfg->sub_bucket_count;
    h->min_value                       = INT64_MAX;
    h->max_value                       = 0;
    h->normalizing_index_offset        = 0;
    h->conversion_ratio                = 1.0;
    h->bucket_count                    = cfg->bucket_count;
    h->counts_len                      = cfg->counts_len;
    h->total_count                     = 0;
}

int hdr_init(
        njt_slab_pool_t *shpool,
        int64_t lowest_discernible_value,
        int64_t highest_trackable_value,
        int significant_figures,
        struct hdr_histogram** result)
{
    njt_atomic_t* counts;
    struct hdr_histogram_bucket_config cfg;
    struct hdr_histogram* histogram;

    int r = hdr_calculate_bucket_config(lowest_discernible_value, highest_trackable_value, significant_figures, &cfg);
    if (r)
    {
        return r;
    }

    counts = (njt_atomic_t*) njt_slab_calloc(shpool, ((size_t) cfg.counts_len + njt_ncpu * 2)*sizeof(njt_atomic_t));
    if (!counts)
    {
        return ENOMEM;
    }

    histogram = (struct hdr_histogram*) njt_slab_calloc(shpool, sizeof(struct hdr_histogram));
    if (!histogram)
    {
        njt_slab_free(shpool, (void *)counts);
        // hdr_free(counts);
        return ENOMEM;
    }

    histogram->counts = counts;
    histogram->total_counts = counts + cfg.counts_len;
    histogram->count0s = histogram->total_counts + njt_ncpu;

    hdr_init_preallocated(histogram, &cfg);
    *result = histogram;

    return 0;
}

void hdr_close(njt_slab_pool_t *shpool, struct hdr_histogram* h)
{
    if (h) {
        njt_slab_free(shpool, (void *)h->counts);
        njt_slab_free(shpool, h);
    }
}

/* reset a histogram to zero. */
void hdr_reset(struct hdr_histogram *h)
{
    int i;

    h->total_count=0;
    h->min_value = INT64_MAX;
    h->max_value = 0;
    memset((void *)h->counts, 0, (sizeof(njt_atomic_t) * h->counts_len));

    for (i=0; i<njt_ncpu; i++) {
        h->total_counts[i] = 0;
        h->count0s[i] = 0;
    }
}

/* ##     ## ########  ########     ###    ######## ########  ######  */
/* ##     ## ##     ## ##     ##   ## ##      ##    ##       ##    ## */
/* ##     ## ##     ## ##     ##  ##   ##     ##    ##       ##       */
/* ##     ## ########  ##     ## ##     ##    ##    ######    ######  */
/* ##     ## ##        ##     ## #########    ##    ##             ## */
/* ##     ## ##        ##     ## ##     ##    ##    ##       ##    ## */
/*  #######  ##        ########  ##     ##    ##    ########  ######  */




bool hdr_record_values(struct hdr_histogram* h, uint64_t value, int64_t count)
{
    int32_t counts_index;

    // if (value < 0)
    // {
    //     return false;
    // }

    counts_index = counts_index_for(h, value);

    if (counts_index < 0 || h->counts_len <= counts_index)
    {
        return false;
    }

    counts_inc_normalised(h, counts_index, count);
    update_min_max(h, value);

    return true;
}

bool hdr_record_value(struct hdr_histogram* h, int64_t value)
{
    return hdr_record_values(h, value, 1);
}


/* ##     ##    ###    ##       ##     ## ########  ######  */
/* ##     ##   ## ##   ##       ##     ## ##       ##    ## */
/* ##     ##  ##   ##  ##       ##     ## ##       ##       */
/* ##     ## ##     ## ##       ##     ## ######    ######  */
/*  ##   ##  ######### ##       ##     ## ##             ## */
/*   ## ##   ##     ## ##       ##     ## ##       ##    ## */
/*    ###    ##     ## ########  #######  ########  ######  */


int64_t hdr_max(const struct hdr_histogram* h)
{
    if (0 == h->max_value)
    {
        return 0;
    }

    return highest_equivalent_value(h, h->max_value);
}


static int64_t get_value_from_idx_up_to_count(const struct hdr_histogram* h, int64_t count_at_percentile)
{
    int64_t count_to_idx = 0;
    int32_t idx;

    count_at_percentile = 0 < count_at_percentile ? count_at_percentile : 1;
    for (idx = 0; idx < h->counts_len; idx++)
    {
        count_to_idx += h->counts[idx];
        if (count_to_idx >= count_at_percentile)
        {
            return hdr_value_at_index(h, idx);
        }
    }

    return 0;
}


int64_t hdr_value_at_percentile(const struct hdr_histogram* h, double percentile)
{
    double requested_percentile = percentile < 100.0 ? percentile : 100.0;
    int64_t count_at_percentile =
        (int64_t) (((requested_percentile / 100) * h->total_count) + 0.5);
    int64_t value_from_idx = get_value_from_idx_up_to_count(h, count_at_percentile);
    if (percentile == 0.0)
    {
        return lowest_equivalent_value(h, value_from_idx);
    }
    return highest_equivalent_value(h, value_from_idx);
}


bool hdr_iter_next(struct hdr_iter* iter)
{
    return iter->_next_fp(iter);
}

static void update_iterated_values(struct hdr_iter* iter, int64_t new_value_iterated_to)
{
    iter->value_iterated_from = iter->value_iterated_to;
    iter->value_iterated_to = new_value_iterated_to;
}


void hdr_iter_init(struct hdr_iter* iter, const struct hdr_histogram* h);



int hdr_value_at_percentiles(struct hdr_histogram *h, const double *percentiles, int64_t *values, size_t length)
{
    struct hdr_iter iter;
    int64_t total_count = 0, total;
    size_t  at_pos = 0;
    size_t  i;
    int     id;

    if (NULL == percentiles || NULL == values)
    {
        return EINVAL;
    }

    for (id=0; id<njt_ncpu; id++) {
        total = h->count0s[id];
        total_count += total;
        total *= -1;
        njt_atomic_fetch_add(&h->count0s[id], total);
    }
    njt_atomic_fetch_add(&h->counts[0], total_count);


    total_count = h->total_count;
    for (id=0; id<njt_ncpu; id++) {
        total = h->total_counts[id];
        total_count += total;
        total *= -1;
        njt_atomic_fetch_add(&h->total_counts[id], total);
    }
    h->total_count = total_count;

    // to avoid allocations we use the values array for intermediate computation
    // i.e. to store the expected cumulative count at each percentile
    for (i = 0; i < length; i++)
    {
        const double requested_percentile = percentiles[i] < 100.0 ? percentiles[i] : 100.0;
        const int64_t count_at_percentile =
        (int64_t) (((requested_percentile / 100) * total_count) + 0.5);
        values[i] = count_at_percentile > 1 ? count_at_percentile : 1;
    }

    hdr_iter_init(&iter, h);
    total = 0;

    while (hdr_iter_next(&iter) && at_pos < length)
    {
        total += iter.count;
        while (at_pos < length && total >= values[at_pos])
        {
            values[at_pos] = highest_equivalent_value(h, iter.value);
            at_pos++;
        }
    }
    return 0;
}


double hdr_mean(const struct hdr_histogram* h)
{
    struct hdr_iter iter;
    int64_t total = 0, count = 0;
    int64_t total_count = h->total_count;

    hdr_iter_init(&iter, h);

    while (hdr_iter_next(&iter) && count < total_count)
    {
        if (0 != iter.count)
        {
            count += iter.count;
            total += iter.count * hdr_median_equivalent_value(h, iter.value);
        }
    }

    return (total * 1.0) / total_count;
}


int64_t hdr_count_at_index(const struct hdr_histogram* h, int32_t index)
{
    return counts_get_normalised(h, index);
}

int64_t hdr_min(const struct hdr_histogram* h)
{
    if (0 < hdr_count_at_index(h, 0))
    {
        return 0;
    }

    return non_zero_min(h);
}


/* #### ######## ######## ########     ###    ########  #######  ########   ######  */
/*  ##     ##    ##       ##     ##   ## ##      ##    ##     ## ##     ## ##    ## */
/*  ##     ##    ##       ##     ##  ##   ##     ##    ##     ## ##     ## ##       */
/*  ##     ##    ######   ########  ##     ##    ##    ##     ## ########   ######  */
/*  ##     ##    ##       ##   ##   #########    ##    ##     ## ##   ##         ## */
/*  ##     ##    ##       ##    ##  ##     ##    ##    ##     ## ##    ##  ##    ## */
/* ####    ##    ######## ##     ## ##     ##    ##     #######  ##     ##  ######  */


static bool has_buckets(struct hdr_iter* iter)
{
    return iter->counts_index < iter->h->counts_len;
}


static bool move_next(struct hdr_iter* iter)
{
    iter->counts_index++;

    if (!has_buckets(iter))
    {
        return false;
    }

    iter->count = counts_get_normalised(iter->h, iter->counts_index);
    iter->cumulative_count += iter->count;
    const int64_t value = hdr_value_at_index(iter->h, iter->counts_index);
    const int32_t bucket_index = get_bucket_index(iter->h, value);
    const int32_t sub_bucket_index = get_sub_bucket_index(value, bucket_index, iter->h->unit_magnitude);
    const int64_t leq = lowest_equivalent_value_given_bucket_indices(iter->h, bucket_index, sub_bucket_index);
    const int64_t size_of_equivalent_value_range = size_of_equivalent_value_range_given_bucket_indices(
        iter->h, bucket_index, sub_bucket_index);
    iter->lowest_equivalent_value = leq;
    iter->value = value;
    iter->highest_equivalent_value = leq + size_of_equivalent_value_range - 1;
    iter->median_equivalent_value = leq + (size_of_equivalent_value_range >> 1);

    return true;
}

static bool all_values_iter_next(struct hdr_iter* iter)
{
    bool result = move_next(iter);

    if (result)
    {
        update_iterated_values(iter, iter->value);
    }

    return result;
}


void hdr_iter_init(struct hdr_iter* iter, const struct hdr_histogram* h)
{
    iter->h = h;

    iter->counts_index = -1;
    iter->total_count = h->total_count;
    iter->count = 0;
    iter->cumulative_count = 0;
    iter->value = 0;
    iter->highest_equivalent_value = 0;
    iter->value_iterated_from = 0;
    iter->value_iterated_to = 0;

    iter->_next_fp = all_values_iter_next;
}


size_t hdr_get_memory_size(struct hdr_histogram *h)
{
    return sizeof(struct hdr_histogram) + h->counts_len * sizeof(int64_t);
}

static bool has_next(struct hdr_iter* iter)
{
    return iter->cumulative_count < iter->total_count;
}


static bool basic_iter_next(struct hdr_iter *iter)
{
    if (!has_next(iter) || iter->counts_index >= iter->h->counts_len)
    {
        return false;
    }

    move_next(iter);

    return true;
}

static bool recorded_iter_next(struct hdr_iter* iter)
{
    while (basic_iter_next(iter))
    {
        if (iter->count != 0)
        {
            update_iterated_values(iter, iter->value);

            iter->specifics.recorded.count_added_in_this_iteration_step = iter->count;
            return true;
        }
    }

    return false;
}


void hdr_iter_recorded_init(struct hdr_iter* iter, const struct hdr_histogram* h)
{
    hdr_iter_init(iter, h);

    iter->specifics.recorded.count_added_in_this_iteration_step = 0;

    iter->_next_fp = recorded_iter_next;
}


int64_t hdr_add(struct hdr_histogram* h, const struct hdr_histogram* from)
{
    struct hdr_iter iter;
    int64_t dropped = 0;
    hdr_iter_recorded_init(&iter, from);

    while (hdr_iter_next(&iter))
    {
        int64_t value = iter.value;
        int64_t count = iter.count;

        if (!hdr_record_values(h, value, count))
        {
            dropped += count;
        }
    }

    return dropped;
}

struct hdr_histogram* njt_http_vts_hdr = NULL;
double njt_http_vts_hdr_percentiles[5];
njt_int_t njt_http_vts_hdr_values[5];

njt_int_t njt_http_vts_hdr_init(njt_slab_pool_t *shpool)
{
    int r;

    r = hdr_init(shpool, 1, 60000, 3, &njt_http_vts_hdr);
    if ((r != 0) || (njt_http_vts_hdr == NULL)) {
        printf("hdr_init failed\n");
        return -1;
    }

    njt_http_vts_hdr_percentiles[0] = 50.0;
    njt_http_vts_hdr_percentiles[1] = 99.0;
    njt_http_vts_hdr_percentiles[2] = 99.9;
    njt_http_vts_hdr_percentiles[3] = 99.99;
    njt_http_vts_hdr_percentiles[4] = 99.999;

    return 0;
}

njt_int_t njt_http_vts_hdr_get(void)
{
    return (njt_int_t)hdr_value_at_percentiles(njt_http_vts_hdr, njt_http_vts_hdr_percentiles, njt_http_vts_hdr_values, 5);
}

bool njt_http_vts_hdr_record(njt_int_t value)
{
    bool b;
    // printf("record %d\n", (int)value);

    b = hdr_record_value(njt_http_vts_hdr, value);
    return b;
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
