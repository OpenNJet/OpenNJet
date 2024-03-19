
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#include <njt_config.h>

#include "njt_stream_server_traffic_status_module.h"
#include "njt_stream_server_traffic_status_filter.h"
#include "njt_stream_server_traffic_status_shm.h"


static njt_int_t njt_stream_server_traffic_status_shm_add_node(njt_stream_session_t *s,
    njt_str_t *key, unsigned type);
static njt_int_t njt_stream_server_traffic_status_shm_add_node_upstream(njt_stream_session_t *s,
    njt_stream_server_traffic_status_node_t *stsn, unsigned init);

static njt_int_t njt_stream_server_traffic_status_shm_add_filter_node(njt_stream_session_t *s,
    njt_array_t *filter_keys);


static njt_int_t
njt_stream_server_traffic_status_shm_add_node(njt_stream_session_t *s,
    njt_str_t *key, unsigned type)
{
    size_t                                    size;
    unsigned                                  init;
    uint32_t                                  hash;
    njt_slab_pool_t                          *shpool;
    njt_rbtree_node_t                        *node;
    njt_stream_server_traffic_status_ctx_t   *ctx;
    njt_stream_server_traffic_status_node_t  *stsn;
    njt_stream_server_traffic_status_conf_t  *stscf;

    ctx = njt_stream_get_module_main_conf(s, njt_stream_stsc_module);

    stscf = njt_stream_get_module_srv_conf(s, njt_stream_stsc_module);

    if (key->len == 0) {
        return NJT_ERROR;
    }

    shpool = (njt_slab_pool_t *) stscf->shm_zone->shm.addr;

    njt_shmtx_lock(&shpool->mutex);

    /* find node */
    hash = njt_crc32_short(key->data, key->len);

    node = njt_stream_server_traffic_status_find_node(s, key, type, hash);

    /* set common */
    if (node == NULL) {
        init = NJT_STREAM_SERVER_TRAFFIC_STATUS_NODE_NONE;
        size = offsetof(njt_rbtree_node_t, color)
               + offsetof(njt_stream_server_traffic_status_node_t, data)
               + key->len;

        node = njt_slab_alloc_locked(shpool, size);
        if (node == NULL) {
            njt_shmtx_unlock(&shpool->mutex);
            return NJT_ERROR;
        }

        stsn = (njt_stream_server_traffic_status_node_t *) &node->color;

        node->key = hash;
        stsn->len = (u_char) key->len;
        njt_stream_server_traffic_status_node_init(s, stsn);
        stsn->stat_upstream.type = type;
        njt_memcpy(stsn->data, key->data, key->len);

        njt_rbtree_insert(ctx->rbtree, node);

    } else {
        init = NJT_STREAM_SERVER_TRAFFIC_STATUS_NODE_FIND;
        stsn = (njt_stream_server_traffic_status_node_t *) &node->color;
        njt_stream_server_traffic_status_node_set(s, stsn);
    }

    /* set addition */
    switch(type) {
    case NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_NO:
        break;

    case NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_UA:
    case NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_UG:
        (void) njt_stream_server_traffic_status_shm_add_node_upstream(s, stsn, init);
        break;

    case NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_FG:
        break;
    }

    stscf->node_caches[type] = node;

    njt_shmtx_unlock(&shpool->mutex);

    return NJT_OK;
}


static njt_int_t
njt_stream_server_traffic_status_shm_add_node_upstream(njt_stream_session_t *s,
    njt_stream_server_traffic_status_node_t *stsn, unsigned init)
{
    njt_msec_int_t                            connect_time, first_byte_time, session_time;
    njt_stream_server_traffic_status_node_t   ostsn;
    njt_stream_server_traffic_status_conf_t  *stscf;

    stscf = njt_stream_get_module_srv_conf(s, njt_stream_stsc_module);

    ostsn = *stsn;
    connect_time = njt_stream_server_traffic_status_upstream_response_time(s, 2);
    first_byte_time = njt_stream_server_traffic_status_upstream_response_time(s, 1); 
    session_time = njt_stream_server_traffic_status_upstream_response_time(s, 0); 

    njt_stream_server_traffic_status_node_time_queue_insert(
        &stsn->stat_upstream.connect_times,
        connect_time);
    njt_stream_server_traffic_status_node_time_queue_insert(
        &stsn->stat_upstream.first_byte_times,
        first_byte_time);
    njt_stream_server_traffic_status_node_time_queue_insert(
        &stsn->stat_upstream.session_times,
        session_time);

    njt_stream_server_traffic_status_node_histogram_observe(
        &stsn->stat_upstream.connect_buckets,
        connect_time);

    njt_stream_server_traffic_status_node_histogram_observe(
        &stsn->stat_upstream.first_byte_buckets,
        first_byte_time);

    njt_stream_server_traffic_status_node_histogram_observe(
        &stsn->stat_upstream.session_buckets,
        session_time);

    if (init == NJT_STREAM_SERVER_TRAFFIC_STATUS_NODE_NONE) {
        stsn->stat_upstream.connect_time_counter = (njt_atomic_uint_t) connect_time;
        stsn->stat_upstream.connect_time = (njt_msec_t) connect_time;
        stsn->stat_upstream.first_byte_time_counter = (njt_atomic_uint_t) first_byte_time;
        stsn->stat_upstream.first_byte_time = (njt_msec_t) first_byte_time;
        stsn->stat_upstream.session_time_counter = (njt_atomic_uint_t) session_time;
        stsn->stat_upstream.session_time = (njt_msec_t) session_time;

    } else {
        stsn->stat_upstream.connect_time_counter += (njt_atomic_uint_t) connect_time;
        stsn->stat_upstream.connect_time = njt_stream_server_traffic_status_node_time_queue_average(
                                               &stsn->stat_upstream.connect_times,
                                               stscf->average_method, stscf->average_period);

        stsn->stat_upstream.first_byte_time_counter += (njt_atomic_uint_t) first_byte_time;
        stsn->stat_upstream.first_byte_time = njt_stream_server_traffic_status_node_time_queue_average(
                                                  &stsn->stat_upstream.first_byte_times,
                                                  stscf->average_method, stscf->average_period);

        stsn->stat_upstream.session_time_counter += (njt_atomic_uint_t) session_time;
        stsn->stat_upstream.session_time = njt_stream_server_traffic_status_node_time_queue_average(
                                               &stsn->stat_upstream.session_times,
                                               stscf->average_method, stscf->average_period);

        /* overflow */
        if (ostsn.stat_upstream.connect_time_counter
            > stsn->stat_upstream.connect_time_counter)
        {
            stsn->stat_u_connect_time_counter_oc++;
        }
        if (ostsn.stat_upstream.first_byte_time_counter
            > stsn->stat_upstream.first_byte_time_counter)
        {
            stsn->stat_u_first_byte_time_counter_oc++;
        }
        if (ostsn.stat_upstream.session_time_counter
            > stsn->stat_upstream.session_time_counter)
        {
            stsn->stat_u_session_time_counter_oc++;
        }
    }

    return NJT_OK;
}


static njt_int_t
njt_stream_server_traffic_status_shm_add_filter_node(njt_stream_session_t *s,
    njt_array_t *filter_keys)
{
    u_char                                     *p;
    unsigned                                    type;
    njt_int_t                                   rc;
    njt_str_t                                   key, dst, filter_key, filter_name;
    njt_uint_t                                  i, n;
    njt_stream_server_traffic_status_filter_t  *filters;

    if (filter_keys == NULL) {
        return NJT_OK;
    }

    filters = filter_keys->elts;
    n = filter_keys->nelts;

    for (i = 0; i < n; i++) {
        if (filters[i].filter_key.value.len <= 0) {
            continue;
        }

        if (njt_stream_complex_value(s, &filters[i].filter_key, &filter_key) != NJT_OK) {
            return NJT_ERROR;
        }

        if (njt_stream_complex_value(s, &filters[i].filter_name, &filter_name) != NJT_OK) {
            return NJT_ERROR;
        }

        if (filter_key.len == 0) {
            continue;
        }

        if (filter_name.len == 0) {
            type = NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_NO;

            rc = njt_stream_server_traffic_status_node_generate_key(s->connection->pool, &key, &filter_key, type);
            if (rc != NJT_OK) {
                return NJT_ERROR;
            }

        } else {
            type = filter_name.len
                   ? NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_FG
                   : NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_NO;

            dst.len = filter_name.len + sizeof("@") - 1 + filter_key.len;
            dst.data = njt_pnalloc(s->connection->pool, dst.len);
            if (dst.data == NULL) {
                return NJT_ERROR;
            }

            p = dst.data;
            p = njt_cpymem(p, filter_name.data, filter_name.len);
            *p++ = NJT_STREAM_SERVER_TRAFFIC_STATUS_KEY_SEPARATOR;
            p = njt_cpymem(p, filter_key.data, filter_key.len);

            rc = njt_stream_server_traffic_status_node_generate_key(s->connection->pool, &key, &dst, type);
            if (rc != NJT_OK) {
                return NJT_ERROR;
            }
        }

        rc = njt_stream_server_traffic_status_shm_add_node(s, &key, type);
        if (rc != NJT_OK) {
            njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                          "shm_add_filter_node::shm_add_node(\"%V\") failed", &key);
        }
    }

    return NJT_OK;
}


njt_int_t
njt_stream_server_traffic_status_shm_add_server(njt_stream_session_t *s)
{
    unsigned   type;
    njt_int_t  rc;
    njt_str_t  key, dst;

    rc = njt_stream_server_traffic_status_find_name(s, &dst);
    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    type = NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_NO;

    rc = njt_stream_server_traffic_status_node_generate_key(s->connection->pool, &key, &dst, type);
    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    return njt_stream_server_traffic_status_shm_add_node(s, &key, type);
}


njt_int_t
njt_stream_server_traffic_status_shm_add_filter(njt_stream_session_t *s)
{
    njt_int_t                                 rc;
    njt_stream_server_traffic_status_ctx_t   *ctx;
    njt_stream_server_traffic_status_conf_t  *stscf;

    ctx = njt_stream_get_module_main_conf(s, njt_stream_stsc_module);

    stscf = njt_stream_get_module_srv_conf(s, njt_stream_stsc_module);

    if (!stscf->filter) {
        return NJT_OK;
    }

    if (ctx->filter_keys != NULL) {
        rc = njt_stream_server_traffic_status_shm_add_filter_node(s, ctx->filter_keys);
        if (rc != NJT_OK) {
            njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                          "shm_add_filter::shm_add_filter_node(\"stream\") failed");
        }
    }

    if (stscf->filter_keys != NULL) {
        rc = njt_stream_server_traffic_status_shm_add_filter_node(s, stscf->filter_keys);
        if (rc != NJT_OK) {
            njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                          "shm_add_filter::shm_add_filter_node(\"server\") failed");
        }
    }

    return NJT_OK;
}

njt_int_t
njt_stream_server_traffic_status_shm_add_upstream(njt_stream_session_t *s)
{
    u_char                           *p;
    unsigned                          type;
    njt_int_t                         rc;
    njt_str_t                        *host, key, dst;
    njt_uint_t                        i;
    njt_stream_upstream_t            *u;
    njt_stream_upstream_srv_conf_t   *uscf, **uscfp;
    njt_stream_upstream_main_conf_t  *umcf;
    njt_stream_upstream_state_t      *state;

    if (s->upstream_states == NULL || s->upstream_states->nelts == 0
        || s->upstream->state == NULL)
    {
        return NJT_OK;
    }

    u = s->upstream;

    if (u->resolved == NULL) {
        uscf = u->upstream;
    } else {
        host = &u->resolved->host;

        umcf = njt_stream_get_module_main_conf(s, njt_stream_upstream_module);

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
        uscf = njt_pcalloc(s->connection->pool, sizeof(njt_stream_upstream_srv_conf_t));
        if (uscf == NULL) {
            return NJT_ERROR;
        }

        uscf->host = u->resolved->host;
        uscf->port = u->resolved->port;
    }

found:

    state = s->upstream_states->elts;
    if (state[0].peer == NULL) {
        njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                      "shm_add_upstream::peer failed");
        return NJT_ERROR;
    }

    dst.len = (uscf->port ? 0 : uscf->host.len + sizeof("@") - 1) + state[0].peer->len;
    dst.data = njt_pnalloc(s->connection->pool, dst.len);
    if (dst.data == NULL) {
        return NJT_ERROR;
    }

    p = dst.data;
    if (uscf->port) {
        p = njt_cpymem(p, state[0].peer->data, state[0].peer->len);
        type = NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_UA;

    } else {
        p = njt_cpymem(p, uscf->host.data, uscf->host.len);
        *p++ = NJT_STREAM_SERVER_TRAFFIC_STATUS_KEY_SEPARATOR;
        p = njt_cpymem(p, state[0].peer->data, state[0].peer->len);
        type = NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_UG;
    }

    rc = njt_stream_server_traffic_status_node_generate_key(s->connection->pool, &key, &dst, type);
    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    rc = njt_stream_server_traffic_status_shm_add_node(s, &key, type);
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, s->connection->log, 0,
                      "shm_add_upstream::shm_add_node(\"%V\") failed", &key);
    }

    return NJT_OK;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
