
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 * Copyright (C), 2021-2023, TMLake(Beijing) Technology Co., Ltd.
 */


#include "njt_http_vhost_traffic_status_module.h"
#include "njt_http_vhost_traffic_status_shm.h"
#include "njt_http_vhost_traffic_status_display_prometheus.h"


u_char *
njt_http_vhost_traffic_status_display_prometheus_set_main(njt_http_request_t *r,
    u_char *buf)
{
    njt_atomic_int_t                           ap, hn, ac, rq, rd, wr, wa;
    njt_http_vhost_traffic_status_loc_conf_t  *vtscf;
    njt_http_vhost_traffic_status_shm_info_t  *shm_info;

    vtscf = njt_http_get_module_loc_conf(r, njt_http_vhost_traffic_status_module);

    ap = *njt_stat_accepted;
    hn = *njt_stat_handled;
    ac = *njt_stat_active;
    rq = *njt_stat_requests;
    rd = *njt_stat_reading;
    wr = *njt_stat_writing;
    wa = *njt_stat_waiting;

    shm_info = njt_pcalloc(r->pool, sizeof(njt_http_vhost_traffic_status_shm_info_t));
    if (shm_info == NULL) {
        return buf;
    }

    njt_http_vhost_traffic_status_shm_info(r, shm_info);

    buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_MAIN, &njt_cycle->hostname,
                      NJT_HTTP_VTS_MODULE_VERSION, NJT_VERSION,
                      (double) vtscf->start_msec / 1000,
                      ap, ac, hn, rd, rq, wa, wr,
                      shm_info->name, shm_info->max_size,
                      shm_info->used_size, shm_info->used_node);

    return buf;
}


u_char *
njt_http_vhost_traffic_status_display_prometheus_set_server_node(
    njt_http_request_t *r,
    u_char *buf, njt_str_t *key,
    njt_http_vhost_traffic_status_node_t *vtsn)
{
    njt_str_t                                               server;
    njt_uint_t                                              i, n;
    njt_http_vhost_traffic_status_loc_conf_t               *vtscf;
    njt_http_vhost_traffic_status_node_histogram_bucket_t  *b;

    vtscf = njt_http_get_module_loc_conf(r, njt_http_vhost_traffic_status_module);

    server = *key;

    (void) njt_http_vhost_traffic_status_node_position_key(&server, 1);

    buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER,
                      &server, vtsn->stat_in_bytes,
                      &server, vtsn->stat_out_bytes,
                      &server, vtsn->stat_1xx_counter,
                      &server, vtsn->stat_2xx_counter,
                      &server, vtsn->stat_3xx_counter,
                      &server, vtsn->stat_4xx_counter,
                      &server, vtsn->stat_5xx_counter,
                      &server, (double) vtsn->stat_request_time_counter / 1000,
                      &server, (double) njt_http_vhost_traffic_status_node_time_queue_average(
                                   &vtsn->stat_request_times, vtscf->average_method,
                                   vtscf->average_period) / 1000);

    /* histogram */
    b = &vtsn->stat_request_buckets;

    n = b->len;

    if (n > 0) {

        /* histogram:bucket */
        for (i = 0; i < n; i++) {
            buf = njt_sprintf(buf,
                      NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_HISTOGRAM_BUCKET,
                      &server, (double) b->buckets[i].msec / 1000, b->buckets[i].counter);
        }

        buf = njt_sprintf(buf,
                  NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_HISTOGRAM_BUCKET_E,
                  &server, vtsn->stat_request_counter);

        /* histogram:sum */
        buf = njt_sprintf(buf,
                  NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_HISTOGRAM_SUM,
                  &server, (double) vtsn->stat_request_time_counter / 1000);

        /* histogram:count */
        buf = njt_sprintf(buf,
                  NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_HISTOGRAM_COUNT,
                  &server, vtsn->stat_request_counter);
    }

#if (NJT_HTTP_CACHE)
    buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_CACHE,
                      &server, vtsn->stat_cache_miss_counter,
                      &server, vtsn->stat_cache_bypass_counter,
                      &server, vtsn->stat_cache_expired_counter,
                      &server, vtsn->stat_cache_stale_counter,
                      &server, vtsn->stat_cache_updating_counter,
                      &server, vtsn->stat_cache_revalidated_counter,
                      &server, vtsn->stat_cache_hit_counter,
                      &server, vtsn->stat_cache_scarce_counter);
#endif

    return buf;
}


u_char *
njt_http_vhost_traffic_status_display_prometheus_set_server(njt_http_request_t *r,
    u_char *buf, njt_rbtree_node_t *node)
{
    njt_str_t                                  key, escaped_key;
    njt_http_vhost_traffic_status_ctx_t       *ctx;
    njt_http_vhost_traffic_status_node_t      *vtsn;
    njt_http_vhost_traffic_status_loc_conf_t  *vtscf;

    ctx = njt_http_get_module_main_conf(r, njt_http_vhost_traffic_status_module);

    vtscf = njt_http_get_module_loc_conf(r, njt_http_vhost_traffic_status_module);

    if (node != ctx->rbtree->sentinel) {
        vtsn = njt_http_vhost_traffic_status_get_node(node);
        njt_http_vhost_traffic_status_sum_node(vtsn, vtscf);

        if (vtsn->stat_upstream.type == NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO) {
            key.data = vtsn->data;
            key.len = vtsn->len;

            njt_http_vhost_traffic_status_escape_prometheus(r->pool, &escaped_key, key.data, key.len);
            buf = njt_http_vhost_traffic_status_display_prometheus_set_server_node(r, buf, &escaped_key, vtsn);

            /* calculates the sum */
            vtscf->stats.stat_request_counter += vtsn->stat_request_counter;
            vtscf->stats.stat_in_bytes += vtsn->stat_in_bytes;
            vtscf->stats.stat_out_bytes += vtsn->stat_out_bytes;
            vtscf->stats.stat_1xx_counter += vtsn->stat_1xx_counter;
            vtscf->stats.stat_2xx_counter += vtsn->stat_2xx_counter;
            vtscf->stats.stat_3xx_counter += vtsn->stat_3xx_counter;
            vtscf->stats.stat_4xx_counter += vtsn->stat_4xx_counter;
            vtscf->stats.stat_5xx_counter += vtsn->stat_5xx_counter;
            vtscf->stats.stat_request_time_counter += vtsn->stat_request_time_counter;
            njt_http_vhost_traffic_status_node_time_queue_merge(
                &vtscf->stats.stat_request_times,
                &vtsn->stat_request_times, vtscf->average_period);

#if (NJT_HTTP_CACHE)
            vtscf->stats.stat_cache_miss_counter +=
                                       vtsn->stat_cache_miss_counter;
            vtscf->stats.stat_cache_bypass_counter +=
                                       vtsn->stat_cache_bypass_counter;
            vtscf->stats.stat_cache_expired_counter +=
                                       vtsn->stat_cache_expired_counter;
            vtscf->stats.stat_cache_stale_counter +=
                                       vtsn->stat_cache_stale_counter;
            vtscf->stats.stat_cache_updating_counter +=
                                       vtsn->stat_cache_updating_counter;
            vtscf->stats.stat_cache_revalidated_counter +=
                                       vtsn->stat_cache_revalidated_counter;
            vtscf->stats.stat_cache_hit_counter +=
                                       vtsn->stat_cache_hit_counter;
            vtscf->stats.stat_cache_scarce_counter +=
                                       vtsn->stat_cache_scarce_counter;
#endif
        }

        buf = njt_http_vhost_traffic_status_display_prometheus_set_server(r, buf, node->left);
        buf = njt_http_vhost_traffic_status_display_prometheus_set_server(r, buf, node->right);
    }

    return buf;
}


u_char *
njt_http_vhost_traffic_status_display_prometheus_set_filter_node(
    njt_http_request_t *r,
    u_char *buf, njt_str_t *key,
    njt_http_vhost_traffic_status_node_t *vtsn)
{
    njt_str_t                                               filter, filter_name;
    njt_uint_t                                              i, n;
    njt_http_vhost_traffic_status_loc_conf_t               *vtscf;
    njt_http_vhost_traffic_status_node_histogram_bucket_t  *b;

    vtscf = njt_http_get_module_loc_conf(r, njt_http_vhost_traffic_status_module);

    filter = filter_name = *key;

    (void) njt_http_vhost_traffic_status_node_position_key(&filter, 1);
    (void) njt_http_vhost_traffic_status_node_position_key(&filter_name, 2);

    buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER,
                      &filter, &filter_name, vtsn->stat_in_bytes,
                      &filter, &filter_name, vtsn->stat_out_bytes,
                      &filter, &filter_name, vtsn->stat_1xx_counter,
                      &filter, &filter_name, vtsn->stat_2xx_counter,
                      &filter, &filter_name, vtsn->stat_3xx_counter,
                      &filter, &filter_name, vtsn->stat_4xx_counter,
                      &filter, &filter_name, vtsn->stat_5xx_counter,
                      &filter, &filter_name, (double) vtsn->stat_request_time_counter / 1000,
                      &filter, &filter_name,
                      (double) njt_http_vhost_traffic_status_node_time_queue_average(
                          &vtsn->stat_request_times, vtscf->average_method,
                          vtscf->average_period) / 1000);

    /* histogram */
    b = &vtsn->stat_request_buckets;

    n = b->len;

    if (n > 0) {

        /* histogram:bucket */
        for (i = 0; i < n; i++) {
            buf = njt_sprintf(buf,
                      NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_HISTOGRAM_BUCKET,
                      &filter, &filter_name, (double) b->buckets[i].msec / 1000,
                      b->buckets[i].counter);
        }

        buf = njt_sprintf(buf,
                  NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_HISTOGRAM_BUCKET_E,
                  &filter, &filter_name, vtsn->stat_request_counter);

        /* histogram:sum */
        buf = njt_sprintf(buf,
                  NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_HISTOGRAM_SUM,
                  &filter, &filter_name, (double) vtsn->stat_request_time_counter / 1000);

        /* histogram:count */
        buf = njt_sprintf(buf,
                  NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_HISTOGRAM_COUNT,
                  &filter, &filter_name, vtsn->stat_request_counter);
    }

#if (NJT_HTTP_CACHE)
    buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_CACHE,
                      &filter, &filter_name, vtsn->stat_cache_miss_counter,
                      &filter, &filter_name, vtsn->stat_cache_bypass_counter,
                      &filter, &filter_name, vtsn->stat_cache_expired_counter,
                      &filter, &filter_name, vtsn->stat_cache_stale_counter,
                      &filter, &filter_name, vtsn->stat_cache_updating_counter,
                      &filter, &filter_name, vtsn->stat_cache_revalidated_counter,
                      &filter, &filter_name, vtsn->stat_cache_hit_counter,
                      &filter, &filter_name, vtsn->stat_cache_scarce_counter);
#endif

    return buf;
}


u_char *
njt_http_vhost_traffic_status_display_prometheus_set_filter(njt_http_request_t *r,
    u_char *buf, njt_rbtree_node_t *node)
{
    njt_str_t                              key, escaped_key;
    njt_http_vhost_traffic_status_ctx_t   *ctx;
    njt_http_vhost_traffic_status_node_t  *vtsn;

    ctx = njt_http_get_module_main_conf(r, njt_http_vhost_traffic_status_module);

    if (node != ctx->rbtree->sentinel) {
        vtsn = njt_http_vhost_traffic_status_get_node(node);

        if (vtsn->stat_upstream.type == NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG) {
            key.data = vtsn->data;
            key.len = vtsn->len;

            njt_http_vhost_traffic_status_escape_prometheus(r->pool, &escaped_key, key.data, key.len);
            buf = njt_http_vhost_traffic_status_display_prometheus_set_filter_node(r, buf, &escaped_key, vtsn);
        }

        buf = njt_http_vhost_traffic_status_display_prometheus_set_filter(r, buf, node->left);
        buf = njt_http_vhost_traffic_status_display_prometheus_set_filter(r, buf, node->right);
    }

    return buf;
}


u_char *
njt_http_vhost_traffic_status_display_prometheus_set_upstream_node(
    njt_http_request_t *r,
    u_char *buf, njt_str_t *key,
    njt_http_vhost_traffic_status_node_t *vtsn)
{
    njt_str_t                                               target, upstream, upstream_server;
    njt_uint_t                                              i, n, len;
    njt_atomic_t                                            time_counter;
    njt_http_vhost_traffic_status_loc_conf_t               *vtscf;
    njt_http_vhost_traffic_status_node_histogram_bucket_t  *b;

    vtscf = njt_http_get_module_loc_conf(r, njt_http_vhost_traffic_status_module);

    upstream = upstream_server = *key;

    if (vtsn->stat_upstream.type == NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG) {
        (void) njt_http_vhost_traffic_status_node_position_key(&upstream, 1);
        (void) njt_http_vhost_traffic_status_node_position_key(&upstream_server, 2);

    } else if (vtsn->stat_upstream.type == NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA) {
        njt_str_set(&upstream, "::nogroups");
        (void) njt_http_vhost_traffic_status_node_position_key(&upstream_server, 1);
    }

    buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM,
                      &upstream, &upstream_server, vtsn->stat_in_bytes,
                      &upstream, &upstream_server, vtsn->stat_out_bytes,
                      &upstream, &upstream_server, vtsn->stat_1xx_counter,
                      &upstream, &upstream_server, vtsn->stat_2xx_counter,
                      &upstream, &upstream_server, vtsn->stat_3xx_counter,
                      &upstream, &upstream_server, vtsn->stat_4xx_counter,
                      &upstream, &upstream_server, vtsn->stat_5xx_counter,
                      &upstream, &upstream_server, vtsn->stat_timeo_counter_oc,
                      &upstream, &upstream_server, (double) vtsn->stat_request_time_counter / 1000,
                      &upstream, &upstream_server,
                      (double) njt_http_vhost_traffic_status_node_time_queue_average(
                          &vtsn->stat_request_times, vtscf->average_method,
                          vtscf->average_period) / 1000,
                      &upstream, &upstream_server, (double) vtsn->stat_upstream.response_time_counter / 1000,
                      &upstream, &upstream_server,
                      (double) njt_http_vhost_traffic_status_node_time_queue_average(
                          &vtsn->stat_upstream.response_times, vtscf->average_method,
                          vtscf->average_period) / 1000);

    /* histogram */
    len = 2;

    while (len--) {
        if (len > 0) {
            b = &vtsn->stat_request_buckets;
            time_counter = vtsn->stat_request_time_counter;
            njt_str_set(&target, "request");

        } else {
            b = &vtsn->stat_upstream.response_buckets;
            time_counter = vtsn->stat_upstream.response_time_counter;
            njt_str_set(&target, "response");
        }

        n = b->len;

        if (n > 0) {
            /* histogram:bucket */
            for (i = 0; i < n; i++) {
                buf = njt_sprintf(buf,
                        NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HISTOGRAM_BUCKET,
                        &target, &upstream, &upstream_server, (double) b->buckets[i].msec / 1000,
                        b->buckets[i].counter);
            }

            buf = njt_sprintf(buf,
                    NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HISTOGRAM_BUCKET_E,
                    &target, &upstream, &upstream_server, vtsn->stat_request_counter);

            /* histogram:sum */
            buf = njt_sprintf(buf,
                    NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HISTOGRAM_SUM,
                    &target, &upstream, &upstream_server, (double) time_counter / 1000);

            /* histogram:count */
            buf = njt_sprintf(buf,
                    NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HISTOGRAM_COUNT,
                    &target, &upstream, &upstream_server, vtsn->stat_request_counter);
        }

    }

    return buf;
}


u_char *
njt_http_vhost_traffic_status_display_prometheus_set_upstream(njt_http_request_t *r,
    u_char *buf, njt_rbtree_node_t *node)
{
    njt_str_t                              key, escaped_key;
    njt_http_vhost_traffic_status_ctx_t   *ctx;
    njt_http_vhost_traffic_status_node_t  *vtsn;

    ctx = njt_http_get_module_main_conf(r, njt_http_vhost_traffic_status_module);

    if (node != ctx->rbtree->sentinel) {
        vtsn = njt_http_vhost_traffic_status_get_node(node);

        if (vtsn->stat_upstream.type == NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG
            || vtsn->stat_upstream.type == NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA)
        {
            key.data = vtsn->data;
            key.len = vtsn->len;

            njt_http_vhost_traffic_status_escape_prometheus(r->pool, &escaped_key, key.data, key.len);
            buf = njt_http_vhost_traffic_status_display_prometheus_set_upstream_node(r, buf, &escaped_key, vtsn);
        }

        buf = njt_http_vhost_traffic_status_display_prometheus_set_upstream(r, buf, node->left);
        buf = njt_http_vhost_traffic_status_display_prometheus_set_upstream(r, buf, node->right);
    }

    return buf;
}


#if (NJT_HTTP_CACHE)

u_char *
njt_http_vhost_traffic_status_display_prometheus_set_cache_node(
    njt_http_request_t *r,
    u_char *buf, njt_str_t *key,
    njt_http_vhost_traffic_status_node_t *vtsn)
{
    njt_str_t  cache;

    cache = *key;

    (void) njt_http_vhost_traffic_status_node_position_key(&cache, 1);

    buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_CACHE,
                      &cache, vtsn->stat_cache_max_size,
                      &cache, vtsn->stat_cache_used_size,
                      &cache, vtsn->stat_in_bytes,
                      &cache, vtsn->stat_out_bytes,
                      &cache, vtsn->stat_cache_miss_counter,
                      &cache, vtsn->stat_cache_bypass_counter,
                      &cache, vtsn->stat_cache_expired_counter,
                      &cache, vtsn->stat_cache_stale_counter,
                      &cache, vtsn->stat_cache_updating_counter,
                      &cache, vtsn->stat_cache_revalidated_counter,
                      &cache, vtsn->stat_cache_hit_counter,
                      &cache, vtsn->stat_cache_scarce_counter);

    return buf;
}


u_char *
njt_http_vhost_traffic_status_display_prometheus_set_cache(njt_http_request_t *r,
    u_char *buf, njt_rbtree_node_t *node)
{
    njt_str_t                              key, escaped_key;
    njt_http_vhost_traffic_status_ctx_t   *ctx;
    njt_http_vhost_traffic_status_node_t  *vtsn;

    ctx = njt_http_get_module_main_conf(r, njt_http_vhost_traffic_status_module);

    if (node != ctx->rbtree->sentinel) {
        vtsn = njt_http_vhost_traffic_status_get_node(node);

        if (vtsn->stat_upstream.type == NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC) {
            key.data = vtsn->data;
            key.len = vtsn->len;

            njt_http_vhost_traffic_status_escape_prometheus(r->pool, &escaped_key, key.data, key.len);
            buf = njt_http_vhost_traffic_status_display_prometheus_set_cache_node(r, buf, &escaped_key, vtsn);
        }

        buf = njt_http_vhost_traffic_status_display_prometheus_set_cache(r, buf, node->left);
        buf = njt_http_vhost_traffic_status_display_prometheus_set_cache(r, buf, node->right);
    }

    return buf;
}

#endif


u_char *
njt_http_vhost_traffic_status_display_prometheus_set(njt_http_request_t *r,
    u_char *buf)
{
    njt_str_t                                 escaped_key;
    u_char                                    *o, *s;
    njt_rbtree_node_t                         *node;
    njt_http_vhost_traffic_status_ctx_t       *ctx;
    njt_http_vhost_traffic_status_loc_conf_t  *vtscf;

    ctx = njt_http_get_module_main_conf(r, njt_http_vhost_traffic_status_module);

    vtscf = njt_http_get_module_loc_conf(r, njt_http_vhost_traffic_status_module);

    node = ctx->rbtree->root;

    /* init stats */
    njt_memzero(&vtscf->stats, sizeof(vtscf->stats));
    njt_http_vhost_traffic_status_node_time_queue_init(&vtscf->stats.stat_request_times);

    /* main & connections */
    buf = njt_http_vhost_traffic_status_display_prometheus_set_main(r, buf);

    /* serverZones */
    buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_S);
#if (NJT_HTTP_CACHE)
    buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_CACHE_S);
#endif
    buf = njt_http_vhost_traffic_status_display_prometheus_set_server(r, buf, node);

    njt_http_vhost_traffic_status_escape_prometheus(r->pool, &escaped_key, vtscf->sum_key.data, vtscf->sum_key.len);
    buf = njt_http_vhost_traffic_status_display_prometheus_set_server_node(r, buf, &escaped_key, &vtscf->stats);
    
    /* filterZones */
    o = buf;

    buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_S);
#if (NJT_HTTP_CACHE)
    buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_CACHE_S);
#endif

    s = buf;

    buf = njt_http_vhost_traffic_status_display_prometheus_set_filter(r, buf, node);

    if (s == buf) {
        buf = o;
    }

    /* upstreamZones */
    o = buf;

    buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_S);

    s = buf;

    buf = njt_http_vhost_traffic_status_display_prometheus_set_upstream(r, buf, node);

    if (s == buf) {
        buf = o;
    } else {
        extern njt_int_t njt_http_vts_hdr_values[5];
        extern njt_int_t njt_http_vts_hdr_get(void);
        buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HDR_S);
        njt_http_vts_hdr_get();
        buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HDR,
                    njt_http_vts_hdr_values[0],
                    njt_http_vts_hdr_values[1],
                    njt_http_vts_hdr_values[2],
                    njt_http_vts_hdr_values[3],
                    njt_http_vts_hdr_values[4]);
    }

#if (NJT_HTTP_CACHE)
    /* cacheZones */
    o = buf;

    buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_PROMETHEUS_FMT_CACHE_S);

    s = buf;

    buf = njt_http_vhost_traffic_status_display_prometheus_set_cache(r, buf, node);

    if (s == buf) {
        buf = o;
    }
#endif

    return buf;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
