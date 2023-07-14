
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 * Copyright (C), 2021-2023, TMLake(Beijing) Technology Co., Ltd.
 */


#include "njt_http_vhost_traffic_status_module.h"
#include "njt_http_vhost_traffic_status_shm.h"
#include "njt_http_vhost_traffic_status_filter.h"
#include "njt_http_vhost_traffic_status_display_json.h"
#include "njt_http_vhost_traffic_status_display.h"

#if (NJT_HTTP_UPSTREAM_CHECK)
#include "njt_http_upstream_check_module.h"
#endif


u_char *
njt_http_vhost_traffic_status_display_set_main(njt_http_request_t *r,
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

    buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_MAIN, &njt_cycle->hostname,
                      NJT_HTTP_VTS_MODULE_VERSION, NJT_VERSION, vtscf->start_msec,
                      njt_http_vhost_traffic_status_current_msec(),
                      ac, rd, wr, wa, ap, hn, rq,
                      shm_info->name, shm_info->max_size,
                      shm_info->used_size, shm_info->used_node);

    return buf;
}


u_char *
njt_http_vhost_traffic_status_display_set_server_node(
    njt_http_request_t *r,
    u_char *buf, njt_str_t *key,
    njt_http_vhost_traffic_status_node_t *vtsn)
{
    u_char                                    *p, *c;
    njt_int_t                                  rc;
    njt_str_t                                  tmp, dst;
    njt_http_vhost_traffic_status_loc_conf_t  *vtscf;

    vtscf = njt_http_get_module_loc_conf(r, njt_http_vhost_traffic_status_module);

    tmp = *key;

    rc = njt_http_vhost_traffic_status_node_position_key(&tmp, 1);
    if (rc != NJT_OK) {
        /* 
         * If this function is called in the
         * njt_http_vhost_traffic_status_display_set_filter_node() function,
         * there is no NJT_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR in key->data.
         * It is normal.
         */
        p = njt_strlchr(key->data, key->data + key->len, NJT_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR);
        if (p != NULL) {
            p = njt_pnalloc(r->pool, key->len * 2 + 1);
            c = njt_hex_dump(p, key->data, key->len);
            *c = '\0';
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "display_set_server_node::node_position_key() key[%s:%p:%d], tmp[:%p:%d] failed",
                          p, key->data, key->len, tmp.data, tmp.len);
        }
    }

    rc = njt_http_vhost_traffic_status_escape_json_pool(r->pool, &dst, &tmp);
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "display_set_server_node::escape_json_pool() failed");
    }

#if (NJT_HTTP_CACHE)
    buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER,
                      &dst, vtsn->stat_request_counter,
                      vtsn->stat_in_bytes,
                      vtsn->stat_out_bytes,
                      vtsn->stat_1xx_counter,
                      vtsn->stat_2xx_counter,
                      vtsn->stat_3xx_counter,
                      vtsn->stat_4xx_counter,
                      vtsn->stat_5xx_counter,
                      vtsn->stat_cache_miss_counter,
                      vtsn->stat_cache_bypass_counter,
                      vtsn->stat_cache_expired_counter,
                      vtsn->stat_cache_stale_counter,
                      vtsn->stat_cache_updating_counter,
                      vtsn->stat_cache_revalidated_counter,
                      vtsn->stat_cache_hit_counter,
                      vtsn->stat_cache_scarce_counter,
                      vtsn->stat_request_time_counter,
                      njt_http_vhost_traffic_status_node_time_queue_average(
                          &vtsn->stat_request_times, vtscf->average_method,
                          vtscf->average_period),
                      njt_http_vhost_traffic_status_display_get_time_queue_times(r,
                          &vtsn->stat_request_times),
                      njt_http_vhost_traffic_status_display_get_time_queue_msecs(r,
                          &vtsn->stat_request_times),
                      njt_http_vhost_traffic_status_display_get_histogram_bucket_msecs(r,
                          &vtsn->stat_request_buckets),
                      njt_http_vhost_traffic_status_display_get_histogram_bucket_counters(r,
                          &vtsn->stat_request_buckets),
                      njt_http_vhost_traffic_status_max_integer,
                      vtsn->stat_request_counter_oc,
                      vtsn->stat_in_bytes_oc,
                      vtsn->stat_out_bytes_oc,
                      vtsn->stat_1xx_counter_oc,
                      vtsn->stat_2xx_counter_oc,
                      vtsn->stat_3xx_counter_oc,
                      vtsn->stat_4xx_counter_oc,
                      vtsn->stat_5xx_counter_oc,
                      vtsn->stat_cache_miss_counter_oc,
                      vtsn->stat_cache_bypass_counter_oc,
                      vtsn->stat_cache_expired_counter_oc,
                      vtsn->stat_cache_stale_counter_oc,
                      vtsn->stat_cache_updating_counter_oc,
                      vtsn->stat_cache_revalidated_counter_oc,
                      vtsn->stat_cache_hit_counter_oc,
                      vtsn->stat_cache_scarce_counter_oc,
                      vtsn->stat_request_time_counter_oc);
#else
    buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER,
                      &dst, vtsn->stat_request_counter,
                      vtsn->stat_in_bytes,
                      vtsn->stat_out_bytes,
                      vtsn->stat_1xx_counter,
                      vtsn->stat_2xx_counter,
                      vtsn->stat_3xx_counter,
                      vtsn->stat_4xx_counter,
                      vtsn->stat_5xx_counter,
                      vtsn->stat_request_time_counter,
                      njt_http_vhost_traffic_status_node_time_queue_average(
                          &vtsn->stat_request_times, vtscf->average_method,
                          vtscf->average_period),
                      njt_http_vhost_traffic_status_display_get_time_queue_times(r,
                          &vtsn->stat_request_times),
                      njt_http_vhost_traffic_status_display_get_time_queue_msecs(r,
                          &vtsn->stat_request_times),
                      njt_http_vhost_traffic_status_display_get_histogram_bucket_msecs(r,
                          &vtsn->stat_request_buckets),
                      njt_http_vhost_traffic_status_display_get_histogram_bucket_counters(r,
                          &vtsn->stat_request_buckets),
                      njt_http_vhost_traffic_status_max_integer,
                      vtsn->stat_request_counter_oc,
                      vtsn->stat_in_bytes_oc,
                      vtsn->stat_out_bytes_oc,
                      vtsn->stat_1xx_counter_oc,
                      vtsn->stat_2xx_counter_oc,
                      vtsn->stat_3xx_counter_oc,
                      vtsn->stat_4xx_counter_oc,
                      vtsn->stat_5xx_counter_oc,
                      vtsn->stat_request_time_counter_oc);
#endif

    return buf;
}


void
njt_http_vhost_traffic_status_sum_node(njt_http_vhost_traffic_status_node_t *vtsn, 
    njt_http_vhost_traffic_status_loc_conf_t  *vtscf)
{
    njt_http_vhost_traffic_status_node_t *sum;
    int                                   i;

    sum = vtsn;
    njt_rwlock_wlock(&sum->lock);
    njt_http_vhost_traffic_status_node_zero(sum);

    for (i=0; i<njt_ncpu; i++) {
        vtsn--;
        sum->stat_request_counter += vtsn->stat_request_counter;
        sum->stat_in_bytes += vtsn->stat_in_bytes;
        sum->stat_out_bytes += vtsn->stat_out_bytes;
        sum->stat_1xx_counter += vtsn->stat_1xx_counter;
        sum->stat_2xx_counter += vtsn->stat_2xx_counter;
        sum->stat_3xx_counter += vtsn->stat_3xx_counter;
        sum->stat_4xx_counter += vtsn->stat_4xx_counter;
        sum->stat_5xx_counter += vtsn->stat_5xx_counter;
        sum->stat_request_time_counter += vtsn->stat_request_time_counter;
        njt_http_vhost_traffic_status_node_time_queue_merge(
                &sum->stat_request_times,
                &vtsn->stat_request_times, vtscf->average_period);
        sum->stat_request_counter_oc += vtsn->stat_request_counter_oc;
        sum->stat_in_bytes_oc += vtsn->stat_in_bytes_oc;
        sum->stat_out_bytes_oc += vtsn->stat_out_bytes_oc;
        sum->stat_1xx_counter_oc += vtsn->stat_1xx_counter_oc;
        sum->stat_2xx_counter_oc += vtsn->stat_2xx_counter_oc;
        sum->stat_3xx_counter_oc += vtsn->stat_3xx_counter_oc;
        sum->stat_4xx_counter_oc += vtsn->stat_4xx_counter_oc;
        sum->stat_5xx_counter_oc += vtsn->stat_5xx_counter_oc;
        sum->stat_timeo_counter_oc += vtsn->stat_timeo_counter_oc;
        sum->stat_request_time_counter_oc += vtsn->stat_request_time_counter_oc;

#if (NJT_HTTP_CACHE)
        sum->stat_cache_miss_counter += vtsn->stat_cache_miss_counter;
        sum->stat_cache_bypass_counter += vtsn->stat_cache_bypass_counter;
        sum->stat_cache_expired_counter += vtsn->stat_cache_expired_counter;
        sum->stat_cache_stale_counter += vtsn->stat_cache_stale_counter;
        sum->stat_cache_updating_counter += vtsn->stat_cache_updating_counter;
        sum->stat_cache_revalidated_counter += vtsn->stat_cache_revalidated_counter;
        sum->stat_cache_hit_counter += vtsn->stat_cache_hit_counter;
        sum->stat_cache_scarce_counter += vtsn->stat_cache_scarce_counter;

        sum->stat_cache_miss_counter_oc += vtsn->stat_cache_miss_counter_oc;
        sum->stat_cache_bypass_counter_oc += vtsn->stat_cache_bypass_counter_oc;
        sum->stat_cache_expired_counter_oc += vtsn->stat_cache_expired_counter_oc;
        sum->stat_cache_stale_counter_oc += vtsn->stat_cache_stale_counter_oc;
        sum->stat_cache_updating_counter_oc += vtsn->stat_cache_updating_counter_oc;
        sum->stat_cache_revalidated_counter_oc += vtsn->stat_cache_revalidated_counter_oc;
        sum->stat_cache_hit_counter_oc += vtsn->stat_cache_hit_counter_oc;
        sum->stat_cache_scarce_counter_oc += vtsn->stat_cache_scarce_counter_oc;
#endif
    }
    njt_rwlock_unlock(&sum->lock);
}


u_char *
njt_http_vhost_traffic_status_display_set_server(njt_http_request_t *r,
    u_char *buf, njt_rbtree_node_t *node)
{
    njt_str_t                                  key;
    njt_http_vhost_traffic_status_ctx_t       *ctx;
    njt_http_vhost_traffic_status_node_t      *vtsn, ovtsn;
    njt_http_vhost_traffic_status_loc_conf_t  *vtscf;

    ctx = njt_http_get_module_main_conf(r, njt_http_vhost_traffic_status_module);

    vtscf = njt_http_get_module_loc_conf(r, njt_http_vhost_traffic_status_module);

    if (node != ctx->rbtree->sentinel) {
        vtsn = njt_http_vhost_traffic_status_get_node(node);
        njt_http_vhost_traffic_status_sum_node(vtsn, vtscf);

        if (vtsn->stat_upstream.type == NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO) {
            key.data = vtsn->data;
            key.len = vtsn->len;

            ovtsn = vtscf->stats;

            buf = njt_http_vhost_traffic_status_display_set_server_node(r, buf, &key, vtsn);

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

            vtscf->stats.stat_request_counter_oc += vtsn->stat_request_counter_oc;
            vtscf->stats.stat_in_bytes_oc += vtsn->stat_in_bytes_oc;
            vtscf->stats.stat_out_bytes_oc += vtsn->stat_out_bytes_oc;
            vtscf->stats.stat_1xx_counter_oc += vtsn->stat_1xx_counter_oc;
            vtscf->stats.stat_2xx_counter_oc += vtsn->stat_2xx_counter_oc;
            vtscf->stats.stat_3xx_counter_oc += vtsn->stat_3xx_counter_oc;
            vtscf->stats.stat_4xx_counter_oc += vtsn->stat_4xx_counter_oc;
            vtscf->stats.stat_5xx_counter_oc += vtsn->stat_5xx_counter_oc;
            vtscf->stats.stat_request_time_counter_oc += vtsn->stat_request_time_counter_oc;

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

            vtscf->stats.stat_cache_miss_counter_oc +=
                                       vtsn->stat_cache_miss_counter_oc;
            vtscf->stats.stat_cache_bypass_counter_oc +=
                                       vtsn->stat_cache_bypass_counter_oc;
            vtscf->stats.stat_cache_expired_counter_oc +=
                                       vtsn->stat_cache_expired_counter_oc;
            vtscf->stats.stat_cache_stale_counter_oc +=
                                       vtsn->stat_cache_stale_counter_oc;
            vtscf->stats.stat_cache_updating_counter_oc +=
                                       vtsn->stat_cache_updating_counter_oc;
            vtscf->stats.stat_cache_revalidated_counter_oc +=
                                       vtsn->stat_cache_revalidated_counter_oc;
            vtscf->stats.stat_cache_hit_counter_oc +=
                                       vtsn->stat_cache_hit_counter_oc;
            vtscf->stats.stat_cache_scarce_counter_oc +=
                                       vtsn->stat_cache_scarce_counter_oc;
#endif

            njt_http_vhost_traffic_status_add_oc((&ovtsn), (&vtscf->stats));
        }

        buf = njt_http_vhost_traffic_status_display_set_server(r, buf, node->left);
        buf = njt_http_vhost_traffic_status_display_set_server(r, buf, node->right);
    }

    return buf;
}


u_char *
njt_http_vhost_traffic_status_display_set_filter_node(njt_http_request_t *r,
    u_char *buf, njt_http_vhost_traffic_status_node_t *vtsn)
{
    njt_str_t   key;

    key.data = vtsn->data;
    key.len = vtsn->len;

    (void) njt_http_vhost_traffic_status_node_position_key(&key, 2);

    return njt_http_vhost_traffic_status_display_set_server_node(r, buf, &key, vtsn);
}


u_char *
njt_http_vhost_traffic_status_display_set_filter(njt_http_request_t *r,
    u_char *buf, njt_rbtree_node_t *node)
{
    njt_str_t                                     key, filter;
    njt_uint_t                                    i, j, n, rc;
    njt_array_t                                  *filter_keys, *filter_nodes;
    njt_http_vhost_traffic_status_filter_key_t   *keys;
    njt_http_vhost_traffic_status_filter_node_t  *nodes;

    /* init array */
    filter_keys = NULL;
    filter_nodes = NULL;

    rc = njt_http_vhost_traffic_status_filter_get_keys(r, &filter_keys, node);

    if (filter_keys != NULL && rc == NJT_OK) {
        keys = filter_keys->elts;
        n = filter_keys->nelts;

        if (n > 1) {
            njt_qsort(keys, (size_t) n,
                      sizeof(njt_http_vhost_traffic_status_filter_key_t),
                      njt_http_traffic_status_filter_cmp_keys);
        }

        njt_memzero(&key, sizeof(njt_str_t));

        for (i = 0; i < n; i++) {
            if (keys[i].key.len == key.len) {
                if (njt_strncmp(keys[i].key.data, key.data, key.len) == 0) {
                    continue;
                }
            }
            key = keys[i].key;

            rc = njt_http_vhost_traffic_status_filter_get_nodes(r, &filter_nodes, &key, node);

            if (filter_nodes != NULL && rc == NJT_OK) {
                rc = njt_http_vhost_traffic_status_escape_json_pool(r->pool, &filter, &keys[i].key);
                if (rc != NJT_OK) {
                    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                  "display_set_filter::escape_json_pool() failed");
                }

                buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_OBJECT_S,
                                  &filter);

                nodes = filter_nodes->elts;
                for (j = 0; j < filter_nodes->nelts; j++) {
                    buf = njt_http_vhost_traffic_status_display_set_filter_node(r, buf,
                              nodes[j].node);
                }

                buf--;
                buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_OBJECT_E);
                buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT);

                /* destroy array to prevent duplication */
                filter_nodes = NULL;
            }

        }

        /* destroy array */
        for (i = 0; i < n; i++) {
             if (keys[i].key.data != NULL) {
                 njt_pfree(r->pool, keys[i].key.data);
             }
        }
        filter_keys = NULL;
    }

    return buf;
}


u_char *
njt_http_vhost_traffic_status_display_set_upstream_node(njt_http_request_t *r,
     u_char *buf, njt_http_upstream_server_t *us,
#if njet_version > 1007001
     njt_http_vhost_traffic_status_node_t *vtsn
#else
     njt_http_vhost_traffic_status_node_t *vtsn, njt_str_t *name
#endif
     )
{
    njt_int_t                                  rc;
    njt_str_t                                  key;
    njt_http_vhost_traffic_status_loc_conf_t  *vtscf;

    vtscf = njt_http_get_module_loc_conf(r, njt_http_vhost_traffic_status_module);

#if njet_version > 1007001
    rc = njt_http_vhost_traffic_status_escape_json_pool(r->pool, &key, &us->name);
#else
    rc = njt_http_vhost_traffic_status_escape_json_pool(r->pool, &key, name);
#endif

    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "display_set_upstream_node::escape_json_pool() failed");
    }

    if (vtsn != NULL) {
        buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_UPSTREAM,
                &key, vtsn->stat_request_counter,
                vtsn->stat_in_bytes, vtsn->stat_out_bytes,
                vtsn->stat_1xx_counter, vtsn->stat_2xx_counter,
                vtsn->stat_3xx_counter, vtsn->stat_4xx_counter,
                vtsn->stat_5xx_counter, vtsn->stat_timeo_counter_oc,
                vtsn->stat_request_time_counter,
                njt_http_vhost_traffic_status_node_time_queue_average(
                    &vtsn->stat_request_times, vtscf->average_method,
                    vtscf->average_period),
                njt_http_vhost_traffic_status_display_get_time_queue_times(r,
                    &vtsn->stat_request_times),
                njt_http_vhost_traffic_status_display_get_time_queue_msecs(r,
                    &vtsn->stat_request_times),
                njt_http_vhost_traffic_status_display_get_histogram_bucket_msecs(r,
                    &vtsn->stat_request_buckets),
                njt_http_vhost_traffic_status_display_get_histogram_bucket_counters(r,
                    &vtsn->stat_request_buckets),
                vtsn->stat_upstream.response_time_counter,
                njt_http_vhost_traffic_status_node_time_queue_average(
                    &vtsn->stat_upstream.response_times, vtscf->average_method,
                    vtscf->average_period),
                njt_http_vhost_traffic_status_display_get_time_queue_times(r,
                    &vtsn->stat_upstream.response_times),
                njt_http_vhost_traffic_status_display_get_time_queue_msecs(r,
                    &vtsn->stat_upstream.response_times),
                njt_http_vhost_traffic_status_display_get_histogram_bucket_msecs(r,
                    &vtsn->stat_upstream.response_buckets),
                njt_http_vhost_traffic_status_display_get_histogram_bucket_counters(r,
                    &vtsn->stat_upstream.response_buckets),
                us->weight, us->max_fails,
                us->fail_timeout,
                njt_http_vhost_traffic_status_boolean_to_string(us->backup),
                njt_http_vhost_traffic_status_boolean_to_string(us->down),
                njt_http_vhost_traffic_status_max_integer,
                vtsn->stat_request_counter_oc, vtsn->stat_in_bytes_oc,
                vtsn->stat_out_bytes_oc, vtsn->stat_1xx_counter_oc,
                vtsn->stat_2xx_counter_oc, vtsn->stat_3xx_counter_oc,
                vtsn->stat_4xx_counter_oc, vtsn->stat_5xx_counter_oc,
                vtsn->stat_request_time_counter_oc, vtsn->stat_response_time_counter_oc);
    } else {
        buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_UPSTREAM,
                &key, (njt_atomic_uint_t) 0,
                (njt_atomic_uint_t) 0, (njt_atomic_uint_t) 0,
                (njt_atomic_uint_t) 0, (njt_atomic_uint_t) 0,
                (njt_atomic_uint_t) 0, (njt_atomic_uint_t) 0,
                (njt_atomic_uint_t) 0, (njt_atomic_uint_t) 0,
                (njt_atomic_uint_t) 0,
                (njt_msec_t) 0,
                (u_char *) "", (u_char *) "",
                (u_char *) "", (u_char *) "",
                (njt_atomic_uint_t) 0,
                (njt_msec_t) 0,
                (u_char *) "", (u_char *) "",
                (u_char *) "", (u_char *) "",
                us->weight, us->max_fails,
                us->fail_timeout,
                njt_http_vhost_traffic_status_boolean_to_string(us->backup),
                njt_http_vhost_traffic_status_boolean_to_string(us->down),
                njt_http_vhost_traffic_status_max_integer,
                (njt_atomic_uint_t) 0, (njt_atomic_uint_t) 0,
                (njt_atomic_uint_t) 0, (njt_atomic_uint_t) 0,
                (njt_atomic_uint_t) 0, (njt_atomic_uint_t) 0,
                (njt_atomic_uint_t) 0, (njt_atomic_uint_t) 0,
                (njt_atomic_uint_t) 0, (njt_atomic_uint_t) 0);
    }

    return buf;
}


u_char *
njt_http_vhost_traffic_status_display_set_upstream_alone(njt_http_request_t *r,
    u_char *buf, njt_rbtree_node_t *node)
{
    unsigned                               type;
    njt_str_t                              key;
    njt_http_upstream_server_t             us;
    njt_http_vhost_traffic_status_ctx_t   *ctx;
    njt_http_vhost_traffic_status_node_t  *vtsn;

    ctx = njt_http_get_module_main_conf(r, njt_http_vhost_traffic_status_module);

    type = NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UA;

    if (node != ctx->rbtree->sentinel) {
        vtsn = njt_http_vhost_traffic_status_get_node(node);

        if (vtsn->stat_upstream.type == type) {
            key.len = vtsn->len;
            key.data = vtsn->data;

            (void) njt_http_vhost_traffic_status_node_position_key(&key, 1);

#if njet_version > 1007001
            us.name = key;
#endif
            us.weight = 0;
            us.max_fails = 0;
            us.fail_timeout = 0;
            us.down = 0;
            us.backup = 0;

#if njet_version > 1007001
            buf = njt_http_vhost_traffic_status_display_set_upstream_node(r, buf, &us, vtsn);
#else
            buf = njt_http_vhost_traffic_status_display_set_upstream_node(r, buf, &us, vtsn, &key);
#endif
        }

        buf = njt_http_vhost_traffic_status_display_set_upstream_alone(r, buf, node->left);
        buf = njt_http_vhost_traffic_status_display_set_upstream_alone(r, buf, node->right);
    }

    return buf;
}


u_char *
njt_http_vhost_traffic_status_display_set_upstream_group(njt_http_request_t *r,
    u_char *buf)
{
    size_t                                 len;
    u_char                                *p, *o, *s;
    uint32_t                               hash;
    unsigned                               type, zone;
    njt_int_t                              rc;
    njt_str_t                              key, dst;
    njt_uint_t                             i, j, k;
    njt_rbtree_node_t                     *node;
    njt_http_upstream_server_t            *us, usn;
#if (NJT_HTTP_UPSTREAM_ZONE)
    njt_http_upstream_rr_peer_t           *peer;
    njt_http_upstream_rr_peers_t          *peers;
#endif
    njt_http_upstream_srv_conf_t          *uscf, **uscfp;
    njt_http_upstream_main_conf_t         *umcf;
    njt_http_vhost_traffic_status_ctx_t   *ctx;
    njt_http_vhost_traffic_status_node_t  *vtsn;

    ctx = njt_http_get_module_main_conf(r, njt_http_vhost_traffic_status_module);
    umcf = njt_http_cycle_get_module_main_conf(njt_http_vtsp_cycle, njt_http_upstream_module);
    uscfp = umcf->upstreams.elts;

    len = 0;
    for (i = 0; i < umcf->upstreams.nelts; i++) {
        uscf = uscfp[i];
        len = njt_max(uscf->host.len, len);
    }

    dst.len = len + sizeof("@[ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255]:65535") - 1;
    dst.data = njt_pnalloc(r->pool, dst.len);
    if (dst.data == NULL) {
        return buf;
    }

    p = dst.data;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        uscf = uscfp[i];

        /* groups */
        if (uscf->servers && !uscf->port) {
            us = uscf->servers->elts;

            type = NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_UG;

            o = buf;

            buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_ARRAY_S,
                              &uscf->host);
            s = buf;

            zone = 0;

#if (NJT_HTTP_UPSTREAM_ZONE)
            if (uscf->shm_zone == NULL) {
                goto not_supported;
            }

            zone = 1;

            peers = uscf->peer.data;

            njt_http_upstream_rr_peers_rlock(peers);

            for (peer = peers->peer; peer; peer = peer->next) {
                p = njt_cpymem(p, uscf->host.data, uscf->host.len);
                *p++ = NJT_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR;
                p = njt_cpymem(p, peer->name.data, peer->name.len);

                dst.len = uscf->host.len + sizeof("@") - 1 + peer->name.len;

                rc = njt_http_vhost_traffic_status_node_generate_key(r->pool, &key, &dst, type);
                if (rc != NJT_OK) {
                    njt_http_upstream_rr_peers_unlock(peers);
                    return buf;
                }

                hash = njt_crc32_short(key.data, key.len);
                node = njt_http_vhost_traffic_status_node_lookup(ctx->rbtree, &key, hash);

                usn.weight = peer->weight;
                usn.max_fails = peer->max_fails;
                usn.fail_timeout = peer->fail_timeout;
                usn.backup = 0;
#if (NJT_HTTP_UPSTREAM_CHECK)
                if (njt_http_upstream_check_peer_down(peer->check_index)) {
                    usn.down = 1;

                } else {
                    usn.down = 0;
                }
#else
                usn.down = (peer->fails >= peer->max_fails || peer->down);
#endif

#if njet_version > 1007001
                usn.name = peer->name;
#endif

                if (node != NULL) {
                     vtsn = njt_http_vhost_traffic_status_get_node(node);
#if njet_version > 1007001
                    buf = njt_http_vhost_traffic_status_display_set_upstream_node(r, buf, &usn, vtsn);
#else
                    buf = njt_http_vhost_traffic_status_display_set_upstream_node(r, buf, &usn, vtsn, &peer->name);
#endif

                } else {
#if njet_version > 1007001
                    buf = njt_http_vhost_traffic_status_display_set_upstream_node(r, buf, &usn, NULL);
#else
                    buf = njt_http_vhost_traffic_status_display_set_upstream_node(r, buf, &usn, NULL, &peer->name);
#endif
                }

                p = dst.data;
            }

            njt_http_upstream_rr_peers_unlock(peers);

not_supported:

#endif

            for (j = 0; j < uscf->servers->nelts; j++) {
                usn = us[j];

                if (zone && usn.backup != 1) {
                    continue;
                }

                /* for all A records */
                for (k = 0; k < usn.naddrs; k++) {
                    p = njt_cpymem(p, uscf->host.data, uscf->host.len);
                    *p++ = NJT_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR;
                    p = njt_cpymem(p, usn.addrs[k].name.data, usn.addrs[k].name.len);

                    dst.len = uscf->host.len + sizeof("@") - 1 + usn.addrs[k].name.len;

                    rc = njt_http_vhost_traffic_status_node_generate_key(r->pool, &key, &dst, type);
                    if (rc != NJT_OK) {
                        return buf;
                    }

                    hash = njt_crc32_short(key.data, key.len);
                    node = njt_http_vhost_traffic_status_node_lookup(ctx->rbtree, &key, hash);

#if njet_version > 1007001
                    usn.name = usn.addrs[k].name;
#endif

                    if (node != NULL) {
                        vtsn = njt_http_vhost_traffic_status_get_node(node);
#if njet_version > 1007001
                        buf = njt_http_vhost_traffic_status_display_set_upstream_node(r, buf, &usn, vtsn);
#else
                        buf = njt_http_vhost_traffic_status_display_set_upstream_node(r, buf, &usn, vtsn, &usn.addrs[k].name);
#endif

                    } else {
#if njet_version > 1007001
                        buf = njt_http_vhost_traffic_status_display_set_upstream_node(r, buf, &usn, NULL);
#else
                        buf = njt_http_vhost_traffic_status_display_set_upstream_node(r, buf, &usn, NULL, &usn.addrs[k].name);
#endif
                    }

                    p = dst.data;
                }
            }

            if (s == buf) {
                buf = o;

            } else {
                buf--;
                buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_ARRAY_E);
                buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT);
            }
        }
    }

    /* alones */
    o = buf;

    njt_str_set(&key, "::nogroups");

    buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_ARRAY_S, &key);

    s = buf;

    buf = njt_http_vhost_traffic_status_display_set_upstream_alone(r, buf, ctx->rbtree->root);

    if (s == buf) {
        buf = o;

    } else {
        buf--;
        buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_ARRAY_E);
        buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT);
    }

    return buf;
}


#if (NJT_HTTP_CACHE)

u_char
*njt_http_vhost_traffic_status_display_set_cache_node(njt_http_request_t *r,
    u_char *buf, njt_http_vhost_traffic_status_node_t *vtsn)
{
    njt_int_t  rc;
    njt_str_t  key, dst;

    dst.data = vtsn->data;
    dst.len = vtsn->len;

    (void) njt_http_vhost_traffic_status_node_position_key(&dst, 1);

    rc = njt_http_vhost_traffic_status_escape_json_pool(r->pool, &key, &dst);
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "display_set_cache_node::escape_json_pool() failed");
    }

    buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_CACHE,
                      &key, vtsn->stat_cache_max_size,
                      vtsn->stat_cache_used_size,
                      vtsn->stat_in_bytes,
                      vtsn->stat_out_bytes,
                      vtsn->stat_cache_miss_counter,
                      vtsn->stat_cache_bypass_counter,
                      vtsn->stat_cache_expired_counter,
                      vtsn->stat_cache_stale_counter,
                      vtsn->stat_cache_updating_counter,
                      vtsn->stat_cache_revalidated_counter,
                      vtsn->stat_cache_hit_counter,
                      vtsn->stat_cache_scarce_counter,
                      njt_http_vhost_traffic_status_max_integer,
                      vtsn->stat_request_counter_oc,
                      vtsn->stat_in_bytes_oc,
                      vtsn->stat_out_bytes_oc,
                      vtsn->stat_1xx_counter_oc,
                      vtsn->stat_2xx_counter_oc,
                      vtsn->stat_3xx_counter_oc,
                      vtsn->stat_4xx_counter_oc,
                      vtsn->stat_5xx_counter_oc,
                      vtsn->stat_cache_miss_counter_oc,
                      vtsn->stat_cache_bypass_counter_oc,
                      vtsn->stat_cache_expired_counter_oc,
                      vtsn->stat_cache_stale_counter_oc,
                      vtsn->stat_cache_updating_counter_oc,
                      vtsn->stat_cache_revalidated_counter_oc,
                      vtsn->stat_cache_hit_counter_oc,
                      vtsn->stat_cache_scarce_counter_oc);

    return buf;
}


u_char *
njt_http_vhost_traffic_status_display_set_cache(njt_http_request_t *r,
    u_char *buf, njt_rbtree_node_t *node)
{
    njt_http_vhost_traffic_status_ctx_t   *ctx;
    njt_http_vhost_traffic_status_node_t  *vtsn;

    ctx = njt_http_get_module_main_conf(r, njt_http_vhost_traffic_status_module);

    if (node != ctx->rbtree->sentinel) {
        vtsn = njt_http_vhost_traffic_status_get_node(node);

        if (vtsn->stat_upstream.type == NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_CC) {
            buf = njt_http_vhost_traffic_status_display_set_cache_node(r, buf, vtsn);
        }

        buf = njt_http_vhost_traffic_status_display_set_cache(r, buf, node->left);
        buf = njt_http_vhost_traffic_status_display_set_cache(r, buf, node->right);
    }

    return buf;
}

#endif


u_char *
njt_http_vhost_traffic_status_display_set(njt_http_request_t *r,
    u_char *buf)
{
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
    buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_S);

    buf = njt_http_vhost_traffic_status_display_set_main(r, buf);

    /* serverZones */
    buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_SERVER_S);

    buf = njt_http_vhost_traffic_status_display_set_server(r, buf, node);

    buf = njt_http_vhost_traffic_status_display_set_server_node(r, buf, &vtscf->sum_key,
                                                                &vtscf->stats);

    buf--;
    buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E);
    buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT);

    /* filterZones */
    o = buf;

    buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_FILTER_S);

    s = buf;

    buf = njt_http_vhost_traffic_status_display_set_filter(r, buf, node);

    if (s == buf) {
        buf = o;

    } else {
        buf--;
        buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E);
        buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT);
    }

    /* upstreamZones */
    o = buf;

    buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_UPSTREAM_S);

    extern njt_int_t njt_http_vts_hdr_values[5];
    extern njt_int_t njt_http_vts_hdr_get(void);
    njt_http_vts_hdr_get();
    buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_UPSTREAM_REQDELAY,
                njt_http_vts_hdr_values[0],
                njt_http_vts_hdr_values[1],
                njt_http_vts_hdr_values[2],
                njt_http_vts_hdr_values[3],
                njt_http_vts_hdr_values[4]);

    s = buf;

    buf = njt_http_vhost_traffic_status_display_set_upstream_group(r, buf);

    if (s == buf) {
        buf = o;
        buf--;

    } else {
        buf--;
        buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E);
    }

#if (NJT_HTTP_CACHE)
    /* cacheZones */
    o = buf;

    buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_NEXT);
    buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_CACHE_S);

    s = buf;

    buf = njt_http_vhost_traffic_status_display_set_cache(r, buf, node);

    if (s == buf) {
        buf = o;

    } else {
        buf--;
        buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E);
    }
#endif

    buf = njt_sprintf(buf, NJT_HTTP_VHOST_TRAFFIC_STATUS_JSON_FMT_E);

    return buf;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
