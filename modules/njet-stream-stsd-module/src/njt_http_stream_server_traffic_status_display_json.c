
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#include <njt_config.h>

#include "njt_http_stream_server_traffic_status_module.h"
#include "njt_http_stream_server_traffic_status_shm.h"
#include "njt_http_stream_server_traffic_status_filter.h"
#include "njt_http_stream_server_traffic_status_display_json.h"
#include "njt_http_stream_server_traffic_status_display.h"


u_char *
njt_http_stream_server_traffic_status_display_set_main(njt_http_request_t *r,
    u_char *buf)
{
    njt_atomic_int_t                                   ap, hn, ac, rq, rd, wr, wa;
    njt_http_stream_server_traffic_status_loc_conf_t  *stscf;
    njt_http_stream_server_traffic_status_shm_info_t  *shm_info;

    stscf = njt_http_get_module_loc_conf(r, njt_stream_stsd_module);

    ap = *njt_stat_accepted;
    hn = *njt_stat_handled;
    ac = *njt_stat_active;
    rq = *njt_stat_requests;
    rd = *njt_stat_reading;
    wr = *njt_stat_writing;
    wa = *njt_stat_waiting;

    shm_info = njt_pcalloc(r->pool, sizeof(njt_http_stream_server_traffic_status_shm_info_t));
    if (shm_info == NULL) {
        return buf;
    }

    njt_http_stream_server_traffic_status_shm_info(r, shm_info);

    buf = njt_sprintf(buf, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_MAIN,
                      &njt_cycle->hostname, NJT_VERSION, stscf->start_msec,
                      njt_http_stream_server_traffic_status_current_msec(),
                      ac, rd, wr, wa, ap, hn, rq,
                      shm_info->name, shm_info->max_size,
                      shm_info->used_size, shm_info->used_node);

    return buf;
}


u_char *
njt_http_stream_server_traffic_status_display_set_server_node(
    njt_http_request_t *r,
    u_char *buf, njt_str_t *key,
    njt_http_stream_server_traffic_status_node_t *stsn)
{
    njt_int_t                                          rc;
    njt_str_t                                          tmp, dst, protocol;
    njt_http_stream_server_traffic_status_loc_conf_t  *stscf;

    stscf = njt_http_get_module_loc_conf(r, njt_stream_stsd_module);

    tmp = *key;

    (void) njt_http_stream_server_traffic_status_node_position_key(&tmp, 1);

    rc = njt_http_stream_server_traffic_status_escape_json_pool(r->pool, &dst, &tmp);
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "display_set_server_node::escape_json_pool() failed");
    }

    protocol.len = 3;
    protocol.data = (u_char *) (stsn->protocol == SOCK_DGRAM ? "UDP" : "TCP");

    buf = njt_sprintf(buf, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_SERVER,
                      &dst, stsn->port, &protocol,
                      stsn->stat_connect_counter,
                      stsn->stat_in_bytes,
                      stsn->stat_out_bytes,
                      stsn->stat_1xx_counter,
                      stsn->stat_2xx_counter,
                      stsn->stat_3xx_counter,
                      stsn->stat_4xx_counter,
                      stsn->stat_5xx_counter,
                      stsn->stat_session_time_counter,
                      njt_http_stream_server_traffic_status_node_time_queue_average(
                          &stsn->stat_session_times, stscf->average_method,
                          stscf->average_period),
                      njt_http_stream_server_traffic_status_display_get_time_queue_times(r,
                          &stsn->stat_session_times),
                      njt_http_stream_server_traffic_status_display_get_time_queue_msecs(r,
                          &stsn->stat_session_times),
                      njt_http_stream_server_traffic_status_display_get_histogram_bucket_msecs(r,
                          &stsn->stat_session_buckets),
                      njt_http_stream_server_traffic_status_display_get_histogram_bucket_counters(r,
                          &stsn->stat_session_buckets),
                      njt_http_stream_server_traffic_status_max_integer,
                      stsn->stat_connect_counter_oc,
                      stsn->stat_in_bytes_oc,
                      stsn->stat_out_bytes_oc,
                      stsn->stat_1xx_counter_oc,
                      stsn->stat_2xx_counter_oc,
                      stsn->stat_3xx_counter_oc,
                      stsn->stat_4xx_counter_oc,
                      stsn->stat_5xx_counter_oc,
                      stsn->stat_session_time_counter_oc);

    return buf;
}


u_char *
njt_http_stream_server_traffic_status_display_set_server(njt_http_request_t *r,
    u_char *buf, njt_rbtree_node_t *node)
{
    njt_str_t                                          key;
    njt_http_stream_server_traffic_status_ctx_t       *ctx;
    njt_http_stream_server_traffic_status_node_t      *stsn, ostsn;
    njt_http_stream_server_traffic_status_loc_conf_t  *stscf;

    ctx = njt_http_get_module_main_conf(r, njt_stream_stsd_module);

    stscf = njt_http_get_module_loc_conf(r, njt_stream_stsd_module);

    if (node != ctx->rbtree->sentinel) {
        stsn = (njt_http_stream_server_traffic_status_node_t *) &node->color;

        if (stsn->stat_upstream.type == NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_NO) {
            key.data = stsn->data;
            key.len = stsn->len;

            ostsn = stscf->stats;

            buf = njt_http_stream_server_traffic_status_display_set_server_node(r, buf, &key, stsn);

            /* calculates the sum */
            stscf->stats.stat_connect_counter +=stsn->stat_connect_counter;
            stscf->stats.stat_in_bytes += stsn->stat_in_bytes;
            stscf->stats.stat_out_bytes += stsn->stat_out_bytes;
            stscf->stats.stat_1xx_counter += stsn->stat_1xx_counter;
            stscf->stats.stat_2xx_counter += stsn->stat_2xx_counter;
            stscf->stats.stat_3xx_counter += stsn->stat_3xx_counter;
            stscf->stats.stat_4xx_counter += stsn->stat_4xx_counter;
            stscf->stats.stat_5xx_counter += stsn->stat_5xx_counter;
            stscf->stats.stat_session_time_counter += stsn->stat_session_time_counter;
            njt_http_stream_server_traffic_status_node_time_queue_merge(
                &stscf->stats.stat_session_times,
                &stsn->stat_session_times, stscf->average_period);

            stscf->stats.stat_connect_counter_oc += stsn->stat_connect_counter_oc;
            stscf->stats.stat_in_bytes_oc += stsn->stat_in_bytes_oc;
            stscf->stats.stat_out_bytes_oc += stsn->stat_out_bytes_oc;
            stscf->stats.stat_1xx_counter_oc += stsn->stat_1xx_counter_oc;
            stscf->stats.stat_2xx_counter_oc += stsn->stat_2xx_counter_oc;
            stscf->stats.stat_3xx_counter_oc += stsn->stat_3xx_counter_oc;
            stscf->stats.stat_4xx_counter_oc += stsn->stat_4xx_counter_oc;
            stscf->stats.stat_5xx_counter_oc += stsn->stat_5xx_counter_oc;
            stscf->stats.stat_session_time_counter_oc += stsn->stat_session_time_counter_oc;

            njt_http_stream_server_traffic_status_add_oc((&ostsn), (&stscf->stats));
        }

        buf = njt_http_stream_server_traffic_status_display_set_server(r, buf, node->left);
        buf = njt_http_stream_server_traffic_status_display_set_server(r, buf, node->right);
    }

    return buf;
}


u_char *
njt_http_stream_server_traffic_status_display_set_filter_node(njt_http_request_t *r,
    u_char *buf, njt_http_stream_server_traffic_status_node_t *stsn)
{
    njt_str_t  key;

    key.data = stsn->data;
    key.len = stsn->len;

    (void) njt_http_stream_server_traffic_status_node_position_key(&key, 2);

    return njt_http_stream_server_traffic_status_display_set_server_node(r, buf, &key, stsn);
}


u_char *
njt_http_stream_server_traffic_status_display_set_filter(njt_http_request_t *r,
    u_char *buf, njt_rbtree_node_t *node)
{
    njt_str_t                                             key, filter;
    njt_uint_t                                            i, j, n, rc;
    njt_array_t                                          *filter_keys, *filter_nodes;
    njt_http_stream_server_traffic_status_filter_key_t   *keys;
    njt_http_stream_server_traffic_status_filter_node_t  *nodes;

    /* init array */
    filter_keys = NULL;
    filter_nodes = NULL;

    rc = njt_http_stream_server_traffic_status_filter_get_keys(r, &filter_keys, node);

    if (filter_keys != NULL && rc == NJT_OK) {
        keys = filter_keys->elts;
        n = filter_keys->nelts;

        if (n > 1) {
            njt_qsort(keys, (size_t) n,
                      sizeof(njt_http_stream_server_traffic_status_filter_key_t),
                      njt_http_stream_server_traffic_status_filter_cmp_keys);
        }

        njt_memzero(&key, sizeof(njt_str_t));

        for (i = 0; i < n; i++) {
            if (keys[i].key.len == key.len) {
                if (njt_strncmp(keys[i].key.data, key.data, key.len) == 0) {
                    continue;
                }
            }
            key = keys[i].key;

            rc = njt_http_stream_server_traffic_status_filter_get_nodes(r, &filter_nodes, &key, node);

            if (filter_nodes != NULL && rc == NJT_OK) {
                rc = njt_http_stream_server_traffic_status_escape_json_pool(r->pool, &filter,
                                                                            &keys[i].key);
                if (rc != NJT_OK) {
                    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                  "display_set_filter::escape_json_pool() failed");
                }

                buf = njt_sprintf(buf, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_OBJECT_S,
                                  &filter);

                nodes = filter_nodes->elts;
                for (j = 0; j < filter_nodes->nelts; j++) {
                    buf = njt_http_stream_server_traffic_status_display_set_filter_node(r, buf,
                              nodes[j].node);
                }

                buf--;
                buf = njt_sprintf(buf, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_OBJECT_E);
                buf = njt_sprintf(buf, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_NEXT);

                /* destory array to prevent duplication */
                if (filter_nodes != NULL) {
                    filter_nodes = NULL;
                }
            }

        }

        /* destory array */
        for (i = 0; i < n; i++) {
             if (keys[i].key.data != NULL) {
                 njt_pfree(r->pool, keys[i].key.data);
             }
        }
        if (filter_keys != NULL) {
            filter_keys = NULL;
        }
    }

    return buf;
}


u_char *
njt_http_stream_server_traffic_status_display_set_upstream_node(njt_http_request_t *r,
     u_char *buf, njt_stream_upstream_server_t *us,
     njt_http_stream_server_traffic_status_node_t *stsn, njt_str_t *name
     )
{
    njt_int_t                                          rc;
    njt_str_t                                          key;
    njt_http_stream_server_traffic_status_loc_conf_t  *stscf;

    stscf = njt_http_get_module_loc_conf(r, njt_stream_stsd_module);

    rc = njt_http_stream_server_traffic_status_escape_json_pool(r->pool, &key, name);

    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "display_set_upstream_node::escape_json_pool() failed");
    }

    if (stsn != NULL) {
        buf = njt_sprintf(buf, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_UPSTREAM,
                &key, stsn->stat_connect_counter,
                stsn->stat_in_bytes, stsn->stat_out_bytes,
                stsn->stat_1xx_counter, stsn->stat_2xx_counter,
                stsn->stat_3xx_counter, stsn->stat_4xx_counter,
                stsn->stat_5xx_counter,
                stsn->stat_session_time_counter,
                njt_http_stream_server_traffic_status_node_time_queue_average(
                    &stsn->stat_session_times, stscf->average_method,
                    stscf->average_period),
                njt_http_stream_server_traffic_status_display_get_time_queue_times(r,
                    &stsn->stat_session_times),
                njt_http_stream_server_traffic_status_display_get_time_queue_msecs(r,
                    &stsn->stat_session_times),
                njt_http_stream_server_traffic_status_display_get_histogram_bucket_msecs(r,
                    &stsn->stat_session_buckets),
                njt_http_stream_server_traffic_status_display_get_histogram_bucket_counters(r,
                    &stsn->stat_session_buckets),
                stsn->stat_upstream.session_time_counter,
                njt_http_stream_server_traffic_status_node_time_queue_average(
                    &stsn->stat_upstream.session_times, stscf->average_method,
                    stscf->average_period),
                njt_http_stream_server_traffic_status_display_get_time_queue_times(r,
                    &stsn->stat_upstream.session_times),
                njt_http_stream_server_traffic_status_display_get_time_queue_msecs(r,
                    &stsn->stat_upstream.session_times),
                njt_http_stream_server_traffic_status_display_get_histogram_bucket_msecs(r,
                    &stsn->stat_upstream.session_buckets),
                njt_http_stream_server_traffic_status_display_get_histogram_bucket_counters(r,
                    &stsn->stat_upstream.session_buckets),
                stsn->stat_upstream.connect_time_counter,
                njt_http_stream_server_traffic_status_node_time_queue_average(
                    &stsn->stat_upstream.connect_times, stscf->average_method,
                    stscf->average_period),
                njt_http_stream_server_traffic_status_display_get_time_queue_times(r,
                    &stsn->stat_upstream.connect_times),
                njt_http_stream_server_traffic_status_display_get_time_queue_msecs(r,
                    &stsn->stat_upstream.connect_times),
                njt_http_stream_server_traffic_status_display_get_histogram_bucket_msecs(r,
                    &stsn->stat_upstream.connect_buckets),
                njt_http_stream_server_traffic_status_display_get_histogram_bucket_counters(r,
                    &stsn->stat_upstream.connect_buckets),
                stsn->stat_upstream.first_byte_time_counter,
                njt_http_stream_server_traffic_status_node_time_queue_average(
                    &stsn->stat_upstream.first_byte_times, stscf->average_method,
                    stscf->average_period),
                njt_http_stream_server_traffic_status_display_get_time_queue_times(r,
                    &stsn->stat_upstream.first_byte_times),
                njt_http_stream_server_traffic_status_display_get_time_queue_msecs(r,
                    &stsn->stat_upstream.first_byte_times),
                njt_http_stream_server_traffic_status_display_get_histogram_bucket_msecs(r,
                    &stsn->stat_upstream.first_byte_buckets),
                njt_http_stream_server_traffic_status_display_get_histogram_bucket_counters(r,
                    &stsn->stat_upstream.first_byte_buckets),
                us->weight, us->max_fails,
                us->fail_timeout,
                njt_http_stream_server_traffic_status_boolean_to_string(us->backup),
                njt_http_stream_server_traffic_status_boolean_to_string(us->down),
                njt_http_stream_server_traffic_status_max_integer,
                stsn->stat_connect_counter_oc, stsn->stat_in_bytes_oc,
                stsn->stat_out_bytes_oc, stsn->stat_1xx_counter_oc,
                stsn->stat_2xx_counter_oc, stsn->stat_3xx_counter_oc,
                stsn->stat_4xx_counter_oc, stsn->stat_5xx_counter_oc,
                stsn->stat_session_time_counter_oc, stsn->stat_u_session_time_counter_oc,
                stsn->stat_u_connect_time_counter_oc, stsn->stat_u_first_byte_time_counter_oc);

    } else {
        buf = njt_sprintf(buf, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_UPSTREAM,
                &key, (njt_atomic_uint_t) 0,
                (njt_atomic_uint_t) 0, (njt_atomic_uint_t) 0,
                (njt_atomic_uint_t) 0, (njt_atomic_uint_t) 0,
                (njt_atomic_uint_t) 0, (njt_atomic_uint_t) 0,
                (njt_atomic_uint_t) 0,
                (njt_atomic_uint_t) 0,
                (njt_msec_t) 0,
                (u_char *) "", (u_char *) "",
                (u_char *) "", (u_char *) "",
                (njt_atomic_uint_t) 0,
                (njt_msec_t) 0,
                (u_char *) "", (u_char *) "",
                (u_char *) "", (u_char *) "",
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
                njt_http_stream_server_traffic_status_boolean_to_string(us->backup),
                njt_http_stream_server_traffic_status_boolean_to_string(us->down),
                njt_http_stream_server_traffic_status_max_integer,
                (njt_atomic_uint_t) 0, (njt_atomic_uint_t) 0,
                (njt_atomic_uint_t) 0, (njt_atomic_uint_t) 0,
                (njt_atomic_uint_t) 0, (njt_atomic_uint_t) 0,
                (njt_atomic_uint_t) 0, (njt_atomic_uint_t) 0,
                (njt_atomic_uint_t) 0, (njt_atomic_uint_t) 0,
                (njt_atomic_uint_t) 0, (njt_atomic_uint_t) 0);
    }

    return buf;
}


u_char *
njt_http_stream_server_traffic_status_display_set_upstream_alone(njt_http_request_t *r,
    u_char *buf, njt_rbtree_node_t *node)
{
    unsigned                                       type;
    njt_str_t                                      key;
    njt_stream_upstream_server_t                   us;
    njt_http_stream_server_traffic_status_ctx_t   *ctx;
    njt_http_stream_server_traffic_status_node_t  *stsn;

    ctx = njt_http_get_module_main_conf(r, njt_stream_stsd_module);

    type = NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_UA;

    if (node != ctx->rbtree->sentinel) {
        stsn = (njt_http_stream_server_traffic_status_node_t *) &node->color;

        if (stsn->stat_upstream.type == type) {
            key.len = stsn->len;
            key.data = stsn->data;

            (void) njt_http_stream_server_traffic_status_node_position_key(&key, 1);
            us.weight = 0;
            us.max_fails = 0;
            us.fail_timeout = 0;
            us.down = 0;
            us.backup = 0;
            buf = njt_http_stream_server_traffic_status_display_set_upstream_node(r, buf, &us, stsn, &key);
        }

        buf = njt_http_stream_server_traffic_status_display_set_upstream_alone(r, buf, node->left);
        buf = njt_http_stream_server_traffic_status_display_set_upstream_alone(r, buf, node->right);
    }

    return buf;
}


u_char *
njt_http_stream_server_traffic_status_display_set_upstream_group(njt_http_request_t *r,
    u_char *buf)
{
    size_t                                         len;
    u_char                                        *p, *o, *s;
    uint32_t                                       hash;
    unsigned                                       type, zone;
    njt_int_t                                      rc;
    njt_str_t                                      key, dst;
    njt_uint_t                                     i, j, k;
    njt_rbtree_node_t                             *node;
    njt_stream_upstream_server_t                  *us, usn;
#if (NJT_STREAM_UPSTREAM_ZONE)
    njt_stream_upstream_rr_peer_t                 *peer;
    njt_stream_upstream_rr_peers_t                *peers;
#endif
    njt_stream_upstream_srv_conf_t                *uscf, **uscfp;
    njt_stream_upstream_main_conf_t               *umcf;
    njt_http_stream_server_traffic_status_ctx_t   *ctx;
    njt_http_stream_server_traffic_status_node_t  *stsn;

    ctx = njt_http_get_module_main_conf(r, njt_stream_stsd_module);
    umcf = ctx->upstream;
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

            type = NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_UG;

            o = buf;

            buf = njt_sprintf(buf, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_ARRAY_S,
                              &uscf->host);
            s = buf;

            zone = 0;

#if (NJT_STREAM_UPSTREAM_ZONE)
            if (uscf->shm_zone == NULL) {
                goto not_supported;
            }

            zone = 1;

            peers = uscf->peer.data;

            njt_stream_upstream_rr_peers_rlock(peers);

            for (peer = peers->peer; peer ; peer = peer->next) {
                p = njt_cpymem(p, uscf->host.data, uscf->host.len);
                *p++ = NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_KEY_SEPARATOR;
                p = njt_cpymem(p, peer->name.data, peer->name.len);

                dst.len = uscf->host.len + sizeof("@") - 1 + peer->name.len;

                rc = njt_http_stream_server_traffic_status_node_generate_key(r->pool, &key, &dst, type);
                if (rc != NJT_OK) {
                    njt_stream_upstream_rr_peers_unlock(peers);
                    return buf;
                }

                hash = njt_crc32_short(key.data, key.len);
                node = njt_http_stream_server_traffic_status_node_lookup(ctx->rbtree, &key, hash);

                usn.weight = peer->weight;
                usn.max_fails = peer->max_fails;
                usn.fail_timeout = peer->fail_timeout;
                usn.backup = 0;
                usn.down = peer->down;
                if (node != NULL) {
                    stsn = (njt_http_stream_server_traffic_status_node_t *) &node->color;
                    buf = njt_http_stream_server_traffic_status_display_set_upstream_node(r, buf, &usn, stsn, &peer->name);
                } else {
                    buf = njt_http_stream_server_traffic_status_display_set_upstream_node(r, buf, &usn, NULL, &peer->name);
                }

                p = dst.data;
            }

            njt_stream_upstream_rr_peers_unlock(peers);

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
                    *p++ = NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_KEY_SEPARATOR;
                    p = njt_cpymem(p, usn.addrs[k].name.data, usn.addrs[k].name.len);

                    dst.len = uscf->host.len + sizeof("@") - 1 + usn.addrs[k].name.len;

                    rc = njt_http_stream_server_traffic_status_node_generate_key(r->pool, &key, &dst, type);
                    if (rc != NJT_OK) {
                        return buf;
                    }

                    hash = njt_crc32_short(key.data, key.len);
                    node = njt_http_stream_server_traffic_status_node_lookup(ctx->rbtree, &key, hash);

                    if (node != NULL) {
                        stsn = (njt_http_stream_server_traffic_status_node_t *) &node->color;
                        buf = njt_http_stream_server_traffic_status_display_set_upstream_node(r, buf, &usn, stsn, &usn.addrs[k].name);
                    } else {
                        buf = njt_http_stream_server_traffic_status_display_set_upstream_node(r, buf, &usn, NULL, &usn.addrs[k].name);
                    }

                    p = dst.data;
                }
            }

            if (s == buf) {
                buf = o;

            } else {
                buf--;
                buf = njt_sprintf(buf, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_ARRAY_E);
                buf = njt_sprintf(buf, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_NEXT);
            }
        }
    }

    /* alones */
    o = buf;

    njt_str_set(&key, "::nogroups");

    buf = njt_sprintf(buf, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_ARRAY_S, &key);

    s = buf;

    buf = njt_http_stream_server_traffic_status_display_set_upstream_alone(r, buf, ctx->rbtree->root);

    if (s == buf) {
        buf = o;

    } else {
        buf--;
        buf = njt_sprintf(buf, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_ARRAY_E);
        buf = njt_sprintf(buf, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_NEXT);
    }

    return buf;
}


u_char *
njt_http_stream_server_traffic_status_display_set(njt_http_request_t *r,
    u_char *buf)
{
    u_char                                            *o, *s;
    njt_str_t                                          stats;
    njt_rbtree_node_t                                 *node;
    njt_http_stream_server_traffic_status_ctx_t       *ctx;
    njt_http_stream_server_traffic_status_loc_conf_t  *stscf;

    ctx = njt_http_get_module_main_conf(r, njt_stream_stsd_module);

    stscf = njt_http_get_module_loc_conf(r, njt_stream_stsd_module);

    node = ctx->rbtree->root;

    /* init stats */
    njt_memzero(&stscf->stats, sizeof(stscf->stats));
    njt_http_stream_server_traffic_status_node_time_queue_init(&stscf->stats.stat_session_times);

    /* main & connections */
    buf = njt_sprintf(buf, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_S);

    buf = njt_http_stream_server_traffic_status_display_set_main(r, buf);

    /* serverZones */
    buf = njt_sprintf(buf, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_SERVER_S);

    buf = njt_http_stream_server_traffic_status_display_set_server(r, buf, node);

    njt_str_set(&stats, "*");

    buf = njt_http_stream_server_traffic_status_display_set_server_node(r, buf, &stats,
                                                                        &stscf->stats);

    buf--;
    buf = njt_sprintf(buf, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_E);
    buf = njt_sprintf(buf, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_NEXT);

    /* filterZones */
    njt_memzero(&stscf->stats, sizeof(stscf->stats));

    o = buf;

    buf = njt_sprintf(buf, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_FILTER_S);

    s = buf;

    buf = njt_http_stream_server_traffic_status_display_set_filter(r, buf, node);

    if (s == buf) {
        buf = o;

    } else {
        buf--;
        buf = njt_sprintf(buf, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_E);
        buf = njt_sprintf(buf, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_NEXT);
    }

    /* upstreamZones */
    o = buf;

    buf = njt_sprintf(buf, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_UPSTREAM_S);

    s = buf;

    buf = njt_http_stream_server_traffic_status_display_set_upstream_group(r, buf);

    if (s == buf) {
        buf = o;
        buf--;

    } else {
        buf--;
        buf = njt_sprintf(buf, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_E);
    }

    buf = njt_sprintf(buf, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_JSON_FMT_E);

    return buf;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
