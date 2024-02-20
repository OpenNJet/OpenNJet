
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#include <njt_config.h>

#include "njt_http_stream_server_traffic_status_module.h"
#include "njt_http_stream_server_traffic_status_shm.h"
#include "njt_http_stream_server_traffic_status_display_prometheus.h"


u_char *
njt_http_stream_server_traffic_status_display_prometheus_set_main(
    njt_http_request_t *r, u_char *buf)
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

    buf = njt_sprintf(buf, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_MAIN,
                      &njt_cycle->hostname, NJT_VERSION,
                      (double) stscf->start_msec / 1000,
                      ap, ac, hn, rd, rq, wa, wr,
                      shm_info->name, shm_info->max_size,
                      shm_info->used_size, shm_info->used_node);

    return buf;
}


u_char *
njt_http_stream_server_traffic_status_display_prometheus_set_server_node(
    njt_http_request_t *r, u_char *buf,
    njt_http_stream_server_traffic_status_node_t *stsn)
{
    njt_str_t                                                       listen, protocol;
    njt_uint_t                                                      i, n;
    njt_http_stream_server_traffic_status_loc_conf_t               *stscf;
    njt_http_stream_server_traffic_status_node_histogram_bucket_t  *b;

    stscf = njt_http_get_module_loc_conf(r, njt_stream_stsd_module);

    listen.data = stsn->data;
    listen.len = stsn->len;

    (void) njt_http_stream_server_traffic_status_node_position_key(&listen, 1);

    protocol.len = 3;
    protocol.data = (u_char *) (stsn->protocol == SOCK_DGRAM ? "UDP" : "TCP");

    buf = njt_sprintf(buf, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER,
                      &listen, stsn->port, &protocol, stsn->stat_in_bytes,
                      &listen, stsn->port, &protocol, stsn->stat_out_bytes,
                      &listen, stsn->port, &protocol, stsn->stat_1xx_counter,
                      &listen, stsn->port, &protocol, stsn->stat_2xx_counter,
                      &listen, stsn->port, &protocol, stsn->stat_3xx_counter,
                      &listen, stsn->port, &protocol, stsn->stat_4xx_counter,
                      &listen, stsn->port, &protocol, stsn->stat_5xx_counter,
                      &listen, stsn->port, &protocol, stsn->stat_connect_counter,
                      &listen, stsn->port, &protocol, (double) stsn->stat_session_time_counter / 1000,
                      &listen, stsn->port, &protocol,
                      (double) njt_http_stream_server_traffic_status_node_time_queue_average(
                          &stsn->stat_session_times, stscf->average_method,
                          stscf->average_period) / 1000);


    /* histogram */
    b = &stsn->stat_session_buckets;

    n = b->len;

    if (n > 0) {

        /* histogram:bucket */
        for (i = 0; i < n; i++) {
            buf = njt_sprintf(buf,
                      NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_HISTOGRAM_BUCKET,
                      &listen, stsn->port, &protocol, (double) b->buckets[i].msec / 1000,
                      b->buckets[i].counter);
        }

        buf = njt_sprintf(buf,
                  NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_HISTOGRAM_BUCKET_E,
                  &listen, stsn->port, &protocol, stsn->stat_connect_counter);

        /* histogram:sum */
        buf = njt_sprintf(buf,
                  NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_HISTOGRAM_SUM,
                  &listen, stsn->port, &protocol,
                  (double) stsn->stat_session_time_counter / 1000);

        /* histogram:count */
        buf = njt_sprintf(buf,
                  NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_HISTOGRAM_COUNT,
                  &listen, stsn->port, &protocol, stsn->stat_connect_counter);
    }

    return buf;
}


u_char *
njt_http_stream_server_traffic_status_display_prometheus_set_server(
    njt_http_request_t *r, u_char *buf, njt_rbtree_node_t *node)
{
    njt_http_stream_server_traffic_status_ctx_t   *ctx;
    njt_http_stream_server_traffic_status_node_t  *stsn;

    ctx = njt_http_get_module_main_conf(r, njt_stream_stsd_module);

    if (node != ctx->rbtree->sentinel) {
        stsn = (njt_http_stream_server_traffic_status_node_t *) &node->color;

        if (stsn->stat_upstream.type == NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_NO) {
            buf = njt_http_stream_server_traffic_status_display_prometheus_set_server_node(r, buf, stsn);
        }

        buf = njt_http_stream_server_traffic_status_display_prometheus_set_server(r, buf, node->left);
        buf = njt_http_stream_server_traffic_status_display_prometheus_set_server(r, buf, node->right);
    }

    return buf;
}


u_char *
njt_http_stream_server_traffic_status_display_prometheus_set_filter_node(
    njt_http_request_t *r, u_char *buf,
    njt_http_stream_server_traffic_status_node_t *stsn)
{
    njt_str_t                                                       key, filter, filter_name;
    njt_uint_t                                                      i, n;
    njt_http_stream_server_traffic_status_loc_conf_t               *stscf;
    njt_http_stream_server_traffic_status_node_histogram_bucket_t  *b; 

    stscf = njt_http_get_module_loc_conf(r, njt_stream_stsd_module);

    key.data = stsn->data;
    key.len = stsn->len;

    filter = filter_name = key;

    (void) njt_http_stream_server_traffic_status_node_position_key(&filter, 1); 
    (void) njt_http_stream_server_traffic_status_node_position_key(&filter_name, 2); 

    buf = njt_sprintf(buf, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER,
                      &filter, &filter_name, stsn->stat_in_bytes,
                      &filter, &filter_name, stsn->stat_out_bytes,
                      &filter, &filter_name, stsn->stat_1xx_counter,
                      &filter, &filter_name, stsn->stat_2xx_counter,
                      &filter, &filter_name, stsn->stat_3xx_counter,
                      &filter, &filter_name, stsn->stat_4xx_counter,
                      &filter, &filter_name, stsn->stat_5xx_counter,
                      &filter, &filter_name, stsn->stat_connect_counter,
                      &filter, &filter_name, (double) stsn->stat_session_time_counter / 1000,
                      &filter, &filter_name,
                      (double) njt_http_stream_server_traffic_status_node_time_queue_average(
                          &stsn->stat_session_times, stscf->average_method,
                          stscf->average_period) / 1000);

    /* histogram */
    b = &stsn->stat_session_buckets;

    n = b->len;

    if (n > 0) {

        /* histogram:bucket */
        for (i = 0; i < n; i++) {
            buf = njt_sprintf(buf,
                      NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_HISTOGRAM_BUCKET,
                      &filter, &filter_name, (double) b->buckets[i].msec / 1000,
                      b->buckets[i].counter);
        }

        buf = njt_sprintf(buf,
                  NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_HISTOGRAM_BUCKET_E,
                  &filter, &filter_name, stsn->stat_connect_counter);

        /* histogram:sum */
        buf = njt_sprintf(buf,
                  NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_HISTOGRAM_SUM,
                  &filter, &filter_name, (double) stsn->stat_session_time_counter / 1000);

        /* histogram:count */
        buf = njt_sprintf(buf,
                  NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_HISTOGRAM_COUNT,
                  &filter, &filter_name, stsn->stat_connect_counter);
    }

    return buf;
}


u_char *
njt_http_stream_server_traffic_status_display_prometheus_set_filter(
    njt_http_request_t *r, u_char *buf, njt_rbtree_node_t *node)
{
    njt_http_stream_server_traffic_status_ctx_t   *ctx;
    njt_http_stream_server_traffic_status_node_t  *stsn;

    ctx = njt_http_get_module_main_conf(r, njt_stream_stsd_module);

    if (node != ctx->rbtree->sentinel) {
        stsn = (njt_http_stream_server_traffic_status_node_t *) &node->color;

        if (stsn->stat_upstream.type == NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_FG) {
            buf = njt_http_stream_server_traffic_status_display_prometheus_set_filter_node(r, buf, stsn);
        }

        buf = njt_http_stream_server_traffic_status_display_prometheus_set_filter(r, buf, node->left);
        buf = njt_http_stream_server_traffic_status_display_prometheus_set_filter(r, buf, node->right);
    }

    return buf;
}


u_char *
njt_http_stream_server_traffic_status_display_prometheus_set_upstream_node(
    njt_http_request_t *r, u_char *buf,
    njt_http_stream_server_traffic_status_node_t *stsn)
{
    njt_str_t                                                       target, upstream, upstream_server;
    njt_uint_t                                                      i, n, len;
    njt_atomic_t                                                    time_counter;
    njt_http_stream_server_traffic_status_loc_conf_t               *stscf;
    njt_http_stream_server_traffic_status_node_histogram_bucket_t  *b;

    stscf = njt_http_get_module_loc_conf(r, njt_stream_stsd_module);

    upstream_server.data = stsn->data;
    upstream_server.len = stsn->len;

    upstream = upstream_server;

    if (stsn->stat_upstream.type == NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_UG) {
        (void) njt_http_stream_server_traffic_status_node_position_key(&upstream, 1);
        (void) njt_http_stream_server_traffic_status_node_position_key(&upstream_server, 2);

    } else if (stsn->stat_upstream.type == NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_UA) {
        njt_str_set(&upstream, "::nogroups");
        (void) njt_http_stream_server_traffic_status_node_position_key(&upstream_server, 1);
    }

    buf = njt_sprintf(buf, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM,
                      &upstream, &upstream_server, stsn->stat_in_bytes,
                      &upstream, &upstream_server, stsn->stat_out_bytes,
                      &upstream, &upstream_server, stsn->stat_1xx_counter,
                      &upstream, &upstream_server, stsn->stat_2xx_counter,
                      &upstream, &upstream_server, stsn->stat_3xx_counter,
                      &upstream, &upstream_server, stsn->stat_4xx_counter,
                      &upstream, &upstream_server, stsn->stat_5xx_counter,
                      &upstream, &upstream_server, stsn->stat_connect_counter,
                      &upstream, &upstream_server, (double) stsn->stat_session_time_counter / 1000,
                      &upstream, &upstream_server,
                      (double) njt_http_stream_server_traffic_status_node_time_queue_average(
                          &stsn->stat_session_times, stscf->average_method,
                          stscf->average_period) / 1000,
                      &upstream, &upstream_server, (double) stsn->stat_upstream.connect_time_counter / 1000,
                      &upstream, &upstream_server,
                      (double) njt_http_stream_server_traffic_status_node_time_queue_average(
                          &stsn->stat_upstream.connect_times, stscf->average_method,
                          stscf->average_period) / 1000,
                      &upstream, &upstream_server, (double) stsn->stat_upstream.first_byte_time_counter / 1000,
                      &upstream, &upstream_server,
                      (double) njt_http_stream_server_traffic_status_node_time_queue_average(
                          &stsn->stat_upstream.first_byte_times, stscf->average_method,
                          stscf->average_period) / 1000,
                      &upstream, &upstream_server, (double) stsn->stat_upstream.session_time_counter / 1000,
                      &upstream, &upstream_server,
                      (double) njt_http_stream_server_traffic_status_node_time_queue_average(
                          &stsn->stat_upstream.session_times, stscf->average_method,
                          stscf->average_period) / 1000);

    /* histogram */
    len = 4;

    while (len--) {
        if (len == 3) {
            b = &stsn->stat_session_buckets;
            time_counter = stsn->stat_session_time_counter;
            njt_str_set(&target, "session");

        } else if (len == 2) {
            b = &stsn->stat_upstream.connect_buckets;
            time_counter = stsn->stat_upstream.connect_time_counter;
            njt_str_set(&target, "response_connect");

        } else if (len == 1) {
            b = &stsn->stat_upstream.first_byte_buckets;
            time_counter = stsn->stat_upstream.first_byte_time_counter;
            njt_str_set(&target, "response_firstbyte");

        } else {
            b = &stsn->stat_upstream.session_buckets;
            time_counter = stsn->stat_upstream.session_time_counter;
            njt_str_set(&target, "response_session");
        }

        n = b->len;

        if (n > 0) {
            /* histogram:bucket */
            for (i = 0; i < n; i++) {
                buf = njt_sprintf(buf,
                        NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HISTOGRAM_BUCKET,
                        &target, &upstream, &upstream_server, (double) b->buckets[i].msec / 1000,
                        b->buckets[i].counter);
            }

            buf = njt_sprintf(buf,
                    NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HISTOGRAM_BUCKET_E,
                    &target, &upstream, &upstream_server, stsn->stat_connect_counter);

            /* histogram:sum */
            buf = njt_sprintf(buf,
                    NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HISTOGRAM_SUM,
                    &target, &upstream, &upstream_server, (double) time_counter / 1000);

            /* histogram:count */
            buf = njt_sprintf(buf,
                    NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_HISTOGRAM_COUNT,
                    &target, &upstream, &upstream_server, stsn->stat_connect_counter);
        }

    }

    return buf;
}


u_char *
njt_http_stream_server_traffic_status_display_prometheus_set_upstream(
    njt_http_request_t *r, u_char *buf, njt_rbtree_node_t *node)
{
    njt_http_stream_server_traffic_status_ctx_t   *ctx;
    njt_http_stream_server_traffic_status_node_t  *stsn;

    ctx = njt_http_get_module_main_conf(r, njt_stream_stsd_module);

    if (node != ctx->rbtree->sentinel) {
        stsn = (njt_http_stream_server_traffic_status_node_t *) &node->color;

        if (stsn->stat_upstream.type == NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_UG
            || stsn->stat_upstream.type == NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_UA)
        {
            buf = njt_http_stream_server_traffic_status_display_prometheus_set_upstream_node(r, buf, stsn);
        }

        buf = njt_http_stream_server_traffic_status_display_prometheus_set_upstream(r, buf, node->left);
        buf = njt_http_stream_server_traffic_status_display_prometheus_set_upstream(r, buf, node->right);
    }

    return buf;
}


u_char *
njt_http_stream_server_traffic_status_display_prometheus_set(
    njt_http_request_t *r, u_char *buf)
{
    u_char                                       *o, *s;
    njt_rbtree_node_t                            *node;
    njt_http_stream_server_traffic_status_ctx_t  *ctx;

    ctx = njt_http_get_module_main_conf(r, njt_stream_stsd_module);

    node = ctx->rbtree->root;

    /* main & connections */
    buf = njt_http_stream_server_traffic_status_display_prometheus_set_main(r, buf);

    /* serverZones */
    o = buf;

    buf = njt_sprintf(buf, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_SERVER_S);

    s = buf;

    buf = njt_http_stream_server_traffic_status_display_prometheus_set_server(r, buf, node);

    if (s == buf) {
        buf = o;
    }

    /* filterZones */
    o = buf;

    buf = njt_sprintf(buf, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_FILTER_S);

    s = buf;

    buf = njt_http_stream_server_traffic_status_display_prometheus_set_filter(r, buf, node);

    if (s == buf) {
        buf = o;
    }

    /* upstreamZones */
    o = buf;

    buf = njt_sprintf(buf, NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_PROMETHEUS_FMT_UPSTREAM_S);

    s = buf;

    buf = njt_http_stream_server_traffic_status_display_prometheus_set_upstream(r, buf, node);

    if (s == buf) {
        buf = o;
    }

    return buf;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
