
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#include <njt_config.h>

#include "njt_http_stream_server_traffic_status_module.h"
#include "njt_http_stream_server_traffic_status_node.h"


njt_int_t
njt_http_stream_server_traffic_status_node_generate_key(njt_pool_t *pool,
    njt_str_t *buf, njt_str_t *dst, unsigned type)
{
    size_t   len;
    u_char  *p;

    len = njt_strlen(njt_http_stream_server_traffic_status_group_to_string(type));

    buf->len = len + sizeof("@") - 1 + dst->len;
    buf->data = njt_pcalloc(pool, buf->len);
    if (buf->data == NULL) {
        *buf = *dst;
        return NJT_ERROR;
    }

    p = buf->data;

    p = njt_cpymem(p, njt_http_stream_server_traffic_status_group_to_string(type), len);
    *p++ = NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_KEY_SEPARATOR;
    p = njt_cpymem(p, dst->data, dst->len);

    return NJT_OK;
}


njt_int_t
njt_http_stream_server_traffic_status_node_position_key(njt_str_t *buf, size_t pos)
{
    size_t   n, c, len;
    u_char  *p, *s;

    n = buf->len + 1;
    c = len = 0;
    p = s = buf->data;

    while (--n) {
        if (*p == NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_KEY_SEPARATOR) {
            if (pos == c) {
                break;
            }
            s = (p + 1);
            c++;
        }
        p++;
        len = (p - s);
    }

    if (pos > c || len == 0) {
        return NJT_ERROR;
    }

    buf->data = s;
    buf->len = len;

    return NJT_OK;
}


njt_rbtree_node_t *
njt_http_stream_server_traffic_status_find_node(njt_http_request_t *r,
    njt_str_t *key, unsigned type, uint32_t key_hash)
{
    uint32_t                                           hash;
    njt_rbtree_node_t                                 *node;
    njt_http_stream_server_traffic_status_ctx_t       *ctx;
    njt_http_stream_server_traffic_status_loc_conf_t  *stscf;

    ctx = njt_http_get_module_main_conf(r, njt_stream_stsd_module);
    stscf = njt_http_get_module_loc_conf(r, njt_stream_stsd_module);

    hash = key_hash;

    if (hash == 0) {
        hash = njt_crc32_short(key->data, key->len);
    }

    if (stscf->node_caches[type] != NULL) {
        if (stscf->node_caches[type]->key == hash) {
            node = stscf->node_caches[type];
            goto found;
        }
    }

    node = njt_http_stream_server_traffic_status_node_lookup(ctx->rbtree, key, hash);

found:

    return node;
}


njt_rbtree_node_t *
njt_http_stream_server_traffic_status_node_lookup(njt_rbtree_t *rbtree, njt_str_t *key,
    uint32_t hash)
{
    njt_int_t                                      rc;
    njt_rbtree_node_t                             *node, *sentinel;
    njt_http_stream_server_traffic_status_node_t  *stsn;

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

        stsn = (njt_http_stream_server_traffic_status_node_t *) &node->color;

        rc = njt_memn2cmp(key->data, stsn->data, key->len, (size_t) stsn->len);
        if (rc == 0) {
            return node;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


void
njt_http_stream_server_traffic_status_node_zero(njt_http_stream_server_traffic_status_node_t *stsn)
{
    stsn->stat_connect_counter = 0;
    stsn->stat_in_bytes = 0;
    stsn->stat_out_bytes = 0;
    stsn->stat_1xx_counter = 0;
    stsn->stat_2xx_counter = 0;
    stsn->stat_3xx_counter = 0;
    stsn->stat_4xx_counter = 0;
    stsn->stat_5xx_counter = 0;

    stsn->stat_session_time_counter = 0;
    stsn->stat_session_time = 0;

    stsn->stat_connect_counter_oc = 0;
    stsn->stat_in_bytes_oc = 0;
    stsn->stat_out_bytes_oc = 0;
    stsn->stat_1xx_counter_oc = 0;
    stsn->stat_2xx_counter_oc = 0;
    stsn->stat_3xx_counter_oc = 0;
    stsn->stat_4xx_counter_oc = 0;
    stsn->stat_5xx_counter_oc = 0;
    stsn->stat_session_time_counter_oc = 0;
    stsn->stat_u_connect_time_counter_oc = 0;
    stsn->stat_u_first_byte_time_counter_oc = 0;
    stsn->stat_u_session_time_counter_oc = 0;
}


void
njt_http_stream_server_traffic_status_node_time_queue_zero(
    njt_http_stream_server_traffic_status_node_time_queue_t *q)
{
    njt_memzero(q, sizeof(njt_http_stream_server_traffic_status_node_time_queue_t));
}


void
njt_http_stream_server_traffic_status_node_time_queue_init(
    njt_http_stream_server_traffic_status_node_time_queue_t *q)
{
    njt_http_stream_server_traffic_status_node_time_queue_zero(q);
    q->rear = NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_DEFAULT_QUEUE_LEN - 1;
    q->len = NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_DEFAULT_QUEUE_LEN;
}


njt_msec_t
njt_http_stream_server_traffic_status_node_time_queue_average(
    njt_http_stream_server_traffic_status_node_time_queue_t *q,
    njt_int_t method, njt_msec_t period)
{
    njt_msec_t  avg;

    if (method == NJT_HTTP_STREAM_SERVER_TRAFFIC_STATUS_AVERAGE_METHOD_AMM) {
        avg = njt_http_stream_server_traffic_status_node_time_queue_amm(q, period);
    } else {
        avg = njt_http_stream_server_traffic_status_node_time_queue_wma(q, period);
    }

    return avg;
}


njt_msec_t
njt_http_stream_server_traffic_status_node_time_queue_amm(
    njt_http_stream_server_traffic_status_node_time_queue_t *q,
    njt_msec_t period)
{
    njt_int_t   c, i, j, k;
    njt_msec_t  x, current_msec;

    current_msec = njt_http_stream_server_traffic_status_current_msec();

    c = 0;
    x = period ? (current_msec - period) : 0;

    for (i = q->front, j = 1, k = 0; i != q->rear; i = (i + 1) % q->len, j++) {
        if (x < q->times[i].time) {
            k += (njt_int_t) q->times[i].msec;
            c++;
        }
    }

    return (c == 0) ? (njt_msec_t) 0 : (njt_msec_t) (k / c);
}


njt_msec_t
njt_http_stream_server_traffic_status_node_time_queue_wma(
    njt_http_stream_server_traffic_status_node_time_queue_t *q,
    njt_msec_t period)
{
    njt_int_t   c, i, j, k;
    njt_msec_t  x, current_msec;

    current_msec = njt_http_stream_server_traffic_status_current_msec();

    c = 0;
    x = period ? (current_msec - period) : 0;

    for (i = q->front, j = 1, k = 0; i != q->rear; i = (i + 1) % q->len, j++) {
        if (x < q->times[i].time) {
            k += (njt_int_t) q->times[i].msec * ++c;
        }
    }

    return (c == 0) ? (njt_msec_t) 0 : (njt_msec_t)
           (k / (njt_int_t) njt_http_stream_server_traffic_status_triangle(c));
}


void
njt_http_stream_server_traffic_status_node_time_queue_merge(
    njt_http_stream_server_traffic_status_node_time_queue_t *a,
    njt_http_stream_server_traffic_status_node_time_queue_t *b,
    njt_msec_t period)
{
    njt_int_t                                                i, j, k, n, len;
    njt_msec_t                                               x, current_msec;
    njt_http_stream_server_traffic_status_node_time_queue_t  q;

    njt_http_stream_server_traffic_status_node_time_queue_init(&q);
    current_msec = njt_http_stream_server_traffic_status_current_msec();
    x = period ? (current_msec - period) : 0;
    len = q.len;

    for (i = a->rear, j = b->rear, k = q.rear, n = 0; n < len -1; ++n) {
        if (a->times[(i + len - 1) % len].time > b->times[(j + len - 1) % len].time) {
            if (x >= a->times[(i + len - 1) % len].time) {
                break;
            }
            q.times[(k + len - 1) % len].time = a->times[(i + len - 1) % len].time;
            q.times[(k + len - 1) % len].msec = a->times[(i + len - 1) % len].msec;
            i = (i + len - 1) % len;

        } else {
            if (x >= b->times[(j + len - 1) % len].time) {
                break;
            }
            q.times[(k + len - 1) % len].time = b->times[(j + len - 1) % len].time;
            q.times[(k + len - 1) % len].msec = b->times[(j + len - 1) % len].msec;
            j = (j + len - 1) % len;
        }
        k = (k + len - 1) % len;
    }
    (void) njt_cpymem(a, &q, sizeof(q));
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
