
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 * Copyright (C), 2021-2023, TMLake(Beijing) Technology Co., Ltd.
 */


#include "njt_http_vhost_traffic_status_module.h"
#include "njt_http_vhost_traffic_status_filter.h"
#include "njt_http_vhost_traffic_status_shm.h"
#include "njt_http_vhost_traffic_status_node.h"


njt_int_t
njt_http_vhost_traffic_status_node_generate_key(njt_pool_t *pool,
    njt_str_t *buf, njt_str_t *dst, unsigned type)
{
    size_t   len;
    u_char  *p;

    len = njt_strlen(njt_http_vhost_traffic_status_group_to_string(type));

    buf->len = len + sizeof("@") - 1 + dst->len;
    buf->data = njt_pcalloc(pool, buf->len);
    if (buf->data == NULL) {
        *buf = *dst;
        return NJT_ERROR;
    }

    p = buf->data;

    p = njt_cpymem(p, njt_http_vhost_traffic_status_group_to_string(type), len);
    *p++ = NJT_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR;
    p = njt_cpymem(p, dst->data, dst->len);

    return NJT_OK;
}


njt_int_t
njt_http_vhost_traffic_status_node_position_key(njt_str_t *buf, size_t pos)
{
    size_t   n, c, len;
    u_char  *p, *s;

    n = buf->len + 1;
    c = len = 0;
    p = s = buf->data;

    while (--n) {
        if (*p == NJT_HTTP_VHOST_TRAFFIC_STATUS_KEY_SEPARATOR) {
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


void
njt_http_vhost_traffic_status_find_name(njt_http_request_t *r,
    njt_str_t *buf)
{
    njt_http_core_srv_conf_t                  *cscf;
    njt_http_vhost_traffic_status_loc_conf_t  *vtscf;

    cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);
    vtscf = njt_http_get_module_loc_conf(r, njt_http_vhost_traffic_status_module);

    if (vtscf->filter && vtscf->filter_host && r->headers_in.server.len) {
        /* set the key by host header */
        *buf = r->headers_in.server;

    } else {
        /* set the key by server_name variable */
        *buf = cscf->server_name;

        if (buf->len == 0) {
            buf->len = 1;
            buf->data = (u_char *) "_";
        }
    }
}


njt_rbtree_node_t *
njt_http_vhost_traffic_status_find_node(njt_http_request_t *r,
    njt_str_t *key, unsigned type, uint32_t key_hash)
{
    uint32_t                                   hash;
    njt_rbtree_node_t                         *node;
    njt_http_vhost_traffic_status_ctx_t       *ctx;
    njt_http_vhost_traffic_status_loc_conf_t  *vtscf;

    ctx = njt_http_get_module_main_conf(r, njt_http_vhost_traffic_status_module);
    vtscf = njt_http_get_module_loc_conf(r, njt_http_vhost_traffic_status_module);

    hash = key_hash;

    if (hash == 0) {
        hash = njt_crc32_short(key->data, key->len);
    }

    if (vtscf->node_caches[type] != NULL) {
        if (vtscf->node_caches[type]->key == hash) {
            node = vtscf->node_caches[type];
            goto found;
        }
    }

    node = njt_http_vhost_traffic_status_node_lookup(ctx->rbtree, key, hash);

found:

    return node;
}


njt_rbtree_node_t *
njt_http_vhost_traffic_status_find_lru(njt_http_request_t *r)
{
    njt_rbtree_node_t                         *node;
    njt_http_vhost_traffic_status_ctx_t       *ctx;
    njt_http_vhost_traffic_status_shm_info_t  *shm_info;

    ctx = njt_http_get_module_main_conf(r, njt_http_vhost_traffic_status_module);
    node = NULL;

    /* disabled */
    if (ctx->filter_max_node == 0) {
        return NULL;
    }

    shm_info = njt_pcalloc(r->pool, sizeof(njt_http_vhost_traffic_status_shm_info_t));

    if (shm_info == NULL) { 
        return NULL;
    }

    njt_http_vhost_traffic_status_shm_info(r, shm_info);

    /* find */
    if (shm_info->filter_used_node >= ctx->filter_max_node) {
        node = njt_http_vhost_traffic_status_find_lru_node(r, NULL, ctx->rbtree->root);
    }

    return node;
}


njt_rbtree_node_t *
njt_http_vhost_traffic_status_find_lru_node(njt_http_request_t *r,
    njt_rbtree_node_t *a, njt_rbtree_node_t *b)
{
    njt_str_t                              filter;
    njt_http_vhost_traffic_status_ctx_t   *ctx;
    njt_http_vhost_traffic_status_node_t  *vtsn;

    ctx = njt_http_get_module_main_conf(r, njt_http_vhost_traffic_status_module);

    if (b != ctx->rbtree->sentinel) {
        vtsn = njt_http_vhost_traffic_status_get_node(b);

        if (vtsn->stat_upstream.type == NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_FG) {
            filter.data = vtsn->data;
            filter.len = vtsn->len;

            (void) njt_http_vhost_traffic_status_node_position_key(&filter, 1);

            if (njt_http_vhost_traffic_status_filter_max_node_match(r, &filter) == NJT_OK) {
                a = njt_http_vhost_traffic_status_find_lru_node_cmp(r, a, b);
            }
        }

        a = njt_http_vhost_traffic_status_find_lru_node(r, a, b->left);
        a = njt_http_vhost_traffic_status_find_lru_node(r, a, b->right);
    }

    return a;
}


njt_rbtree_node_t *
njt_http_vhost_traffic_status_find_lru_node_cmp(njt_http_request_t *r,
    njt_rbtree_node_t *a, njt_rbtree_node_t *b)
{
    njt_int_t                                         ai, bi;
    njt_http_vhost_traffic_status_node_t             *avtsn, *bvtsn;
    njt_http_vhost_traffic_status_node_time_queue_t  *aq, *bq;

    if (a == NULL) {
        return b;
    }

    avtsn = njt_http_vhost_traffic_status_get_node(a);
    bvtsn = njt_http_vhost_traffic_status_get_node(b);

    aq = &avtsn->stat_request_times;
    bq = &bvtsn->stat_request_times;

    if (aq->front == aq->rear) {
        return a;
    }

    if (bq->front == bq->rear) {
        return b;
    }

    ai = njt_http_vhost_traffic_status_node_time_queue_rear(aq);
    bi = njt_http_vhost_traffic_status_node_time_queue_rear(bq);

    return (aq->times[ai].time < bq->times[bi].time) ? a : b;
}


njt_rbtree_node_t *
njt_http_vhost_traffic_status_node_lookup(njt_rbtree_t *rbtree, njt_str_t *key,
    uint32_t hash)
{
    njt_int_t                              rc;
    njt_rbtree_node_t                     *node, *sentinel;
    njt_http_vhost_traffic_status_node_t  *vtsn;

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

        vtsn = njt_http_vhost_traffic_status_get_node(node);

        rc = njt_memn2cmp(key->data, vtsn->data, key->len, (size_t) vtsn->len);
        if (rc == 0) {
            return node;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


void
njt_http_vhost_traffic_status_node_zero(njt_http_vhost_traffic_status_node_t *vtsn)
{
    vtsn->stat_request_counter = 0;
    vtsn->stat_in_bytes = 0;
    vtsn->stat_out_bytes = 0;
    vtsn->stat_1xx_counter = 0;
    vtsn->stat_2xx_counter = 0;
    vtsn->stat_3xx_counter = 0;
    vtsn->stat_4xx_counter = 0;
    vtsn->stat_5xx_counter = 0;
    vtsn->stat_timeo_counter_oc = 0;

    vtsn->stat_request_time_counter = 0;
    vtsn->stat_request_time = 0;
    vtsn->stat_upstream.response_time_counter = 0;
    vtsn->stat_upstream.response_time = 0;

    vtsn->stat_request_counter_oc = 0;
    vtsn->stat_in_bytes_oc = 0;
    vtsn->stat_out_bytes_oc = 0;
    vtsn->stat_1xx_counter_oc = 0;
    vtsn->stat_2xx_counter_oc = 0;
    vtsn->stat_3xx_counter_oc = 0;
    vtsn->stat_4xx_counter_oc = 0;
    vtsn->stat_5xx_counter_oc = 0;
    vtsn->stat_request_time_counter_oc = 0;
    vtsn->stat_response_time_counter_oc = 0;

#if (NJT_HTTP_CACHE)
    vtsn->stat_cache_miss_counter = 0;
    vtsn->stat_cache_bypass_counter = 0;
    vtsn->stat_cache_expired_counter = 0;
    vtsn->stat_cache_stale_counter = 0;
    vtsn->stat_cache_updating_counter = 0;
    vtsn->stat_cache_revalidated_counter = 0;
    vtsn->stat_cache_hit_counter = 0;
    vtsn->stat_cache_scarce_counter = 0;

    vtsn->stat_cache_miss_counter_oc = 0;
    vtsn->stat_cache_bypass_counter_oc = 0;
    vtsn->stat_cache_expired_counter_oc = 0;
    vtsn->stat_cache_stale_counter_oc = 0;
    vtsn->stat_cache_updating_counter_oc = 0;
    vtsn->stat_cache_revalidated_counter_oc = 0;
    vtsn->stat_cache_hit_counter_oc = 0;
    vtsn->stat_cache_scarce_counter_oc = 0;
#endif

}


void
njt_http_vhost_traffic_status_nodes_zero(njt_http_vhost_traffic_status_node_t *vtsn)
{
    int                 i;

    njt_http_vhost_traffic_status_node_zero(vtsn);
    for (i=0; i<njt_ncpu; i++) {
        vtsn--;
        njt_http_vhost_traffic_status_node_zero(vtsn);
    }
}


/*
   Initialize the node and update it with the first request.
   Set the `stat_request_time` to the time of the first request.
*/
void
njt_http_vhost_traffic_status_node_init(njt_http_request_t *r,
    njt_http_vhost_traffic_status_node_t *vtsn)
{
    /* init serverZone */
    njt_http_vhost_traffic_status_node_zero(vtsn);
    njt_http_vhost_traffic_status_node_time_queue_init(&vtsn->stat_request_times);
    njt_http_vhost_traffic_status_node_histogram_bucket_init(r, &vtsn->stat_request_buckets);

    /* init upstreamZone */
    vtsn->stat_upstream.type = NJT_HTTP_VHOST_TRAFFIC_STATUS_UPSTREAM_NO;
    vtsn->stat_upstream.response_time_counter = 0;
    vtsn->stat_upstream.response_time = 0;
    njt_http_vhost_traffic_status_node_time_queue_init(&vtsn->stat_upstream.response_times);
    njt_http_vhost_traffic_status_node_histogram_bucket_init(r,
        &vtsn->stat_upstream.response_buckets);
}


void
njt_http_vhost_traffic_status_node_init_update(njt_http_request_t *r,
    njt_http_vhost_traffic_status_node_t *vtsn)
{
    njt_msec_int_t  ms;

    /* set serverZone */
    ms = njt_http_vhost_traffic_status_request_time(r);
    vtsn->stat_request_time = (njt_msec_t) ms;

    njt_http_vhost_traffic_status_node_update(r, vtsn, ms);
}


void
njt_http_vhost_traffic_status_nodes_init(njt_http_request_t *r,
    njt_http_vhost_traffic_status_node_t *vtsn)
{
    int             i;

    njt_http_vhost_traffic_status_node_init(r, vtsn);
    for (i=0; i<njt_ncpu; i++) {
        vtsn--;
        njt_http_vhost_traffic_status_node_init(r, vtsn);
    }
}



/*
   Update the node from a subsequent request. Now there is more than one request,
   calculate the average request time.
*/
void
njt_http_vhost_traffic_status_node_set(njt_http_request_t *r,
    njt_http_vhost_traffic_status_node_t *vtsn)
{
    njt_msec_int_t                             ms;
    njt_http_vhost_traffic_status_node_t       ovtsn;
    njt_http_vhost_traffic_status_loc_conf_t  *vtscf;

    vtscf = njt_http_get_module_loc_conf(r, njt_http_vhost_traffic_status_module);

    ovtsn = *vtsn;

    ms = njt_http_vhost_traffic_status_request_time(r);
    njt_http_vhost_traffic_status_node_update(r, vtsn, ms);

    vtsn->stat_request_time = njt_http_vhost_traffic_status_node_time_queue_average(
                                  &vtsn->stat_request_times, vtscf->average_method,
                                  vtscf->average_period);

    njt_http_vhost_traffic_status_add_oc((&ovtsn), vtsn);
}


void
njt_http_vhost_traffic_status_node_update(njt_http_request_t *r,
    njt_http_vhost_traffic_status_node_t *vtsn, njt_msec_int_t ms)
{
    njt_uint_t status = r->headers_out.status;

    vtsn->stat_request_counter++;
    vtsn->stat_in_bytes += (njt_atomic_uint_t) r->request_length;
    vtsn->stat_out_bytes += (njt_atomic_uint_t) r->connection->sent;

    njt_http_vhost_traffic_status_add_rc(status, vtsn);

    vtsn->stat_request_time_counter += (njt_atomic_uint_t) ms;

    njt_http_vhost_traffic_status_node_time_queue_insert(&vtsn->stat_request_times,
                                                         ms);

    njt_http_vhost_traffic_status_node_histogram_observe(&vtsn->stat_request_buckets,
                                                         ms);

#if (NJT_HTTP_CACHE)
    if (r->upstream != NULL && r->upstream->cache_status != 0) {
        njt_http_vhost_traffic_status_add_cc(r->upstream->cache_status, vtsn);
    }
#endif
}


void
njt_http_vhost_traffic_status_node_time_queue_zero(
    njt_http_vhost_traffic_status_node_time_queue_t *q)
{
    njt_memzero(q, sizeof(njt_http_vhost_traffic_status_node_time_queue_t));
}


void
njt_http_vhost_traffic_status_node_time_queue_init(
    njt_http_vhost_traffic_status_node_time_queue_t *q)
{
    njt_http_vhost_traffic_status_node_time_queue_zero(q);
    q->rear = NJT_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_QUEUE_LEN - 1;
    q->len = NJT_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_QUEUE_LEN;
}


njt_int_t
njt_http_vhost_traffic_status_node_time_queue_push(
    njt_http_vhost_traffic_status_node_time_queue_t *q,
    njt_msec_int_t x)
{
    if ((q->rear + 1) % q->len == q->front) {
        return NJT_ERROR;
    }

    q->times[q->rear].time = njt_http_vhost_traffic_status_current_msec();
    q->times[q->rear].msec = x;
    q->rear = (q->rear + 1) % q->len;

    return NJT_OK;
}


njt_int_t
njt_http_vhost_traffic_status_node_time_queue_pop(
    njt_http_vhost_traffic_status_node_time_queue_t *q,
    njt_http_vhost_traffic_status_node_time_t *x)
{
    if (q->front == q->rear) {
        return NJT_ERROR;
    }

    *x = q->times[q->front];
    q->front = (q->front + 1) % q->len;

    return NJT_OK;
}


njt_int_t
njt_http_vhost_traffic_status_node_time_queue_rear(
    njt_http_vhost_traffic_status_node_time_queue_t *q)
{
    return (q->rear > 0) ? (q->rear - 1) : (NJT_HTTP_VHOST_TRAFFIC_STATUS_DEFAULT_QUEUE_LEN - 1);
}


void
njt_http_vhost_traffic_status_node_time_queue_insert(
    njt_http_vhost_traffic_status_node_time_queue_t *q,
    njt_msec_int_t x)
{
    njt_int_t                                  rc;
    njt_http_vhost_traffic_status_node_time_t  rx;
    rc = njt_http_vhost_traffic_status_node_time_queue_pop(q, &rx)
         | njt_http_vhost_traffic_status_node_time_queue_push(q, x);

    if (rc != NJT_OK) {
        njt_http_vhost_traffic_status_node_time_queue_init(q);
    }
}


njt_msec_t
njt_http_vhost_traffic_status_node_time_queue_average(
    njt_http_vhost_traffic_status_node_time_queue_t *q,
    njt_int_t method, njt_msec_t period)
{
    njt_msec_t  avg;

    if (method == NJT_HTTP_VHOST_TRAFFIC_STATUS_AVERAGE_METHOD_AMM) {
        avg = njt_http_vhost_traffic_status_node_time_queue_amm(q, period);
    } else {
        avg = njt_http_vhost_traffic_status_node_time_queue_wma(q, period);
    }

    return avg;
}


njt_msec_t
njt_http_vhost_traffic_status_node_time_queue_amm(
    njt_http_vhost_traffic_status_node_time_queue_t *q,
    njt_msec_t period)
{
    njt_int_t   c, i, j, k;
    njt_msec_t  x, current_msec;

    current_msec = njt_http_vhost_traffic_status_current_msec();

    c = 0;
    x = period ? (current_msec - period) : 0;

    for (i = q->front, j = 1, k = 0; i != q->rear; i = (i + 1) % q->len, j++) {
        if (x < q->times[i].time) {
            k += (njt_int_t) q->times[i].msec;
            c++;
        }
    }

    if (j != q->len) {
        njt_http_vhost_traffic_status_node_time_queue_init(q);
    }

    return (c == 0) ? (njt_msec_t) 0 : (njt_msec_t) (k / c);
}


njt_msec_t
njt_http_vhost_traffic_status_node_time_queue_wma(
    njt_http_vhost_traffic_status_node_time_queue_t *q,
    njt_msec_t period)
{
    njt_int_t   c, i, j, k;
    njt_msec_t  x, current_msec;

    current_msec = njt_http_vhost_traffic_status_current_msec();

    c = 0;
    x = period ? (current_msec - period) : 0;

    for (i = q->front, j = 1, k = 0; i != q->rear; i = (i + 1) % q->len, j++) {
        if (x < q->times[i].time) {
            k += (njt_int_t) q->times[i].msec * ++c;
        }
    }

    if (j != q->len) {
        njt_http_vhost_traffic_status_node_time_queue_init(q);
    }

    return (c == 0) ? (njt_msec_t) 0 : (njt_msec_t)
           (k / (njt_int_t) njt_http_vhost_traffic_status_triangle(c));
}


void
njt_http_vhost_traffic_status_node_time_queue_merge(
    njt_http_vhost_traffic_status_node_time_queue_t *a,
    njt_http_vhost_traffic_status_node_time_queue_t *b,
    njt_msec_t period)
{
    njt_int_t                                        i, j, k, n, len;
    njt_msec_t                                       x, current_msec;
    njt_http_vhost_traffic_status_node_time_queue_t  q;

    njt_http_vhost_traffic_status_node_time_queue_init(&q);

    current_msec = njt_http_vhost_traffic_status_current_msec();
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


void
njt_http_vhost_traffic_status_node_histogram_bucket_init(njt_http_request_t *r,
    njt_http_vhost_traffic_status_node_histogram_bucket_t *b)
{
    njt_uint_t                                       i, n;
    njt_http_vhost_traffic_status_loc_conf_t        *vtscf;
    njt_http_vhost_traffic_status_node_histogram_t  *buckets;

    vtscf = njt_http_get_module_loc_conf(r, njt_http_vhost_traffic_status_module);

    if (vtscf->histogram_buckets == NULL) {
        b->len = 0;
        return;
    }

    buckets = vtscf->histogram_buckets->elts;
    n = vtscf->histogram_buckets->nelts;
    b->len = n;

    for (i = 0; i < n; i++) {
        b->buckets[i].msec = buckets[i].msec;
        b->buckets[i].counter = 0;
    }
}


void
njt_http_vhost_traffic_status_node_histogram_observe(
    njt_http_vhost_traffic_status_node_histogram_bucket_t *b,
    njt_msec_int_t x)
{
    njt_uint_t  i, n;

    n = b->len;

    for (i = 0; i < n; i++) {
        if (x <= b->buckets[i].msec) {
            b->buckets[i].counter++;
        }
    }
}


njt_int_t
njt_http_vhost_traffic_status_node_member_cmp(njt_str_t *member, const char *name)
{
    if (member->len == njt_strlen(name) && njt_strncmp(name, member->data, member->len) == 0) {
        return 0;
    }

    return 1;
}


njt_atomic_uint_t
njt_http_vhost_traffic_status_node_member(njt_http_vhost_traffic_status_node_t *vtsn,
    njt_str_t *member)
{
    if (njt_http_vhost_traffic_status_node_member_cmp(member, "request") == 0)
    {
        return vtsn->stat_request_counter;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "in") == 0)
    {
        return vtsn->stat_in_bytes;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "out") == 0)
    {
        return vtsn->stat_out_bytes;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "1xx") == 0)
    {
        return vtsn->stat_1xx_counter;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "2xx") == 0)
    {
        return vtsn->stat_2xx_counter;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "3xx") == 0)
    {
        return vtsn->stat_3xx_counter;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "4xx") == 0)
    {
        return vtsn->stat_4xx_counter;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "5xx") == 0)
    {
        return vtsn->stat_5xx_counter;
    }

#if (NJT_HTTP_CACHE)
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "cache_miss") == 0)
    {
        return vtsn->stat_cache_miss_counter;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "cache_bypass") == 0)
    {
        return vtsn->stat_cache_bypass_counter;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "cache_expired") == 0)
    {
        return vtsn->stat_cache_expired_counter;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "cache_stale") == 0)
    {
        return vtsn->stat_cache_stale_counter;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "cache_updating") == 0)
    {
        return vtsn->stat_cache_updating_counter;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "cache_revalidated") == 0)
    {
        return vtsn->stat_cache_revalidated_counter;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "cache_hit") == 0)
    {
        return vtsn->stat_cache_hit_counter;
    }
    else if (njt_http_vhost_traffic_status_node_member_cmp(member, "cache_scarce") == 0)
    {
        return vtsn->stat_cache_scarce_counter;
    }
#endif

    return 0;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
