
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#include <njt_config.h>

#include "njt_stream_server_traffic_status_module.h"
#include "njt_stream_server_traffic_status_node.h"


njt_int_t
njt_stream_server_traffic_status_node_generate_key(njt_pool_t *pool,
    njt_str_t *buf, njt_str_t *dst, unsigned type)
{
    size_t   len;
    u_char  *p;

    len = njt_strlen(njt_stream_server_traffic_status_group_to_string(type));

    buf->len = len + sizeof("@") - 1 + dst->len;
    buf->data = njt_pcalloc(pool, buf->len);
    if (buf->data == NULL) {
        *buf = *dst;
        return NJT_ERROR;
    }

    p = buf->data;

    p = njt_cpymem(p, njt_stream_server_traffic_status_group_to_string(type), len);
    *p++ = NJT_STREAM_SERVER_TRAFFIC_STATUS_KEY_SEPARATOR;
    p = njt_cpymem(p, dst->data, dst->len);

    return NJT_OK;
}


njt_int_t
njt_stream_server_traffic_status_node_position_key(njt_str_t *buf, size_t pos)
{
    size_t   n, c, len;
    u_char  *p, *s;

    n = buf->len + 1;
    c = len = 0;
    p = s = buf->data;

    while (--n) {
        if (*p == NJT_STREAM_SERVER_TRAFFIC_STATUS_KEY_SEPARATOR) {
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


njt_int_t
njt_stream_server_traffic_status_find_name(njt_stream_session_t *s,
    njt_str_t *buf)
{
    u_char      addr[NJT_SOCKADDR_STRLEN];
    njt_str_t   str, protocol;
    njt_uint_t  port;

    str.len = NJT_SOCKADDR_STRLEN;
    str.data = addr;

    if (njt_connection_local_sockaddr(s->connection, &str, 0) != NJT_OK) {
        return NJT_ERROR;
    }

    str.data = njt_pnalloc(s->connection->pool, str.len);
    if (str.data == NULL) {
        return NJT_ERROR;
    }

    njt_memcpy(str.data, addr, str.len);

    port = njt_inet_get_port(s->connection->local_sockaddr);

    protocol.len = 3;
    protocol.data = (u_char *) (s->connection->type == SOCK_DGRAM ? "UDP" : "TCP");

    buf->len = str.len + sizeof("[]:65535") + sizeof("TCP");
    buf->data = njt_pnalloc(s->connection->pool, buf->len);
    if (buf->data == NULL) {
        return NJT_ERROR;
    }

    /* protocol:port:addr */
    buf->len = njt_sprintf(buf->data, "%V:%ui:%V", &protocol, port, &str) - buf->data;

    return NJT_OK;
}


njt_rbtree_node_t *
njt_stream_server_traffic_status_find_node(njt_stream_session_t *s,
    njt_str_t *key, unsigned type, uint32_t key_hash)
{
    uint32_t                                  hash;
    njt_rbtree_node_t                        *node;
    njt_stream_server_traffic_status_ctx_t   *ctx;
    njt_stream_server_traffic_status_conf_t  *stscf;

    ctx = njt_stream_get_module_main_conf(s, njt_stream_stsc_module);
    stscf = njt_stream_get_module_srv_conf(s, njt_stream_stsc_module);

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

    node = njt_stream_server_traffic_status_node_lookup(ctx->rbtree, key, hash);

found:

    return node;
}


njt_rbtree_node_t *
njt_stream_server_traffic_status_node_lookup(njt_rbtree_t *rbtree, njt_str_t *key,
    uint32_t hash)
{
    njt_int_t                                 rc;
    njt_rbtree_node_t                        *node, *sentinel;
    njt_stream_server_traffic_status_node_t  *stsn;

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

        stsn = (njt_stream_server_traffic_status_node_t *) &node->color;

        rc = njt_memn2cmp(key->data, stsn->data, key->len, (size_t) stsn->len);
        if (rc == 0) {
            return node;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


void
njt_stream_server_traffic_status_node_zero(njt_stream_server_traffic_status_node_t *stsn)
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
njt_stream_server_traffic_status_node_init(njt_stream_session_t *s,
    njt_stream_server_traffic_status_node_t *stsn)
{
    njt_uint_t status = s->status;

    /* init serverZone */
    njt_stream_server_traffic_status_node_zero(stsn);
    njt_stream_server_traffic_status_node_time_queue_init(&stsn->stat_session_times);
    njt_stream_server_traffic_status_node_histogram_bucket_init(s,
        &stsn->stat_session_buckets);
    stsn->port = njt_inet_get_port(s->connection->local_sockaddr);
    stsn->protocol = s->connection->type;

    /* init upstreamZone */
    stsn->stat_upstream.type = NJT_STREAM_SERVER_TRAFFIC_STATUS_UPSTREAM_NO;
    stsn->stat_upstream.connect_time_counter = 0;
    stsn->stat_upstream.connect_time = 0;
    stsn->stat_upstream.first_byte_time_counter = 0;
    stsn->stat_upstream.first_byte_time = 0;
    stsn->stat_upstream.session_time_counter = 0;
    stsn->stat_upstream.session_time = 0;
    njt_stream_server_traffic_status_node_time_queue_init(
        &stsn->stat_upstream.connect_times);
    njt_stream_server_traffic_status_node_time_queue_init(
        &stsn->stat_upstream.first_byte_times);
    njt_stream_server_traffic_status_node_time_queue_init(
        &stsn->stat_upstream.session_times);
    njt_stream_server_traffic_status_node_histogram_bucket_init(s,
        &stsn->stat_upstream.connect_buckets);
    njt_stream_server_traffic_status_node_histogram_bucket_init(s,
        &stsn->stat_upstream.first_byte_buckets);
    njt_stream_server_traffic_status_node_histogram_bucket_init(s,
        &stsn->stat_upstream.session_buckets);

    /* set serverZone */
    stsn->stat_connect_counter = 1;
    stsn->stat_in_bytes = (njt_atomic_uint_t) s->received;
    stsn->stat_out_bytes = (njt_atomic_uint_t) s->connection->sent;

    njt_stream_server_traffic_status_add_rc(status, stsn);

    stsn->stat_session_time = (njt_msec_t) njt_stream_server_traffic_status_session_time(s);
    stsn->stat_session_time_counter = (njt_atomic_uint_t) stsn->stat_session_time; 

    njt_stream_server_traffic_status_node_time_queue_insert(&stsn->stat_session_times,
        stsn->stat_session_time);
}


void
njt_stream_server_traffic_status_node_set(njt_stream_session_t *s,
    njt_stream_server_traffic_status_node_t *stsn)
{
    njt_uint_t                                status;
    njt_msec_int_t                            ms;
    njt_stream_server_traffic_status_node_t   ostsn;
    njt_stream_server_traffic_status_conf_t  *stscf;

    stscf = njt_stream_get_module_srv_conf(s, njt_stream_stsc_module);

    status = s->status;
    ostsn = *stsn;

    stsn->stat_connect_counter++;
    stsn->stat_in_bytes += (njt_atomic_uint_t) s->received;
    stsn->stat_out_bytes += (njt_atomic_uint_t) s->connection->sent;

    njt_stream_server_traffic_status_add_rc(status, stsn);

    ms = njt_stream_server_traffic_status_session_time(s);

    stsn->stat_session_time_counter += (njt_atomic_uint_t) ms;

    njt_stream_server_traffic_status_node_time_queue_insert(&stsn->stat_session_times,
                                                            ms);

    njt_stream_server_traffic_status_node_histogram_observe(&stsn->stat_session_buckets,
                                                            ms);

    stsn->stat_session_time = njt_stream_server_traffic_status_node_time_queue_average(
                                  &stsn->stat_session_times, stscf->average_method,
                                  stscf->average_period);

    njt_stream_server_traffic_status_add_oc((&ostsn), stsn);
}


void
njt_stream_server_traffic_status_node_time_queue_zero(
    njt_stream_server_traffic_status_node_time_queue_t *q)
{
    njt_memzero(q, sizeof(njt_stream_server_traffic_status_node_time_queue_t));
}


void
njt_stream_server_traffic_status_node_time_queue_init(
    njt_stream_server_traffic_status_node_time_queue_t *q)
{
    njt_stream_server_traffic_status_node_time_queue_zero(q);
    q->rear = NJT_STREAM_SERVER_TRAFFIC_STATUS_DEFAULT_QUEUE_LEN - 1;
    q->len = NJT_STREAM_SERVER_TRAFFIC_STATUS_DEFAULT_QUEUE_LEN;
}


njt_int_t
njt_stream_server_traffic_status_node_time_queue_push(
    njt_stream_server_traffic_status_node_time_queue_t *q,
    njt_msec_int_t x)
{
    if ((q->rear + 1) % q->len == q->front) {
        return NJT_ERROR;
    }

    q->times[q->rear].time = njt_stream_server_traffic_status_current_msec();
    q->times[q->rear].msec = x;
    q->rear = (q->rear + 1) % q->len;

    return NJT_OK;
}


njt_int_t
njt_stream_server_traffic_status_node_time_queue_pop(
    njt_stream_server_traffic_status_node_time_queue_t *q,
    njt_stream_server_traffic_status_node_time_t *x)
{
    if (q->front == q->rear) {
        return NJT_ERROR;
    }

    *x = q->times[q->front];
    q->front = (q->front + 1) % q->len;

    return NJT_OK;
}


void
njt_stream_server_traffic_status_node_time_queue_insert(
    njt_stream_server_traffic_status_node_time_queue_t *q,
    njt_msec_int_t x)
{
    njt_int_t                                     rc;
    njt_stream_server_traffic_status_node_time_t  rx;
    rc = njt_stream_server_traffic_status_node_time_queue_pop(q, &rx)
         | njt_stream_server_traffic_status_node_time_queue_push(q, x);

    if (rc != NJT_OK) {
        njt_stream_server_traffic_status_node_time_queue_init(q);
    }
}


njt_msec_t
njt_stream_server_traffic_status_node_time_queue_average(
    njt_stream_server_traffic_status_node_time_queue_t *q,
    njt_int_t method, njt_msec_t period)
{
    njt_msec_t  avg;

    if (method == NJT_STREAM_SERVER_TRAFFIC_STATUS_AVERAGE_METHOD_AMM) {
        avg = njt_stream_server_traffic_status_node_time_queue_amm(q, period);
    } else {
        avg = njt_stream_server_traffic_status_node_time_queue_wma(q, period);
    }

    return avg;
}


njt_msec_t
njt_stream_server_traffic_status_node_time_queue_amm(
    njt_stream_server_traffic_status_node_time_queue_t *q,
    njt_msec_t period)
{
    njt_int_t   c, i, j, k;
    njt_msec_t  x, current_msec;

    current_msec = njt_stream_server_traffic_status_current_msec();

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
njt_stream_server_traffic_status_node_time_queue_wma(
    njt_stream_server_traffic_status_node_time_queue_t *q,
    njt_msec_t period)
{
    njt_int_t   c, i, j, k;
    njt_msec_t  x, current_msec;

    current_msec = njt_stream_server_traffic_status_current_msec();

    c = 0;
    x = period ? (current_msec - period) : 0;

    for (i = q->front, j = 1, k = 0; i != q->rear; i = (i + 1) % q->len, j++) {
        if (x < q->times[i].time) {
            k += (njt_int_t) q->times[i].msec * ++c;
        }
    }

    return (c == 0) ? (njt_msec_t) 0 : (njt_msec_t)
           (k / (njt_int_t) njt_stream_server_traffic_status_triangle(c));
}


void
njt_stream_server_traffic_status_node_histogram_bucket_init(
    njt_stream_session_t *s,
    njt_stream_server_traffic_status_node_histogram_bucket_t *b)
{
    njt_uint_t                                          i, n;
    njt_stream_server_traffic_status_conf_t            *stscf;
    njt_stream_server_traffic_status_node_histogram_t  *buckets;

    stscf = njt_stream_get_module_srv_conf(s, njt_stream_stsc_module);

    if (stscf->histogram_buckets == NULL) {
        b->len = 0;
        return;
    }

    buckets = stscf->histogram_buckets->elts;
    n = stscf->histogram_buckets->nelts;
    b->len = n;

    for (i = 0; i < n; i++) {
        b->buckets[i].msec = buckets[i].msec;
        b->buckets[i].counter = 0;
    }
}


void
njt_stream_server_traffic_status_node_histogram_observe(
    njt_stream_server_traffic_status_node_histogram_bucket_t *b,
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
njt_stream_server_traffic_status_node_member_cmp(njt_str_t *member, const char *name)
{
    if (member->len == njt_strlen(name) && njt_strncmp(name, member->data, member->len) == 0) {
        return 0;
    }

    return 1;
}


njt_atomic_uint_t
njt_stream_server_traffic_status_node_member(njt_stream_server_traffic_status_node_t *stsn,
    njt_str_t *member)
{
    if (njt_stream_server_traffic_status_node_member_cmp(member, "connect") == 0)
    {
        return stsn->stat_connect_counter;
    }
    else if (njt_stream_server_traffic_status_node_member_cmp(member, "in") == 0)
    {
        return stsn->stat_in_bytes;
    }
    else if (njt_stream_server_traffic_status_node_member_cmp(member, "out") == 0)
    {
        return stsn->stat_out_bytes;
    }
    else if (njt_stream_server_traffic_status_node_member_cmp(member, "1xx") == 0)
    {
        return stsn->stat_1xx_counter;
    }
    else if (njt_stream_server_traffic_status_node_member_cmp(member, "2xx") == 0)
    {
        return stsn->stat_2xx_counter;
    }
    else if (njt_stream_server_traffic_status_node_member_cmp(member, "3xx") == 0)
    {
        return stsn->stat_3xx_counter;
    }
    else if (njt_stream_server_traffic_status_node_member_cmp(member, "4xx") == 0)
    {
        return stsn->stat_4xx_counter;
    }
    else if (njt_stream_server_traffic_status_node_member_cmp(member, "5xx") == 0)
    {
        return stsn->stat_5xx_counter;
    }

    return 0;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
