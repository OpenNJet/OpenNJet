
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


#define njt_http_v3_table_entry_size(n, v) ((n)->len + (v)->len + 32)


static njt_int_t njt_http_v3_evict(njt_connection_t *c, size_t target);
static void njt_http_v3_unblock(void *data);
static njt_int_t njt_http_v3_new_entry(njt_connection_t *c);


typedef struct {
    njt_queue_t        queue;
    njt_connection_t  *connection;
    njt_uint_t        *nblocked;
} njt_http_v3_block_t;


static njt_http_v3_field_t  njt_http_v3_static_table[] = {

    { njt_string(":authority"),            njt_string("") },
    { njt_string(":path"),                 njt_string("/") },
    { njt_string("age"),                   njt_string("0") },
    { njt_string("content-disposition"),   njt_string("") },
    { njt_string("content-length"),        njt_string("0") },
    { njt_string("cookie"),                njt_string("") },
    { njt_string("date"),                  njt_string("") },
    { njt_string("etag"),                  njt_string("") },
    { njt_string("if-modified-since"),     njt_string("") },
    { njt_string("if-none-match"),         njt_string("") },
    { njt_string("last-modified"),         njt_string("") },
    { njt_string("link"),                  njt_string("") },
    { njt_string("location"),              njt_string("") },
    { njt_string("referer"),               njt_string("") },
    { njt_string("set-cookie"),            njt_string("") },
    { njt_string(":method"),               njt_string("CONNECT") },
    { njt_string(":method"),               njt_string("DELETE") },
    { njt_string(":method"),               njt_string("GET") },
    { njt_string(":method"),               njt_string("HEAD") },
    { njt_string(":method"),               njt_string("OPTIONS") },
    { njt_string(":method"),               njt_string("POST") },
    { njt_string(":method"),               njt_string("PUT") },
    { njt_string(":scheme"),               njt_string("http") },
    { njt_string(":scheme"),               njt_string("https") },
    { njt_string(":status"),               njt_string("103") },
    { njt_string(":status"),               njt_string("200") },
    { njt_string(":status"),               njt_string("304") },
    { njt_string(":status"),               njt_string("404") },
    { njt_string(":status"),               njt_string("503") },
    { njt_string("accept"),                njt_string("*/*") },
    { njt_string("accept"),
          njt_string("application/dns-message") },
    { njt_string("accept-encoding"),       njt_string("gzip, deflate, br") },
    { njt_string("accept-ranges"),         njt_string("bytes") },
    { njt_string("access-control-allow-headers"),
                                           njt_string("cache-control") },
    { njt_string("access-control-allow-headers"),
                                           njt_string("content-type") },
    { njt_string("access-control-allow-origin"),
                                           njt_string("*") },
    { njt_string("cache-control"),         njt_string("max-age=0") },
    { njt_string("cache-control"),         njt_string("max-age=2592000") },
    { njt_string("cache-control"),         njt_string("max-age=604800") },
    { njt_string("cache-control"),         njt_string("no-cache") },
    { njt_string("cache-control"),         njt_string("no-store") },
    { njt_string("cache-control"),
          njt_string("public, max-age=31536000") },
    { njt_string("content-encoding"),      njt_string("br") },
    { njt_string("content-encoding"),      njt_string("gzip") },
    { njt_string("content-type"),
          njt_string("application/dns-message") },
    { njt_string("content-type"),
          njt_string("application/javascript") },
    { njt_string("content-type"),          njt_string("application/json") },
    { njt_string("content-type"),
          njt_string("application/x-www-form-urlencoded") },
    { njt_string("content-type"),          njt_string("image/gif") },
    { njt_string("content-type"),          njt_string("image/jpeg") },
    { njt_string("content-type"),          njt_string("image/png") },
    { njt_string("content-type"),          njt_string("text/css") },
    { njt_string("content-type"),
          njt_string("text/html;charset=utf-8") },
    { njt_string("content-type"),          njt_string("text/plain") },
    { njt_string("content-type"),
          njt_string("text/plain;charset=utf-8") },
    { njt_string("range"),                 njt_string("bytes=0-") },
    { njt_string("strict-transport-security"),
                                           njt_string("max-age=31536000") },
    { njt_string("strict-transport-security"),
          njt_string("max-age=31536000;includesubdomains") },
    { njt_string("strict-transport-security"),
          njt_string("max-age=31536000;includesubdomains;preload") },
    { njt_string("vary"),                  njt_string("accept-encoding") },
    { njt_string("vary"),                  njt_string("origin") },
    { njt_string("x-content-type-options"),
                                           njt_string("nosniff") },
    { njt_string("x-xss-protection"),      njt_string("1;mode=block") },
    { njt_string(":status"),               njt_string("100") },
    { njt_string(":status"),               njt_string("204") },
    { njt_string(":status"),               njt_string("206") },
    { njt_string(":status"),               njt_string("302") },
    { njt_string(":status"),               njt_string("400") },
    { njt_string(":status"),               njt_string("403") },
    { njt_string(":status"),               njt_string("421") },
    { njt_string(":status"),               njt_string("425") },
    { njt_string(":status"),               njt_string("500") },
    { njt_string("accept-language"),       njt_string("") },
    { njt_string("access-control-allow-credentials"),
                                           njt_string("FALSE") },
    { njt_string("access-control-allow-credentials"),
                                           njt_string("TRUE") },
    { njt_string("access-control-allow-headers"),
                                           njt_string("*") },
    { njt_string("access-control-allow-methods"),
                                           njt_string("get") },
    { njt_string("access-control-allow-methods"),
                                           njt_string("get, post, options") },
    { njt_string("access-control-allow-methods"),
                                           njt_string("options") },
    { njt_string("access-control-expose-headers"),
                                           njt_string("content-length") },
    { njt_string("access-control-request-headers"),
                                           njt_string("content-type") },
    { njt_string("access-control-request-method"),
                                           njt_string("get") },
    { njt_string("access-control-request-method"),
                                           njt_string("post") },
    { njt_string("alt-svc"),               njt_string("clear") },
    { njt_string("authorization"),         njt_string("") },
    { njt_string("content-security-policy"),
          njt_string("script-src 'none';object-src 'none';base-uri 'none'") },
    { njt_string("early-data"),            njt_string("1") },
    { njt_string("expect-ct"),             njt_string("") },
    { njt_string("forwarded"),             njt_string("") },
    { njt_string("if-range"),              njt_string("") },
    { njt_string("origin"),                njt_string("") },
    { njt_string("purpose"),               njt_string("prefetch") },
    { njt_string("server"),                njt_string("") },
    { njt_string("timing-allow-origin"),   njt_string("*") },
    { njt_string("upgrade-insecure-requests"),
                                           njt_string("1") },
    { njt_string("user-agent"),            njt_string("") },
    { njt_string("x-forwarded-for"),       njt_string("") },
    { njt_string("x-frame-options"),       njt_string("deny") },
    { njt_string("x-frame-options"),       njt_string("sameorigin") }
};


njt_int_t
njt_http_v3_ref_insert(njt_connection_t *c, njt_uint_t dynamic,
    njt_uint_t index, njt_str_t *value)
{
    njt_str_t                     name;
    njt_http_v3_session_t        *h3c;
    njt_http_v3_dynamic_table_t  *dt;

    if (dynamic) {
        njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 ref insert dynamic[%ui] \"%V\"", index, value);

        h3c = njt_http_v3_get_session(c);
        dt = &h3c->table;

        if (dt->base + dt->nelts <= index) {
            return NJT_HTTP_V3_ERR_ENCODER_STREAM_ERROR;
        }

        index = dt->base + dt->nelts - 1 - index;

        if (njt_http_v3_lookup(c, index, &name, NULL) != NJT_OK) {
            return NJT_HTTP_V3_ERR_ENCODER_STREAM_ERROR;
        }

    } else {
        njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 ref insert static[%ui] \"%V\"", index, value);

        if (njt_http_v3_lookup_static(c, index, &name, NULL) != NJT_OK) {
            return NJT_HTTP_V3_ERR_ENCODER_STREAM_ERROR;
        }
    }

    return njt_http_v3_insert(c, &name, value);
}


njt_int_t
njt_http_v3_insert(njt_connection_t *c, njt_str_t *name, njt_str_t *value)
{
    u_char                       *p;
    size_t                        size;
    njt_http_v3_field_t          *field;
    njt_http_v3_session_t        *h3c;
    njt_http_v3_dynamic_table_t  *dt;

    size = njt_http_v3_table_entry_size(name, value);

    h3c = njt_http_v3_get_session(c);
    dt = &h3c->table;

    if (size > dt->capacity) {
        njt_log_error(NJT_LOG_ERR, c->log, 0,
                      "not enough dynamic table capacity");
        return NJT_HTTP_V3_ERR_ENCODER_STREAM_ERROR;
    }

    njt_log_debug4(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 insert [%ui] \"%V\":\"%V\", size:%uz",
                   dt->base + dt->nelts, name, value, size);

    p = njt_alloc(sizeof(njt_http_v3_field_t) + name->len + value->len,
                  c->log);
    if (p == NULL) {
        return NJT_ERROR;
    }

    field = (njt_http_v3_field_t *) p;

    field->name.data = p + sizeof(njt_http_v3_field_t);
    field->name.len = name->len;
    field->value.data = njt_cpymem(field->name.data, name->data, name->len);
    field->value.len = value->len;
    njt_memcpy(field->value.data, value->data, value->len);

    dt->elts[dt->nelts++] = field;
    dt->size += size;

    dt->insert_count++;

    if (njt_http_v3_evict(c, dt->capacity) != NJT_OK) {
        return NJT_ERROR;
    }

    njt_post_event(&dt->send_insert_count, &njt_posted_events);

    if (njt_http_v3_new_entry(c) != NJT_OK) {
        return NJT_ERROR;
    }

    return NJT_OK;
}


void
njt_http_v3_inc_insert_count_handler(njt_event_t *ev)
{
    njt_connection_t             *c;
    njt_http_v3_session_t        *h3c;
    njt_http_v3_dynamic_table_t  *dt;

    c = ev->data;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 inc insert count handler");

    h3c = njt_http_v3_get_session(c);
    dt = &h3c->table;

    if (dt->insert_count > dt->ack_insert_count) {
        if (njt_http_v3_send_inc_insert_count(c,
                                       dt->insert_count - dt->ack_insert_count)
            != NJT_OK)
        {
            return;
        }

        dt->ack_insert_count = dt->insert_count;
    }
}


njt_int_t
njt_http_v3_set_capacity(njt_connection_t *c, njt_uint_t capacity)
{
    njt_uint_t                     max, prev_max;
    njt_http_v3_field_t          **elts;
    njt_http_v3_session_t         *h3c;
    njt_http_v3_srv_conf_t        *h3scf;
    njt_http_v3_dynamic_table_t   *dt;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 set capacity %ui", capacity);

    h3c = njt_http_v3_get_session(c);
    h3scf = njt_http_v3_get_module_srv_conf(c, njt_http_v3_module);

    if (capacity > h3scf->max_table_capacity) {
        njt_log_error(NJT_LOG_INFO, c->log, 0,
                      "client exceeded http3_max_table_capacity limit");
        return NJT_HTTP_V3_ERR_ENCODER_STREAM_ERROR;
    }

    if (njt_http_v3_evict(c, capacity) != NJT_OK) {
        return NJT_HTTP_V3_ERR_ENCODER_STREAM_ERROR;
    }

    dt = &h3c->table;
    max = capacity / 32;
    prev_max = dt->capacity / 32;

    if (max > prev_max) {
        elts = njt_alloc(max * sizeof(void *), c->log);
        if (elts == NULL) {
            return NJT_ERROR;
        }

        if (dt->elts) {
            njt_memcpy(elts, dt->elts, dt->nelts * sizeof(void *));
            njt_free(dt->elts);
        }

        dt->elts = elts;
    }

    dt->capacity = capacity;

    return NJT_OK;
}


void
njt_http_v3_cleanup_table(njt_http_v3_session_t *h3c)
{
    njt_uint_t                    n;
    njt_http_v3_dynamic_table_t  *dt;

    dt = &h3c->table;

    if (dt->elts == NULL) {
        return;
    }

    for (n = 0; n < dt->nelts; n++) {
        njt_free(dt->elts[n]);
    }

    njt_free(dt->elts);
}


static njt_int_t
njt_http_v3_evict(njt_connection_t *c, size_t target)
{
    size_t                        size;
    njt_uint_t                    n;
    njt_http_v3_field_t          *field;
    njt_http_v3_session_t        *h3c;
    njt_http_v3_dynamic_table_t  *dt;

    h3c = njt_http_v3_get_session(c);
    dt = &h3c->table;
    n = 0;

    while (dt->size > target) {
        field = dt->elts[n++];
        size = njt_http_v3_table_entry_size(&field->name, &field->value);

        njt_log_debug4(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 evict [%ui] \"%V\":\"%V\" size:%uz",
                       dt->base, &field->name, &field->value, size);

        njt_free(field);
        dt->size -= size;
    }

    if (n) {
        dt->nelts -= n;
        dt->base += n;
        njt_memmove(dt->elts, &dt->elts[n], dt->nelts * sizeof(void *));
    }

    return NJT_OK;
}


njt_int_t
njt_http_v3_duplicate(njt_connection_t *c, njt_uint_t index)
{
    njt_str_t                     name, value;
    njt_http_v3_session_t        *h3c;
    njt_http_v3_dynamic_table_t  *dt;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0, "http3 duplicate %ui", index);

    h3c = njt_http_v3_get_session(c);
    dt = &h3c->table;

    if (dt->base + dt->nelts <= index) {
        return NJT_HTTP_V3_ERR_ENCODER_STREAM_ERROR;
    }

    index = dt->base + dt->nelts - 1 - index;

    if (njt_http_v3_lookup(c, index, &name, &value) != NJT_OK) {
        return NJT_HTTP_V3_ERR_ENCODER_STREAM_ERROR;
    }

    return njt_http_v3_insert(c, &name, &value);
}


njt_int_t
njt_http_v3_ack_section(njt_connection_t *c, njt_uint_t stream_id)
{
    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 ack section %ui", stream_id);

    /* we do not use dynamic tables */

    return NJT_HTTP_V3_ERR_DECODER_STREAM_ERROR;
}


njt_int_t
njt_http_v3_inc_insert_count(njt_connection_t *c, njt_uint_t inc)
{
    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 increment insert count %ui", inc);

    /* we do not use dynamic tables */

    return NJT_HTTP_V3_ERR_DECODER_STREAM_ERROR;
}


njt_int_t
njt_http_v3_lookup_static(njt_connection_t *c, njt_uint_t index,
    njt_str_t *name, njt_str_t *value)
{
    njt_uint_t            nelts;
    njt_http_v3_field_t  *field;

    nelts = sizeof(njt_http_v3_static_table)
            / sizeof(njt_http_v3_static_table[0]);

    if (index >= nelts) {
        njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 static[%ui] lookup out of bounds: %ui",
                       index, nelts);
        return NJT_ERROR;
    }

    field = &njt_http_v3_static_table[index];

    njt_log_debug3(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 static[%ui] lookup \"%V\":\"%V\"",
                   index, &field->name, &field->value);

    if (name) {
        *name = field->name;
    }

    if (value) {
        *value = field->value;
    }

    return NJT_OK;
}


njt_int_t
njt_http_v3_lookup(njt_connection_t *c, njt_uint_t index, njt_str_t *name,
    njt_str_t *value)
{
    njt_http_v3_field_t          *field;
    njt_http_v3_session_t        *h3c;
    njt_http_v3_dynamic_table_t  *dt;

    h3c = njt_http_v3_get_session(c);
    dt = &h3c->table;

    if (index < dt->base || index - dt->base >= dt->nelts) {
        njt_log_debug3(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 dynamic[%ui] lookup out of bounds: [%ui,%ui]",
                       index, dt->base, dt->base + dt->nelts);
        return NJT_ERROR;
    }

    field = dt->elts[index - dt->base];

    njt_log_debug3(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 dynamic[%ui] lookup \"%V\":\"%V\"",
                   index, &field->name, &field->value);

    if (name) {
        *name = field->name;
    }

    if (value) {
        *value = field->value;
    }

    return NJT_OK;
}


njt_int_t
njt_http_v3_decode_insert_count(njt_connection_t *c, njt_uint_t *insert_count)
{
    njt_uint_t                    max_entries, full_range, max_value,
                                  max_wrapped, req_insert_count;
    njt_http_v3_srv_conf_t       *h3scf;
    njt_http_v3_session_t        *h3c;
    njt_http_v3_dynamic_table_t  *dt;

    /* QPACK 4.5.1.1. Required Insert Count */

    if (*insert_count == 0) {
        return NJT_OK;
    }

    h3c = njt_http_v3_get_session(c);
    dt = &h3c->table;

    h3scf = njt_http_v3_get_module_srv_conf(c, njt_http_v3_module);

    max_entries = h3scf->max_table_capacity / 32;
    full_range = 2 * max_entries;

    if (*insert_count > full_range) {
        return NJT_HTTP_V3_ERR_DECOMPRESSION_FAILED;
    }

    max_value = dt->base + dt->nelts + max_entries;
    max_wrapped = (max_value / full_range) * full_range;
    req_insert_count = max_wrapped + *insert_count - 1;

    if (req_insert_count > max_value) {
        if (req_insert_count <= full_range) {
            return NJT_HTTP_V3_ERR_DECOMPRESSION_FAILED;
        }

        req_insert_count -= full_range;
    }

    if (req_insert_count == 0) {
        return NJT_HTTP_V3_ERR_DECOMPRESSION_FAILED;
    }

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 decode insert_count %ui -> %ui",
                   *insert_count, req_insert_count);

    *insert_count = req_insert_count;

    return NJT_OK;
}


njt_int_t
njt_http_v3_check_insert_count(njt_connection_t *c, njt_uint_t insert_count)
{
    size_t                        n;
    njt_pool_cleanup_t           *cln;
    njt_http_v3_block_t          *block;
    njt_http_v3_session_t        *h3c;
    njt_http_v3_srv_conf_t       *h3scf;
    njt_http_v3_dynamic_table_t  *dt;

    h3c = njt_http_v3_get_session(c);
    dt = &h3c->table;

    n = dt->base + dt->nelts;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 check insert count req:%ui, have:%ui",
                   insert_count, n);

    if (n >= insert_count) {
        return NJT_OK;
    }

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0, "http3 block stream");

    block = NULL;

    for (cln = c->pool->cleanup; cln; cln = cln->next) {
        if (cln->handler == njt_http_v3_unblock) {
            block = cln->data;
            break;
        }
    }

    if (block == NULL) {
        cln = njt_pool_cleanup_add(c->pool, sizeof(njt_http_v3_block_t));
        if (cln == NULL) {
            return NJT_ERROR;
        }

        cln->handler = njt_http_v3_unblock;

        block = cln->data;
        block->queue.prev = NULL;
        block->connection = c;
        block->nblocked = &h3c->nblocked;
    }

    if (block->queue.prev == NULL) {
        h3scf = njt_http_v3_get_module_srv_conf(c, njt_http_v3_module);

        if (h3c->nblocked == h3scf->max_blocked_streams) {
            njt_log_error(NJT_LOG_INFO, c->log, 0,
                          "client exceeded http3_max_blocked_streams limit");

            njt_http_v3_finalize_connection(c,
                                          NJT_HTTP_V3_ERR_DECOMPRESSION_FAILED,
                                          "too many blocked streams");
            return NJT_HTTP_V3_ERR_DECOMPRESSION_FAILED;
        }

        h3c->nblocked++;
        njt_queue_insert_tail(&h3c->blocked, &block->queue);
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 blocked:%ui", h3c->nblocked);

    return NJT_BUSY;
}


void
njt_http_v3_ack_insert_count(njt_connection_t *c, uint64_t insert_count)
{
    njt_http_v3_session_t        *h3c;
    njt_http_v3_dynamic_table_t  *dt;

    h3c = njt_http_v3_get_session(c);
    dt = &h3c->table;

    if (dt->ack_insert_count < insert_count) {
        dt->ack_insert_count = insert_count;
    }
}


static void
njt_http_v3_unblock(void *data)
{
    njt_http_v3_block_t  *block = data;

    if (block->queue.prev) {
        njt_queue_remove(&block->queue);
        block->queue.prev = NULL;
        (*block->nblocked)--;
    }
}


static njt_int_t
njt_http_v3_new_entry(njt_connection_t *c)
{
    njt_queue_t            *q;
    njt_connection_t       *bc;
    njt_http_v3_block_t    *block;
    njt_http_v3_session_t  *h3c;

    h3c = njt_http_v3_get_session(c);

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 new dynamic entry, blocked:%ui", h3c->nblocked);

    while (!njt_queue_empty(&h3c->blocked)) {
        q = njt_queue_head(&h3c->blocked);
        block = (njt_http_v3_block_t *) q;
        bc = block->connection;

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, bc->log, 0, "http3 unblock stream");

        njt_http_v3_unblock(block);
        njt_post_event(bc->read, &njt_posted_events);
    }

    return NJT_OK;
}


njt_int_t
njt_http_v3_set_param(njt_connection_t *c, uint64_t id, uint64_t value)
{
    switch (id) {

    case NJT_HTTP_V3_PARAM_MAX_TABLE_CAPACITY:
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 param QPACK_MAX_TABLE_CAPACITY:%uL", value);
        break;

    case NJT_HTTP_V3_PARAM_MAX_FIELD_SECTION_SIZE:
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 param SETTINGS_MAX_FIELD_SECTION_SIZE:%uL",
                       value);
        break;

    case NJT_HTTP_V3_PARAM_BLOCKED_STREAMS:
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 param QPACK_BLOCKED_STREAMS:%uL", value);
        break;

    default:

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 param #%uL:%uL", id, value);
    }

    return NJT_OK;
}
