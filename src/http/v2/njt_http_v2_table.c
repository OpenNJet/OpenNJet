
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 * Copyright (C) Valentin V. Bartenev
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


#define NJT_HTTP_V2_TABLE_SIZE  4096


static njt_int_t njt_http_v2_table_account(njt_http_v2_connection_t *h2c,
    size_t size);


static njt_http_v2_header_t  njt_http_v2_static_table[] = {
    { njt_string(":authority"), njt_string("") },
    { njt_string(":method"), njt_string("GET") },
    { njt_string(":method"), njt_string("POST") },
    { njt_string(":path"), njt_string("/") },
    { njt_string(":path"), njt_string("/index.html") },
    { njt_string(":scheme"), njt_string("http") },
    { njt_string(":scheme"), njt_string("https") },
    { njt_string(":status"), njt_string("200") },
    { njt_string(":status"), njt_string("204") },
    { njt_string(":status"), njt_string("206") },
    { njt_string(":status"), njt_string("304") },
    { njt_string(":status"), njt_string("400") },
    { njt_string(":status"), njt_string("404") },
    { njt_string(":status"), njt_string("500") },
    { njt_string("accept-charset"), njt_string("") },
    { njt_string("accept-encoding"), njt_string("gzip, deflate") },
    { njt_string("accept-language"), njt_string("") },
    { njt_string("accept-ranges"), njt_string("") },
    { njt_string("accept"), njt_string("") },
    { njt_string("access-control-allow-origin"), njt_string("") },
    { njt_string("age"), njt_string("") },
    { njt_string("allow"), njt_string("") },
    { njt_string("authorization"), njt_string("") },
    { njt_string("cache-control"), njt_string("") },
    { njt_string("content-disposition"), njt_string("") },
    { njt_string("content-encoding"), njt_string("") },
    { njt_string("content-language"), njt_string("") },
    { njt_string("content-length"), njt_string("") },
    { njt_string("content-location"), njt_string("") },
    { njt_string("content-range"), njt_string("") },
    { njt_string("content-type"), njt_string("") },
    { njt_string("cookie"), njt_string("") },
    { njt_string("date"), njt_string("") },
    { njt_string("etag"), njt_string("") },
    { njt_string("expect"), njt_string("") },
    { njt_string("expires"), njt_string("") },
    { njt_string("from"), njt_string("") },
    { njt_string("host"), njt_string("") },
    { njt_string("if-match"), njt_string("") },
    { njt_string("if-modified-since"), njt_string("") },
    { njt_string("if-none-match"), njt_string("") },
    { njt_string("if-range"), njt_string("") },
    { njt_string("if-unmodified-since"), njt_string("") },
    { njt_string("last-modified"), njt_string("") },
    { njt_string("link"), njt_string("") },
    { njt_string("location"), njt_string("") },
    { njt_string("max-forwards"), njt_string("") },
    { njt_string("proxy-authenticate"), njt_string("") },
    { njt_string("proxy-authorization"), njt_string("") },
    { njt_string("range"), njt_string("") },
    { njt_string("referer"), njt_string("") },
    { njt_string("refresh"), njt_string("") },
    { njt_string("retry-after"), njt_string("") },
    { njt_string("server"), njt_string("") },
    { njt_string("set-cookie"), njt_string("") },
    { njt_string("strict-transport-security"), njt_string("") },
    { njt_string("transfer-encoding"), njt_string("") },
    { njt_string("user-agent"), njt_string("") },
    { njt_string("vary"), njt_string("") },
    { njt_string("via"), njt_string("") },
    { njt_string("www-authenticate"), njt_string("") },
};

#define NJT_HTTP_V2_STATIC_TABLE_ENTRIES                                      \
    (sizeof(njt_http_v2_static_table)                                         \
     / sizeof(njt_http_v2_header_t))


njt_str_t *
njt_http_v2_get_static_name(njt_uint_t index)
{
    return &njt_http_v2_static_table[index - 1].name;
}


njt_str_t *
njt_http_v2_get_static_value(njt_uint_t index)
{
    return &njt_http_v2_static_table[index - 1].value;
}


njt_int_t
njt_http_v2_get_indexed_header(njt_http_v2_connection_t *h2c, njt_uint_t index,
    njt_uint_t name_only)
{
    u_char                *p;
    size_t                 rest;
    njt_http_v2_header_t  *entry;

    if (index == 0) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent invalid hpack table index 0");
        return NJT_ERROR;
    }

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 get indexed %s: %ui",
                   name_only ? "name" : "header", index);

    index--;

    if (index < NJT_HTTP_V2_STATIC_TABLE_ENTRIES) {
        h2c->state.header = njt_http_v2_static_table[index];
        return NJT_OK;
    }

    index -= NJT_HTTP_V2_STATIC_TABLE_ENTRIES;

    if (index < h2c->hpack.added - h2c->hpack.deleted) {
        index = (h2c->hpack.added - index - 1) % h2c->hpack.allocated;
        entry = h2c->hpack.entries[index];

        p = njt_pnalloc(h2c->state.pool, entry->name.len + 1);
        if (p == NULL) {
            return NJT_ERROR;
        }

        h2c->state.header.name.len = entry->name.len;
        h2c->state.header.name.data = p;

        rest = h2c->hpack.storage + NJT_HTTP_V2_TABLE_SIZE - entry->name.data;

        if (entry->name.len > rest) {
            p = njt_cpymem(p, entry->name.data, rest);
            p = njt_cpymem(p, h2c->hpack.storage, entry->name.len - rest);

        } else {
            p = njt_cpymem(p, entry->name.data, entry->name.len);
        }

        *p = '\0';

        if (name_only) {
            return NJT_OK;
        }

        p = njt_pnalloc(h2c->state.pool, entry->value.len + 1);
        if (p == NULL) {
            return NJT_ERROR;
        }

        h2c->state.header.value.len = entry->value.len;
        h2c->state.header.value.data = p;

        rest = h2c->hpack.storage + NJT_HTTP_V2_TABLE_SIZE - entry->value.data;

        if (entry->value.len > rest) {
            p = njt_cpymem(p, entry->value.data, rest);
            p = njt_cpymem(p, h2c->hpack.storage, entry->value.len - rest);

        } else {
            p = njt_cpymem(p, entry->value.data, entry->value.len);
        }

        *p = '\0';

        return NJT_OK;
    }

    njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                  "client sent out of bound hpack table index: %ui", index);

    return NJT_ERROR;
}


njt_int_t
njt_http_v2_add_header(njt_http_v2_connection_t *h2c,
    njt_http_v2_header_t *header)
{
    size_t                 avail;
    njt_uint_t             index;
    njt_http_v2_header_t  *entry, **entries;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 table add: \"%V: %V\"",
                   &header->name, &header->value);

    if (h2c->hpack.entries == NULL) {
        h2c->hpack.allocated = 64;
        h2c->hpack.size = NJT_HTTP_V2_TABLE_SIZE;
        h2c->hpack.free = NJT_HTTP_V2_TABLE_SIZE;

        h2c->hpack.entries = njt_palloc(h2c->connection->pool,
                                        sizeof(njt_http_v2_header_t *)
                                        * h2c->hpack.allocated);
        if (h2c->hpack.entries == NULL) {
            return NJT_ERROR;
        }

        h2c->hpack.storage = njt_palloc(h2c->connection->pool,
                                        h2c->hpack.free);
        if (h2c->hpack.storage == NULL) {
            return NJT_ERROR;
        }

        h2c->hpack.pos = h2c->hpack.storage;
    }

    if (njt_http_v2_table_account(h2c, header->name.len + header->value.len)
        != NJT_OK)
    {
        return NJT_OK;
    }

    if (h2c->hpack.reused == h2c->hpack.deleted) {
        entry = njt_palloc(h2c->connection->pool, sizeof(njt_http_v2_header_t));
        if (entry == NULL) {
            return NJT_ERROR;
        }

    } else {
        entry = h2c->hpack.entries[h2c->hpack.reused++ % h2c->hpack.allocated];
    }

    avail = h2c->hpack.storage + NJT_HTTP_V2_TABLE_SIZE - h2c->hpack.pos;

    entry->name.len = header->name.len;
    entry->name.data = h2c->hpack.pos;

    if (avail >= header->name.len) {
        h2c->hpack.pos = njt_cpymem(h2c->hpack.pos, header->name.data,
                                    header->name.len);
    } else {
        njt_memcpy(h2c->hpack.pos, header->name.data, avail);
        h2c->hpack.pos = njt_cpymem(h2c->hpack.storage,
                                    header->name.data + avail,
                                    header->name.len - avail);
        avail = NJT_HTTP_V2_TABLE_SIZE;
    }

    avail -= header->name.len;

    entry->value.len = header->value.len;
    entry->value.data = h2c->hpack.pos;

    if (avail >= header->value.len) {
        h2c->hpack.pos = njt_cpymem(h2c->hpack.pos, header->value.data,
                                    header->value.len);
    } else {
        njt_memcpy(h2c->hpack.pos, header->value.data, avail);
        h2c->hpack.pos = njt_cpymem(h2c->hpack.storage,
                                    header->value.data + avail,
                                    header->value.len - avail);
    }

    if (h2c->hpack.allocated == h2c->hpack.added - h2c->hpack.deleted) {

        entries = njt_palloc(h2c->connection->pool,
                             sizeof(njt_http_v2_header_t *)
                             * (h2c->hpack.allocated + 64));
        if (entries == NULL) {
            return NJT_ERROR;
        }

        index = h2c->hpack.deleted % h2c->hpack.allocated;

        njt_memcpy(entries, &h2c->hpack.entries[index],
                   (h2c->hpack.allocated - index)
                   * sizeof(njt_http_v2_header_t *));

        njt_memcpy(&entries[h2c->hpack.allocated - index], h2c->hpack.entries,
                   index * sizeof(njt_http_v2_header_t *));

        (void) njt_pfree(h2c->connection->pool, h2c->hpack.entries);

        h2c->hpack.entries = entries;

        h2c->hpack.added = h2c->hpack.allocated;
        h2c->hpack.deleted = 0;
        h2c->hpack.reused = 0;
        h2c->hpack.allocated += 64;
    }

    h2c->hpack.entries[h2c->hpack.added++ % h2c->hpack.allocated] = entry;

    return NJT_OK;
}


static njt_int_t
njt_http_v2_table_account(njt_http_v2_connection_t *h2c, size_t size)
{
    njt_http_v2_header_t  *entry;

    size += 32;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 table account: %uz free:%uz",
                   size, h2c->hpack.free);

    if (size <= h2c->hpack.free) {
        h2c->hpack.free -= size;
        return NJT_OK;
    }

    if (size > h2c->hpack.size) {
        h2c->hpack.deleted = h2c->hpack.added;
        h2c->hpack.free = h2c->hpack.size;
        return NJT_DECLINED;
    }

    do {
        entry = h2c->hpack.entries[h2c->hpack.deleted++ % h2c->hpack.allocated];
        h2c->hpack.free += 32 + entry->name.len + entry->value.len;
    } while (size > h2c->hpack.free);

    h2c->hpack.free -= size;

    return NJT_OK;
}


njt_int_t
njt_http_v2_table_size(njt_http_v2_connection_t *h2c, size_t size)
{
    ssize_t                needed;
    njt_http_v2_header_t  *entry;

    if (size > NJT_HTTP_V2_TABLE_SIZE) {
        njt_log_error(NJT_LOG_INFO, h2c->connection->log, 0,
                      "client sent invalid table size update: %uz", size);

        return NJT_ERROR;
    }

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 new hpack table size: %uz was:%uz",
                   size, h2c->hpack.size);

    needed = h2c->hpack.size - size;

    while (needed > (ssize_t) h2c->hpack.free) {
        entry = h2c->hpack.entries[h2c->hpack.deleted++ % h2c->hpack.allocated];
        h2c->hpack.free += 32 + entry->name.len + entry->value.len;
    }

    h2c->hpack.size = size;
    h2c->hpack.free -= needed;

    return NJT_OK;
}
