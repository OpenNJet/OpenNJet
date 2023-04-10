
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include <njet.h>
#include "njt_http_lua_headers_out.h"
#include "njt_http_lua_util.h"
#include <ctype.h>


static njt_int_t njt_http_set_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value);
static njt_int_t njt_http_set_header_helper(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value,
    njt_table_elt_t **output_header, unsigned no_create);
static njt_int_t njt_http_set_builtin_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value);
static njt_int_t njt_http_set_builtin_multi_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value);
static njt_int_t njt_http_set_last_modified_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value);
static njt_int_t njt_http_set_content_length_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value);
static njt_int_t njt_http_set_content_type_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value);
static njt_int_t njt_http_clear_builtin_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value);
static njt_int_t njt_http_clear_last_modified_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value);
static njt_int_t njt_http_clear_content_length_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value);
static njt_int_t njt_http_set_location_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value);


static njt_http_lua_set_header_t  njt_http_lua_set_handlers[] = {

    { njt_string("Server"),
                 offsetof(njt_http_headers_out_t, server),
                 njt_http_set_builtin_header },

    { njt_string("Date"),
                 offsetof(njt_http_headers_out_t, date),
                 njt_http_set_builtin_header },

#if 1
    { njt_string("Content-Encoding"),
                 offsetof(njt_http_headers_out_t, content_encoding),
                 njt_http_set_builtin_header },
#endif

    { njt_string("Location"),
                 offsetof(njt_http_headers_out_t, location),
                 njt_http_set_location_header },

    { njt_string("Refresh"),
                 offsetof(njt_http_headers_out_t, refresh),
                 njt_http_set_builtin_header },

    { njt_string("Last-Modified"),
                 offsetof(njt_http_headers_out_t, last_modified),
                 njt_http_set_last_modified_header },

    { njt_string("Content-Range"),
                 offsetof(njt_http_headers_out_t, content_range),
                 njt_http_set_builtin_header },

    { njt_string("Accept-Ranges"),
                 offsetof(njt_http_headers_out_t, accept_ranges),
                 njt_http_set_builtin_header },

    { njt_string("WWW-Authenticate"),
                 offsetof(njt_http_headers_out_t, www_authenticate),
                 njt_http_set_builtin_header },

    { njt_string("Expires"),
                 offsetof(njt_http_headers_out_t, expires),
                 njt_http_set_builtin_header },

    { njt_string("E-Tag"),
                 offsetof(njt_http_headers_out_t, etag),
                 njt_http_set_builtin_header },

    { njt_string("ETag"),
                 offsetof(njt_http_headers_out_t, etag),
                 njt_http_set_builtin_header },

    { njt_string("Content-Length"),
                 offsetof(njt_http_headers_out_t, content_length),
                 njt_http_set_content_length_header },

    { njt_string("Content-Type"),
                 offsetof(njt_http_headers_out_t, content_type),
                 njt_http_set_content_type_header },

    { njt_string("Cache-Control"),
                 offsetof(njt_http_headers_out_t, cache_control),
                 njt_http_set_builtin_multi_header },

#if (njet_version >= 1013009)
    { njt_string("Link"),
                 offsetof(njt_http_headers_out_t, link),
                 njt_http_set_builtin_multi_header },
#endif

    { njt_null_string, 0, njt_http_set_header }
};


/* request time implementation */

static njt_int_t
njt_http_set_header(njt_http_request_t *r, njt_http_lua_header_val_t *hv,
    njt_str_t *value)
{
    return njt_http_set_header_helper(r, hv, value, NULL, 0);
}


static njt_int_t
njt_http_set_header_helper(njt_http_request_t *r, njt_http_lua_header_val_t *hv,
    njt_str_t *value, njt_table_elt_t **output_header,
    unsigned no_create)
{
    njt_table_elt_t             *h;
    njt_list_part_t             *part;
    njt_uint_t                   i;
    unsigned                     matched = 0;

    if (hv->no_override) {
        goto new_header;
    }

#if 1
    if (r->headers_out.location
        && r->headers_out.location->value.len
        && r->headers_out.location->value.data[0] == '/')
    {
        /* XXX njt_http_core_find_config_phase, for example,
         * may not initialize the "key" and "hash" fields
         * for a nasty optimization purpose, and
         * we have to work-around it here */

        r->headers_out.location->hash = njt_http_lua_location_hash;
        njt_str_set(&r->headers_out.location->key, "Location");
    }
#endif

    part = &r->headers_out.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].hash != 0
            && h[i].key.len == hv->key.len
            && njt_strncasecmp(hv->key.data, h[i].key.data, h[i].key.len) == 0)
        {
            dd("found out header %.*s", (int) h[i].key.len, h[i].key.data);

            if (value->len == 0 || matched) {
                dd("clearing normal header for %.*s", (int) hv->key.len,
                   hv->key.data);

                h[i].value.len = 0;
                h[i].hash = 0;

            } else {
                dd("setting header to value %.*s", (int) value->len,
                   value->data);

                h[i].value = *value;
                h[i].hash = hv->hash;
            }

            if (output_header) {
                *output_header = &h[i];
            }

            /* return NJT_OK; */
            matched = 1;
        }
    }

    if (matched){
        return NJT_OK;
    }

    if (no_create && value->len == 0) {
        return NJT_OK;
    }

new_header:

    /* XXX we still need to create header slot even if the value
     * is empty because some builtin headers like Last-Modified
     * relies on this to get cleared */

    h = njt_list_push(&r->headers_out.headers);

    if (h == NULL) {
        return NJT_ERROR;
    }

    if (value->len == 0) {
        h->hash = 0;

    } else {
        h->hash = hv->hash;
    }

    h->key = hv->key;
    h->value = *value;

    h->lowcase_key = njt_pnalloc(r->pool, h->key.len);
    if (h->lowcase_key == NULL) {
        return NJT_ERROR;
    }

    njt_strlow(h->lowcase_key, h->key.data, h->key.len);

    if (output_header) {
        *output_header = h;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_set_location_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value)
{
    njt_int_t         rc;
    njt_table_elt_t  *h;

    rc = njt_http_set_builtin_header(r, hv, value);
    if (rc != NJT_OK) {
        return rc;
    }

    /*
     * we do not set r->headers_out.location here to avoid the handling
     * the local redirects without a host name by njt_http_header_filter()
     */

    h = r->headers_out.location;
    if (h && h->value.len && h->value.data[0] == '/') {
        r->headers_out.location = NULL;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_set_builtin_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value)
{
    njt_table_elt_t  *h, **old;

    if (hv->offset) {
        old = (njt_table_elt_t **) ((char *) &r->headers_out + hv->offset);

    } else {
        old = NULL;
    }

    if (old == NULL || *old == NULL) {
        return njt_http_set_header_helper(r, hv, value, old, 0);
    }

    h = *old;

    if (value->len == 0) {
        dd("clearing the builtin header");

        h->hash = 0;
        h->value = *value;

        return NJT_OK;
    }

    h->hash = hv->hash;
    h->key = hv->key;
    h->value = *value;

    return NJT_OK;
}


static njt_int_t
njt_http_set_builtin_multi_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value)
{
    njt_array_t      *pa;
    njt_table_elt_t  *ho, **ph;
    njt_uint_t        i;

    pa = (njt_array_t *) ((char *) &r->headers_out + hv->offset);

    if (pa->elts == NULL) {
        if (njt_array_init(pa, r->pool, 2, sizeof(njt_table_elt_t *))
            != NJT_OK)
        {
            return NJT_ERROR;
        }
    }

    if (hv->no_override) {
        ph = pa->elts;
        for (i = 0; i < pa->nelts; i++) {
            if (!ph[i]->hash) {
                ph[i]->value = *value;
                ph[i]->hash = hv->hash;
                return NJT_OK;
            }
        }

        goto create;
    }

    /* override old values (if any) */

    if (pa->nelts > 0) {
        ph = pa->elts;
        for (i = 1; i < pa->nelts; i++) {
            ph[i]->hash = 0;
            ph[i]->value.len = 0;
        }

        ph[0]->value = *value;

        if (value->len == 0) {
            ph[0]->hash = 0;

        } else {
            ph[0]->hash = hv->hash;
        }

        return NJT_OK;
    }

create:

    ph = njt_array_push(pa);
    if (ph == NULL) {
        return NJT_ERROR;
    }

    ho = njt_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NJT_ERROR;
    }

    ho->value = *value;

    if (value->len == 0) {
        ho->hash = 0;

    } else {
        ho->hash = hv->hash;
    }

    ho->key = hv->key;
    *ph = ho;

    return NJT_OK;
}


static njt_int_t
njt_http_set_content_type_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value)
{
    njt_uint_t          i;

    r->headers_out.content_type_len = value->len;

#if 1
    for (i = 0; i < value->len; i++) {
        if (value->data[i] == ';') {
            r->headers_out.content_type_len = i;
            break;
        }
    }
#endif

    r->headers_out.content_type = *value;
    r->headers_out.content_type_hash = hv->hash;
    r->headers_out.content_type_lowcase = NULL;

    value->len = 0;

    return njt_http_set_header_helper(r, hv, value, NULL, 1);
}


static njt_int_t njt_http_set_last_modified_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value)
{
    if (value->len == 0) {
        return njt_http_clear_last_modified_header(r, hv, value);
    }

    r->headers_out.last_modified_time = njt_http_parse_time(value->data,
                                                            value->len);

    dd("last modified time: %d", (int) r->headers_out.last_modified_time);

    return njt_http_set_builtin_header(r, hv, value);
}


static njt_int_t
njt_http_clear_last_modified_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value)
{
    r->headers_out.last_modified_time = -1;

    return njt_http_clear_builtin_header(r, hv, value);
}


static njt_int_t
njt_http_set_content_length_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value)
{
    off_t           len;

    if (value->len == 0) {
        return njt_http_clear_content_length_header(r, hv, value);
    }

    len = njt_atoof(value->data, value->len);
    if (len == NJT_ERROR) {
        return NJT_ERROR;
    }

    r->headers_out.content_length_n = len;

    return njt_http_set_builtin_header(r, hv, value);
}


static njt_int_t
njt_http_clear_content_length_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value)
{
    r->headers_out.content_length_n = -1;

    return njt_http_clear_builtin_header(r, hv, value);
}


static njt_int_t
njt_http_clear_builtin_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value)
{
    value->len = 0;

    return njt_http_set_builtin_header(r, hv, value);
}


njt_int_t
njt_http_lua_set_output_header(njt_http_request_t *r, njt_http_lua_ctx_t *ctx,
    njt_str_t key, njt_str_t value, unsigned override)
{
    njt_http_lua_header_val_t         hv;
    njt_http_lua_set_header_t        *handlers = njt_http_lua_set_handlers;
    njt_uint_t                        i;

    dd("set header value: %.*s", (int) value.len, value.data);

    if (njt_http_lua_copy_escaped_header(r, &key, 1) != NJT_OK) {
        return NJT_ERROR;
    }

    if (njt_http_lua_copy_escaped_header(r, &value, 0) != NJT_OK) {
        return NJT_ERROR;
    }

    hv.hash = njt_hash_key_lc(key.data, key.len);
    hv.key = key;

    hv.offset = 0;
    hv.no_override = !override;
    hv.handler = NULL;

    for (i = 0; handlers[i].name.len; i++) {
        if (hv.key.len != handlers[i].name.len
            || njt_strncasecmp(hv.key.data, handlers[i].name.data,
                               handlers[i].name.len) != 0)
        {
            dd("hv key comparison: %s <> %s", handlers[i].name.data,
               hv.key.data);

            continue;
        }

        dd("Matched handler: %s %s", handlers[i].name.data, hv.key.data);

        hv.offset = handlers[i].offset;
        hv.handler = handlers[i].handler;

        if (hv.handler == njt_http_set_content_type_header) {
            ctx->mime_set = 1;
        }

        break;
    }

    if (handlers[i].name.len == 0 && handlers[i].handler) {
        hv.offset = handlers[i].offset;
        hv.handler = handlers[i].handler;
    }

#if 1
    if (hv.handler == NULL) {
        return NJT_ERROR;
    }
#endif

    return hv.handler(r, &hv, &value);
}


int
njt_http_lua_get_output_header(lua_State *L, njt_http_request_t *r,
    njt_http_lua_ctx_t *ctx, njt_str_t *key)
{
    njt_table_elt_t            *h;
    njt_list_part_t            *part;
    njt_uint_t                  i;
    unsigned                    found;

    dd("looking for response header \"%.*s\"", (int) key->len, key->data);

    switch (key->len) {
    case 14:
        if (r->headers_out.content_length == NULL
            && r->headers_out.content_length_n >= 0
            && njt_strncasecmp(key->data, (u_char *) "Content-Length", 14) == 0)
        {
            lua_pushinteger(L, (lua_Integer) r->headers_out.content_length_n);
            return 1;
        }

        break;

    case 12:
        if (njt_strncasecmp(key->data, (u_char *) "Content-Type", 12) == 0
            && r->headers_out.content_type.len)
        {
            lua_pushlstring(L, (char *) r->headers_out.content_type.data,
                            r->headers_out.content_type.len);
            return 1;
        }

        break;

    default:
        break;
    }

    dd("not a built-in output header");

    found = 0;

#if 1
    if (r->headers_out.location
        && r->headers_out.location->value.len
        && r->headers_out.location->value.data[0] == '/')
    {
        /* XXX njt_http_core_find_config_phase, for example,
         * may not initialize the "key" and "hash" fields
         * for a nasty optimization purpose, and
         * we have to work-around it here */

        r->headers_out.location->hash = njt_http_lua_location_hash;
        njt_str_set(&r->headers_out.location->key, "Location");
    }
#endif

    part = &r->headers_out.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].hash == 0) {
            continue;
        }

        if (h[i].hash != 0
            && h[i].key.len == key->len
            && njt_strncasecmp(key->data, h[i].key.data, h[i].key.len) == 0)
         {
             if (!found) {
                 found = 1;

                 lua_pushlstring(L, (char *) h[i].value.data, h[i].value.len);
                 continue;
             }

             if (found == 1) {
                 lua_createtable(L, 4 /* narr */, 0);
                 lua_insert(L, -2);
                 lua_rawseti(L, -2, found);
             }

             found++;

             lua_pushlstring(L, (char *) h[i].value.data, h[i].value.len);
             lua_rawseti(L, -2, found);
         }
    }

    if (found) {
        return 1;
    }

    lua_pushnil(L);
    return 1;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
