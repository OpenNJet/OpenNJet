
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include <njet.h>
#include "njt_http_lua_headers_in.h"
#include "njt_http_lua_util.h"
#include <ctype.h>


static njt_int_t njt_http_set_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value);
static njt_int_t njt_http_set_header_helper(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value,
    njt_table_elt_t **output_header);
static njt_int_t njt_http_set_builtin_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value);
static njt_int_t njt_http_set_user_agent_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value);
static njt_int_t njt_http_set_connection_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value);
static njt_int_t njt_http_set_content_length_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value);
static njt_int_t njt_http_set_builtin_multi_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value);
static njt_int_t njt_http_clear_builtin_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value);
static njt_int_t njt_http_clear_content_length_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value);
static njt_int_t njt_http_lua_validate_host(njt_str_t *host, njt_pool_t *pool,
    njt_uint_t alloc);
static njt_int_t njt_http_set_host_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value);
static njt_int_t njt_http_lua_rm_header_helper(njt_list_t *l,
    njt_list_part_t *cur, njt_uint_t i);


static njt_http_lua_set_header_t  njt_http_lua_set_handlers[] = {
    { njt_string("Host"),
                 offsetof(njt_http_headers_in_t, host),
                 njt_http_set_host_header },

    { njt_string("Connection"),
                 offsetof(njt_http_headers_in_t, connection),
                 njt_http_set_connection_header },

    { njt_string("If-Modified-Since"),
                 offsetof(njt_http_headers_in_t, if_modified_since),
                 njt_http_set_builtin_header },

    { njt_string("If-Unmodified-Since"),
                 offsetof(njt_http_headers_in_t, if_unmodified_since),
                 njt_http_set_builtin_header },

    { njt_string("If-Match"),
                 offsetof(njt_http_headers_in_t, if_match),
                 njt_http_set_builtin_header },

    { njt_string("If-None-Match"),
                 offsetof(njt_http_headers_in_t, if_none_match),
                 njt_http_set_builtin_header },

    { njt_string("User-Agent"),
                 offsetof(njt_http_headers_in_t, user_agent),
                 njt_http_set_user_agent_header },

    { njt_string("Referer"),
                 offsetof(njt_http_headers_in_t, referer),
                 njt_http_set_builtin_header },

    { njt_string("Content-Length"),
                 offsetof(njt_http_headers_in_t, content_length),
                 njt_http_set_content_length_header },

    { njt_string("Content-Type"),
                 offsetof(njt_http_headers_in_t, content_type),
                 njt_http_set_builtin_header },

    { njt_string("Range"),
                 offsetof(njt_http_headers_in_t, range),
                 njt_http_set_builtin_header },

    { njt_string("If-Range"),
                 offsetof(njt_http_headers_in_t, if_range),
                 njt_http_set_builtin_header },

    { njt_string("Transfer-Encoding"),
                 offsetof(njt_http_headers_in_t, transfer_encoding),
                 njt_http_set_builtin_header },

    { njt_string("Expect"),
                 offsetof(njt_http_headers_in_t, expect),
                 njt_http_set_builtin_header },

    { njt_string("Upgrade"),
                 offsetof(njt_http_headers_in_t, upgrade),
                 njt_http_set_builtin_header },

#if (NJT_HTTP_GZIP)
    { njt_string("Accept-Encoding"),
                 offsetof(njt_http_headers_in_t, accept_encoding),
                 njt_http_set_builtin_header },

    { njt_string("Via"),
                 offsetof(njt_http_headers_in_t, via),
                 njt_http_set_builtin_header },
#endif

    { njt_string("Authorization"),
                 offsetof(njt_http_headers_in_t, authorization),
                 njt_http_set_builtin_header },

    { njt_string("Keep-Alive"),
                 offsetof(njt_http_headers_in_t, keep_alive),
                 njt_http_set_builtin_header },

#if (NJT_HTTP_X_FORWARDED_FOR)
    { njt_string("X-Forwarded-For"),
                 offsetof(njt_http_headers_in_t, x_forwarded_for),
                 njt_http_set_builtin_multi_header },

#endif

#if (NJT_HTTP_REALIP)
    { njt_string("X-Real-IP"),
                 offsetof(njt_http_headers_in_t, x_real_ip),
                 njt_http_set_builtin_header },
#endif

#if (NJT_HTTP_DAV)
    { njt_string("Depth"),
                 offsetof(njt_http_headers_in_t, depth),
                 njt_http_set_builtin_header },

    { njt_string("Destination"),
                 offsetof(njt_http_headers_in_t, destination),
                 njt_http_set_builtin_header },

    { njt_string("Overwrite"),
                 offsetof(njt_http_headers_in_t, overwrite),
                 njt_http_set_builtin_header },

    { njt_string("Date"), offsetof(njt_http_headers_in_t, date),
                 njt_http_set_builtin_header },
#endif

#if defined(njet_version) && njet_version >= 1023000
    { njt_string("Cookie"),
                 offsetof(njt_http_headers_in_t, cookie),
                 njt_http_set_builtin_multi_header },
#else
    { njt_string("Cookie"),
                 offsetof(njt_http_headers_in_t, cookies),
                 njt_http_set_builtin_multi_header },
#endif

    { njt_null_string, 0, njt_http_set_header }
};


/* request time implementation */

static njt_int_t
njt_http_set_header(njt_http_request_t *r, njt_http_lua_header_val_t *hv,
    njt_str_t *value)
{
    return njt_http_set_header_helper(r, hv, value, NULL);
}


static njt_int_t
njt_http_set_header_helper(njt_http_request_t *r, njt_http_lua_header_val_t *hv,
    njt_str_t *value, njt_table_elt_t **output_header)
{
    njt_table_elt_t             *h, *matched;
    njt_list_part_t             *part;
    njt_uint_t                   i;
    njt_uint_t                   rc;

    if (hv->no_override) {
        goto new_header;
    }

    matched = NULL;

retry:

    part = &r->headers_in.headers.part;
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

        dd("i: %d, part: %p", (int) i, part);

        if (h[i].key.len == hv->key.len
            && njt_strncasecmp(h[i].key.data, hv->key.data, h[i].key.len)
               == 0)
        {
            if (value->len == 0 || (matched && matched != &h[i])) {
                h[i].hash = 0;

                dd("rm header %.*s: %.*s", (int) h[i].key.len, h[i].key.data,
                   (int) h[i].value.len, h[i].value.data);

                rc = njt_http_lua_rm_header_helper(&r->headers_in.headers,
                                                   part, i);

                njt_http_lua_assert(!(r->headers_in.headers.part.next == NULL
                                      && r->headers_in.headers.last
                                         != &r->headers_in.headers.part));

                dd("rm header: rc=%d", (int) rc);

                if (rc == NJT_OK) {

                    if (output_header) {
                        *output_header = NULL;
                    }

                    goto retry;
                }

                return NJT_ERROR;
            }

            h[i].value = *value;

            if (output_header) {
                *output_header = &h[i];
                dd("setting existing builtin input header");
            }

            if (matched == NULL) {
                matched = &h[i];
            }
        }
    }

    if (matched){
        return NJT_OK;
    }

    if (value->len == 0) {
        return NJT_OK;
    }

new_header:

    h = njt_list_push(&r->headers_in.headers);

    if (h == NULL) {
        return NJT_ERROR;
    }

    dd("created new header for %.*s", (int) hv->key.len, hv->key.data);

    if (value->len == 0) {
        h->hash = 0;

    } else {
        h->hash = hv->hash;
    }

    h->key = hv->key;
    h->value = *value;
#if defined(njet_version) && njet_version >= 1023000
    h->next = NULL;
#endif

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
njt_http_set_builtin_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value)
{
    njt_table_elt_t             *h, **old;

    dd("entered set_builtin_header (input)");

    if (hv->offset) {
        old = (njt_table_elt_t **) ((char *) &r->headers_in + hv->offset);

    } else {
        old = NULL;
    }

    dd("old builtin ptr ptr: %p", old);
    if (old) {
        dd("old builtin ptr: %p", *old);
    }

    if (old == NULL || *old == NULL) {
        dd("set normal header");
        return njt_http_set_header_helper(r, hv, value, old);
    }

    h = *old;

    if (value->len == 0) {
        h->hash = 0;
        h->value = *value;

        return njt_http_set_header_helper(r, hv, value, old);
    }

    h->hash = hv->hash;
    h->value = *value;

    return NJT_OK;
}


static njt_int_t
njt_http_lua_validate_host(njt_str_t *host, njt_pool_t *pool, njt_uint_t alloc)
{
    u_char  *h, ch;
    size_t   i, dot_pos, host_len;

    enum {
        sw_usual = 0,
        sw_literal,
        sw_rest,
    } state;

    dot_pos = host->len;
    host_len = host->len;

    h = host->data;

    state = sw_usual;

    for (i = 0; i < host->len; i++) {
        ch = h[i];

        switch (ch) {

        case '.':
            if (dot_pos == i - 1) {
                return NJT_DECLINED;
            }

            dot_pos = i;
            break;

        case ':':
            if (state == sw_usual) {
                host_len = i;
                state = sw_rest;
            }
            break;

        case '[':
            if (i == 0) {
                state = sw_literal;
            }
            break;

        case ']':
            if (state == sw_literal) {
                host_len = i + 1;
                state = sw_rest;
            }
            break;

        case '\0':
            return NJT_DECLINED;

        default:

            if (njt_path_separator(ch)) {
                return NJT_DECLINED;
            }

            if (ch >= 'A' && ch <= 'Z') {
                alloc = 1;
            }

            break;
        }
    }

    if (dot_pos == host_len - 1) {
        host_len--;
    }

    if (host_len == 0) {
        return NJT_DECLINED;
    }

    if (alloc) {
        host->data = njt_pnalloc(pool, host_len);
        if (host->data == NULL) {
            return NJT_ERROR;
        }

        njt_strlow(host->data, h, host_len);
    }

    host->len = host_len;

    return NJT_OK;
}


static njt_int_t
njt_http_set_host_header(njt_http_request_t *r, njt_http_lua_header_val_t *hv,
    njt_str_t *value)
{
    njt_str_t                    host;
    njt_http_lua_main_conf_t    *lmcf;
    njt_http_variable_value_t   *var;

    dd("server new value len: %d", (int) value->len);

    lmcf = njt_http_get_module_main_conf(r, njt_http_lua_module);

    if (value->len) {
        host= *value;

        if (njt_http_lua_validate_host(&host, r->pool, 0) != NJT_OK) {
            return NJT_ERROR;
        }

        r->headers_in.server = host;

    } else {
        r->headers_in.server = *value;
    }

    var = &r->variables[lmcf->host_var_index];
    var->valid = 0;
    var->not_found = 0;

    return njt_http_set_builtin_header(r, hv, value);
}


static njt_int_t
njt_http_set_connection_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value)
{
    r->headers_in.connection_type = 0;

    if (value->len == 0) {
        return njt_http_set_builtin_header(r, hv, value);
    }

    if (njt_strcasestrn(value->data, "close", 5 - 1)) {
        r->headers_in.connection_type = NJT_HTTP_CONNECTION_CLOSE;
        r->headers_in.keep_alive_n = -1;

    } else if (njt_strcasestrn(value->data, "keep-alive", 10 - 1)) {
        r->headers_in.connection_type = NJT_HTTP_CONNECTION_KEEP_ALIVE;
    }

    return njt_http_set_builtin_header(r, hv, value);
}


/* borrowed the code from njt_http_request.c:njt_http_process_user_agent */
static njt_int_t
njt_http_set_user_agent_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value)
{
    u_char  *user_agent, *msie;

    /* clear existing settings */

    r->headers_in.msie = 0;
    r->headers_in.msie6 = 0;
    r->headers_in.opera = 0;
    r->headers_in.gecko = 0;
    r->headers_in.chrome = 0;
    r->headers_in.safari = 0;
    r->headers_in.konqueror = 0;

    if (value->len == 0) {
        return njt_http_set_builtin_header(r, hv, value);
    }

    /* check some widespread browsers */

    user_agent = value->data;

    msie = njt_strstrn(user_agent, "MSIE ", 5 - 1);

    if (msie && msie + 7 < user_agent + value->len) {

        r->headers_in.msie = 1;

        if (msie[6] == '.') {

            switch (msie[5]) {
            case '4':
            case '5':
                r->headers_in.msie6 = 1;
                break;
            case '6':
                if (njt_strstrn(msie + 8, "SV1", 3 - 1) == NULL) {
                    r->headers_in.msie6 = 1;
                }
                break;
            }
        }
    }

    if (njt_strstrn(user_agent, "Opera", 5 - 1)) {
        r->headers_in.opera = 1;
        r->headers_in.msie = 0;
        r->headers_in.msie6 = 0;
    }

    if (!r->headers_in.msie && !r->headers_in.opera) {

        if (njt_strstrn(user_agent, "Gecko/", 6 - 1)) {
            r->headers_in.gecko = 1;

        } else if (njt_strstrn(user_agent, "Chrome/", 7 - 1)) {
            r->headers_in.chrome = 1;

        } else if (njt_strstrn(user_agent, "Safari/", 7 - 1)
                   && njt_strstrn(user_agent, "Mac OS X", 8 - 1))
        {
            r->headers_in.safari = 1;

        } else if (njt_strstrn(user_agent, "Konqueror", 9 - 1)) {
            r->headers_in.konqueror = 1;
        }
    }

    return njt_http_set_builtin_header(r, hv, value);
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

    dd("reset headers_in.content_length_n to %d", (int) len);

    r->headers_in.content_length_n = len;

    return njt_http_set_builtin_header(r, hv, value);
}


static njt_int_t
njt_http_set_builtin_multi_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value)
{
#if defined(njet_version) && njet_version >= 1023000
    njt_table_elt_t  **headers, **ph, *h;

    headers = (njt_table_elt_t **) ((char *) &r->headers_in + hv->offset);

    if (!hv->no_override && *headers != NULL) {
#if defined(DDEBUG) && (DDEBUG)
        int  nelts = 0;

        for (h = *headers; h; h = h->next) {
            nelts++;
        }

        dd("clear multi-value headers: %d", nelts);
#endif

        *headers = NULL;
    }

    if (njt_http_set_header_helper(r, hv, value, &h) == NJT_ERROR) {
        return NJT_ERROR;
    }

    if (value->len == 0) {
        return NJT_OK;
    }

    dd("new multi-value header: %p", h);

    if (*headers) {
        for (ph = headers; *ph; ph = &(*ph)->next) { /* void */ }
        *ph = h;

    } else {
        *headers = h;
    }

    h->next = NULL;

    return NJT_OK;
#else
    njt_array_t       *headers;
    njt_table_elt_t  **v, *h;

    headers = (njt_array_t *) ((char *) &r->headers_in + hv->offset);

    if (!hv->no_override && headers->nelts > 0) {
        njt_array_destroy(headers);

        if (njt_array_init(headers, r->pool, 2,
                           sizeof(njt_table_elt_t *))
            != NJT_OK)
        {
            return NJT_ERROR;
        }

        dd("clear multi-value headers: %d", (int) headers->nelts);
    }

#if 1
    if (headers->nalloc == 0) {
        if (njt_array_init(headers, r->pool, 2,
                           sizeof(njt_table_elt_t *))
            != NJT_OK)
        {
            return NJT_ERROR;
        }
    }
#endif

    if (njt_http_set_header_helper(r, hv, value, &h) == NJT_ERROR) {
        return NJT_ERROR;
    }

    if (value->len == 0) {
        return NJT_OK;
    }

    dd("new multi-value header: %p", h);

    v = njt_array_push(headers);
    if (v == NULL) {
        return NJT_ERROR;
    }

    *v = h;
    return NJT_OK;
#endif
}


static njt_int_t
njt_http_clear_content_length_header(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value)
{
    r->headers_in.content_length_n = -1;

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
njt_http_lua_set_input_header(njt_http_request_t *r, njt_str_t key,
    njt_str_t value, unsigned override)
{
    njt_http_lua_header_val_t         hv;
    njt_http_lua_set_header_t        *handlers = njt_http_lua_set_handlers;
    njt_int_t                         rc;
    njt_uint_t                        i;

    dd("set header value: %.*s", (int) value.len, value.data);

    rc = njt_http_lua_copy_escaped_header(r, &key, 1);
    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    rc = njt_http_lua_copy_escaped_header(r, &value, 0);
    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    if (value.len > 0) {
        hv.hash = njt_hash_key_lc(key.data, key.len);

    } else {
        hv.hash = 0;
    }

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

    if (r->headers_out.status == 400 || r->headers_in.headers.last == NULL) {
        /* must be a 400 Bad Request */
        return NJT_OK;
    }

    return hv.handler(r, &hv, &value);
}


static njt_int_t
njt_http_lua_rm_header_helper(njt_list_t *l, njt_list_part_t *cur,
    njt_uint_t i)
{
    njt_table_elt_t             *data;
    njt_list_part_t             *new, *part;

    dd("list rm item: part %p, i %d, nalloc %d", cur, (int) i,
       (int) l->nalloc);

    data = cur->elts;

    dd("cur: nelts %d, nalloc %d", (int) cur->nelts,
       (int) l->nalloc);

    dd("removing: \"%.*s:%.*s\"", (int) data[i].key.len, data[i].key.data,
       (int) data[i].value.len, data[i].value.data);

    if (i == 0) {
        dd("first entry in the part");
        cur->elts = (char *) cur->elts + l->size;
        cur->nelts--;

        if (cur == l->last) {
            dd("being the last part");
            if (cur->nelts == 0) {
#if 1
                part = &l->part;
                dd("cur=%p, part=%p, part next=%p, last=%p",
                   cur, part, part->next, l->last);

                if (part == cur) {
                    cur->elts = (char *) cur->elts - l->size;
                    /* do nothing */

                } else {
                    while (part->next != cur) {
                        if (part->next == NULL) {
                            return NJT_ERROR;
                        }

                        part = part->next;
                    }

                    l->last = part;
                    part->next = NULL;
                    dd("part nelts: %d", (int) part->nelts);
                    l->nalloc = part->nelts;
                }
#endif

            } else {
                l->nalloc--;
                dd("nalloc decreased: %d", (int) l->nalloc);
            }

            return NJT_OK;
        }

        if (cur->nelts == 0) {
            dd("current part is empty");
            part = &l->part;
            if (part == cur) {
                njt_http_lua_assert(cur->next != NULL);

                dd("remove 'cur' from the list by rewriting 'cur': "
                   "l->last: %p, cur: %p, cur->next: %p, part: %p",
                   l->last, cur, cur->next, part);

                if (l->last == cur->next) {
                    dd("last is cur->next");
                    l->part = *(cur->next);
                    l->last = part;
                    l->nalloc = part->nelts;

                } else {
                    l->part = *(cur->next);
                }

            } else {
                dd("remove 'cur' from the list");
                while (part->next != cur) {
                    if (part->next == NULL) {
                        return NJT_ERROR;
                    }

                    part = part->next;
                }

                part->next = cur->next;
            }

            return NJT_OK;
        }

        return NJT_OK;
    }

    if (i == cur->nelts - 1) {
        dd("last entry in the part");

        cur->nelts--;

        if (cur == l->last) {
            l->nalloc--;
        }

        return NJT_OK;
    }

    dd("the middle entry in the part");

    new = njt_palloc(l->pool, sizeof(njt_list_part_t));
    if (new == NULL) {
        return NJT_ERROR;
    }

    new->elts = &data[i + 1];
    new->nelts = cur->nelts - i - 1;
    new->next = cur->next;

    cur->nelts = i;
    cur->next = new;

    if (cur == l->last) {
        l->last = new;
        l->nalloc = new->nelts;
    }

    return NJT_OK;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
