
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 * Copyright (C), 2021-2023, TMLake(Beijing) Technology Co., Ltd.
 */

#include <ctype.h>

#include <njt_config.h>
#include <njt_core.h>

#include "njt_http_vhost_traffic_status_string.h"


#if !defined(njet_version) || njet_version < 1007009

/* from src/core/njt_string.c in v1.7.9 */
uintptr_t
njt_http_vhost_traffic_status_escape_json(u_char *dst, u_char *src, size_t size)
{
    u_char      ch;
    njt_uint_t  len;

    if (dst == NULL) {
        len = 0;

        while (size) {
            ch = *src++;

            if (ch == '\\' || ch == '"') {
                len++;

            } else if (ch <= 0x1f) {
                len += sizeof("\\u001F") - 2;
            }

            size--;
        }

        return (uintptr_t) len;
    }

    while (size) {
        ch = *src++;

        if (ch > 0x1f) {

            if (ch == '\\' || ch == '"') {
                *dst++ = '\\';
            }

            *dst++ = ch;

        } else {
            *dst++ = '\\'; *dst++ = 'u'; *dst++ = '0'; *dst++ = '0';
            *dst++ = '0' + (ch >> 4);

            ch &= 0xf;

            *dst++ = (ch < 10) ? ('0' + ch) : ('A' + ch - 10);
        }

        size--;
    }

    return (uintptr_t) dst;
}

#endif


njt_int_t
njt_http_vhost_traffic_status_escape_json_pool(njt_pool_t *pool,
    njt_str_t *buf, njt_str_t *dst)
{
    u_char  *p;

    buf->len = dst->len * 6;
    buf->data = njt_pcalloc(pool, buf->len);
    if (buf->data == NULL) {
        *buf = *dst;
        return NJT_ERROR;
    }

    p = buf->data;

#if !defined(njet_version) || njet_version < 1007009
    p = (u_char *) njt_http_vhost_traffic_status_escape_json(p, dst->data, dst->len);
#else
    p = (u_char *) njt_escape_json(p, dst->data, dst->len);
#endif

    buf->len = njt_strlen(buf->data);

    return NJT_OK;
}


njt_int_t
njt_http_vhost_traffic_status_copy_str(njt_pool_t *pool,
    njt_str_t *buf, njt_str_t *dst)
{
    u_char  *p;

    buf->len = dst->len;
    buf->data = njt_pcalloc(pool, dst->len + 1); /* 1 byte for terminating '\0' */
    if (buf->data == NULL) {
        return NJT_ERROR;
    }

    p = buf->data;

    njt_memcpy(p, dst->data, dst->len);

    return NJT_OK;
}


njt_int_t
njt_http_vhost_traffic_status_replace_chrc(njt_str_t *buf,
    u_char in, u_char to)
{
    size_t   len;
    u_char  *p;

    p = buf->data;

    len = buf->len;

    while(len--) {
        if (*p == in) {
            *p = to;
        }
        p++;
    }

    return NJT_OK;
}


njt_int_t
njt_http_vhost_traffic_status_replace_strc(njt_str_t *buf,
    njt_str_t *dst, u_char c)
{
    size_t   n, len;
    u_char  *p, *o;
    p = o = buf->data;
    n = 0;

    /* we need the buf's last '\0' for njt_strstrn() */
    if (*(buf->data + buf->len) != 0) {
        return NJT_ERROR;
    }

    while ((p = njt_strstrn(p, (char *) dst->data, dst->len - 1)) != NULL) {
        n++;
        len = buf->len - (p - o) - (n * dst->len) + n - 1;
        *p++ = c;
        njt_memmove(p, p + dst->len - 1, len);
    }

    if (n > 0) {
        buf->len = buf->len - (n * dst->len) + n;
    }

    return NJT_OK;
}


njt_int_t
njt_http_vhost_traffic_status_escape_prometheus(njt_pool_t *pool, njt_str_t *buf, u_char *p, size_t n)
{
    u_char  c, *pa, *pb, *last, *char_end;
    size_t  size;
    u_char  HEX_MAP[] = "0123456789ABCDEF";

    last = p + n;
    pa = p;
    size = 0;

    /* Find the first character that needs to be escaped */
    while (pa < last) {
        if (isascii(*pa)) {
            if (*pa == '"' || *pa == '\\' || *pa == '\n') {
                break;
            } else {
                pa++;
            }
        } else {
            char_end = pa;
            if (njt_utf8_decode(&char_end, last - pa) > 0x10ffff) {
                break;
            } else {
                pa = char_end;
            }
        }
    }

    if (pa == last) {
        // no escapes required - return the original string
        buf->data = p;
        buf->len = n;
        return NJT_OK;
    }

    size = pa - p;

    /* Allocate enough space for the unescaped prefix and worst case for remainder */
    buf->data = njt_pcalloc(pool, size + (n - size) * 5);
    if (buf->data == NULL) {
        /*
            Return the unescaped string up to the first special character 
            in case the caller does not handle the error.
        */
        buf->data = p;
        buf->len = size;
        return NJT_ERROR;
    }

    /* Copy `size` unescaped characters to start of destination. */
    pb = njt_copy(buf->data, p, size);

    /* Individually copy remaining characters to destination, escaping as necessary */
    while (pa < last) {
        if (isascii(*pa)) {
            if (*pa == '"' || *pa == '\\') {
                *pb++ = '\\';
                *pb++ = *pa++;
                size += 2;
            } else if (*pa == '\n') {
                *pb++ = '\\';
                *pb++ = 'n';
                pa++;
                size += 2;
            } else {
                *pb++ = *pa++;
                size++;
            }
        } else {
            char_end = pa;
            if (njt_utf8_decode(&char_end, last - pa) > 0x10ffff) {
                /* invalid UTF-8 - escape single char to allow resynchronization */
                c = *pa++;
                /* two slashes are required to be valid encoding for prometheus*/
                *pb++ = '\\';
                *pb++ = '\\';
                *pb++ = 'x';
                *pb++ = HEX_MAP[c >> 4];
                *pb++ = HEX_MAP[c & 0x0f];
                size += 5;
            } else {
                while (pa < char_end) {
                    *pb++ = *pa++;
                    size++;
                }
            }
        }
    }

    buf->len = size;
    return NJT_OK;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
