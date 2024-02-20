
/*
 * Copyright (C) YoungJoo Kim (vozlt)
 */


#include <njt_config.h>
#include <njt_core.h>

#include "njt_http_stream_server_traffic_status_string.h"


/* from src/core/njt_string.c in v1.7.9 */
uintptr_t
njt_http_stream_server_traffic_status_escape_json(u_char *dst, u_char *src, size_t size)
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

njt_int_t
njt_http_stream_server_traffic_status_escape_json_pool(njt_pool_t *pool,
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

    p = (u_char *) njt_http_stream_server_traffic_status_escape_json(p, dst->data, dst->len);

    buf->len = njt_strlen(buf->data);

    return NJT_OK;
}


njt_int_t
njt_http_stream_server_traffic_status_copy_str(njt_pool_t *pool,
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
njt_http_stream_server_traffic_status_replace_chrc(njt_str_t *buf,
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
njt_http_stream_server_traffic_status_replace_strc(njt_str_t *buf,
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

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
