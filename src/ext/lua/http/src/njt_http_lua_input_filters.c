
/*
 * Copyright (C) by OpenResty Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_http_lua_common.h"


njt_int_t
njt_http_lua_read_bytes(njt_buf_t *src, njt_chain_t *buf_in, size_t *rest,
    ssize_t bytes, njt_log_t *log)
{
    if (bytes == 0) {
        return NJT_ERROR;
    }

    if ((size_t) bytes >= *rest) {

        buf_in->buf->last += *rest;
        src->pos += *rest;
        *rest = 0;

        return NJT_OK;
    }

    /* bytes < *rest */

    buf_in->buf->last += bytes;
    src->pos += bytes;
    *rest -= bytes;

    return NJT_AGAIN;
}


njt_int_t
njt_http_lua_read_all(njt_buf_t *src, njt_chain_t *buf_in, ssize_t bytes,
    njt_log_t *log)
{
    if (bytes == 0) {
        return NJT_OK;
    }

    buf_in->buf->last += bytes;
    src->pos += bytes;

    return NJT_AGAIN;
}


njt_int_t
njt_http_lua_read_any(njt_buf_t *src, njt_chain_t *buf_in, size_t *max,
    ssize_t bytes, njt_log_t *log)
{
    if (bytes == 0) {
        return NJT_ERROR;
    }

    if (bytes >= (ssize_t) *max) {
        bytes = (ssize_t) *max;
    }

    buf_in->buf->last += bytes;
    src->pos += bytes;

    return NJT_OK;
}


njt_int_t
njt_http_lua_read_line(njt_buf_t *src, njt_chain_t *buf_in, ssize_t bytes,
    njt_log_t *log)
{
    u_char                      *dst;
    u_char                       c;
#if (NJT_DEBUG)
    u_char                      *begin;
#endif

#if (NJT_DEBUG)
    begin = src->pos;
#endif

    if (bytes == 0) {
        return NJT_ERROR;
    }

    dd("already read: %p: %.*s", buf_in,
       (int) (buf_in->buf->last - buf_in->buf->pos), buf_in->buf->pos);

    dd("data read: %.*s", (int) bytes, src->pos);

    dst = buf_in->buf->last;

    while (bytes--) {

        c = *src->pos++;

        switch (c) {
        case '\n':
            njt_log_debug2(NJT_LOG_DEBUG_HTTP, log, 0,
                           "lua read the final line part: \"%*s\"",
                           src->pos - 1 - begin, begin);

            buf_in->buf->last = dst;

            dd("read a line: %p: %.*s", buf_in,
               (int) (buf_in->buf->last - buf_in->buf->pos), buf_in->buf->pos);

            return NJT_OK;

        case '\r':
            /* ignore it */
            break;

        default:
            *dst++ = c;
            break;
        }
    }

#if (NJT_DEBUG)
    njt_log_debug2(NJT_LOG_DEBUG_HTTP, log, 0,
                   "lua read partial line data: %*s", dst - begin, begin);
#endif

    buf_in->buf->last = dst;

    return NJT_AGAIN;
}
