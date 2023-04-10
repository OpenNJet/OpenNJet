
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 * Copyright (C) Valentin V. Bartenev
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


static u_char *njt_http_v2_write_int(u_char *pos, njt_uint_t prefix,
    njt_uint_t value);


u_char *
njt_http_v2_string_encode(u_char *dst, u_char *src, size_t len, u_char *tmp,
    njt_uint_t lower)
{
    size_t  hlen;

    hlen = njt_http_huff_encode(src, len, tmp, lower);

    if (hlen > 0) {
        *dst = NJT_HTTP_V2_ENCODE_HUFF;
        dst = njt_http_v2_write_int(dst, njt_http_v2_prefix(7), hlen);
        return njt_cpymem(dst, tmp, hlen);
    }

    *dst = NJT_HTTP_V2_ENCODE_RAW;
    dst = njt_http_v2_write_int(dst, njt_http_v2_prefix(7), len);

    if (lower) {
        njt_strlow(dst, src, len);
        return dst + len;
    }

    return njt_cpymem(dst, src, len);
}


static u_char *
njt_http_v2_write_int(u_char *pos, njt_uint_t prefix, njt_uint_t value)
{
    if (value < prefix) {
        *pos++ |= value;
        return pos;
    }

    *pos++ |= prefix;
    value -= prefix;

    while (value >= 128) {
        *pos++ = value % 128 + 128;
        value /= 128;
    }

    *pos++ = (u_char) value;

    return pos;
}
