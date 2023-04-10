
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_CRC32_H_INCLUDED_
#define _NJT_CRC32_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


extern uint32_t  *njt_crc32_table_short;
extern uint32_t   njt_crc32_table256[];


static njt_inline uint32_t
njt_crc32_short(u_char *p, size_t len)
{
    u_char    c;
    uint32_t  crc;

    crc = 0xffffffff;

    while (len--) {
        c = *p++;
        crc = njt_crc32_table_short[(crc ^ (c & 0xf)) & 0xf] ^ (crc >> 4);
        crc = njt_crc32_table_short[(crc ^ (c >> 4)) & 0xf] ^ (crc >> 4);
    }

    return crc ^ 0xffffffff;
}


static njt_inline uint32_t
njt_crc32_long(u_char *p, size_t len)
{
    uint32_t  crc;

    crc = 0xffffffff;

    while (len--) {
        crc = njt_crc32_table256[(crc ^ *p++) & 0xff] ^ (crc >> 8);
    }

    return crc ^ 0xffffffff;
}


#define njt_crc32_init(crc)                                                   \
    crc = 0xffffffff


static njt_inline void
njt_crc32_update(uint32_t *crc, u_char *p, size_t len)
{
    uint32_t  c;

    c = *crc;

    while (len--) {
        c = njt_crc32_table256[(c ^ *p++) & 0xff] ^ (c >> 8);
    }

    *crc = c;
}


#define njt_crc32_final(crc)                                                  \
    crc ^= 0xffffffff


njt_int_t njt_crc32_table_init(void);


#endif /* _NJT_CRC32_H_INCLUDED_ */
