
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_MD5_H_INCLUDED_
#define _NJT_MD5_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


typedef struct {
    uint64_t  bytes;
    uint32_t  a, b, c, d;
    u_char    buffer[64];
} njt_md5_t;


void njt_md5_init(njt_md5_t *ctx);
void njt_md5_update(njt_md5_t *ctx, const void *data, size_t size);
void njt_md5_final(u_char result[16], njt_md5_t *ctx);


#endif /* _NJT_MD5_H_INCLUDED_ */
