
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_SHA1_H_INCLUDED_
#define _NJT_SHA1_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


typedef struct {
    uint64_t  bytes;
    uint32_t  a, b, c, d, e, f;
    u_char    buffer[64];
} njt_sha1_t;


void njt_sha1_init(njt_sha1_t *ctx);
void njt_sha1_update(njt_sha1_t *ctx, const void *data, size_t size);
void njt_sha1_final(u_char result[20], njt_sha1_t *ctx);


#endif /* _NJT_SHA1_H_INCLUDED_ */
