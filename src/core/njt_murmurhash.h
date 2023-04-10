
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_MURMURHASH_H_INCLUDED_
#define _NJT_MURMURHASH_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


uint32_t njt_murmur_hash2(u_char *data, size_t len);


#endif /* _NJT_MURMURHASH_H_INCLUDED_ */
