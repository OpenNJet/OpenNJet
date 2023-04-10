
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_CRYPT_H_INCLUDED_
#define _NJT_CRYPT_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


njt_int_t njt_crypt(njt_pool_t *pool, u_char *key, u_char *salt,
    u_char **encrypted);


#endif /* _NJT_CRYPT_H_INCLUDED_ */
