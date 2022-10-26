/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) TMLake, Inc.
 */


#include <njt_config.h>
#include <njt_core.h>


#if (NJT_CRYPT)

njt_int_t
njt_libc_crypt(njt_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    /* STUB: a plain text password */

    *encrypted = key;

    return NJT_OK;
}

#endif /* NJT_CRYPT */
