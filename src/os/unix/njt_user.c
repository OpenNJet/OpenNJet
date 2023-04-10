
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


#if (NJT_CRYPT)

#if (NJT_HAVE_GNU_CRYPT_R)

njt_int_t
njt_libc_crypt(njt_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    char               *value;
    size_t              len;
    struct crypt_data   cd;

    cd.initialized = 0;

    value = crypt_r((char *) key, (char *) salt, &cd);

    if (value) {
        len = njt_strlen(value) + 1;

        *encrypted = njt_pnalloc(pool, len);
        if (*encrypted == NULL) {
            return NJT_ERROR;
        }

        njt_memcpy(*encrypted, value, len);
        return NJT_OK;
    }

    njt_log_error(NJT_LOG_CRIT, pool->log, njt_errno, "crypt_r() failed");

    return NJT_ERROR;
}

#else

njt_int_t
njt_libc_crypt(njt_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    char       *value;
    size_t      len;
    njt_err_t   err;

    value = crypt((char *) key, (char *) salt);

    if (value) {
        len = njt_strlen(value) + 1;

        *encrypted = njt_pnalloc(pool, len);
        if (*encrypted == NULL) {
            return NJT_ERROR;
        }

        njt_memcpy(*encrypted, value, len);
        return NJT_OK;
    }

    err = njt_errno;

    njt_log_error(NJT_LOG_CRIT, pool->log, err, "crypt() failed");

    return NJT_ERROR;
}

#endif

#endif /* NJT_CRYPT */
