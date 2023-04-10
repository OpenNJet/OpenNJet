
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


static njt_str_t   njt_unknown_error = njt_string("Unknown error");


#if (NJT_HAVE_STRERRORDESC_NP)

/*
 * The strerrordesc_np() function, introduced in glibc 2.32, is
 * async-signal-safe.  This makes it possible to use it directly,
 * without copying error messages.
 */


u_char *
njt_strerror(njt_err_t err, u_char *errstr, size_t size)
{
    size_t       len;
    const char  *msg;

    msg = strerrordesc_np(err);

    if (msg == NULL) {
        msg = (char *) njt_unknown_error.data;
        len = njt_unknown_error.len;

    } else {
        len = njt_strlen(msg);
    }

    size = njt_min(size, len);

    return njt_cpymem(errstr, msg, size);
}


njt_int_t
njt_strerror_init(void)
{
    return NJT_OK;
}


#else

/*
 * The strerror() messages are copied because:
 *
 * 1) strerror() and strerror_r() functions are not Async-Signal-Safe,
 *    therefore, they cannot be used in signal handlers;
 *
 * 2) a direct sys_errlist[] array may be used instead of these functions,
 *    but Linux linker warns about its usage:
 *
 * warning: `sys_errlist' is deprecated; use `strerror' or `strerror_r' instead
 * warning: `sys_nerr' is deprecated; use `strerror' or `strerror_r' instead
 *
 *    causing false bug reports.
 */


static njt_str_t  *njt_sys_errlist;
static njt_err_t   njt_first_error;
static njt_err_t   njt_last_error;


u_char *
njt_strerror(njt_err_t err, u_char *errstr, size_t size)
{
    njt_str_t  *msg;

    if (err >= njt_first_error && err < njt_last_error) {
        msg = &njt_sys_errlist[err - njt_first_error];

    } else {
        msg = &njt_unknown_error;
    }

    size = njt_min(size, msg->len);

    return njt_cpymem(errstr, msg->data, size);
}


njt_int_t
njt_strerror_init(void)
{
    char       *msg;
    u_char     *p;
    size_t      len;
    njt_err_t   err;

#if (NJT_SYS_NERR)
    njt_first_error = 0;
    njt_last_error = NJT_SYS_NERR;

#elif (EPERM > 1000 && EPERM < 0x7fffffff - 1000)

    /*
     * If number of errors is not known, and EPERM error code has large
     * but reasonable value, guess possible error codes based on the error
     * messages returned by strerror(), starting from EPERM.  Notably,
     * this covers GNU/Hurd, where errors start at 0x40000001.
     */

    for (err = EPERM; err > EPERM - 1000; err--) {
        njt_set_errno(0);
        msg = strerror(err);

        if (errno == EINVAL
            || msg == NULL
            || strncmp(msg, "Unknown error", 13) == 0)
        {
            continue;
        }

        njt_first_error = err;
    }

    for (err = EPERM; err < EPERM + 1000; err++) {
        njt_set_errno(0);
        msg = strerror(err);

        if (errno == EINVAL
            || msg == NULL
            || strncmp(msg, "Unknown error", 13) == 0)
        {
            continue;
        }

        njt_last_error = err + 1;
    }

#else

    /*
     * If number of errors is not known, guess it based on the error
     * messages returned by strerror().
     */

    njt_first_error = 0;

    for (err = 0; err < 1000; err++) {
        njt_set_errno(0);
        msg = strerror(err);

        if (errno == EINVAL
            || msg == NULL
            || strncmp(msg, "Unknown error", 13) == 0)
        {
            continue;
        }

        njt_last_error = err + 1;
    }

#endif

    /*
     * njt_strerror() is not ready to work at this stage, therefore,
     * malloc() is used and possible errors are logged using strerror().
     */

    len = (njt_last_error - njt_first_error) * sizeof(njt_str_t);

    njt_sys_errlist = malloc(len);
    if (njt_sys_errlist == NULL) {
        goto failed;
    }

    for (err = njt_first_error; err < njt_last_error; err++) {
        msg = strerror(err);

        if (msg == NULL) {
            njt_sys_errlist[err - njt_first_error] = njt_unknown_error;
            continue;
        }

        len = njt_strlen(msg);

        p = malloc(len);
        if (p == NULL) {
            goto failed;
        }

        njt_memcpy(p, msg, len);
        njt_sys_errlist[err - njt_first_error].len = len;
        njt_sys_errlist[err - njt_first_error].data = p;
    }

    return NJT_OK;

failed:

    err = errno;
    njt_log_stderr(0, "malloc(%uz) failed (%d: %s)", len, err, strerror(err));

    return NJT_ERROR;
}

#endif
