
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


njt_int_t
njt_thread_cond_create(njt_thread_cond_t *cond, njt_log_t *log)
{
    njt_err_t  err;

    err = pthread_cond_init(cond, NULL);
    if (err == 0) {
        return NJT_OK;
    }

    njt_log_error(NJT_LOG_EMERG, log, err, "pthread_cond_init() failed");
    return NJT_ERROR;
}


njt_int_t
njt_thread_cond_destroy(njt_thread_cond_t *cond, njt_log_t *log)
{
    njt_err_t  err;

    err = pthread_cond_destroy(cond);
    if (err == 0) {
        return NJT_OK;
    }

    njt_log_error(NJT_LOG_EMERG, log, err, "pthread_cond_destroy() failed");
    return NJT_ERROR;
}


njt_int_t
njt_thread_cond_signal(njt_thread_cond_t *cond, njt_log_t *log)
{
    njt_err_t  err;

    err = pthread_cond_signal(cond);
    if (err == 0) {
        return NJT_OK;
    }

    njt_log_error(NJT_LOG_EMERG, log, err, "pthread_cond_signal() failed");
    return NJT_ERROR;
}


njt_int_t
njt_thread_cond_wait(njt_thread_cond_t *cond, njt_thread_mutex_t *mtx,
    njt_log_t *log)
{
    njt_err_t  err;

    err = pthread_cond_wait(cond, mtx);

#if 0
    njt_time_update();
#endif

    if (err == 0) {
        return NJT_OK;
    }

    njt_log_error(NJT_LOG_ALERT, log, err, "pthread_cond_wait() failed");

    return NJT_ERROR;
}
