
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


njt_err_t
njt_create_thread(njt_tid_t *tid,
    njt_thread_value_t (__stdcall *func)(void *arg), void *arg, njt_log_t *log)
{
    u_long     id;
    njt_err_t  err;

    *tid = CreateThread(NULL, 0, func, arg, 0, &id);

    if (*tid != NULL) {
        njt_log_error(NJT_LOG_NOTICE, log, 0,
                      "create thread " NJT_TID_T_FMT, id);
        return 0;
    }

    err = njt_errno;
    njt_log_error(NJT_LOG_ALERT, log, err, "CreateThread() failed");
    return err;
}
