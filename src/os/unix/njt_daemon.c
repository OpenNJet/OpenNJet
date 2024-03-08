
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


njt_int_t
njt_daemon(njt_log_t *log)
{
    int  fd;

    switch (fork()) {
    case -1:
        njt_log_error(NJT_LOG_EMERG, log, njt_errno, "fork() failed");
        return NJT_ERROR;

    case 0:
        break;

    default:
        /* just to make it ASAN or Valgrind clean */  
        njt_destroy_pool(njt_cycle->pool); // orenresty patch
        exit(0);
    }

    njt_parent = njt_pid;
    njt_pid = njt_getpid();

    if (setsid() == -1) {
        njt_log_error(NJT_LOG_EMERG, log, njt_errno, "setsid() failed");
        return NJT_ERROR;
    }

    umask(0);

    fd = open("/dev/null", O_RDWR);
    if (fd == -1) {
        njt_log_error(NJT_LOG_EMERG, log, njt_errno,
                      "open(\"/dev/null\") failed");
        return NJT_ERROR;
    }

    if (dup2(fd, STDIN_FILENO) == -1) {
        njt_log_error(NJT_LOG_EMERG, log, njt_errno, "dup2(STDIN) failed");
        return NJT_ERROR;
    }

    if (dup2(fd, STDOUT_FILENO) == -1) {
        njt_log_error(NJT_LOG_EMERG, log, njt_errno, "dup2(STDOUT) failed");
        return NJT_ERROR;
    }

#if 0
    if (dup2(fd, STDERR_FILENO) == -1) {
        njt_log_error(NJT_LOG_EMERG, log, njt_errno, "dup2(STDERR) failed");
        return NJT_ERROR;
    }
#endif

    if (fd > STDERR_FILENO) {
        if (close(fd) == -1) {
            njt_log_error(NJT_LOG_EMERG, log, njt_errno, "close() failed");
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}
