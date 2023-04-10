
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njet.h>


njt_int_t   njt_ncpu;
njt_int_t   njt_max_sockets;
njt_uint_t  njt_inherited_nonblocking;
njt_uint_t  njt_tcp_nodelay_and_tcp_nopush;


struct rlimit  rlmt;


njt_os_io_t njt_os_io = {
    njt_unix_recv,
    njt_readv_chain,
    njt_udp_unix_recv,
    njt_unix_send,
    njt_udp_unix_send,
    njt_udp_unix_sendmsg_chain,
    njt_writev_chain,
    0
};


njt_int_t
njt_os_init(njt_log_t *log)
{
    njt_time_t  *tp;
    njt_uint_t   n;
#if (NJT_HAVE_LEVEL1_DCACHE_LINESIZE)
    long         size;
#endif

#if (NJT_HAVE_OS_SPECIFIC_INIT)
    if (njt_os_specific_init(log) != NJT_OK) {
        return NJT_ERROR;
    }
#endif

    if (njt_init_setproctitle(log) != NJT_OK) {
        return NJT_ERROR;
    }

    njt_pagesize = getpagesize();
    njt_cacheline_size = NJT_CPU_CACHE_LINE;

    for (n = njt_pagesize; n >>= 1; njt_pagesize_shift++) { /* void */ }

#if (NJT_HAVE_SC_NPROCESSORS_ONLN)
    if (njt_ncpu == 0) {
        njt_ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    }
#endif

    if (njt_ncpu < 1) {
        njt_ncpu = 1;
    }

#if (NJT_HAVE_LEVEL1_DCACHE_LINESIZE)
    size = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
    if (size > 0) {
        njt_cacheline_size = size;
    }
#endif

    njt_cpuinfo();

    if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
        njt_log_error(NJT_LOG_ALERT, log, errno,
                      "getrlimit(RLIMIT_NOFILE) failed");
        return NJT_ERROR;
    }

    njt_max_sockets = (njt_int_t) rlmt.rlim_cur;

#if (NJT_HAVE_INHERITED_NONBLOCK || NJT_HAVE_ACCEPT4)
    njt_inherited_nonblocking = 1;
#else
    njt_inherited_nonblocking = 0;
#endif

    tp = njt_timeofday();
    srandom(((unsigned) njt_pid << 16) ^ tp->sec ^ tp->msec);

    return NJT_OK;
}


void
njt_os_status(njt_log_t *log)
{
    njt_log_error(NJT_LOG_NOTICE, log, 0, NJT_VER_BUILD);

#ifdef NJT_COMPILER
    njt_log_error(NJT_LOG_NOTICE, log, 0, "built by " NJT_COMPILER);
#endif

#if (NJT_HAVE_OS_SPECIFIC_INIT)
    njt_os_specific_status(log);
#endif

    njt_log_error(NJT_LOG_NOTICE, log, 0,
                  "getrlimit(RLIMIT_NOFILE): %r:%r",
                  rlmt.rlim_cur, rlmt.rlim_max);
}


#if 0

njt_int_t
njt_posix_post_conf_init(njt_log_t *log)
{
    njt_fd_t  pp[2];

    if (pipe(pp) == -1) {
        njt_log_error(NJT_LOG_EMERG, log, njt_errno, "pipe() failed");
        return NJT_ERROR;
    }

    if (dup2(pp[1], STDERR_FILENO) == -1) {
        njt_log_error(NJT_LOG_EMERG, log, errno, "dup2(STDERR) failed");
        return NJT_ERROR;
    }

    if (pp[1] > STDERR_FILENO) {
        if (close(pp[1]) == -1) {
            njt_log_error(NJT_LOG_EMERG, log, errno, "close() failed");
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}

#endif
