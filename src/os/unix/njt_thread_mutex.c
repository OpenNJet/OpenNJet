
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_config.h>
#include <njt_core.h>


/*
 * All modern pthread mutex implementations try to acquire a lock
 * atomically in userland before going to sleep in kernel.  Some
 * spins before the sleeping.
 *
 * In Solaris since version 8 all mutex types spin before sleeping.
 * The default spin count is 1000.  It can be overridden using
 * _THREAD_ADAPTIVE_SPIN=100 environment variable.
 *
 * In MacOSX all mutex types spin to acquire a lock protecting a mutex's
 * internals.  If the mutex is busy, thread calls Mach semaphore_wait().
 *
 *
 * PTHREAD_MUTEX_NORMAL lacks deadlock detection and is the fastest
 * mutex type.
 *
 *   Linux:    No spinning.  The internal name PTHREAD_MUTEX_TIMED_NP
 *             remains from the times when pthread_mutex_timedlock() was
 *             non-standard extension.  Alias name: PTHREAD_MUTEX_FAST_NP.
 *   FreeBSD:  No spinning.
 *
 *
 * PTHREAD_MUTEX_ERRORCHECK is usually as fast as PTHREAD_MUTEX_NORMAL
 * yet has lightweight deadlock detection.
 *
 *   Linux:    No spinning.  The internal name: PTHREAD_MUTEX_ERRORCHECK_NP.
 *   FreeBSD:  No spinning.
 *
 *
 * PTHREAD_MUTEX_RECURSIVE allows recursive locking.
 *
 *   Linux:    No spinning.  The internal name: PTHREAD_MUTEX_RECURSIVE_NP.
 *   FreeBSD:  No spinning.
 *
 *
 * PTHREAD_MUTEX_ADAPTIVE_NP spins on SMP systems before sleeping.
 *
 *   Linux:    No deadlock detection.  Dynamically changes a spin count
 *             for each mutex from 10 to 100 based on spin count taken
 *             previously.
 *   FreeBSD:  Deadlock detection.  The default spin count is 2000.
 *             It can be overridden using LIBPTHREAD_SPINLOOPS environment
 *             variable or by pthread_mutex_setspinloops_np().  If a lock
 *             is still busy, sched_yield() can be called on both UP and
 *             SMP systems.  The default yield loop count is zero, but
 *             it can be set by LIBPTHREAD_YIELDLOOPS environment
 *             variable or by pthread_mutex_setyieldloops_np().
 *   Solaris:  No PTHREAD_MUTEX_ADAPTIVE_NP.
 *   MacOSX:   No PTHREAD_MUTEX_ADAPTIVE_NP.
 *
 *
 * PTHREAD_MUTEX_ELISION_NP is a Linux extension to elide locks using
 * Intel Restricted Transactional Memory.  It is the most suitable for
 * rwlock pattern access because it allows simultaneous reads without lock.
 * Supported since glibc 2.18.
 *
 *
 * PTHREAD_MUTEX_DEFAULT is default mutex type.
 *
 *   Linux:    PTHREAD_MUTEX_NORMAL.
 *   FreeBSD:  PTHREAD_MUTEX_ERRORCHECK.
 *   Solaris:  PTHREAD_MUTEX_NORMAL.
 *   MacOSX:   PTHREAD_MUTEX_NORMAL.
 */


njt_int_t
njt_thread_mutex_create(njt_thread_mutex_t *mtx, njt_log_t *log)
{
    njt_err_t            err;
    pthread_mutexattr_t  attr;

    err = pthread_mutexattr_init(&attr);
    if (err != 0) {
        njt_log_error(NJT_LOG_EMERG, log, err,
                      "pthread_mutexattr_init() failed");
        return NJT_ERROR;
    }

    err = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
    if (err != 0) {
        njt_log_error(NJT_LOG_EMERG, log, err,
                      "pthread_mutexattr_settype"
                      "(PTHREAD_MUTEX_ERRORCHECK) failed");
        return NJT_ERROR;
    }

    err = pthread_mutex_init(mtx, &attr);
    if (err != 0) {
        njt_log_error(NJT_LOG_EMERG, log, err,
                      "pthread_mutex_init() failed");
        return NJT_ERROR;
    }

    err = pthread_mutexattr_destroy(&attr);
    if (err != 0) {
        njt_log_error(NJT_LOG_ALERT, log, err,
                      "pthread_mutexattr_destroy() failed");
    }

    return NJT_OK;
}


njt_int_t
njt_thread_mutex_destroy(njt_thread_mutex_t *mtx, njt_log_t *log)
{
    njt_err_t  err;

    err = pthread_mutex_destroy(mtx);
    if (err != 0) {
        njt_log_error(NJT_LOG_ALERT, log, err,
                      "pthread_mutex_destroy() failed");
        return NJT_ERROR;
    }

    return NJT_OK;
}


njt_int_t
njt_thread_mutex_lock(njt_thread_mutex_t *mtx, njt_log_t *log)
{
    njt_err_t  err;

    err = pthread_mutex_lock(mtx);
    if (err == 0) {
        return NJT_OK;
    }

    njt_log_error(NJT_LOG_ALERT, log, err, "pthread_mutex_lock() failed");

    return NJT_ERROR;
}


njt_int_t
njt_thread_mutex_unlock(njt_thread_mutex_t *mtx, njt_log_t *log)
{
    njt_err_t  err;

    err = pthread_mutex_unlock(mtx);

#if 0
    njt_time_update();
#endif

    if (err == 0) {
        return NJT_OK;
    }

    njt_log_error(NJT_LOG_ALERT, log, err, "pthread_mutex_unlock() failed");

    return NJT_ERROR;
}
