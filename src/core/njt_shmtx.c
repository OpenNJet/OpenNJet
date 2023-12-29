
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


#if (NJT_HAVE_ATOMIC_OPS)


static void njt_shmtx_wakeup(njt_shmtx_t *mtx);


njt_int_t
njt_shmtx_create(njt_shmtx_t *mtx, njt_shmtx_sh_t *addr, u_char *name)
{
    mtx->lock = &addr->lock;

    if (mtx->spin == (njt_uint_t) -1) {
        return NJT_OK;
    }

    mtx->spin = 2048;

#if (NJT_HAVE_POSIX_SEM)

    mtx->wait = &addr->wait;

    if (sem_init(&mtx->sem, 1, 0) == -1) {
        njt_log_error(NJT_LOG_ALERT, njt_cycle->log, njt_errno,
                      "sem_init() failed");
    } else {
        mtx->semaphore = 1;
    }

#endif

    return NJT_OK;
}


void
njt_shmtx_destroy(njt_shmtx_t *mtx)
{
#if (NJT_HAVE_POSIX_SEM)

    if (mtx->semaphore) {
        if (sem_destroy(&mtx->sem) == -1) {
            njt_log_error(NJT_LOG_ALERT, njt_cycle->log, njt_errno,
                          "sem_destroy() failed");
        }
    }

#endif
}


njt_uint_t
njt_shmtx_trylock(njt_shmtx_t *mtx)
{
    return (*mtx->lock == 0 && njt_atomic_cmp_set(mtx->lock, 0, njt_pid));
}


void
njt_shmtx_lock(njt_shmtx_t *mtx)
{
    njt_uint_t         i, n;

    // njt_log_debug0(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0, "shmtx lock");

    for ( ;; ) {

        if (*mtx->lock == 0 && njt_atomic_cmp_set(mtx->lock, 0, njt_pid)) {
            return;
        }

        if (njt_ncpu > 1) {

            for (n = 1; n < mtx->spin; n <<= 1) {

                for (i = 0; i < n; i++) {
                    njt_cpu_pause();
                }

                if (*mtx->lock == 0
                    && njt_atomic_cmp_set(mtx->lock, 0, njt_pid))
                {
                    return;
                }
            }
        }

#if (NJT_HAVE_POSIX_SEM)

        if (mtx->semaphore) {
            (void) njt_atomic_fetch_add(mtx->wait, 1);

            if (*mtx->lock == 0 && njt_atomic_cmp_set(mtx->lock, 0, njt_pid)) {
                (void) njt_atomic_fetch_add(mtx->wait, -1);
                return;
            }

            njt_log_debug1(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,
                           "shmtx wait %uA", *mtx->wait);

            while (sem_wait(&mtx->sem) == -1) {
                njt_err_t  err;

                err = njt_errno;

                if (err != NJT_EINTR) {
                    njt_log_error(NJT_LOG_ALERT, njt_cycle->log, err,
                                  "sem_wait() failed while waiting on shmtx");
                    break;
                }
            }

            njt_log_debug0(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,
                           "shmtx awoke");

            continue;
        }

#endif

        njt_sched_yield();
    }
}


void
njt_shmtx_unlock(njt_shmtx_t *mtx)
{
    if (mtx->spin != (njt_uint_t) -1) {
        // njt_log_debug0(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0, "shmtx unlock");
    }

    if (njt_atomic_cmp_set(mtx->lock, njt_pid, 0)) {
        njt_shmtx_wakeup(mtx);
    }
}


njt_uint_t
njt_shmtx_force_unlock(njt_shmtx_t *mtx, njt_pid_t pid)
{
    njt_log_debug0(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,
                   "shmtx forced unlock");

    if (njt_atomic_cmp_set(mtx->lock, pid, 0)) {
        njt_shmtx_wakeup(mtx);
        return 1;
    }

    return 0;
}


static void
njt_shmtx_wakeup(njt_shmtx_t *mtx)
{
#if (NJT_HAVE_POSIX_SEM)
    njt_atomic_uint_t  wait;

    if (!mtx->semaphore) {
        return;
    }

    for ( ;; ) {

        wait = *mtx->wait;

        if ((njt_atomic_int_t) wait <= 0) {
            return;
        }

        if (njt_atomic_cmp_set(mtx->wait, wait, wait - 1)) {
            break;
        }
    }

    njt_log_debug1(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,
                   "shmtx wake %uA", wait);

    if (sem_post(&mtx->sem) == -1) {
        njt_log_error(NJT_LOG_ALERT, njt_cycle->log, njt_errno,
                      "sem_post() failed while wake shmtx");
    }

#endif
}


#define NJT_RWLOCK_SPIN         2048
#define NJT_RWLOCK_WLOCK        ((njt_atomic_uint_t) -1)
#define NJT_RWLOCK_LOCK_BASE    0x100000000

njt_int_t njt_shrwlock_create(njt_shrwlock_t *rwlock, njt_shmtx_sh_t *addr,
    u_char *name)
{
    rwlock->lock = &addr->lock;

    if (njt_atomic_cmp_set(rwlock->lock, 0, NJT_RWLOCK_LOCK_BASE)) {
        /* ok */
    } else {
        /* there is sth wrong */
    }

    return NJT_OK; 
}


void njt_shrwlock_destroy(njt_shrwlock_t *rwlock)
{
    /* do nothing */
}


void njt_shrwlock_rdlock(njt_shrwlock_t *rwlock)
{
    njt_uint_t         i, n;
    njt_atomic_uint_t  readers;

    for ( ;; ) {
        readers = *rwlock->lock;

        if (readers != NJT_RWLOCK_WLOCK
            && njt_atomic_cmp_set(rwlock->lock, readers, readers + 1))
        {
            return;
        }

        if (njt_ncpu > 1) {

            for (n = 1; n < NJT_RWLOCK_SPIN; n <<= 1) {

                for (i = 0; i < n; i++) {
                    njt_cpu_pause();
                }

                readers = *rwlock->lock;

                if (readers != NJT_RWLOCK_WLOCK
                    && njt_atomic_cmp_set(rwlock->lock, readers, readers + 1))
                {
                    return;
                }
            }
        }

        njt_sched_yield();
    }
}


void njt_shrwlock_wrlock(njt_shrwlock_t *rwlock)
{
    njt_uint_t  i, n;

    for ( ;; ) {

        if (*rwlock->lock == NJT_RWLOCK_LOCK_BASE && njt_atomic_cmp_set(rwlock->lock, NJT_RWLOCK_LOCK_BASE, NJT_RWLOCK_WLOCK)) {
            return;
        }

        if (njt_ncpu > 1) {

            for (n = 1; n < NJT_RWLOCK_SPIN; n <<= 1) {

                for (i = 0; i < n; i++) {
                    njt_cpu_pause();
                }

                if (*rwlock->lock == 0
                    && njt_atomic_cmp_set(rwlock->lock, NJT_RWLOCK_LOCK_BASE, NJT_RWLOCK_WLOCK))
                {
                    return;
                }
            }
        }

        njt_sched_yield();
    }
}


void njt_shrwlock_unlock(njt_shrwlock_t *rwlock)
{
    if (*rwlock->lock == NJT_RWLOCK_WLOCK) {
        (void) njt_atomic_cmp_set(rwlock->lock, NJT_RWLOCK_WLOCK, NJT_RWLOCK_LOCK_BASE);
    } else {
        (void) njt_atomic_fetch_add(rwlock->lock, -1);
    }
}


void njt_shrwlock_rd2wrlock(njt_shrwlock_t *rwlock)
{
    njt_shrwlock_unlock(rwlock);
    njt_shrwlock_wrlock(rwlock);
}


void njt_shrwlock_wr2rdlock(njt_shrwlock_t *rwlock)
{
    njt_shrwlock_unlock(rwlock);
    njt_shrwlock_rdlock(rwlock);
}


#else


njt_int_t
njt_shmtx_create(njt_shmtx_t *mtx, njt_shmtx_sh_t *addr, u_char *name)
{
    if (mtx->name) {

        if (njt_strcmp(name, mtx->name) == 0) {
            mtx->name = name;
            return NJT_OK;
        }

        njt_shmtx_destroy(mtx);
    }

    mtx->fd = njt_open_file(name, NJT_FILE_RDWR, NJT_FILE_CREATE_OR_OPEN,
                            NJT_FILE_DEFAULT_ACCESS);

    if (mtx->fd == NJT_INVALID_FILE) {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, njt_errno,
                      njt_open_file_n " \"%s\" failed", name);
        return NJT_ERROR;
    }

    if (njt_delete_file(name) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_ALERT, njt_cycle->log, njt_errno,
                      njt_delete_file_n " \"%s\" failed", name);
    }

    mtx->name = name;

    return NJT_OK;
}


void
njt_shmtx_destroy(njt_shmtx_t *mtx)
{
    if (njt_close_file(mtx->fd) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_ALERT, njt_cycle->log, njt_errno,
                      njt_close_file_n " \"%s\" failed", mtx->name);
    }
}


njt_uint_t
njt_shmtx_trylock(njt_shmtx_t *mtx)
{
    njt_err_t  err;

    err = njt_trylock_fd(mtx->fd);

    if (err == 0) {
        return 1;
    }

    if (err == NJT_EAGAIN) {
        return 0;
    }

#if __osf__ /* Tru64 UNIX */

    if (err == NJT_EACCES) {
        return 0;
    }

#endif

    njt_log_abort(err, njt_trylock_fd_n " %s failed", mtx->name);

    return 0;
}


void
njt_shmtx_lock(njt_shmtx_t *mtx)
{
    njt_err_t  err;

    err = njt_lock_fd(mtx->fd);

    if (err == 0) {
        return;
    }

    njt_log_abort(err, njt_lock_fd_n " %s failed", mtx->name);
}


void
njt_shmtx_unlock(njt_shmtx_t *mtx)
{
    njt_err_t  err;

    err = njt_unlock_fd(mtx->fd);

    if (err == 0) {
        return;
    }

    njt_log_abort(err, njt_unlock_fd_n " %s failed", mtx->name);
}


njt_uint_t
njt_shmtx_force_unlock(njt_shmtx_t *mtx, njt_pid_t pid)
{
    return 0;
}

#endif
