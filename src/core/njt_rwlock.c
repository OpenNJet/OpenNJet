
/*
 * Copyright (C) Ruslan Ermilov
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


#if (NJT_HAVE_ATOMIC_OPS)


#define NJT_RWLOCK_SPIN   2048
#define NJT_RWLOCK_WLOCK  ((njt_atomic_uint_t) -1)


void
njt_rwlock_wlock(njt_atomic_t *lock)
{
    njt_uint_t  i, n;

    for ( ;; ) {

        if (*lock == 0 && njt_atomic_cmp_set(lock, 0, NJT_RWLOCK_WLOCK)) {
            return;
        }

        if (njt_ncpu > 1) {

            for (n = 1; n < NJT_RWLOCK_SPIN; n <<= 1) {

                for (i = 0; i < n; i++) {
                    njt_cpu_pause();
                }

                if (*lock == 0
                    && njt_atomic_cmp_set(lock, 0, NJT_RWLOCK_WLOCK))
                {
                    return;
                }
            }
        }

        njt_sched_yield();
    }
}


void
njt_rwlock_rlock(njt_atomic_t *lock)
{
    njt_uint_t         i, n;
    njt_atomic_uint_t  readers;

    for ( ;; ) {
        readers = *lock;

        if (readers != NJT_RWLOCK_WLOCK
            && njt_atomic_cmp_set(lock, readers, readers + 1))
        {
            return;
        }

        if (njt_ncpu > 1) {

            for (n = 1; n < NJT_RWLOCK_SPIN; n <<= 1) {

                for (i = 0; i < n; i++) {
                    njt_cpu_pause();
                }

                readers = *lock;

                if (readers != NJT_RWLOCK_WLOCK
                    && njt_atomic_cmp_set(lock, readers, readers + 1))
                {
                    return;
                }
            }
        }

        njt_sched_yield();
    }
}


void
njt_rwlock_unlock(njt_atomic_t *lock)
{
    if (*lock == NJT_RWLOCK_WLOCK) {
        (void) njt_atomic_cmp_set(lock, NJT_RWLOCK_WLOCK, 0);
    } else {
        (void) njt_atomic_fetch_add(lock, -1);
    }
}


void
njt_rwlock_downgrade(njt_atomic_t *lock)
{
    if (*lock == NJT_RWLOCK_WLOCK) {
        *lock = 1;
    }
}


#else

#if (NJT_HTTP_UPSTREAM_ZONE || NJT_STREAM_UPSTREAM_ZONE)

#error njt_atomic_cmp_set() is not defined!

#endif

#endif
