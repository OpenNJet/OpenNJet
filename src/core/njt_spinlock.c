
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


void
njt_spinlock(njt_atomic_t *lock, njt_atomic_int_t value, njt_uint_t spin)
{

#if (NJT_HAVE_ATOMIC_OPS)

    njt_uint_t  i, n;

    for ( ;; ) {

        if (*lock == 0 && njt_atomic_cmp_set(lock, 0, value)) {
            return;
        }

        if (njt_ncpu > 1) {

            for (n = 1; n < spin; n <<= 1) {

                for (i = 0; i < n; i++) {
                    njt_cpu_pause();
                }

                if (*lock == 0 && njt_atomic_cmp_set(lock, 0, value)) {
                    return;
                }
            }
        }

        njt_sched_yield();
    }

#else

#if (NJT_THREADS)

#error njt_spinlock() or njt_atomic_cmp_set() are not defined !

#endif

#endif

}
