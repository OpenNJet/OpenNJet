
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_ATOMIC_H_INCLUDED_
#define _NJT_ATOMIC_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


#define NJT_HAVE_ATOMIC_OPS   1

typedef int32_t                     njt_atomic_int_t;
typedef uint32_t                    njt_atomic_uint_t;
typedef volatile njt_atomic_uint_t  njt_atomic_t;
#define NJT_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)


#if defined( __WATCOMC__ ) || defined( __BORLANDC__ ) || defined(__GNUC__)    \
    || ( _MSC_VER >= 1300 )

/* the new SDK headers */

#define njt_atomic_cmp_set(lock, old, set)                                    \
    ((njt_atomic_uint_t) InterlockedCompareExchange((long *) lock, set, old)  \
                         == old)

#else

/* the old MS VC6.0SP2 SDK headers */

#define njt_atomic_cmp_set(lock, old, set)                                    \
    (InterlockedCompareExchange((void **) lock, (void *) set, (void *) old)   \
     == (void *) old)

#endif


#define njt_atomic_fetch_add(p, add) InterlockedExchangeAdd((long *) p, add)


#define njt_memory_barrier()


#if defined( __BORLANDC__ ) || ( __WATCOMC__ < 1230 )

/*
 * Borland C++ 5.5 (tasm32) and Open Watcom C prior to 1.3
 * do not understand the "pause" instruction
 */

#define njt_cpu_pause()
#else
#define njt_cpu_pause()       __asm { pause }
#endif


void njt_spinlock(njt_atomic_t *lock, njt_atomic_int_t value, njt_uint_t spin);

#define njt_trylock(lock)  (*(lock) == 0 && njt_atomic_cmp_set(lock, 0, 1))
#define njt_unlock(lock)    *(lock) = 0


#endif /* _NJT_ATOMIC_H_INCLUDED_ */
