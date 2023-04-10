
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_ATOMIC_H_INCLUDED_
#define _NJT_ATOMIC_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


#if (NJT_HAVE_LIBATOMIC)

#define AO_REQUIRE_CAS
#include <atomic_ops.h>

#define NJT_HAVE_ATOMIC_OPS  1

typedef long                        njt_atomic_int_t;
typedef AO_t                        njt_atomic_uint_t;
typedef volatile njt_atomic_uint_t  njt_atomic_t;

#if (NJT_PTR_SIZE == 8)
#define NJT_ATOMIC_T_LEN            (sizeof("-9223372036854775808") - 1)
#else
#define NJT_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)
#endif

#define njt_atomic_cmp_set(lock, old, new)                                    \
    AO_compare_and_swap(lock, old, new)
#define njt_atomic_fetch_add(value, add)                                      \
    AO_fetch_and_add(value, add)
#define njt_memory_barrier()        AO_nop()
#define njt_cpu_pause()


#elif (NJT_HAVE_GCC_ATOMIC)

/* GCC 4.1 builtin atomic operations */

#define NJT_HAVE_ATOMIC_OPS  1

typedef long                        njt_atomic_int_t;
typedef unsigned long               njt_atomic_uint_t;

#if (NJT_PTR_SIZE == 8)
#define NJT_ATOMIC_T_LEN            (sizeof("-9223372036854775808") - 1)
#else
#define NJT_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)
#endif

typedef volatile njt_atomic_uint_t  njt_atomic_t;


#define njt_atomic_cmp_set(lock, old, set)                                    \
    __sync_bool_compare_and_swap(lock, old, set)

#define njt_atomic_fetch_add(value, add)                                      \
    __sync_fetch_and_add(value, add)

#define njt_memory_barrier()        __sync_synchronize()

#if ( __i386__ || __i386 || __amd64__ || __amd64 )
#define njt_cpu_pause()             __asm__ ("pause")
#else
#define njt_cpu_pause()
#endif


#elif (NJT_DARWIN_ATOMIC)

/*
 * use Darwin 8 atomic(3) and barrier(3) operations
 * optimized at run-time for UP and SMP
 */

#include <libkern/OSAtomic.h>

/* "bool" conflicts with perl's CORE/handy.h */
#if 0
#undef bool
#endif


#define NJT_HAVE_ATOMIC_OPS  1

#if (NJT_PTR_SIZE == 8)

typedef int64_t                     njt_atomic_int_t;
typedef uint64_t                    njt_atomic_uint_t;
#define NJT_ATOMIC_T_LEN            (sizeof("-9223372036854775808") - 1)

#define njt_atomic_cmp_set(lock, old, new)                                    \
    OSAtomicCompareAndSwap64Barrier(old, new, (int64_t *) lock)

#define njt_atomic_fetch_add(value, add)                                      \
    (OSAtomicAdd64(add, (int64_t *) value) - add)

#else

typedef int32_t                     njt_atomic_int_t;
typedef uint32_t                    njt_atomic_uint_t;
#define NJT_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)

#define njt_atomic_cmp_set(lock, old, new)                                    \
    OSAtomicCompareAndSwap32Barrier(old, new, (int32_t *) lock)

#define njt_atomic_fetch_add(value, add)                                      \
    (OSAtomicAdd32(add, (int32_t *) value) - add)

#endif

#define njt_memory_barrier()        OSMemoryBarrier()

#define njt_cpu_pause()

typedef volatile njt_atomic_uint_t  njt_atomic_t;


#elif ( __i386__ || __i386 )

typedef int32_t                     njt_atomic_int_t;
typedef uint32_t                    njt_atomic_uint_t;
typedef volatile njt_atomic_uint_t  njt_atomic_t;
#define NJT_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)


#if ( __SUNPRO_C )

#define NJT_HAVE_ATOMIC_OPS  1

njt_atomic_uint_t
njt_atomic_cmp_set(njt_atomic_t *lock, njt_atomic_uint_t old,
    njt_atomic_uint_t set);

njt_atomic_int_t
njt_atomic_fetch_add(njt_atomic_t *value, njt_atomic_int_t add);

/*
 * Sun Studio 12 exits with segmentation fault on '__asm ("pause")',
 * so njt_cpu_pause is declared in src/os/unix/njt_sunpro_x86.il
 */

void
njt_cpu_pause(void);

/* the code in src/os/unix/njt_sunpro_x86.il */

#define njt_memory_barrier()        __asm (".volatile"); __asm (".nonvolatile")


#else /* ( __GNUC__ || __INTEL_COMPILER ) */

#define NJT_HAVE_ATOMIC_OPS  1

#include "njt_gcc_atomic_x86.h"

#endif


#elif ( __amd64__ || __amd64 )

typedef int64_t                     njt_atomic_int_t;
typedef uint64_t                    njt_atomic_uint_t;
typedef volatile njt_atomic_uint_t  njt_atomic_t;
#define NJT_ATOMIC_T_LEN            (sizeof("-9223372036854775808") - 1)


#if ( __SUNPRO_C )

#define NJT_HAVE_ATOMIC_OPS  1

njt_atomic_uint_t
njt_atomic_cmp_set(njt_atomic_t *lock, njt_atomic_uint_t old,
    njt_atomic_uint_t set);

njt_atomic_int_t
njt_atomic_fetch_add(njt_atomic_t *value, njt_atomic_int_t add);

/*
 * Sun Studio 12 exits with segmentation fault on '__asm ("pause")',
 * so njt_cpu_pause is declared in src/os/unix/njt_sunpro_amd64.il
 */

void
njt_cpu_pause(void);

/* the code in src/os/unix/njt_sunpro_amd64.il */

#define njt_memory_barrier()        __asm (".volatile"); __asm (".nonvolatile")


#else /* ( __GNUC__ || __INTEL_COMPILER ) */

#define NJT_HAVE_ATOMIC_OPS  1

#include "njt_gcc_atomic_amd64.h"

#endif


#elif ( __sparc__ || __sparc || __sparcv9 )

#if (NJT_PTR_SIZE == 8)

typedef int64_t                     njt_atomic_int_t;
typedef uint64_t                    njt_atomic_uint_t;
#define NJT_ATOMIC_T_LEN            (sizeof("-9223372036854775808") - 1)

#else

typedef int32_t                     njt_atomic_int_t;
typedef uint32_t                    njt_atomic_uint_t;
#define NJT_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)

#endif

typedef volatile njt_atomic_uint_t  njt_atomic_t;


#if ( __SUNPRO_C )

#define NJT_HAVE_ATOMIC_OPS  1

#include "njt_sunpro_atomic_sparc64.h"


#else /* ( __GNUC__ || __INTEL_COMPILER ) */

#define NJT_HAVE_ATOMIC_OPS  1

#include "njt_gcc_atomic_sparc64.h"

#endif


#elif ( __powerpc__ || __POWERPC__ )

#define NJT_HAVE_ATOMIC_OPS  1

#if (NJT_PTR_SIZE == 8)

typedef int64_t                     njt_atomic_int_t;
typedef uint64_t                    njt_atomic_uint_t;
#define NJT_ATOMIC_T_LEN            (sizeof("-9223372036854775808") - 1)

#else

typedef int32_t                     njt_atomic_int_t;
typedef uint32_t                    njt_atomic_uint_t;
#define NJT_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)

#endif

typedef volatile njt_atomic_uint_t  njt_atomic_t;


#include "njt_gcc_atomic_ppc.h"

#endif


#if !(NJT_HAVE_ATOMIC_OPS)

#define NJT_HAVE_ATOMIC_OPS  0

typedef int32_t                     njt_atomic_int_t;
typedef uint32_t                    njt_atomic_uint_t;
typedef volatile njt_atomic_uint_t  njt_atomic_t;
#define NJT_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)


static njt_inline njt_atomic_uint_t
njt_atomic_cmp_set(njt_atomic_t *lock, njt_atomic_uint_t old,
    njt_atomic_uint_t set)
{
    if (*lock == old) {
        *lock = set;
        return 1;
    }

    return 0;
}


static njt_inline njt_atomic_int_t
njt_atomic_fetch_add(njt_atomic_t *value, njt_atomic_int_t add)
{
    njt_atomic_int_t  old;

    old = *value;
    *value += add;

    return old;
}

#define njt_memory_barrier()
#define njt_cpu_pause()

#endif


void njt_spinlock(njt_atomic_t *lock, njt_atomic_int_t value, njt_uint_t spin);

#define njt_trylock(lock)  (*(lock) == 0 && njt_atomic_cmp_set(lock, 0, 1))
#define njt_unlock(lock)    *(lock) = 0


#endif /* _NJT_ATOMIC_H_INCLUDED_ */
