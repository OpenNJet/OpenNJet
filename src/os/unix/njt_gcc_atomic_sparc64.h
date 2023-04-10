
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


/*
 * "casa   [r1] 0x80, r2, r0"  and
 * "casxa  [r1] 0x80, r2, r0"  do the following:
 *
 *     if ([r1] == r2) {
 *         swap(r0, [r1]);
 *     } else {
 *         r0 = [r1];
 *     }
 *
 * so "r0 == r2" means that the operation was successful.
 *
 *
 * The "r" means the general register.
 * The "+r" means the general register used for both input and output.
 */


#if (NJT_PTR_SIZE == 4)
#define NJT_CASA  "casa"
#else
#define NJT_CASA  "casxa"
#endif


static njt_inline njt_atomic_uint_t
njt_atomic_cmp_set(njt_atomic_t *lock, njt_atomic_uint_t old,
    njt_atomic_uint_t set)
{
    __asm__ volatile (

    NJT_CASA " [%1] 0x80, %2, %0"

    : "+r" (set) : "r" (lock), "r" (old) : "memory");

    return (set == old);
}


static njt_inline njt_atomic_int_t
njt_atomic_fetch_add(njt_atomic_t *value, njt_atomic_int_t add)
{
    njt_atomic_uint_t  old, res;

    old = *value;

    for ( ;; ) {

        res = old + add;

        __asm__ volatile (

        NJT_CASA " [%1] 0x80, %2, %0"

        : "+r" (res) : "r" (value), "r" (old) : "memory");

        if (res == old) {
            return res;
        }

        old = res;
    }
}


#if (NJT_SMP)
#define njt_memory_barrier()                                                  \
            __asm__ volatile (                                                \
            "membar #LoadLoad | #LoadStore | #StoreStore | #StoreLoad"        \
            ::: "memory")
#else
#define njt_memory_barrier()   __asm__ volatile ("" ::: "memory")
#endif

#define njt_cpu_pause()
