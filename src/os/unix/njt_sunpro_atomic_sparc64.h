
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#if (NJT_PTR_SIZE == 4)
#define NJT_CASA  njt_casa
#else
#define NJT_CASA  njt_casxa
#endif


njt_atomic_uint_t
njt_casa(njt_atomic_uint_t set, njt_atomic_uint_t old, njt_atomic_t *lock);

njt_atomic_uint_t
njt_casxa(njt_atomic_uint_t set, njt_atomic_uint_t old, njt_atomic_t *lock);

/* the code in src/os/unix/njt_sunpro_sparc64.il */


static njt_inline njt_atomic_uint_t
njt_atomic_cmp_set(njt_atomic_t *lock, njt_atomic_uint_t old,
    njt_atomic_uint_t set)
{
    set = NJT_CASA(set, old, lock);

    return (set == old);
}


static njt_inline njt_atomic_int_t
njt_atomic_fetch_add(njt_atomic_t *value, njt_atomic_int_t add)
{
    njt_atomic_uint_t  old, res;

    old = *value;

    for ( ;; ) {

        res = old + add;

        res = NJT_CASA(res, old, value);

        if (res == old) {
            return res;
        }

        old = res;
    }
}


#define njt_memory_barrier()                                                  \
        __asm (".volatile");                                                  \
        __asm ("membar #LoadLoad | #LoadStore | #StoreStore | #StoreLoad");   \
        __asm (".nonvolatile")

#define njt_cpu_pause()
