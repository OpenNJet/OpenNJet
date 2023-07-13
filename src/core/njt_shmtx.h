
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_SHMTX_H_INCLUDED_
#define _NJT_SHMTX_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


typedef struct {
    njt_atomic_t   lock;
#if (NJT_HAVE_POSIX_SEM)
    njt_atomic_t   wait;
#endif
} njt_shmtx_sh_t;


typedef struct {
#if (NJT_HAVE_ATOMIC_OPS)
    njt_atomic_t  *lock;
#if (NJT_HAVE_POSIX_SEM)
    njt_atomic_t  *wait;
    njt_uint_t     semaphore;
    sem_t          sem;
#endif
#else
    njt_fd_t       fd;
    u_char        *name;
#endif
    njt_uint_t     spin;
} njt_shmtx_t;


typedef struct {
#if (NJT_HAVE_ATOMIC_OPS)
    njt_atomic_t  *lock;
#if (NJT_HAVE_POSIX_SEM)
    njt_atomic_t  *wait;
    njt_uint_t     semaphore;
    sem_t          sem;
#endif
#else
    njt_fd_t       fd;
    u_char        *name;
#endif
    njt_uint_t     spin;
#if (NJT_HAVE_ATOMIC_OPS)    
    njt_atomic_t   want;
#endif
} njt_shrwlock_t;


njt_int_t njt_shmtx_create(njt_shmtx_t *mtx, njt_shmtx_sh_t *addr,
    u_char *name);
void njt_shmtx_destroy(njt_shmtx_t *mtx);
njt_uint_t njt_shmtx_trylock(njt_shmtx_t *mtx);
void njt_shmtx_lock(njt_shmtx_t *mtx);
void njt_shmtx_unlock(njt_shmtx_t *mtx);
njt_uint_t njt_shmtx_force_unlock(njt_shmtx_t *mtx, njt_pid_t pid);

njt_int_t njt_shrwlock_create(njt_shrwlock_t *rwlock, njt_shmtx_sh_t *addr,
    u_char *name);
void njt_shrwlock_destroy(njt_shrwlock_t *rwlock);
void njt_shrwlock_rdlock(njt_shrwlock_t *rwlock);
void njt_shrwlock_wrlock(njt_shrwlock_t *rwlock);
void njt_shrwlock_rd2wrlock(njt_shrwlock_t *rwlock);
void njt_shrwlock_wr2rdlock(njt_shrwlock_t *rwlock);
void njt_shrwlock_unlock(njt_shrwlock_t *rwlock);


#endif /* _NJT_SHMTX_H_INCLUDED_ */
