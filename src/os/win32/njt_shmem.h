
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_SHMEM_H_INCLUDED_
#define _NJT_SHMEM_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


typedef struct {
    u_char      *addr;
    size_t       size;
    njt_str_t    name;
    HANDLE       handle;
    njt_log_t   *log;
    njt_uint_t   exists;   /* unsigned  exists:1;  */
} njt_shm_t;


njt_int_t njt_shm_alloc(njt_shm_t *shm);
njt_int_t njt_shm_remap(njt_shm_t *shm, u_char *addr);
void njt_shm_free(njt_shm_t *shm);

extern njt_uint_t  njt_allocation_granularity;


#endif /* _NJT_SHMEM_H_INCLUDED_ */
