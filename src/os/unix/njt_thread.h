
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_THREAD_H_INCLUDED_
#define _NJT_THREAD_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>

#if (NJT_THREADS)

#include <pthread.h>


typedef pthread_mutex_t  njt_thread_mutex_t;

njt_int_t njt_thread_mutex_create(njt_thread_mutex_t *mtx, njt_log_t *log);
njt_int_t njt_thread_mutex_destroy(njt_thread_mutex_t *mtx, njt_log_t *log);
njt_int_t njt_thread_mutex_lock(njt_thread_mutex_t *mtx, njt_log_t *log);
njt_int_t njt_thread_mutex_unlock(njt_thread_mutex_t *mtx, njt_log_t *log);


typedef pthread_cond_t  njt_thread_cond_t;

njt_int_t njt_thread_cond_create(njt_thread_cond_t *cond, njt_log_t *log);
njt_int_t njt_thread_cond_destroy(njt_thread_cond_t *cond, njt_log_t *log);
njt_int_t njt_thread_cond_signal(njt_thread_cond_t *cond, njt_log_t *log);
njt_int_t njt_thread_cond_wait(njt_thread_cond_t *cond, njt_thread_mutex_t *mtx,
    njt_log_t *log);


#if (NJT_LINUX)

typedef pid_t      njt_tid_t;
#define NJT_TID_T_FMT         "%P"

#elif (NJT_FREEBSD)

typedef uint32_t   njt_tid_t;
#define NJT_TID_T_FMT         "%uD"

#elif (NJT_DARWIN)

typedef uint64_t   njt_tid_t;
#define NJT_TID_T_FMT         "%uL"

#else

typedef uint64_t   njt_tid_t;
#define NJT_TID_T_FMT         "%uL"

#endif

njt_tid_t njt_thread_tid(void);

#define njt_log_tid           njt_thread_tid()

#else

#define njt_log_tid           0
#define NJT_TID_T_FMT         "%d"

#endif


#endif /* _NJT_THREAD_H_INCLUDED_ */
