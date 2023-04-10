
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_THREAD_H_INCLUDED_
#define _NJT_THREAD_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


typedef HANDLE  njt_tid_t;
typedef DWORD   njt_thread_value_t;


njt_err_t njt_create_thread(njt_tid_t *tid,
    njt_thread_value_t (__stdcall *func)(void *arg), void *arg, njt_log_t *log);

#define njt_log_tid                 GetCurrentThreadId()
#define NJT_TID_T_FMT               "%ud"


#endif /* _NJT_THREAD_H_INCLUDED_ */
