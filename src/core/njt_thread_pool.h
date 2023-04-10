
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 * Copyright (C) Valentin V. Bartenev
 */


#ifndef _NJT_THREAD_POOL_H_INCLUDED_
#define _NJT_THREAD_POOL_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


struct njt_thread_task_s {
    njt_thread_task_t   *next;
    njt_uint_t           id;
    void                *ctx;
    void               (*handler)(void *data, njt_log_t *log);
    njt_event_t          event;
};


typedef struct njt_thread_pool_s  njt_thread_pool_t;


njt_thread_pool_t *njt_thread_pool_add(njt_conf_t *cf, njt_str_t *name);
njt_thread_pool_t *njt_thread_pool_get(njt_cycle_t *cycle, njt_str_t *name);

njt_thread_task_t *njt_thread_task_alloc(njt_pool_t *pool, size_t size);
njt_int_t njt_thread_task_post(njt_thread_pool_t *tp, njt_thread_task_t *task);


#endif /* _NJT_THREAD_POOL_H_INCLUDED_ */
