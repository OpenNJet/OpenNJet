
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_EVENT_POSTED_H_INCLUDED_
#define _NJT_EVENT_POSTED_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


#define njt_post_event(ev, q)                                                 \
                                                                              \
    if (!(ev)->posted) {                                                      \
        (ev)->posted = 1;                                                     \
        njt_queue_insert_tail(q, &(ev)->queue);                               \
                                                                              \
        njt_log_debug1(NJT_LOG_DEBUG_CORE, (ev)->log, 0, "post event %p", ev);\
                                                                              \
    } else  {                                                                 \
        njt_log_debug1(NJT_LOG_DEBUG_CORE, (ev)->log, 0,                      \
                       "update posted event %p", ev);                         \
    }


#define njt_delete_posted_event(ev)                                           \
                                                                              \
    (ev)->posted = 0;                                                         \
    njt_queue_remove(&(ev)->queue);                                           \
                                                                              \
    njt_log_debug1(NJT_LOG_DEBUG_CORE, (ev)->log, 0,                          \
                   "delete posted event %p", ev);



void njt_event_process_posted(njt_cycle_t *cycle, njt_queue_t *posted);
void njt_event_move_posted_next(njt_cycle_t *cycle);


extern njt_queue_t  njt_posted_accept_events;
extern njt_queue_t  njt_posted_next_events;
extern njt_queue_t  njt_posted_events;
extern njt_queue_t  njt_posted_delayed_events;

#define HAVE_POSTED_DELAYED_EVENTS_PATCH

#endif /* _NJT_EVENT_POSTED_H_INCLUDED_ */
