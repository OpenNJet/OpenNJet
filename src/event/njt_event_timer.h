
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_EVENT_TIMER_H_INCLUDED_
#define _NJT_EVENT_TIMER_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


#define NJT_TIMER_INFINITE  (njt_msec_t) -1

#define NJT_TIMER_LAZY_DELAY  300


njt_int_t njt_event_timer_init(njt_log_t *log);
njt_msec_t njt_event_find_timer(void);
void njt_event_expire_timers(void);
njt_int_t njt_event_no_timers_left(void);


extern njt_rbtree_t  njt_event_timer_rbtree;


static njt_inline void
njt_event_del_timer(njt_event_t *ev)
{
    // njt_log_debug2(NJT_LOG_DEBUG_EVENT, ev->log, 0,
    //                "event timer del: %d: %M",
    //                 njt_event_ident(ev->data), ev->timer.key);

    njt_rbtree_delete(&njt_event_timer_rbtree, &ev->timer);

#if (NJT_DEBUG)
    ev->timer.left = NULL;
    ev->timer.right = NULL;
    ev->timer.parent = NULL;
#endif

    ev->timer_set = 0;
}


static njt_inline void
njt_event_add_timer(njt_event_t *ev, njt_msec_t timer)
{
    njt_msec_t      key;
    njt_msec_int_t  diff;

    key = njt_current_msec + timer;

    if (ev->timer_set) {

        /*
         * Use a previous timer value if difference between it and a new
         * value is less than NJT_TIMER_LAZY_DELAY milliseconds: this allows
         * to minimize the rbtree operations for fast connections.
         */

        diff = (njt_msec_int_t) (key - ev->timer.key);

        if (njt_abs(diff) < NJT_TIMER_LAZY_DELAY) {
            njt_log_debug3(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                           "event timer: %d, old: %M, new: %M",
                            njt_event_ident(ev->data), ev->timer.key, key);
            return;
        }

        njt_del_timer(ev);
    }

    ev->timer.key = key;

    // njt_log_debug3(NJT_LOG_DEBUG_EVENT, ev->log, 0,
    //                "event timer add: %d: %M:%M",
    //                 njt_event_ident(ev->data), timer, ev->timer.key);

    njt_rbtree_insert(&njt_event_timer_rbtree, &ev->timer);

    ev->timer_set = 1;
}


#endif /* _NJT_EVENT_TIMER_H_INCLUDED_ */
