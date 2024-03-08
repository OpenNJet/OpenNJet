
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


njt_queue_t  njt_posted_accept_events;
njt_queue_t  njt_posted_next_events;
njt_queue_t  njt_posted_events;
njt_queue_t  njt_posted_delayed_events; // openresty patch


void
njt_event_process_posted(njt_cycle_t *cycle, njt_queue_t *posted)
{
    njt_queue_t  *q;
    njt_event_t  *ev;

    while (!njt_queue_empty(posted)) {

        q = njt_queue_head(posted);
        ev = njt_queue_data(q, njt_event_t, queue);

        njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                      "posted event %p", ev);

        njt_delete_posted_event(ev);

        ev->handler(ev);
    }
}


void
njt_event_move_posted_next(njt_cycle_t *cycle)
{
    njt_queue_t  *q;
    njt_event_t  *ev;

    for (q = njt_queue_head(&njt_posted_next_events);
         q != njt_queue_sentinel(&njt_posted_next_events);
         q = njt_queue_next(q))
    {
        ev = njt_queue_data(q, njt_event_t, queue);

        njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                      "posted next event %p", ev);

        ev->ready = 1;
        ev->available = -1;
    }

    njt_queue_add(&njt_posted_events, &njt_posted_next_events);
    njt_queue_init(&njt_posted_next_events);
}
