
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>


njt_rbtree_t              njt_event_timer_rbtree;
static njt_rbtree_node_t  njt_event_timer_sentinel;

/*
 * the event timer rbtree may contain the duplicate keys, however,
 * it should not be a problem, because we use the rbtree to find
 * a minimum timer value only
 */

njt_int_t
njt_event_timer_init(njt_log_t *log)
{
    njt_rbtree_init(&njt_event_timer_rbtree, &njt_event_timer_sentinel,
                    njt_rbtree_insert_timer_value);

    return NJT_OK;
}


njt_msec_t
njt_event_find_timer(void)
{
    njt_msec_int_t      timer;
    njt_rbtree_node_t  *node, *root, *sentinel;

    if (njt_event_timer_rbtree.root == &njt_event_timer_sentinel) {
        return NJT_TIMER_INFINITE;
    }

    root = njt_event_timer_rbtree.root;
    sentinel = njt_event_timer_rbtree.sentinel;

    node = njt_rbtree_min(root, sentinel);

    timer = (njt_msec_int_t) (node->key - njt_current_msec);

    return (njt_msec_t) (timer > 0 ? timer : 0);
}


void
njt_event_expire_timers(void)
{
    njt_event_t        *ev;
    njt_rbtree_node_t  *node, *root, *sentinel;

    sentinel = njt_event_timer_rbtree.sentinel;

    for ( ;; ) {
        root = njt_event_timer_rbtree.root;

        if (root == sentinel) {
            return;
        }

        node = njt_rbtree_min(root, sentinel);

        /* node->key > njt_current_msec */

        if ((njt_msec_int_t) (node->key - njt_current_msec) > 0) {
            return;
        }

        ev = njt_rbtree_data(node, njt_event_t, timer);

        // njt_log_debug2(NJT_LOG_DEBUG_EVENT, ev->log, 0,
        //                "event timer del: %d: %M",
        //                njt_event_ident(ev->data), ev->timer.key);

        njt_rbtree_delete(&njt_event_timer_rbtree, &ev->timer);

#if (NJT_DEBUG)
        ev->timer.left = NULL;
        ev->timer.right = NULL;
        ev->timer.parent = NULL;
#endif

        ev->timer_set = 0;

        ev->timedout = 1;

        ev->handler(ev);
    }
}


njt_int_t
njt_event_no_timers_left(void)
{
    njt_event_t        *ev;
    njt_rbtree_node_t  *node, *root, *sentinel;

    sentinel = njt_event_timer_rbtree.sentinel;
    root = njt_event_timer_rbtree.root;

    if (root == sentinel) {
        return NJT_OK;
    }

    for (node = njt_rbtree_min(root, sentinel);
         node;
         node = njt_rbtree_next(&njt_event_timer_rbtree, node))
    {
        ev = njt_rbtree_data(node, njt_event_t, timer);

        if (!ev->cancelable) {
            return NJT_AGAIN;
        }
    }

    /* only cancelable timers left */

    return NJT_OK;
}
