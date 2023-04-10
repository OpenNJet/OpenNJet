
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


/*
 * find the middle queue element if the queue has odd number of elements
 * or the first element of the queue's second part otherwise
 */

njt_queue_t *
njt_queue_middle(njt_queue_t *queue)
{
    njt_queue_t  *middle, *next;

    middle = njt_queue_head(queue);

    if (middle == njt_queue_last(queue)) {
        return middle;
    }

    next = njt_queue_head(queue);

    for ( ;; ) {
        middle = njt_queue_next(middle);

        next = njt_queue_next(next);

        if (next == njt_queue_last(queue)) {
            return middle;
        }

        next = njt_queue_next(next);

        if (next == njt_queue_last(queue)) {
            return middle;
        }
    }
}


/* the stable insertion sort */

void
njt_queue_sort(njt_queue_t *queue,
    njt_int_t (*cmp)(const njt_queue_t *, const njt_queue_t *))
{
    njt_queue_t  *q, *prev, *next;

    q = njt_queue_head(queue);

    if (q == njt_queue_last(queue)) {
        return;
    }

    for (q = njt_queue_next(q); q != njt_queue_sentinel(queue); q = next) {

        prev = njt_queue_prev(q);
        next = njt_queue_next(q);

        njt_queue_remove(q);

        do {
            if (cmp(prev, q) <= 0) {
                break;
            }

            prev = njt_queue_prev(prev);

        } while (prev != njt_queue_sentinel(queue));

        njt_queue_insert_after(prev, q);
    }
}
