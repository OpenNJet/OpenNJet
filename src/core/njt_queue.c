
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>

static void njt_queue_merge(njt_queue_t *queue, njt_queue_t *tail,
    njt_int_t (*cmp)(const njt_queue_t *, const njt_queue_t *));


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


/* the stable merge sort */

void
njt_queue_sort(njt_queue_t *queue,
    njt_int_t (*cmp)(const njt_queue_t *, const njt_queue_t *))
{
    njt_queue_t  *q, tail;

    q = njt_queue_head(queue);

    if (q == njt_queue_last(queue)) {
        return;
    }

    q = njt_queue_middle(queue);

    njt_queue_split(queue, q, &tail);

    njt_queue_sort(queue, cmp);
    njt_queue_sort(&tail, cmp);

    njt_queue_merge(queue, &tail, cmp);
}


static void
njt_queue_merge(njt_queue_t *queue, njt_queue_t *tail,
    njt_int_t (*cmp)(const njt_queue_t *, const njt_queue_t *))
{
    njt_queue_t  *q1, *q2;

    q1 = njt_queue_head(queue);
    q2 = njt_queue_head(tail);

    for ( ;; ) {
        if (q1 == njt_queue_sentinel(queue)) {
            njt_queue_add(queue, tail);
            break;
        }

        if (q2 == njt_queue_sentinel(tail)) {
            break;
        }

        if (cmp(q1, q2) <= 0) {
            q1 = njt_queue_next(q1);
            continue;
        }

        njt_queue_remove(q2);
        njt_queue_insert_before(q1, q2);

        q2 = njt_queue_head(tail);
    }
}
