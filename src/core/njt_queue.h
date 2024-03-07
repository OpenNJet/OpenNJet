
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


#ifndef _NJT_QUEUE_H_INCLUDED_
#define _NJT_QUEUE_H_INCLUDED_


typedef struct njt_queue_s  njt_queue_t;

struct njt_queue_s {
    njt_queue_t  *prev;
    njt_queue_t  *next;
};


#define njt_queue_init(q)                                                     \
    (q)->prev = q;                                                            \
    (q)->next = q


#define njt_queue_empty(h)                                                    \
    (h == (h)->prev)


#define njt_queue_insert_head(h, x)                                           \
    (x)->next = (h)->next;                                                    \
    (x)->next->prev = x;                                                      \
    (x)->prev = h;                                                            \
    (h)->next = x


#define njt_queue_insert_after   njt_queue_insert_head


#define njt_queue_insert_tail(h, x)                                           \
    (x)->prev = (h)->prev;                                                    \
    (x)->prev->next = x;                                                      \
    (x)->next = h;                                                            \
    (h)->prev = x


#define njt_queue_insert_before   njt_queue_insert_tail


#define njt_queue_head(h)                                                     \
    (h)->next


#define njt_queue_last(h)                                                     \
    (h)->prev


#define njt_queue_sentinel(h)                                                 \
    (h)


#define njt_queue_next(q)                                                     \
    (q)->next


#define njt_queue_prev(q)                                                     \
    (q)->prev


#if (NJT_DEBUG)

#define njt_queue_remove(x)                                                   \
    (x)->next->prev = (x)->prev;                                              \
    (x)->prev->next = (x)->next;                                              \
    (x)->prev = NULL;                                                         \
    (x)->next = NULL

#else

#define njt_queue_remove(x)                                                   \
    (x)->next->prev = (x)->prev;                                              \
    (x)->prev->next = (x)->next

#endif


#define njt_queue_split(h, q, n)                                              \
    (n)->prev = (h)->prev;                                                    \
    (n)->prev->next = n;                                                      \
    (n)->next = q;                                                            \
    (h)->prev = (q)->prev;                                                    \
    (h)->prev->next = h;                                                      \
    (q)->prev = n;


#define njt_queue_add(h, n)                                                   \
    (h)->prev->next = (n)->next;                                              \
    (n)->next->prev = (h)->prev;                                              \
    (h)->prev = (n)->prev;                                                    \
    (h)->prev->next = h;


#define njt_queue_data(q, type, link)                                         \
    (type *) ((u_char *) q - offsetof(type, link))


njt_queue_t *njt_queue_middle(njt_queue_t *queue);
void njt_queue_sort(njt_queue_t *queue,
    njt_int_t (*cmp)(const njt_queue_t *, const njt_queue_t *));


#endif /* _NJT_QUEUE_H_INCLUDED_ */
