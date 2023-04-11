
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


njt_list_t *
njt_list_create(njt_pool_t *pool, njt_uint_t n, size_t size)
{
    njt_list_t  *list;

    list = njt_palloc(pool, sizeof(njt_list_t));
    if (list == NULL) {
        return NULL;
    }

    if (njt_list_init(list, pool, n, size) != NJT_OK) {
        return NULL;
    }

    return list;
}


void *
njt_list_push(njt_list_t *l)
{
    void             *elt;
    njt_list_part_t  *last;

    last = l->last;

    if (last->nelts == l->nalloc) {

        /* the last part is full, allocate a new list part */

        last = njt_palloc(l->pool, sizeof(njt_list_part_t));
        if (last == NULL) {
            return NULL;
        }

        last->elts = njt_palloc(l->pool, l->nalloc * l->size);
        if (last->elts == NULL) {
            return NULL;
        }

        last->nelts = 0;
        last->next = NULL;

        l->last->next = last;
        l->last = last;
    }

    elt = (char *) last->elts + l->size * last->nelts;
    last->nelts++;

    return elt;
}
