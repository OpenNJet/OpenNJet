
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_LIST_H_INCLUDED_
#define _NJT_LIST_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


typedef struct njt_list_part_s  njt_list_part_t;

struct njt_list_part_s {
    void             *elts;
    njt_uint_t        nelts;
    njt_list_part_t  *next;
};


typedef struct {
    njt_list_part_t  *last;
    njt_list_part_t   part;
    size_t            size;
    njt_uint_t        nalloc;
    njt_pool_t       *pool;
} njt_list_t;


njt_list_t *njt_list_create(njt_pool_t *pool, njt_uint_t n, size_t size);

static njt_inline njt_int_t
njt_list_init(njt_list_t *list, njt_pool_t *pool, njt_uint_t n, size_t size)
{
    list->part.elts = njt_palloc(pool, n * size);
    if (list->part.elts == NULL) {
        return NJT_ERROR;
    }

    list->part.nelts = 0;
    list->part.next = NULL;
    list->last = &list->part;
    list->size = size;
    list->nalloc = n;
    list->pool = pool;

    return NJT_OK;
}


/*
 *
 *  the iteration through the list:
 *
 *  part = &list.part;
 *  data = part->elts;
 *
 *  for (i = 0 ;; i++) {
 *
 *      if (i >= part->nelts) {
 *          if (part->next == NULL) {
 *              break;
 *          }
 *
 *          part = part->next;
 *          data = part->elts;
 *          i = 0;
 *      }
 *
 *      ...  data[i] ...
 *
 *  }
 */


void *njt_list_push(njt_list_t *list);


#endif /* _NJT_LIST_H_INCLUDED_ */
