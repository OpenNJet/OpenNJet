
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) TMLake, Inc.
 */


#ifndef _NJT_ARRAY_H_INCLUDED_
#define _NJT_ARRAY_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


typedef struct {
    void        *elts;
    njt_uint_t   nelts;
    size_t       size;
    njt_uint_t   nalloc;
    njt_pool_t  *pool;
} njt_array_t;


njt_array_t *njt_array_create(njt_pool_t *p, njt_uint_t n, size_t size);
void njt_array_destroy(njt_array_t *a);
void *njt_array_push(njt_array_t *a);
void *njt_array_push_n(njt_array_t *a, njt_uint_t n);


static njt_inline njt_int_t
njt_array_init(njt_array_t *array, njt_pool_t *pool, njt_uint_t n, size_t size)
{
    /*
     * set "array->nelts" before "array->elts", otherwise MSVC thinks
     * that "array->nelts" may be used without having been initialized
     */

    array->nelts = 0;
    array->size = size;
    array->nalloc = n;
    array->pool = pool;

    array->elts = njt_palloc(pool, n * size);
    if (array->elts == NULL) {
        return NJT_ERROR;
    }

    return NJT_OK;
}


#endif /* _NJT_ARRAY_H_INCLUDED_ */
