
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_pcrefix.c.tt2
 */


/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) TMLake, Inc.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_stream_lua_pcrefix.h"
#include "stdio.h"

#if (NJT_PCRE)

static njt_pool_t *njt_stream_lua_pcre_pool = NULL;

static void *(*old_pcre_malloc)(size_t);
static void (*old_pcre_free)(void *ptr);


/* XXX: work-around to nginx regex subsystem, must init a memory pool
 * to use PCRE functions. As PCRE still has memory-leaking problems,
 * and nginx overwrote pcre_malloc/free hooks with its own static
 * functions, so nobody else can reuse nginx regex subsystem... */
static void *
njt_stream_lua_pcre_malloc(size_t size)
{
    dd("lua pcre pool is %p", njt_stream_lua_pcre_pool);

    if (njt_stream_lua_pcre_pool) {
        return njt_palloc(njt_stream_lua_pcre_pool, size);
    }

    fprintf(stderr, "error: lua pcre malloc failed due to empty pcre pool");

    return NULL;
}


static void
njt_stream_lua_pcre_free(void *ptr)
{
    dd("lua pcre pool is %p", njt_stream_lua_pcre_pool);

    if (njt_stream_lua_pcre_pool) {
        njt_pfree(njt_stream_lua_pcre_pool, ptr);
        return;
    }

    fprintf(stderr, "error: lua pcre free failed due to empty pcre pool");
}


njt_pool_t *
njt_stream_lua_pcre_malloc_init(njt_pool_t *pool)
{
    njt_pool_t          *old_pool;

    if (pcre_malloc != njt_stream_lua_pcre_malloc) {

        dd("overriding nginx pcre malloc and free");

        njt_stream_lua_pcre_pool = pool;

        old_pcre_malloc = pcre_malloc;
        old_pcre_free = pcre_free;

        pcre_malloc = njt_stream_lua_pcre_malloc;
        pcre_free = njt_stream_lua_pcre_free;

        return NULL;
    }

    dd("lua pcre pool was %p", njt_stream_lua_pcre_pool);

    old_pool = njt_stream_lua_pcre_pool;
    njt_stream_lua_pcre_pool = pool;

    dd("lua pcre pool is %p", njt_stream_lua_pcre_pool);

    return old_pool;
}


void
njt_stream_lua_pcre_malloc_done(njt_pool_t *old_pool)
{
    dd("lua pcre pool was %p", njt_stream_lua_pcre_pool);

    njt_stream_lua_pcre_pool = old_pool;

    dd("lua pcre pool is %p", njt_stream_lua_pcre_pool);

    if (old_pool == NULL) {
        pcre_malloc = old_pcre_malloc;
        pcre_free = old_pcre_free;
    }
}

#endif /* NJT_PCRE */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
