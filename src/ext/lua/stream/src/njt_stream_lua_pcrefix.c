
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_pcrefix.c.tt2
 */


/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_stream_lua_pcrefix.h"
#include "stdio.h"

#if (NJT_PCRE)

static njt_pool_t *njt_stream_lua_pcre_pool = NULL;

#if (NJT_PCRE2)
static njt_uint_t  njt_regex_direct_alloc;
#else
static void *(*old_pcre_malloc)(size_t);
static void (*old_pcre_free)(void *ptr);
#endif


/* XXX: work-around to njet regex subsystem, must init a memory pool
 * to use PCRE functions. As PCRE still has memory-leaking problems,
 * and njet overwrote pcre_malloc/free hooks with its own static
 * functions, so nobody else can reuse njet regex subsystem... */
#if (NJT_PCRE2)

void *
njt_stream_lua_pcre_malloc(size_t size, void *data)
{
    dd("lua pcre pool is %p", njt_stream_lua_pcre_pool);

    if (njt_stream_lua_pcre_pool) {
        return njt_palloc(njt_stream_lua_pcre_pool, size);
    }

    if (njt_regex_direct_alloc) {
        return njt_alloc(size, njt_cycle->log);
    }

    fprintf(stderr, "error: lua pcre malloc failed due to empty pcre pool");

    return NULL;
}


void
njt_stream_lua_pcre_free(void *ptr, void *data)
{
    dd("lua pcre pool is %p", njt_stream_lua_pcre_pool);

    if (njt_stream_lua_pcre_pool) {
        njt_pfree(njt_stream_lua_pcre_pool, ptr);
        return;
    }

    if (njt_regex_direct_alloc) {
        njt_free(ptr);
        return;
    }

    fprintf(stderr, "error: lua pcre free failed due to empty pcre pool");
}

#else

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

#endif


#if (NJT_PCRE2)

njt_pool_t *
njt_stream_lua_pcre_malloc_init(njt_pool_t *pool)
{
    njt_pool_t          *old_pool;

    dd("lua pcre pool was %p", njt_stream_lua_pcre_pool);

    njt_regex_direct_alloc = (pool == NULL) ? 1 : 0;

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
    njt_regex_direct_alloc = 0;

    dd("lua pcre pool is %p", njt_stream_lua_pcre_pool);
}

#else

njt_pool_t *
njt_stream_lua_pcre_malloc_init(njt_pool_t *pool)
{
    njt_pool_t          *old_pool;

    if (pcre_malloc != njt_stream_lua_pcre_malloc) {

        dd("overriding njet pcre malloc and free");

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

#endif
#endif /* NJT_PCRE */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
