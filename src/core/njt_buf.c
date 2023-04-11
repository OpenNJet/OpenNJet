
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


njt_buf_t *
njt_create_temp_buf(njt_pool_t *pool, size_t size)
{
    njt_buf_t *b;

    b = njt_calloc_buf(pool);
    if (b == NULL) {
        return NULL;
    }

    b->start = njt_palloc(pool, size);
    if (b->start == NULL) {
        return NULL;
    }

    /*
     * set by njt_calloc_buf():
     *
     *     b->file_pos = 0;
     *     b->file_last = 0;
     *     b->file = NULL;
     *     b->shadow = NULL;
     *     b->tag = 0;
     *     and flags
     */

    b->pos = b->start;
    b->last = b->start;
    b->end = b->last + size;
    b->temporary = 1;

    return b;
}


njt_chain_t *
njt_alloc_chain_link(njt_pool_t *pool)
{
    njt_chain_t  *cl;

    cl = pool->chain;

    if (cl) {
        pool->chain = cl->next;
        return cl;
    }

    cl = njt_palloc(pool, sizeof(njt_chain_t));
    if (cl == NULL) {
        return NULL;
    }

    return cl;
}


njt_chain_t *
njt_create_chain_of_bufs(njt_pool_t *pool, njt_bufs_t *bufs)
{
    u_char       *p;
    njt_int_t     i;
    njt_buf_t    *b;
    njt_chain_t  *chain, *cl, **ll;

    p = njt_palloc(pool, bufs->num * bufs->size);
    if (p == NULL) {
        return NULL;
    }

    ll = &chain;

    for (i = 0; i < bufs->num; i++) {

        b = njt_calloc_buf(pool);
        if (b == NULL) {
            return NULL;
        }

        /*
         * set by njt_calloc_buf():
         *
         *     b->file_pos = 0;
         *     b->file_last = 0;
         *     b->file = NULL;
         *     b->shadow = NULL;
         *     b->tag = 0;
         *     and flags
         *
         */

        b->pos = p;
        b->last = p;
        b->temporary = 1;

        b->start = p;
        p += bufs->size;
        b->end = p;

        cl = njt_alloc_chain_link(pool);
        if (cl == NULL) {
            return NULL;
        }

        cl->buf = b;
        *ll = cl;
        ll = &cl->next;
    }

    *ll = NULL;

    return chain;
}


njt_int_t
njt_chain_add_copy(njt_pool_t *pool, njt_chain_t **chain, njt_chain_t *in)
{
    njt_chain_t  *cl, **ll;

    ll = chain;

    for (cl = *chain; cl; cl = cl->next) {
        ll = &cl->next;
    }

    while (in) {
        cl = njt_alloc_chain_link(pool);
        if (cl == NULL) {
            *ll = NULL;
            return NJT_ERROR;
        }

        cl->buf = in->buf;
        *ll = cl;
        ll = &cl->next;
        in = in->next;
    }

    *ll = NULL;

    return NJT_OK;
}


njt_chain_t *
njt_chain_get_free_buf(njt_pool_t *p, njt_chain_t **free)
{
    njt_chain_t  *cl;

    if (*free) {
        cl = *free;
        *free = cl->next;
        cl->next = NULL;
        return cl;
    }

    cl = njt_alloc_chain_link(p);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = njt_calloc_buf(p);
    if (cl->buf == NULL) {
        return NULL;
    }

    cl->next = NULL;

    return cl;
}


void
njt_chain_update_chains(njt_pool_t *p, njt_chain_t **free, njt_chain_t **busy,
    njt_chain_t **out, njt_buf_tag_t tag)
{
    njt_chain_t  *cl;

    if (*out) {
        if (*busy == NULL) {
            *busy = *out;

        } else {
            for (cl = *busy; cl->next; cl = cl->next) { /* void */ }

            cl->next = *out;
        }

        *out = NULL;
    }

    while (*busy) {
        cl = *busy;

        if (cl->buf->tag != tag) {
            *busy = cl->next;
            njt_free_chain(p, cl);
            continue;
        }

        if (njt_buf_size(cl->buf) != 0) {
            break;
        }

        cl->buf->pos = cl->buf->start;
        cl->buf->last = cl->buf->start;

        *busy = cl->next;
        cl->next = *free;
        *free = cl;
    }
}


off_t
njt_chain_coalesce_file(njt_chain_t **in, off_t limit)
{
    off_t         total, size, aligned, fprev;
    njt_fd_t      fd;
    njt_chain_t  *cl;

    total = 0;

    cl = *in;
    fd = cl->buf->file->fd;

    do {
        size = cl->buf->file_last - cl->buf->file_pos;

        if (size > limit - total) {
            size = limit - total;

            aligned = (cl->buf->file_pos + size + njt_pagesize - 1)
                       & ~((off_t) njt_pagesize - 1);

            if (aligned <= cl->buf->file_last) {
                size = aligned - cl->buf->file_pos;
            }

            total += size;
            break;
        }

        total += size;
        fprev = cl->buf->file_pos + size;
        cl = cl->next;

    } while (cl
             && cl->buf->in_file
             && total < limit
             && fd == cl->buf->file->fd
             && fprev == cl->buf->file_pos);

    *in = cl;

    return total;
}


njt_chain_t *
njt_chain_update_sent(njt_chain_t *in, off_t sent)
{
    off_t  size;

    for ( /* void */ ; in; in = in->next) {

        if (njt_buf_special(in->buf)) {
            continue;
        }

        if (sent == 0) {
            break;
        }

        size = njt_buf_size(in->buf);

        if (sent >= size) {
            sent -= size;

            if (njt_buf_in_memory(in->buf)) {
                in->buf->pos = in->buf->last;
            }

            if (in->buf->in_file) {
                in->buf->file_pos = in->buf->file_last;
            }

            continue;
        }

        if (njt_buf_in_memory(in->buf)) {
            in->buf->pos += (size_t) sent;
        }

        if (in->buf->in_file) {
            in->buf->file_pos += sent;
        }

        break;
    }

    return in;
}
