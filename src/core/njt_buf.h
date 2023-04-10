
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_BUF_H_INCLUDED_
#define _NJT_BUF_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


typedef void *            njt_buf_tag_t;

typedef struct njt_buf_s  njt_buf_t;

struct njt_buf_s {
    u_char          *pos;
    u_char          *last;
    off_t            file_pos;
    off_t            file_last;

    u_char          *start;         /* start of buffer */
    u_char          *end;           /* end of buffer */
    njt_buf_tag_t    tag;
    njt_file_t      *file;
    njt_buf_t       *shadow;


    /* the buf's content could be changed */
    unsigned         temporary:1;

    /*
     * the buf's content is in a memory cache or in a read only memory
     * and must not be changed
     */
    unsigned         memory:1;

    /* the buf's content is mmap()ed and must not be changed */
    unsigned         mmap:1;

    unsigned         recycled:1;
    unsigned         in_file:1;
    unsigned         flush:1;
    unsigned         sync:1;
    unsigned         last_buf:1;
    unsigned         last_in_chain:1;

    unsigned         last_shadow:1;
    unsigned         temp_file:1;

    /* STUB */ int   num;
};


struct njt_chain_s {
    njt_buf_t    *buf;
    njt_chain_t  *next;
};


typedef struct {
    njt_int_t    num;
    size_t       size;
} njt_bufs_t;


typedef struct njt_output_chain_ctx_s  njt_output_chain_ctx_t;

typedef njt_int_t (*njt_output_chain_filter_pt)(void *ctx, njt_chain_t *in);

typedef void (*njt_output_chain_aio_pt)(njt_output_chain_ctx_t *ctx,
    njt_file_t *file);

struct njt_output_chain_ctx_s {
    njt_buf_t                   *buf;
    njt_chain_t                 *in;
    njt_chain_t                 *free;
    njt_chain_t                 *busy;

    unsigned                     sendfile:1;
    unsigned                     directio:1;
    unsigned                     unaligned:1;
    unsigned                     need_in_memory:1;
    unsigned                     need_in_temp:1;
    unsigned                     aio:1;

#if (NJT_HAVE_FILE_AIO || NJT_COMPAT)
    njt_output_chain_aio_pt      aio_handler;
#endif

#if (NJT_THREADS || NJT_COMPAT)
    njt_int_t                  (*thread_handler)(njt_thread_task_t *task,
                                                 njt_file_t *file);
    njt_thread_task_t           *thread_task;
#endif

    off_t                        alignment;

    njt_pool_t                  *pool;
    njt_int_t                    allocated;
    njt_bufs_t                   bufs;
    njt_buf_tag_t                tag;

    njt_output_chain_filter_pt   output_filter;
    void                        *filter_ctx;
};


typedef struct {
    njt_chain_t                 *out;
    njt_chain_t                **last;
    njt_connection_t            *connection;
    njt_pool_t                  *pool;
    off_t                        limit;
} njt_chain_writer_ctx_t;


#define NJT_CHAIN_ERROR     (njt_chain_t *) NJT_ERROR


#define njt_buf_in_memory(b)       ((b)->temporary || (b)->memory || (b)->mmap)
#define njt_buf_in_memory_only(b)  (njt_buf_in_memory(b) && !(b)->in_file)

#define njt_buf_special(b)                                                   \
    (((b)->flush || (b)->last_buf || (b)->sync)                              \
     && !njt_buf_in_memory(b) && !(b)->in_file)

#define njt_buf_sync_only(b)                                                 \
    ((b)->sync && !njt_buf_in_memory(b)                                      \
     && !(b)->in_file && !(b)->flush && !(b)->last_buf)

#define njt_buf_size(b)                                                      \
    (njt_buf_in_memory(b) ? (off_t) ((b)->last - (b)->pos):                  \
                            ((b)->file_last - (b)->file_pos))

njt_buf_t *njt_create_temp_buf(njt_pool_t *pool, size_t size);
njt_chain_t *njt_create_chain_of_bufs(njt_pool_t *pool, njt_bufs_t *bufs);


#define njt_alloc_buf(pool)  njt_palloc(pool, sizeof(njt_buf_t))
#define njt_calloc_buf(pool) njt_pcalloc(pool, sizeof(njt_buf_t))

njt_chain_t *njt_alloc_chain_link(njt_pool_t *pool);
#define njt_free_chain(pool, cl)                                             \
    (cl)->next = (pool)->chain;                                              \
    (pool)->chain = (cl)



njt_int_t njt_output_chain(njt_output_chain_ctx_t *ctx, njt_chain_t *in);
njt_int_t njt_chain_writer(void *ctx, njt_chain_t *in);

njt_int_t njt_chain_add_copy(njt_pool_t *pool, njt_chain_t **chain,
    njt_chain_t *in);
njt_chain_t *njt_chain_get_free_buf(njt_pool_t *p, njt_chain_t **free);
void njt_chain_update_chains(njt_pool_t *p, njt_chain_t **free,
    njt_chain_t **busy, njt_chain_t **out, njt_buf_tag_t tag);

off_t njt_chain_coalesce_file(njt_chain_t **in, off_t limit);

njt_chain_t *njt_chain_update_sent(njt_chain_t *in, off_t sent);

#endif /* _NJT_BUF_H_INCLUDED_ */
