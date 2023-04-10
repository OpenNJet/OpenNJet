
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


#ifndef _NJT_OPEN_FILE_CACHE_H_INCLUDED_
#define _NJT_OPEN_FILE_CACHE_H_INCLUDED_


#define NJT_OPEN_FILE_DIRECTIO_OFF  NJT_MAX_OFF_T_VALUE


typedef struct {
    njt_fd_t                 fd;
    njt_file_uniq_t          uniq;
    time_t                   mtime;
    off_t                    size;
    off_t                    fs_size;
    off_t                    directio;
    size_t                   read_ahead;

    njt_err_t                err;
    char                    *failed;

    time_t                   valid;

    njt_uint_t               min_uses;

#if (NJT_HAVE_OPENAT)
    size_t                   disable_symlinks_from;
    unsigned                 disable_symlinks:2;
#endif

    unsigned                 test_dir:1;
    unsigned                 test_only:1;
    unsigned                 log:1;
    unsigned                 errors:1;
    unsigned                 events:1;

    unsigned                 is_dir:1;
    unsigned                 is_file:1;
    unsigned                 is_link:1;
    unsigned                 is_exec:1;
    unsigned                 is_directio:1;
} njt_open_file_info_t;


typedef struct njt_cached_open_file_s  njt_cached_open_file_t;

struct njt_cached_open_file_s {
    njt_rbtree_node_t        node;
    njt_queue_t              queue;

    u_char                  *name;
    time_t                   created;
    time_t                   accessed;

    njt_fd_t                 fd;
    njt_file_uniq_t          uniq;
    time_t                   mtime;
    off_t                    size;
    njt_err_t                err;

    uint32_t                 uses;

#if (NJT_HAVE_OPENAT)
    size_t                   disable_symlinks_from;
    unsigned                 disable_symlinks:2;
#endif

    unsigned                 count:24;
    unsigned                 close:1;
    unsigned                 use_event:1;

    unsigned                 is_dir:1;
    unsigned                 is_file:1;
    unsigned                 is_link:1;
    unsigned                 is_exec:1;
    unsigned                 is_directio:1;

    njt_event_t             *event;
};


typedef struct {
    njt_rbtree_t             rbtree;
    njt_rbtree_node_t        sentinel;
    njt_queue_t              expire_queue;

    njt_uint_t               current;
    njt_uint_t               max;
    time_t                   inactive;
} njt_open_file_cache_t;


typedef struct {
    njt_open_file_cache_t   *cache;
    njt_cached_open_file_t  *file;
    njt_uint_t               min_uses;
    njt_log_t               *log;
} njt_open_file_cache_cleanup_t;


typedef struct {

    /* njt_connection_t stub to allow use c->fd as event ident */
    void                    *data;
    njt_event_t             *read;
    njt_event_t             *write;
    njt_fd_t                 fd;

    njt_cached_open_file_t  *file;
    njt_open_file_cache_t   *cache;
} njt_open_file_cache_event_t;


njt_open_file_cache_t *njt_open_file_cache_init(njt_pool_t *pool,
    njt_uint_t max, time_t inactive);
njt_int_t njt_open_cached_file(njt_open_file_cache_t *cache, njt_str_t *name,
    njt_open_file_info_t *of, njt_pool_t *pool);


#endif /* _NJT_OPEN_FILE_CACHE_H_INCLUDED_ */
