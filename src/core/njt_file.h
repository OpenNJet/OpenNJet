
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_FILE_H_INCLUDED_
#define _NJT_FILE_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


struct njt_file_s {
    njt_fd_t                   fd;
    njt_str_t                  name;
    njt_file_info_t            info;

    off_t                      offset;
    off_t                      sys_offset;

    njt_log_t                 *log;

#if (NJT_THREADS || NJT_COMPAT)
    njt_int_t                (*thread_handler)(njt_thread_task_t *task,
                                               njt_file_t *file);
    void                      *thread_ctx;
    njt_thread_task_t         *thread_task;
#endif

#if (NJT_HAVE_FILE_AIO || NJT_COMPAT)
    njt_event_aio_t           *aio;
#endif

    unsigned                   valid_info:1;
    unsigned                   directio:1;
};


#define NJT_MAX_PATH_LEVEL  3


typedef njt_msec_t (*njt_path_manager_pt) (void *data);
typedef njt_msec_t (*njt_path_purger_pt) (void *data);
typedef void (*njt_path_loader_pt) (void *data);


typedef struct {
    njt_str_t                  name;
    size_t                     len;
    size_t                     level[NJT_MAX_PATH_LEVEL];

    njt_path_manager_pt        manager;
    njt_path_purger_pt         purger;
    njt_path_loader_pt         loader;
    void                      *data;

    u_char                    *conf_file;
    njt_uint_t                 line;
} njt_path_t;


typedef struct {
    njt_str_t                  name;
    size_t                     level[NJT_MAX_PATH_LEVEL];
} njt_path_init_t;


typedef struct {
    njt_file_t                 file;
    off_t                      offset;
    njt_path_t                *path;
    njt_pool_t                *pool;
    char                      *warn;

    njt_uint_t                 access;

    unsigned                   log_level:8;
    unsigned                   persistent:1;
    unsigned                   clean:1;
    unsigned                   thread_write:1;
} njt_temp_file_t;


typedef struct {
    njt_uint_t                 access;
    njt_uint_t                 path_access;
    time_t                     time;
    njt_fd_t                   fd;

    unsigned                   create_path:1;
    unsigned                   delete_file:1;

    njt_log_t                 *log;
} njt_ext_rename_file_t;


typedef struct {
    off_t                      size;
    size_t                     buf_size;

    njt_uint_t                 access;
    time_t                     time;

    njt_log_t                 *log;
} njt_copy_file_t;


typedef struct njt_tree_ctx_s  njt_tree_ctx_t;

typedef njt_int_t (*njt_tree_init_handler_pt) (void *ctx, void *prev);
typedef njt_int_t (*njt_tree_handler_pt) (njt_tree_ctx_t *ctx, njt_str_t *name);

struct njt_tree_ctx_s {
    off_t                      size;
    off_t                      fs_size;
    njt_uint_t                 access;
    time_t                     mtime;

    njt_tree_init_handler_pt   init_handler;
    njt_tree_handler_pt        file_handler;
    njt_tree_handler_pt        pre_tree_handler;
    njt_tree_handler_pt        post_tree_handler;
    njt_tree_handler_pt        spec_handler;

    void                      *data;
    size_t                     alloc;

    njt_log_t                 *log;
};


njt_int_t njt_get_full_name(njt_pool_t *pool, njt_str_t *prefix,
    njt_str_t *name);

ssize_t njt_write_chain_to_temp_file(njt_temp_file_t *tf, njt_chain_t *chain);
njt_int_t njt_create_temp_file(njt_file_t *file, njt_path_t *path,
    njt_pool_t *pool, njt_uint_t persistent, njt_uint_t clean,
    njt_uint_t access);
void njt_create_hashed_filename(njt_path_t *path, u_char *file, size_t len);
njt_int_t njt_create_path(njt_file_t *file, njt_path_t *path);
njt_err_t njt_create_full_path(u_char *dir, njt_uint_t access);
njt_int_t njt_add_path(njt_conf_t *cf, njt_path_t **slot);
njt_int_t njt_create_paths(njt_cycle_t *cycle, njt_uid_t user);
njt_int_t njt_ext_rename_file(njt_str_t *src, njt_str_t *to,
    njt_ext_rename_file_t *ext);
njt_int_t njt_copy_file(u_char *from, u_char *to, njt_copy_file_t *cf);
njt_int_t njt_walk_tree(njt_tree_ctx_t *ctx, njt_str_t *tree);

njt_atomic_uint_t njt_next_temp_number(njt_uint_t collision);

char *njt_conf_set_path_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *njt_conf_merge_path_value(njt_conf_t *cf, njt_path_t **path,
    njt_path_t *prev, njt_path_init_t *init);
char *njt_conf_set_access_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf);


extern njt_atomic_t      *njt_temp_number;
extern njt_atomic_int_t   njt_random_number;


#endif /* _NJT_FILE_H_INCLUDED_ */
