
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_CACHE_H_INCLUDED_
#define _NJT_HTTP_CACHE_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


#define NJT_HTTP_CACHE_MISS          1
#define NJT_HTTP_CACHE_BYPASS        2
#define NJT_HTTP_CACHE_EXPIRED       3
#define NJT_HTTP_CACHE_STALE         4
#define NJT_HTTP_CACHE_UPDATING      5
#define NJT_HTTP_CACHE_REVALIDATED   6
#define NJT_HTTP_CACHE_HIT           7
#define NJT_HTTP_CACHE_SCARCE        8

#define NJT_HTTP_CACHE_KEY_LEN       16
#define NJT_HTTP_CACHE_ETAG_LEN      128
#define NJT_HTTP_CACHE_VARY_LEN      128

#define NJT_HTTP_CACHE_VERSION       5


typedef struct {
    njt_uint_t                       status;
    time_t                           valid;
} njt_http_cache_valid_t;
//by chengxu
#if (NJT_HTTP_CACHE_PURGE)
//分片过滤器部分的代码
typedef struct {
    size_t               size;
} njt_http_slice_loc_conf_t;
extern njt_module_t  njt_http_slice_filter_module;
#endif
// end
typedef struct {
    njt_rbtree_node_t                node;
    //by chengxu
#if (NJT_HTTP_CACHE_PURGE)
    //增加请求key
    njt_str_t                        request_key;
    njt_str_t                        file_key;
#endif
    // end
    njt_queue_t                      queue;

    u_char                           key[NJT_HTTP_CACHE_KEY_LEN
                                         - sizeof(njt_rbtree_key_t)];

    unsigned                         count:20;
    unsigned                         uses:10;
    unsigned                         valid_msec:10;
    unsigned                         error:10;
    unsigned                         exists:1;
    unsigned                         updating:1;
    unsigned                         deleting:1;
    unsigned                         purged:1;
                                     /* 10 unused bits */

    njt_file_uniq_t                  uniq;
    time_t                           expire;
    time_t                           valid_sec;
    size_t                           body_start;
    off_t                            fs_size;
    njt_msec_t                       lock_time;
} njt_http_file_cache_node_t;


struct njt_http_cache_s {
    njt_file_t                       file;
    njt_array_t                      keys;
    uint32_t                         crc32;
    u_char                           key[NJT_HTTP_CACHE_KEY_LEN];
    u_char                           main[NJT_HTTP_CACHE_KEY_LEN];
    // by chengxu
#if (NJT_HTTP_CACHE)
    //增加请求key
    njt_str_t                       request_key;
    njt_array_t                      file_keys;
#endif
    //end
    njt_file_uniq_t                  uniq;
    time_t                           valid_sec;
    time_t                           updating_sec;
    time_t                           error_sec;
    time_t                           last_modified;
    time_t                           date;

    njt_str_t                        etag;
    njt_str_t                        vary;
    u_char                           variant[NJT_HTTP_CACHE_KEY_LEN];

    size_t                           buffer_size;
    size_t                           header_start;
    size_t                           body_start;
    off_t                            length;
    off_t                            fs_size;

    njt_uint_t                       min_uses;
    njt_uint_t                       error;
    njt_uint_t                       valid_msec;
    njt_uint_t                       vary_tag;

    njt_buf_t                       *buf;

    njt_http_file_cache_t           *file_cache;
    njt_http_file_cache_node_t      *node;

#if (NJT_THREADS || NJT_COMPAT)
    njt_thread_task_t               *thread_task;
#endif

    njt_msec_t                       lock_timeout;
    njt_msec_t                       lock_age;
    njt_msec_t                       lock_time;
    njt_msec_t                       wait_time;

    njt_event_t                      wait_event;

    unsigned                         lock:1;
    unsigned                         waiting:1;

    unsigned                         updated:1;
    unsigned                         updating:1;
    unsigned                         exists:1;
    unsigned                         temp_file:1;
    unsigned                         purged:1;
    unsigned                         reading:1;
    unsigned                         secondary:1;
    unsigned                         update_variant:1;
    unsigned                         background:1;

    unsigned                         stale_updating:1;
    unsigned                         stale_error:1;
};


typedef struct {
    njt_uint_t                       version;
    time_t                           valid_sec;
    time_t                           updating_sec;
    time_t                           error_sec;
    time_t                           last_modified;
    time_t                           date;
    uint32_t                         crc32;
    u_short                          valid_msec;
    u_short                          header_start;
    u_short                          body_start;
    u_char                           etag_len;
    u_char                           etag[NJT_HTTP_CACHE_ETAG_LEN];
    u_char                           vary_len;
    u_char                           vary[NJT_HTTP_CACHE_VARY_LEN];
    u_char                           variant[NJT_HTTP_CACHE_KEY_LEN];
} njt_http_file_cache_header_t;


typedef struct {
    njt_rbtree_t                     rbtree;
    njt_rbtree_node_t                sentinel;
    njt_queue_t                      queue;
    njt_atomic_t                     cold;
    njt_atomic_t                     loading;
    off_t                            size;
    njt_uint_t                       count;
    njt_uint_t                       watermark;
} njt_http_file_cache_sh_t;


struct njt_http_file_cache_s {
    njt_http_file_cache_sh_t        *sh;
    njt_slab_pool_t                 *shpool;

    njt_path_t                      *path;

    off_t                            min_free;
    off_t                            max_size;
    size_t                           bsize;

    time_t                           inactive;

    time_t                           fail_time;

    njt_uint_t                       files;
    njt_uint_t                       loader_files;
    njt_msec_t                       last;
    njt_msec_t                       loader_sleep;
    njt_msec_t                       loader_threshold;

    njt_uint_t                       manager_files;
    njt_msec_t                       manager_sleep;
    njt_msec_t                       manager_threshold;

    // by chengxu
#if (NJT_HTTP_CACHE_PURGE)
    njt_uint_t                       purger_files;
    njt_msec_t                       purger_sleep;
    njt_msec_t                       purger_threshold;
#endif
    //end

    njt_shm_zone_t                  *shm_zone;

    njt_uint_t                       use_temp_path;
                                     /* unsigned use_temp_path:1 */
};


njt_int_t njt_http_file_cache_new(njt_http_request_t *r);
njt_int_t njt_http_file_cache_create(njt_http_request_t *r);
void njt_http_file_cache_create_key(njt_http_request_t *r);
njt_int_t njt_http_file_cache_open(njt_http_request_t *r);
njt_int_t njt_http_file_cache_set_header(njt_http_request_t *r, u_char *buf);
void njt_http_file_cache_update(njt_http_request_t *r, njt_temp_file_t *tf);
void njt_http_file_cache_update_header(njt_http_request_t *r);
njt_int_t njt_http_cache_send(njt_http_request_t *);
void njt_http_file_cache_free(njt_http_cache_t *c, njt_temp_file_t *tf);
time_t njt_http_file_cache_valid(njt_array_t *cache_valid, njt_uint_t status);

char *njt_http_file_cache_set_slot(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
char *njt_http_file_cache_valid_set_slot(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);


extern njt_str_t  njt_http_cache_status[];
// by chengxu
#if (NJT_HTTP_CACHE_PURGE)
// 删除所有文件缓存
njt_int_t njt_http_file_cache_purge_one_cache_files(njt_http_file_cache_t *cache);
//删除指定文件
njt_int_t njt_http_file_cache_purge_one_file(njt_http_request_t *r);
//清理指定路径缓存文件
njt_int_t njt_http_file_cache_purge_one_path(njt_http_request_t *r);
//生成request_key
njt_int_t njt_http_file_cache_set_request_key(njt_http_request_t *r);
#endif
//end

#endif /* _NJT_HTTP_CACHE_H_INCLUDED_ */
