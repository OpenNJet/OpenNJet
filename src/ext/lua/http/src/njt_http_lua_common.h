
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_LUA_COMMON_H_INCLUDED_
#define _NJT_HTTP_LUA_COMMON_H_INCLUDED_


#include "njt_http_lua_autoconf.h"

#include <njet.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_md5.h>

#include <setjmp.h>
#include <stdint.h>

#include <luajit.h>
#include <lualib.h>
#include <lauxlib.h>


#if defined(NDK) && NDK
#include <ndk.h>

typedef struct {
    size_t       size;
    int          ref;
    u_char      *key;
    u_char      *chunkname;
    njt_str_t    script;
} njt_http_lua_set_var_data_t;
#endif


#ifdef NJT_LUA_USE_ASSERT
#include <assert.h>
#   define njt_http_lua_assert(a)  assert(a)
#else
#   define njt_http_lua_assert(a)
#endif


/**
 * max positive +1.7976931348623158e+308
 * min positive +2.2250738585072014e-308
 */
#ifndef NJT_DOUBLE_LEN
#define NJT_DOUBLE_LEN  25
#endif


#if (NJT_PCRE)
#   if (NJT_PCRE2)
#       define LUA_HAVE_PCRE_JIT 1
#   else

#include <pcre.h>

#       if (PCRE_MAJOR > 8) || (PCRE_MAJOR == 8 && PCRE_MINOR >= 21)
#           define LUA_HAVE_PCRE_JIT 1
#       else
#           define LUA_HAVE_PCRE_JIT 0
#       endif
#   endif
#endif


#if (njet_version < 1006000)
#   error at least njet 1.6.0 is required but found an older version
#endif

#if LUA_VERSION_NUM != 501
#   error unsupported Lua language version
#endif

#if !defined(LUAJIT_VERSION_NUM) || (LUAJIT_VERSION_NUM < 20000)
#   error unsupported LuaJIT version
#endif


#if (!defined OPENSSL_NO_OCSP && defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB)
#   define NJT_HTTP_LUA_USE_OCSP 1
#endif

#ifndef NJT_HTTP_PERMANENT_REDIRECT
#   define NJT_HTTP_PERMANENT_REDIRECT 308
#endif

#ifndef NJT_HAVE_SHA1
#   if (njet_version >= 1011002)
#       define NJT_HAVE_SHA1 1
#   endif
#endif

#ifndef MD5_DIGEST_LENGTH
#   define MD5_DIGEST_LENGTH 16
#endif

#ifndef NJT_HTTP_LUA_MAX_ARGS
#   define NJT_HTTP_LUA_MAX_ARGS 100
#endif

#ifndef NJT_HTTP_LUA_MAX_HEADERS
#   define NJT_HTTP_LUA_MAX_HEADERS 100
#endif


/* Nginx HTTP Lua Inline tag prefix */

#define NJT_HTTP_LUA_INLINE_TAG "nhli_"

#define NJT_HTTP_LUA_INLINE_TAG_LEN                                          \
    (sizeof(NJT_HTTP_LUA_INLINE_TAG) - 1)

#define NJT_HTTP_LUA_INLINE_KEY_LEN                                          \
    (NJT_HTTP_LUA_INLINE_TAG_LEN + 2 * MD5_DIGEST_LENGTH)

/* Nginx HTTP Lua File tag prefix */

#define NJT_HTTP_LUA_FILE_TAG "nhlf_"

#define NJT_HTTP_LUA_FILE_TAG_LEN                                            \
    (sizeof(NJT_HTTP_LUA_FILE_TAG) - 1)

#define NJT_HTTP_LUA_FILE_KEY_LEN                                            \
    (NJT_HTTP_LUA_FILE_TAG_LEN + 2 * MD5_DIGEST_LENGTH)


/* must be within 16 bit */
#define NJT_HTTP_LUA_CONTEXT_SET                0x0001
#define NJT_HTTP_LUA_CONTEXT_REWRITE            0x0002
#define NJT_HTTP_LUA_CONTEXT_ACCESS             0x0004
#define NJT_HTTP_LUA_CONTEXT_CONTENT            0x0008
#define NJT_HTTP_LUA_CONTEXT_LOG                0x0010
#define NJT_HTTP_LUA_CONTEXT_HEADER_FILTER      0x0020
#define NJT_HTTP_LUA_CONTEXT_BODY_FILTER        0x0040
#define NJT_HTTP_LUA_CONTEXT_TIMER              0x0080
#define NJT_HTTP_LUA_CONTEXT_INIT_WORKER        0x0100
#define NJT_HTTP_LUA_CONTEXT_BALANCER           0x0200
#define NJT_HTTP_LUA_CONTEXT_SSL_CERT           0x0400
#define NJT_HTTP_LUA_CONTEXT_SSL_SESS_STORE     0x0800
#define NJT_HTTP_LUA_CONTEXT_SSL_SESS_FETCH     0x1000
#define NJT_HTTP_LUA_CONTEXT_EXIT_WORKER        0x2000
#define NJT_HTTP_LUA_CONTEXT_SSL_CLIENT_HELLO   0x4000
#define NJT_HTTP_LUA_CONTEXT_SERVER_REWRITE     0x8000


#define NJT_HTTP_LUA_FFI_NO_REQ_CTX         -100
#define NJT_HTTP_LUA_FFI_BAD_CONTEXT        -101


#if (NJT_PTR_SIZE >= 8 && !defined(_WIN64))
#   define njt_http_lua_lightudata_mask(ludata)                              \
        ((void *) ((uintptr_t) (&njt_http_lua_##ludata) & ((1UL << 47) - 1)))
#else
#   define njt_http_lua_lightudata_mask(ludata)                              \
        (&njt_http_lua_##ludata)
#endif


typedef struct njt_http_lua_co_ctx_s  njt_http_lua_co_ctx_t;

typedef struct njt_http_lua_sema_mm_s  njt_http_lua_sema_mm_t;

typedef union njt_http_lua_srv_conf_u  njt_http_lua_srv_conf_t;

typedef struct njt_http_lua_main_conf_s  njt_http_lua_main_conf_t;

typedef struct njt_http_lua_header_val_s  njt_http_lua_header_val_t;

typedef struct njt_http_lua_posted_thread_s  njt_http_lua_posted_thread_t;

typedef struct njt_http_lua_balancer_peer_data_s
    njt_http_lua_balancer_peer_data_t;

typedef njt_int_t (*njt_http_lua_main_conf_handler_pt)(njt_log_t *log,
    njt_http_lua_main_conf_t *lmcf, lua_State *L);

typedef njt_int_t (*njt_http_lua_srv_conf_handler_pt)(njt_http_request_t *r,
    njt_http_lua_srv_conf_t *lscf, lua_State *L);

typedef njt_int_t (*njt_http_lua_set_header_pt)(njt_http_request_t *r,
    njt_http_lua_header_val_t *hv, njt_str_t *value);


typedef struct {
    u_char              *package;
    lua_CFunction        loader;
} njt_http_lua_preload_hook_t;


typedef struct {
    int             ref;
    lua_State      *co;
    njt_queue_t     queue;
} njt_http_lua_thread_ref_t;


struct njt_http_lua_main_conf_s {
    lua_State           *lua;
    njt_pool_cleanup_t  *vm_cleanup;

    njt_str_t            lua_path;
    njt_str_t            lua_cpath;

    njt_cycle_t         *cycle;
    njt_pool_t          *pool;

    njt_int_t            max_pending_timers;
    njt_int_t            pending_timers;

    njt_int_t            max_running_timers;
    njt_int_t            running_timers;

    njt_connection_t    *watcher;  /* for watching the process exit event */

    njt_int_t            lua_thread_cache_max_entries;

    njt_hash_t           builtin_headers_out;

#if (NJT_PCRE)
    njt_int_t            regex_cache_entries;
    njt_int_t            regex_cache_max_entries;
    njt_int_t            regex_match_limit;
#endif

#if (LUA_HAVE_PCRE_JIT)
#if (NJT_PCRE2)
    pcre2_jit_stack     *jit_stack;
#else
    pcre_jit_stack      *jit_stack;
#endif
#endif

    njt_array_t         *shm_zones;  /* of njt_shm_zone_t* */

    njt_array_t         *shdict_zones; /* shm zones of "shdict" */

    njt_array_t         *preload_hooks; /* of njt_http_lua_preload_hook_t */

    njt_flag_t           postponed_to_rewrite_phase_end;
    njt_flag_t           postponed_to_access_phase_end;

    njt_http_lua_main_conf_handler_pt    init_handler;
    njt_str_t                            init_src;
    u_char                              *init_chunkname;

    njt_http_lua_main_conf_handler_pt    init_worker_handler;
    njt_str_t                            init_worker_src;
    u_char                              *init_worker_chunkname;

    njt_http_lua_main_conf_handler_pt    exit_worker_handler;
    njt_str_t                            exit_worker_src;
    u_char                              *exit_worker_chunkname;

    njt_http_lua_balancer_peer_data_t      *balancer_peer_data;
                    /* neither yielding nor recursion is possible in
                     * balancer_by_lua*, so there cannot be any races among
                     * concurrent requests and it is safe to store the peer
                     * data pointer in the main conf.
                     */

    njt_chain_t                            *body_filter_chain;
                    /* neither yielding nor recursion is possible in
                     * body_filter_by_lua*, so there cannot be any races among
                     * concurrent requests when storing the chain
                     * data pointer in the main conf.
                     */

    njt_http_variable_value_t              *setby_args;
                    /* neither yielding nor recursion is possible in
                     * set_by_lua*, so there cannot be any races among
                     * concurrent requests when storing the args pointer
                     * in the main conf.
                     */

    size_t                                  setby_nargs;
                    /* neither yielding nor recursion is possible in
                     * set_by_lua*, so there cannot be any races among
                     * concurrent requests when storing the nargs in the
                     * main conf.
                     */

    njt_uint_t                      shm_zones_inited;

    njt_http_lua_sema_mm_t         *sema_mm;

    njt_uint_t           malloc_trim_cycle;  /* a cycle is defined as the number
                                                of requests */
    njt_uint_t           malloc_trim_req_count;

    njt_uint_t           directive_line;

#if (njet_version >= 1011011)
    /* the following 2 fields are only used by njt.req.raw_headers() for now */
    njt_buf_t          **busy_buf_ptrs;
    njt_int_t            busy_buf_ptr_count;
#endif

    njt_int_t            host_var_index;

    njt_flag_t           set_sa_restart;

    njt_queue_t          free_lua_threads;  /* of njt_http_lua_thread_ref_t */
    njt_queue_t          cached_lua_threads;  /* of njt_http_lua_thread_ref_t */

    njt_uint_t           worker_thread_vm_pool_size;

    unsigned             requires_header_filter:1;
    unsigned             requires_body_filter:1;
    unsigned             requires_capture_filter:1;
    unsigned             requires_rewrite:1;
    unsigned             requires_access:1;
    unsigned             requires_log:1;
    unsigned             requires_shm:1;
    unsigned             requires_capture_log:1;
    unsigned             requires_server_rewrite:1;
};


union njt_http_lua_srv_conf_u {
    struct {
#if (NJT_HTTP_SSL)
        njt_http_lua_srv_conf_handler_pt     ssl_cert_handler;
        njt_str_t                            ssl_cert_src;
        u_char                              *ssl_cert_src_key;
        u_char                              *ssl_cert_chunkname;
        int                                  ssl_cert_src_ref;

        njt_http_lua_srv_conf_handler_pt     ssl_sess_store_handler;
        njt_str_t                            ssl_sess_store_src;
        u_char                              *ssl_sess_store_src_key;
        u_char                              *ssl_sess_store_chunkname;
        int                                  ssl_sess_store_src_ref;

        njt_http_lua_srv_conf_handler_pt     ssl_sess_fetch_handler;
        njt_str_t                            ssl_sess_fetch_src;
        u_char                              *ssl_sess_fetch_src_key;
        u_char                              *ssl_sess_fetch_chunkname;
        int                                  ssl_sess_fetch_src_ref;

        njt_http_lua_srv_conf_handler_pt     ssl_client_hello_handler;
        njt_str_t                            ssl_client_hello_src;
        u_char                              *ssl_client_hello_src_key;
        u_char                              *ssl_client_hello_chunkname;
        int                                  ssl_client_hello_src_ref;
#endif

        njt_http_lua_srv_conf_handler_pt     server_rewrite_handler;
        njt_http_complex_value_t             server_rewrite_src;
        u_char                              *server_rewrite_src_key;
        u_char                              *server_rewrite_chunkname;
        int                                  server_rewrite_src_ref;
    } srv;

    struct {
        njt_http_lua_srv_conf_handler_pt     handler;
        njt_str_t                            src;
        u_char                              *src_key;
        u_char                              *chunkname;
        int                                  src_ref;
    } balancer;
};


typedef struct {
#if (NJT_HTTP_SSL)
    njt_ssl_t              *ssl;  /* shared by SSL cosockets */
    njt_array_t            *ssl_certificates;
    njt_array_t            *ssl_certificate_keys;
    njt_uint_t              ssl_protocols;
    njt_str_t               ssl_ciphers;
    njt_uint_t              ssl_verify_depth;
    njt_str_t               ssl_trusted_certificate;
    njt_str_t               ssl_crl;
#if (njet_version >= 1019004)
    njt_array_t            *ssl_conf_commands;
#endif
#endif

    njt_flag_t              force_read_body; /* whether force request body to
                                                be read */

    njt_flag_t              enable_code_cache; /* whether to enable
                                                  code cache */

    njt_flag_t              http10_buffering;

    njt_http_handler_pt     rewrite_handler;
    njt_http_handler_pt     access_handler;
    njt_http_handler_pt     content_handler;
    njt_http_handler_pt     log_handler;
    njt_http_handler_pt     header_filter_handler;

    njt_http_output_body_filter_pt         body_filter_handler;



    u_char                  *rewrite_chunkname;
    njt_http_complex_value_t rewrite_src;    /*  rewrite_by_lua
                                                inline script/script
                                                file path */

    u_char                  *rewrite_src_key; /* cached key for rewrite_src */
    int                      rewrite_src_ref;

    u_char                  *access_chunkname;
    njt_http_complex_value_t access_src;     /*  access_by_lua
                                                inline script/script
                                                file path */

    u_char                  *access_src_key; /* cached key for access_src */
    int                      access_src_ref;

    u_char                  *content_chunkname;
    njt_http_complex_value_t content_src;    /*  content_by_lua
                                                inline script/script
                                                file path */

    u_char                 *content_src_key; /* cached key for content_src */
    int                     content_src_ref;


    u_char                      *log_chunkname;
    njt_http_complex_value_t     log_src;     /* log_by_lua inline script/script
                                                 file path */

    u_char                      *log_src_key; /* cached key for log_src */
    int                          log_src_ref;

    njt_http_complex_value_t header_filter_src;  /*  header_filter_by_lua
                                                     inline script/script
                                                     file path */

    u_char                 *header_filter_chunkname;
    u_char                 *header_filter_src_key;
                                    /* cached key for header_filter_src */
    int                     header_filter_src_ref;


    njt_http_complex_value_t         body_filter_src;
    u_char                          *body_filter_src_key;
    u_char                          *body_filter_chunkname;
    int                              body_filter_src_ref;

    njt_msec_t                       keepalive_timeout;
    njt_msec_t                       connect_timeout;
    njt_msec_t                       send_timeout;
    njt_msec_t                       read_timeout;

    size_t                           send_lowat;
    size_t                           buffer_size;

    njt_uint_t                       pool_size;

    njt_flag_t                       transform_underscores_in_resp_headers;
    njt_flag_t                       log_socket_errors;
    njt_flag_t                       check_client_abort;
    njt_flag_t                       use_default_type;
#ifdef NJT_HTTP_DYN_LUA_MODULE
    njt_int_t                        dynamic;
    njt_pool_t                       *conf_pool;
#endif
} njt_http_lua_loc_conf_t;


typedef enum {
    NJT_HTTP_LUA_USER_CORO_NOP      = 0,
    NJT_HTTP_LUA_USER_CORO_RESUME   = 1,
    NJT_HTTP_LUA_USER_CORO_YIELD    = 2,
    NJT_HTTP_LUA_USER_THREAD_RESUME = 3,
} njt_http_lua_user_coro_op_t;


typedef enum {
    NJT_HTTP_LUA_CO_RUNNING   = 0, /* coroutine running */
    NJT_HTTP_LUA_CO_SUSPENDED = 1, /* coroutine suspended */
    NJT_HTTP_LUA_CO_NORMAL    = 2, /* coroutine normal */
    NJT_HTTP_LUA_CO_DEAD      = 3, /* coroutine dead */
    NJT_HTTP_LUA_CO_ZOMBIE    = 4, /* coroutine zombie */
} njt_http_lua_co_status_t;


struct njt_http_lua_posted_thread_s {
    njt_http_lua_co_ctx_t               *co_ctx;
    njt_http_lua_posted_thread_t        *next;
};


struct njt_http_lua_co_ctx_s {
    void                    *data;      /* user state for cosockets */

    lua_State               *co;
    njt_http_lua_co_ctx_t   *parent_co_ctx;

    njt_http_lua_posted_thread_t    *zombie_child_threads;
    njt_http_lua_posted_thread_t   **next_zombie_child_thread;

    njt_http_cleanup_pt      cleanup;

    njt_int_t               *sr_statuses; /* all capture subrequest statuses */

    njt_http_headers_out_t **sr_headers;

    njt_str_t               *sr_bodies;   /* all captured subrequest bodies */

    uint8_t                 *sr_flags;

    unsigned                 nresults_from_worker_thread;  /* number of results
                                                            * from worker
                                                            * thread callback */
    unsigned                 nrets;     /* njt_http_lua_run_thread nrets arg. */

    unsigned                 nsubreqs;  /* number of subrequests of the
                                         * current request */

    unsigned                 pending_subreqs; /* number of subrequests being
                                                 waited */

    njt_event_t              sleep;  /* used for njt.sleep */

    njt_queue_t              sem_wait_queue;

#ifdef NJT_LUA_USE_ASSERT
    int                      co_top; /* stack top after yielding/creation,
                                        only for sanity checks */
#endif

    int                      co_ref; /*  reference to anchor the thread
                                         coroutines (entry coroutine and user
                                         threads) in the Lua registry,
                                         preventing the thread coroutine
                                         from beging collected by the
                                         Lua GC */

    unsigned                 waited_by_parent:1;  /* whether being waited by
                                                     a parent coroutine */

    unsigned                 co_status:3;  /* the current coroutine's status */

    unsigned                 flushing:1; /* indicates whether the current
                                            coroutine is waiting for
                                            njt.flush(true) */

    unsigned                 is_uthread:1; /* whether the current coroutine is
                                              a user thread */

    unsigned                 thread_spawn_yielded:1; /* yielded from
                                                        the njt.thread.spawn()
                                                        call */
    unsigned                 sem_resume_status:1;

    unsigned                 is_wrap:1; /* set when creating coroutines via
                                           coroutine.wrap */

    unsigned                 propagate_error:1; /* set when propagating an error
                                                   from a coroutine to its
                                                   parent */
};


typedef struct {
    lua_State       *vm;
    njt_int_t        count;
} njt_http_lua_vm_state_t;


typedef struct njt_http_lua_ctx_s {
    /* for lua_code_cache off: */
    njt_http_lua_vm_state_t  *vm_state;

    njt_http_request_t      *request;
    njt_http_handler_pt      resume_handler;

    njt_http_lua_co_ctx_t   *cur_co_ctx; /* co ctx for the current coroutine */

    /* FIXME: we should use rbtree here to prevent O(n) lookup overhead */
    njt_list_t              *user_co_ctx; /* coroutine contexts for user
                                             coroutines */

    njt_http_lua_co_ctx_t    entry_co_ctx; /* coroutine context for the
                                              entry coroutine */

    njt_http_lua_co_ctx_t   *on_abort_co_ctx; /* coroutine context for the
                                                 on_abort thread */

    int                      ctx_ref;  /*  reference to anchor
                                           request ctx data in lua
                                           registry */

    unsigned                 flushing_coros; /* number of coroutines waiting on
                                                njt.flush(true) */

    njt_chain_t             *out;  /* buffered output chain for HTTP 1.0 */
    njt_chain_t             *free_bufs;
    njt_chain_t             *busy_bufs;
    njt_chain_t             *free_recv_bufs;

    njt_chain_t             *filter_in_bufs;  /* for the body filter */
    njt_chain_t             *filter_busy_bufs;  /* for the body filter */

    njt_pool_cleanup_pt     *cleanup;

    njt_http_cleanup_t      *free_cleanup; /* free list of cleanup records */

    njt_chain_t             *body; /* buffered subrequest response body
                                      chains */

    njt_chain_t            **last_body; /* for the "body" field */

    njt_str_t                exec_uri;
    njt_str_t                exec_args;

    njt_int_t                exit_code;

    void                    *downstream;  /* can be either
                                             njt_http_lua_socket_tcp_upstream_t
                                             or njt_http_lua_co_ctx_t */

    njt_uint_t               index;              /* index of the current
                                                    subrequest in its parent
                                                    request */

    njt_http_lua_posted_thread_t   *posted_threads;

    int                      uthreads; /* number of active user threads */

    uint16_t                 context;   /* the current running directive context
                                           (or running phase) for the current
                                           Lua chunk */

    unsigned                 run_post_subrequest:1; /* whether it has run
                                                       post_subrequest
                                                       (for subrequests only) */

    unsigned                 waiting_more_body:1;   /* 1: waiting for more
                                                       request body data;
                                                       0: no need to wait */

    unsigned         co_op:2; /*  coroutine API operation */

    unsigned         exited:1;

    unsigned         eof:1;             /*  1: last_buf has been sent;
                                            0: last_buf not sent yet */

    unsigned         capture:1;  /*  1: response body of current request
                                        is to be captured by the lua
                                        capture filter,
                                     0: not to be captured */


    unsigned         read_body_done:1;      /* 1: request body has been all
                                               read; 0: body has not been
                                               all read */

    unsigned         headers_set:1; /* whether the user has set custom
                                       response headers */
    unsigned         mime_set:1;    /* whether the user has set Content-Type
                                       response header */
    unsigned         entered_server_rewrite_phase:1;
    unsigned         entered_rewrite_phase:1;
    unsigned         entered_access_phase:1;
    unsigned         entered_content_phase:1;

    unsigned         buffering:1; /* HTTP 1.0 response body buffering flag */

    unsigned         no_abort:1; /* prohibit "world abortion" via njt.exit()
                                    and etc */

    unsigned         header_sent:1; /* r->header_sent is not sufficient for
                                     * this because special header filters
                                     * like njt_image_filter may intercept
                                     * the header. so we should always test
                                     * both flags. see the test case in
                                     * t/020-subrequest.t */

    unsigned         seen_last_in_filter:1;  /* used by body_filter_by_lua* */
    unsigned         seen_last_for_subreq:1; /* used by body capture filter */
    unsigned         writing_raw_req_socket:1; /* used by raw downstream
                                                  socket */
    unsigned         acquired_raw_req_socket:1;  /* whether a raw req socket
                                                    is acquired */
    unsigned         seen_body_data:1;
} njt_http_lua_ctx_t;


struct njt_http_lua_header_val_s {
    njt_http_complex_value_t                value;
    njt_uint_t                              hash;
    njt_str_t                               key;
    njt_http_lua_set_header_pt              handler;
    njt_uint_t                              offset;
    unsigned                                no_override;
};


typedef struct {
    njt_str_t                               name;
    njt_uint_t                              offset;
    njt_http_lua_set_header_pt              handler;
} njt_http_lua_set_header_t;


extern njt_module_t njt_http_lua_module;
extern njt_http_output_header_filter_pt njt_http_lua_next_header_filter;
extern njt_http_output_body_filter_pt njt_http_lua_next_body_filter;


#endif /* _NJT_HTTP_LUA_COMMON_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
