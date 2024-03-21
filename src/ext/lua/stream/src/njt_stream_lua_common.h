
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_common.h.tt2
 */


/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_STREAM_LUA_COMMON_H_INCLUDED_
#define _NJT_STREAM_LUA_COMMON_H_INCLUDED_


#include "njt_stream_lua_autoconf.h"

#include <njet.h>
#include <njt_core.h>
#include <njt_stream.h>
#include <njt_md5.h>

#include <setjmp.h>
#include <stdint.h>

#include <luajit.h>
#include <lualib.h>
#include <lauxlib.h>


#include "njt_stream_lua_request.h"


#if (NJT_PCRE)
#   if (NJT_PCRE2)
#      define LUA_HAVE_PCRE_JIT 1
#   else

#include <pcre.h>

#       if (PCRE_MAJOR > 8) || (PCRE_MAJOR == 8 && PCRE_MINOR >= 21)
#           define LUA_HAVE_PCRE_JIT 1
#       else
#           define LUA_HAVE_PCRE_JIT 0
#       endif
#   endif
#endif


#if !defined(njet_version) || njet_version < 1013006
#error at least njet 1.13.6 is required but found an older version
#endif




#if LUA_VERSION_NUM != 501
#   error unsupported Lua language version
#endif


#if !defined(LUAJIT_VERSION_NUM) || (LUAJIT_VERSION_NUM < 20000)
#   error unsupported LuaJIT version
#endif


#if (!defined OPENSSL_NO_OCSP && defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB)
#   define NJT_STREAM_LUA_USE_OCSP 1
#endif




#ifndef NJT_HAVE_SHA1
#   if defined(njet_version) && njet_version >= 1011002
#       define NJT_HAVE_SHA1  1
#   endif
#endif


#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16
#endif


#ifdef NJT_LUA_USE_ASSERT
#   include <assert.h>
#   define njt_stream_lua_assert(a)  assert(a)
#else
#   define njt_stream_lua_assert(a)
#endif


/* NJet HTTP Lua Inline tag prefix */

#define NJT_STREAM_LUA_INLINE_TAG "nhli_"

#define NJT_STREAM_LUA_INLINE_TAG_LEN                                        \
    (sizeof(NJT_STREAM_LUA_INLINE_TAG) - 1)

#define NJT_STREAM_LUA_INLINE_KEY_LEN                                        \
    (NJT_STREAM_LUA_INLINE_TAG_LEN + 2 * MD5_DIGEST_LENGTH)

/* NJet HTTP Lua File tag prefix */

#define NJT_STREAM_LUA_FILE_TAG "nhlf_"

#define NJT_STREAM_LUA_FILE_TAG_LEN                                          \
    (sizeof(NJT_STREAM_LUA_FILE_TAG) - 1)

#define NJT_STREAM_LUA_FILE_KEY_LEN                                          \
    (NJT_STREAM_LUA_FILE_TAG_LEN + 2 * MD5_DIGEST_LENGTH)


#define NJT_STREAM_CLIENT_CLOSED_REQUEST     499




#ifndef NJT_STREAM_LUA_MAX_ARGS
#define NJT_STREAM_LUA_MAX_ARGS 100
#endif


/* must be within 16 bit */
#define NJT_STREAM_LUA_CONTEXT_CONTENT                              0x0001
#define NJT_STREAM_LUA_CONTEXT_LOG                                  0x0002
#define NJT_STREAM_LUA_CONTEXT_TIMER                                0x0004
#define NJT_STREAM_LUA_CONTEXT_INIT_WORKER                          0x0008
#define NJT_STREAM_LUA_CONTEXT_BALANCER                             0x0010
#define NJT_STREAM_LUA_CONTEXT_PREREAD                              0x0020
#define NJT_STREAM_LUA_CONTEXT_SSL_CERT                             0x0040
#define NJT_STREAM_LUA_CONTEXT_SSL_CLIENT_HELLO                     0x0080


#define NJT_STREAM_LUA_FFI_NO_REQ_CTX         -100
#define NJT_STREAM_LUA_FFI_BAD_CONTEXT        -101


#if (NJT_PTR_SIZE >= 8 && !defined(_WIN64))
#define njt_stream_lua_lightudata_mask(ludata)                               \
    ((void *) ((uintptr_t) (&njt_stream_lua_##ludata) & ((1UL << 47) - 1)))

#else
#define njt_stream_lua_lightudata_mask(ludata)                               \
    (&njt_stream_lua_##ludata)
#endif


typedef struct njt_stream_lua_main_conf_s  njt_stream_lua_main_conf_t;
typedef struct njt_stream_lua_srv_conf_s  njt_stream_lua_srv_conf_t;


typedef struct njt_stream_lua_balancer_peer_data_s
    njt_stream_lua_balancer_peer_data_t;


typedef struct njt_stream_lua_sema_mm_s  njt_stream_lua_sema_mm_t;


typedef njt_int_t (*njt_stream_lua_main_conf_handler_pt)(njt_log_t *log,
    njt_stream_lua_main_conf_t *lmcf, lua_State *L);
typedef njt_int_t (*njt_stream_lua_srv_conf_handler_pt)(
    njt_stream_lua_request_t *r, njt_stream_lua_srv_conf_t *lscf, lua_State *L);


typedef struct {
    u_char              *package;
    lua_CFunction        loader;
} njt_stream_lua_preload_hook_t;


struct njt_stream_lua_main_conf_s {
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

    njt_array_t         *preload_hooks; /* of njt_stream_lua_preload_hook_t */

    njt_flag_t           postponed_to_preread_phase_end;

    njt_stream_lua_main_conf_handler_pt          init_handler;
    njt_str_t                                    init_src;

    njt_stream_lua_main_conf_handler_pt          init_worker_handler;
    njt_str_t                                    init_worker_src;

    njt_stream_lua_balancer_peer_data_t          *balancer_peer_data;
                    /* neither yielding nor recursion is possible in
                     * balancer_by_lua*, so there cannot be any races among
                     * concurrent requests and it is safe to store the peer
                     * data pointer in the main conf.
                     */

    njt_uint_t                      shm_zones_inited;

    njt_stream_lua_sema_mm_t               *sema_mm;

    njt_uint_t           malloc_trim_cycle;  /* a cycle is defined as the number
                                                of reqeusts */
    njt_uint_t           malloc_trim_req_count;


    njt_flag_t           set_sa_restart;

    unsigned             requires_preread:1;

    unsigned             requires_log:1;
    unsigned             requires_shm:1;
    unsigned             requires_capture_log:1;
};




struct njt_stream_lua_srv_conf_s {
#if (NJT_STREAM_SSL)
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

    struct {
        njt_stream_lua_srv_conf_handler_pt           ssl_cert_handler;
        njt_str_t                                    ssl_cert_src;
        u_char                                      *ssl_cert_src_key;

        njt_stream_lua_srv_conf_handler_pt           ssl_client_hello_handler;
        njt_str_t                                    ssl_client_hello_src;
        u_char                                      *ssl_client_hello_src_key;
    } srv;
#endif

    njt_flag_t              enable_code_cache; /* whether to enable
                                                  code cache */

    njt_stream_lua_handler_pt           preread_handler;

    njt_stream_lua_handler_pt           content_handler;
    njt_stream_lua_handler_pt           log_handler;

    u_char                      *preread_chunkname;
    njt_stream_complex_value_t   preread_src;     /* access_by_lua
                                                inline script/script
                                                file path */

    u_char                  *preread_src_key; /* cached key for access_src */

    u_char                  *content_chunkname;

    njt_stream_complex_value_t       content_src;
                                                  /* content_by_lua
                                                   * inline script/script
                                                   * file path */

    u_char                 *content_src_key; /* cached key for content_src */

    u_char                           *log_chunkname;
    njt_stream_complex_value_t        log_src;
                                              /* log_by_lua inline script/script
                                               * file path */

    u_char                                 *log_src_key;
    /* cached key for log_src */


    njt_msec_t                       keepalive_timeout;
    njt_msec_t                       connect_timeout;
    njt_msec_t                       send_timeout;
    njt_msec_t                       read_timeout;

    size_t                           send_lowat;
    size_t                           buffer_size;

    njt_uint_t                       pool_size;


    njt_flag_t                       log_socket_errors;
    njt_flag_t                       check_client_abort;


    struct {
        njt_str_t           src;
        u_char             *src_key;

        njt_stream_lua_srv_conf_handler_pt        handler;
    } balancer;

};

typedef njt_stream_lua_srv_conf_t njt_stream_lua_loc_conf_t;


typedef enum {
    NJT_STREAM_LUA_USER_CORO_NOP      = 0,
    NJT_STREAM_LUA_USER_CORO_RESUME   = 1,
    NJT_STREAM_LUA_USER_CORO_YIELD    = 2,
    NJT_STREAM_LUA_USER_THREAD_RESUME = 3
} njt_stream_lua_user_coro_op_t;


typedef enum {
    NJT_STREAM_LUA_CO_RUNNING   = 0, /* coroutine running */
    NJT_STREAM_LUA_CO_SUSPENDED = 1, /* coroutine suspended */
    NJT_STREAM_LUA_CO_NORMAL    = 2, /* coroutine normal */
    NJT_STREAM_LUA_CO_DEAD      = 3, /* coroutine dead */
    NJT_STREAM_LUA_CO_ZOMBIE    = 4, /* coroutine zombie */
} njt_stream_lua_co_status_t;


typedef struct njt_stream_lua_co_ctx_s  njt_stream_lua_co_ctx_t;

typedef struct njt_stream_lua_posted_thread_s  njt_stream_lua_posted_thread_t;

struct njt_stream_lua_posted_thread_s {
    njt_stream_lua_co_ctx_t                     *co_ctx;
    njt_stream_lua_posted_thread_t              *next;
};




struct njt_stream_lua_co_ctx_s {
    void                    *data;      /* user state for cosockets */

    lua_State                       *co;
    njt_stream_lua_co_ctx_t         *parent_co_ctx;

    njt_stream_lua_posted_thread_t          *zombie_child_threads;

    njt_stream_lua_cleanup_pt      cleanup;


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
} njt_stream_lua_vm_state_t;


typedef struct njt_stream_lua_ctx_s {
    /* for lua_coce_cache off: */
    njt_stream_lua_vm_state_t           *vm_state;

    njt_stream_lua_request_t            *request;
    njt_stream_lua_handler_pt            resume_handler;

    njt_stream_lua_co_ctx_t             *cur_co_ctx;
                                    /* co ctx for the current coroutine */

    /* FIXME: we should use rbtree here to prevent O(n) lookup overhead */
    njt_list_t              *user_co_ctx; /* coroutine contexts for user
                                             coroutines */

    njt_stream_lua_co_ctx_t    entry_co_ctx; /* coroutine context for the
                                              entry coroutine */

    njt_stream_lua_co_ctx_t   *on_abort_co_ctx; /* coroutine context for the
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

    njt_stream_lua_cleanup_pt  *cleanup;
    njt_stream_lua_cleanup_t   *free_cleanup; /* free list of cleanup records */



    njt_int_t                exit_code;

    void                    *downstream;
                                    /* can be either
                                     * njt_stream_lua_socket_tcp_upstream_t
                                     * or njt_stream_lua_co_ctx_t */


    njt_stream_lua_posted_thread_t         *posted_threads;

    int                      uthreads; /* number of active user threads */

    uint16_t                 context;   /* the current running directive context
                                           (or running phase) for the current
                                           Lua chunk */


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

    unsigned         entered_preread_phase:1;

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
    unsigned         peek_needs_more_data:1; /* whether req socket is waiting
                                               for more data in preread buf */
} njt_stream_lua_ctx_t;




extern njt_module_t njt_stream_lua_module;



#endif /* _NJT_STREAM_LUA_COMMON_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
