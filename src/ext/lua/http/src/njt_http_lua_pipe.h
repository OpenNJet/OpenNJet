
/*
 * Copyright (C) by OpenResty Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_LUA_PIPE_H_INCLUDED_
#define _NJT_HTTP_LUA_PIPE_H_INCLUDED_


#include "njt_http_lua_common.h"


typedef njt_int_t (*njt_http_lua_pipe_input_filter)(void *data, ssize_t bytes);


typedef struct {
    njt_connection_t                   *c;
    njt_http_lua_pipe_input_filter      input_filter;
    void                               *input_filter_ctx;
    size_t                              rest;
    njt_chain_t                        *buf_in;
    njt_chain_t                        *bufs_in;
    njt_buf_t                           buffer;
    njt_err_t                           pipe_errno;
    unsigned                            err_type:16;
    unsigned                            eof:1;
} njt_http_lua_pipe_ctx_t;


typedef struct njt_http_lua_pipe_s  njt_http_lua_pipe_t;


typedef struct {
    njt_pid_t               _pid;
    njt_msec_t              write_timeout;
    njt_msec_t              stdout_read_timeout;
    njt_msec_t              stderr_read_timeout;
    njt_msec_t              wait_timeout;
    /* pipe hides the implementation from the Lua binding */
    njt_http_lua_pipe_t    *pipe;
} njt_http_lua_ffi_pipe_proc_t;


typedef int (*njt_http_lua_pipe_retval_handler)(
    njt_http_lua_ffi_pipe_proc_t *proc, lua_State *L);


struct njt_http_lua_pipe_s {
    njt_pool_t                         *pool;
    njt_chain_t                        *free_bufs;
    njt_rbtree_node_t                  *node;
    int                                 stdin_fd;
    int                                 stdout_fd;
    int                                 stderr_fd;
    njt_http_lua_pipe_ctx_t            *stdin_ctx;
    njt_http_lua_pipe_ctx_t            *stdout_ctx;
    njt_http_lua_pipe_ctx_t            *stderr_ctx;
    njt_http_lua_pipe_retval_handler    retval_handler;
    njt_http_cleanup_pt                *cleanup;
    njt_http_request_t                 *r;
    size_t                              buffer_size;
    unsigned                            closed:1;
    unsigned                            dead:1;
    unsigned                            timeout:1;
    unsigned                            merge_stderr:1;
};


typedef struct {
    u_char                           color;
    u_char                           reason_code;
    int                              status;
    njt_http_lua_co_ctx_t           *wait_co_ctx;
    njt_http_lua_ffi_pipe_proc_t    *proc;
} njt_http_lua_pipe_node_t;


typedef struct {
    int     signo;
    char   *signame;
} njt_http_lua_pipe_signal_t;


#if !(NJT_WIN32) && defined(HAVE_SOCKET_CLOEXEC_PATCH)
#define HAVE_NJT_LUA_PIPE   1


void njt_http_lua_pipe_init(void);
njt_int_t njt_http_lua_pipe_add_signal_handler(njt_cycle_t *cycle);
#endif


#endif /* _NJT_HTTP_LUA_PIPE_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
