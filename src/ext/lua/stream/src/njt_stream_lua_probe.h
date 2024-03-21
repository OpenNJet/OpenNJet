
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_probe.h.tt2
 */

/*
 * automatically generated from the file dtrace/njt_lua_provider.d by the
 *  gen-dtrace-probe-header tool in the njet-devel-utils project:
 *  https://github.com/agentzh/njet-devel-utils
 */

#ifndef _NJT_STREAM_LUA_PROBE_H_INCLUDED_
#define _NJT_STREAM_LUA_PROBE_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>




#if defined(NJT_DTRACE) && NJT_DTRACE

#include <njt_dtrace_provider.h>

#define njt_stream_lua_probe_info(s)                                         \
    NJET_LUA_HTTP_LUA_INFO(s)

#define njt_stream_lua_probe_register_preload_package(L, pkg)                \
    NJET_LUA_HTTP_LUA_REGISTER_PRELOAD_PACKAGE(L, pkg)

#define njt_stream_lua_probe_req_socket_consume_preread(r, data, len)        \
    NJET_LUA_HTTP_LUA_REQ_SOCKET_CONSUME_PREREAD(r, data, len)

#define njt_stream_lua_probe_user_coroutine_create(r, parent, child)         \
    NJET_LUA_HTTP_LUA_USER_COROUTINE_CREATE(r, parent, child)

#define njt_stream_lua_probe_user_coroutine_resume(r, parent, child)         \
    NJET_LUA_HTTP_LUA_USER_COROUTINE_RESUME(r, parent, child)

#define njt_stream_lua_probe_user_coroutine_yield(r, parent, child)          \
    NJET_LUA_HTTP_LUA_USER_COROUTINE_YIELD(r, parent, child)

#define njt_stream_lua_probe_thread_yield(r, L)                              \
    NJET_LUA_HTTP_LUA_THREAD_YIELD(r, L)

#define njt_stream_lua_probe_socket_tcp_send_start(r, u, data, len)          \
    NJET_LUA_HTTP_LUA_SOCKET_TCP_SEND_START(r, u, data, len)

#define njt_stream_lua_probe_socket_tcp_receive_done(r, u, data, len)        \
    NJET_LUA_HTTP_LUA_SOCKET_TCP_RECEIVE_DONE(r, u, data, len)

#define njt_stream_lua_probe_socket_tcp_setkeepalive_buf_unread(r, u,        \
                                                                data,        \
                                                                len)         \
    NJET_LUA_HTTP_LUA_SOCKET_TCP_SETKEEPALIVE_BUF_UNREAD(r, u, data, len)

#define njt_stream_lua_probe_user_thread_spawn(r, creator, newthread)        \
    NJET_LUA_HTTP_LUA_USER_THREAD_SPAWN(r, creator, newthread)

#define njt_stream_lua_probe_thread_delete(r, thread, ctx)                   \
    NJET_LUA_HTTP_LUA_THREAD_DELETE(r, thread, ctx)

#define njt_stream_lua_probe_run_posted_thread(r, thread, status)            \
    NJET_LUA_HTTP_LUA_RUN_POSTED_THREAD(r, thread, status)

#define njt_stream_lua_probe_coroutine_done(r, co, success)                  \
    NJET_LUA_HTTP_LUA_COROUTINE_DONE(r, co, success)

#define njt_stream_lua_probe_user_thread_wait(parent, child)                 \
    NJET_LUA_HTTP_LUA_USER_THREAD_WAIT(parent, child)

#else /* !(NJT_DTRACE) */

#define njt_stream_lua_probe_info(s)
#define njt_stream_lua_probe_register_preload_package(L, pkg)
#define njt_stream_lua_probe_req_socket_consume_preread(r, data, len)
#define njt_stream_lua_probe_user_coroutine_create(r, parent, child)
#define njt_stream_lua_probe_user_coroutine_resume(r, parent, child)
#define njt_stream_lua_probe_user_coroutine_yield(r, parent, child)
#define njt_stream_lua_probe_thread_yield(r, L)
#define njt_stream_lua_probe_socket_tcp_send_start(r, u, data, len)
#define njt_stream_lua_probe_socket_tcp_receive_done(r, u, data, len)
#define njt_stream_lua_probe_socket_tcp_setkeepalive_buf_unread(r, u, data, len)
#define njt_stream_lua_probe_user_thread_spawn(r, creator, newthread)
#define njt_stream_lua_probe_thread_delete(r, thread, ctx)
#define njt_stream_lua_probe_run_posted_thread(r, thread, status)
#define njt_stream_lua_probe_coroutine_done(r, co, success)
#define njt_stream_lua_probe_user_thread_wait(parent, child)

#endif

#endif /* _NJT_STREAM_LUA_PROBE_H_INCLUDED_ */
