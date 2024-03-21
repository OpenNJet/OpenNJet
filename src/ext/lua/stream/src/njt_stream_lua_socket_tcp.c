
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_socket_tcp.c.tt2
 */


/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_stream_lua_socket_tcp.h"
#include "njt_stream_lua_input_filters.h"
#include "njt_stream_lua_util.h"
#include "njt_stream_lua_uthread.h"
#include "njt_stream_lua_output.h"
#include "njt_stream_lua_contentby.h"
#include "njt_stream_lua_probe.h"


static int njt_stream_lua_socket_tcp(lua_State *L);
static int njt_stream_lua_socket_tcp_connect(lua_State *L);
#if (NJT_STREAM_SSL)
static int njt_stream_lua_socket_tcp_sslhandshake(lua_State *L);
#endif
static int njt_stream_lua_socket_tcp_receive(lua_State *L);
static int njt_stream_lua_socket_tcp_receiveany(lua_State *L);
static int njt_stream_lua_socket_tcp_send(lua_State *L);
static int njt_stream_lua_socket_tcp_close(lua_State *L);
static int njt_stream_lua_socket_tcp_setoption(lua_State *L);
static int njt_stream_lua_socket_tcp_settimeout(lua_State *L);
static int njt_stream_lua_socket_tcp_settimeouts(lua_State *L);
static void njt_stream_lua_socket_tcp_handler(njt_event_t *ev);
static njt_int_t njt_stream_lua_socket_tcp_get_peer(njt_peer_connection_t *pc,
    void *data);
static void njt_stream_lua_socket_init_peer_connection_addr_text(
    njt_peer_connection_t *pc);
static void njt_stream_lua_socket_read_handler(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u);
static void njt_stream_lua_socket_send_handler(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u);
static void njt_stream_lua_socket_connected_handler(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u);
static void njt_stream_lua_socket_tcp_cleanup(void *data);
static void njt_stream_lua_socket_tcp_finalize(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u);
static void njt_stream_lua_socket_tcp_finalize_read_part(
    njt_stream_lua_request_t *r, njt_stream_lua_socket_tcp_upstream_t *u);
static void njt_stream_lua_socket_tcp_finalize_write_part(
    njt_stream_lua_request_t *r, njt_stream_lua_socket_tcp_upstream_t *u,
    int do_shutdown);

static njt_int_t njt_stream_lua_socket_send(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u);
static njt_int_t njt_stream_lua_socket_test_connect(njt_stream_lua_request_t *r,
    njt_connection_t *c);
static void njt_stream_lua_socket_handle_conn_error(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u, njt_uint_t ft_type);
static void njt_stream_lua_socket_handle_read_error(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u, njt_uint_t ft_type);
static void njt_stream_lua_socket_handle_write_error(
    njt_stream_lua_request_t *r, njt_stream_lua_socket_tcp_upstream_t *u,
    njt_uint_t ft_type);
static void njt_stream_lua_socket_handle_conn_success(
    njt_stream_lua_request_t *r, njt_stream_lua_socket_tcp_upstream_t *u);
static void njt_stream_lua_socket_handle_read_success(
    njt_stream_lua_request_t *r, njt_stream_lua_socket_tcp_upstream_t *u);
static void njt_stream_lua_socket_handle_write_success(
    njt_stream_lua_request_t *r, njt_stream_lua_socket_tcp_upstream_t *u);
static int njt_stream_lua_socket_tcp_send_retval_handler(
    njt_stream_lua_request_t *r, njt_stream_lua_socket_tcp_upstream_t *u,
    lua_State *L);
static int njt_stream_lua_socket_tcp_conn_retval_handler(
    njt_stream_lua_request_t *r, njt_stream_lua_socket_tcp_upstream_t *u,
    lua_State *L);
static void njt_stream_lua_socket_dummy_handler(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u);
static int njt_stream_lua_socket_tcp_receive_helper(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u, lua_State *L);
static njt_int_t njt_stream_lua_socket_tcp_read(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u);
static int njt_stream_lua_socket_tcp_receive_retval_handler(
    njt_stream_lua_request_t *r, njt_stream_lua_socket_tcp_upstream_t *u,
    lua_State *L);
static njt_int_t njt_stream_lua_socket_read_line(void *data, ssize_t bytes);
static void njt_stream_lua_socket_resolve_handler(njt_resolver_ctx_t *ctx);
static int njt_stream_lua_socket_resolve_retval_handler(
    njt_stream_lua_request_t *r, njt_stream_lua_socket_tcp_upstream_t *u,
    lua_State *L);
static int njt_stream_lua_socket_conn_error_retval_handler(
    njt_stream_lua_request_t *r, njt_stream_lua_socket_tcp_upstream_t *u,
    lua_State *L);
static int njt_stream_lua_socket_read_error_retval_handler(
    njt_stream_lua_request_t *r, njt_stream_lua_socket_tcp_upstream_t *u,
    lua_State *L);
static int njt_stream_lua_socket_write_error_retval_handler(
    njt_stream_lua_request_t *r, njt_stream_lua_socket_tcp_upstream_t *u,
    lua_State *L);
static njt_int_t njt_stream_lua_socket_read_all(void *data, ssize_t bytes);
static njt_int_t njt_stream_lua_socket_read_until(void *data, ssize_t bytes);
static njt_int_t njt_stream_lua_socket_read_chunk(void *data, ssize_t bytes);
static njt_int_t njt_stream_lua_socket_read_any(void *data, ssize_t bytes);
static int njt_stream_lua_socket_tcp_receiveuntil(lua_State *L);
static int njt_stream_lua_socket_receiveuntil_iterator(lua_State *L);
static njt_int_t njt_stream_lua_socket_compile_pattern(u_char *data, size_t len,
    njt_stream_lua_socket_compiled_pattern_t *cp, njt_log_t *log);
static int njt_stream_lua_socket_cleanup_compiled_pattern(lua_State *L);
static void njt_stream_lua_req_socket_rev_handler(njt_stream_lua_request_t *r);
static int njt_stream_lua_socket_tcp_getreusedtimes(lua_State *L);
static int njt_stream_lua_socket_tcp_setkeepalive(lua_State *L);
static void njt_stream_lua_socket_tcp_create_socket_pool(lua_State *L,
    njt_stream_lua_request_t *r, njt_str_t key, njt_int_t pool_size,
    njt_int_t backlog, njt_stream_lua_socket_pool_t **spool);
static njt_int_t njt_stream_lua_get_keepalive_peer(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u);
static void njt_stream_lua_socket_keepalive_dummy_handler(njt_event_t *ev);
static int njt_stream_lua_socket_tcp_connect_helper(lua_State *L,
    njt_stream_lua_socket_tcp_upstream_t *u, njt_stream_lua_request_t *r,
    njt_stream_lua_ctx_t *ctx, u_char *host_ref, size_t host_len,
    in_port_t port, unsigned resuming);
static void njt_stream_lua_socket_tcp_conn_op_timeout_handler(
    njt_event_t *ev);
static int njt_stream_lua_socket_tcp_conn_op_timeout_retval_handler(
    njt_stream_lua_request_t *r, njt_stream_lua_socket_tcp_upstream_t *u,
    lua_State *L);
static void njt_stream_lua_socket_tcp_resume_conn_op(
    njt_stream_lua_socket_pool_t *spool);
static void njt_stream_lua_socket_tcp_conn_op_ctx_cleanup(void *data);
static void njt_stream_lua_socket_tcp_conn_op_resume_handler(njt_event_t *ev);
static njt_int_t njt_stream_lua_socket_keepalive_close_handler(njt_event_t *ev);
static void njt_stream_lua_socket_keepalive_rev_handler(njt_event_t *ev);
static int njt_stream_lua_socket_tcp_conn_op_resume_retval_handler(
    njt_stream_lua_request_t *r, njt_stream_lua_socket_tcp_upstream_t *u,
    lua_State *L);
static int njt_stream_lua_socket_tcp_upstream_destroy(lua_State *L);
static int njt_stream_lua_socket_downstream_destroy(lua_State *L);
static njt_int_t njt_stream_lua_socket_push_input_data(
    njt_stream_lua_request_t *r, njt_stream_lua_ctx_t *ctx,
    njt_stream_lua_socket_tcp_upstream_t *u, lua_State *L);
static njt_int_t njt_stream_lua_socket_add_pending_data(
    njt_stream_lua_request_t *r, njt_stream_lua_socket_tcp_upstream_t *u,
    u_char *pos, size_t len, u_char *pat, int prefix, int old_state);
static njt_int_t njt_stream_lua_socket_add_input_buffer(
    njt_stream_lua_request_t *r, njt_stream_lua_socket_tcp_upstream_t *u);
static njt_int_t njt_stream_lua_socket_insert_buffer(
    njt_stream_lua_request_t *r, njt_stream_lua_socket_tcp_upstream_t *u,
    u_char *pat, size_t prefix);
static njt_int_t njt_stream_lua_socket_tcp_conn_op_resume(
    njt_stream_lua_request_t *r);
static njt_int_t njt_stream_lua_socket_tcp_conn_resume(
    njt_stream_lua_request_t *r);
static njt_int_t njt_stream_lua_socket_tcp_read_resume(
    njt_stream_lua_request_t *r);
static njt_int_t njt_stream_lua_socket_tcp_write_resume(
    njt_stream_lua_request_t *r);
static njt_int_t njt_stream_lua_socket_tcp_resume_helper(
    njt_stream_lua_request_t *r, int socket_op);
static void njt_stream_lua_tcp_queue_conn_op_cleanup(void *data);
static void njt_stream_lua_tcp_resolve_cleanup(void *data);
static void njt_stream_lua_coctx_cleanup(void *data);
static void njt_stream_lua_socket_free_pool(njt_log_t *log,
    njt_stream_lua_socket_pool_t *spool);
static int njt_stream_lua_socket_shutdown_pool(lua_State *L);
static void njt_stream_lua_socket_shutdown_pool_helper(
    njt_stream_lua_socket_pool_t *spool);
static int njt_stream_lua_socket_prepare_error_retvals(
    njt_stream_lua_request_t *r, njt_stream_lua_socket_tcp_upstream_t *u,
    lua_State *L, njt_uint_t ft_type);
#if (NJT_STREAM_SSL)
static int njt_stream_lua_ssl_handshake_retval_handler(
    njt_stream_lua_request_t *r, njt_stream_lua_socket_tcp_upstream_t *u,
    lua_State *L);
static void njt_stream_lua_ssl_handshake_handler(njt_connection_t *c);
static int njt_stream_lua_ssl_free_session(lua_State *L);
#endif
static void njt_stream_lua_socket_tcp_close_connection(njt_connection_t *c);

static int njt_stream_lua_socket_tcp_peek(lua_State *L);
static njt_int_t njt_stream_lua_socket_tcp_peek_resume(njt_stream_lua_request_t *r);
static int njt_stream_lua_socket_tcp_shutdown(lua_State *L);


enum {
    SOCKET_CTX_INDEX = 1,
    SOCKET_KEY_INDEX = 3,
    SOCKET_CONNECT_TIMEOUT_INDEX = 2,
    SOCKET_SEND_TIMEOUT_INDEX = 4,
    SOCKET_READ_TIMEOUT_INDEX = 5,
};


enum {
    SOCKET_OP_CONNECT,
    SOCKET_OP_READ,
    SOCKET_OP_WRITE,
    SOCKET_OP_RESUME_CONN
};


#define njt_stream_lua_socket_check_busy_connecting(r, u, L)                 \
    if ((u)->conn_waiting) {                                                 \
        lua_pushnil(L);                                                      \
        lua_pushliteral(L, "socket busy connecting");                        \
        return 2;                                                            \
    }


#define njt_stream_lua_socket_check_busy_reading(r, u, L)                    \
    if ((u)->read_waiting) {                                                 \
        lua_pushnil(L);                                                      \
        lua_pushliteral(L, "socket busy reading");                           \
        return 2;                                                            \
    }


#define njt_stream_lua_socket_check_busy_writing(r, u, L)                    \
    if ((u)->write_waiting) {                                                \
        lua_pushnil(L);                                                      \
        lua_pushliteral(L, "socket busy writing");                           \
        return 2;                                                            \
    }                                                                        \
    if ((u)->raw_downstream                                                  \
        && ((r)->connection->buffered))                                      \
    {                                                                        \
        lua_pushnil(L);                                                      \
        lua_pushliteral(L, "socket busy writing");                           \
        return 2;                                                            \
    }



static char njt_stream_lua_raw_req_socket_metatable_key;
static char njt_stream_lua_tcp_socket_metatable_key;
static char njt_stream_lua_upstream_udata_metatable_key;
static char njt_stream_lua_downstream_udata_metatable_key;
static char njt_stream_lua_pool_udata_metatable_key;
static char njt_stream_lua_pattern_udata_metatable_key;
#if (NJT_STREAM_SSL)
static char njt_stream_lua_ssl_session_metatable_key;
#endif


void
njt_stream_lua_inject_socket_tcp_api(njt_log_t *log, lua_State *L)
{
    njt_int_t         rc;

    lua_createtable(L, 0, 4 /* nrec */);    /* njt.socket */

    lua_pushcfunction(L, njt_stream_lua_socket_tcp);
    lua_pushvalue(L, -1);
    lua_setfield(L, -3, "tcp");
    lua_setfield(L, -2, "stream");

    {
        const char  buf[] = "local sock = njt.socket.tcp()"
                            " local ok, err = sock:connect(...)"
                            " if ok then return sock else return nil, err end";

        rc = luaL_loadbuffer(L, buf, sizeof(buf) - 1, "=njt.socket.connect");
    }

    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_CRIT, log, 0,
                      "failed to load Lua code for njt.socket.connect(): %i",
                      rc);

    } else {
        lua_setfield(L, -2, "connect");
    }

    lua_setfield(L, -2, "socket");


    /* {{{raw req socket object metatable */
    lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(
                          raw_req_socket_metatable_key));
    lua_createtable(L, 0 /* narr */, 9 /* nrec */);

    lua_pushcfunction(L, njt_stream_lua_socket_tcp_receive);
    lua_setfield(L, -2, "receive");

    lua_pushcfunction(L, njt_stream_lua_socket_tcp_receiveany);
    lua_setfield(L, -2, "receiveany");

    lua_pushcfunction(L, njt_stream_lua_socket_tcp_receiveuntil);
    lua_setfield(L, -2, "receiveuntil");

    lua_pushcfunction(L, njt_stream_lua_socket_tcp_send);
    lua_setfield(L, -2, "send");

    lua_pushcfunction(L, njt_stream_lua_socket_tcp_settimeout);
    lua_setfield(L, -2, "settimeout"); /* njt socket mt */

    lua_pushcfunction(L, njt_stream_lua_socket_tcp_settimeouts);
    lua_setfield(L, -2, "settimeouts"); /* njt socket mt */

    lua_pushcfunction(L, njt_stream_lua_socket_tcp_peek);
    lua_setfield(L, -2, "peek");

    lua_pushcfunction(L, njt_stream_lua_socket_tcp_shutdown);
    lua_setfield(L, -2, "shutdown");

    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");

    lua_rawset(L, LUA_REGISTRYINDEX);
    /* }}} */

    /* {{{tcp object metatable */
    lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(
                          tcp_socket_metatable_key));
    lua_createtable(L, 0 /* narr */, 14 /* nrec */);

    lua_pushcfunction(L, njt_stream_lua_socket_tcp_connect);
    lua_setfield(L, -2, "connect");

#if (NJT_STREAM_SSL)

    lua_pushcfunction(L, njt_stream_lua_socket_tcp_sslhandshake);
    lua_setfield(L, -2, "sslhandshake");

#endif

    lua_pushcfunction(L, njt_stream_lua_socket_tcp_receive);
    lua_setfield(L, -2, "receive");

    lua_pushcfunction(L, njt_stream_lua_socket_tcp_receiveuntil);
    lua_setfield(L, -2, "receiveuntil");

    lua_pushcfunction(L, njt_stream_lua_socket_tcp_receiveany);
    lua_setfield(L, -2, "receiveany");

    lua_pushcfunction(L, njt_stream_lua_socket_tcp_send);
    lua_setfield(L, -2, "send");

    lua_pushcfunction(L, njt_stream_lua_socket_tcp_close);
    lua_setfield(L, -2, "close");

    lua_pushcfunction(L, njt_stream_lua_socket_tcp_setoption);
    lua_setfield(L, -2, "setoption");

    lua_pushcfunction(L, njt_stream_lua_socket_tcp_settimeout);
    lua_setfield(L, -2, "settimeout"); /* njt socket mt */

    lua_pushcfunction(L, njt_stream_lua_socket_tcp_settimeouts);
    lua_setfield(L, -2, "settimeouts"); /* njt socket mt */

    lua_pushcfunction(L, njt_stream_lua_socket_tcp_getreusedtimes);
    lua_setfield(L, -2, "getreusedtimes");

    lua_pushcfunction(L, njt_stream_lua_socket_tcp_setkeepalive);
    lua_setfield(L, -2, "setkeepalive");

    lua_pushcfunction(L, njt_stream_lua_socket_tcp_shutdown);
    lua_setfield(L, -2, "shutdown");

    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    lua_rawset(L, LUA_REGISTRYINDEX);
    /* }}} */

    /* {{{upstream userdata metatable */
    lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(
                          upstream_udata_metatable_key));
    lua_createtable(L, 0 /* narr */, 1 /* nrec */); /* metatable */
    lua_pushcfunction(L, njt_stream_lua_socket_tcp_upstream_destroy);
    lua_setfield(L, -2, "__gc");
    lua_rawset(L, LUA_REGISTRYINDEX);
    /* }}} */

    /* {{{downstream userdata metatable */
    lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(
                          downstream_udata_metatable_key));
    lua_createtable(L, 0 /* narr */, 1 /* nrec */); /* metatable */
    lua_pushcfunction(L, njt_stream_lua_socket_downstream_destroy);
    lua_setfield(L, -2, "__gc");
    lua_rawset(L, LUA_REGISTRYINDEX);
    /* }}} */

    /* {{{socket pool userdata metatable */
    lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(
                          pool_udata_metatable_key));
    lua_createtable(L, 0, 1); /* metatable */
    lua_pushcfunction(L, njt_stream_lua_socket_shutdown_pool);
    lua_setfield(L, -2, "__gc");
    lua_rawset(L, LUA_REGISTRYINDEX);
    /* }}} */

    /* {{{socket compiled pattern userdata metatable */
    lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(
                          pattern_udata_metatable_key));
    lua_createtable(L, 0 /* narr */, 1 /* nrec */); /* metatable */
    lua_pushcfunction(L, njt_stream_lua_socket_cleanup_compiled_pattern);
    lua_setfield(L, -2, "__gc");
    lua_rawset(L, LUA_REGISTRYINDEX);
    /* }}} */

#if (NJT_STREAM_SSL)

    /* {{{ssl session userdata metatable */
    lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(
                          ssl_session_metatable_key));
    lua_createtable(L, 0 /* narr */, 1 /* nrec */); /* metatable */
    lua_pushcfunction(L, njt_stream_lua_ssl_free_session);
    lua_setfield(L, -2, "__gc");
    lua_rawset(L, LUA_REGISTRYINDEX);
    /* }}} */

#endif
}


static int
njt_stream_lua_socket_tcp(lua_State *L)
{
    njt_stream_lua_request_t        *r;
    njt_stream_lua_ctx_t            *ctx;

    if (lua_gettop(L) != 0) {
        return luaL_error(L, "expecting zero arguments, but got %d",
                          lua_gettop(L));
    }

    r = njt_stream_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no ctx found");
    }

    njt_stream_lua_check_context(L, ctx, NJT_STREAM_LUA_CONTEXT_YIELDABLE);

    lua_createtable(L, 5 /* narr */, 1 /* nrec */);
    lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(
                          tcp_socket_metatable_key));
    lua_rawget(L, LUA_REGISTRYINDEX);
    lua_setmetatable(L, -2);

    dd("top: %d", lua_gettop(L));

    return 1;
}


static void
njt_stream_lua_socket_tcp_create_socket_pool(lua_State *L,
    njt_stream_lua_request_t *r, njt_str_t key, njt_int_t pool_size, njt_int_t backlog,
    njt_stream_lua_socket_pool_t **spool)
{
    u_char                              *p;
    size_t                               size, key_len;
    njt_int_t                            i;

    njt_stream_lua_socket_pool_t                *sp;
    njt_stream_lua_socket_pool_item_t           *items;

    njt_log_debug2(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket connection pool size: "
                   "%i, backlog: %i",
                   pool_size, backlog);

    key_len = njt_align(key.len + 1, sizeof(void *));

    size = sizeof(njt_stream_lua_socket_pool_t) - 1 + key_len
           + sizeof(njt_stream_lua_socket_pool_item_t) * pool_size;

    /* before calling this function, the Lua stack is:
     * -1 key
     * -2 pools
     */
    sp = lua_newuserdata(L, size);
    if (sp == NULL) {
        luaL_error(L, "no memory");
        return;
    }

    lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(
                          pool_udata_metatable_key));
    lua_rawget(L, LUA_REGISTRYINDEX);
    lua_setmetatable(L, -2);

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket keepalive create "
                   "connection pool for key \"%V\"", &key);

    /* a new socket pool with metatable is push to the stack, so now we have:
     * -1 sp
     * -2 key
     * -3 pools
     *
     * it is time to set pools[key] to sp.
     */
    lua_rawset(L, -3);

    /* clean up the stack for consistency's sake */
    lua_pop(L, 1);

    sp->backlog = backlog;
    sp->size = pool_size;
    sp->connections = 0;
    sp->lua_vm = njt_stream_lua_get_lua_vm(r, NULL);

    njt_queue_init(&sp->cache_connect_op);
    njt_queue_init(&sp->wait_connect_op);
    njt_queue_init(&sp->cache);
    njt_queue_init(&sp->free);

    p = njt_copy(sp->key, key.data, key.len);
    *p++ = '\0';

    items = (njt_stream_lua_socket_pool_item_t *) (sp->key + key_len);

    dd("items: %p", items);

    njt_stream_lua_assert((void *) items
                          == njt_align_ptr(items, sizeof(void *)));

    for (i = 0; i < pool_size; i++) {
        njt_queue_insert_head(&sp->free, &items[i].queue);
        items[i].socket_pool = sp;
    }

    *spool = sp;
}


static int
njt_stream_lua_socket_tcp_connect_helper(lua_State *L,
    njt_stream_lua_socket_tcp_upstream_t *u, njt_stream_lua_request_t *r,
    njt_stream_lua_ctx_t *ctx, u_char *host_ref, size_t host_len,
    in_port_t port, unsigned resuming)
{
    int                                    n;
    int                                    host_size;
    int                                    saved_top;
    njt_int_t                              rc;
    njt_str_t                              host;
    njt_str_t                             *conn_op_host;
    njt_url_t                              url;
    njt_queue_t                           *q;
    njt_resolver_ctx_t                    *rctx, temp;

    njt_stream_lua_co_ctx_t                       *coctx;
    njt_stream_lua_socket_pool_t                  *spool;
    njt_stream_lua_socket_tcp_conn_op_ctx_t       *conn_op_ctx;

    njt_stream_core_srv_conf_t  *clcf;

    spool = u->socket_pool;
    if (spool != NULL) {
        rc = njt_stream_lua_get_keepalive_peer(r, u);

        if (rc == NJT_OK) {
            lua_pushinteger(L, 1);
            return 1;
        }

        /* rc == NJT_DECLINED */

        spool->connections++;

        /* check if backlog is enabled and
         * don't queue resuming connection operation */
        if (spool->backlog >= 0 && !resuming) {

            dd("lua tcp socket %s connections %ld",
               spool->key, spool->connections);

            if (spool->connections > spool->size + spool->backlog) {
                spool->connections--;
                lua_pushnil(L);
                lua_pushliteral(L, "too many waiting connect operations");
                return 2;
            }

            if (spool->connections > spool->size) {
                njt_log_debug2(NJT_LOG_DEBUG_STREAM, u->peer.log, 0,
                               "stream lua tcp socket queue connect "
                               "operation for connection pool \"%s\", "
                               "connections: %i",
                               spool->key, spool->connections);

                host_size = sizeof(u_char) *
                    (njt_max(host_len, NJT_INET_ADDRSTRLEN) + 1);

                if (!njt_queue_empty(&spool->cache_connect_op)) {
                    q = njt_queue_last(&spool->cache_connect_op);
                    njt_queue_remove(q);
                    conn_op_ctx = njt_queue_data(
                        q, njt_stream_lua_socket_tcp_conn_op_ctx_t, queue);

                    conn_op_host = &conn_op_ctx->host;
                    if (host_len > conn_op_host->len
                        && host_len > NJT_INET_ADDRSTRLEN)
                    {
                        njt_free(conn_op_host->data);
                        conn_op_host->data = njt_alloc(host_size,
                                                       njt_cycle->log);
                        if (conn_op_host->data == NULL) {
                            njt_free(conn_op_ctx);
                            goto no_memory_and_not_resuming;
                        }
                    }

                } else {
                    conn_op_ctx = njt_alloc(
                        sizeof(njt_stream_lua_socket_tcp_conn_op_ctx_t),
                        njt_cycle->log);
                    if (conn_op_ctx == NULL) {
                        goto no_memory_and_not_resuming;
                    }

                    conn_op_host = &conn_op_ctx->host;
                    conn_op_host->data = njt_alloc(host_size, njt_cycle->log);
                    if (conn_op_host->data == NULL) {
                        njt_free(conn_op_ctx);
                        goto no_memory_and_not_resuming;
                    }
                }

                conn_op_ctx->cleanup = NULL;

                njt_memcpy(conn_op_host->data, host_ref, host_len);
                conn_op_host->data[host_len] = '\0';
                conn_op_host->len = host_len;

                conn_op_ctx->port = port;

                u->write_co_ctx = ctx->cur_co_ctx;

                conn_op_ctx->u = u;
                ctx->cur_co_ctx->cleanup =
                    njt_stream_lua_tcp_queue_conn_op_cleanup;
                ctx->cur_co_ctx->data = conn_op_ctx;

                njt_memzero(&conn_op_ctx->event, sizeof(njt_event_t));
                conn_op_ctx->event.handler =
                    njt_stream_lua_socket_tcp_conn_op_timeout_handler;
                conn_op_ctx->event.data = conn_op_ctx;
                conn_op_ctx->event.log = njt_cycle->log;

                njt_add_timer(&conn_op_ctx->event, u->connect_timeout);

                njt_queue_insert_tail(&spool->wait_connect_op,
                                      &conn_op_ctx->queue);

                njt_log_debug3(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0,
                               "stream lua tcp socket queued connect "
                               "operation for %d(ms), u: %p, ctx: %p",
                               u->connect_timeout, conn_op_ctx->u, conn_op_ctx);

                return lua_yield(L, 0);
            }
        }

    } /* end spool != NULL */

    host.data = njt_palloc(r->pool, host_len + 1);
    if (host.data == NULL) {
        return luaL_error(L, "no memory");
    }

    host.len = host_len;

    njt_memcpy(host.data, host_ref, host_len);
    host.data[host_len] = '\0';

    njt_memzero(&url, sizeof(njt_url_t));
    url.url = host;
    url.default_port = port;
    url.no_resolve = 1;

    coctx = ctx->cur_co_ctx;

    if (njt_parse_url(r->pool, &url) != NJT_OK) {
        lua_pushnil(L);

        if (url.err) {
            lua_pushfstring(L, "failed to parse host name \"%s\": %s",
                            url.url.data, url.err);

        } else {
            lua_pushfstring(L, "failed to parse host name \"%s\"",
                            url.url.data);
        }

        goto failed;
    }

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket connect timeout: %M",
                   u->connect_timeout);

    u->resolved = njt_pcalloc(r->pool,
                              sizeof(njt_stream_upstream_resolved_t));
    if (u->resolved == NULL) {
        if (resuming) {
            lua_pushnil(L);
            lua_pushliteral(L, "no memory");
            goto failed;
        }

        goto no_memory_and_not_resuming;
    }

    if (url.addrs && url.addrs[0].sockaddr) {
        njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                       "stream lua tcp socket network address given "
                       "directly");

        u->resolved->sockaddr = url.addrs[0].sockaddr;
        u->resolved->socklen = url.addrs[0].socklen;
        u->resolved->naddrs = 1;
        u->resolved->host = url.addrs[0].name;

    } else {
        u->resolved->host = host;
        u->resolved->port = url.default_port;
    }

    if (u->resolved->sockaddr) {
        rc = njt_stream_lua_socket_resolve_retval_handler(r, u, L);
        if (rc == NJT_AGAIN && !resuming) {
            return lua_yield(L, 0);
        }

        if (rc > 1) {
            goto failed;
        }

        return rc;
    }

    clcf = njt_stream_lua_get_module_loc_conf(r, njt_stream_core_module);

    temp.name = host;
    rctx = njt_resolve_start(clcf->resolver, &temp);
    if (rctx == NULL) {
        u->ft_type |= NJT_STREAM_LUA_SOCKET_FT_RESOLVER;
        lua_pushnil(L);
        lua_pushliteral(L, "failed to start the resolver");
        goto failed;
    }

    if (rctx == NJT_NO_RESOLVER) {
        u->ft_type |= NJT_STREAM_LUA_SOCKET_FT_RESOLVER;
        lua_pushnil(L);
        lua_pushfstring(L, "no resolver defined to resolve \"%s\"", host.data);
        goto failed;
    }

    rctx->name = host;
    rctx->handler = njt_stream_lua_socket_resolve_handler;
    rctx->data = u;
    rctx->timeout = clcf->resolver_timeout;

    u->resolved->ctx = rctx;
    u->write_co_ctx = ctx->cur_co_ctx;

    njt_stream_lua_cleanup_pending_operation(coctx);
    coctx->cleanup = njt_stream_lua_tcp_resolve_cleanup;
    coctx->data = u;

    saved_top = lua_gettop(L);

    if (njt_resolve_name(rctx) != NJT_OK) {
        njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                       "stream lua tcp socket fail to run resolver "
                       "immediately");

        u->ft_type |= NJT_STREAM_LUA_SOCKET_FT_RESOLVER;

        coctx->cleanup = NULL;
        coctx->data = NULL;

        u->resolved->ctx = NULL;
        lua_pushnil(L);
        lua_pushfstring(L, "%s could not be resolved", host.data);
        goto failed;
    }

    if (u->conn_waiting) {
        dd("resolved and already connecting");

        if (resuming) {
            return NJT_AGAIN;
        }

        return lua_yield(L, 0);
    }

    n = lua_gettop(L) - saved_top;
    if (n) {
        dd("errors occurred during resolving or connecting"
           "or already connected");

        if (n > 1) {
            goto failed;
        }

        return n;
    }

    /* still resolving */

    u->conn_waiting = 1;
    u->write_prepare_retvals = njt_stream_lua_socket_resolve_retval_handler;

    dd("setting data to %p", u);

    if (ctx->entered_content_phase) {
        r->write_event_handler = njt_stream_lua_content_wev_handler;

    } else {
        r->write_event_handler = njt_stream_lua_core_run_phases;
    }

    if (resuming) {
        return NJT_AGAIN;
    }

    return lua_yield(L, 0);

failed:

    if (spool != NULL) {
        spool->connections--;
        njt_stream_lua_socket_tcp_resume_conn_op(spool);
    }

    return 2;

no_memory_and_not_resuming:

    if (spool != NULL) {
        spool->connections--;
        njt_stream_lua_socket_tcp_resume_conn_op(spool);
    }

    return luaL_error(L, "no memory");
}


static int
njt_stream_lua_socket_tcp_connect(lua_State *L)
{
    njt_stream_lua_request_t    *r;
    njt_stream_lua_ctx_t        *ctx;
    int                          port;
    int                          n;
    u_char                      *p;
    size_t                       len;
    njt_peer_connection_t       *pc;
    int                          connect_timeout, send_timeout, read_timeout;
    unsigned                     custom_pool;
    int                          key_index;
    njt_int_t                    backlog;
    njt_int_t                    pool_size;
    njt_str_t                    key;
    const char                  *msg;

    njt_stream_lua_loc_conf_t                   *llcf;
    njt_stream_lua_socket_tcp_upstream_t        *u;
    njt_stream_lua_socket_pool_t                *spool;

    n = lua_gettop(L);
    if (n != 2 && n != 3 && n != 4) {
        return luaL_error(L, "njt.socket connect: expecting 2, 3, or 4 "
                          "arguments (including the object), but seen %d", n);
    }

    r = njt_stream_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no ctx found");
    }

    njt_stream_lua_check_context(L, ctx, NJT_STREAM_LUA_CONTEXT_YIELDABLE);

    luaL_checktype(L, 1, LUA_TTABLE);

    p = (u_char *) luaL_checklstring(L, 2, &len);

    backlog = -1;
    key_index = 2;
    pool_size = 0;
    custom_pool = 0;
    llcf = njt_stream_lua_get_module_loc_conf(r, njt_stream_lua_module);

    if (lua_type(L, n) == LUA_TTABLE) {

        /* found the last optional option table */

        lua_getfield(L, n, "pool_size");

        if (lua_isnumber(L, -1)) {
            pool_size = (njt_int_t) lua_tointeger(L, -1);

            if (pool_size <= 0) {
                msg = lua_pushfstring(L, "bad \"pool_size\" option value: %i",
                                      pool_size);
                return luaL_argerror(L, n, msg);
            }

        } else if (!lua_isnil(L, -1)) {
            msg = lua_pushfstring(L, "bad \"pool_size\" option type: %s",
                                  lua_typename(L, lua_type(L, -1)));
            return luaL_argerror(L, n, msg);
        }

        lua_pop(L, 1);

        lua_getfield(L, n, "backlog");

        if (lua_isnumber(L, -1)) {
            backlog = (njt_int_t) lua_tointeger(L, -1);

            if (backlog < 0) {
                msg = lua_pushfstring(L, "bad \"backlog\" option value: %i",
                                      backlog);
                return luaL_argerror(L, n, msg);
            }

            /* use default value for pool size if only backlog specified */
            if (pool_size == 0) {
                pool_size = llcf->pool_size;
            }
        }

        lua_pop(L, 1);

        lua_getfield(L, n, "pool");

        switch (lua_type(L, -1)) {
        case LUA_TNUMBER:
            lua_tostring(L, -1);
            /* FALLTHROUGH */

        case LUA_TSTRING:
            custom_pool = 1;

            lua_pushvalue(L, -1);
            lua_rawseti(L, 1, SOCKET_KEY_INDEX);

            key_index = n + 1;

            break;

        case LUA_TNIL:
            lua_pop(L, 2);
            break;

        default:
            msg = lua_pushfstring(L, "bad \"pool\" option type: %s",
                                  luaL_typename(L, -1));
            luaL_argerror(L, n, msg);
            break;
        }

        n--;
    }

    /* the fourth argument is not a table */
    if (n == 4) {
        lua_pop(L, 1);
        n--;
    }

    if (n == 3) {
        port = luaL_checkinteger(L, 3);

        if (port < 0 || port > 65535) {
            lua_pushnil(L);
            lua_pushfstring(L, "bad port number: %d", port);
            return 2;
        }

        if (!custom_pool) {
            lua_pushliteral(L, ":");
            lua_insert(L, 3);
            lua_concat(L, 3);
        }

        dd("socket key: %s", lua_tostring(L, -1));

    } else { /* n == 2 */
        port = 0;
    }

    if (!custom_pool) {
        /* the key's index is 2 */

        lua_pushvalue(L, 2);
        lua_rawseti(L, 1, SOCKET_KEY_INDEX);
    }

    lua_rawgeti(L, 1, SOCKET_CTX_INDEX);
    u = lua_touserdata(L, -1);
    lua_pop(L, 1);

    if (u) {
        if (u->request && u->request != r) {
            return luaL_error(L, "bad request");
        }

        njt_stream_lua_socket_check_busy_connecting(r, u, L);
        njt_stream_lua_socket_check_busy_reading(r, u, L);
        njt_stream_lua_socket_check_busy_writing(r, u, L);

        if (u->body_downstream || u->raw_downstream) {
            return luaL_error(L, "attempt to re-connect a request socket");
        }

        if (u->peer.connection) {
            njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                           "stream lua tcp socket reconnect without "
                           "shutting down");

            njt_stream_lua_socket_tcp_finalize(r, u);
        }

        njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                       "lua reuse socket upstream ctx");

    } else {
        u = lua_newuserdata(L, sizeof(njt_stream_lua_socket_tcp_upstream_t));
        if (u == NULL) {
            return luaL_error(L, "no memory");
        }

#if 1
        lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(
                              upstream_udata_metatable_key));
        lua_rawget(L, LUA_REGISTRYINDEX);
        lua_setmetatable(L, -2);
#endif

        lua_rawseti(L, 1, SOCKET_CTX_INDEX);
    }

    njt_memzero(u, sizeof(njt_stream_lua_socket_tcp_upstream_t));

    u->request = r; /* set the controlling request */

    u->conf = llcf;

    pc = &u->peer;

    pc->log = r->connection->log;
    pc->log_error = NJT_ERROR_ERR;

    dd("lua peer connection log: %p", pc->log);

    lua_rawgeti(L, 1, SOCKET_CONNECT_TIMEOUT_INDEX);
    lua_rawgeti(L, 1, SOCKET_SEND_TIMEOUT_INDEX);
    lua_rawgeti(L, 1, SOCKET_READ_TIMEOUT_INDEX);

    read_timeout = (njt_int_t) lua_tointeger(L, -1);
    send_timeout = (njt_int_t) lua_tointeger(L, -2);
    connect_timeout = (njt_int_t) lua_tointeger(L, -3);

    lua_pop(L, 3);

    if (connect_timeout > 0) {
        u->connect_timeout = (njt_msec_t) connect_timeout;

    } else {
        u->connect_timeout = u->conf->connect_timeout;
    }

    if (send_timeout > 0) {
        u->send_timeout = (njt_msec_t) send_timeout;

    } else {
        u->send_timeout = u->conf->send_timeout;
    }

    if (read_timeout > 0) {
        u->read_timeout = (njt_msec_t) read_timeout;

    } else {
        u->read_timeout = u->conf->read_timeout;
    }

    lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(
                          socket_pool_key));
    lua_rawget(L, LUA_REGISTRYINDEX); /* table */
    lua_pushvalue(L, key_index); /* key */

    lua_rawget(L, -2);
    spool = lua_touserdata(L, -1);
    lua_pop(L, 1);

    if (spool != NULL) {
        u->socket_pool = spool;

    } else if (pool_size > 0) {
        lua_pushvalue(L, key_index);
        key.data = (u_char *) lua_tolstring(L, -1, &key.len);

        njt_stream_lua_socket_tcp_create_socket_pool(L, r, key, pool_size,
                                                     backlog, &spool);
        u->socket_pool = spool;
    }

    return njt_stream_lua_socket_tcp_connect_helper(L, u, r, ctx, p,
                                                    len, port, 0);
}


static void
njt_stream_lua_socket_resolve_handler(njt_resolver_ctx_t *ctx)
{
    njt_stream_lua_request_t            *r;
#if (NJT_DEBUG)
    njt_connection_t                    *c;
#endif
    lua_State                           *L;
    u_char                              *p;
    size_t                               len;
    socklen_t                            socklen;
    struct sockaddr                     *sockaddr;
    njt_uint_t                           i;
    unsigned                             waiting;

    njt_stream_upstream_resolved_t              *ur;
    njt_stream_lua_ctx_t                        *lctx;
    njt_stream_lua_socket_tcp_upstream_t        *u;

    u = ctx->data;
    r = u->request;

#if (NJT_DEBUG)

    c = r->connection;

#endif

    ur = u->resolved;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "stream lua tcp socket resolve handler");

    lctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (lctx == NULL) {
        return;
    }

    lctx->cur_co_ctx = u->write_co_ctx;

    u->write_co_ctx->cleanup = NULL;

    L = lctx->cur_co_ctx->co;

    waiting = u->conn_waiting;

    if (ctx->state) {
        njt_log_debug2(NJT_LOG_DEBUG_STREAM, c->log, 0,
                       "stream lua tcp socket resolver error: %s "
                       "(connect waiting: %d)",
                       njt_resolver_strerror(ctx->state), (int) waiting);

        lua_pushnil(L);
        lua_pushlstring(L, (char *) ctx->name.data, ctx->name.len);
        lua_pushfstring(L, " could not be resolved (%d: %s)",
                        (int) ctx->state,
                        njt_resolver_strerror(ctx->state));
        lua_concat(L, 2);

        u->write_prepare_retvals =
                                njt_stream_lua_socket_conn_error_retval_handler;
        njt_stream_lua_socket_handle_conn_error(r, u,
                                             NJT_STREAM_LUA_SOCKET_FT_RESOLVER);


        return;
    }

    ur->naddrs = ctx->naddrs;
    ur->addrs = ctx->addrs;

#if (NJT_DEBUG)
    {
        u_char      text[NJT_SOCKADDR_STRLEN];
        njt_str_t   addr;
        //by zyg njt_uint_t  i;

        addr.data = text;

        for (i = 0; i < ctx->naddrs; i++) {
            addr.len = njt_sock_ntop(ur->addrs[i].sockaddr, ur->addrs[i].socklen,
                                     text, NJT_SOCKADDR_STRLEN, 0);

            njt_log_debug1(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                           "name was resolved to %V", &addr);
        }
    }
#endif

    njt_stream_lua_assert(ur->naddrs > 0);

    if (ur->naddrs == 1) {
        i = 0;

    } else {
        i = njt_random() % ur->naddrs;
    }

    dd("selected addr index: %d", (int) i);

    socklen = ur->addrs[i].socklen;

    sockaddr = njt_palloc(r->pool, socklen);
    if (sockaddr == NULL) {
        goto nomem;
    }

    njt_memcpy(sockaddr, ur->addrs[i].sockaddr, socklen);

    switch (sockaddr->sa_family) {
#if (NJT_HAVE_INET6)
    case AF_INET6:
        ((struct sockaddr_in6 *) sockaddr)->sin6_port = htons(ur->port);
        break;
#endif
    default: /* AF_INET */
        ((struct sockaddr_in *) sockaddr)->sin_port = htons(ur->port);
    }

    p = njt_pnalloc(r->pool, NJT_SOCKADDR_STRLEN);
    if (p == NULL) {
        goto nomem;
    }

    len = njt_sock_ntop(sockaddr, socklen, p, NJT_SOCKADDR_STRLEN, 1);
    ur->sockaddr = sockaddr;
    ur->socklen = socklen;
    ur->host.data = p;
    ur->host.len = len;
    ur->naddrs = 1;

    njt_resolve_name_done(ctx);
    ur->ctx = NULL;

    u->conn_waiting = 0;
    u->write_co_ctx = NULL;

    if (waiting) {
        lctx->resume_handler = njt_stream_lua_socket_tcp_conn_resume;
        r->write_event_handler(r);


    } else {
        (void) njt_stream_lua_socket_resolve_retval_handler(r, u, L);
    }

    return;

nomem:

    if (ur->ctx) {
        njt_resolve_name_done(ctx);
        ur->ctx = NULL;
    }

    u->write_prepare_retvals = njt_stream_lua_socket_conn_error_retval_handler;
    njt_stream_lua_socket_handle_conn_error(r, u,
                                            NJT_STREAM_LUA_SOCKET_FT_NOMEM);

    if (waiting) {
        dd("run posted requests");


    } else {
        lua_pushnil(L);
        lua_pushliteral(L, "no memory");
    }
}


static void
njt_stream_lua_socket_init_peer_connection_addr_text(njt_peer_connection_t *pc)
{
    njt_connection_t            *c;
    size_t                       addr_text_max_len;

    c = pc->connection;

    switch (pc->sockaddr->sa_family) {

#if (NJT_HAVE_INET6)
    case AF_INET6:
        addr_text_max_len = NJT_INET6_ADDRSTRLEN;
        break;
#endif

#if (NJT_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
        addr_text_max_len = NJT_UNIX_ADDRSTRLEN;
        break;
#endif

    case AF_INET:
        addr_text_max_len = NJT_INET_ADDRSTRLEN;
        break;

    default:
        addr_text_max_len = NJT_SOCKADDR_STRLEN;
        break;
    }

    c->addr_text.data = njt_pnalloc(c->pool, addr_text_max_len);
    if (c->addr_text.data == NULL) {
        njt_log_error(NJT_LOG_ERR, pc->log, 0,
                      "init peer connection addr_text failed: no memory");
        return;
    }

    c->addr_text.len = njt_sock_ntop(pc->sockaddr, pc->socklen,
                                     c->addr_text.data,
                                     addr_text_max_len, 0);
}


static int
njt_stream_lua_socket_resolve_retval_handler(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u, lua_State *L)
{
    njt_stream_lua_ctx_t                    *ctx;
    njt_peer_connection_t                   *pc;
    njt_connection_t                        *c;
    njt_stream_lua_cleanup_t                *cln;
    njt_stream_upstream_resolved_t          *ur;
    njt_int_t                                rc;
    njt_stream_lua_co_ctx_t                 *coctx;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket resolve retval handler");

    if (u->ft_type & NJT_STREAM_LUA_SOCKET_FT_RESOLVER) {
        return 2;
    }

    pc = &u->peer;

    ur = u->resolved;

    if (ur->sockaddr) {
        pc->sockaddr = ur->sockaddr;
        pc->socklen = ur->socklen;
        pc->name = &ur->host;

    } else {
        lua_pushnil(L);
        lua_pushliteral(L, "resolver not working");
        return 2;
    }

    pc->get = njt_stream_lua_socket_tcp_get_peer;

    rc = njt_event_connect_peer(pc);

    if (rc == NJT_ERROR) {
        u->socket_errno = njt_socket_errno;
    }

    if (u->cleanup == NULL) {
        cln = njt_stream_lua_cleanup_add(r, 0);
        if (cln == NULL) {
            u->ft_type |= NJT_STREAM_LUA_SOCKET_FT_ERROR;
            lua_pushnil(L);
            lua_pushliteral(L, "no memory");
            return 2;
        }

        cln->handler = njt_stream_lua_socket_tcp_cleanup;
        cln->data = u;
        u->cleanup = &cln->handler;
    }

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket connect: %i", rc);

    if (rc == NJT_ERROR) {
        return njt_stream_lua_socket_conn_error_retval_handler(r, u, L);
    }

    if (rc == NJT_BUSY) {
        u->ft_type |= NJT_STREAM_LUA_SOCKET_FT_ERROR;
        lua_pushnil(L);
        lua_pushliteral(L, "no live connection");
        return 2;
    }

    if (rc == NJT_DECLINED) {
        dd("socket errno: %d", (int) njt_socket_errno);
        u->ft_type |= NJT_STREAM_LUA_SOCKET_FT_ERROR;
        u->socket_errno = njt_socket_errno;
        return njt_stream_lua_socket_conn_error_retval_handler(r, u, L);
    }

    /* rc == NJT_OK || rc == NJT_AGAIN */

    c = pc->connection;

    c->data = u;

    c->write->handler = njt_stream_lua_socket_tcp_handler;
    c->read->handler = njt_stream_lua_socket_tcp_handler;

    u->write_event_handler = njt_stream_lua_socket_connected_handler;
    u->read_event_handler = njt_stream_lua_socket_connected_handler;

    c->sendfile &= r->connection->sendfile;

    if (c->pool == NULL) {

        /* we need separate pool here to be able to cache SSL connections */

        c->pool = njt_create_pool(128, r->connection->log);
        if (c->pool == NULL) {
            return njt_stream_lua_socket_prepare_error_retvals(r, u, L,
                                                NJT_STREAM_LUA_SOCKET_FT_NOMEM);
        }
    }

    c->log = r->connection->log;
    c->pool->log = c->log;
    c->read->log = c->log;
    c->write->log = c->log;

    /* init or reinit the njt_output_chain() and njt_chain_writer() contexts */

#if 0
    u->writer.out = NULL;
    u->writer.last = &u->writer.out;
#endif

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);

    coctx = ctx->cur_co_ctx;

    dd("setting data to %p", u);

    if (rc == NJT_OK) {
        njt_log_debug1(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                       "stream lua tcp socket connected: fd:%d", (int) c->fd);

        /* We should delete the current write/read event
         * here because the socket object may not be used immediately
         * on the Lua land, thus causing hot spin around level triggered
         * event poll and wasting CPU cycles. */

        if (njt_handle_write_event(c->write, 0) != NJT_OK) {
            njt_stream_lua_socket_handle_conn_error(r, u,
                                                NJT_STREAM_LUA_SOCKET_FT_ERROR);
            lua_pushnil(L);
            lua_pushliteral(L, "failed to handle write event");
            return 2;
        }

        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            njt_stream_lua_socket_handle_conn_error(r, u,
                                                NJT_STREAM_LUA_SOCKET_FT_ERROR);
            lua_pushnil(L);
            lua_pushliteral(L, "failed to handle read event");
            return 2;
        }

        u->read_event_handler = njt_stream_lua_socket_dummy_handler;
        u->write_event_handler = njt_stream_lua_socket_dummy_handler;

        lua_pushinteger(L, 1);
        return 1;
    }

    /* rc == NJT_AGAIN */

    njt_stream_lua_cleanup_pending_operation(coctx);
    coctx->cleanup = njt_stream_lua_coctx_cleanup;
    coctx->data = u;

    njt_add_timer(c->write, u->connect_timeout);

    u->write_co_ctx = ctx->cur_co_ctx;
    u->conn_waiting = 1;
    u->write_prepare_retvals = njt_stream_lua_socket_tcp_conn_retval_handler;

    dd("setting data to %p", u);

    if (ctx->entered_content_phase) {
        r->write_event_handler = njt_stream_lua_content_wev_handler;

    } else {
        r->write_event_handler = njt_stream_lua_core_run_phases;
    }

    return NJT_AGAIN;
}


static int
njt_stream_lua_socket_conn_error_retval_handler(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u, lua_State *L)
{
    njt_uint_t      ft_type;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket error retval handler");

    if (u->write_co_ctx) {
        u->write_co_ctx->cleanup = NULL;
    }

    njt_stream_lua_socket_tcp_finalize(r, u);

    ft_type = u->ft_type;
    u->ft_type = 0;
    return njt_stream_lua_socket_prepare_error_retvals(r, u, L, ft_type);
}


#if (NJT_STREAM_SSL)

static int
njt_stream_lua_socket_tcp_sslhandshake(lua_State *L)
{
    int                      n, top;
    njt_int_t                rc;
    njt_str_t                name = njt_null_string;
    njt_connection_t        *c;
    njt_ssl_session_t      **psession;

    njt_stream_lua_request_t                    *r;
    njt_stream_lua_ctx_t                        *ctx;
    njt_stream_lua_co_ctx_t                     *coctx;
    njt_stream_lua_socket_tcp_upstream_t        *u;

    /* Lua function arguments: self [,session] [,host] [,verify]
       [,send_status_req] */

    n = lua_gettop(L);
    if (n < 1 || n > 5) {
        return luaL_error(L, "njt.socket sslhandshake: expecting 1 ~ 5 "
                          "arguments (including the object), but seen %d", n);
    }

    r = njt_stream_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket ssl handshake");

    luaL_checktype(L, 1, LUA_TTABLE);

    lua_rawgeti(L, 1, SOCKET_CTX_INDEX);
    u = lua_touserdata(L, -1);

    if (u == NULL
        || u->peer.connection == NULL
        || u->read_closed
        || u->write_closed)
    {
        lua_pushnil(L);
        lua_pushliteral(L, "closed");
        return 2;
    }

    if (u->request != r) {
        return luaL_error(L, "bad request");
    }

    njt_stream_lua_socket_check_busy_connecting(r, u, L);
    njt_stream_lua_socket_check_busy_reading(r, u, L);
    njt_stream_lua_socket_check_busy_writing(r, u, L);

    if (u->raw_downstream || u->body_downstream) {
        lua_pushnil(L);
        lua_pushliteral(L, "not supported for downstream");
        return 2;
    }

    c = u->peer.connection;

    u->ssl_session_reuse = 1;

    if (c->ssl && c->ssl->handshaked) {
        switch (lua_type(L, 2)) {
        case LUA_TUSERDATA:
            lua_pushvalue(L, 2);
            break;

        case LUA_TBOOLEAN:
            if (!lua_toboolean(L, 2)) {
                /* avoid generating the ssl session */
                lua_pushboolean(L, 1);
                break;
            }
            /* fall through */

        default:
            njt_stream_lua_ssl_handshake_retval_handler(r, u, L);
            break;
        }

        return 1;
    }

    if (njt_ssl_create_connection(u->conf->ssl, c,
                                  NJT_SSL_BUFFER|NJT_SSL_CLIENT)
        != NJT_OK)
    {
        lua_pushnil(L);
        lua_pushliteral(L, "failed to create ssl connection");
        return 2;
    }

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no ctx found");
    }

    coctx = ctx->cur_co_ctx;

    c->sendfile = 0;

    if (n >= 2) {
        if (lua_type(L, 2) == LUA_TBOOLEAN) {
            u->ssl_session_reuse = lua_toboolean(L, 2);

        } else {
            psession = lua_touserdata(L, 2);

            if (psession != NULL && *psession != NULL) {
                if (njt_ssl_set_session(c, *psession) != NJT_OK) {
                    lua_pushnil(L);
                    lua_pushliteral(L, "lua ssl set session failed");
                    return 2;
                }

                njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                               "stream lua ssl set session: %p", *psession);
            }
        }

        if (n >= 3) {
            name.data = (u_char *) lua_tolstring(L, 3, &name.len);

            if (name.data) {
                njt_log_debug2(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                               "stream lua ssl server name: \"%*s\"", name.len,
                               name.data);

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

                if (SSL_set_tlsext_host_name(c->ssl->connection,
                                             (char *) name.data)
                    == 0)
                {
                    lua_pushnil(L);
                    lua_pushliteral(L, "SSL_set_tlsext_host_name failed");
                    return 2;
                }

#else

               njt_log_debug0(NJT_LOG_DEBUG_STREAM, c->log, 0,
                              "lua socket SNI disabled because the current "
                              "version of OpenSSL lacks the support");

#endif
            }

            if (n >= 4) {
                u->ssl_verify = lua_toboolean(L, 4);

                if (n >= 5) {
                    if (lua_toboolean(L, 5)) {
#ifdef NJT_STREAM_LUA_USE_OCSP
                        SSL_set_tlsext_status_type(c->ssl->connection,
                                                   TLSEXT_STATUSTYPE_ocsp);
#else
                        return luaL_error(L, "no OCSP support");
#endif
                    }
                }
            }
        }
    }

    dd("found sni name: %.*s %p", (int) name.len, name.data, name.data);

    if (name.len == 0) {
        u->ssl_name.len = 0;

    } else {
        if (u->ssl_name.data) {
            /* buffer already allocated */

            if (u->ssl_name.len >= name.len) {
                /* reuse it */
                njt_memcpy(u->ssl_name.data, name.data, name.len);
                u->ssl_name.len = name.len;

            } else {
                njt_free(u->ssl_name.data);
                goto new_ssl_name;
            }

        } else {

new_ssl_name:

            u->ssl_name.data = njt_alloc(name.len, njt_cycle->log);
            if (u->ssl_name.data == NULL) {
                u->ssl_name.len = 0;

                lua_pushnil(L);
                lua_pushliteral(L, "no memory");
                return 2;
            }

            njt_memcpy(u->ssl_name.data, name.data, name.len);
            u->ssl_name.len = name.len;
        }
    }

    u->write_co_ctx = coctx;

#if 0
#ifdef NJT_STREAM_LUA_USE_OCSP
    SSL_set_tlsext_status_type(c->ssl->connection, TLSEXT_STATUSTYPE_ocsp);
#endif
#endif

    rc = njt_ssl_handshake(c);

    dd("njt_ssl_handshake returned %d", (int) rc);

    if (rc == NJT_AGAIN) {
        if (c->write->timer_set) {
            njt_del_timer(c->write);
        }

        njt_add_timer(c->read, u->connect_timeout);

        u->conn_waiting = 1;
        u->write_prepare_retvals = njt_stream_lua_ssl_handshake_retval_handler;

        njt_stream_lua_cleanup_pending_operation(coctx);
        coctx->cleanup = njt_stream_lua_coctx_cleanup;
        coctx->data = u;

        c->ssl->handler = njt_stream_lua_ssl_handshake_handler;

        if (ctx->entered_content_phase) {
            r->write_event_handler = njt_stream_lua_content_wev_handler;

        } else {
            r->write_event_handler = njt_stream_lua_core_run_phases;
        }

        return lua_yield(L, 0);
    }

    top = lua_gettop(L);
    njt_stream_lua_ssl_handshake_handler(c);
    return lua_gettop(L) - top;
}


static void
njt_stream_lua_ssl_handshake_handler(njt_connection_t *c)
{
    const char                  *err;
    int                          waiting;
    lua_State                   *L;
    njt_int_t                    rc;
    njt_connection_t            *dc;  /* downstream connection */
    njt_stream_lua_request_t    *r;

    njt_stream_lua_ctx_t                        *ctx;
    njt_stream_lua_loc_conf_t                   *llcf;
    njt_stream_lua_socket_tcp_upstream_t        *u;

    u = c->data;
    r = u->request;

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        return;
    }

    c->write->handler = njt_stream_lua_socket_tcp_handler;
    c->read->handler = njt_stream_lua_socket_tcp_handler;

    waiting = u->conn_waiting;

    dc = r->connection;
    L = u->write_co_ctx->co;

    if (c->read->timedout) {
        lua_pushnil(L);
        lua_pushliteral(L, "timeout");
        goto failed;
    }

    if (c->read->timer_set) {
        njt_del_timer(c->read);
    }

    if (c->ssl->handshaked) {

        if (u->ssl_verify) {
            rc = SSL_get_verify_result(c->ssl->connection);

            if (rc != X509_V_OK) {
                lua_pushnil(L);
                err = lua_pushfstring(L, "%d: %s", (int) rc,
                                      X509_verify_cert_error_string(rc));

                llcf = njt_stream_lua_get_module_loc_conf(r,
                                                         njt_stream_lua_module);
                if (llcf->log_socket_errors) {
                    njt_log_error(NJT_LOG_ERR, dc->log, 0, "stream lua ssl "
                                  "certificate verify error: (%s)", err);
                }

                goto failed;
            }

#if defined(njet_version) && njet_version >= 1007000

            if (u->ssl_name.len
                && njt_ssl_check_host(c, &u->ssl_name) != NJT_OK)
            {
                lua_pushnil(L);
                lua_pushliteral(L, "certificate host mismatch");

                llcf = njt_stream_lua_get_module_loc_conf(r,
                                                         njt_stream_lua_module);
                if (llcf->log_socket_errors) {
                    njt_log_error(NJT_LOG_ERR, dc->log, 0, "stream lua ssl "
                                  "certificate does not match host \"%V\"",
                                  &u->ssl_name);
                }

                goto failed;
            }

#endif
        }

        if (waiting) {
            njt_stream_lua_socket_handle_conn_success(r, u);

        } else {
            (void) njt_stream_lua_ssl_handshake_retval_handler(r, u, L);
        }


        return;
    }

    lua_pushnil(L);
    lua_pushliteral(L, "handshake failed");

failed:

    if (waiting) {
        u->write_prepare_retvals =
                                njt_stream_lua_socket_conn_error_retval_handler;
        njt_stream_lua_socket_handle_conn_error(r, u,
                                                NJT_STREAM_LUA_SOCKET_FT_SSL);


    } else {
        (void) njt_stream_lua_socket_conn_error_retval_handler(r, u, L);
    }
}


static int
njt_stream_lua_ssl_handshake_retval_handler(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u, lua_State *L)
{
    njt_connection_t            *c;
    njt_ssl_session_t           *ssl_session, **ud;

    if (!u->ssl_session_reuse) {
        lua_pushboolean(L, 1);
        return 1;
    }

    ud = lua_newuserdata(L, sizeof(njt_ssl_session_t *));

    c = u->peer.connection;

    ssl_session = njt_ssl_get_session(c);
    if (ssl_session == NULL) {
        *ud = NULL;

    } else {
        *ud = ssl_session;

       njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                      "stream lua ssl save session: %p", ssl_session);

        /* set up the __gc metamethod */
        lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(
                              ssl_session_metatable_key));
        lua_rawget(L, LUA_REGISTRYINDEX);
        lua_setmetatable(L, -2);
    }

    return 1;
}

#endif  /* NJT_STREAM_SSL */


static int
njt_stream_lua_socket_read_error_retval_handler(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u, lua_State *L)
{
    njt_uint_t          ft_type;

    if (u->read_co_ctx) {
        u->read_co_ctx->cleanup = NULL;
    }

    ft_type = u->ft_type;
    u->ft_type = 0;

    if (u->no_close) {
        u->no_close = 0;

    } else {
        njt_stream_lua_socket_tcp_finalize_read_part(r, u);
    }

    return njt_stream_lua_socket_prepare_error_retvals(r, u, L, ft_type);
}


static int
njt_stream_lua_socket_write_error_retval_handler(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u, lua_State *L)
{
    njt_uint_t          ft_type;

    if (u->write_co_ctx) {
        u->write_co_ctx->cleanup = NULL;
    }

    njt_stream_lua_socket_tcp_finalize_write_part(r, u, 0);

    ft_type = u->ft_type;
    u->ft_type = 0;
    return njt_stream_lua_socket_prepare_error_retvals(r, u, L, ft_type);
}


static int
njt_stream_lua_socket_prepare_error_retvals(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u, lua_State *L, njt_uint_t ft_type)
{
    u_char           errstr[NJT_MAX_ERROR_STR];
    u_char          *p;

    if (ft_type & (NJT_STREAM_LUA_SOCKET_FT_RESOLVER
                   | NJT_STREAM_LUA_SOCKET_FT_SSL))
    {
        return 2;
    }

    lua_pushnil(L);

    if (ft_type & NJT_STREAM_LUA_SOCKET_FT_TIMEOUT) {
        lua_pushliteral(L, "timeout");

    } else if (ft_type & NJT_STREAM_LUA_SOCKET_FT_CLOSED) {
        lua_pushliteral(L, "closed");

    } else if (ft_type & NJT_STREAM_LUA_SOCKET_FT_BUFTOOSMALL) {
        lua_pushliteral(L, "buffer too small");

    } else if (ft_type & NJT_STREAM_LUA_SOCKET_FT_NOMEM) {
        lua_pushliteral(L, "no memory");

    } else if (ft_type & NJT_STREAM_LUA_SOCKET_FT_CLIENTABORT) {
        lua_pushliteral(L, "client aborted");

    } else {

        if (u->socket_errno) {
            p = njt_strerror(u->socket_errno, errstr, sizeof(errstr));
            /* for compatibility with LuaSocket */
            njt_strlow(errstr, errstr, p - errstr);
            lua_pushlstring(L, (char *) errstr, p - errstr);

        } else {
            lua_pushliteral(L, "error");
        }
    }

    return 2;
}


static int
njt_stream_lua_socket_tcp_conn_retval_handler(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u, lua_State *L)
{
    if (u->ft_type) {
        return njt_stream_lua_socket_conn_error_retval_handler(r, u, L);
    }

    lua_pushinteger(L, 1);
    return 1;
}


static int
njt_stream_lua_socket_tcp_peek(lua_State *L)
{
    njt_stream_lua_request_t            *r;
    njt_connection_t                    *c;
    njt_stream_lua_ctx_t                *ctx;
    njt_stream_lua_loc_conf_t           *llcf;
    njt_stream_lua_co_ctx_t             *coctx;
    int                                  n;
    lua_Integer                          bytes;
    size_t                               size;

    njt_stream_lua_socket_tcp_upstream_t        *u;

    r = njt_stream_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    njt_stream_lua_check_context(L, ctx, NJT_STREAM_LUA_CONTEXT_PREREAD);

    n = lua_gettop(L);
    if (n != 2) {
        return luaL_error(L, "expecting 2 arguments "
                          "(including the object), but got %d", n);
    }

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket calling peek() method");

    luaL_checktype(L, 1, LUA_TTABLE);

    lua_rawgeti(L, 1, SOCKET_CTX_INDEX);
    u = lua_touserdata(L, -1);

    if (u == NULL) {
        llcf = njt_stream_lua_get_module_loc_conf(r, njt_stream_lua_module);

        if (llcf->log_socket_errors) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "attempt to peek data on a closed socket: u:%p", u);
        }

        lua_pushnil(L);
        lua_pushliteral(L, "closed");
        return 2;
    }

    if (u->read_consumed) {
        return luaL_error(L, "attempt to peek on a consumed socket");
    }

    c = u->peer.connection;

    if (u->request != r) {
        return luaL_error(L, "bad request");
    }

    njt_stream_lua_socket_check_busy_reading(r, u, L);

    if (!lua_isnumber(L, 2)) {
        return luaL_error(L, "argument must be a number");
    }

    bytes = lua_tointeger(L, 2);
    if (bytes < 0) {
        return luaL_argerror(L, 2, "bytes can not be negative");
    }

    if (bytes == 0) {
        lua_pushliteral(L, "");
        return 1;
    }

    u->length = (size_t) bytes;

    if (c->buffer != NULL) {
        size = c->buffer->last - c->buffer->pos;

        if (size >= u->length) {
            lua_pushlstring(L, (char *) c->buffer->pos, u->length);
            return 1;
        }
    }

    /* not enough data in the preread buffer */

    coctx = ctx->cur_co_ctx;

    njt_stream_lua_cleanup_pending_operation(coctx);
    coctx->cleanup = njt_stream_lua_coctx_cleanup;
    coctx->data = u;

    dd("setting data to %p, coctx:%p", u, coctx);

    ctx->downstream = u;
    ctx->resume_handler = njt_stream_lua_socket_tcp_peek_resume;
    ctx->peek_needs_more_data = 1;
    u->read_co_ctx = coctx;
    u->read_waiting = 1;

    return lua_yield(L, 0);
}


static njt_int_t
njt_stream_lua_socket_tcp_peek_resume(njt_stream_lua_request_t *r)
{
    lua_State                           *vm;
    njt_int_t                            rc;
    njt_uint_t                           nreqs;
    njt_connection_t                    *c;
    njt_stream_lua_ctx_t                *ctx;
    size_t                               size;

    njt_stream_lua_socket_tcp_upstream_t            *u;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket resuming peek");

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        return NJT_ERROR;
    }

    u = ctx->downstream;
    c = r->connection;
    vm = njt_stream_lua_get_lua_vm(r, ctx);
    nreqs = c->requests;

    size = c->buffer->last - c->buffer->pos;

    if (size < u->length) {
        njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                     "lua peek does not have enough data, returning NJT_AGAIN");

        return njt_stream_lua_run_posted_threads(c, vm, r, ctx, nreqs);
    }

    ctx->resume_handler = njt_stream_lua_wev_handler;
    /* read handler might have been changed by njt_stream_core_preread_phase */
    r->connection->read->handler = njt_stream_lua_request_handler;

    lua_pushlstring(u->read_co_ctx->co, (char *) c->buffer->pos, u->length);

    u->read_co_ctx->cleanup = NULL;
    ctx->cur_co_ctx = u->read_co_ctx;
    u->read_co_ctx = NULL;
    ctx->peek_needs_more_data = 0;
    u->read_waiting = 0;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "lua tcp operation done, resuming lua thread");

    rc = njt_stream_lua_run_thread(vm, r, ctx, 1);

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "lua run thread returned %d", rc);

    if (rc == NJT_AGAIN) {
        return njt_stream_lua_run_posted_threads(c, vm, r, ctx, nreqs);
    }

    if (rc == NJT_DONE) {
        njt_stream_lua_finalize_request(r, NJT_DONE);
        return njt_stream_lua_run_posted_threads(c, vm, r, ctx, nreqs);
    }

    return rc;
}


static int
njt_stream_lua_socket_tcp_receive_helper(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u, lua_State *L)
{
    njt_int_t                                    rc;
    njt_stream_lua_ctx_t                        *lctx;
    njt_stream_lua_co_ctx_t                     *coctx;

    u->input_filter_ctx = u;

    lctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);

    if (u->bufs_in == NULL) {
        u->bufs_in =
            njt_stream_lua_chain_get_free_buf(r->connection->log,
                                              r->pool,
                                              &lctx->free_recv_bufs,
                                              u->conf->buffer_size);

        if (u->bufs_in == NULL) {
            return luaL_error(L, "no memory");
        }

        u->buf_in = u->bufs_in;
        u->buffer = *u->buf_in->buf;
    }

    dd("tcp receive: buf_in: %p, bufs_in: %p", u->buf_in, u->bufs_in);

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket read timeout: %M", u->read_timeout);

    if (u->raw_downstream || u->body_downstream) {
        r->read_event_handler = njt_stream_lua_req_socket_rev_handler;
    }

    u->read_waiting = 0;
    u->read_co_ctx = NULL;

    rc = njt_stream_lua_socket_tcp_read(r, u);

    if (rc == NJT_ERROR) {
        dd("read failed: %d", (int) u->ft_type);
        rc = njt_stream_lua_socket_tcp_receive_retval_handler(r, u, L);
        dd("tcp receive retval returned: %d", (int) rc);
        return rc;
    }

    if (rc == NJT_OK) {

        njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                       "stream lua tcp socket receive done in a single run");

        return njt_stream_lua_socket_tcp_receive_retval_handler(r, u, L);
    }

    /* rc == NJT_AGAIN */

    u->read_event_handler = njt_stream_lua_socket_read_handler;

    coctx = lctx->cur_co_ctx;

    njt_stream_lua_cleanup_pending_operation(coctx);
    coctx->cleanup = njt_stream_lua_coctx_cleanup;
    coctx->data = u;

    if (lctx->entered_content_phase) {
        r->write_event_handler = njt_stream_lua_content_wev_handler;

    } else {
        r->write_event_handler = njt_stream_lua_core_run_phases;
    }

    u->read_co_ctx = coctx;
    u->read_waiting = 1;
    u->read_prepare_retvals = njt_stream_lua_socket_tcp_receive_retval_handler;

    dd("setting data to %p, coctx:%p", u, coctx);

    if (u->raw_downstream || u->body_downstream) {
        lctx->downstream = u;
    }

    return lua_yield(L, 0);
}


static int
njt_stream_lua_socket_tcp_receiveany(lua_State *L)
{
    int                                  n;
    lua_Integer                          bytes;
    njt_stream_lua_request_t            *r;
    njt_stream_lua_loc_conf_t           *llcf;

    njt_stream_lua_socket_tcp_upstream_t        *u;

    n = lua_gettop(L);
    if (n != 2) {
        return luaL_error(L, "expecting 2 arguments "
                          "(including the object), but got %d", n);
    }

    r = njt_stream_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    luaL_checktype(L, 1, LUA_TTABLE);

    lua_rawgeti(L, 1, SOCKET_CTX_INDEX);
    u = lua_touserdata(L, -1);

    if (u == NULL || u->peer.connection == NULL || u->read_closed) {

        llcf = njt_stream_lua_get_module_loc_conf(r, njt_stream_lua_module);

        if (llcf->log_socket_errors) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "attempt to receive data on a closed "
                          "socket: u:%p, c:%p, ft:%d eof:%d",
                          u, u ? u->peer.connection : NULL,
                          u ? (int) u->ft_type : 0, u ? (int) u->eof : 0);
        }

        lua_pushnil(L);
        lua_pushliteral(L, "closed");
        return 2;
    }

    if (u->request != r) {
        return luaL_error(L, "bad request");
    }

    njt_stream_lua_socket_check_busy_connecting(r, u, L);
    njt_stream_lua_socket_check_busy_reading(r, u, L);

    if (!lua_isnumber(L, 2)) {
        return luaL_argerror(L, 2, "bad max argument");
    }

    bytes = lua_tointeger(L, 2);
    if (bytes <= 0) {
        return luaL_argerror(L, 2, "bad max argument");
    }

    u->input_filter = njt_stream_lua_socket_read_any;
    u->rest = (size_t) bytes;
    u->length = u->rest;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket calling receiveany() "
                   "method to read at most %uz bytes", u->rest);

    return njt_stream_lua_socket_tcp_receive_helper(r, u, L);
}


static int
njt_stream_lua_socket_tcp_receive(lua_State *L)
{
    njt_stream_lua_request_t            *r;
    njt_stream_lua_loc_conf_t           *llcf;
    int                                  n;
    njt_str_t                            pat;
    lua_Integer                          bytes;
    char                                *p;
    int                                  typ;

    njt_stream_lua_socket_tcp_upstream_t        *u;

    n = lua_gettop(L);
    if (n != 1 && n != 2) {
        return luaL_error(L, "expecting 1 or 2 arguments "
                          "(including the object), but got %d", n);
    }

    r = njt_stream_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket calling receive() method");

    luaL_checktype(L, 1, LUA_TTABLE);

    lua_rawgeti(L, 1, SOCKET_CTX_INDEX);
    u = lua_touserdata(L, -1);

    if (u == NULL || u->peer.connection == NULL || u->read_closed) {

        llcf = njt_stream_lua_get_module_loc_conf(r, njt_stream_lua_module);

        if (llcf->log_socket_errors) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "stream attempt to receive data on a closed "
                          "socket: u:%p, c:%p, ft:%d eof:%d",
                          u, u ? u->peer.connection : NULL,
                          u ? (int) u->ft_type : 0, u ? (int) u->eof : 0);
        }

        lua_pushnil(L);
        lua_pushliteral(L, "closed");
        return 2;
    }

    if (u->request != r) {
        return luaL_error(L, "bad request");
    }

    njt_stream_lua_socket_check_busy_connecting(r, u, L);
    njt_stream_lua_socket_check_busy_reading(r, u, L);

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket read timeout: %M", u->read_timeout);

    if (n > 1) {
        if (lua_isnumber(L, 2)) {
            typ = LUA_TNUMBER;

        } else {
            typ = lua_type(L, 2);
        }

        switch (typ) {
        case LUA_TSTRING:
            pat.data = (u_char *) luaL_checklstring(L, 2, &pat.len);
            if (pat.len != 2 || pat.data[0] != '*') {
                p = (char *) lua_pushfstring(L, "bad pattern argument: %s",
                                             (char *) pat.data);

                return luaL_argerror(L, 2, p);
            }

            switch (pat.data[1]) {
            case 'l':
                u->input_filter = njt_stream_lua_socket_read_line;
                break;

            case 'a':
                u->input_filter = njt_stream_lua_socket_read_all;
                break;

            default:
                return luaL_argerror(L, 2, "bad pattern argument");
                break;
            }

            u->length = 0;
            u->rest = 0;

            break;

        case LUA_TNUMBER:
            bytes = lua_tointeger(L, 2);
            if (bytes < 0) {
                return luaL_argerror(L, 2, "bad pattern argument");
            }

#if 1
            if (bytes == 0) {
                lua_pushliteral(L, "");
                return 1;
            }
#endif

            u->input_filter = njt_stream_lua_socket_read_chunk;
            u->length = (size_t) bytes;
            u->rest = u->length;

            break;

        default:
            return luaL_argerror(L, 2, "bad pattern argument");
            break;
        }

    } else {
        u->input_filter = njt_stream_lua_socket_read_line;
        u->length = 0;
        u->rest = 0;
    }

    return njt_stream_lua_socket_tcp_receive_helper(r, u, L);
}


static njt_int_t
njt_stream_lua_socket_read_chunk(void *data, ssize_t bytes)
{
    njt_int_t                                        rc;
    njt_stream_lua_socket_tcp_upstream_t            *u = data;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, u->request->connection->log, 0,
                   "stream lua tcp socket read chunk %z", bytes);

    rc = njt_stream_lua_read_bytes(&u->buffer, u->buf_in, &u->rest,
                                   bytes, u->request->connection->log);
    if (rc == NJT_ERROR) {
        u->ft_type |= NJT_STREAM_LUA_SOCKET_FT_CLOSED;
        return NJT_ERROR;
    }

    return rc;
}


static njt_int_t
njt_stream_lua_socket_read_all(void *data, ssize_t bytes)
{
    njt_stream_lua_socket_tcp_upstream_t            *u = data;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, u->request->connection->log, 0,
                   "stream lua tcp socket read all");
    return njt_stream_lua_read_all(&u->buffer, u->buf_in, bytes,
                                   u->request->connection->log);
}


static njt_int_t
njt_stream_lua_socket_read_line(void *data, ssize_t bytes)
{
    njt_int_t                                        rc;
    njt_stream_lua_socket_tcp_upstream_t            *u = data;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, u->request->connection->log, 0,
                   "stream lua tcp socket read line");

    rc = njt_stream_lua_read_line(&u->buffer, u->buf_in, bytes,
                                  u->request->connection->log);
    if (rc == NJT_ERROR) {
        u->ft_type |= NJT_STREAM_LUA_SOCKET_FT_CLOSED;
        return NJT_ERROR;
    }

    return rc;
}


static njt_int_t
njt_stream_lua_socket_read_any(void *data, ssize_t bytes)
{
    njt_int_t                                        rc;
    njt_stream_lua_socket_tcp_upstream_t            *u = data;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, u->request->connection->log, 0,
                   "stream lua tcp socket read any");

    rc = njt_stream_lua_read_any(&u->buffer, u->buf_in, &u->rest, bytes,
                                 u->request->connection->log);
    if (rc == NJT_ERROR) {
        u->ft_type |= NJT_STREAM_LUA_SOCKET_FT_CLOSED;
        return NJT_ERROR;
    }

    return rc;
}


static njt_int_t
njt_stream_lua_socket_tcp_read(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u)
{
    njt_int_t                    rc;
    njt_connection_t            *c;
    njt_buf_t                   *b;
    njt_event_t                 *rev;
    size_t                       size;
    ssize_t                      n;
    unsigned                     read;
    off_t                        preread = 0;

    njt_stream_lua_loc_conf_t           *llcf;

    c = u->peer.connection;
    rev = c->read;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "stream lua tcp socket read data: wait:%d",
                   (int) u->read_waiting);

    b = &u->buffer;
    read = 0;

    for ( ;; ) {

        size = b->last - b->pos;

        if (size || u->eof) {

            rc = u->input_filter(u->input_filter_ctx, size);

            if (rc == NJT_OK) {

                njt_log_debug2(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                               "stream lua tcp socket receive done: "
                               "wait:%d, eof:%d, ", (int) u->read_waiting,
                               (int) u->eof);


#if 1
                if (njt_handle_read_event(rev, 0) != NJT_OK) {
                    njt_stream_lua_socket_handle_read_error(r, u,
                                                NJT_STREAM_LUA_SOCKET_FT_ERROR);
                    return NJT_ERROR;
                }
#endif


                u->read_consumed = 1;

                njt_stream_lua_socket_handle_read_success(r, u);
                return NJT_OK;
            }

            if (rc == NJT_ERROR) {
                dd("input filter error: ft_type:%d wait:%d",
                   (int) u->ft_type, (int) u->read_waiting);

                njt_stream_lua_socket_handle_read_error(r, u,
                                                NJT_STREAM_LUA_SOCKET_FT_ERROR);
                return NJT_ERROR;
            }

            /* rc == NJT_AGAIN */


            continue;
        }

        if (read && !rev->ready) {
            rc = NJT_AGAIN;
            break;
        }

        size = b->end - b->last;

        if (size == 0) {
            rc = njt_stream_lua_socket_add_input_buffer(r, u);
            if (rc == NJT_ERROR) {
                njt_stream_lua_socket_handle_read_error(r, u,
                                                NJT_STREAM_LUA_SOCKET_FT_NOMEM);

                return NJT_ERROR;
            }

            b = &u->buffer;
            size = (size_t) (b->end - b->last);
        }

        if (u->raw_downstream) {
            if (r->connection->buffer != NULL) {
                preread = njt_buf_size(r->connection->buffer);
            }

            if (preread) {

                if ((off_t) size > preread) {
                    size = (size_t) preread;
                }

                njt_stream_lua_probe_req_socket_consume_preread(r,
                                                     r->connection->buffer->pos,
                                                                size);

                b->last = njt_copy(b->last, r->connection->buffer->pos, size);
                r->connection->buffer->pos += size;
                continue;
            }

        }

#if 1
        if (rev->active && !rev->ready) {
            rc = NJT_AGAIN;
            break;
        }
#endif

        njt_log_debug1(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                       "stream lua tcp socket try to recv data %uz", size);

        n = c->recv(c, b->last, size);

        dd("read event ready: %d", (int) c->read->ready);

        read = 1;

        njt_log_debug1(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                       "stream lua tcp socket recv returned %d", (int) n);

        if (n == NJT_AGAIN) {
            rc = NJT_AGAIN;
            dd("socket recv busy");
            break;
        }

        if (n == 0) {

            if (u->raw_downstream || u->body_downstream) {

                llcf = njt_stream_lua_get_module_loc_conf(r,
                                                         njt_stream_lua_module);

                if (llcf->check_client_abort) {

                    njt_stream_lua_socket_handle_read_error(r, u,
                                          NJT_STREAM_LUA_SOCKET_FT_CLIENTABORT);
                    return NJT_ERROR;
                }

                /* llcf->check_client_abort == 0 */

            }

            u->eof = 1;

            njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                           "stream lua tcp socket closed");

            continue;
        }

        if (n == NJT_ERROR) {
            u->socket_errno = njt_socket_errno;
            njt_stream_lua_socket_handle_read_error(r, u,
                                                NJT_STREAM_LUA_SOCKET_FT_ERROR);
            return NJT_ERROR;
        }

        b->last += n;

    }

#if 1
    if (njt_handle_read_event(rev, 0) != NJT_OK) {
        njt_stream_lua_socket_handle_read_error(r, u,
                                                NJT_STREAM_LUA_SOCKET_FT_ERROR);
        return NJT_ERROR;
    }
#endif

    if (rev->active) {
        njt_add_timer(rev, u->read_timeout);

    } else if (rev->timer_set) {
        njt_del_timer(rev);
    }

    return rc;
}


static int
njt_stream_lua_socket_tcp_send(lua_State *L)
{
    njt_int_t                            rc;
    njt_stream_lua_request_t            *r;
    u_char                              *p;
    size_t                               len;
    njt_chain_t                         *cl;
    int                                  type;
    int                                  tcp_nodelay;
    const char                          *msg;
    njt_buf_t                           *b;
    njt_connection_t                    *c;

    njt_stream_lua_ctx_t                        *ctx;
    njt_stream_lua_socket_tcp_upstream_t        *u;
    njt_stream_lua_loc_conf_t                   *llcf;

    njt_stream_core_srv_conf_t  *clcf;

    njt_stream_lua_co_ctx_t                     *coctx;

    /* TODO: add support for the optional "i" and "j" arguments */

    if (lua_gettop(L) != 2) {
        return luaL_error(L, "expecting 2 arguments (including the object), "
                          "but got %d", lua_gettop(L));
    }

    r = njt_stream_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    luaL_checktype(L, 1, LUA_TTABLE);

    lua_rawgeti(L, 1, SOCKET_CTX_INDEX);
    u = lua_touserdata(L, -1);
    lua_pop(L, 1);

    dd("tcp send: u=%p, u->write_closed=%d", u, (unsigned) u->write_closed);

    if (u == NULL || u->peer.connection == NULL || u->write_closed) {
        llcf = njt_stream_lua_get_module_loc_conf(r, njt_stream_lua_module);

        if (llcf->log_socket_errors) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "attempt to send data on a closed socket: u:%p, "
                          "c:%p, ft:%d eof:%d",
                          u, u ? u->peer.connection : NULL,
                          u ? (int) u->ft_type : 0, u ? (int) u->eof : 0);
        }

        lua_pushnil(L);
        lua_pushliteral(L, "closed");
        return 2;
    }

    if (u->request != r) {
        return luaL_error(L, "bad request");
    }

    njt_stream_lua_socket_check_busy_connecting(r, u, L);
    njt_stream_lua_socket_check_busy_writing(r, u, L);

    if (u->body_downstream) {
        return luaL_error(L, "attempt to write to request sockets");
    }

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket send timeout: %M", u->send_timeout);

    type = lua_type(L, 2);
    switch (type) {
        case LUA_TNUMBER:
        case LUA_TSTRING:
            lua_tolstring(L, 2, &len);
            break;

        case LUA_TTABLE:
            len = njt_stream_lua_calc_strlen_in_table(L, 2, 2, 1 /* strict */);
            break;

        case LUA_TNIL:
            len = sizeof("nil") - 1;
            break;

        case LUA_TBOOLEAN:
            if (lua_toboolean(L, 2)) {
                len = sizeof("true") - 1;

            } else {
                len = sizeof("false") - 1;
            }

            break;

        default:
            msg = lua_pushfstring(L, "string, number, boolean, nil, "
                                  "or array table expected, got %s",
                                  lua_typename(L, type));

            return luaL_argerror(L, 2, msg);
    }

    if (len == 0) {
        lua_pushinteger(L, 0);
        return 1;
    }

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);

    cl = njt_stream_lua_chain_get_free_buf(r->connection->log, r->pool,
                                           &ctx->free_bufs, len);

    if (cl == NULL) {
        return luaL_error(L, "no memory");
    }

    b = cl->buf;

    switch (type) {
        case LUA_TNUMBER:
        case LUA_TSTRING:
            p = (u_char *) lua_tolstring(L, -1, &len);
            b->last = njt_copy(b->last, (u_char *) p, len);
            break;

        case LUA_TTABLE:
            b->last = njt_stream_lua_copy_str_in_table(L, -1, b->last);
            break;

        case LUA_TNIL:
            *b->last++ = 'n';
            *b->last++ = 'i';
            *b->last++ = 'l';
            break;

        case LUA_TBOOLEAN:
            if (lua_toboolean(L, 2)) {
                *b->last++ = 't';
                *b->last++ = 'r';
                *b->last++ = 'u';
                *b->last++ = 'e';

            } else {
                *b->last++ = 'f';
                *b->last++ = 'a';
                *b->last++ = 'l';
                *b->last++ = 's';
                *b->last++ = 'e';
            }

            break;

        default:
            return luaL_error(L, "impossible to reach here");
    }

    u->request_bufs = cl;

    u->request_len = len;

    /* mimic njt_http_upstream_init_request here */

    clcf = njt_stream_lua_get_module_loc_conf(r, njt_stream_core_module);
    c = u->peer.connection;

    if (clcf->tcp_nodelay && c->tcp_nodelay == NJT_TCP_NODELAY_UNSET) {
        njt_log_debug0(NJT_LOG_DEBUG_STREAM, c->log, 0,
                       "stream lua socket tcp_nodelay");

        tcp_nodelay = 1;

        if (setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY,
                       (const void *) &tcp_nodelay, sizeof(int))
            == -1)
        {
            llcf = njt_stream_lua_get_module_loc_conf(r, njt_stream_lua_module);
            if (llcf->log_socket_errors) {
                njt_connection_error(c, njt_socket_errno,
                                     "setsockopt(TCP_NODELAY) "
                                     "failed");
            }

            lua_pushnil(L);
            lua_pushliteral(L, "setsocketopt tcp_nodelay failed");
            return 2;
        }

        c->tcp_nodelay = NJT_TCP_NODELAY_SET;
    }

#if 1
    u->write_waiting = 0;
    u->write_co_ctx = NULL;
#endif

    njt_stream_lua_probe_socket_tcp_send_start(r, u, b->pos, len);

    rc = njt_stream_lua_socket_send(r, u);

    dd("socket send returned %d", (int) rc);

    if (rc == NJT_ERROR) {
        return njt_stream_lua_socket_write_error_retval_handler(r, u, L);
    }

    if (rc == NJT_OK) {
        lua_pushinteger(L, len);
        return 1;
    }

    /* rc == NJT_AGAIN */

    coctx = ctx->cur_co_ctx;

    njt_stream_lua_cleanup_pending_operation(coctx);
    coctx->cleanup = njt_stream_lua_coctx_cleanup;
    coctx->data = u;

    if (u->raw_downstream) {
        ctx->writing_raw_req_socket = 1;
    }

    if (ctx->entered_content_phase) {
        r->write_event_handler = njt_stream_lua_content_wev_handler;

    } else {
        r->write_event_handler = njt_stream_lua_core_run_phases;
    }

    u->write_co_ctx = coctx;
    u->write_waiting = 1;
    u->write_prepare_retvals = njt_stream_lua_socket_tcp_send_retval_handler;

    dd("setting data to %p", u);

    return lua_yield(L, 0);
}


static int
njt_stream_lua_socket_tcp_send_retval_handler(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u, lua_State *L)
{
    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket send return value handler");

    if (u->ft_type) {
        return njt_stream_lua_socket_write_error_retval_handler(r, u, L);
    }

    lua_pushinteger(L, u->request_len);
    return 1;
}


static int
njt_stream_lua_socket_tcp_receive_retval_handler(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u, lua_State *L)
{
    int                          n;
    njt_int_t                    rc;
    njt_stream_lua_ctx_t        *ctx;
    njt_event_t                 *ev;

    njt_stream_lua_loc_conf_t           *llcf;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket receive return value handler");

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);

#if 1
    if (u->raw_downstream || u->body_downstream) {
        llcf = njt_stream_lua_get_module_loc_conf(r, njt_stream_lua_module);

        if (llcf->check_client_abort) {

            r->read_event_handler = njt_stream_lua_rd_check_broken_connection;

            ev = r->connection->read;

            dd("rev active: %d", ev->active);

            if ((njt_event_flags & NJT_USE_LEVEL_EVENT) && !ev->active) {
                if (njt_add_event(ev, NJT_READ_EVENT, 0) != NJT_OK) {
                    lua_pushnil(L);
                    lua_pushliteral(L, "failed to add event");
                    return 2;
                }
            }

        } else {
            /* llcf->check_client_abort == 0 */
            r->read_event_handler = njt_stream_lua_block_reading;
        }
    }
#endif

    if (u->ft_type) {

        if (u->ft_type & NJT_STREAM_LUA_SOCKET_FT_TIMEOUT) {
            u->no_close = 1;
        }

        dd("u->bufs_in: %p", u->bufs_in);

        if (u->bufs_in) {
            rc = njt_stream_lua_socket_push_input_data(r, ctx, u, L);
            if (rc == NJT_ERROR) {
                lua_pushnil(L);
                lua_pushliteral(L, "no memory");
                return 2;
            }

            (void) njt_stream_lua_socket_read_error_retval_handler(r, u, L);

            lua_pushvalue(L, -3);
            lua_remove(L, -4);
            return 3;
        }

        n = njt_stream_lua_socket_read_error_retval_handler(r, u, L);
        lua_pushliteral(L, "");
        return n + 1;
    }

    rc = njt_stream_lua_socket_push_input_data(r, ctx, u, L);
    if (rc == NJT_ERROR) {
        lua_pushnil(L);
        lua_pushliteral(L, "no memory");
        return 2;
    }

    return 1;
}


static int
njt_stream_lua_socket_tcp_close(lua_State *L)
{
    njt_stream_lua_request_t        *r;

    njt_stream_lua_socket_tcp_upstream_t        *u;

    if (lua_gettop(L) != 1) {
        return luaL_error(L, "expecting 1 argument "
                          "(including the object) but seen %d", lua_gettop(L));
    }

    r = njt_stream_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    luaL_checktype(L, 1, LUA_TTABLE);

    lua_rawgeti(L, 1, SOCKET_CTX_INDEX);
    u = lua_touserdata(L, -1);
    lua_pop(L, 1);

    if (u == NULL
        || u->peer.connection == NULL
        || (u->read_closed && u->write_closed))
    {
        lua_pushnil(L);
        lua_pushliteral(L, "closed");
        return 2;
    }

    if (u->request != r) {
        return luaL_error(L, "bad request");
    }

    njt_stream_lua_socket_check_busy_connecting(r, u, L);
    njt_stream_lua_socket_check_busy_reading(r, u, L);
    njt_stream_lua_socket_check_busy_writing(r, u, L);

    if (u->raw_downstream || u->body_downstream) {
        lua_pushnil(L);
        lua_pushliteral(L, "attempt to close a request socket");
        return 2;
    }

    njt_stream_lua_socket_tcp_finalize(r, u);

    lua_pushinteger(L, 1);
    return 1;
}


static int
njt_stream_lua_socket_tcp_shutdown(lua_State *L)
{
    njt_stream_lua_request_t                    *r;
    njt_stream_lua_socket_tcp_upstream_t        *u;
    njt_str_t                                    direction;
    char                                        *p;
    njt_stream_lua_ctx_t                        *ctx;

    if (lua_gettop(L) != 2) {
        return luaL_error(L, "expecting 2 arguments "
                          "(including the object) but seen %d", lua_gettop(L));
    }

    luaL_checktype(L, 1, LUA_TTABLE);

    lua_rawgeti(L, 1, SOCKET_CTX_INDEX);
    u = lua_touserdata(L, -1);
    lua_pop(L, 1);

    r = njt_stream_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    if (u == NULL
        || u->peer.connection == NULL
        || (u->read_closed && u->write_closed))
    {
        lua_pushnil(L);
        lua_pushliteral(L, "closed");
        return 2;
    }

    if (u->write_closed) {
        lua_pushnil(L);
        lua_pushliteral(L, "already shutdown");
        return 2;
    }

    if (u->request != r) {
        return luaL_error(L, "bad request");
    }

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        njt_stream_lua_socket_handle_write_error(r, u,
                                                NJT_STREAM_LUA_SOCKET_FT_ERROR);
        return NJT_ERROR;
    }

    /*
     * only allow shutdown on raw request in stream module in content phase.
     * in http module, lingering close will take care of the shutdown.
     * in stream module, it is unsafe to shutdown prior on reaching content
     * phase as later phases may still need to write to the socket.
     */

    if (u->raw_downstream) {
        njt_stream_lua_check_context(L, ctx, NJT_STREAM_LUA_CONTEXT_CONTENT);

        if (ctx->eof) {
            lua_pushnil(L);
            lua_pushliteral(L, "seen eof");
            return 2;
        }

        /* prevent all further output attempt */
        ctx->eof = 1;
    }

    njt_stream_lua_socket_check_busy_connecting(r, u, L);
    njt_stream_lua_socket_check_busy_writing(r, u, L);

    /* shutdown */
    direction.data = (u_char *) luaL_checklstring(L, 2, &direction.len);
    if (direction.len == 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "pattern is empty");
        return 2;
    }

    if (direction.len != 4 || njt_strcmp(direction.data, "send") != 0) {
        p = (char *) lua_pushfstring(L, "bad shutdown argument: %s",
                                     (char *) direction.data);

        return luaL_argerror(L, 2, p);
    }

    njt_stream_lua_socket_tcp_finalize_write_part(r, u, 1);

    lua_pushinteger(L, 1);
    return 1;
}


static int
njt_stream_lua_socket_tcp_setoption(lua_State *L)
{
    /* TODO */
    return 0;
}


static int
njt_stream_lua_socket_tcp_settimeout(lua_State *L)
{
    int                     n;
    njt_int_t               timeout;

    njt_stream_lua_socket_tcp_upstream_t        *u;

    n = lua_gettop(L);

    if (n != 2) {
        return luaL_error(L, "njt.socket settimout: expecting 2 arguments "
                          "(including the object) but seen %d", lua_gettop(L));
    }

    timeout = (njt_int_t) lua_tonumber(L, 2);
    if (timeout >> 31) {
        return luaL_error(L, "bad timeout value");
    }

    lua_pushinteger(L, timeout);
    lua_pushinteger(L, timeout);

    lua_rawseti(L, 1, SOCKET_CONNECT_TIMEOUT_INDEX);
    lua_rawseti(L, 1, SOCKET_SEND_TIMEOUT_INDEX);
    lua_rawseti(L, 1, SOCKET_READ_TIMEOUT_INDEX);

    lua_rawgeti(L, 1, SOCKET_CTX_INDEX);
    u = lua_touserdata(L, -1);

    if (u) {
        if (timeout > 0) {
            u->read_timeout = (njt_msec_t) timeout;
            u->send_timeout = (njt_msec_t) timeout;
            u->connect_timeout = (njt_msec_t) timeout;

        } else {
            u->read_timeout = u->conf->read_timeout;
            u->send_timeout = u->conf->send_timeout;
            u->connect_timeout = u->conf->connect_timeout;
        }
    }

    return 0;
}


static int
njt_stream_lua_socket_tcp_settimeouts(lua_State *L)
{
    int                     n;
    njt_int_t               connect_timeout, send_timeout, read_timeout;

    njt_stream_lua_socket_tcp_upstream_t        *u;

    n = lua_gettop(L);

    if (n != 4) {
        return luaL_error(L, "njt.socket settimout: expecting 4 arguments "
                          "(including the object) but seen %d", lua_gettop(L));
    }

    connect_timeout = (njt_int_t) lua_tonumber(L, 2);
    if (connect_timeout >> 31) {
        return luaL_error(L, "bad timeout value");
    }

    send_timeout = (njt_int_t) lua_tonumber(L, 3);
    if (send_timeout >> 31) {
        return luaL_error(L, "bad timeout value");
    }

    read_timeout = (njt_int_t) lua_tonumber(L, 4);
    if (read_timeout >> 31) {
        return luaL_error(L, "bad timeout value");
    }

    lua_rawseti(L, 1, SOCKET_READ_TIMEOUT_INDEX);
    lua_rawseti(L, 1, SOCKET_SEND_TIMEOUT_INDEX);
    lua_rawseti(L, 1, SOCKET_CONNECT_TIMEOUT_INDEX);

    lua_rawgeti(L, 1, SOCKET_CTX_INDEX);
    u = lua_touserdata(L, -1);

    if (u) {
        if (connect_timeout > 0) {
            u->connect_timeout = (njt_msec_t) connect_timeout;

        } else {
            u->connect_timeout = u->conf->connect_timeout;
        }

        if (send_timeout > 0) {
            u->send_timeout = (njt_msec_t) send_timeout;

        } else {
            u->send_timeout = u->conf->send_timeout;
        }

        if (read_timeout > 0) {
            u->read_timeout = (njt_msec_t) read_timeout;

        } else {
            u->read_timeout = u->conf->read_timeout;
        }
    }

    return 0;
}


static void
njt_stream_lua_socket_tcp_handler(njt_event_t *ev)
{
    njt_stream_lua_request_t                       *r;
    njt_stream_lua_socket_tcp_upstream_t           *u;
    njt_connection_t                               *c;

    c = ev->data;
    u = c->data;
    r = u->request;
    c = r->connection;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "stream lua tcp socket handler: wev %d", (int) ev->write);

    if (ev->write) {
        u->write_event_handler(r, u);

    } else {
        u->read_event_handler(r, u);
    }

}


static njt_int_t
njt_stream_lua_socket_tcp_get_peer(njt_peer_connection_t *pc, void *data)
{
    /* empty */
    return NJT_OK;
}


static void
njt_stream_lua_socket_read_handler(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u)
{
    njt_connection_t                    *c;
    njt_stream_lua_loc_conf_t           *llcf;

    c = u->peer.connection;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket read handler");

    if (c->read->timedout) {
        c->read->timedout = 0;

        llcf = njt_stream_lua_get_module_loc_conf(r, njt_stream_lua_module);

        if (llcf->log_socket_errors) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "stream lua tcp socket read timed out");
        }

        njt_stream_lua_socket_handle_read_error(r, u,
                                              NJT_STREAM_LUA_SOCKET_FT_TIMEOUT);
        return;
    }

#if 1
    if (c->read->timer_set) {
        njt_del_timer(c->read);
    }
#endif

    if (u->buffer.start != NULL) {
        (void) njt_stream_lua_socket_tcp_read(r, u);
    }
}


static void
njt_stream_lua_socket_send_handler(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u)
{
    njt_connection_t                    *c;
    njt_stream_lua_loc_conf_t           *llcf;

    c = u->peer.connection;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket send handler");

    if (c->write->timedout) {
        llcf = njt_stream_lua_get_module_loc_conf(r, njt_stream_lua_module);

        if (llcf->log_socket_errors) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "stream lua tcp socket write timed out");
        }

        njt_stream_lua_socket_handle_write_error(r, u,
                                              NJT_STREAM_LUA_SOCKET_FT_TIMEOUT);
        return;
    }

    if (u->request_bufs) {
        (void) njt_stream_lua_socket_send(r, u);
    }
}


static njt_int_t
njt_stream_lua_socket_send(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u)
{
    njt_int_t                    n;
    njt_connection_t            *c;
    njt_stream_lua_ctx_t        *ctx;
    njt_buf_t                   *b;

    c = u->peer.connection;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket send data");

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        njt_stream_lua_socket_handle_write_error(r, u,
                                                NJT_STREAM_LUA_SOCKET_FT_ERROR);
        return NJT_ERROR;
    }

    b = u->request_bufs->buf;

    for (;;) {
        n = c->send(c, b->pos, b->last - b->pos);

        if (n >= 0) {
            b->pos += n;

            if (b->pos == b->last) {
                njt_log_debug0(NJT_LOG_DEBUG_STREAM, c->log, 0,
                               "stream lua tcp socket sent all the data");

                if (c->write->timer_set) {
                    njt_del_timer(c->write);
                }


                njt_chain_update_chains(r->pool,
                                        &ctx->free_bufs, &ctx->busy_bufs,
                                        &u->request_bufs,
                                        (njt_buf_tag_t) &njt_stream_lua_module);

                u->write_event_handler = njt_stream_lua_socket_dummy_handler;

                if (njt_handle_write_event(c->write, 0) != NJT_OK) {
                    njt_stream_lua_socket_handle_write_error(r, u,
                                                NJT_STREAM_LUA_SOCKET_FT_ERROR);
                    return NJT_ERROR;
                }

                njt_stream_lua_socket_handle_write_success(r, u);
                return NJT_OK;
            }

            /* keep sending more data */
            continue;
        }

        /* NJT_ERROR || NJT_AGAIN */
        break;
    }

    if (n == NJT_ERROR) {
        c->error = 1;
        u->socket_errno = njt_socket_errno;
        njt_stream_lua_socket_handle_write_error(r, u,
                                                NJT_STREAM_LUA_SOCKET_FT_ERROR);
        return NJT_ERROR;
    }

    /* n == NJT_AGAIN */

    if (u->raw_downstream) {
        ctx->writing_raw_req_socket = 1;
    }

    u->write_event_handler = njt_stream_lua_socket_send_handler;

    njt_add_timer(c->write, u->send_timeout);

    if (njt_handle_write_event(c->write, u->conf->send_lowat) != NJT_OK) {
        njt_stream_lua_socket_handle_write_error(r, u,
                                                NJT_STREAM_LUA_SOCKET_FT_ERROR);
        return NJT_ERROR;
    }

    return NJT_AGAIN;
}


static void
njt_stream_lua_socket_handle_conn_success(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u)
{
    njt_stream_lua_ctx_t                *ctx;
    njt_stream_lua_co_ctx_t             *coctx;

#if 1
    u->read_event_handler = njt_stream_lua_socket_dummy_handler;
    u->write_event_handler = njt_stream_lua_socket_dummy_handler;
#endif

    if (u->conn_waiting) {
        u->conn_waiting = 0;

        coctx = u->write_co_ctx;
        coctx->cleanup = NULL;
        u->write_co_ctx = NULL;

        ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
        if (ctx == NULL) {
            return;
        }

        ctx->resume_handler = njt_stream_lua_socket_tcp_conn_resume;
        ctx->cur_co_ctx = coctx;

        njt_stream_lua_assert(coctx && (!njt_stream_lua_is_thread(ctx)
                              || coctx->co_ref >= 0));

        njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                       "stream lua tcp socket waking up the current "
                       "request (conn)");

        r->write_event_handler(r);
    }
}


static void
njt_stream_lua_socket_handle_read_success(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u)
{
    njt_stream_lua_ctx_t                *ctx;
    njt_stream_lua_co_ctx_t             *coctx;

#if 1
    u->read_event_handler = njt_stream_lua_socket_dummy_handler;
#endif

    if (u->read_waiting) {
        u->read_waiting = 0;

        coctx = u->read_co_ctx;
        coctx->cleanup = NULL;
        u->read_co_ctx = NULL;

        ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
        if (ctx == NULL) {
            return;
        }

        ctx->resume_handler = njt_stream_lua_socket_tcp_read_resume;
        ctx->cur_co_ctx = coctx;

        njt_stream_lua_assert(coctx && (!njt_stream_lua_is_thread(ctx)
                              || coctx->co_ref >= 0));

        njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                       "stream lua tcp socket waking up the current "
                       "request (read)");

        r->write_event_handler(r);
    }
}


static void
njt_stream_lua_socket_handle_write_success(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u)
{
    njt_stream_lua_ctx_t                *ctx;
    njt_stream_lua_co_ctx_t             *coctx;

#if 1
    u->write_event_handler = njt_stream_lua_socket_dummy_handler;
#endif

    if (u->write_waiting) {
        u->write_waiting = 0;

        coctx = u->write_co_ctx;
        coctx->cleanup = NULL;
        u->write_co_ctx = NULL;

        ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
        if (ctx == NULL) {
            return;
        }

        ctx->resume_handler = njt_stream_lua_socket_tcp_write_resume;
        ctx->cur_co_ctx = coctx;

        njt_stream_lua_assert(coctx && (!njt_stream_lua_is_thread(ctx)
                              || coctx->co_ref >= 0));

        njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                       "stream lua tcp socket waking up the current "
                       "request (read)");

        r->write_event_handler(r);
    }
}


static void
njt_stream_lua_socket_handle_conn_error(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u, njt_uint_t ft_type)
{
    njt_stream_lua_ctx_t                *ctx;
    njt_stream_lua_co_ctx_t             *coctx;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket handle connect error");

    u->ft_type |= ft_type;

#if 1
    njt_stream_lua_socket_tcp_finalize(r, u);
#endif

    u->read_event_handler = njt_stream_lua_socket_dummy_handler;
    u->write_event_handler = njt_stream_lua_socket_dummy_handler;

    dd("connection waiting: %d", (int) u->conn_waiting);

    coctx = u->write_co_ctx;

    if (u->conn_waiting) {
        u->conn_waiting = 0;

        coctx->cleanup = NULL;
        u->write_co_ctx = NULL;

        ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);

        ctx->resume_handler = njt_stream_lua_socket_tcp_conn_resume;
        ctx->cur_co_ctx = coctx;

        njt_stream_lua_assert(coctx && (!njt_stream_lua_is_thread(ctx)
                              || coctx->co_ref >= 0));

        njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                       "stream lua tcp socket waking up the current request");

        r->write_event_handler(r);
    }
}


static void
njt_stream_lua_socket_handle_read_error(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u, njt_uint_t ft_type)
{
    njt_stream_lua_ctx_t                *ctx;
    njt_stream_lua_co_ctx_t             *coctx;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket handle read error");

    u->ft_type |= ft_type;

#if 0
    njt_stream_lua_socket_tcp_finalize(r, u);
#endif

    u->read_event_handler = njt_stream_lua_socket_dummy_handler;

    if (u->read_waiting) {
        u->read_waiting = 0;

        coctx = u->read_co_ctx;
        coctx->cleanup = NULL;
        u->read_co_ctx = NULL;

        ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);

        ctx->resume_handler = njt_stream_lua_socket_tcp_read_resume;
        ctx->cur_co_ctx = coctx;

        njt_stream_lua_assert(coctx && (!njt_stream_lua_is_thread(ctx)
                              || coctx->co_ref >= 0));

        njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                       "stream lua tcp socket waking up the current request");

        r->write_event_handler(r);
    }
}


static void
njt_stream_lua_socket_handle_write_error(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u, njt_uint_t ft_type)
{
    njt_stream_lua_ctx_t                *ctx;
    njt_stream_lua_co_ctx_t             *coctx;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket handle write error");

    u->ft_type |= ft_type;

#if 0
    njt_stream_lua_socket_tcp_finalize(r, u);
#endif

    u->write_event_handler = njt_stream_lua_socket_dummy_handler;

    if (u->write_waiting) {
        u->write_waiting = 0;

        coctx = u->write_co_ctx;
        coctx->cleanup = NULL;
        u->write_co_ctx = NULL;

        ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);

        ctx->resume_handler = njt_stream_lua_socket_tcp_write_resume;
        ctx->cur_co_ctx = coctx;

        njt_stream_lua_assert(coctx && (!njt_stream_lua_is_thread(ctx)
                              || coctx->co_ref >= 0));

        njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                       "stream lua tcp socket waking up the current request");

        r->write_event_handler(r);
    }
}


static void
njt_stream_lua_socket_connected_handler(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u)
{
    njt_int_t                    rc;
    njt_connection_t            *c;

    njt_stream_lua_loc_conf_t           *llcf;

    c = u->peer.connection;

    if (c->write->timedout) {

        llcf = njt_stream_lua_get_module_loc_conf(r, njt_stream_lua_module);

        if (llcf->log_socket_errors) {
            njt_stream_lua_socket_init_peer_connection_addr_text(&u->peer);

            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "stream lua tcp socket connect timed out,"
                          " when connecting to %V:%ud",
                          &c->addr_text, njt_inet_get_port(u->peer.sockaddr));
        }

        njt_stream_lua_socket_handle_conn_error(r, u,
                                              NJT_STREAM_LUA_SOCKET_FT_TIMEOUT);
        return;
    }

    if (c->write->timer_set) {
        njt_del_timer(c->write);
    }

    rc = njt_stream_lua_socket_test_connect(r, c);
    if (rc != NJT_OK) {
        if (rc > 0) {
            u->socket_errno = (njt_err_t) rc;
        }

        njt_stream_lua_socket_handle_conn_error(r, u,
                                                NJT_STREAM_LUA_SOCKET_FT_ERROR);
        return;
    }

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket connected");

    /* We should delete the current write/read event
     * here because the socket object may not be used immediately
     * on the Lua land, thus causing hot spin around level triggered
     * event poll and wasting CPU cycles. */

    if (njt_handle_write_event(c->write, 0) != NJT_OK) {
        njt_stream_lua_socket_handle_conn_error(r, u,
                                                NJT_STREAM_LUA_SOCKET_FT_ERROR);
        return;
    }

    if (njt_handle_read_event(c->read, 0) != NJT_OK) {
        njt_stream_lua_socket_handle_conn_error(r, u,
                                                NJT_STREAM_LUA_SOCKET_FT_ERROR);
        return;
    }

    njt_stream_lua_socket_handle_conn_success(r, u);
}


static void
njt_stream_lua_socket_tcp_cleanup(void *data)
{
    njt_stream_lua_socket_tcp_upstream_t        *u = data;

    njt_stream_lua_request_t    *r;

    r = u->request;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "cleanup lua tcp socket request");

    njt_stream_lua_socket_tcp_finalize(r, u);
}


static void
njt_stream_lua_socket_tcp_finalize_read_part(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u)
{
    njt_chain_t                         *cl;
    njt_chain_t                        **ll;
    njt_connection_t                    *c;
    njt_stream_lua_ctx_t                *ctx;

    if (u->read_closed) {
        return;
    }

    u->read_closed = 1;

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);

    if (ctx && u->bufs_in) {

        ll = &u->bufs_in;
        for (cl = u->bufs_in; cl; cl = cl->next) {
            dd("bufs_in chain: %p, next %p", cl, cl->next);
            cl->buf->pos = cl->buf->last;
            ll = &cl->next;
        }

        dd("ctx: %p", ctx);
        dd("free recv bufs: %p", ctx->free_recv_bufs);
        *ll = ctx->free_recv_bufs;
        ctx->free_recv_bufs = u->bufs_in;
        u->bufs_in = NULL;
        u->buf_in = NULL;
        njt_memzero(&u->buffer, sizeof(njt_buf_t));
    }

    if (u->raw_downstream || u->body_downstream) {
        if (r->connection->read->timer_set) {
            njt_del_timer(r->connection->read);
        }
        return;
    }

    c = u->peer.connection;

    if (c) {
        if (c->read->timer_set) {
            njt_del_timer(c->read);
        }

        if (c->read->active || c->read->disabled) {
            njt_del_event(c->read, NJT_READ_EVENT, NJT_CLOSE_EVENT);
        }

#if defined(njet_version) && njet_version >= 1007005
        if (c->read->posted) {
#else
        if (c->read->prev) {
#endif
            njt_delete_posted_event(c->read);
        }

        c->read->closed = 1;

        /* TODO: shutdown the reading part of the connection */
    }
}


static void
njt_stream_lua_socket_tcp_finalize_write_part(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u, int do_shutdown)

{
    njt_connection_t                    *c;
    njt_stream_lua_ctx_t                *ctx;

    c = u->peer.connection;

    if (u->write_closed) {
        return;
    }

    u->write_closed = 1;

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);

    if (c && do_shutdown) {
        if (njt_shutdown_socket(c->fd, NJT_WRITE_SHUTDOWN) == -1) {
            njt_connection_error(c, njt_socket_errno,
                                 njt_shutdown_socket_n " failed");
            return;
        }

        njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                       "stream lua shutdown socket write direction");
    }

    if (u->raw_downstream || u->body_downstream) {
        if (ctx && ctx->writing_raw_req_socket) {
            ctx->writing_raw_req_socket = 0;
            if (r->connection->write->timer_set) {
                njt_del_timer(r->connection->write);
            }

            r->connection->write->error = 1;
        }
        return;
    }

    if (c) {
        if (c->write->timer_set) {
            njt_del_timer(c->write);
        }

        if (c->write->active || c->write->disabled) {
            njt_del_event(c->write, NJT_WRITE_EVENT, NJT_CLOSE_EVENT);
        }

#if defined(njet_version) && njet_version >= 1007005
        if (c->write->posted) {
#else
        if (c->write->prev) {
#endif
            njt_delete_posted_event(c->write);
        }

        c->write->closed = 1;
    }
}


static void
njt_stream_lua_socket_tcp_conn_op_timeout_handler(njt_event_t *ev)
{
    njt_stream_lua_socket_tcp_upstream_t            *u;
    njt_stream_lua_ctx_t                            *ctx;
    njt_stream_lua_request_t                        *r;
    njt_stream_lua_co_ctx_t                         *coctx;
    njt_stream_lua_loc_conf_t                       *llcf;
    njt_stream_lua_socket_tcp_conn_op_ctx_t         *conn_op_ctx;

    conn_op_ctx = ev->data;
    njt_queue_remove(&conn_op_ctx->queue);

    u = conn_op_ctx->u;
    r = u->request;

    coctx = u->write_co_ctx;
    coctx->cleanup = NULL;
    /* note that we store conn_op_ctx in coctx->data instead of u */
    coctx->data = conn_op_ctx;
    u->write_co_ctx = NULL;

    llcf = njt_stream_lua_get_module_loc_conf(r, njt_stream_lua_module);

    if (llcf->log_socket_errors) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "stream lua tcp socket queued connect "
                      "timed out, when trying to connect to %V:%ud",
                      &conn_op_ctx->host, conn_op_ctx->port);
    }

    njt_queue_insert_head(&u->socket_pool->cache_connect_op,
                          &conn_op_ctx->queue);
    u->socket_pool->connections--;

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        return;
    }

    ctx->cur_co_ctx = coctx;

    njt_stream_lua_assert(coctx && (!njt_stream_lua_is_thread(ctx)
                          || coctx->co_ref >= 0));

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket waking up the current "
                   "request");

    u->write_prepare_retvals =
        njt_stream_lua_socket_tcp_conn_op_timeout_retval_handler;

    if (ctx->entered_content_phase) {
        (void) njt_stream_lua_socket_tcp_conn_op_resume(r);

    } else {
        ctx->resume_handler = njt_stream_lua_socket_tcp_conn_op_resume;
        njt_stream_lua_core_run_phases(r);
    }

}


static int
njt_stream_lua_socket_tcp_conn_op_timeout_retval_handler(
    njt_stream_lua_request_t *r, njt_stream_lua_socket_tcp_upstream_t *u,
    lua_State *L)
{
    lua_pushnil(L);
    lua_pushliteral(L, "timeout");
    return 2;
}


static void
njt_stream_lua_socket_tcp_resume_conn_op(
    njt_stream_lua_socket_pool_t *spool)
{
    njt_queue_t                                     *q;
    njt_stream_lua_socket_tcp_conn_op_ctx_t         *conn_op_ctx;

#if (NJT_DEBUG)
    njt_stream_lua_assert(spool->connections >= 0);

#else
    if (spool->connections < 0) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                      "stream lua tcp socket connections count "
                      "mismatched for connection pool \"%s\", connections: "
                      "%i, size: %i",
                      spool->key, spool->connections, spool->size);
        spool->connections = 0;
    }
#endif

    /* we manually destroy wait_connect_op before triggering connect
     * operation resumption, so that there is no resumption happens when NJet
     * is exiting.
     */
    if (njt_queue_empty(&spool->wait_connect_op)) {
        return;
    }

    q = njt_queue_head(&spool->wait_connect_op);
    conn_op_ctx = njt_queue_data(q,
                                 njt_stream_lua_socket_tcp_conn_op_ctx_t,
                                 queue);
    njt_log_debug4(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0,
                   "stream lua tcp socket post connect operation "
                   "resumption u: %p, ctx: %p for connection pool \"%s\", "
                   "connections: %i",
                   conn_op_ctx->u, conn_op_ctx, spool->key, spool->connections);

    if (conn_op_ctx->event.timer_set) {
        njt_del_timer(&conn_op_ctx->event);
    }

    conn_op_ctx->event.handler =
        njt_stream_lua_socket_tcp_conn_op_resume_handler;

    njt_post_event((&conn_op_ctx->event), &njt_posted_events);
}


static void
njt_stream_lua_socket_tcp_conn_op_ctx_cleanup(void *data)
{
    njt_stream_lua_socket_tcp_upstream_t           *u;
    njt_stream_lua_socket_tcp_conn_op_ctx_t        *conn_op_ctx = data;

    u = conn_op_ctx->u;

    njt_log_debug2(NJT_LOG_DEBUG_STREAM, u->request->connection->log, 0,
                   "stream cleanup lua tcp socket "
                   "conn_op_ctx: %p, u: %p",
                   conn_op_ctx, u);

    njt_queue_insert_head(&u->socket_pool->cache_connect_op,
                          &conn_op_ctx->queue);
}


static void
njt_stream_lua_socket_tcp_conn_op_resume_handler(njt_event_t *ev)
{
    njt_queue_t                                     *q;
    njt_stream_lua_request_t                        *r;
    njt_stream_lua_cleanup_t                        *cln;
    njt_stream_lua_ctx_t                            *ctx;
    njt_stream_lua_co_ctx_t                         *coctx;
    njt_stream_lua_socket_pool_t                    *spool;
    njt_stream_lua_socket_tcp_upstream_t            *u;
    njt_stream_lua_socket_tcp_conn_op_ctx_t         *conn_op_ctx;

    conn_op_ctx = ev->data;
    u = conn_op_ctx->u;
    r = u->request;
    spool = u->socket_pool;

    if (njt_queue_empty(&spool->wait_connect_op)) {
#if (NJT_DEBUG)
        njt_stream_lua_assert(!(spool->backlog >= 0
                              && spool->connections > spool->size));

#else
        if (spool->backlog >= 0 && spool->connections > spool->size) {
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                          "stream lua tcp socket connections count "
                          "mismatched for connection pool \"%s\", connections: "
                          "%i, size: %i",
                          spool->key, spool->connections, spool->size);
            spool->connections = spool->size;
        }
#endif

        return;
    }

    q = njt_queue_head(&spool->wait_connect_op);
    njt_queue_remove(q);

    coctx = u->write_co_ctx;
    coctx->cleanup = NULL;
    /* note that we store conn_op_ctx in coctx->data instead of u */
    coctx->data = conn_op_ctx;
    /* clear njt_stream_lua_tcp_queue_conn_op_cleanup */
    u->write_co_ctx = NULL;

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        njt_queue_insert_head(&spool->cache_connect_op,
                              &conn_op_ctx->queue);
        return;
    }

    ctx->cur_co_ctx = coctx;

    njt_stream_lua_assert(coctx && (!njt_stream_lua_is_thread(ctx)
                          || coctx->co_ref >= 0));

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket waking up the current "
                   "request");

    u->write_prepare_retvals =
        njt_stream_lua_socket_tcp_conn_op_resume_retval_handler;

    if (ctx->entered_content_phase) {
        (void) njt_stream_lua_socket_tcp_conn_op_resume(r);

    } else {
        cln = njt_stream_lua_cleanup_add(r, 0);
        if (cln != NULL) {
            cln->handler = njt_stream_lua_socket_tcp_conn_op_ctx_cleanup;
            cln->data = conn_op_ctx;
            conn_op_ctx->cleanup = &cln->handler;
        }

        ctx->resume_handler = njt_stream_lua_socket_tcp_conn_op_resume;
        njt_stream_lua_core_run_phases(r);
    }

}


static int
njt_stream_lua_socket_tcp_conn_op_resume_retval_handler(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u, lua_State *L)
{
    int                                              nret;
    njt_stream_lua_ctx_t                            *ctx;
    njt_stream_lua_co_ctx_t                         *coctx;
    njt_stream_lua_socket_tcp_conn_op_ctx_t         *conn_op_ctx;

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        return NJT_ERROR;
    }

    coctx = ctx->cur_co_ctx;
    dd("coctx: %p", coctx);
    conn_op_ctx = coctx->data;
    if (conn_op_ctx->cleanup != NULL) {
        *conn_op_ctx->cleanup = NULL;
        njt_stream_lua_cleanup_free(r, conn_op_ctx->cleanup);
        conn_op_ctx->cleanup = NULL;
    }

    /* decrease pending connect operation counter */
    u->socket_pool->connections--;

    nret = njt_stream_lua_socket_tcp_connect_helper(L, u, r, ctx,
                                                    conn_op_ctx->host.data,
                                                    conn_op_ctx->host.len,
                                                    conn_op_ctx->port, 1);
    njt_queue_insert_head(&u->socket_pool->cache_connect_op,
                          &conn_op_ctx->queue);

    return nret;
}


static void
njt_stream_lua_socket_tcp_finalize(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u)
{
    njt_connection_t               *c;

    njt_stream_lua_socket_pool_t           *spool;

    dd("request: %p, u: %p, u->cleanup: %p", r, u, u->cleanup);

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua finalize socket");

    if (u->cleanup) {
        *u->cleanup = NULL;
        njt_stream_lua_cleanup_free(r, u->cleanup);
        u->cleanup = NULL;
    }

    njt_stream_lua_socket_tcp_finalize_read_part(r, u);

    njt_stream_lua_socket_tcp_finalize_write_part(r, u, 0);

    if (u->raw_downstream || u->body_downstream) {
        u->peer.connection = NULL;
        return;
    }

    if (u->resolved && u->resolved->ctx) {
        njt_resolve_name_done(u->resolved->ctx);
        u->resolved->ctx = NULL;
    }

    if (u->peer.free) {
        u->peer.free(&u->peer, u->peer.data, 0);
    }

#if (NJT_STREAM_SSL)
    if (u->ssl_name.data) {
        njt_free(u->ssl_name.data);
        u->ssl_name.data = NULL;
        u->ssl_name.len = 0;
    }
#endif

    c = u->peer.connection;
    if (c) {
        njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                       "lua close socket connection");

        njt_stream_lua_socket_tcp_close_connection(c);
        u->peer.connection = NULL;

        u->conn_closed = 1;

        spool = u->socket_pool;
        if (spool == NULL) {
            return;
        }

        spool->connections--;

        if (spool->connections == 0) {
            njt_stream_lua_socket_free_pool(r->connection->log, spool);
            return;
        }

        njt_stream_lua_socket_tcp_resume_conn_op(spool);
    }
}


static void
njt_stream_lua_socket_tcp_close_connection(njt_connection_t *c)
{
#if (NJT_STREAM_SSL)

    if (c->ssl) {
        c->ssl->no_wait_shutdown = 1;
        c->ssl->no_send_shutdown = 1;

        (void) njt_ssl_shutdown(c);
    }

#endif

    if (c->pool) {
        njt_destroy_pool(c->pool);
        c->pool = NULL;
    }

    njt_close_connection(c);
}


static njt_int_t
njt_stream_lua_socket_test_connect(njt_stream_lua_request_t *r,
    njt_connection_t *c)
{
    int              err;
    socklen_t        len;

    njt_stream_lua_loc_conf_t           *llcf;

#if (NJT_HAVE_KQUEUE)

    njt_event_t     *ev;

    if (njt_event_flags & NJT_USE_KQUEUE_EVENT)  {
        dd("pending eof: (%p)%d (%p)%d", c->write, c->write->pending_eof,
           c->read, c->read->pending_eof);

        if (c->write->pending_eof) {
            ev = c->write;

        } else if (c->read->pending_eof) {
            ev = c->read;

        } else {
            ev = NULL;
        }

        if (ev) {
            llcf = njt_stream_lua_get_module_loc_conf(r, njt_stream_lua_module);
            if (llcf->log_socket_errors) {
                (void) njt_connection_error(c, ev->kq_errno,
                                            "kevent() reported that "
                                            "connect() failed");
            }
            return ev->kq_errno;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = njt_errno;
        }

        if (err) {
            llcf = njt_stream_lua_get_module_loc_conf(r, njt_stream_lua_module);
            if (llcf->log_socket_errors) {
                (void) njt_connection_error(c, err, "connect() failed");
            }
            return err;
        }
    }

    return NJT_OK;
}


static void
njt_stream_lua_socket_dummy_handler(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u)
{
    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket dummy handler");
}


static int
njt_stream_lua_socket_tcp_receiveuntil(lua_State *L)
{
    njt_stream_lua_request_t            *r;
    int                                  n;
    njt_str_t                            pat;
    njt_int_t                            rc;
    size_t                               size;
    unsigned                             inclusive = 0;

    njt_stream_lua_socket_compiled_pattern_t           *cp;

    n = lua_gettop(L);
    if (n != 2 && n != 3) {
        return luaL_error(L, "expecting 2 or 3 arguments "
                          "(including the object), but got %d", n);
    }

    if (n == 3) {
        /* check out the options table */

        luaL_checktype(L, 3, LUA_TTABLE);

        lua_getfield(L, 3, "inclusive");

        switch (lua_type(L, -1)) {
            case LUA_TNIL:
                /* do nothing */
                break;

            case LUA_TBOOLEAN:
                if (lua_toboolean(L, -1)) {
                    inclusive = 1;
                }
                break;

            default:
                return luaL_error(L, "bad \"inclusive\" option value type: %s",
                                  luaL_typename(L, -1));

        }

        lua_pop(L, 2);
    }

    r = njt_stream_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket calling receiveuntil() method");

    luaL_checktype(L, 1, LUA_TTABLE);

    pat.data = (u_char *) luaL_checklstring(L, 2, &pat.len);
    if (pat.len == 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "pattern is empty");
        return 2;
    }

    size = sizeof(njt_stream_lua_socket_compiled_pattern_t);

    cp = lua_newuserdata(L, size);
    if (cp == NULL) {
        return luaL_error(L, "no memory");
    }

    lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(
                          pattern_udata_metatable_key));
    lua_rawget(L, LUA_REGISTRYINDEX);
    lua_setmetatable(L, -2);

    njt_memzero(cp, size);

    cp->inclusive = inclusive;

    rc = njt_stream_lua_socket_compile_pattern(pat.data, pat.len, cp,
                                               r->connection->log);

    if (rc != NJT_OK) {
        lua_pushnil(L);
        lua_pushliteral(L, "failed to compile pattern");
        return 2;
    }

    lua_pushcclosure(L, njt_stream_lua_socket_receiveuntil_iterator, 3);
    return 1;
}


static int
njt_stream_lua_socket_receiveuntil_iterator(lua_State *L)
{
    njt_stream_lua_request_t            *r;
    njt_int_t                            rc;
    njt_stream_lua_ctx_t                *ctx;
    lua_Integer                          bytes;
    int                                  n;

    njt_stream_lua_socket_tcp_upstream_t            *u;
    njt_stream_lua_co_ctx_t                         *coctx;
    njt_stream_lua_socket_compiled_pattern_t        *cp;

    n = lua_gettop(L);
    if (n > 1) {
        return luaL_error(L, "expecting 0 or 1 arguments, "
                          "but seen %d", n);
    }

    if (n >= 1) {
        bytes = luaL_checkinteger(L, 1);
        if (bytes < 0) {
            bytes = 0;
        }

    } else {
        bytes = 0;
    }

    lua_rawgeti(L, lua_upvalueindex(1), SOCKET_CTX_INDEX);
    u = lua_touserdata(L, -1);
    lua_pop(L, 1);

    if (u == NULL || u->peer.connection == NULL || u->read_closed) {
        lua_pushnil(L);
        lua_pushliteral(L, "closed");
        return 2;
    }

    r = njt_stream_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    if (u->request != r) {
        return luaL_error(L, "bad request");
    }

    njt_stream_lua_socket_check_busy_connecting(r, u, L);
    njt_stream_lua_socket_check_busy_reading(r, u, L);

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket receiveuntil iterator");

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket read timeout: %M", u->read_timeout);

    u->input_filter = njt_stream_lua_socket_read_until;

    cp = lua_touserdata(L, lua_upvalueindex(3));

    dd("checking existing state: %d", cp->state);

    if (cp->state == -1) {
        cp->state = 0;

        lua_pushnil(L);
        lua_pushnil(L);
        lua_pushnil(L);
        return 3;
    }

    cp->upstream = u;

    cp->pattern.data =
        (u_char *) lua_tolstring(L, lua_upvalueindex(2),
                                 &cp->pattern.len);

    u->input_filter_ctx = cp;

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);

    if (u->bufs_in == NULL) {
        u->bufs_in =
            njt_stream_lua_chain_get_free_buf(r->connection->log, r->pool,
                                              &ctx->free_recv_bufs,
                                              u->conf->buffer_size);

        if (u->bufs_in == NULL) {
            return luaL_error(L, "no memory");
        }

        u->buf_in = u->bufs_in;
        u->buffer = *u->buf_in->buf;
    }

    u->length = (size_t) bytes;
    u->rest = u->length;

    if (u->raw_downstream || u->body_downstream) {
        r->read_event_handler = njt_stream_lua_req_socket_rev_handler;
    }

    u->read_waiting = 0;
    u->read_co_ctx = NULL;

    rc = njt_stream_lua_socket_tcp_read(r, u);

    if (rc == NJT_ERROR) {
        dd("read failed: %d", (int) u->ft_type);
        rc = njt_stream_lua_socket_tcp_receive_retval_handler(r, u, L);
        dd("tcp receive retval returned: %d", (int) rc);
        return rc;
    }

    if (rc == NJT_OK) {

        njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                       "stream lua tcp socket receive done in a single run");

        return njt_stream_lua_socket_tcp_receive_retval_handler(r, u, L);
    }

    /* rc == NJT_AGAIN */

    coctx = ctx->cur_co_ctx;

    u->read_event_handler = njt_stream_lua_socket_read_handler;

    njt_stream_lua_cleanup_pending_operation(coctx);
    coctx->cleanup = njt_stream_lua_coctx_cleanup;
    coctx->data = u;

    if (ctx->entered_content_phase) {
        r->write_event_handler = njt_stream_lua_content_wev_handler;

    } else {
        r->write_event_handler = njt_stream_lua_core_run_phases;
    }

    u->read_co_ctx = coctx;
    u->read_waiting = 1;
    u->read_prepare_retvals = njt_stream_lua_socket_tcp_receive_retval_handler;

    dd("setting data to %p", u);

    if (u->raw_downstream || u->body_downstream) {
        ctx->downstream = u;
    }

    return lua_yield(L, 0);
}


static njt_int_t
njt_stream_lua_socket_compile_pattern(u_char *data, size_t len,
    njt_stream_lua_socket_compiled_pattern_t *cp, njt_log_t *log)
{
    size_t              i;
    size_t              prefix_len;
    size_t              size;
    unsigned            found;
    int                 cur_state, new_state;

    njt_stream_lua_dfa_edge_t               *edge;
    njt_stream_lua_dfa_edge_t              **last = NULL;

    cp->pattern.len = len;

    if (len <= 2) {
        return NJT_OK;
    }

    for (i = 1; i < len; i++) {
        prefix_len = 1;

        while (prefix_len <= len - i - 1) {

            if (njt_memcmp(data, &data[i], prefix_len) == 0) {
                if (data[prefix_len] == data[i + prefix_len]) {
                    prefix_len++;
                    continue;
                }

                cur_state = i + prefix_len;
                new_state = prefix_len + 1;

                if (cp->recovering == NULL) {
                    size = sizeof(void *) * (len - 2);
                    cp->recovering = njt_alloc(size, log);
                    if (cp->recovering == NULL) {
                        return NJT_ERROR;
                    }

                    njt_memzero(cp->recovering, size);
                }

                edge = cp->recovering[cur_state - 2];

                found = 0;

                if (edge == NULL) {
                    last = &cp->recovering[cur_state - 2];

                } else {

                    for (; edge; edge = edge->next) {
                        last = &edge->next;

                        if (edge->chr == data[prefix_len]) {
                            found = 1;

                            if (edge->new_state < new_state) {
                                edge->new_state = new_state;
                            }

                            break;
                        }
                    }
                }

                if (!found) {
                    njt_log_debug7(NJT_LOG_DEBUG_STREAM, log, 0,
                                   "stream lua tcp socket read until "
                                   "recovering point: on state %d (%*s), if "
                                   "next is '%c', then recover to state %d "
                                   "(%*s)", cur_state, (size_t) cur_state, data,
                                   data[prefix_len], new_state,
                                   (size_t) new_state, data);

                    edge = njt_alloc(sizeof(njt_stream_lua_dfa_edge_t), log);
                    if (edge == NULL) {
                        return NJT_ERROR;
                    }

                    edge->chr = data[prefix_len];
                    edge->new_state = new_state;
                    edge->next = NULL;

                    *last = edge;
                }

                break;
            }

            break;
        }
    }

    return NJT_OK;
}


static njt_int_t
njt_stream_lua_socket_read_until(void *data, ssize_t bytes)
{
    njt_stream_lua_socket_compiled_pattern_t        *cp = data;
    njt_stream_lua_socket_tcp_upstream_t            *u;

    njt_stream_lua_request_t                *r;
    njt_buf_t                               *b;
    u_char                                   c;
    u_char                                  *pat;
    size_t                                   pat_len;
    int                                      i;
    int                                      state;
    int                                      old_state = 0; /* just to make old
                                                               gcc happy */
    njt_stream_lua_dfa_edge_t               *edge;
    unsigned                                 matched;
    njt_int_t                                rc;

    u = cp->upstream;
    r = u->request;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket read until");

    if (bytes == 0) {
        u->ft_type |= NJT_STREAM_LUA_SOCKET_FT_CLOSED;
        return NJT_ERROR;
    }

    b = &u->buffer;

    pat = cp->pattern.data;
    pat_len = cp->pattern.len;
    state = cp->state;

    i = 0;
    while (i < bytes) {
        c = b->pos[i];

        dd("%d: read char %d, state: %d", i, c, state);

        if (c == pat[state]) {
            i++;
            state++;

            if (state == (int) pat_len) {
                /* already matched the whole pattern */
                dd("pat len: %d", (int) pat_len);

                b->pos += i;

                if (u->length) {
                    cp->state = -1;

                } else {
                    cp->state = 0;
                }

                if (cp->inclusive) {
                    rc = njt_stream_lua_socket_add_pending_data(r, u, b->pos, 0,
                                                                pat, state,
                                                                state);

                    if (rc != NJT_OK) {
                        u->ft_type |= NJT_STREAM_LUA_SOCKET_FT_ERROR;
                        return NJT_ERROR;
                    }
                }

                return NJT_OK;
            }

            continue;
        }

        if (state == 0) {
            u->buf_in->buf->last++;

            i++;

            if (u->length && --u->rest == 0) {
                cp->state = state;
                b->pos += i;
                return NJT_OK;
            }

            continue;
        }

        matched = 0;

        if (cp->recovering && state >= 2) {
            dd("accessing state: %d, index: %d", state, state - 2);
            for (edge = cp->recovering[state - 2]; edge; edge = edge->next) {

                if (edge->chr == c) {
                    dd("matched '%c' and jumping to state %d", c,
                       edge->new_state);

                    old_state = state;
                    state = edge->new_state;
                    matched = 1;
                    break;
                }
            }
        }

        if (!matched) {
#if 1
            dd("adding pending data: %.*s", state, pat);
            rc = njt_stream_lua_socket_add_pending_data(r, u, b->pos, i, pat,
                                                        state, state);

            if (rc != NJT_OK) {
                u->ft_type |= NJT_STREAM_LUA_SOCKET_FT_ERROR;
                return NJT_ERROR;
            }

#endif

            if (u->length) {
                if (u->rest <= (size_t) state) {
                    u->rest = 0;
                    cp->state = 0;
                    b->pos += i;
                    return NJT_OK;

                } else {
                    u->rest -= state;
                }
            }

            state = 0;
            continue;
        }

        /* matched */

        dd("adding pending data: %.*s", (int) (old_state + 1 - state),
           (char *) pat);

        rc = njt_stream_lua_socket_add_pending_data(r, u, b->pos, i, pat,
                                                    old_state + 1 - state,
                                                    old_state);

        if (rc != NJT_OK) {
            u->ft_type |= NJT_STREAM_LUA_SOCKET_FT_ERROR;
            return NJT_ERROR;
        }

        i++;

        if (u->length) {
            if (u->rest <= (size_t) state) {
                u->rest = 0;
                cp->state = state;
                b->pos += i;
                return NJT_OK;

            } else {
                u->rest -= state;
            }
        }

        continue;
    }

    b->pos += i;
    cp->state = state;

    return NJT_AGAIN;
}


static int
njt_stream_lua_socket_cleanup_compiled_pattern(lua_State *L)
{
    njt_stream_lua_socket_compiled_pattern_t            *cp;

    njt_stream_lua_dfa_edge_t       *edge, *p;
    unsigned                         i;

    dd("cleanup compiled pattern");

    cp = lua_touserdata(L, 1);
    if (cp == NULL || cp->recovering == NULL) {
        return 0;
    }

    dd("pattern len: %d", (int) cp->pattern.len);

    for (i = 0; i < cp->pattern.len - 2; i++) {
        edge = cp->recovering[i];

        while (edge) {
            p = edge;
            edge = edge->next;

            dd("freeing edge %p", p);

            njt_free(p);

            dd("edge: %p", edge);
        }
    }

#if 1
    njt_free(cp->recovering);
    cp->recovering = NULL;
#endif

    return 0;
}


int
njt_stream_lua_req_socket_tcp(lua_State *L)
{
    int                              n, raw;
    njt_peer_connection_t           *pc;
    njt_stream_lua_loc_conf_t       *llcf;
    njt_connection_t                *c;
    njt_stream_lua_request_t        *r;
    njt_stream_lua_ctx_t            *ctx;
    njt_stream_lua_cleanup_t        *cln;
    njt_stream_lua_co_ctx_t         *coctx;

    njt_stream_lua_socket_tcp_upstream_t        *u;

    n = lua_gettop(L);

    if (n != 0 && n != 1) {
        return luaL_error(L, "expecting zero arguments, but got %d",
                          lua_gettop(L));
    }

    if (n == 1) {
        lua_pop(L, 1);
    }

    raw = 1;

    r = njt_stream_lua_get_req(L);


    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no ctx found");
    }

    njt_stream_lua_check_context(L, ctx, NJT_STREAM_LUA_CONTEXT_CONTENT
                                 |NJT_STREAM_LUA_CONTEXT_PREREAD);

    c = r->connection;

    if (raw) {

        if (c->buffered) {
            lua_pushnil(L);
            lua_pushliteral(L, "pending data to write");
            return 2;
        }



        dd("ctx acquired raw req socket: %d", ctx->acquired_raw_req_socket);

        if (ctx->acquired_raw_req_socket) {
            lua_pushnil(L);
            lua_pushliteral(L, "duplicate call");
            return 2;
        }

        ctx->acquired_raw_req_socket = 1;


    } else {
    }

    lua_createtable(L, 2 /* narr */, 3 /* nrec */); /* the object */

    if (raw) {
        lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(
                              raw_req_socket_metatable_key));

    }

    lua_rawget(L, LUA_REGISTRYINDEX);
    lua_setmetatable(L, -2);

    u = lua_newuserdata(L, sizeof(njt_stream_lua_socket_tcp_upstream_t));
    if (u == NULL) {
        return luaL_error(L, "no memory");
    }

#if 1
    lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(
                          downstream_udata_metatable_key));
    lua_rawget(L, LUA_REGISTRYINDEX);
    lua_setmetatable(L, -2);
#endif

    lua_rawseti(L, 1, SOCKET_CTX_INDEX);

    njt_memzero(u, sizeof(njt_stream_lua_socket_tcp_upstream_t));

    if (raw) {
        u->raw_downstream = 1;

    } else {
    }

    coctx = ctx->cur_co_ctx;

    u->request = r;

    llcf = njt_stream_lua_get_module_loc_conf(r, njt_stream_lua_module);

    u->conf = llcf;

    u->read_timeout = u->conf->read_timeout;
    u->connect_timeout = u->conf->connect_timeout;
    u->send_timeout = u->conf->send_timeout;

    cln = njt_stream_lua_cleanup_add(r, 0);
    if (cln == NULL) {
        u->ft_type |= NJT_STREAM_LUA_SOCKET_FT_ERROR;
        lua_pushnil(L);
        lua_pushliteral(L, "no memory");
        return 2;
    }

    cln->handler = njt_stream_lua_socket_tcp_cleanup;
    cln->data = u;
    u->cleanup = &cln->handler;

    pc = &u->peer;

    pc->log = c->log;
    pc->log_error = NJT_ERROR_ERR;

    pc->connection = c;

    dd("setting data to %p", u);

    coctx->data = u;
    ctx->downstream = u;

    if (c->read->timer_set) {
        njt_del_timer(c->read);
    }

    if (raw) {
        if (c->write->timer_set) {
            njt_del_timer(c->write);
        }
    }

    lua_settop(L, 1);
    return 1;
}


static void
njt_stream_lua_req_socket_rev_handler(njt_stream_lua_request_t *r)
{
    njt_stream_lua_ctx_t                        *ctx;
    njt_stream_lua_socket_tcp_upstream_t        *u;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "lua request socket read event handler");

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        r->read_event_handler = njt_stream_lua_block_reading;
        return;
    }

    u = ctx->downstream;
    if (u == NULL || u->peer.connection == NULL) {
        r->read_event_handler = njt_stream_lua_block_reading;
        return;
    }

    u->read_event_handler(r, u);
}

static int
njt_stream_lua_socket_tcp_getreusedtimes(lua_State *L)
{
    njt_stream_lua_socket_tcp_upstream_t          *u;

    if (lua_gettop(L) != 1) {
        return luaL_error(L, "expecting 1 argument "
                          "(including the object), but got %d", lua_gettop(L));
    }

    luaL_checktype(L, 1, LUA_TTABLE);

    lua_rawgeti(L, 1, SOCKET_CTX_INDEX);
    u = lua_touserdata(L, -1);

    if (u == NULL
        || u->peer.connection == NULL
        || (u->read_closed && u->write_closed))
    {
        lua_pushnil(L);
        lua_pushliteral(L, "closed");
        return 2;
    }

    lua_pushinteger(L, u->reused);
    return 1;
}


static int
njt_stream_lua_socket_tcp_setkeepalive(lua_State *L)
{
    njt_stream_lua_loc_conf_t                   *llcf;
    njt_stream_lua_socket_tcp_upstream_t        *u;
    njt_stream_lua_socket_pool_t                *spool;
    njt_stream_lua_socket_pool_item_t           *item;

    njt_connection_t                    *c;
    njt_str_t                            key;
    njt_queue_t                         *q;
    njt_peer_connection_t               *pc;
    njt_stream_lua_request_t            *r;
    njt_msec_t                           timeout;
    njt_int_t                            pool_size;
    int                                  n;
    njt_int_t                            rc;
    njt_buf_t                           *b;
    const char                          *msg;

    n = lua_gettop(L);

    if (n < 1 || n > 3) {
        return luaL_error(L, "expecting 1 to 3 arguments "
                          "(including the object), but got %d", n);
    }

    luaL_checktype(L, 1, LUA_TTABLE);

    lua_rawgeti(L, 1, SOCKET_CTX_INDEX);
    u = lua_touserdata(L, -1);
    lua_pop(L, 1);

    if (u == NULL) {
        lua_pushnil(L);
        lua_pushliteral(L, "closed");
        return 2;
    }

    /* stack: obj timeout? size? */

    pc = &u->peer;
    c = pc->connection;

    if (c == NULL || u->read_closed || u->write_closed) {
        lua_pushnil(L);
        lua_pushliteral(L, "closed");
        return 2;
    }

    r = njt_stream_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    if (u->request != r) {
        return luaL_error(L, "bad request");
    }

    njt_stream_lua_socket_check_busy_connecting(r, u, L);
    njt_stream_lua_socket_check_busy_reading(r, u, L);
    njt_stream_lua_socket_check_busy_writing(r, u, L);

    b = &u->buffer;

    if (b->start && njt_buf_size(b)) {
        njt_stream_lua_probe_socket_tcp_setkeepalive_buf_unread(r, u, b->pos,
                                                              b->last - b->pos);

        lua_pushnil(L);
        lua_pushliteral(L, "unread data in buffer");
        return 2;
    }

    if (c->read->eof
        || c->read->error
        || c->read->timedout
        || c->write->error
        || c->write->timedout)
    {
        lua_pushnil(L);
        lua_pushliteral(L, "invalid connection");
        return 2;
    }

    if (njt_handle_read_event(c->read, 0) != NJT_OK) {
        lua_pushnil(L);
        lua_pushliteral(L, "failed to handle read event");
        return 2;
    }

    if (njt_terminate || njt_exiting) {
        njt_log_debug1(NJT_LOG_DEBUG_STREAM, pc->log, 0,
                       "stream lua tcp socket set keepalive while "
                       "process exiting, closing connection %p", c);

        njt_stream_lua_socket_tcp_finalize(r, u);
        lua_pushinteger(L, 1);
        return 1;
    }

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, pc->log, 0,
                   "stream lua tcp socket set keepalive: saving "
                   "connection %p", c);

    lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(
                          socket_pool_key));
    lua_rawget(L, LUA_REGISTRYINDEX);

    /* stack: obj timeout? size? pools */

    lua_rawgeti(L, 1, SOCKET_KEY_INDEX);
    key.data = (u_char *) lua_tolstring(L, -1, &key.len);
    if (key.data == NULL) {
        lua_pushnil(L);
        lua_pushliteral(L, "key not found");
        return 2;
    }

    dd("saving connection to key %s", lua_tostring(L, -1));

    lua_pushvalue(L, -1);
    lua_rawget(L, -3);
    spool = lua_touserdata(L, -1);
    lua_pop(L, 1);

    /* stack: obj timeout? size? pools cache_key */

    llcf = njt_stream_lua_get_module_loc_conf(r, njt_stream_lua_module);

    if (spool == NULL) {
        /* create a new socket pool for the current peer key */

        if (n >= 3 && !lua_isnil(L, 3)) {
            pool_size = luaL_checkinteger(L, 3);

        } else {
            pool_size = llcf->pool_size;
        }

        if (pool_size <= 0) {
            msg = lua_pushfstring(L, "bad \"pool_size\" option value: %i",
                                  pool_size);
            return luaL_argerror(L, n, msg);
        }

        njt_stream_lua_socket_tcp_create_socket_pool(L, r, key,
                                                     pool_size, -1,
                                                     &spool);
    }

    if (njt_queue_empty(&spool->free)) {

        q = njt_queue_last(&spool->cache);
        njt_queue_remove(q);

        item = njt_queue_data(q, njt_stream_lua_socket_pool_item_t, queue);

        njt_stream_lua_socket_tcp_close_connection(item->connection);

        /* only decrease the counter for connections which were counted */
        if (u->socket_pool != NULL) {
            u->socket_pool->connections--;
        }

    } else {
        q = njt_queue_head(&spool->free);
        njt_queue_remove(q);

        item = njt_queue_data(q, njt_stream_lua_socket_pool_item_t, queue);

        /* we should always increase connections after getting connected,
         * and decrease connections after getting closed.
         * however, we don't create connection pool in previous connect method.
         * so we increase connections here for backward compatibility.
         */
        if (u->socket_pool == NULL) {
            spool->connections++;
        }
    }

    item->connection = c;
    njt_queue_insert_head(&spool->cache, q);

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, pc->log, 0,
                   "stream lua tcp socket clear current socket connection");

    pc->connection = NULL;

#if 0
    if (u->cleanup) {
        *u->cleanup = NULL;
        u->cleanup = NULL;
    }
#endif

    if (c->read->timer_set) {
        njt_del_timer(c->read);
    }

    if (c->write->timer_set) {
        njt_del_timer(c->write);
    }

    if (n >= 2 && !lua_isnil(L, 2)) {
        timeout = (njt_msec_t) luaL_checkinteger(L, 2);

    } else {
        timeout = llcf->keepalive_timeout;
    }

#if (NJT_DEBUG)
    if (timeout == 0) {
        njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                       "stream lua tcp socket keepalive timeout: unlimited");
    }
#endif

    if (timeout) {
        njt_log_debug1(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                       "stream lua tcp socket keepalive timeout: %M ms",
                       timeout);

        njt_add_timer(c->read, timeout);
    }

    c->write->handler = njt_stream_lua_socket_keepalive_dummy_handler;
    c->read->handler = njt_stream_lua_socket_keepalive_rev_handler;

    c->data = item;
    c->idle = 1;
    c->log = njt_cycle->log;
    c->pool->log = njt_cycle->log;
    c->read->log = njt_cycle->log;
    c->write->log = njt_cycle->log;

    item->socklen = pc->socklen;
    njt_memcpy(&item->sockaddr, pc->sockaddr, pc->socklen);
    item->reused = u->reused;

    if (c->read->ready) {
        rc = njt_stream_lua_socket_keepalive_close_handler(c->read);
        if (rc != NJT_OK) {
            lua_pushnil(L);
            lua_pushliteral(L, "connection in dubious state");
            return 2;
        }
    }

#if 1
    njt_stream_lua_socket_tcp_finalize(r, u);
#endif

    /* since we set u->peer->connection to NULL previously, the connect
     * operation won't be resumed in the
     * njt_stream_lua_socket_tcp_finalize.
     * Therefore we need to resume it here.
     */
    njt_stream_lua_socket_tcp_resume_conn_op(spool);

    lua_pushinteger(L, 1);
    return 1;
}


static njt_int_t
njt_stream_lua_get_keepalive_peer(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u)
{
    njt_stream_lua_socket_pool_item_t           *item;
    njt_stream_lua_socket_pool_t                *spool;

    njt_stream_lua_cleanup_t            *cln;
    njt_queue_t                         *q;
    njt_peer_connection_t               *pc;
    njt_connection_t                    *c;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket pool get keepalive peer");

    pc = &u->peer;

    spool = u->socket_pool;

    if (!njt_queue_empty(&spool->cache)) {
        q = njt_queue_head(&spool->cache);

        item = njt_queue_data(q, njt_stream_lua_socket_pool_item_t, queue);
        c = item->connection;

        njt_queue_remove(q);
        njt_queue_insert_head(&spool->free, q);

        njt_log_debug2(NJT_LOG_DEBUG_STREAM, pc->log, 0,
                       "stream lua tcp socket get keepalive peer: "
                       "using connection %p, fd:%d", c, c->fd);

        c->idle = 0;
        c->log = pc->log;
        c->pool->log = pc->log;
        c->read->log = pc->log;
        c->write->log = pc->log;
        c->data = u;

#if 1
        c->write->handler = njt_stream_lua_socket_tcp_handler;
        c->read->handler = njt_stream_lua_socket_tcp_handler;
#endif

        if (c->read->timer_set) {
            njt_del_timer(c->read);
        }

        pc->connection = c;
        pc->cached = 1;

        u->reused = item->reused + 1;

#if 1
        u->write_event_handler = njt_stream_lua_socket_dummy_handler;
        u->read_event_handler = njt_stream_lua_socket_dummy_handler;
#endif

        if (u->cleanup == NULL) {
            cln = njt_stream_lua_cleanup_add(r, 0);
            if (cln == NULL) {
                u->ft_type |= NJT_STREAM_LUA_SOCKET_FT_ERROR;
                return NJT_ERROR;
            }

            cln->handler = njt_stream_lua_socket_tcp_cleanup;
            cln->data = u;
            u->cleanup = &cln->handler;
        }

        return NJT_OK;
    }

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, pc->log, 0,
                   "stream lua tcp socket keepalive: connection pool empty");

    return NJT_DECLINED;
}


static void
njt_stream_lua_socket_keepalive_dummy_handler(njt_event_t *ev)
{
    njt_log_debug0(NJT_LOG_DEBUG_STREAM, ev->log, 0,
                   "stream keepalive dummy handler");
}


static void
njt_stream_lua_socket_keepalive_rev_handler(njt_event_t *ev)
{
    (void) njt_stream_lua_socket_keepalive_close_handler(ev);
}


static njt_int_t
njt_stream_lua_socket_keepalive_close_handler(njt_event_t *ev)
{
    njt_stream_lua_socket_pool_item_t           *item;
    njt_stream_lua_socket_pool_t                *spool;

    int                n;
    char               buf[1];
    njt_connection_t  *c;

    c = ev->data;

    if (c->close) {
        goto close;
    }

    if (c->read->timedout) {
        njt_log_debug0(NJT_LOG_DEBUG_STREAM, ev->log, 0,
                       "stream lua tcp socket keepalive max idle timeout");

        goto close;
    }

    dd("read event ready: %d", (int) c->read->ready);

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, ev->log, 0,
                   "stream lua tcp socket keepalive close handler "
                   "check stale events");

    n = recv(c->fd, buf, 1, MSG_PEEK);

    if (n == -1 && njt_socket_errno == NJT_EAGAIN) {
        /* stale event */

        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            goto close;
        }

        return NJT_OK;
    }

close:

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, ev->log, 0,
                   "stream lua tcp socket keepalive close handler: fd:%d",
                   c->fd);

    item = c->data;
    spool = item->socket_pool;

    njt_stream_lua_socket_tcp_close_connection(c);

    njt_queue_remove(&item->queue);
    njt_queue_insert_head(&spool->free, &item->queue);
    spool->connections--;

    dd("keepalive: connections: %u", (unsigned) spool->connections);

    if (spool->connections == 0) {
        njt_stream_lua_socket_free_pool(ev->log, spool);

    } else {
        njt_stream_lua_socket_tcp_resume_conn_op(spool);
    }

    return NJT_DECLINED;
}


static void
njt_stream_lua_socket_free_pool(njt_log_t *log,
    njt_stream_lua_socket_pool_t *spool)
{
    lua_State                           *L;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, log, 0,
                   "stream lua tcp socket keepalive: free "
                   "connection pool for \"%s\"", spool->key);

    L = spool->lua_vm;

    lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(
                          socket_pool_key));
    lua_rawget(L, LUA_REGISTRYINDEX);
    lua_pushstring(L, (char *) spool->key);
    lua_pushnil(L);
    lua_rawset(L, -3);
    lua_pop(L, 1);
}


static void
njt_stream_lua_socket_shutdown_pool_helper(
    njt_stream_lua_socket_pool_t *spool)
{
    njt_queue_t                                     *q;
    njt_connection_t                                *c;
    njt_stream_lua_socket_pool_item_t               *item;
    njt_stream_lua_socket_tcp_conn_op_ctx_t         *conn_op_ctx;

    while (!njt_queue_empty(&spool->cache)) {
        q = njt_queue_head(&spool->cache);

        item = njt_queue_data(q, njt_stream_lua_socket_pool_item_t, queue);
        c = item->connection;

        njt_stream_lua_socket_tcp_close_connection(c);

        njt_queue_remove(q);
        njt_queue_insert_head(&spool->free, q);
    }

    while (!njt_queue_empty(&spool->cache_connect_op)) {
        q = njt_queue_head(&spool->cache_connect_op);
        njt_queue_remove(q);
        conn_op_ctx = njt_queue_data(q, njt_stream_lua_socket_tcp_conn_op_ctx_t,
                                     queue);
        njt_stream_lua_socket_tcp_free_conn_op_ctx(conn_op_ctx);
    }

    while (!njt_queue_empty(&spool->wait_connect_op)) {
        q = njt_queue_head(&spool->wait_connect_op);
        njt_queue_remove(q);
        conn_op_ctx = njt_queue_data(q, njt_stream_lua_socket_tcp_conn_op_ctx_t,
                                     queue);

        if (conn_op_ctx->event.timer_set) {
            njt_del_timer(&conn_op_ctx->event);
        }

        njt_stream_lua_socket_tcp_free_conn_op_ctx(conn_op_ctx);
    }

    /* spool->connections will be decreased down to zero in
     * njt_stream_lua_socket_tcp_finalize */
}


static int
njt_stream_lua_socket_shutdown_pool(lua_State *L)
{
    njt_stream_lua_socket_pool_t                *spool;

    spool = lua_touserdata(L, 1);

    if (spool != NULL) {
        njt_stream_lua_socket_shutdown_pool_helper(spool);
    }

    return 0;
}


static int
njt_stream_lua_socket_tcp_upstream_destroy(lua_State *L)
{
    njt_stream_lua_socket_tcp_upstream_t            *u;

    dd("upstream destroy triggered by Lua GC");

    u = lua_touserdata(L, 1);
    if (u == NULL) {
        return 0;
    }

    if (u->cleanup) {
        njt_stream_lua_socket_tcp_cleanup(u); /* it will clear u->cleanup */
    }

    return 0;
}


static int
njt_stream_lua_socket_downstream_destroy(lua_State *L)
{
    njt_stream_lua_socket_tcp_upstream_t           *u;

    dd("downstream destroy");

    u = lua_touserdata(L, 1);
    if (u == NULL) {
        dd("u is NULL");
        return 0;
    }

    if (u->cleanup) {
        njt_stream_lua_socket_tcp_cleanup(u); /* it will clear u->cleanup */
    }

    return 0;
}


static njt_int_t
njt_stream_lua_socket_push_input_data(njt_stream_lua_request_t *r,
    njt_stream_lua_ctx_t *ctx, njt_stream_lua_socket_tcp_upstream_t *u,
    lua_State *L)
{
    njt_chain_t             *cl;
    njt_chain_t            **ll;
#if (DDEBUG) || (NJT_DTRACE)
    size_t                   size = 0;
#endif
    size_t                   chunk_size;
    njt_buf_t               *b;
    size_t                   nbufs;
    luaL_Buffer              luabuf;

    dd("bufs_in: %p, buf_in: %p", u->bufs_in, u->buf_in);

    nbufs = 0;
    ll = NULL;

    luaL_buffinit(L, &luabuf);

    for (cl = u->bufs_in; cl; cl = cl->next) {
        b = cl->buf;
        chunk_size = b->last - b->pos;

        dd("copying input data chunk from %p: \"%.*s\"", cl,
           (int) chunk_size, b->pos);

        luaL_addlstring(&luabuf, (char *) b->pos, chunk_size);

        if (cl->next) {
            ll = &cl->next;
        }

#if (DDEBUG) || (NJT_DTRACE)
        size += chunk_size;
#endif

        nbufs++;
    }

    luaL_pushresult(&luabuf);

#if (DDEBUG)
    dd("size: %d, nbufs: %d", (int) size, (int) nbufs);
#endif

#if (NJT_DTRACE)
    njt_stream_lua_probe_socket_tcp_receive_done(r, u,
                                                 (u_char *) lua_tostring(L, -1),
                                                 size);
#endif

    if (nbufs > 1 && ll) {
        dd("recycle buffers: %d", (int) (nbufs - 1));

        *ll = ctx->free_recv_bufs;
        ctx->free_recv_bufs = u->bufs_in;
        u->bufs_in = u->buf_in;
    }

    if (u->buffer.pos == u->buffer.last) {
        dd("resetting u->buffer pos & last");
        u->buffer.pos = u->buffer.start;
        u->buffer.last = u->buffer.start;
    }

    if (u->bufs_in) {
        u->buf_in->buf->last = u->buffer.pos;
        u->buf_in->buf->pos = u->buffer.pos;
    }

    return NJT_OK;
}


static njt_int_t
njt_stream_lua_socket_add_input_buffer(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u)
{
    njt_chain_t                 *cl;
    njt_stream_lua_ctx_t        *ctx;

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);

    cl = njt_stream_lua_chain_get_free_buf(r->connection->log, r->pool,
                                           &ctx->free_recv_bufs,
                                           u->conf->buffer_size);

    if (cl == NULL) {
        return NJT_ERROR;
    }

    u->buf_in->next = cl;
    u->buf_in = cl;
    u->buffer = *cl->buf;

    return NJT_OK;
}


static njt_int_t
njt_stream_lua_socket_add_pending_data(njt_stream_lua_request_t *r,
    njt_stream_lua_socket_tcp_upstream_t *u, u_char *pos, size_t len,
    u_char *pat, int prefix, int old_state)
{
    u_char          *last;
    njt_buf_t       *b;

    dd("resuming data: %d: [%.*s]", prefix, prefix, pat);

    last = &pos[len];

    b = u->buf_in->buf;

    if (last - b->last == old_state) {
        b->last += prefix;
        return NJT_OK;
    }

    dd("need more buffers because %d != %d", (int) (last - b->last),
       (int) old_state);

    if (njt_stream_lua_socket_insert_buffer(r, u, pat, prefix) != NJT_OK) {
        return NJT_ERROR;
    }

    b->pos = last;
    b->last = last;

    return NJT_OK;
}


static njt_int_t njt_stream_lua_socket_insert_buffer(
    njt_stream_lua_request_t *r, njt_stream_lua_socket_tcp_upstream_t *u,
    u_char *pat, size_t prefix)
{
    njt_chain_t             *cl, *new_cl, **ll;
    size_t                   size;
    njt_buf_t               *b;

    njt_stream_lua_ctx_t            *ctx;

    if (prefix <= u->conf->buffer_size) {
        size = u->conf->buffer_size;

    } else {
        size = prefix;
    }

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);

    new_cl = njt_stream_lua_chain_get_free_buf(r->connection->log, r->pool,
                                               &ctx->free_recv_bufs,
                                               size);

    if (new_cl == NULL) {
        return NJT_ERROR;
    }

    b = new_cl->buf;

    b->last = njt_copy(b->last, pat, prefix);

    dd("copy resumed data to %p: %d: \"%.*s\"",
       new_cl, (int) (b->last - b->pos), (int) (b->last - b->pos), b->pos);

    dd("before resuming data: bufs_in %p, buf_in %p, buf_in next %p",
       u->bufs_in, u->buf_in, u->buf_in->next);

    ll = &u->bufs_in;
    for (cl = u->bufs_in; cl->next; cl = cl->next) {
        ll = &cl->next;
    }

    *ll = new_cl;
    new_cl->next = u->buf_in;

    dd("after resuming data: bufs_in %p, buf_in %p, buf_in next %p",
       u->bufs_in, u->buf_in, u->buf_in->next);

#if (DDEBUG)
    for (cl = u->bufs_in; cl; cl = cl->next) {
        b = cl->buf;

        dd("result buf after resuming data: %p: %.*s", cl,
           (int) njt_buf_size(b), b->pos);
    }
#endif

    return NJT_OK;
}


static njt_int_t
njt_stream_lua_socket_tcp_conn_op_resume(njt_stream_lua_request_t *r)
{
    return njt_stream_lua_socket_tcp_resume_helper(r,
                                                   SOCKET_OP_RESUME_CONN);
}


static njt_int_t
njt_stream_lua_socket_tcp_conn_resume(njt_stream_lua_request_t *r)
{
    return njt_stream_lua_socket_tcp_resume_helper(r, SOCKET_OP_CONNECT);
}


static njt_int_t
njt_stream_lua_socket_tcp_read_resume(njt_stream_lua_request_t *r)
{
    return njt_stream_lua_socket_tcp_resume_helper(r, SOCKET_OP_READ);
}


static njt_int_t
njt_stream_lua_socket_tcp_write_resume(njt_stream_lua_request_t *r)
{
    return njt_stream_lua_socket_tcp_resume_helper(r, SOCKET_OP_WRITE);
}


static njt_int_t
njt_stream_lua_socket_tcp_resume_helper(njt_stream_lua_request_t *r,
    int socket_op)
{
    int                                  nret;
    lua_State                           *vm;
    njt_int_t                            rc;
    njt_uint_t                           nreqs;
    njt_connection_t                    *c;

    njt_stream_lua_ctx_t                            *ctx;
    njt_stream_lua_co_ctx_t                         *coctx;
    njt_stream_lua_socket_tcp_upstream_t            *u;
    njt_stream_lua_socket_tcp_conn_op_ctx_t         *conn_op_ctx;
    njt_stream_lua_socket_tcp_retval_handler         prepare_retvals;

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        return NJT_ERROR;
    }

    ctx->resume_handler = njt_stream_lua_wev_handler;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp operation done, resuming lua "
                   "thread");

    coctx = ctx->cur_co_ctx;

    dd("coctx: %p", coctx);

    switch (socket_op) {

    case SOCKET_OP_RESUME_CONN:
        conn_op_ctx = coctx->data;
        u = conn_op_ctx->u;
        prepare_retvals = u->write_prepare_retvals;
        break;

    case SOCKET_OP_CONNECT:
    case SOCKET_OP_WRITE:
        u = coctx->data;
        prepare_retvals = u->write_prepare_retvals;
        break;

    case SOCKET_OP_READ:
        u = coctx->data;
        prepare_retvals = u->read_prepare_retvals;
        break;

    default:
        /* impossible to reach here */
        return NJT_ERROR;
    }

    njt_log_debug2(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua tcp socket calling prepare retvals handler %p, "
                   "u:%p", prepare_retvals, u);

    nret = prepare_retvals(r, u, ctx->cur_co_ctx->co);
    if (socket_op == SOCKET_OP_CONNECT
        && nret > 1
        && !u->conn_closed
        && u->socket_pool != NULL)
    {
        u->socket_pool->connections--;
        njt_stream_lua_socket_tcp_resume_conn_op(u->socket_pool);
    }

    if (nret == NJT_AGAIN) {
        return NJT_DONE;
    }

    c = r->connection;
    vm = njt_stream_lua_get_lua_vm(r, ctx);
    nreqs = c->requests;

    rc = njt_stream_lua_run_thread(vm, r, ctx, nret);

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream lua run thread returned %d", rc);

    if (rc == NJT_AGAIN) {
        return njt_stream_lua_run_posted_threads(c, vm, r, ctx, nreqs);
    }

    if (rc == NJT_DONE) {
        njt_stream_lua_finalize_request(r, NJT_DONE);
        return njt_stream_lua_run_posted_threads(c, vm, r, ctx, nreqs);
    }

    if (ctx->entered_content_phase) {
        njt_stream_lua_finalize_request(r, rc);
        return NJT_DONE;
    }

    return rc;
}


static void
njt_stream_lua_tcp_queue_conn_op_cleanup(void *data)
{
    njt_stream_lua_co_ctx_t                        *coctx = data;
    njt_stream_lua_socket_tcp_upstream_t           *u;
    njt_stream_lua_socket_tcp_conn_op_ctx_t        *conn_op_ctx;

    conn_op_ctx = coctx->data;
    u = conn_op_ctx->u;

    njt_log_debug2(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0,
                   "stream lua tcp socket abort queueing, "
                   "conn_op_ctx: %p, u: %p",
                   conn_op_ctx, u);

    if (conn_op_ctx->event.posted) {
        njt_delete_posted_event(&conn_op_ctx->event);

    } else if (conn_op_ctx->event.timer_set) {
        njt_del_timer(&conn_op_ctx->event);
    }

    njt_queue_remove(&conn_op_ctx->queue);
    njt_queue_insert_head(&u->socket_pool->cache_connect_op,
                          &conn_op_ctx->queue);

    u->socket_pool->connections--;
    njt_stream_lua_socket_tcp_resume_conn_op(u->socket_pool);
}


static void
njt_stream_lua_tcp_resolve_cleanup(void *data)
{
    njt_resolver_ctx_t                          *rctx;
    njt_stream_lua_socket_tcp_upstream_t        *u;
    njt_stream_lua_co_ctx_t                     *coctx = data;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0,
                   "stream lua tcp socket abort resolver");

    u = coctx->data;
    if (u == NULL) {
        return;
    }

    if (u->socket_pool != NULL) {
        u->socket_pool->connections--;
        njt_stream_lua_socket_tcp_resume_conn_op(u->socket_pool);
    }

    rctx = u->resolved->ctx;
    if (rctx == NULL) {
        return;
    }

    /* postpone free the rctx in the handler */
    rctx->handler = njt_resolve_name_done;
}


static void
njt_stream_lua_coctx_cleanup(void *data)
{
    njt_stream_lua_socket_tcp_upstream_t            *u;
    njt_stream_lua_co_ctx_t                         *coctx = data;

    dd("running coctx cleanup");

    u = coctx->data;
    if (u == NULL) {
        return;
    }

    if (u->request == NULL) {
        return;
    }

    njt_stream_lua_socket_tcp_finalize(u->request, u);
}


#if (NJT_STREAM_SSL)

static int
njt_stream_lua_ssl_free_session(lua_State *L)
{
    njt_ssl_session_t      **psession;

    psession = lua_touserdata(L, 1);
    if (psession && *psession != NULL) {
        njt_log_debug1(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0,
                       "stream lua ssl free session: %p", *psession);

        njt_ssl_free_session(*psession);
    }

    return 0;
}

#endif  /* NJT_STREAM_SSL */


void
njt_stream_lua_cleanup_conn_pools(lua_State *L)
{
    njt_stream_lua_socket_pool_t                *spool;

    lua_pushlightuserdata(L, njt_stream_lua_lightudata_mask(
                          socket_pool_key));
    lua_rawget(L, LUA_REGISTRYINDEX); /* table */

    lua_pushnil(L);  /* first key */
    while (lua_next(L, -2) != 0) {
        /* tb key val */
        spool = lua_touserdata(L, -1);

        if (spool != NULL) {
            njt_log_debug2(NJT_LOG_DEBUG_STREAM, njt_cycle->log, 0,
                           "stream lua tcp socket keepalive: free "
                           "connection pool %p for \"%s\"", spool, spool->key);

            njt_stream_lua_socket_shutdown_pool_helper(spool);
        }

        lua_pop(L, 1);
    }

    lua_pop(L, 1);
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
