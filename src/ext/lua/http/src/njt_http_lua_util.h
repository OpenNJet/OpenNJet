
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.yy
 */


#ifndef _NJT_HTTP_LUA_UTIL_H_INCLUDED_
#define _NJT_HTTP_LUA_UTIL_H_INCLUDED_


#ifdef DDEBUG
#include "ddebug.h"
#endif


#include "njt_http_lua_common.h"
#include "njt_http_lua_ssl.h"
#include "njt_http_lua_api.h"


#ifndef NJT_UNESCAPE_URI_COMPONENT
#   define NJT_UNESCAPE_URI_COMPONENT 0
#endif


#ifndef NJT_HTTP_SWITCHING_PROTOCOLS
#   define NJT_HTTP_SWITCHING_PROTOCOLS 101
#endif

#define NJT_HTTP_LUA_ESCAPE_HEADER_NAME  7

#define NJT_HTTP_LUA_ESCAPE_HEADER_VALUE  8

#define NJT_HTTP_LUA_CONTEXT_YIELDABLE (NJT_HTTP_LUA_CONTEXT_REWRITE         \
                                | NJT_HTTP_LUA_CONTEXT_SERVER_REWRITE        \
                                | NJT_HTTP_LUA_CONTEXT_ACCESS                \
                                | NJT_HTTP_LUA_CONTEXT_CONTENT               \
                                | NJT_HTTP_LUA_CONTEXT_TIMER                 \
                                | NJT_HTTP_LUA_CONTEXT_SSL_CLIENT_HELLO      \
                                | NJT_HTTP_LUA_CONTEXT_SSL_CERT              \
                                | NJT_HTTP_LUA_CONTEXT_SSL_SESS_FETCH)


/* key in Lua vm registry for all the "njt.ctx" tables */
#define njt_http_lua_ctx_tables_key  "njt_lua_ctx_tables"


#define njt_http_lua_context_name(c)                                         \
    ((c) == NJT_HTTP_LUA_CONTEXT_SET ? "set_by_lua*"                         \
     : (c) == NJT_HTTP_LUA_CONTEXT_REWRITE ? "rewrite_by_lua*"               \
     : (c) == NJT_HTTP_LUA_CONTEXT_SERVER_REWRITE ? "server_rewrite_by_lua*" \
     : (c) == NJT_HTTP_LUA_CONTEXT_ACCESS ? "access_by_lua*"                 \
     : (c) == NJT_HTTP_LUA_CONTEXT_CONTENT ? "content_by_lua*"               \
     : (c) == NJT_HTTP_LUA_CONTEXT_LOG ? "log_by_lua*"                       \
     : (c) == NJT_HTTP_LUA_CONTEXT_HEADER_FILTER ? "header_filter_by_lua*"   \
     : (c) == NJT_HTTP_LUA_CONTEXT_BODY_FILTER ? "body_filter_by_lua*"       \
     : (c) == NJT_HTTP_LUA_CONTEXT_TIMER ? "njt.timer"                       \
     : (c) == NJT_HTTP_LUA_CONTEXT_INIT_WORKER ? "init_worker_by_lua*"       \
     : (c) == NJT_HTTP_LUA_CONTEXT_EXIT_WORKER ? "exit_worker_by_lua*"       \
     : (c) == NJT_HTTP_LUA_CONTEXT_BALANCER ? "balancer_by_lua*"             \
     : (c) == NJT_HTTP_LUA_CONTEXT_SSL_CLIENT_HELLO ?                        \
                                                 "ssl_client_hello_by_lua*"  \
     : (c) == NJT_HTTP_LUA_CONTEXT_SSL_CERT ? "ssl_certificate_by_lua*"      \
     : (c) == NJT_HTTP_LUA_CONTEXT_SSL_SESS_STORE ?                          \
                                                 "ssl_session_store_by_lua*" \
     : (c) == NJT_HTTP_LUA_CONTEXT_SSL_SESS_FETCH ?                          \
                                                 "ssl_session_fetch_by_lua*" \
     : "(unknown)")


#define njt_http_lua_check_context(L, ctx, flags)                            \
    if (!((ctx)->context & (flags))) {                                       \
        return luaL_error(L, "API disabled in the context of %s",            \
                          njt_http_lua_context_name((ctx)->context));        \
    }


#define njt_http_lua_check_fake_request(L, r)                                \
    if ((r)->connection->fd == (njt_socket_t) -1) {                          \
        return luaL_error(L, "API disabled in the current context");         \
    }


#define njt_http_lua_check_fake_request2(L, r, ctx)                          \
    if ((r)->connection->fd == (njt_socket_t) -1) {                          \
        return luaL_error(L, "API disabled in the context of %s",            \
                          njt_http_lua_context_name((ctx)->context));        \
    }


#define njt_http_lua_check_if_abortable(L, ctx)                              \
    if ((ctx)->no_abort) {                                                   \
        return luaL_error(L, "attempt to abort with pending subrequests");   \
    }


#define njt_http_lua_ssl_get_ctx(ssl_conn)                                   \
    SSL_get_ex_data(ssl_conn, njt_http_lua_ssl_ctx_index)


#define njt_http_lua_hash_literal(s)                                         \
    njt_http_lua_hash_str((u_char *) s, sizeof(s) - 1)


typedef struct {
    njt_http_lua_ffi_str_t   key;
    njt_http_lua_ffi_str_t   value;
} njt_http_lua_ffi_table_elt_t;


/* char whose address we use as the key in Lua vm registry for
 * user code cache table */
extern char njt_http_lua_code_cache_key;

/* char whose address we use as the key in Lua vm registry for
 * socket connection pool table */
extern char njt_http_lua_socket_pool_key;

/* coroutine anchoring table key in Lua VM registry */
extern char njt_http_lua_coroutines_key;

/* key to the metatable for njt.req.get_headers() and njt.resp.get_headers() */
extern char njt_http_lua_headers_metatable_key;


static njt_inline njt_int_t
njt_http_lua_ffi_check_context(njt_http_lua_ctx_t *ctx, unsigned flags,
    u_char *err, size_t *errlen)
{
    if (!(ctx->context & flags)) {
        *errlen = njt_snprintf(err, *errlen,
                               "API disabled in the context of %s",
                               njt_http_lua_context_name((ctx)->context))
                  - err;

        return NJT_DECLINED;
    }

    return NJT_OK;
}


njt_int_t njt_http_lua_init_vm(lua_State **new_vm, lua_State *parent_vm,
    njt_cycle_t *cycle, njt_pool_t *pool, njt_http_lua_main_conf_t *lmcf,
    njt_log_t *log, njt_pool_cleanup_t **pcln);

lua_State *njt_http_lua_new_thread(njt_http_request_t *r, lua_State *l,
    int *ref);

u_char *njt_http_lua_rebase_path(njt_pool_t *pool, u_char *src, size_t len);

njt_int_t njt_http_lua_send_header_if_needed(njt_http_request_t *r,
    njt_http_lua_ctx_t *ctx);

njt_int_t njt_http_lua_send_chain_link(njt_http_request_t *r,
    njt_http_lua_ctx_t *ctx, njt_chain_t *cl);

void njt_http_lua_discard_bufs(njt_pool_t *pool, njt_chain_t *in);

njt_int_t njt_http_lua_add_copy_chain(njt_http_request_t *r,
    njt_http_lua_ctx_t *ctx, njt_chain_t ***plast, njt_chain_t *in,
    njt_int_t *eof);

void njt_http_lua_reset_ctx(njt_http_request_t *r, lua_State *L,
    njt_http_lua_ctx_t *ctx);

void njt_http_lua_generic_phase_post_read(njt_http_request_t *r);

void njt_http_lua_request_cleanup(njt_http_lua_ctx_t *ctx, int forcible);

void njt_http_lua_request_cleanup_handler(void *data);

njt_int_t njt_http_lua_run_thread(lua_State *L, njt_http_request_t *r,
    njt_http_lua_ctx_t *ctx, volatile int nret);

njt_int_t njt_http_lua_wev_handler(njt_http_request_t *r);

u_char *njt_http_lua_digest_hex(u_char *dest, const u_char *buf,
    int buf_len);

void njt_http_lua_set_multi_value_table(lua_State *L, int index);

void njt_http_lua_unescape_uri(u_char **dst, u_char **src, size_t size,
    njt_uint_t type);

uintptr_t njt_http_lua_escape_uri(u_char *dst, u_char *src,
    size_t size, njt_uint_t type);

njt_int_t njt_http_lua_copy_escaped_header(njt_http_request_t *r,
    njt_str_t *dst, int is_name);

void njt_http_lua_inject_req_api(njt_log_t *log, lua_State *L);

void njt_http_lua_process_args_option(njt_http_request_t *r,
    lua_State *L, int table, njt_str_t *args);

njt_int_t njt_http_lua_open_and_stat_file(u_char *name,
    njt_open_file_info_t *of, njt_log_t *log);

njt_chain_t *njt_http_lua_chain_get_free_buf(njt_log_t *log, njt_pool_t *p,
    njt_chain_t **free, size_t len);

#ifndef OPENRESTY_LUAJIT
void njt_http_lua_create_new_globals_table(lua_State *L, int narr, int nrec);
#endif

int njt_http_lua_traceback(lua_State *L);

njt_http_lua_co_ctx_t *njt_http_lua_get_co_ctx(lua_State *L,
    njt_http_lua_ctx_t *ctx);

njt_http_lua_co_ctx_t *njt_http_lua_create_co_ctx(njt_http_request_t *r,
    njt_http_lua_ctx_t *ctx);

njt_int_t njt_http_lua_run_posted_threads(njt_connection_t *c, lua_State *L,
    njt_http_request_t *r, njt_http_lua_ctx_t *ctx, njt_uint_t nreqs);

njt_int_t njt_http_lua_post_thread(njt_http_request_t *r,
    njt_http_lua_ctx_t *ctx, njt_http_lua_co_ctx_t *coctx);

void njt_http_lua_del_thread(njt_http_request_t *r, lua_State *L,
    njt_http_lua_ctx_t *ctx, njt_http_lua_co_ctx_t *coctx);

void njt_http_lua_rd_check_broken_connection(njt_http_request_t *r);

njt_int_t njt_http_lua_test_expect(njt_http_request_t *r);

njt_int_t njt_http_lua_check_broken_connection(njt_http_request_t *r,
    njt_event_t *ev);

void njt_http_lua_finalize_request(njt_http_request_t *r, njt_int_t rc);

void njt_http_lua_finalize_fake_request(njt_http_request_t *r,
    njt_int_t rc);

void njt_http_lua_close_fake_connection(njt_connection_t *c);

void njt_http_lua_free_fake_request(njt_http_request_t *r);

void njt_http_lua_release_njt_ctx_table(njt_log_t *log, lua_State *L,
    njt_http_lua_ctx_t *ctx);

void njt_http_lua_cleanup_vm(void *data);

njt_connection_t *njt_http_lua_create_fake_connection(njt_pool_t *pool);

njt_http_request_t *njt_http_lua_create_fake_request(njt_connection_t *c);

njt_int_t njt_http_lua_report(njt_log_t *log, lua_State *L, int status,
    const char *prefix);

int njt_http_lua_do_call(njt_log_t *log, lua_State *L);

njt_http_cleanup_t *njt_http_lua_cleanup_add(njt_http_request_t *r,
    size_t size);

void njt_http_lua_cleanup_free(njt_http_request_t *r,
    njt_http_cleanup_pt *cleanup);

#if (NJT_HTTP_LUA_HAVE_SA_RESTART)
void njt_http_lua_set_sa_restart(njt_log_t *log);
#endif

njt_addr_t *njt_http_lua_parse_addr(lua_State *L, u_char *text, size_t len);

size_t njt_http_lua_escape_log(u_char *dst, u_char *src, size_t size);


static njt_inline void
njt_http_lua_init_ctx(njt_http_request_t *r, njt_http_lua_ctx_t *ctx)
{
    njt_memzero(ctx, sizeof(njt_http_lua_ctx_t));
    ctx->ctx_ref = LUA_NOREF;
    ctx->entry_co_ctx.co_ref = LUA_NOREF;
    ctx->entry_co_ctx.next_zombie_child_thread =
        &ctx->entry_co_ctx.zombie_child_threads;
    ctx->resume_handler = njt_http_lua_wev_handler;
    ctx->request = r;
}


static njt_inline njt_http_lua_ctx_t *
njt_http_lua_create_ctx(njt_http_request_t *r)
{
    njt_int_t                    rc;
    lua_State                   *L = NULL;
    njt_http_lua_ctx_t          *ctx;
    njt_pool_cleanup_t          *cln;
    njt_http_lua_loc_conf_t     *llcf;
    njt_http_lua_main_conf_t    *lmcf;

    ctx = njt_palloc(r->pool, sizeof(njt_http_lua_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    njt_http_lua_init_ctx(r, ctx);
    njt_http_set_ctx(r, ctx, njt_http_lua_module);

    llcf = njt_http_get_module_loc_conf(r, njt_http_lua_module);
    if (!llcf->enable_code_cache && r->connection->fd != (njt_socket_t) -1) {
        lmcf = njt_http_get_module_main_conf(r, njt_http_lua_module);

#ifdef DDEBUG
        dd("lmcf: %p", lmcf);
#endif

        rc = njt_http_lua_init_vm(&L, lmcf->lua, lmcf->cycle, r->pool, lmcf,
                                  r->connection->log, &cln);
        if (rc != NJT_OK) {
            if (rc == NJT_DECLINED) {
                njt_http_lua_assert(L != NULL);

                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "failed to load the 'resty.core' module "
                              "(https://github.com/openresty/lua-resty"
                              "-core); ensure you are using an OpenResty "
                              "release from https://openresty.org/en/"
                              "download.html (reason: %s)",
                              lua_tostring(L, -1));

            } else {
                /* rc == NJT_ERROR */
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "failed to initialize Lua VM");
            }

            return NULL;
        }

        /* rc == NJT_OK */

        njt_http_lua_assert(L != NULL);

        if (lmcf->init_handler) {
            if (lmcf->init_handler(r->connection->log, lmcf, L) != NJT_OK) {
                /* an error happened */
                return NULL;
            }
        }

        ctx->vm_state = cln->data;

    } else {
        ctx->vm_state = NULL;
    }

    return ctx;
}


static njt_inline lua_State *
njt_http_lua_get_lua_vm(njt_http_request_t *r, njt_http_lua_ctx_t *ctx)
{
    njt_http_lua_main_conf_t    *lmcf;

    if (ctx == NULL) {
        ctx = njt_http_get_module_ctx(r, njt_http_lua_module);
    }

    if (ctx && ctx->vm_state) {
        return ctx->vm_state->vm;
    }

    lmcf = njt_http_get_module_main_conf(r, njt_http_lua_module);

#ifdef DDEBUG
    dd("lmcf->lua: %p", lmcf->lua);
#endif

    return lmcf->lua;
}


#ifndef OPENRESTY_LUAJIT
#define njt_http_lua_req_key  "__njt_req"
#endif


static njt_inline njt_http_request_t *
njt_http_lua_get_req(lua_State *L)
{
#ifdef OPENRESTY_LUAJIT
    return lua_getexdata(L);
#else
    njt_http_request_t    *r;

    lua_getglobal(L, njt_http_lua_req_key);
    r = lua_touserdata(L, -1);
    lua_pop(L, 1);

    return r;
#endif
}


static njt_inline void
njt_http_lua_set_req(lua_State *L, njt_http_request_t *r)
{
#ifdef OPENRESTY_LUAJIT
    lua_setexdata(L, (void *) r);
#else
    lua_pushlightuserdata(L, r);
    lua_setglobal(L, njt_http_lua_req_key);
#endif
}


static njt_inline void
njt_http_lua_attach_co_ctx_to_L(lua_State *L, njt_http_lua_co_ctx_t *coctx)
{
#ifdef HAVE_LUA_EXDATA2
    lua_setexdata2(L, (void *) coctx);
#endif
}


#ifndef OPENRESTY_LUAJIT
static njt_inline void
njt_http_lua_get_globals_table(lua_State *L)
{
    lua_pushvalue(L, LUA_GLOBALSINDEX);
}


static njt_inline void
njt_http_lua_set_globals_table(lua_State *L)
{
    lua_replace(L, LUA_GLOBALSINDEX);
}
#endif /* OPENRESTY_LUAJIT */


static njt_inline njt_uint_t
njt_http_lua_hash_str(u_char *src, size_t n)
{
    njt_uint_t  key;

    key = 0;

    while (n--) {
        key = njt_hash(key, *src);
        src++;
    }

    return key;
}


static njt_inline njt_int_t
njt_http_lua_set_content_type(njt_http_request_t *r, njt_http_lua_ctx_t *ctx)
{
    njt_http_lua_loc_conf_t     *llcf;

    ctx->mime_set = 1;

    llcf = njt_http_get_module_loc_conf(r, njt_http_lua_module);
    if (llcf->use_default_type
        && r->headers_out.status != NJT_HTTP_NOT_MODIFIED)
    {
        return njt_http_set_content_type(r);
    }

    return NJT_OK;
}


static njt_inline void
njt_http_lua_cleanup_pending_operation(njt_http_lua_co_ctx_t *coctx)
{
    if (coctx->cleanup) {
        coctx->cleanup(coctx);
        coctx->cleanup = NULL;
    }
}


static njt_inline njt_chain_t *
njt_http_lua_get_flush_chain(njt_http_request_t *r, njt_http_lua_ctx_t *ctx)
{
    njt_chain_t  *cl;

    cl = njt_http_lua_chain_get_free_buf(r->connection->log, r->pool,
                                         &ctx->free_bufs, 0);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf->flush = 1;

    return cl;
}


#if (njet_version < 1011002)
static njt_inline in_port_t
njt_inet_get_port(struct sockaddr *sa)
{
    struct sockaddr_in   *sin;
#if (NJT_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    switch (sa->sa_family) {

#if (NJT_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) sa;
        return ntohs(sin6->sin6_port);
#endif

#if (NJT_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
        return 0;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) sa;
        return ntohs(sin->sin_port);
    }
}
#endif


static njt_inline njt_int_t
njt_http_lua_check_unsafe_uri_bytes(njt_http_request_t *r, u_char *str,
    size_t len, u_char *byte)
{
    size_t           i;
    u_char           c;

                     /* %00-%08, %0A-%1F, %7F */

    static uint32_t  unsafe[] = {
        0xfffffdff, /* 1111 1111 1111 1111  1111 1101 1111 1111 */

                    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

                    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

                    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
        0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
        0x00000000  /* 0000 0000 0000 0000  0000 0000 0000 0000 */
    };

    for (i = 0; i < len; i++, str++) {
        c = *str;
        if (unsafe[c >> 5] & (1 << (c & 0x1f))) {
            *byte = c;
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


static njt_inline void
njt_http_lua_free_thread(njt_http_request_t *r, lua_State *L, int co_ref,
    lua_State *co, njt_http_lua_main_conf_t *lmcf)
{
#ifdef HAVE_LUA_RESETTHREAD
    njt_queue_t                 *q;
    njt_http_lua_thread_ref_t   *tref;
    njt_http_lua_ctx_t          *ctx;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP,
                   r == NULL ? njt_cycle->log : r->connection->log, 0,
                   "lua freeing light thread %p (ref %d)", co, co_ref);

    ctx = r != NULL ? njt_http_get_module_ctx(r, njt_http_lua_module) : NULL;
    if (ctx != NULL
        && L == ctx->entry_co_ctx.co
        && L == lmcf->lua
        && !njt_queue_empty(&lmcf->free_lua_threads))
    {
        lua_resetthread(L, co);

        q = njt_queue_head(&lmcf->free_lua_threads);
        tref = njt_queue_data(q, njt_http_lua_thread_ref_t, queue);

        njt_http_lua_assert(tref->ref == LUA_NOREF);
        njt_http_lua_assert(tref->co == NULL);

        tref->ref = co_ref;
        tref->co = co;

        njt_queue_remove(q);
        njt_queue_insert_head(&lmcf->cached_lua_threads, q);

        njt_log_debug2(NJT_LOG_DEBUG_HTTP,
                       r != NULL ? r->connection->log : njt_cycle->log, 0,
                       "lua caching unused lua thread %p (ref %d)", co,
                       co_ref);

        return;
    }
#endif

    njt_log_debug2(NJT_LOG_DEBUG_HTTP,
                   r != NULL ? r->connection->log : njt_cycle->log, 0,
                   "lua unref lua thread %p (ref %d)", co, co_ref);

    lua_pushlightuserdata(L, njt_http_lua_lightudata_mask(
                          coroutines_key));
    lua_rawget(L, LUA_REGISTRYINDEX);

    luaL_unref(L, -1, co_ref);
    lua_pop(L, 1);
}


static njt_inline int
njt_http_lua_new_cached_thread(lua_State *L, lua_State **out_co,
    njt_http_lua_main_conf_t *lmcf, int set_globals)
{
    int                          co_ref;
    lua_State                   *co;

#ifdef HAVE_LUA_RESETTHREAD
    njt_queue_t                 *q;
    njt_http_lua_thread_ref_t   *tref;

    if (L == lmcf->lua && !njt_queue_empty(&lmcf->cached_lua_threads)) {
        q = njt_queue_head(&lmcf->cached_lua_threads);
        tref = njt_queue_data(q, njt_http_lua_thread_ref_t, queue);

        njt_http_lua_assert(tref->ref != LUA_NOREF);
        njt_http_lua_assert(tref->co != NULL);

        co = tref->co;
        co_ref = tref->ref;

        tref->co = NULL;
        tref->ref = LUA_NOREF;

        njt_queue_remove(q);
        njt_queue_insert_head(&lmcf->free_lua_threads, q);

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "lua reusing cached lua thread %p (ref %d)", co, co_ref);

        lua_pushlightuserdata(L, njt_http_lua_lightudata_mask(
                              coroutines_key));
        lua_rawget(L, LUA_REGISTRYINDEX);
        lua_rawgeti(L, -1, co_ref);

    } else
#endif
    {
        lua_pushlightuserdata(L, njt_http_lua_lightudata_mask(
                              coroutines_key));
        lua_rawget(L, LUA_REGISTRYINDEX);
        co = lua_newthread(L);
        lua_pushvalue(L, -1);
        co_ref = luaL_ref(L, -3);

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, njt_cycle->log, 0,
                       "lua ref lua thread %p (ref %d)", co, co_ref);

#ifndef OPENRESTY_LUAJIT
        if (set_globals) {
            lua_createtable(co, 0, 0);  /* the new globals table */

            /* co stack: global_tb */

            lua_createtable(co, 0, 1);  /* the metatable */
            njt_http_lua_get_globals_table(co);
            lua_setfield(co, -2, "__index");
            lua_setmetatable(co, -2);

            /* co stack: global_tb */

            njt_http_lua_set_globals_table(co);
        }
#endif
    }

    *out_co = co;

    return co_ref;
}


static njt_inline void *
njt_http_lua_hash_find_lc(njt_hash_t *hash, njt_uint_t key, u_char *name,
    size_t len)
{
    njt_uint_t       i;
    njt_hash_elt_t  *elt;

    elt = hash->buckets[key % hash->size];

    if (elt == NULL) {
        return NULL;
    }

    while (elt->value) {
        if (len != (size_t) elt->len) {
            goto next;
        }

        for (i = 0; i < len; i++) {
            if (njt_tolower(name[i]) != elt->name[i]) {
                goto next;
            }
        }

        return elt->value;

    next:

        elt = (njt_hash_elt_t *) njt_align_ptr(&elt->name[0] + elt->len,
                                               sizeof(void *));
        continue;
    }

    return NULL;
}


extern njt_uint_t  njt_http_lua_location_hash;
extern njt_uint_t  njt_http_lua_content_length_hash;


#endif /* _NJT_HTTP_LUA_UTIL_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
