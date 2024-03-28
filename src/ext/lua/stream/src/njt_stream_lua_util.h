
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_util.h.tt2
 */


/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_STREAM_LUA_UTIL_H_INCLUDED_
#define _NJT_STREAM_LUA_UTIL_H_INCLUDED_


#ifdef DDEBUG
#include "ddebug.h"
#endif


#include "njt_stream_lua_common.h"
#include "njt_stream_lua_ssl.h"
#include "njt_stream_lua_api.h"


#ifndef NJT_UNESCAPE_URI_COMPONENT
#define NJT_UNESCAPE_URI_COMPONENT  0
#endif


typedef struct {
    njt_stream_lua_ffi_str_t         key;
    njt_stream_lua_ffi_str_t         value;
} njt_stream_lua_ffi_table_elt_t;


/* char whose address we use as the key in Lua vm registry for
 * user code cache table */
extern char njt_stream_lua_code_cache_key;


/* key in Lua vm registry for all the "njt.ctx" tables */
#define njt_stream_lua_ctx_tables_key  "njt_lua_ctx_tables"


/* char whose address we use as the key in Lua vm registry for
 * regex cache table */
extern char njt_stream_lua_regex_cache_key;

/* char whose address we use as the key in Lua vm registry for
 * socket connection pool table */
extern char njt_stream_lua_socket_pool_key;

/* char whose address we use as the key for the coroutine parent relationship */
extern char njt_stream_lua_coroutine_parents_key;

/* coroutine anchoring table key in Lua VM registry */
extern char njt_stream_lua_coroutines_key;

/* key to the metatable for njt.req.get_headers() and njt.resp.get_headers() */
extern char njt_stream_lua_headers_metatable_key;


#ifndef njt_str_set
#define njt_str_set(str, text)                                               \
    (str)->len = sizeof(text) - 1; (str)->data = (u_char *) text
#endif


#define NJT_STREAM_LUA_CONTEXT_YIELDABLE (NJT_STREAM_LUA_CONTEXT_PREREAD     \
                                | NJT_STREAM_LUA_CONTEXT_CONTENT             \
                                | NJT_STREAM_LUA_CONTEXT_TIMER               \
                                | NJT_STREAM_LUA_CONTEXT_SSL_CLIENT_HELLO    \
                                | NJT_STREAM_LUA_CONTEXT_SSL_CERT)


#define njt_stream_lua_context_name(c)                                       \
    ((c) == NJT_STREAM_LUA_CONTEXT_CONTENT ? "content_by_lua*"               \
     : (c) == NJT_STREAM_LUA_CONTEXT_LOG ? "log_by_lua*"                     \
     : (c) == NJT_STREAM_LUA_CONTEXT_TIMER ? "njt.timer"                     \
     : (c) == NJT_STREAM_LUA_CONTEXT_INIT_WORKER ? "init_worker_by_lua*"     \
     : (c) == NJT_STREAM_LUA_CONTEXT_BALANCER ? "balancer_by_lua*"           \
     : (c) == NJT_STREAM_LUA_CONTEXT_PREREAD ? "preread_by_lua*"             \
     : (c) == NJT_STREAM_LUA_CONTEXT_SSL_CLIENT_HELLO ?                      \
                                                 "ssl_client_hello_by_lua*"  \
     : (c) == NJT_STREAM_LUA_CONTEXT_SSL_CERT ? "ssl_certificate_by_lua*"    \
     : "(unknown)")


#define njt_stream_lua_check_context(L, ctx, flags)                          \
    if (!((ctx)->context & (flags))) {                                       \
        return luaL_error(L, "API disabled in the context of %s",            \
                          njt_stream_lua_context_name((ctx)->context));      \
    }


static njt_inline njt_int_t
njt_stream_lua_ffi_check_context(njt_stream_lua_ctx_t *ctx,
    unsigned flags, u_char *err, size_t *errlen)
{
    if (!(ctx->context & flags)) {
        *errlen = njt_snprintf(err, *errlen,
                               "API disabled in the context of %s",
                               njt_stream_lua_context_name((ctx)->context))
                  - err;

        return NJT_DECLINED;
    }

    return NJT_OK;
}


#define njt_stream_lua_check_fake_request(L, r)                              \
    if ((r)->connection->fd == (njt_socket_t) -1) {                          \
        return luaL_error(L, "API disabled in the current context");         \
    }


#define njt_stream_lua_check_fake_request2(L, r, ctx)                        \
    if ((r)->connection->fd == (njt_socket_t) -1) {                          \
        return luaL_error(L, "API disabled in the context of %s",            \
                          njt_stream_lua_context_name((ctx)                  \
                          ->context));                                       \
    }


#define njt_stream_lua_ssl_get_ctx(ssl_conn)                                 \
    SSL_get_ex_data(ssl_conn, njt_stream_lua_ssl_ctx_index)


njt_int_t njt_stream_lua_init_vm(lua_State **new_vm, lua_State *parent_vm,
    njt_cycle_t *cycle, njt_pool_t *pool,
    njt_stream_lua_main_conf_t *lmcf, njt_log_t *log,
    njt_pool_cleanup_t **pcln);

lua_State *njt_stream_lua_new_thread(njt_stream_lua_request_t *r, lua_State *l,
    int *ref);

u_char *njt_stream_lua_rebase_path(njt_pool_t *pool, u_char *src, size_t len);

njt_int_t njt_stream_lua_send_header_if_needed(njt_stream_lua_request_t *r,
    njt_stream_lua_ctx_t *ctx);

njt_int_t njt_stream_lua_send_chain_link(njt_stream_lua_request_t *r,
    njt_stream_lua_ctx_t *ctx, njt_chain_t *cl);

void njt_stream_lua_discard_bufs(njt_pool_t *pool, njt_chain_t *in);

njt_int_t njt_stream_lua_add_copy_chain(njt_stream_lua_request_t *r,
    njt_stream_lua_ctx_t *ctx, njt_chain_t ***plast, njt_chain_t *in,
    njt_int_t *eof);

void njt_stream_lua_reset_ctx(njt_stream_lua_request_t *r, lua_State *L,
    njt_stream_lua_ctx_t *ctx);

void njt_stream_lua_generic_phase_post_read(njt_stream_lua_request_t *r);

void njt_stream_lua_request_cleanup(njt_stream_lua_ctx_t *ctx, int foricible);

void njt_stream_lua_request_cleanup_handler(void *data);

njt_int_t njt_stream_lua_run_thread(lua_State *L, njt_stream_lua_request_t *r,
    njt_stream_lua_ctx_t *ctx, volatile int nret);

njt_int_t njt_stream_lua_wev_handler(njt_stream_lua_request_t *r);

u_char *njt_stream_lua_digest_hex(u_char *dest, const u_char *buf,
    int buf_len);

void njt_stream_lua_set_multi_value_table(lua_State *L, int index);

void njt_stream_lua_unescape_uri(u_char **dst, u_char **src, size_t size,
    njt_uint_t type);

uintptr_t njt_stream_lua_escape_uri(u_char *dst, u_char *src,
    size_t size, njt_uint_t type);

void njt_stream_lua_inject_req_api(njt_log_t *log, lua_State *L);

void njt_stream_lua_process_args_option(njt_stream_lua_request_t *r,
    lua_State *L, int table, njt_str_t *args);

njt_int_t njt_stream_lua_open_and_stat_file(u_char *name,
    njt_open_file_info_t *of, njt_log_t *log);

njt_chain_t *njt_stream_lua_chain_get_free_buf(njt_log_t *log, njt_pool_t *p,
    njt_chain_t **free, size_t len);


static njt_inline void
njt_stream_lua_attach_co_ctx_to_L(lua_State *L, njt_stream_lua_co_ctx_t *coctx)
{
#ifdef HAVE_LUA_EXDATA2
    lua_setexdata2(L, (void *) coctx);
#endif
}


#ifndef OPENRESTY_LUAJIT
void njt_stream_lua_create_new_globals_table(lua_State *L, int narr, int nrec);
#endif

int njt_stream_lua_traceback(lua_State *L);

njt_stream_lua_co_ctx_t *njt_stream_lua_get_co_ctx(lua_State *L,
    njt_stream_lua_ctx_t *ctx);

njt_stream_lua_co_ctx_t *njt_stream_lua_create_co_ctx(
    njt_stream_lua_request_t *r, njt_stream_lua_ctx_t *ctx);

njt_int_t njt_stream_lua_run_posted_threads(njt_connection_t *c, lua_State *L,
    njt_stream_lua_request_t *r, njt_stream_lua_ctx_t *ctx, njt_uint_t nreqs);

njt_int_t njt_stream_lua_post_thread(njt_stream_lua_request_t *r,
    njt_stream_lua_ctx_t *ctx, njt_stream_lua_co_ctx_t *coctx);

void njt_stream_lua_del_thread(njt_stream_lua_request_t *r, lua_State *L,
    njt_stream_lua_ctx_t *ctx, njt_stream_lua_co_ctx_t *coctx);

void njt_stream_lua_rd_check_broken_connection(njt_stream_lua_request_t *r);

njt_int_t njt_stream_lua_test_expect(njt_stream_lua_request_t *r);

njt_int_t njt_stream_lua_check_broken_connection(njt_stream_lua_request_t *r,
    njt_event_t *ev);

void njt_stream_lua_finalize_request(njt_stream_lua_request_t *r, njt_int_t rc);

void njt_stream_lua_finalize_fake_request(njt_stream_lua_request_t *r,
    njt_int_t rc);

void njt_stream_lua_close_fake_connection(njt_connection_t *c);

void njt_stream_lua_free_fake_request(njt_stream_lua_request_t *r);

void njt_stream_lua_release_njt_ctx_table(njt_log_t *log, lua_State *L,
    njt_stream_lua_ctx_t *ctx);

void njt_stream_lua_cleanup_vm(void *data);

njt_connection_t *njt_stream_lua_create_fake_connection(njt_pool_t *pool);

njt_stream_lua_request_t *
    njt_stream_lua_create_fake_request(njt_stream_session_t *s);

njt_stream_session_t *njt_stream_lua_create_fake_session(njt_connection_t *c);

njt_int_t njt_stream_lua_report(njt_log_t *log, lua_State *L, int status,
    const char *prefix);

int njt_stream_lua_do_call(njt_log_t *log, lua_State *L);



void njt_stream_lua_cleanup_free(njt_stream_lua_request_t *r,
    njt_stream_lua_cleanup_pt *cleanup);

#if (NJT_STREAM_LUA_HAVE_SA_RESTART)
void njt_stream_lua_set_sa_restart(njt_log_t *log);
#endif

#define njt_stream_lua_check_if_abortable(L, ctx)                            \
    if ((ctx)->no_abort) {                                                   \
        return luaL_error(L, "attempt to abort with pending subrequests");   \
    }


static njt_inline void
njt_stream_lua_init_ctx(njt_stream_lua_request_t *r, njt_stream_lua_ctx_t *ctx)
{
    njt_memzero(ctx, sizeof(njt_stream_lua_ctx_t));
    ctx->ctx_ref = LUA_NOREF;
    ctx->entry_co_ctx.co_ref = LUA_NOREF;
    ctx->resume_handler = njt_stream_lua_wev_handler;
    ctx->request = r;
}


static njt_inline njt_stream_lua_ctx_t *
njt_stream_lua_create_ctx(njt_stream_session_t *r)
{
    njt_int_t                            rc;
    lua_State                           *L = NULL;
    njt_stream_lua_ctx_t                *ctx;
    njt_pool_cleanup_t                  *cln;
    njt_stream_lua_loc_conf_t           *llcf;
    njt_stream_lua_main_conf_t          *lmcf;

    njt_stream_lua_request_t               *sreq;

    ctx = njt_palloc(r->connection->pool, sizeof(njt_stream_lua_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    sreq = njt_stream_lua_create_request(r);

    if (sreq == NULL) {
        return NULL;
    }

    njt_stream_lua_init_ctx(sreq, ctx);

    njt_stream_set_ctx(r, ctx, njt_stream_lua_module);

    llcf = njt_stream_get_module_srv_conf(r, njt_stream_lua_module);

    if (!llcf->enable_code_cache && r->connection->fd != (njt_socket_t) -1) {
        lmcf = njt_stream_get_module_main_conf(r, njt_stream_lua_module);

#ifdef DDEBUG
        dd("lmcf: %p", lmcf);
#endif

        /*
         * caveats: we need to move the vm cleanup hook to the list end
         * to ensure it will be executed *after* the request cleanup
         * hook registered by njt_stream_lua_create_request to preserve
         * the correct semantics.
         */

        rc = njt_stream_lua_init_vm(&L, lmcf->lua, lmcf->cycle, sreq->pool,
                                    lmcf, r->connection->log, &cln);

        while (cln->next != NULL) {
            cln = cln->next;
        }

        cln->next = sreq->pool->cleanup;

        cln = sreq->pool->cleanup;
        sreq->pool->cleanup = cln->next;
        cln->next = NULL;

        if (rc != NJT_OK) {
            if (rc == NJT_DECLINED) {
                njt_stream_lua_assert(L != NULL);

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

        njt_stream_lua_assert(L != NULL);

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
njt_stream_lua_get_lua_vm(njt_stream_lua_request_t *r,
    njt_stream_lua_ctx_t *ctx)
{
    njt_stream_lua_main_conf_t          *lmcf;

    if (ctx == NULL) {
        ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    }

    if (ctx && ctx->vm_state) {
        return ctx->vm_state->vm;
    }

    lmcf = njt_stream_lua_get_module_main_conf(r, njt_stream_lua_module);

#ifdef DDEBUG
    dd("lmcf->lua: %p", lmcf->lua);
#endif

    return lmcf->lua;
}


#define njt_stream_lua_req_key  "__njt_req"


static njt_inline njt_stream_lua_request_t *
njt_stream_lua_get_req(lua_State *L)
{
#ifdef OPENRESTY_LUAJIT
    return lua_getexdata(L);
#else
    njt_stream_lua_request_t    *r;

    lua_getglobal(L, njt_stream_lua_req_key);
    r = lua_touserdata(L, -1);
    lua_pop(L, 1);

    return r;
#endif
}


static njt_inline void
njt_stream_lua_set_req(lua_State *L, njt_stream_lua_request_t *r)
{
#ifdef OPENRESTY_LUAJIT
    lua_setexdata(L, (void *) r);
#else
    lua_pushlightuserdata(L, r);
    lua_setglobal(L, njt_stream_lua_req_key);
#endif
}


static njt_inline void
njt_stream_lua_get_globals_table(lua_State *L)
{
    lua_pushvalue(L, LUA_GLOBALSINDEX);
}


static njt_inline void
njt_stream_lua_set_globals_table(lua_State *L)
{
    lua_replace(L, LUA_GLOBALSINDEX);
}


#define njt_stream_lua_hash_literal(s)                                       \
    njt_stream_lua_hash_str((u_char *) s, sizeof(s) - 1)


static njt_inline njt_uint_t
njt_stream_lua_hash_str(u_char *src, size_t n)
{
    njt_uint_t  key;

    key = 0;

    while (n--) {
        key = njt_hash(key, *src);
        src++;
    }

    return key;
}




static njt_inline void
njt_stream_lua_cleanup_pending_operation(njt_stream_lua_co_ctx_t *coctx)
{
    if (coctx->cleanup) {
        coctx->cleanup(coctx);
        coctx->cleanup = NULL;
    }
}


static njt_inline njt_chain_t *
njt_stream_lua_get_flush_chain(njt_stream_lua_request_t *r,
    njt_stream_lua_ctx_t *ctx)
{
    njt_chain_t  *cl;

    cl = njt_stream_lua_chain_get_free_buf(r->connection->log, r->pool,
                                           &ctx->free_bufs, 0);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf->flush = 1;

    return cl;
}


#if defined(njet_version) && njet_version < 1011002
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


extern njt_uint_t  njt_stream_lua_location_hash;
extern njt_uint_t  njt_stream_lua_content_length_hash;


#endif /* _NJT_STREAM_LUA_UTIL_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
