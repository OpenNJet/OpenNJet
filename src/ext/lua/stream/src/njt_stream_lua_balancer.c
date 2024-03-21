
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_balancer.c.tt2
 */


/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_stream_lua_cache.h"
#include "njt_stream_lua_balancer.h"
#include "njt_stream_lua_util.h"
#include "njt_stream_lua_directive.h"


struct njt_stream_lua_balancer_peer_data_s {
    /* the round robin data must be first */
    njt_stream_upstream_rr_peer_data_t        rrp;

    njt_stream_lua_srv_conf_t                *conf;
    njt_stream_lua_request_t                 *request;

    njt_uint_t                                more_tries;
    njt_uint_t                                total_tries;

    struct sockaddr                          *sockaddr;
    socklen_t                                 socklen;

    njt_str_t                                *host;
    in_port_t                                 port;

    int                                       last_peer_state;

};


#if (NJT_STREAM_SSL && HAVE_NJT_STREAM_BALANCER_EXPORT_PATCH)
static njt_int_t njt_stream_lua_balancer_set_session(njt_peer_connection_t *pc,
    void *data);
static void njt_stream_lua_balancer_save_session(njt_peer_connection_t *pc,
    void *data);
#endif
static njt_int_t njt_stream_lua_balancer_init(njt_conf_t *cf,
    njt_stream_upstream_srv_conf_t *us);


static njt_int_t njt_stream_lua_balancer_init_peer(njt_stream_session_t *s,
    njt_stream_upstream_srv_conf_t *us);


#if (HAS_NJT_STREAM_PROXY_GET_NEXT_UPSTREAM_TRIES_PATCH)
njt_uint_t
njt_stream_proxy_get_next_upstream_tries(njt_stream_session_t *s);
#endif


static njt_int_t njt_stream_lua_balancer_get_peer(njt_peer_connection_t *pc,
    void *data);
static njt_int_t njt_stream_lua_balancer_by_chunk(lua_State *L,
    njt_stream_lua_request_t *r);
void njt_stream_lua_balancer_free_peer(njt_peer_connection_t *pc, void *data,
    njt_uint_t state);


njt_int_t
njt_stream_lua_balancer_handler_file(njt_stream_lua_request_t *r,
    njt_stream_lua_srv_conf_t *lscf, lua_State *L)
{
    njt_int_t           rc;

    rc = njt_stream_lua_cache_loadfile(r->connection->log, L,
                                       lscf->balancer.src.data,
                                       lscf->balancer.src_key);
    if (rc != NJT_OK) {
        return rc;
    }

    /*  make sure we have a valid code chunk */
    njt_stream_lua_assert(lua_isfunction(L, -1));

    return njt_stream_lua_balancer_by_chunk(L, r);
}


njt_int_t
njt_stream_lua_balancer_handler_inline(njt_stream_lua_request_t *r,
    njt_stream_lua_srv_conf_t *lscf, lua_State *L)
{
    njt_int_t           rc;

    rc = njt_stream_lua_cache_loadbuffer(r->connection->log, L,
                                         lscf->balancer.src.data,
                                         lscf->balancer.src.len,
                                         lscf->balancer.src_key,
                                         "=balancer_by_lua");
    if (rc != NJT_OK) {
        return rc;
    }

    /*  make sure we have a valid code chunk */
    njt_stream_lua_assert(lua_isfunction(L, -1));

    return njt_stream_lua_balancer_by_chunk(L, r);
}


char *
njt_stream_lua_balancer_by_lua_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    char        *rv;
    njt_conf_t   save;

    save = *cf;
    cf->handler = njt_stream_lua_balancer_by_lua;
    cf->handler_conf = conf;

    rv = njt_stream_lua_conf_lua_block_parse(cf, cmd);

    *cf = save;

    return rv;
}


char *
njt_stream_lua_balancer_by_lua(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    u_char                      *p;
    u_char                      *name;
    njt_str_t                   *value;

    njt_stream_lua_srv_conf_t               *lscf = conf;
    njt_stream_upstream_srv_conf_t          *uscf;

    dd("enter");

    /*  must specify a content handler */
    if (cmd->post == NULL) {
        return NJT_CONF_ERROR;
    }

    if (lscf->balancer.handler) {
        return "is duplicate";
    }

    value = cf->args->elts;

    lscf->balancer.handler = (njt_stream_lua_srv_conf_handler_pt) cmd->post;

    if (cmd->post == njt_stream_lua_balancer_handler_file) {
        /* Lua code in an external file */

        name = njt_stream_lua_rebase_path(cf->pool, value[1].data,
                                          value[1].len);
        if (name == NULL) {
            return NJT_CONF_ERROR;
        }

        lscf->balancer.src.data = name;
        lscf->balancer.src.len = njt_strlen(name);

        p = njt_palloc(cf->pool, NJT_STREAM_LUA_FILE_KEY_LEN + 1);
        if (p == NULL) {
            return NJT_CONF_ERROR;
        }

        lscf->balancer.src_key = p;

        p = njt_copy(p, NJT_STREAM_LUA_FILE_TAG,
                     NJT_STREAM_LUA_FILE_TAG_LEN);
        p = njt_stream_lua_digest_hex(p, value[1].data, value[1].len);
        *p = '\0';

    } else {
        /* inlined Lua code */

        lscf->balancer.src = value[1];

        p = njt_palloc(cf->pool,
                     sizeof("balancer_by_lua") + NJT_STREAM_LUA_INLINE_KEY_LEN);
        if (p == NULL) {
            return NJT_CONF_ERROR;
        }

        lscf->balancer.src_key = p;

        p = njt_copy(p, "balancer_by_lua", sizeof("balancer_by_lua") - 1);
        p = njt_copy(p, NJT_STREAM_LUA_INLINE_TAG,
                     NJT_STREAM_LUA_INLINE_TAG_LEN);
        p = njt_stream_lua_digest_hex(p, value[1].data, value[1].len);
        *p = '\0';
    }

    uscf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_upstream_module);

    if (uscf->peer.init_upstream) {
        njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                           "load balancing method redefined");
    }

    uscf->peer.init_upstream = njt_stream_lua_balancer_init;

    uscf->flags = NJT_STREAM_UPSTREAM_CREATE
                  |NJT_STREAM_UPSTREAM_WEIGHT
                  |NJT_STREAM_UPSTREAM_MAX_FAILS
                  |NJT_STREAM_UPSTREAM_FAIL_TIMEOUT
                  |NJT_STREAM_UPSTREAM_DOWN;

    return NJT_CONF_OK;
}


static njt_int_t
njt_stream_lua_balancer_init(njt_conf_t *cf,
    njt_stream_upstream_srv_conf_t *us)
{
    if (njt_stream_upstream_init_round_robin(cf, us) != NJT_OK) {
        return NJT_ERROR;
    }

    /* this callback is called upon individual requests */
    us->peer.init = njt_stream_lua_balancer_init_peer;

    return NJT_OK;
}


static njt_int_t
njt_stream_lua_balancer_init_peer(njt_stream_session_t *s,
    njt_stream_upstream_srv_conf_t *us)
{
    njt_stream_lua_srv_conf_t                  *bcf;
    njt_stream_lua_balancer_peer_data_t        *bp;
    njt_stream_upstream_t                      *upstream;

    njt_stream_lua_request_t                      *r;
    njt_stream_lua_ctx_t                          *ctx;

    ctx = njt_stream_get_module_ctx(s, njt_stream_lua_module);
    if (ctx == NULL) {
        ctx = njt_stream_lua_create_ctx(s);

        if (ctx == NULL) {
            return NJT_ERROR;
        }
    }

    r = ctx->request;

    upstream = s->upstream;


    bp = njt_pcalloc(r->pool, sizeof(njt_stream_lua_balancer_peer_data_t));
    if (bp == NULL) {
        return NJT_ERROR;
    }

    upstream->peer.data = &bp->rrp;

    if (njt_stream_upstream_init_round_robin_peer(s, us) != NJT_OK) {
        return NJT_ERROR;
    }

    upstream->peer.get = njt_stream_lua_balancer_get_peer;
    upstream->peer.free = njt_stream_lua_balancer_free_peer;

    upstream->peer.notify = NULL;

#if (NJT_STREAM_SSL && HAVE_NJT_STREAM_BALANCER_EXPORT_PATCH)
    upstream->peer.set_session = njt_stream_lua_balancer_set_session;
    upstream->peer.save_session = njt_stream_lua_balancer_save_session;
#endif

    bcf = njt_stream_conf_upstream_srv_conf(us, njt_stream_lua_module);

    bp->conf = bcf;
    bp->request = r;

    return NJT_OK;
}


static njt_int_t
njt_stream_lua_balancer_get_peer(njt_peer_connection_t *pc, void *data)
{
    lua_State                          *L;
    njt_int_t                           rc;
    njt_stream_lua_request_t           *r;

    njt_stream_lua_ctx_t                       *ctx;
    njt_stream_lua_srv_conf_t                  *lscf;
    njt_stream_lua_main_conf_t                 *lmcf;
    njt_stream_lua_balancer_peer_data_t        *bp = data;

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, pc->log, 0,
                   "lua balancer peer, tries: %ui", pc->tries);

    lscf = bp->conf;

    r = bp->request;

    njt_stream_lua_assert(lscf->balancer.handler && r);

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);

    if (ctx == NULL) {

        ctx = njt_stream_lua_create_ctx(r->session);

        if (ctx == NULL) {
            return NJT_ERROR;
        }

        L = njt_stream_lua_get_lua_vm(r, ctx);

    } else {
        L = njt_stream_lua_get_lua_vm(r, ctx);

        dd("reset ctx");
        njt_stream_lua_reset_ctx(r, L, ctx);
    }

    ctx->context = NJT_STREAM_LUA_CONTEXT_BALANCER;

    bp->sockaddr = NULL;
    bp->socklen = 0;
    bp->more_tries = 0;
    bp->total_tries++;

    lmcf = njt_stream_lua_get_module_main_conf(r, njt_stream_lua_module);

    /* balancer_by_lua does not support yielding and
     * there cannot be any conflicts among concurrent requests,
     * thus it is safe to store the peer data in the main conf.
     */
    lmcf->balancer_peer_data = bp;

    rc = lscf->balancer.handler(r, lscf, L);

    if (rc == NJT_ERROR) {
        return NJT_ERROR;
    }

    if (ctx->exited && ctx->exit_code != NJT_OK) {
        rc = ctx->exit_code;
        if (rc == NJT_ERROR
            || rc == NJT_BUSY
            || rc == NJT_DECLINED
#ifdef HAVE_BALANCER_STATUS_CODE_PATCH
            || rc >= NJT_STREAM_SPECIAL_RESPONSE
#endif
        ) {
            return rc;
        }

        if (rc > NJT_OK) {
            return NJT_ERROR;
        }
    }

    if (bp->sockaddr && bp->socklen) {
        pc->sockaddr = bp->sockaddr;
        pc->socklen = bp->socklen;
        pc->cached = 0;
        pc->connection = NULL;
        pc->name = bp->host;

        bp->rrp.peers->single = 0;

        if (bp->more_tries) {
            r->session->upstream->peer.tries += bp->more_tries;
        }

        dd("tries: %d", (int) r->session->upstream->peer.tries);

        return NJT_OK;
    }

    return njt_stream_upstream_get_round_robin_peer(pc, &bp->rrp);
}


static njt_int_t
njt_stream_lua_balancer_by_chunk(lua_State *L, njt_stream_lua_request_t *r)
{
    u_char                  *err_msg;
    size_t                   len;
    njt_int_t                rc;

    /* init njet context in Lua VM */
    njt_stream_lua_set_req(L, r);

#ifndef OPENRESTY_LUAJIT
    njt_stream_lua_create_new_globals_table(L, 0 /* narr */, 1 /* nrec */);

    /*  {{{ make new env inheriting main thread's globals table */
    lua_createtable(L, 0, 1 /* nrec */);   /* the metatable for the new env */
    njt_stream_lua_get_globals_table(L);
    lua_setfield(L, -2, "__index");
    lua_setmetatable(L, -2);    /*  setmetatable({}, {__index = _G}) */
    /*  }}} */

    lua_setfenv(L, -2);    /*  set new running env for the code closure */
#endif /* OPENRESTY_LUAJIT */

    lua_pushcfunction(L, njt_stream_lua_traceback);
    lua_insert(L, 1);  /* put it under chunk and args */

    /*  protected call user code */
    rc = lua_pcall(L, 0, 1, 1);

    lua_remove(L, 1);  /* remove traceback function */

    dd("rc == %d", (int) rc);

    if (rc != 0) {
        /*  error occurred when running loaded code */
        err_msg = (u_char *) lua_tolstring(L, -1, &len);

        if (err_msg == NULL) {
            err_msg = (u_char *) "unknown reason";
            len = sizeof("unknown reason") - 1;
        }

        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "failed to run balancer_by_lua*: %*s", len, err_msg);

        lua_settop(L, 0); /*  clear remaining elems on stack */

        return NJT_ERROR;
    }

    lua_settop(L, 0); /*  clear remaining elems on stack */
    return rc;
}


void
njt_stream_lua_balancer_free_peer(njt_peer_connection_t *pc, void *data,
    njt_uint_t state)
{
    njt_stream_lua_balancer_peer_data_t        *bp = data;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, pc->log, 0,
                   "lua balancer free peer, tries: %ui", pc->tries);

    if (bp->sockaddr && bp->socklen) {
        bp->last_peer_state = (int) state;

        if (pc->tries) {
            pc->tries--;
        }

        return;
    }

    /* fallback */

    njt_stream_upstream_free_round_robin_peer(pc, data, state);
}


#if (NJT_STREAM_SSL && HAVE_NJT_STREAM_BALANCER_EXPORT_PATCH)
static njt_int_t
njt_stream_lua_balancer_set_session(njt_peer_connection_t *pc, void *data)
{
    njt_stream_lua_balancer_peer_data_t        *bp = data;

    if (bp->sockaddr && bp->socklen) {
        /* TODO */
        return NJT_OK;
    }

    return njt_stream_upstream_set_round_robin_peer_session(pc, &bp->rrp);
}


static void
njt_stream_lua_balancer_save_session(njt_peer_connection_t *pc, void *data)
{
    njt_stream_lua_balancer_peer_data_t        *bp = data;

    if (bp->sockaddr && bp->socklen) {
        /* TODO */
        return;
    }

    njt_stream_upstream_save_round_robin_peer_session(pc, &bp->rrp);
    return;
}

#endif


int
njt_stream_lua_ffi_balancer_set_current_peer(njt_stream_lua_request_t *r,
    const u_char *addr, size_t addr_len, int port, char **err)
{
    njt_url_t                      url;
    njt_stream_lua_ctx_t          *ctx;
    njt_stream_upstream_t         *u;

    njt_stream_lua_main_conf_t                 *lmcf;
    njt_stream_lua_balancer_peer_data_t        *bp;

    if (r == NULL) {
        *err = "no request found";
        return NJT_ERROR;
    }

    u = r->session->upstream;

    if (u == NULL) {
        *err = "no upstream found";
        return NJT_ERROR;
    }

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        *err = "no ctx found";
        return NJT_ERROR;
    }

    if ((ctx->context & NJT_STREAM_LUA_CONTEXT_BALANCER) == 0) {
        *err = "API disabled in the current context";
        return NJT_ERROR;
    }

    lmcf = njt_stream_lua_get_module_main_conf(r, njt_stream_lua_module);

    /* we cannot read r->upstream->peer.data here directly because
     * it could be overridden by other modules like
     * njt_stream_upstream_keepalive_module.
     */
    bp = lmcf->balancer_peer_data;
    if (bp == NULL) {
        *err = "no upstream peer data found";
        return NJT_ERROR;
    }

    njt_memzero(&url, sizeof(njt_url_t));

    url.url.data = njt_palloc(r->pool, addr_len);
    if (url.url.data == NULL) {
        *err = "no memory";
        return NJT_ERROR;
    }

    njt_memcpy(url.url.data, addr, addr_len);

    url.url.len = addr_len;
    url.default_port = (in_port_t) port;
    url.uri_part = 0;
    url.no_resolve = 1;

    if (njt_parse_url(r->pool, &url) != NJT_OK) {
        if (url.err) {
            *err = url.err;
        }

        return NJT_ERROR;
    }

    if (url.addrs && url.addrs[0].sockaddr) {
        bp->sockaddr = url.addrs[0].sockaddr;
        bp->socklen = url.addrs[0].socklen;
        bp->host = &url.addrs[0].name;

    } else {
        *err = "no host allowed";
        return NJT_ERROR;
    }

    return NJT_OK;
}


#if (NJT_STREAM_HAVE_PROXY_TIMEOUT_FIELDS_PATCH)
int
njt_stream_lua_ffi_balancer_set_timeouts(njt_stream_lua_request_t *r,
    long connect_timeout, long timeout,
    char **err)
{
    njt_stream_lua_ctx_t     *ctx;
    njt_stream_proxy_ctx_t   *pctx;

    if (r == NULL) {
        *err = "no request found";
        return NJT_ERROR;
    }

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        *err = "no ctx found";
        return NJT_ERROR;
    }

    if ((ctx->context & NJT_STREAM_LUA_CONTEXT_BALANCER) == 0) {
        *err = "API disabled in the current context";
        return NJT_ERROR;
    }

    pctx = njt_stream_lua_get_module_ctx(r, njt_stream_proxy_module);
    njt_stream_lua_assert(pctx != NULL);
    if (pctx == NULL) {
        *err = "no proxy ctx found";
        return NJT_ERROR;
    }

    if (connect_timeout > 0) {
        pctx->connect_timeout = connect_timeout;
    }

    if (timeout > 0) {
        pctx->timeout = timeout;
    }

    return NJT_OK;
}
#else
int
njt_stream_lua_ffi_balancer_set_timeouts(njt_stream_lua_request_t *r,
    long connect_timeout, long timeout,
    char **err)
{
    *err = "required NJet patch not present, API disabled";
    return NJT_ERROR;
}
#endif


int
njt_stream_lua_ffi_balancer_set_more_tries(njt_stream_lua_request_t *r,
    int count, char **err)
{
#if (HAS_NJT_STREAM_PROXY_GET_NEXT_UPSTREAM_TRIES_PATCH)
    njt_uint_t                                  max_tries, total;
#endif
    njt_stream_lua_ctx_t                       *ctx;
    njt_stream_upstream_t                      *u;

    njt_stream_lua_main_conf_t                 *lmcf;
    njt_stream_lua_balancer_peer_data_t        *bp;

    if (r == NULL) {
        *err = "no request found";
        return NJT_ERROR;
    }

    u = r->session->upstream;

    if (u == NULL) {
        *err = "no upstream found";
        return NJT_ERROR;
    }

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        *err = "no ctx found";
        return NJT_ERROR;
    }

    if ((ctx->context & NJT_STREAM_LUA_CONTEXT_BALANCER) == 0) {
        *err = "API disabled in the current context";
        return NJT_ERROR;
    }

    lmcf = njt_stream_lua_get_module_main_conf(r, njt_stream_lua_module);

    bp = lmcf->balancer_peer_data;
    if (bp == NULL) {
        *err = "no upstream peer data found";
        return NJT_ERROR;
    }

#if (HAS_NJT_STREAM_PROXY_GET_NEXT_UPSTREAM_TRIES_PATCH)
    max_tries = njt_stream_proxy_get_next_upstream_tries(r->session);
    total = bp->total_tries + u->peer.tries - 1;

    if (max_tries && total + count > max_tries) {
        count = max_tries - total;
        *err = "reduced tries due to limit";

    } else {
        *err = NULL;
    }
#else
    *err = NULL;
#endif

    bp->more_tries = count;
    return NJT_OK;
}


int
njt_stream_lua_ffi_balancer_get_last_failure(njt_stream_lua_request_t *r,
    int *status, char **err)
{
    njt_stream_lua_ctx_t                       *ctx;
    njt_stream_upstream_t                      *u;
    njt_stream_lua_balancer_peer_data_t        *bp;
    njt_stream_lua_main_conf_t                 *lmcf;

    if (r == NULL) {
        *err = "no request found";
        return NJT_ERROR;
    }

    u = r->session->upstream;

    if (u == NULL) {
        *err = "no upstream found";
        return NJT_ERROR;
    }

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);
    if (ctx == NULL) {
        *err = "no ctx found";
        return NJT_ERROR;
    }

    if ((ctx->context & NJT_STREAM_LUA_CONTEXT_BALANCER) == 0) {
        *err = "API disabled in the current context";
        return NJT_ERROR;
    }

    lmcf = njt_stream_lua_get_module_main_conf(r, njt_stream_lua_module);

    bp = lmcf->balancer_peer_data;
    if (bp == NULL) {
        *err = "no upstream peer data found";
        return NJT_ERROR;
    }

    *status = 0;

    return bp->last_peer_state;
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
