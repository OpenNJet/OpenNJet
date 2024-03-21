/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#if (NJT_STREAM_SSL)

#include "njt_stream_lua_cache.h"
#include "njt_stream_lua_initworkerby.h"
#include "njt_stream_lua_util.h"
#include "njt_stream_ssl_module.h"
#include "njt_stream_lua_contentby.h"
#include "njt_stream_lua_ssl_certby.h"
#include "njt_stream_lua_ssl_client_helloby.h"
#include "njt_stream_lua_directive.h"
#include "njt_stream_lua_ssl.h"


static void njt_stream_lua_ssl_client_hello_done(void *data);
static void njt_stream_lua_ssl_client_hello_aborted(void *data);
static u_char *njt_stream_lua_log_ssl_client_hello_error(njt_log_t *log,
    u_char *buf, size_t len);
static njt_int_t njt_stream_lua_ssl_client_hello_by_chunk(lua_State *L,
    njt_stream_lua_request_t *r);


njt_int_t
njt_stream_lua_ssl_client_hello_handler_file(njt_stream_lua_request_t *r,
    njt_stream_lua_srv_conf_t *lscf, lua_State *L)
{
    njt_int_t           rc;

    rc = njt_stream_lua_cache_loadfile(r->connection->log, L,
                                       lscf->srv.ssl_client_hello_src.data,
                                       lscf->srv.ssl_client_hello_src_key);
    if (rc != NJT_OK) {
        return rc;
    }

    /*  make sure we have a valid code chunk */
    njt_stream_lua_assert(lua_isfunction(L, -1));

    return njt_stream_lua_ssl_client_hello_by_chunk(L, r);
}


njt_int_t
njt_stream_lua_ssl_client_hello_handler_inline(njt_stream_lua_request_t *r,
    njt_stream_lua_srv_conf_t *lscf, lua_State *L)
{
    njt_int_t           rc;

    rc = njt_stream_lua_cache_loadbuffer(r->connection->log, L,
                                         lscf->srv.ssl_client_hello_src.data,
                                         lscf->srv.ssl_client_hello_src.len,
                                         lscf->srv.ssl_client_hello_src_key,
                                         "=ssl_client_hello_by_lua");
    if (rc != NJT_OK) {
        return rc;
    }

    /*  make sure we have a valid code chunk */
    njt_stream_lua_assert(lua_isfunction(L, -1));

    return njt_stream_lua_ssl_client_hello_by_chunk(L, r);
}


char *
njt_stream_lua_ssl_client_hello_by_lua_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    char        *rv;
    njt_conf_t   save;

    save = *cf;
    cf->handler = njt_stream_lua_ssl_client_hello_by_lua;
    cf->handler_conf = conf;

    rv = njt_stream_lua_conf_lua_block_parse(cf, cmd);

    *cf = save;

    return rv;
}


char *
njt_stream_lua_ssl_client_hello_by_lua(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
#ifndef SSL_ERROR_WANT_CLIENT_HELLO_CB

    njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                  "at least OpenSSL 1.1.1 required but found "
                  OPENSSL_VERSION_TEXT);

    return NJT_CONF_ERROR;

#else

    u_char                           *p;
    u_char                           *name;
    njt_str_t                        *value;
    njt_stream_lua_srv_conf_t        *lscf = conf;

    /*  must specify a concrete handler */
    if (cmd->post == NULL) {
        return NJT_CONF_ERROR;
    }

    if (lscf->srv.ssl_client_hello_handler) {
        return "is duplicate";
    }

    if (njt_stream_lua_ssl_init(cf->log) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    value = cf->args->elts;

    lscf->srv.ssl_client_hello_handler =
        (njt_stream_lua_srv_conf_handler_pt) cmd->post;

    if (cmd->post == njt_stream_lua_ssl_client_hello_handler_file) {
        /* Lua code in an external file */

        name = njt_stream_lua_rebase_path(cf->pool, value[1].data,
                                          value[1].len);
        if (name == NULL) {
            return NJT_CONF_ERROR;
        }

        lscf->srv.ssl_client_hello_src.data = name;
        lscf->srv.ssl_client_hello_src.len = njt_strlen(name);

        p = njt_palloc(cf->pool, NJT_STREAM_LUA_FILE_KEY_LEN + 1);
        if (p == NULL) {
            return NJT_CONF_ERROR;
        }

        lscf->srv.ssl_client_hello_src_key = p;

        p = njt_copy(p, NJT_STREAM_LUA_FILE_TAG, NJT_STREAM_LUA_FILE_TAG_LEN);
        p = njt_stream_lua_digest_hex(p, value[1].data, value[1].len);
        *p = '\0';

    } else {
        /* inlined Lua code */

        lscf->srv.ssl_client_hello_src = value[1];

        p = njt_palloc(cf->pool,
                       sizeof("ssl_client_hello_by_lua") +
                       NJT_STREAM_LUA_INLINE_KEY_LEN);
        if (p == NULL) {
            return NJT_CONF_ERROR;
        }

        lscf->srv.ssl_client_hello_src_key = p;

        p = njt_copy(p, "ssl_client_hello_by_lua",
                     sizeof("ssl_client_hello_by_lua") - 1);
        p = njt_copy(p, NJT_STREAM_LUA_INLINE_TAG,
                     NJT_STREAM_LUA_INLINE_TAG_LEN);
        p = njt_stream_lua_digest_hex(p, value[1].data, value[1].len);
        *p = '\0';
    }

    return NJT_CONF_OK;

#endif  /* NO SSL_ERROR_WANT_CLIENT_HELLO_CB */
}


int
njt_stream_lua_ssl_client_hello_handler(njt_ssl_conn_t *ssl_conn,
    int *al, void *arg)
{
    lua_State                          *L;
    njt_int_t                           rc;
    njt_connection_t                   *c, *fc;
    njt_stream_lua_request_t           *r = NULL;
    njt_pool_cleanup_t                 *cln;
    njt_stream_lua_srv_conf_t          *lscf;
    njt_stream_lua_ssl_ctx_t           *cctx;
    njt_stream_core_srv_conf_t         *cscf;
    njt_stream_session_t               *s, *fs;

    c = njt_ssl_get_connection(ssl_conn);

    njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                   "stream ssl client hello: connection reusable: %ud",
                   c->reusable);

    cctx = njt_stream_lua_ssl_get_ctx(c->ssl->connection);

    dd("ssl client hello handler, client-hello-ctx=%p", cctx);

    if (cctx && cctx->entered_client_hello_handler) {
        /* not the first time */

        if (cctx->done) {
            njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                           "stream lua_client_hello_by_lua:"
                           " client hello cb exit code: %d",
                           cctx->exit_code);

            dd("lua ssl client hello done, finally");
            return cctx->exit_code;
        }

        return -1;
    }

    dd("first time");

    njt_reusable_connection(c, 0);

    s = c->data;

    fc = njt_stream_lua_create_fake_connection(NULL);
    if (fc == NULL) {
        goto failed;
    }

    fc->log->handler = njt_stream_lua_log_ssl_client_hello_error;
    fc->log->data = fc;

    fc->addr_text = c->addr_text;
    fc->listening = c->listening;

    fs = njt_stream_lua_create_fake_session(fc);
    if (fs == NULL) {
        goto failed;
    }

    fs->main_conf = s->main_conf;
    fs->srv_conf = s->srv_conf;

    r = njt_stream_lua_create_fake_request(fs);
    if (r == NULL) {
        goto failed;
    }

    fc->log->file = c->log->file;
    fc->log->log_level = c->log->log_level;
    fc->ssl = c->ssl;

    cscf = njt_stream_get_module_srv_conf(fs, njt_stream_core_module);

#if defined(njet_version) && njet_version >= 1009000
    njt_set_connection_log(fc, cscf->error_log);

#else
#error "stream ssl_client_hello_by_lua only supports njet >= 1.19.3"
#endif

    if (cctx == NULL) {
        cctx = njt_pcalloc(c->pool, sizeof(njt_stream_lua_ssl_ctx_t));
        if (cctx == NULL) {
            goto failed;  /* error */
        }

        cctx->ctx_ref = LUA_NOREF;
    }

    cctx->exit_code = 1;  /* successful by default */
    cctx->connection = c;
    cctx->request = r;
    cctx->entered_client_hello_handler = 1;
    cctx->done = 0;

    dd("setting cctx");

    if (SSL_set_ex_data(c->ssl->connection, njt_stream_lua_ssl_ctx_index,
                        cctx) == 0)
    {
        njt_ssl_error(NJT_LOG_ALERT, c->log, 0, "SSL_set_ex_data() failed");
        goto failed;
    }

    lscf = njt_stream_lua_get_module_srv_conf(r, njt_stream_lua_module);

    /* TODO honor lua_code_cache off */
    L = njt_stream_lua_get_lua_vm(r, NULL);

    c->log->action = "loading SSL client hello by lua";

    if (lscf->srv.ssl_client_hello_handler == NULL) {

        njt_log_error(NJT_LOG_ALERT, c->log, 0,
                      "no ssl_client_hello_by_lua* defined in "
                      "server %s:%ui", &cscf->file_name, &cscf->line);

        goto failed;
    }

    rc = lscf->srv.ssl_client_hello_handler(r, lscf, L);

    if (rc >= NJT_OK || rc == NJT_ERROR) {
        cctx->done = 1;

        if (cctx->cleanup) {
            *cctx->cleanup = NULL;
        }

        njt_log_debug2(NJT_LOG_DEBUG_STREAM, c->log, 0,
                       "stream lua_client_hello_by_lua:"
                       " handler return value: %i, "
                       "client hello cb exit code: %d", rc, cctx->exit_code);

        c->log->action = "SSL handshaking";
        return cctx->exit_code;
    }

    /* rc == NJT_DONE */

    cln = njt_pool_cleanup_add(fc->pool, 0);
    if (cln == NULL) {
        goto failed;
    }

    cln->handler = njt_stream_lua_ssl_client_hello_done;
    cln->data = cctx;

    if (cctx->cleanup == NULL) {
        cln = njt_pool_cleanup_add(c->pool, 0);
        if (cln == NULL) {
            goto failed;
        }

        cln->data = cctx;
        cctx->cleanup = &cln->handler;
    }

    *cctx->cleanup = njt_stream_lua_ssl_client_hello_aborted;

    return -1;

#if 1
failed:

    if (r && r->pool) {
        njt_stream_lua_free_fake_request(r);
    }

    if (fc) {
        njt_stream_lua_close_fake_connection(fc);
    }

    return 0;
#endif
}


static void
njt_stream_lua_ssl_client_hello_done(void *data)
{
    njt_connection_t                *c;
    njt_stream_lua_ssl_ctx_t        *cctx = data;

    dd("lua ssl client hello done");

    if (cctx->aborted) {
        return;
    }

    njt_stream_lua_assert(cctx->done == 0);

    cctx->done = 1;

    if (cctx->cleanup) {
        *cctx->cleanup = NULL;
    }

    c = cctx->connection;

    c->log->action = "SSL handshaking";

    njt_post_event(c->write, &njt_posted_events);
}


static void
njt_stream_lua_ssl_client_hello_aborted(void *data)
{
    njt_stream_lua_ssl_ctx_t            *cctx = data;

    dd("lua ssl client hello done");

    if (cctx->done) {
        /* completed successfully already */
        return;
    }

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, cctx->connection->log, 0,
                   "stream lua_client_hello_by_lua: client hello cb aborted");

    cctx->aborted = 1;
    cctx->request->connection->ssl = NULL;

    njt_stream_lua_finalize_fake_request(cctx->request, NJT_ERROR);
}


static u_char *
njt_stream_lua_log_ssl_client_hello_error(njt_log_t *log, u_char *buf,
    size_t len)
{
    u_char              *p;
    njt_connection_t    *c;

    if (log->action) {
        p = njt_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    p = njt_snprintf(buf, len, ", context: ssl_client_hello_by_lua*");
    len -= p - buf;
    buf = p;

    c = log->data;

    if (c && c->addr_text.len) {
        p = njt_snprintf(buf, len, ", client: %V", &c->addr_text);
        len -= p - buf;
        buf = p;
    }

    if (c && c->listening && c->listening->addr_text.len) {
        p = njt_snprintf(buf, len, ", server: %V", &c->listening->addr_text);
        /* len -= p - buf; */
        buf = p;
    }

    return buf;
}


static njt_int_t
njt_stream_lua_ssl_client_hello_by_chunk(lua_State *L,
    njt_stream_lua_request_t *r)
{
    int                              co_ref;
    njt_int_t                        rc;
    lua_State                       *co;
    njt_stream_lua_ctx_t            *ctx;
    njt_stream_lua_cleanup_t        *cln;

    ctx = njt_stream_lua_get_module_ctx(r, njt_stream_lua_module);

    if (ctx == NULL) {
        ctx = njt_stream_lua_create_ctx(r->session);
        if (ctx == NULL) {
            rc = NJT_ERROR;
            njt_stream_lua_finalize_request(r, rc);
            return rc;
        }

    } else {
        dd("reset ctx");
        njt_stream_lua_reset_ctx(r, L, ctx);
    }

    ctx->entered_content_phase = 1;

    /*  {{{ new coroutine to handle request */
    co = njt_stream_lua_new_thread(r, L, &co_ref);

    if (co == NULL) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "stream failed to create new"
                      " coroutine to handle request");

        rc = NJT_ERROR;
        njt_stream_lua_finalize_request(r, rc);
        return rc;
    }

    /*  move code closure to new coroutine */
    lua_xmove(L, co, 1);

#ifndef OPENRESTY_LUAJIT
    /*  set closure's env table to new coroutine's globals table */
    njt_stream_lua_get_globals_table(co);
    lua_setfenv(co, -2);
#endif

    /* save njet request in coroutine globals table */
    njt_stream_lua_set_req(co, r);

    ctx->cur_co_ctx = &ctx->entry_co_ctx;
    ctx->cur_co_ctx->co = co;
    ctx->cur_co_ctx->co_ref = co_ref;
#ifdef NJT_LUA_USE_ASSERT
    ctx->cur_co_ctx->co_top = 1;
#endif

    njt_stream_lua_attach_co_ctx_to_L(co, ctx->cur_co_ctx);

    /* register request cleanup hooks */
    if (ctx->cleanup == NULL) {
        cln = njt_stream_lua_cleanup_add(r, 0);
        if (cln == NULL) {
            rc = NJT_ERROR;
            njt_stream_lua_finalize_request(r, rc);
            return rc;
        }

        cln->handler = njt_stream_lua_request_cleanup_handler;
        cln->data = ctx;
        ctx->cleanup = &cln->handler;
    }

    ctx->context = NJT_STREAM_LUA_CONTEXT_SSL_CLIENT_HELLO;

    rc = njt_stream_lua_run_thread(L, r, ctx, 0);

    if (rc == NJT_ERROR || rc >= NJT_OK) {
        /* do nothing */

    } else if (rc == NJT_AGAIN) {
        rc = njt_stream_lua_content_run_posted_threads(L, r, ctx, 0);

    } else if (rc == NJT_DONE) {
        rc = njt_stream_lua_content_run_posted_threads(L, r, ctx, 1);

    } else {
        rc = NJT_OK;
    }

    njt_stream_lua_finalize_request(r, rc);
    return rc;
}


int njt_stream_lua_ffi_ssl_get_client_hello_server_name(
    njt_stream_lua_request_t *r, const char **name,
    size_t *namelen, char **err)
{
    njt_ssl_conn_t          *ssl_conn;
#ifdef SSL_ERROR_WANT_CLIENT_HELLO_CB
    const unsigned char     *p;
    size_t                   remaining, len;
#endif

    if (r->connection == NULL || r->connection->ssl == NULL) {
        *err = "bad request";
        return NJT_ERROR;
    }

    ssl_conn = r->connection->ssl->connection;
    if (ssl_conn == NULL) {
        *err = "bad ssl conn";
        return NJT_ERROR;
    }

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

#ifdef SSL_ERROR_WANT_CLIENT_HELLO_CB
    remaining = 0;

    /* This code block is taken from OpenSSL's client_hello_select_server_ctx()
     * */
    if (!SSL_client_hello_get0_ext(ssl_conn, TLSEXT_TYPE_server_name, &p,
                                   &remaining))
    {
        return NJT_DECLINED;
    }

    if (remaining <= 2) {
        *err = "Bad SSL Client Hello Extension";
        return NJT_ERROR;
    }

    len = (*(p++) << 8);
    len += *(p++);
    if (len + 2 != remaining) {
        *err = "Bad SSL Client Hello Extension";
        return NJT_ERROR;
    }

    remaining = len;
    if (remaining == 0 || *p++ != TLSEXT_NAMETYPE_host_name) {
        *err = "Bad SSL Client Hello Extension";
        return NJT_ERROR;
    }

    remaining--;
    if (remaining <= 2) {
        *err = "Bad SSL Client Hello Extension";
        return NJT_ERROR;
    }

    len = (*(p++) << 8);
    len += *(p++);
    if (len + 2 > remaining) {
        *err = "Bad SSL Client Hello Extension";
        return NJT_ERROR;
    }

    remaining = len;
    *name = (const char *) p;
    *namelen = len;

    return NJT_OK;

#else
    *err = "OpenSSL too old to support this function";
    return NJT_ERROR;
#endif

#else
    *err = "no TLS extension support";
    return NJT_ERROR;
#endif
}


int
njt_stream_lua_ffi_ssl_get_client_hello_ext(njt_stream_lua_request_t *r,
    unsigned int type, const unsigned char **out, size_t *outlen, char **err)
{
    njt_ssl_conn_t          *ssl_conn;

    if (r->connection == NULL || r->connection->ssl == NULL) {
        *err = "bad request";
        return NJT_ERROR;
    }

    ssl_conn = r->connection->ssl->connection;
    if (ssl_conn == NULL) {
        *err = "bad ssl conn";
        return NJT_ERROR;
    }

#ifdef SSL_ERROR_WANT_CLIENT_HELLO_CB
    if (SSL_client_hello_get0_ext(ssl_conn, type, out, outlen) == 0) {
        return NJT_DECLINED;
    }

    return NJT_OK;

#else
    *err = "OpenSSL too old to support this function";
    return NJT_ERROR;
#endif
}


int
njt_stream_lua_ffi_ssl_set_protocols(njt_stream_lua_request_t *r,
    int protocols, char **err)
{

    njt_ssl_conn_t    *ssl_conn;

    if (r->connection == NULL || r->connection->ssl == NULL) {
        *err = "bad request";
        return NJT_ERROR;
    }

    ssl_conn = r->connection->ssl->connection;
    if (ssl_conn == NULL) {
        *err = "bad ssl conn";
        return NJT_ERROR;
    }

#if OPENSSL_VERSION_NUMBER >= 0x009080dfL
    /* only in 0.9.8m+ */
    SSL_clear_options(ssl_conn,
                      SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1);
#endif

    if (!(protocols & NJT_SSL_SSLv2)) {
        SSL_set_options(ssl_conn, SSL_OP_NO_SSLv2);
    }

    if (!(protocols & NJT_SSL_SSLv3)) {
        SSL_set_options(ssl_conn, SSL_OP_NO_SSLv3);
    }

    if (!(protocols & NJT_SSL_TLSv1)) {
        SSL_set_options(ssl_conn, SSL_OP_NO_TLSv1);
    }

#ifdef SSL_OP_NO_TLSv1_1
    SSL_clear_options(ssl_conn, SSL_OP_NO_TLSv1_1);
    if (!(protocols & NJT_SSL_TLSv1_1)) {
        SSL_set_options(ssl_conn, SSL_OP_NO_TLSv1_1);
    }
#endif

#ifdef SSL_OP_NO_TLSv1_2
    SSL_clear_options(ssl_conn, SSL_OP_NO_TLSv1_2);
    if (!(protocols & NJT_SSL_TLSv1_2)) {
        SSL_set_options(ssl_conn, SSL_OP_NO_TLSv1_2);
    }
#endif

#ifdef SSL_OP_NO_TLSv1_3
    SSL_clear_options(ssl_conn, SSL_OP_NO_TLSv1_3);
    if (!(protocols & NJT_SSL_TLSv1_3)) {
        SSL_set_options(ssl_conn, SSL_OP_NO_TLSv1_3);
    }
#endif

    return NJT_OK;
}

#endif /* NJT_STREAM_SSL */
