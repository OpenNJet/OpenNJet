
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_ssl_certby.c.tt2
 */


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
#include "njt_stream_lua_directive.h"
#include "njt_stream_lua_ssl.h"


enum {
    NJT_STREAM_LUA_ADDR_TYPE_UNIX  = 0,
    NJT_STREAM_LUA_ADDR_TYPE_INET  = 1,
    NJT_STREAM_LUA_ADDR_TYPE_INET6 = 2
};


static void njt_stream_lua_ssl_cert_done(void *data);
static void njt_stream_lua_ssl_cert_aborted(void *data);
static u_char *njt_stream_lua_log_ssl_cert_error(njt_log_t *log, u_char *buf,
    size_t len);
static njt_int_t njt_stream_lua_ssl_cert_by_chunk(lua_State *L,
    njt_stream_lua_request_t *r);


njt_int_t
njt_stream_lua_ssl_cert_handler_file(njt_stream_lua_request_t *r,
    njt_stream_lua_srv_conf_t *lscf, lua_State *L)
{
    njt_int_t           rc;

    rc = njt_stream_lua_cache_loadfile(r->connection->log, L,
                                       lscf->srv.ssl_cert_src.data,
                                       lscf->srv.ssl_cert_src_key);
    if (rc != NJT_OK) {
        return rc;
    }

    /*  make sure we have a valid code chunk */
    njt_stream_lua_assert(lua_isfunction(L, -1));

    return njt_stream_lua_ssl_cert_by_chunk(L, r);
}


njt_int_t
njt_stream_lua_ssl_cert_handler_inline(njt_stream_lua_request_t *r,
    njt_stream_lua_srv_conf_t *lscf, lua_State *L)
{
    njt_int_t           rc;

    rc = njt_stream_lua_cache_loadbuffer(r->connection->log, L,
                                         lscf->srv.ssl_cert_src.data,
                                         lscf->srv.ssl_cert_src.len,
                                         lscf->srv.ssl_cert_src_key,
                                         "=ssl_certificate_by_lua");
    if (rc != NJT_OK) {
        return rc;
    }

    /*  make sure we have a valid code chunk */
    njt_stream_lua_assert(lua_isfunction(L, -1));

    return njt_stream_lua_ssl_cert_by_chunk(L, r);
}


char *
njt_stream_lua_ssl_cert_by_lua_block(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    char        *rv;
    njt_conf_t   save;

    save = *cf;
    cf->handler = njt_stream_lua_ssl_cert_by_lua;
    cf->handler_conf = conf;

    rv = njt_stream_lua_conf_lua_block_parse(cf, cmd);

    *cf = save;

    return rv;
}


char *
njt_stream_lua_ssl_cert_by_lua(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
#if OPENSSL_VERSION_NUMBER < 0x1000205fL

    njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                  "at least OpenSSL 1.0.2e required but found "
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

    if (lscf->srv.ssl_cert_handler) {
        return "is duplicate";
    }

    if (njt_stream_lua_ssl_init(cf->log) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    value = cf->args->elts;

    lscf->srv.ssl_cert_handler = (njt_stream_lua_srv_conf_handler_pt) cmd->post;

    if (cmd->post == njt_stream_lua_ssl_cert_handler_file) {
        /* Lua code in an external file */

        name = njt_stream_lua_rebase_path(cf->pool, value[1].data,
                                          value[1].len);
        if (name == NULL) {
            return NJT_CONF_ERROR;
        }

        lscf->srv.ssl_cert_src.data = name;
        lscf->srv.ssl_cert_src.len = njt_strlen(name);

        p = njt_palloc(cf->pool, NJT_STREAM_LUA_FILE_KEY_LEN + 1);
        if (p == NULL) {
            return NJT_CONF_ERROR;
        }

        lscf->srv.ssl_cert_src_key = p;

        p = njt_copy(p, NJT_STREAM_LUA_FILE_TAG, NJT_STREAM_LUA_FILE_TAG_LEN);
        p = njt_stream_lua_digest_hex(p, value[1].data, value[1].len);
        *p = '\0';

    } else {
        /* inlined Lua code */

        lscf->srv.ssl_cert_src = value[1];

        p = njt_palloc(cf->pool,
                       sizeof("ssl_certificate_by_lua") +
                       NJT_STREAM_LUA_INLINE_KEY_LEN);
        if (p == NULL) {
            return NJT_CONF_ERROR;
        }

        lscf->srv.ssl_cert_src_key = p;

        p = njt_copy(p, "ssl_certificate_by_lua",
                     sizeof("ssl_certificate_by_lua") - 1);
        p = njt_copy(p, NJT_STREAM_LUA_INLINE_TAG, NJT_STREAM_LUA_INLINE_TAG_LEN);
        p = njt_stream_lua_digest_hex(p, value[1].data, value[1].len);
        *p = '\0';
    }

    return NJT_CONF_OK;

#endif  /* OPENSSL_VERSION_NUMBER < 0x1000205fL */
}


int
njt_stream_lua_ssl_cert_handler(njt_ssl_conn_t *ssl_conn, void *data)
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
                   "stream ssl cert: connection reusable: %ud", c->reusable);

    cctx = njt_stream_lua_ssl_get_ctx(c->ssl->connection);

    dd("ssl cert handler, cert-ctx=%p", cctx);

    if (cctx && cctx->entered_cert_handler) {
        /* not the first time */

        if (cctx->done) {
            njt_log_debug1(NJT_LOG_DEBUG_STREAM, c->log, 0,
                           "stream lua_certificate_by_lua:"
                           " cert cb exit code: %d",
                           cctx->exit_code);

            dd("lua ssl cert done, finally");
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

    fc->log->handler = njt_stream_lua_log_ssl_cert_error;
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
#   error "stream ssl_cert_by_lua only supports njet >= 1.13.0"
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
    cctx->entered_cert_handler = 1;
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

    c->log->action = "loading SSL certificate by lua";

    if (lscf->srv.ssl_cert_handler == NULL) {

        njt_log_error(NJT_LOG_ALERT, c->log, 0,
                      "no ssl_certificate_by_lua* defined in "
                      "server %s:%ui", &cscf->file_name, &cscf->line);

        goto failed;
    }

    rc = lscf->srv.ssl_cert_handler(r, lscf, L);

    if (rc >= NJT_OK || rc == NJT_ERROR) {
        cctx->done = 1;

        if (cctx->cleanup) {
            *cctx->cleanup = NULL;
        }

        njt_log_debug2(NJT_LOG_DEBUG_STREAM, c->log, 0,
                       "stream lua_certificate_by_lua:"
                       " handler return value: %i, "
                       "cert cb exit code: %d", rc, cctx->exit_code);

        c->log->action = "SSL handshaking";
        return cctx->exit_code;
    }

    /* rc == NJT_DONE */

    cln = njt_pool_cleanup_add(fc->pool, 0);
    if (cln == NULL) {
        goto failed;
    }

    cln->handler = njt_stream_lua_ssl_cert_done;
    cln->data = cctx;

    if (cctx->cleanup == NULL) {
        cln = njt_pool_cleanup_add(c->pool, 0);
        if (cln == NULL) {
            goto failed;
        }

        cln->data = cctx;
        cctx->cleanup = &cln->handler;
    }

    *cctx->cleanup = njt_stream_lua_ssl_cert_aborted;

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
njt_stream_lua_ssl_cert_done(void *data)
{
    njt_connection_t                *c;
    njt_stream_lua_ssl_ctx_t        *cctx = data;

    dd("lua ssl cert done");

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
njt_stream_lua_ssl_cert_aborted(void *data)
{
    njt_stream_lua_ssl_ctx_t            *cctx = data;

    dd("lua ssl cert done");

    if (cctx->done) {
        /* completed successfully already */
        return;
    }

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, cctx->connection->log, 0,
                   "stream lua_certificate_by_lua: cert cb aborted");

    cctx->aborted = 1;
    cctx->request->connection->ssl = NULL;

    njt_stream_lua_finalize_fake_request(cctx->request, NJT_ERROR);
}


static u_char *
njt_stream_lua_log_ssl_cert_error(njt_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;
    njt_connection_t    *c;

    if (log->action) {
        p = njt_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    p = njt_snprintf(buf, len, ", context: ssl_certificate_by_lua*");
    len -= p - buf;
    buf = p;

    c = log->data;

    if (c != NULL) {
        if (c->addr_text.len) {
            p = njt_snprintf(buf, len, ", client: %V", &c->addr_text);
            len -= p - buf;
            buf = p;
        }

        if (c->listening && c->listening->addr_text.len) {
            p = njt_snprintf(buf, len, ", server: %V",
                             &c->listening->addr_text);
            /* len -= p - buf; */
            buf = p;
        }
    }

    return buf;
}


static njt_int_t
njt_stream_lua_ssl_cert_by_chunk(lua_State *L, njt_stream_lua_request_t *r)
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

    ctx->context = NJT_STREAM_LUA_CONTEXT_SSL_CERT;

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


int
njt_stream_lua_ffi_ssl_get_tls1_version(njt_stream_lua_request_t *r, char **err)
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

    dd("tls1 ver: %d", SSL_version(ssl_conn));

    return SSL_version(ssl_conn);
}


int
njt_stream_lua_ffi_ssl_clear_certs(njt_stream_lua_request_t *r, char **err)
{
#ifdef LIBRESSL_VERSION_NUMBER

    *err = "LibreSSL not supported";
    return NJT_ERROR;

#else

#   if OPENSSL_VERSION_NUMBER < 0x1000205fL

    *err = "at least OpenSSL 1.0.2e required but found " OPENSSL_VERSION_TEXT;
    return NJT_ERROR;

#   else

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

    SSL_certs_clear(ssl_conn);
    return NJT_OK;

#   endif  /* OPENSSL_VERSION_NUMBER < 0x1000205fL */
#endif
}


int
njt_stream_lua_ffi_ssl_set_der_certificate(njt_stream_lua_request_t *r,
    const char *data, size_t len, char **err)
{
#ifdef LIBRESSL_VERSION_NUMBER

    *err = "LibreSSL not supported";
    return NJT_ERROR;

#else

#   if OPENSSL_VERSION_NUMBER < 0x1000205fL

    *err = "at least OpenSSL 1.0.2e required but found " OPENSSL_VERSION_TEXT;
    return NJT_ERROR;

#   else

    BIO               *bio = NULL;
    X509              *x509 = NULL;
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

    bio = BIO_new_mem_buf((char *) data, len);
    if (bio == NULL) {
        *err = "BIO_new_mem_buf() failed";
        goto failed;
    }

    x509 = d2i_X509_bio(bio, NULL);
    if (x509 == NULL) {
        *err = "d2i_X509_bio() failed";
        goto failed;
    }

    if (SSL_use_certificate(ssl_conn, x509) == 0) {
        *err = "SSL_use_certificate() failed";
        goto failed;
    }

#if 0
    if (SSL_set_ex_data(ssl_conn, njt_ssl_certificate_index, x509) == 0) {
        *err = "SSL_set_ex_data() failed";
        goto failed;
    }
#endif

    X509_free(x509);
    x509 = NULL;

    /* read rest of the chain */

    while (!BIO_eof(bio)) {

        x509 = d2i_X509_bio(bio, NULL);
        if (x509 == NULL) {
            *err = "d2i_X509_bio() failed";
            goto failed;
        }

        if (SSL_add0_chain_cert(ssl_conn, x509) == 0) {
            *err = "SSL_add0_chain_cert() failed";
            goto failed;
        }
    }

    BIO_free(bio);

    *err = NULL;
    return NJT_OK;

failed:

    if (bio) {
        BIO_free(bio);
    }

    if (x509) {
        X509_free(x509);
    }

    ERR_clear_error();

    return NJT_ERROR;

#   endif  /* OPENSSL_VERSION_NUMBER < 0x1000205fL */
#endif
}


int
njt_stream_lua_ffi_ssl_set_der_private_key(njt_stream_lua_request_t *r,
    const char *data, size_t len, char **err)
{
    BIO               *bio = NULL;
    EVP_PKEY          *pkey = NULL;
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

    bio = BIO_new_mem_buf((char *) data, len);
    if (bio == NULL) {
        *err = "BIO_new_mem_buf() failed";
        goto failed;
    }

    pkey = d2i_PrivateKey_bio(bio, NULL);
    if (pkey == NULL) {
        *err = "d2i_PrivateKey_bio() failed";
        goto failed;
    }

    if (SSL_use_PrivateKey(ssl_conn, pkey) == 0) {
        *err = "SSL_use_PrivateKey() failed";
        goto failed;
    }

    EVP_PKEY_free(pkey);
    BIO_free(bio);

    return NJT_OK;

failed:

    if (pkey) {
        EVP_PKEY_free(pkey);
    }

    if (bio) {
        BIO_free(bio);
    }

    ERR_clear_error();

    return NJT_ERROR;
}


int
njt_stream_lua_ffi_ssl_raw_server_addr(njt_stream_lua_request_t *r, char **addr,
    size_t *addrlen, int *addrtype, char **err)
{
#if (NJT_HAVE_UNIX_DOMAIN)
    struct sockaddr_un   *saun;
#endif
    njt_ssl_conn_t       *ssl_conn;
    njt_connection_t     *c;
    struct sockaddr_in   *sin;
#if (NJT_HAVE_INET6)
    struct sockaddr_in6  *sin6;
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

    c = njt_ssl_get_connection(ssl_conn);

    if (njt_connection_local_sockaddr(c, NULL, 0) != NJT_OK) {
        return 0;
    }

    switch (c->local_sockaddr->sa_family) {

#if (NJT_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) c->local_sockaddr;
        *addrlen = 16;
        *addr = (char *) &sin6->sin6_addr.s6_addr;
        *addrtype = NJT_STREAM_LUA_ADDR_TYPE_INET6;

        break;
#endif

#if (NJT_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
        saun = (struct sockaddr_un *) c->local_sockaddr;

        /* on Linux sockaddr might not include sun_path at all */
        if (c->local_socklen <= (socklen_t)
            offsetof(struct sockaddr_un, sun_path))
        {
            *addr = "";
            *addrlen = 0;

        } else {
            *addr = saun->sun_path;
            *addrlen = njt_strlen(saun->sun_path);
        }

        *addrtype = NJT_STREAM_LUA_ADDR_TYPE_UNIX;
        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) c->local_sockaddr;
        *addr = (char *) &sin->sin_addr.s_addr;
        *addrlen = 4;
        *addrtype = NJT_STREAM_LUA_ADDR_TYPE_INET;
        break;
    }

    return NJT_OK;
}


int
njt_stream_lua_ffi_ssl_server_name(njt_stream_lua_request_t *r, char **name,
    size_t *namelen, char **err)
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

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

    *name = (char *) SSL_get_servername(ssl_conn, TLSEXT_NAMETYPE_host_name);

    if (*name) {
        *namelen = njt_strlen(*name);
        return NJT_OK;
    }

    return NJT_DECLINED;

#else

    *err = "no TLS extension support";
    return NJT_ERROR;

#endif
}


int
njt_stream_lua_ffi_ssl_server_port(njt_stream_lua_request_t *r,
    unsigned short *server_port, char **err)
{
    njt_ssl_conn_t          *ssl_conn;
    njt_connection_t        *c;

    if (r->connection == NULL || r->connection->ssl == NULL) {
        *err = "bad request";
        return NJT_ERROR;
    }

    ssl_conn = r->connection->ssl->connection;
    if (ssl_conn == NULL) {
        *err = "bad ssl conn";
        return NJT_ERROR;
    }

    c = njt_ssl_get_connection(ssl_conn);

    switch (c->local_sockaddr->sa_family) {

    case AF_UNIX:
        *err = "unix domain has no port";
        return NJT_ERROR;

    default:
        *server_port = (unsigned short) njt_inet_get_port(c->local_sockaddr);
        return NJT_OK;
    }
}


int
njt_stream_lua_ffi_ssl_raw_client_addr(njt_stream_lua_request_t *r, char **addr,
    size_t *addrlen, int *addrtype, char **err)
{
#if (NJT_HAVE_UNIX_DOMAIN)
    struct sockaddr_un  *saun;
#endif
    njt_ssl_conn_t      *ssl_conn;
    njt_connection_t    *c;
    struct sockaddr_in  *sin;
#if (NJT_HAVE_INET6)
    struct sockaddr_in6 *sin6;
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

    c = njt_ssl_get_connection(ssl_conn);

    switch (c->sockaddr->sa_family) {

#if (NJT_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) c->sockaddr;
        *addrlen = 16;
        *addr = (char *) &sin6->sin6_addr.s6_addr;
        *addrtype = NJT_STREAM_LUA_ADDR_TYPE_INET6;

        break;
#endif

# if (NJT_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
        saun = (struct sockaddr_un *)c->sockaddr;
        /* on Linux sockaddr might not include sun_path at all */
        if (c->socklen <= (socklen_t) offsetof(struct sockaddr_un, sun_path)) {
            *addr = "";
            *addrlen = 0;

        } else {
            *addr = saun->sun_path;
            *addrlen = njt_strlen(saun->sun_path);
        }

        *addrtype = NJT_STREAM_LUA_ADDR_TYPE_UNIX;
        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) c->sockaddr;
        *addr = (char *) &sin->sin_addr.s_addr;
        *addrlen = 4;
        *addrtype = NJT_STREAM_LUA_ADDR_TYPE_INET;
        break;
    }

    return NJT_OK;
}


int
njt_stream_lua_ffi_cert_pem_to_der(const u_char *pem, size_t pem_len, u_char *der,
    char **err)
{
    int       total, len;
    BIO      *bio;
    X509     *x509;
    u_long    n;

    bio = BIO_new_mem_buf((char *) pem, (int) pem_len);
    if (bio == NULL) {
        *err = "BIO_new_mem_buf() failed";
        ERR_clear_error();
        return NJT_ERROR;
    }

    x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
    if (x509 == NULL) {
        *err = "PEM_read_bio_X509_AUX() failed";
        BIO_free(bio);
        ERR_clear_error();
        return NJT_ERROR;
    }

    total = i2d_X509(x509, &der);
    if (total < 0) {
        *err = "i2d_X509() failed";
        X509_free(x509);
        BIO_free(bio);
        ERR_clear_error();
        return NJT_ERROR;
    }

    X509_free(x509);

    /* read rest of the chain */

    for ( ;; ) {

        x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (x509 == NULL) {
            n = ERR_peek_last_error();

            if (ERR_GET_LIB(n) == ERR_LIB_PEM
                && ERR_GET_REASON(n) == PEM_R_NO_START_LINE)
            {
                /* end of file */
                ERR_clear_error();
                break;
            }

            /* some real error */

            *err = "PEM_read_bio_X509() failed";
            BIO_free(bio);
            ERR_clear_error();
            return NJT_ERROR;
        }

        len = i2d_X509(x509, &der);
        if (len < 0) {
            *err = "i2d_X509() failed";
            X509_free(x509);
            BIO_free(bio);
            ERR_clear_error();
            return NJT_ERROR;
        }

        total += len;

        X509_free(x509);
    }

    BIO_free(bio);

    return total;
}


int
njt_stream_lua_ffi_priv_key_pem_to_der(const u_char *pem, size_t pem_len,
    const u_char *passphrase, u_char *der, char **err)
{
    int          len;
    BIO         *in;
    EVP_PKEY    *pkey;

    in = BIO_new_mem_buf((char *) pem, (int) pem_len);
    if (in == NULL) {
        *err = "BIO_new_mem_buf() failed";
        ERR_clear_error();
        return NJT_ERROR;
    }

    pkey = PEM_read_bio_PrivateKey(in, NULL, NULL, (void *)passphrase);
    if (pkey == NULL) {
        BIO_free(in);
        *err = "PEM_read_bio_PrivateKey() failed";
        ERR_clear_error();
        return NJT_ERROR;
    }

    BIO_free(in);

    len = i2d_PrivateKey(pkey, &der);
    if (len < 0) {
        EVP_PKEY_free(pkey);
        *err = "i2d_PrivateKey() failed";
        ERR_clear_error();
        return NJT_ERROR;
    }

    EVP_PKEY_free(pkey);

    return len;
}


void *
njt_stream_lua_ffi_parse_pem_cert(const u_char *pem, size_t pem_len,
    char **err)
{
    BIO             *bio;
    X509            *x509;
    u_long           n;
    STACK_OF(X509)  *chain;

    bio = BIO_new_mem_buf((char *) pem, (int) pem_len);
    if (bio == NULL) {
        *err = "BIO_new_mem_buf() failed";
        ERR_clear_error();
        return NULL;
    }

    x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
    if (x509 == NULL) {
        *err = "PEM_read_bio_X509_AUX() failed";
        BIO_free(bio);
        ERR_clear_error();
        return NULL;
    }

    chain = sk_X509_new_null();
    if (chain == NULL) {
        *err = "sk_X509_new_null() failed";
        X509_free(x509);
        BIO_free(bio);
        ERR_clear_error();
        return NULL;
    }

    if (sk_X509_push(chain, x509) == 0) {
        *err = "sk_X509_push() failed";
        sk_X509_free(chain);
        X509_free(x509);
        BIO_free(bio);
        ERR_clear_error();
        return NULL;
    }

    /* read rest of the chain */

    for ( ;; ) {

        x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (x509 == NULL) {
            n = ERR_peek_last_error();

            if (ERR_GET_LIB(n) == ERR_LIB_PEM
                && ERR_GET_REASON(n) == PEM_R_NO_START_LINE)
            {
                /* end of file */
                ERR_clear_error();
                break;
            }

            /* some real error */

            *err = "PEM_read_bio_X509() failed";
            sk_X509_pop_free(chain, X509_free);
            BIO_free(bio);
            ERR_clear_error();
            return NULL;
        }

        if (sk_X509_push(chain, x509) == 0) {
            *err = "sk_X509_push() failed";
            sk_X509_pop_free(chain, X509_free);
            X509_free(x509);
            BIO_free(bio);
            ERR_clear_error();
            return NULL;
        }
    }

    BIO_free(bio);

    return chain;
}


void
njt_stream_lua_ffi_free_cert(void *cdata)
{
    STACK_OF(X509)  *chain = cdata;

    sk_X509_pop_free(chain, X509_free);
}


void *
njt_stream_lua_ffi_parse_pem_priv_key(const u_char *pem, size_t pem_len,
    char **err)
{
    BIO         *in;
    EVP_PKEY    *pkey;

    in = BIO_new_mem_buf((char *) pem, (int) pem_len);
    if (in == NULL) {
        *err = "BIO_new_mem_buf() failed";
        ERR_clear_error();
        return NULL;
    }

    pkey = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
    if (pkey == NULL) {
        *err = "PEM_read_bio_PrivateKey() failed";
        BIO_free(in);
        ERR_clear_error();
        return NULL;
    }

    BIO_free(in);

    return pkey;
}


void
njt_stream_lua_ffi_free_priv_key(void *cdata)
{
    EVP_PKEY *pkey = cdata;

    EVP_PKEY_free(pkey);
}


int
njt_stream_lua_ffi_set_cert(njt_stream_lua_request_t *r,
    void *cdata, char **err)
{
#ifdef LIBRESSL_VERSION_NUMBER

    *err = "LibreSSL not supported";
    return NJT_ERROR;

#else

#   if OPENSSL_VERSION_NUMBER < 0x1000205fL

    *err = "at least OpenSSL 1.0.2e required but found " OPENSSL_VERSION_TEXT;
    return NJT_ERROR;

#   else

#ifdef OPENSSL_IS_BORINGSSL
    size_t             i;
#else
    int                i;
#endif
    X509              *x509 = NULL;
    njt_ssl_conn_t    *ssl_conn;
    STACK_OF(X509)    *chain = cdata;

    if (r->connection == NULL || r->connection->ssl == NULL) {
        *err = "bad request";
        return NJT_ERROR;
    }

    ssl_conn = r->connection->ssl->connection;
    if (ssl_conn == NULL) {
        *err = "bad ssl conn";
        return NJT_ERROR;
    }

    if (sk_X509_num(chain) < 1) {
        *err = "invalid certificate chain";
        goto failed;
    }

    x509 = sk_X509_value(chain, 0);
    if (x509 == NULL) {
        *err = "sk_X509_value() failed";
        goto failed;
    }

    if (SSL_use_certificate(ssl_conn, x509) == 0) {
        *err = "SSL_use_certificate() failed";
        goto failed;
    }

    x509 = NULL;

    /* read rest of the chain */

    for (i = 1; i < sk_X509_num(chain); i++) {

        x509 = sk_X509_value(chain, i);
        if (x509 == NULL) {
            *err = "sk_X509_value() failed";
            goto failed;
        }

        if (SSL_add1_chain_cert(ssl_conn, x509) == 0) {
            *err = "SSL_add1_chain_cert() failed";
            goto failed;
        }
    }

    *err = NULL;
    return NJT_OK;

failed:

    ERR_clear_error();

    return NJT_ERROR;

#   endif  /* OPENSSL_VERSION_NUMBER < 0x1000205fL */
#endif
}


int
njt_stream_lua_ffi_set_priv_key(njt_stream_lua_request_t *r,
    void *cdata, char **err)
{
    EVP_PKEY          *pkey = NULL;
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

    pkey = cdata;
    if (pkey == NULL) {
        *err = "invalid private key failed";
        goto failed;
    }

    if (SSL_use_PrivateKey(ssl_conn, pkey) == 0) {
        *err = "SSL_use_PrivateKey() failed";
        goto failed;
    }

    return NJT_OK;

failed:

    ERR_clear_error();

    return NJT_ERROR;
}


#ifndef LIBRESSL_VERSION_NUMBER
static int
njt_stream_lua_ssl_verify_callback(int ok, X509_STORE_CTX *x509_store)
{
    /*
     * we never terminate handshake here and user can later use
     * $ssl_client_verify to check verification result.
     *
     * this is consistent with NJet behavior.
     */
    return 1;
}
#endif


int
njt_stream_lua_ffi_ssl_verify_client(njt_stream_lua_request_t *r,
    void *ca_certs, int depth, char **err)
{
#ifdef LIBRESSL_VERSION_NUMBER

    *err = "LibreSSL not supported";
    return NJT_ERROR;

#else

    njt_stream_lua_ctx_t        *ctx;
    njt_ssl_conn_t              *ssl_conn;
    njt_stream_ssl_conf_t       *sscf;
    STACK_OF(X509)              *chain = ca_certs;
    STACK_OF(X509_NAME)         *name_chain = NULL;
    X509                        *x509 = NULL;
    X509_NAME                   *subject = NULL;
    X509_STORE                  *ca_store = NULL;
#ifdef OPENSSL_IS_BORINGSSL
    size_t                      i;
#else
    int                         i;
#endif

    ctx = njt_stream_get_module_ctx(r->session, njt_stream_lua_module);
    if (ctx == NULL) {
        *err = "no request ctx found";
        return NJT_ERROR;
    }

    if (!(ctx->context & NJT_STREAM_LUA_CONTEXT_SSL_CERT)) {
        *err = "API disabled in the current context";
        return NJT_ERROR;
    }

    if (r->connection == NULL || r->connection->ssl == NULL) {
        *err = "bad request";
        return NJT_ERROR;
    }

    ssl_conn = r->connection->ssl->connection;
    if (ssl_conn == NULL) {
        *err = "bad ssl conn";
        return NJT_ERROR;
    }

    /* enable verify */

    SSL_set_verify(ssl_conn, SSL_VERIFY_PEER,
                   njt_stream_lua_ssl_verify_callback);

    /* set depth */

    if (depth < 0) {
        sscf = njt_stream_get_module_srv_conf(r->session,
                                              njt_stream_ssl_module);
        if (sscf != NULL) {
            depth = sscf->verify_depth;

        } else {
            /* same as the default value of ssl_verify_depth */
            depth = 1;
        }
    }

    SSL_set_verify_depth(ssl_conn, depth);

    /* set CA chain */

    if (chain != NULL) {
        ca_store = X509_STORE_new();
        if (ca_store == NULL) {
            *err = "X509_STORE_new() failed";
            return NJT_ERROR;
        }

        /* construct name chain */

        name_chain = sk_X509_NAME_new_null();
        if (name_chain == NULL) {
            *err = "sk_X509_NAME_new_null() failed";
            goto failed;
        }

        for (i = 0; i < sk_X509_num(chain); i++) {
            x509 = sk_X509_value(chain, i);
            if (x509 == NULL) {
                *err = "sk_X509_value() failed";
                goto failed;
            }

            /* add subject to name chain, which will be sent to client */
            subject = X509_NAME_dup(X509_get_subject_name(x509));
            if (subject == NULL) {
                *err = "X509_get_subject_name() failed";
                goto failed;
            }

            if (!sk_X509_NAME_push(name_chain, subject)) {
                *err = "sk_X509_NAME_push() failed";
                X509_NAME_free(subject);
                goto failed;
            }

            /* add to trusted CA store */
            if (X509_STORE_add_cert(ca_store, x509) == 0) {
                *err = "X509_STORE_add_cert() failed";
                goto failed;
            }
        }

        if (SSL_set0_verify_cert_store(ssl_conn, ca_store) == 0) {
            *err = "SSL_set0_verify_cert_store() failed";
            goto failed;
        }

        SSL_set_client_CA_list(ssl_conn, name_chain);
    }

    return NJT_OK;

failed:

    sk_X509_NAME_free(name_chain);

    X509_STORE_free(ca_store);

    return NJT_ERROR;
#endif
}


#endif /* NJT_STREAM_SSL */
