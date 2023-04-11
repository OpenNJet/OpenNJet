
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_event_connect.h>


#if (!defined OPENSSL_NO_OCSP && defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB)


typedef struct {
    njt_str_t                    staple;
    njt_msec_t                   timeout;

    njt_resolver_t              *resolver;
    njt_msec_t                   resolver_timeout;

    njt_addr_t                  *addrs;
    njt_uint_t                   naddrs;
    njt_str_t                    host;
    njt_str_t                    uri;
    in_port_t                    port;

    SSL_CTX                     *ssl_ctx;

    X509                        *cert;
    X509                        *issuer;
    STACK_OF(X509)              *chain;

    u_char                      *name;

    time_t                       valid;
    time_t                       refresh;

    unsigned                     verify:1;
    unsigned                     loading:1;
} njt_ssl_stapling_t;


typedef struct {
    njt_addr_t                  *addrs;
    njt_uint_t                   naddrs;

    njt_str_t                    host;
    njt_str_t                    uri;
    in_port_t                    port;
    njt_uint_t                   depth;

    njt_shm_zone_t              *shm_zone;

    njt_resolver_t              *resolver;
    njt_msec_t                   resolver_timeout;
} njt_ssl_ocsp_conf_t;


typedef struct {
    njt_rbtree_t                 rbtree;
    njt_rbtree_node_t            sentinel;
    njt_queue_t                  expire_queue;
} njt_ssl_ocsp_cache_t;


typedef struct {
    njt_str_node_t               node;
    njt_queue_t                  queue;
    int                          status;
    time_t                       valid;
} njt_ssl_ocsp_cache_node_t;


typedef struct njt_ssl_ocsp_ctx_s  njt_ssl_ocsp_ctx_t;


struct njt_ssl_ocsp_s {
    STACK_OF(X509)              *certs;
    njt_uint_t                   ncert;

    int                          cert_status;
    njt_int_t                    status;

    njt_ssl_ocsp_conf_t         *conf;
    njt_ssl_ocsp_ctx_t          *ctx;
};


struct njt_ssl_ocsp_ctx_s {
    SSL_CTX                     *ssl_ctx;

    X509                        *cert;
    X509                        *issuer;
    STACK_OF(X509)              *chain;

    int                          status;
    time_t                       valid;

    u_char                      *name;

    njt_uint_t                   naddrs;
    njt_uint_t                   naddr;

    njt_addr_t                  *addrs;
    njt_str_t                    host;
    njt_str_t                    uri;
    in_port_t                    port;

    njt_resolver_t              *resolver;
    njt_msec_t                   resolver_timeout;

    njt_msec_t                   timeout;

    void                       (*handler)(njt_ssl_ocsp_ctx_t *ctx);
    void                        *data;

    njt_str_t                    key;
    njt_buf_t                   *request;
    njt_buf_t                   *response;
    njt_peer_connection_t        peer;

    njt_shm_zone_t              *shm_zone;

    njt_int_t                  (*process)(njt_ssl_ocsp_ctx_t *ctx);

    njt_uint_t                   state;

    njt_uint_t                   code;
    njt_uint_t                   count;
    njt_uint_t                   flags;
    njt_uint_t                   done;

    u_char                      *header_name_start;
    u_char                      *header_name_end;
    u_char                      *header_start;
    u_char                      *header_end;

    njt_pool_t                  *pool;
    njt_log_t                   *log;
};


static njt_int_t njt_ssl_stapling_certificate(njt_conf_t *cf, njt_ssl_t *ssl,
    X509 *cert, njt_str_t *file, njt_str_t *responder, njt_uint_t verify);
static njt_int_t njt_ssl_stapling_file(njt_conf_t *cf, njt_ssl_t *ssl,
    njt_ssl_stapling_t *staple, njt_str_t *file);
static njt_int_t njt_ssl_stapling_issuer(njt_conf_t *cf, njt_ssl_t *ssl,
    njt_ssl_stapling_t *staple);
static njt_int_t njt_ssl_stapling_responder(njt_conf_t *cf, njt_ssl_t *ssl,
    njt_ssl_stapling_t *staple, njt_str_t *responder);

static int njt_ssl_certificate_status_callback(njt_ssl_conn_t *ssl_conn,
    void *data);
static void njt_ssl_stapling_update(njt_ssl_stapling_t *staple);
static void njt_ssl_stapling_ocsp_handler(njt_ssl_ocsp_ctx_t *ctx);

static time_t njt_ssl_stapling_time(ASN1_GENERALIZEDTIME *asn1time);

static void njt_ssl_stapling_cleanup(void *data);

static void njt_ssl_ocsp_validate_next(njt_connection_t *c);
static void njt_ssl_ocsp_handler(njt_ssl_ocsp_ctx_t *ctx);
static njt_int_t njt_ssl_ocsp_responder(njt_connection_t *c,
    njt_ssl_ocsp_ctx_t *ctx);

static njt_ssl_ocsp_ctx_t *njt_ssl_ocsp_start(njt_log_t *log);
static void njt_ssl_ocsp_done(njt_ssl_ocsp_ctx_t *ctx);
static void njt_ssl_ocsp_next(njt_ssl_ocsp_ctx_t *ctx);
static void njt_ssl_ocsp_request(njt_ssl_ocsp_ctx_t *ctx);
static void njt_ssl_ocsp_resolve_handler(njt_resolver_ctx_t *resolve);
static void njt_ssl_ocsp_connect(njt_ssl_ocsp_ctx_t *ctx);
static void njt_ssl_ocsp_write_handler(njt_event_t *wev);
static void njt_ssl_ocsp_read_handler(njt_event_t *rev);
static void njt_ssl_ocsp_dummy_handler(njt_event_t *ev);

static njt_int_t njt_ssl_ocsp_create_request(njt_ssl_ocsp_ctx_t *ctx);
static njt_int_t njt_ssl_ocsp_process_status_line(njt_ssl_ocsp_ctx_t *ctx);
static njt_int_t njt_ssl_ocsp_parse_status_line(njt_ssl_ocsp_ctx_t *ctx);
static njt_int_t njt_ssl_ocsp_process_headers(njt_ssl_ocsp_ctx_t *ctx);
static njt_int_t njt_ssl_ocsp_parse_header_line(njt_ssl_ocsp_ctx_t *ctx);
static njt_int_t njt_ssl_ocsp_process_body(njt_ssl_ocsp_ctx_t *ctx);
static njt_int_t njt_ssl_ocsp_verify(njt_ssl_ocsp_ctx_t *ctx);

static njt_int_t njt_ssl_ocsp_cache_lookup(njt_ssl_ocsp_ctx_t *ctx);
static njt_int_t njt_ssl_ocsp_cache_store(njt_ssl_ocsp_ctx_t *ctx);
static njt_int_t njt_ssl_ocsp_create_key(njt_ssl_ocsp_ctx_t *ctx);

static u_char *njt_ssl_ocsp_log_error(njt_log_t *log, u_char *buf, size_t len);


njt_int_t
njt_ssl_stapling(njt_conf_t *cf, njt_ssl_t *ssl, njt_str_t *file,
    njt_str_t *responder, njt_uint_t verify)
{
    X509  *cert;

    for (cert = SSL_CTX_get_ex_data(ssl->ctx, njt_ssl_certificate_index);
         cert;
         cert = X509_get_ex_data(cert, njt_ssl_next_certificate_index))
    {
        if (njt_ssl_stapling_certificate(cf, ssl, cert, file, responder, verify)
            != NJT_OK)
        {
            return NJT_ERROR;
        }
    }

    SSL_CTX_set_tlsext_status_cb(ssl->ctx, njt_ssl_certificate_status_callback);

    return NJT_OK;
}


static njt_int_t
njt_ssl_stapling_certificate(njt_conf_t *cf, njt_ssl_t *ssl, X509 *cert,
    njt_str_t *file, njt_str_t *responder, njt_uint_t verify)
{
    njt_int_t            rc;
    njt_pool_cleanup_t  *cln;
    njt_ssl_stapling_t  *staple;

    staple = njt_pcalloc(cf->pool, sizeof(njt_ssl_stapling_t));
    if (staple == NULL) {
        return NJT_ERROR;
    }

    cln = njt_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NJT_ERROR;
    }

    cln->handler = njt_ssl_stapling_cleanup;
    cln->data = staple;

    if (X509_set_ex_data(cert, njt_ssl_stapling_index, staple) == 0) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0, "X509_set_ex_data() failed");
        return NJT_ERROR;
    }

#ifdef SSL_CTRL_SELECT_CURRENT_CERT
    /* OpenSSL 1.0.2+ */
    SSL_CTX_select_current_cert(ssl->ctx, cert);
#endif

#ifdef SSL_CTRL_GET_EXTRA_CHAIN_CERTS
    /* OpenSSL 1.0.1+ */
    SSL_CTX_get_extra_chain_certs(ssl->ctx, &staple->chain);
#else
    staple->chain = ssl->ctx->extra_certs;
#endif

    staple->ssl_ctx = ssl->ctx;
    staple->timeout = 60000;
    staple->verify = verify;
    staple->cert = cert;
    staple->name = X509_get_ex_data(staple->cert,
                                    njt_ssl_certificate_name_index);

    if (file->len) {
        /* use OCSP response from the file */

        if (njt_ssl_stapling_file(cf, ssl, staple, file) != NJT_OK) {
            return NJT_ERROR;
        }

        return NJT_OK;
    }

    rc = njt_ssl_stapling_issuer(cf, ssl, staple);

    if (rc == NJT_DECLINED) {
        return NJT_OK;
    }

    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    rc = njt_ssl_stapling_responder(cf, ssl, staple, responder);

    if (rc == NJT_DECLINED) {
        return NJT_OK;
    }

    if (rc != NJT_OK) {
        return NJT_ERROR;
    }

    return NJT_OK;
}


static njt_int_t
njt_ssl_stapling_file(njt_conf_t *cf, njt_ssl_t *ssl,
    njt_ssl_stapling_t *staple, njt_str_t *file)
{
    BIO            *bio;
    int             len;
    u_char         *p, *buf;
    OCSP_RESPONSE  *response;

    if (njt_conf_full_name(cf->cycle, file, 1) != NJT_OK) {
        return NJT_ERROR;
    }

    bio = BIO_new_file((char *) file->data, "rb");
    if (bio == NULL) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "BIO_new_file(\"%s\") failed", file->data);
        return NJT_ERROR;
    }

    response = d2i_OCSP_RESPONSE_bio(bio, NULL);
    if (response == NULL) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "d2i_OCSP_RESPONSE_bio(\"%s\") failed", file->data);
        BIO_free(bio);
        return NJT_ERROR;
    }

    len = i2d_OCSP_RESPONSE(response, NULL);
    if (len <= 0) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "i2d_OCSP_RESPONSE(\"%s\") failed", file->data);
        goto failed;
    }

    buf = njt_alloc(len, ssl->log);
    if (buf == NULL) {
        goto failed;
    }

    p = buf;
    len = i2d_OCSP_RESPONSE(response, &p);
    if (len <= 0) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "i2d_OCSP_RESPONSE(\"%s\") failed", file->data);
        njt_free(buf);
        goto failed;
    }

    OCSP_RESPONSE_free(response);
    BIO_free(bio);

    staple->staple.data = buf;
    staple->staple.len = len;
    staple->valid = NJT_MAX_TIME_T_VALUE;

    return NJT_OK;

failed:

    OCSP_RESPONSE_free(response);
    BIO_free(bio);

    return NJT_ERROR;
}


static njt_int_t
njt_ssl_stapling_issuer(njt_conf_t *cf, njt_ssl_t *ssl,
    njt_ssl_stapling_t *staple)
{
    int              i, n, rc;
    X509            *cert, *issuer;
    X509_STORE      *store;
    X509_STORE_CTX  *store_ctx;

    cert = staple->cert;

    n = sk_X509_num(staple->chain);

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, ssl->log, 0,
                   "SSL get issuer: %d extra certs", n);

    for (i = 0; i < n; i++) {
        issuer = sk_X509_value(staple->chain, i);
        if (X509_check_issued(issuer, cert) == X509_V_OK) {
#if OPENSSL_VERSION_NUMBER >= 0x10100001L
            X509_up_ref(issuer);
#else
            CRYPTO_add(&issuer->references, 1, CRYPTO_LOCK_X509);
#endif

            njt_log_debug1(NJT_LOG_DEBUG_EVENT, ssl->log, 0,
                           "SSL get issuer: found %p in extra certs", issuer);

            staple->issuer = issuer;

            return NJT_OK;
        }
    }

    store = SSL_CTX_get_cert_store(ssl->ctx);
    if (store == NULL) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_get_cert_store() failed");
        return NJT_ERROR;
    }

    store_ctx = X509_STORE_CTX_new();
    if (store_ctx == NULL) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "X509_STORE_CTX_new() failed");
        return NJT_ERROR;
    }

    if (X509_STORE_CTX_init(store_ctx, store, NULL, NULL) == 0) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "X509_STORE_CTX_init() failed");
        X509_STORE_CTX_free(store_ctx);
        return NJT_ERROR;
    }

    rc = X509_STORE_CTX_get1_issuer(&issuer, store_ctx, cert);

    if (rc == -1) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "X509_STORE_CTX_get1_issuer() failed");
        X509_STORE_CTX_free(store_ctx);
        return NJT_ERROR;
    }

    if (rc == 0) {
        njt_log_error(NJT_LOG_WARN, ssl->log, 0,
                      "\"ssl_stapling\" ignored, "
                      "issuer certificate not found for certificate \"%s\"",
                      staple->name);
        X509_STORE_CTX_free(store_ctx);
        return NJT_DECLINED;
    }

    X509_STORE_CTX_free(store_ctx);

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, ssl->log, 0,
                   "SSL get issuer: found %p in cert store", issuer);

    staple->issuer = issuer;

    return NJT_OK;
}


static njt_int_t
njt_ssl_stapling_responder(njt_conf_t *cf, njt_ssl_t *ssl,
    njt_ssl_stapling_t *staple, njt_str_t *responder)
{
    char                      *s;
    njt_str_t                  rsp;
    njt_url_t                  u;
    STACK_OF(OPENSSL_STRING)  *aia;

    if (responder->len == 0) {

        /* extract OCSP responder URL from certificate */

        aia = X509_get1_ocsp(staple->cert);
        if (aia == NULL) {
            njt_log_error(NJT_LOG_WARN, ssl->log, 0,
                          "\"ssl_stapling\" ignored, "
                          "no OCSP responder URL in the certificate \"%s\"",
                          staple->name);
            return NJT_DECLINED;
        }

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
        s = sk_OPENSSL_STRING_value(aia, 0);
#else
        s = sk_value(aia, 0);
#endif
        if (s == NULL) {
            njt_log_error(NJT_LOG_WARN, ssl->log, 0,
                          "\"ssl_stapling\" ignored, "
                          "no OCSP responder URL in the certificate \"%s\"",
                          staple->name);
            X509_email_free(aia);
            return NJT_DECLINED;
        }

        responder = &rsp;

        responder->len = njt_strlen(s);
        responder->data = njt_palloc(cf->pool, responder->len);
        if (responder->data == NULL) {
            X509_email_free(aia);
            return NJT_ERROR;
        }

        njt_memcpy(responder->data, s, responder->len);
        X509_email_free(aia);
    }

    njt_memzero(&u, sizeof(njt_url_t));

    u.url = *responder;
    u.default_port = 80;
    u.uri_part = 1;

    if (u.url.len > 7
        && njt_strncasecmp(u.url.data, (u_char *) "http://", 7) == 0)
    {
        u.url.len -= 7;
        u.url.data += 7;

    } else {
        njt_log_error(NJT_LOG_WARN, ssl->log, 0,
                      "\"ssl_stapling\" ignored, "
                      "invalid URL prefix in OCSP responder \"%V\" "
                      "in the certificate \"%s\"",
                      &u.url, staple->name);
        return NJT_DECLINED;
    }

    if (njt_parse_url(cf->pool, &u) != NJT_OK) {
        if (u.err) {
            njt_log_error(NJT_LOG_WARN, ssl->log, 0,
                          "\"ssl_stapling\" ignored, "
                          "%s in OCSP responder \"%V\" "
                          "in the certificate \"%s\"",
                          u.err, &u.url, staple->name);
            return NJT_DECLINED;
        }

        return NJT_ERROR;
    }

    staple->addrs = u.addrs;
    staple->naddrs = u.naddrs;
    staple->host = u.host;
    staple->uri = u.uri;
    staple->port = u.port;

    if (staple->uri.len == 0) {
        njt_str_set(&staple->uri, "/");
    }

    return NJT_OK;
}


njt_int_t
njt_ssl_stapling_resolver(njt_conf_t *cf, njt_ssl_t *ssl,
    njt_resolver_t *resolver, njt_msec_t resolver_timeout)
{
    X509                *cert;
    njt_ssl_stapling_t  *staple;

    for (cert = SSL_CTX_get_ex_data(ssl->ctx, njt_ssl_certificate_index);
         cert;
         cert = X509_get_ex_data(cert, njt_ssl_next_certificate_index))
    {
        staple = X509_get_ex_data(cert, njt_ssl_stapling_index);
        staple->resolver = resolver;
        staple->resolver_timeout = resolver_timeout;
    }

    return NJT_OK;
}


static int
njt_ssl_certificate_status_callback(njt_ssl_conn_t *ssl_conn, void *data)
{
    int                  rc;
    X509                *cert;
    u_char              *p;
    njt_connection_t    *c;
    njt_ssl_stapling_t  *staple;

    c = njt_ssl_get_connection(ssl_conn);

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL certificate status callback");

    rc = SSL_TLSEXT_ERR_NOACK;

    cert = SSL_get_certificate(ssl_conn);

    if (cert == NULL) {
        return rc;
    }

    staple = X509_get_ex_data(cert, njt_ssl_stapling_index);

    if (staple == NULL) {
        return rc;
    }

    if (staple->staple.len
        && staple->valid >= njt_time())
    {
        /* we have to copy ocsp response as OpenSSL will free it by itself */

        p = OPENSSL_malloc(staple->staple.len);
        if (p == NULL) {
            njt_ssl_error(NJT_LOG_ALERT, c->log, 0, "OPENSSL_malloc() failed");
            return SSL_TLSEXT_ERR_NOACK;
        }

        njt_memcpy(p, staple->staple.data, staple->staple.len);

        SSL_set_tlsext_status_ocsp_resp(ssl_conn, p, staple->staple.len);

        rc = SSL_TLSEXT_ERR_OK;
    }

    njt_ssl_stapling_update(staple);

    return rc;
}


static void
njt_ssl_stapling_update(njt_ssl_stapling_t *staple)
{
    njt_ssl_ocsp_ctx_t  *ctx;

    if (staple->host.len == 0
        || staple->loading || staple->refresh >= njt_time())
    {
        return;
    }

    staple->loading = 1;

    ctx = njt_ssl_ocsp_start(njt_cycle->log);
    if (ctx == NULL) {
        return;
    }

    ctx->ssl_ctx = staple->ssl_ctx;
    ctx->cert = staple->cert;
    ctx->issuer = staple->issuer;
    ctx->chain = staple->chain;
    ctx->name = staple->name;
    ctx->flags = (staple->verify ? OCSP_TRUSTOTHER : OCSP_NOVERIFY);

    ctx->addrs = staple->addrs;
    ctx->naddrs = staple->naddrs;
    ctx->host = staple->host;
    ctx->uri = staple->uri;
    ctx->port = staple->port;
    ctx->timeout = staple->timeout;

    ctx->resolver = staple->resolver;
    ctx->resolver_timeout = staple->resolver_timeout;

    ctx->handler = njt_ssl_stapling_ocsp_handler;
    ctx->data = staple;

    njt_ssl_ocsp_request(ctx);

    return;
}


static void
njt_ssl_stapling_ocsp_handler(njt_ssl_ocsp_ctx_t *ctx)
{
    time_t               now;
    njt_str_t            response;
    njt_ssl_stapling_t  *staple;

    staple = ctx->data;
    now = njt_time();

    if (njt_ssl_ocsp_verify(ctx) != NJT_OK) {
        goto error;
    }

    if (ctx->status != V_OCSP_CERTSTATUS_GOOD) {
        njt_log_error(NJT_LOG_ERR, ctx->log, 0,
                      "certificate status \"%s\" in the OCSP response",
                      OCSP_cert_status_str(ctx->status));
        goto error;
    }

    /* copy the response to memory not in ctx->pool */

    response.len = ctx->response->last - ctx->response->pos;
    response.data = njt_alloc(response.len, ctx->log);

    if (response.data == NULL) {
        goto error;
    }

    njt_memcpy(response.data, ctx->response->pos, response.len);

    if (staple->staple.data) {
        njt_free(staple->staple.data);
    }

    staple->staple = response;
    staple->valid = ctx->valid;

    /*
     * refresh before the response expires,
     * but not earlier than in 5 minutes, and at least in an hour
     */

    staple->loading = 0;
    staple->refresh = njt_max(njt_min(ctx->valid - 300, now + 3600), now + 300);

    njt_ssl_ocsp_done(ctx);
    return;

error:

    staple->loading = 0;
    staple->refresh = now + 300;

    njt_ssl_ocsp_done(ctx);
}


static time_t
njt_ssl_stapling_time(ASN1_GENERALIZEDTIME *asn1time)
{
    BIO     *bio;
    char    *value;
    size_t   len;
    time_t   time;

    /*
     * OpenSSL doesn't provide a way to convert ASN1_GENERALIZEDTIME
     * into time_t.  To do this, we use ASN1_GENERALIZEDTIME_print(),
     * which uses the "MMM DD HH:MM:SS YYYY [GMT]" format (e.g.,
     * "Feb  3 00:55:52 2015 GMT"), and parse the result.
     */

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        return NJT_ERROR;
    }

    /* fake weekday prepended to match C asctime() format */

    BIO_write(bio, "Tue ", sizeof("Tue ") - 1);
    ASN1_GENERALIZEDTIME_print(bio, asn1time);
    len = BIO_get_mem_data(bio, &value);

    time = njt_parse_http_time((u_char *) value, len);

    BIO_free(bio);

    return time;
}


static void
njt_ssl_stapling_cleanup(void *data)
{
    njt_ssl_stapling_t  *staple = data;

    if (staple->issuer) {
        X509_free(staple->issuer);
    }

    if (staple->staple.data) {
        njt_free(staple->staple.data);
    }
}


njt_int_t
njt_ssl_ocsp(njt_conf_t *cf, njt_ssl_t *ssl, njt_str_t *responder,
    njt_uint_t depth, njt_shm_zone_t *shm_zone)
{
    njt_url_t             u;
    njt_ssl_ocsp_conf_t  *ocf;

    ocf = njt_pcalloc(cf->pool, sizeof(njt_ssl_ocsp_conf_t));
    if (ocf == NULL) {
        return NJT_ERROR;
    }

    ocf->depth = depth;
    ocf->shm_zone = shm_zone;

    if (responder->len) {
        njt_memzero(&u, sizeof(njt_url_t));

        u.url = *responder;
        u.default_port = 80;
        u.uri_part = 1;

        if (u.url.len > 7
            && njt_strncasecmp(u.url.data, (u_char *) "http://", 7) == 0)
        {
            u.url.len -= 7;
            u.url.data += 7;

        } else {
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "invalid URL prefix in OCSP responder \"%V\" "
                          "in \"ssl_ocsp_responder\"", &u.url);
            return NJT_ERROR;
        }

        if (njt_parse_url(cf->pool, &u) != NJT_OK) {
            if (u.err) {
                njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                              "%s in OCSP responder \"%V\" "
                              "in \"ssl_ocsp_responder\"", u.err, &u.url);
            }

            return NJT_ERROR;
        }

        ocf->addrs = u.addrs;
        ocf->naddrs = u.naddrs;
        ocf->host = u.host;
        ocf->uri = u.uri;
        ocf->port = u.port;
    }

    if (SSL_CTX_set_ex_data(ssl->ctx, njt_ssl_ocsp_index, ocf) == 0) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set_ex_data() failed");
        return NJT_ERROR;
    }

    return NJT_OK;
}


njt_int_t
njt_ssl_ocsp_resolver(njt_conf_t *cf, njt_ssl_t *ssl,
    njt_resolver_t *resolver, njt_msec_t resolver_timeout)
{
    njt_ssl_ocsp_conf_t  *ocf;

    ocf = SSL_CTX_get_ex_data(ssl->ctx, njt_ssl_ocsp_index);
    ocf->resolver = resolver;
    ocf->resolver_timeout = resolver_timeout;

    return NJT_OK;
}


njt_int_t
njt_ssl_ocsp_validate(njt_connection_t *c)
{
    X509                 *cert;
    SSL_CTX              *ssl_ctx;
    njt_int_t             rc;
    X509_STORE           *store;
    X509_STORE_CTX       *store_ctx;
    STACK_OF(X509)       *chain;
    njt_ssl_ocsp_t       *ocsp;
    njt_ssl_ocsp_conf_t  *ocf;

    if (c->ssl->in_ocsp) {
        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            return NJT_ERROR;
        }

        if (njt_handle_write_event(c->write, 0) != NJT_OK) {
            return NJT_ERROR;
        }

        return NJT_AGAIN;
    }

    ssl_ctx = SSL_get_SSL_CTX(c->ssl->connection);

    ocf = SSL_CTX_get_ex_data(ssl_ctx, njt_ssl_ocsp_index);
    if (ocf == NULL) {
        return NJT_OK;
    }

    if (SSL_get_verify_result(c->ssl->connection) != X509_V_OK) {
        return NJT_OK;
    }

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return NJT_OK;
    }

    ocsp = njt_pcalloc(c->pool, sizeof(njt_ssl_ocsp_t));
    if (ocsp == NULL) {
        X509_free(cert);
        return NJT_ERROR;
    }

    c->ssl->ocsp = ocsp;

    ocsp->status = NJT_AGAIN;
    ocsp->cert_status = V_OCSP_CERTSTATUS_GOOD;
    ocsp->conf = ocf;

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined LIBRESSL_VERSION_NUMBER)

    ocsp->certs = SSL_get0_verified_chain(c->ssl->connection);

    if (ocsp->certs) {
        ocsp->certs = X509_chain_up_ref(ocsp->certs);
        if (ocsp->certs == NULL) {
            X509_free(cert);
            return NJT_ERROR;
        }
    }

#endif

    if (ocsp->certs == NULL) {
        store = SSL_CTX_get_cert_store(ssl_ctx);
        if (store == NULL) {
            njt_ssl_error(NJT_LOG_ERR, c->log, 0,
                          "SSL_CTX_get_cert_store() failed");
            X509_free(cert);
            return NJT_ERROR;
        }

        store_ctx = X509_STORE_CTX_new();
        if (store_ctx == NULL) {
            njt_ssl_error(NJT_LOG_ERR, c->log, 0,
                          "X509_STORE_CTX_new() failed");
            X509_free(cert);
            return NJT_ERROR;
        }

        chain = SSL_get_peer_cert_chain(c->ssl->connection);

        if (X509_STORE_CTX_init(store_ctx, store, cert, chain) == 0) {
            njt_ssl_error(NJT_LOG_ERR, c->log, 0,
                          "X509_STORE_CTX_init() failed");
            X509_STORE_CTX_free(store_ctx);
            X509_free(cert);
            return NJT_ERROR;
        }

        rc = X509_verify_cert(store_ctx);
        if (rc <= 0) {
            njt_ssl_error(NJT_LOG_ERR, c->log, 0, "X509_verify_cert() failed");
            X509_STORE_CTX_free(store_ctx);
            X509_free(cert);
            return NJT_ERROR;
        }

        ocsp->certs = X509_STORE_CTX_get1_chain(store_ctx);
        if (ocsp->certs == NULL) {
            njt_ssl_error(NJT_LOG_ERR, c->log, 0,
                          "X509_STORE_CTX_get1_chain() failed");
            X509_STORE_CTX_free(store_ctx);
            X509_free(cert);
            return NJT_ERROR;
        }

        X509_STORE_CTX_free(store_ctx);
    }

    X509_free(cert);

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "ssl ocsp validate, certs:%d", sk_X509_num(ocsp->certs));

    njt_ssl_ocsp_validate_next(c);

    if (ocsp->status == NJT_AGAIN) {
        c->ssl->in_ocsp = 1;
        return NJT_AGAIN;
    }

    return NJT_OK;
}


static void
njt_ssl_ocsp_validate_next(njt_connection_t *c)
{
    njt_int_t             rc;
    njt_uint_t            n;
    njt_ssl_ocsp_t       *ocsp;
    njt_ssl_ocsp_ctx_t   *ctx;
    njt_ssl_ocsp_conf_t  *ocf;

    ocsp = c->ssl->ocsp;
    ocf = ocsp->conf;

    n = sk_X509_num(ocsp->certs);

    for ( ;; ) {

        if (ocsp->ncert == n - 1 || (ocf->depth == 2 && ocsp->ncert == 1)) {
            njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                           "ssl ocsp validated, certs:%ui", ocsp->ncert);
            rc = NJT_OK;
            goto done;
        }

        njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "ssl ocsp validate cert:%ui", ocsp->ncert);

        ctx = njt_ssl_ocsp_start(c->log);
        if (ctx == NULL) {
            rc = NJT_ERROR;
            goto done;
        }

        ocsp->ctx = ctx;

        ctx->ssl_ctx = SSL_get_SSL_CTX(c->ssl->connection);
        ctx->cert = sk_X509_value(ocsp->certs, ocsp->ncert);
        ctx->issuer = sk_X509_value(ocsp->certs, ocsp->ncert + 1);
        ctx->chain = ocsp->certs;

        ctx->resolver = ocf->resolver;
        ctx->resolver_timeout = ocf->resolver_timeout;

        ctx->handler = njt_ssl_ocsp_handler;
        ctx->data = c;

        ctx->shm_zone = ocf->shm_zone;

        ctx->addrs = ocf->addrs;
        ctx->naddrs = ocf->naddrs;
        ctx->host = ocf->host;
        ctx->uri = ocf->uri;
        ctx->port = ocf->port;

        rc = njt_ssl_ocsp_responder(c, ctx);
        if (rc != NJT_OK) {
            goto done;
        }

        if (ctx->uri.len == 0) {
            njt_str_set(&ctx->uri, "/");
        }

        ocsp->ncert++;

        rc = njt_ssl_ocsp_cache_lookup(ctx);

        if (rc == NJT_ERROR) {
            goto done;
        }

        if (rc == NJT_DECLINED) {
            break;
        }

        /* rc == NJT_OK */

        if (ctx->status != V_OCSP_CERTSTATUS_GOOD) {
            njt_log_debug1(NJT_LOG_DEBUG_EVENT, ctx->log, 0,
                           "ssl ocsp cached status \"%s\"",
                           OCSP_cert_status_str(ctx->status));
            ocsp->cert_status = ctx->status;
            goto done;
        }

        ocsp->ctx = NULL;
        njt_ssl_ocsp_done(ctx);
    }

    njt_ssl_ocsp_request(ctx);
    return;

done:

    ocsp->status = rc;

    if (c->ssl->in_ocsp) {
        c->ssl->handshaked = 1;
        c->ssl->handler(c);
    }
}


static void
njt_ssl_ocsp_handler(njt_ssl_ocsp_ctx_t *ctx)
{
    njt_int_t          rc;
    njt_ssl_ocsp_t    *ocsp;
    njt_connection_t  *c;

    c = ctx->data;
    ocsp = c->ssl->ocsp;
    ocsp->ctx = NULL;

    rc = njt_ssl_ocsp_verify(ctx);
    if (rc != NJT_OK) {
        goto done;
    }

    rc = njt_ssl_ocsp_cache_store(ctx);
    if (rc != NJT_OK) {
        goto done;
    }

    if (ctx->status != V_OCSP_CERTSTATUS_GOOD) {
        ocsp->cert_status = ctx->status;
        goto done;
    }

    njt_ssl_ocsp_done(ctx);

    njt_ssl_ocsp_validate_next(c);

    return;

done:

    ocsp->status = rc;
    njt_ssl_ocsp_done(ctx);

    if (c->ssl->in_ocsp) {
        c->ssl->handshaked = 1;
        c->ssl->handler(c);
    }
}


static njt_int_t
njt_ssl_ocsp_responder(njt_connection_t *c, njt_ssl_ocsp_ctx_t *ctx)
{
    char                      *s;
    njt_str_t                  responder;
    njt_url_t                  u;
    STACK_OF(OPENSSL_STRING)  *aia;

    if (ctx->host.len) {
        return NJT_OK;
    }

    /* extract OCSP responder URL from certificate */

    aia = X509_get1_ocsp(ctx->cert);
    if (aia == NULL) {
        njt_log_error(NJT_LOG_ERR, c->log, 0,
                      "no OCSP responder URL in certificate");
        return NJT_ERROR;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
    s = sk_OPENSSL_STRING_value(aia, 0);
#else
    s = sk_value(aia, 0);
#endif
    if (s == NULL) {
        njt_log_error(NJT_LOG_ERR, c->log, 0,
                      "no OCSP responder URL in certificate");
        X509_email_free(aia);
        return NJT_ERROR;
    }

    responder.len = njt_strlen(s);
    responder.data = njt_palloc(ctx->pool, responder.len);
    if (responder.data == NULL) {
        X509_email_free(aia);
        return NJT_ERROR;
    }

    njt_memcpy(responder.data, s, responder.len);
    X509_email_free(aia);

    njt_memzero(&u, sizeof(njt_url_t));

    u.url = responder;
    u.default_port = 80;
    u.uri_part = 1;
    u.no_resolve = 1;

    if (u.url.len > 7
        && njt_strncasecmp(u.url.data, (u_char *) "http://", 7) == 0)
    {
        u.url.len -= 7;
        u.url.data += 7;

    } else {
        njt_log_error(NJT_LOG_ERR, c->log, 0,
                      "invalid URL prefix in OCSP responder \"%V\" "
                      "in certificate", &u.url);
        return NJT_ERROR;
    }

    if (njt_parse_url(ctx->pool, &u) != NJT_OK) {
        if (u.err) {
            njt_log_error(NJT_LOG_ERR, c->log, 0,
                          "%s in OCSP responder \"%V\" in certificate",
                          u.err, &u.url);
        }

        return NJT_ERROR;
    }

    if (u.host.len == 0) {
        njt_log_error(NJT_LOG_ERR, c->log, 0,
                      "empty host in OCSP responder in certificate");
        return NJT_ERROR;
    }

    ctx->addrs = u.addrs;
    ctx->naddrs = u.naddrs;
    ctx->host = u.host;
    ctx->uri = u.uri;
    ctx->port = u.port;

    return NJT_OK;
}


njt_int_t
njt_ssl_ocsp_get_status(njt_connection_t *c, const char **s)
{
    njt_ssl_ocsp_t  *ocsp;

    ocsp = c->ssl->ocsp;
    if (ocsp == NULL) {
        return NJT_OK;
    }

    if (ocsp->status == NJT_ERROR) {
        *s = "certificate status request failed";
        return NJT_DECLINED;
    }

    switch (ocsp->cert_status) {

    case V_OCSP_CERTSTATUS_GOOD:
        return NJT_OK;

    case V_OCSP_CERTSTATUS_REVOKED:
        *s = "certificate revoked";
        break;

    default: /* V_OCSP_CERTSTATUS_UNKNOWN */
        *s = "certificate status unknown";
    }

    return NJT_DECLINED;
}


void
njt_ssl_ocsp_cleanup(njt_connection_t *c)
{
    njt_ssl_ocsp_t  *ocsp;

    ocsp = c->ssl->ocsp;
    if (ocsp == NULL) {
        return;
    }

    if (ocsp->ctx) {
        njt_ssl_ocsp_done(ocsp->ctx);
        ocsp->ctx = NULL;
    }

    if (ocsp->certs) {
        sk_X509_pop_free(ocsp->certs, X509_free);
        ocsp->certs = NULL;
    }
}


static njt_ssl_ocsp_ctx_t *
njt_ssl_ocsp_start(njt_log_t *log)
{
    njt_pool_t          *pool;
    njt_ssl_ocsp_ctx_t  *ctx;

    pool = njt_create_pool(2048, log);
    if (pool == NULL) {
        return NULL;
    }

    ctx = njt_pcalloc(pool, sizeof(njt_ssl_ocsp_ctx_t));
    if (ctx == NULL) {
        njt_destroy_pool(pool);
        return NULL;
    }

    log = njt_palloc(pool, sizeof(njt_log_t));
    if (log == NULL) {
        njt_destroy_pool(pool);
        return NULL;
    }

    ctx->pool = pool;

    *log = *ctx->pool->log;

    ctx->pool->log = log;
    ctx->log = log;

    log->handler = njt_ssl_ocsp_log_error;
    log->data = ctx;
    log->action = "requesting certificate status";

    return ctx;
}


static void
njt_ssl_ocsp_done(njt_ssl_ocsp_ctx_t *ctx)
{
    njt_log_debug0(NJT_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp done");

    if (ctx->peer.connection) {
        njt_close_connection(ctx->peer.connection);
    }

    njt_destroy_pool(ctx->pool);
}


static void
njt_ssl_ocsp_error(njt_ssl_ocsp_ctx_t *ctx)
{
    njt_log_debug0(NJT_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp error");

    ctx->code = 0;
    ctx->handler(ctx);
}


static void
njt_ssl_ocsp_next(njt_ssl_ocsp_ctx_t *ctx)
{
    njt_log_debug0(NJT_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp next");

    if (++ctx->naddr >= ctx->naddrs) {
        njt_ssl_ocsp_error(ctx);
        return;
    }

    ctx->request->pos = ctx->request->start;

    if (ctx->response) {
        ctx->response->last = ctx->response->pos;
    }

    if (ctx->peer.connection) {
        njt_close_connection(ctx->peer.connection);
        ctx->peer.connection = NULL;
    }

    ctx->state = 0;
    ctx->count = 0;
    ctx->done = 0;

    njt_ssl_ocsp_connect(ctx);
}


static void
njt_ssl_ocsp_request(njt_ssl_ocsp_ctx_t *ctx)
{
    njt_resolver_ctx_t  *resolve, temp;

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp request");

    if (njt_ssl_ocsp_create_request(ctx) != NJT_OK) {
        njt_ssl_ocsp_error(ctx);
        return;
    }

    if (ctx->resolver) {
        /* resolve OCSP responder hostname */

        temp.name = ctx->host;

        resolve = njt_resolve_start(ctx->resolver, &temp);
        if (resolve == NULL) {
            njt_ssl_ocsp_error(ctx);
            return;
        }

        if (resolve == NJT_NO_RESOLVER) {
            if (ctx->naddrs == 0) {
                njt_log_error(NJT_LOG_ERR, ctx->log, 0,
                              "no resolver defined to resolve %V", &ctx->host);

                njt_ssl_ocsp_error(ctx);
                return;
            }

            njt_log_error(NJT_LOG_WARN, ctx->log, 0,
                          "no resolver defined to resolve %V", &ctx->host);
            goto connect;
        }

        resolve->name = ctx->host;
        resolve->handler = njt_ssl_ocsp_resolve_handler;
        resolve->data = ctx;
        resolve->timeout = ctx->resolver_timeout;

        if (njt_resolve_name(resolve) != NJT_OK) {
            njt_ssl_ocsp_error(ctx);
            return;
        }

        return;
    }

connect:

    njt_ssl_ocsp_connect(ctx);
}


static void
njt_ssl_ocsp_resolve_handler(njt_resolver_ctx_t *resolve)
{
    njt_ssl_ocsp_ctx_t *ctx = resolve->data;

    u_char           *p;
    size_t            len;
    socklen_t         socklen;
    njt_uint_t        i;
    struct sockaddr  *sockaddr;

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp resolve handler");

    if (resolve->state) {
        njt_log_error(NJT_LOG_ERR, ctx->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &resolve->name, resolve->state,
                      njt_resolver_strerror(resolve->state));
        goto failed;
    }

#if (NJT_DEBUG)
    {
    u_char     text[NJT_SOCKADDR_STRLEN];
    njt_str_t  addr;

    addr.data = text;

    for (i = 0; i < resolve->naddrs; i++) {
        addr.len = njt_sock_ntop(resolve->addrs[i].sockaddr,
                                 resolve->addrs[i].socklen,
                                 text, NJT_SOCKADDR_STRLEN, 0);

        njt_log_debug1(NJT_LOG_DEBUG_EVENT, ctx->log, 0,
                       "name was resolved to %V", &addr);

    }
    }
#endif

    ctx->naddrs = resolve->naddrs;
    ctx->addrs = njt_pcalloc(ctx->pool, ctx->naddrs * sizeof(njt_addr_t));

    if (ctx->addrs == NULL) {
        goto failed;
    }

    for (i = 0; i < resolve->naddrs; i++) {

        socklen = resolve->addrs[i].socklen;

        sockaddr = njt_palloc(ctx->pool, socklen);
        if (sockaddr == NULL) {
            goto failed;
        }

        njt_memcpy(sockaddr, resolve->addrs[i].sockaddr, socklen);
        njt_inet_set_port(sockaddr, ctx->port);

        ctx->addrs[i].sockaddr = sockaddr;
        ctx->addrs[i].socklen = socklen;

        p = njt_pnalloc(ctx->pool, NJT_SOCKADDR_STRLEN);
        if (p == NULL) {
            goto failed;
        }

        len = njt_sock_ntop(sockaddr, socklen, p, NJT_SOCKADDR_STRLEN, 1);

        ctx->addrs[i].name.len = len;
        ctx->addrs[i].name.data = p;
    }

    njt_resolve_name_done(resolve);

    njt_ssl_ocsp_connect(ctx);
    return;

failed:

    njt_resolve_name_done(resolve);
    njt_ssl_ocsp_error(ctx);
}


static void
njt_ssl_ocsp_connect(njt_ssl_ocsp_ctx_t *ctx)
{
    njt_int_t    rc;
    njt_addr_t  *addr;

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp connect %ui/%ui", ctx->naddr, ctx->naddrs);

    addr = &ctx->addrs[ctx->naddr];

    ctx->peer.sockaddr = addr->sockaddr;
    ctx->peer.socklen = addr->socklen;
    ctx->peer.name = &addr->name;
    ctx->peer.get = njt_event_get_peer;
    ctx->peer.log = ctx->log;
    ctx->peer.log_error = NJT_ERROR_ERR;

    rc = njt_event_connect_peer(&ctx->peer);

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp connect peer done");

    if (rc == NJT_ERROR) {
        njt_ssl_ocsp_error(ctx);
        return;
    }

    if (rc == NJT_BUSY || rc == NJT_DECLINED) {
        njt_ssl_ocsp_next(ctx);
        return;
    }

    ctx->peer.connection->data = ctx;
    ctx->peer.connection->pool = ctx->pool;

    ctx->peer.connection->read->handler = njt_ssl_ocsp_read_handler;
    ctx->peer.connection->write->handler = njt_ssl_ocsp_write_handler;

    ctx->process = njt_ssl_ocsp_process_status_line;

    if (ctx->timeout) {
        njt_add_timer(ctx->peer.connection->read, ctx->timeout);
        njt_add_timer(ctx->peer.connection->write, ctx->timeout);
    }

    if (rc == NJT_OK) {
        njt_ssl_ocsp_write_handler(ctx->peer.connection->write);
        return;
    }
}


static void
njt_ssl_ocsp_write_handler(njt_event_t *wev)
{
    ssize_t              n, size;
    njt_connection_t    *c;
    njt_ssl_ocsp_ctx_t  *ctx;

    c = wev->data;
    ctx = c->data;

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, wev->log, 0,
                   "ssl ocsp write handler");

    if (wev->timedout) {
        njt_log_error(NJT_LOG_ERR, wev->log, NJT_ETIMEDOUT,
                      "OCSP responder timed out");
        njt_ssl_ocsp_next(ctx);
        return;
    }

    size = ctx->request->last - ctx->request->pos;

    n = njt_send(c, ctx->request->pos, size);

    if (n == NJT_ERROR) {
        njt_ssl_ocsp_next(ctx);
        return;
    }

    if (n > 0) {
        ctx->request->pos += n;

        if (n == size) {
            wev->handler = njt_ssl_ocsp_dummy_handler;

            if (wev->timer_set) {
                njt_del_timer(wev);
            }

            if (njt_handle_write_event(wev, 0) != NJT_OK) {
                njt_ssl_ocsp_error(ctx);
            }

            return;
        }
    }

    if (!wev->timer_set && ctx->timeout) {
        njt_add_timer(wev, ctx->timeout);
    }
}


static void
njt_ssl_ocsp_read_handler(njt_event_t *rev)
{
    ssize_t              n, size;
    njt_int_t            rc;
    njt_connection_t    *c;
    njt_ssl_ocsp_ctx_t  *ctx;

    c = rev->data;
    ctx = c->data;

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, rev->log, 0,
                   "ssl ocsp read handler");

    if (rev->timedout) {
        njt_log_error(NJT_LOG_ERR, rev->log, NJT_ETIMEDOUT,
                      "OCSP responder timed out");
        njt_ssl_ocsp_next(ctx);
        return;
    }

    if (ctx->response == NULL) {
        ctx->response = njt_create_temp_buf(ctx->pool, 16384);
        if (ctx->response == NULL) {
            njt_ssl_ocsp_error(ctx);
            return;
        }
    }

    for ( ;; ) {

        size = ctx->response->end - ctx->response->last;

        n = njt_recv(c, ctx->response->last, size);

        if (n > 0) {
            ctx->response->last += n;

            rc = ctx->process(ctx);

            if (rc == NJT_ERROR) {
                njt_ssl_ocsp_next(ctx);
                return;
            }

            continue;
        }

        if (n == NJT_AGAIN) {

            if (njt_handle_read_event(rev, 0) != NJT_OK) {
                njt_ssl_ocsp_error(ctx);
            }

            return;
        }

        break;
    }

    ctx->done = 1;

    rc = ctx->process(ctx);

    if (rc == NJT_DONE) {
        /* ctx->handler() was called */
        return;
    }

    njt_log_error(NJT_LOG_ERR, ctx->log, 0,
                  "OCSP responder prematurely closed connection");

    njt_ssl_ocsp_next(ctx);
}


static void
njt_ssl_ocsp_dummy_handler(njt_event_t *ev)
{
    njt_log_debug0(NJT_LOG_DEBUG_EVENT, ev->log, 0,
                   "ssl ocsp dummy handler");
}


static njt_int_t
njt_ssl_ocsp_create_request(njt_ssl_ocsp_ctx_t *ctx)
{
    int            len;
    u_char        *p;
    uintptr_t      escape;
    njt_str_t      binary, base64;
    njt_buf_t     *b;
    OCSP_CERTID   *id;
    OCSP_REQUEST  *ocsp;

    ocsp = OCSP_REQUEST_new();
    if (ocsp == NULL) {
        njt_ssl_error(NJT_LOG_CRIT, ctx->log, 0,
                      "OCSP_REQUEST_new() failed");
        return NJT_ERROR;
    }

    id = OCSP_cert_to_id(NULL, ctx->cert, ctx->issuer);
    if (id == NULL) {
        njt_ssl_error(NJT_LOG_CRIT, ctx->log, 0,
                      "OCSP_cert_to_id() failed");
        goto failed;
    }

    if (OCSP_request_add0_id(ocsp, id) == NULL) {
        njt_ssl_error(NJT_LOG_CRIT, ctx->log, 0,
                      "OCSP_request_add0_id() failed");
        OCSP_CERTID_free(id);
        goto failed;
    }

    len = i2d_OCSP_REQUEST(ocsp, NULL);
    if (len <= 0) {
        njt_ssl_error(NJT_LOG_CRIT, ctx->log, 0,
                      "i2d_OCSP_REQUEST() failed");
        goto failed;
    }

    binary.len = len;
    binary.data = njt_palloc(ctx->pool, len);
    if (binary.data == NULL) {
        goto failed;
    }

    p = binary.data;
    len = i2d_OCSP_REQUEST(ocsp, &p);
    if (len <= 0) {
        njt_ssl_error(NJT_LOG_EMERG, ctx->log, 0,
                      "i2d_OCSP_REQUEST() failed");
        goto failed;
    }

    base64.len = njt_base64_encoded_length(binary.len);
    base64.data = njt_palloc(ctx->pool, base64.len);
    if (base64.data == NULL) {
        goto failed;
    }

    njt_encode_base64(&base64, &binary);

    escape = njt_escape_uri(NULL, base64.data, base64.len,
                            NJT_ESCAPE_URI_COMPONENT);

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp request length %z, escape %d",
                   base64.len, (int) escape);

    len = sizeof("GET ") - 1 + ctx->uri.len + sizeof("/") - 1
          + base64.len + 2 * escape + sizeof(" HTTP/1.0" CRLF) - 1
          + sizeof("Host: ") - 1 + ctx->host.len + sizeof(CRLF) - 1
          + sizeof(CRLF) - 1;

    b = njt_create_temp_buf(ctx->pool, len);
    if (b == NULL) {
        goto failed;
    }

    p = b->last;

    p = njt_cpymem(p, "GET ", sizeof("GET ") - 1);
    p = njt_cpymem(p, ctx->uri.data, ctx->uri.len);

    if (ctx->uri.data[ctx->uri.len - 1] != '/') {
        *p++ = '/';
    }

    if (escape == 0) {
        p = njt_cpymem(p, base64.data, base64.len);

    } else {
        p = (u_char *) njt_escape_uri(p, base64.data, base64.len,
                                      NJT_ESCAPE_URI_COMPONENT);
    }

    p = njt_cpymem(p, " HTTP/1.0" CRLF, sizeof(" HTTP/1.0" CRLF) - 1);
    p = njt_cpymem(p, "Host: ", sizeof("Host: ") - 1);
    p = njt_cpymem(p, ctx->host.data, ctx->host.len);
    *p++ = CR; *p++ = LF;

    /* add "\r\n" at the header end */
    *p++ = CR; *p++ = LF;

    b->last = p;
    ctx->request = b;

    OCSP_REQUEST_free(ocsp);

    return NJT_OK;

failed:

    OCSP_REQUEST_free(ocsp);

    return NJT_ERROR;
}


static njt_int_t
njt_ssl_ocsp_process_status_line(njt_ssl_ocsp_ctx_t *ctx)
{
    njt_int_t  rc;

    rc = njt_ssl_ocsp_parse_status_line(ctx);

    if (rc == NJT_OK) {
        njt_log_debug3(NJT_LOG_DEBUG_EVENT, ctx->log, 0,
                       "ssl ocsp status %ui \"%*s\"",
                       ctx->code,
                       ctx->header_end - ctx->header_start,
                       ctx->header_start);

        ctx->process = njt_ssl_ocsp_process_headers;
        return ctx->process(ctx);
    }

    if (rc == NJT_AGAIN) {
        return NJT_AGAIN;
    }

    /* rc == NJT_ERROR */

    njt_log_error(NJT_LOG_ERR, ctx->log, 0,
                  "OCSP responder sent invalid response");

    return NJT_ERROR;
}


static njt_int_t
njt_ssl_ocsp_parse_status_line(njt_ssl_ocsp_ctx_t *ctx)
{
    u_char      ch;
    u_char     *p;
    njt_buf_t  *b;
    enum {
        sw_start = 0,
        sw_H,
        sw_HT,
        sw_HTT,
        sw_HTTP,
        sw_first_major_digit,
        sw_major_digit,
        sw_first_minor_digit,
        sw_minor_digit,
        sw_status,
        sw_space_after_status,
        sw_status_text,
        sw_almost_done
    } state;

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp process status line");

    state = ctx->state;
    b = ctx->response;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

        /* "HTTP/" */
        case sw_start:
            switch (ch) {
            case 'H':
                state = sw_H;
                break;
            default:
                return NJT_ERROR;
            }
            break;

        case sw_H:
            switch (ch) {
            case 'T':
                state = sw_HT;
                break;
            default:
                return NJT_ERROR;
            }
            break;

        case sw_HT:
            switch (ch) {
            case 'T':
                state = sw_HTT;
                break;
            default:
                return NJT_ERROR;
            }
            break;

        case sw_HTT:
            switch (ch) {
            case 'P':
                state = sw_HTTP;
                break;
            default:
                return NJT_ERROR;
            }
            break;

        case sw_HTTP:
            switch (ch) {
            case '/':
                state = sw_first_major_digit;
                break;
            default:
                return NJT_ERROR;
            }
            break;

        /* the first digit of major HTTP version */
        case sw_first_major_digit:
            if (ch < '1' || ch > '9') {
                return NJT_ERROR;
            }

            state = sw_major_digit;
            break;

        /* the major HTTP version or dot */
        case sw_major_digit:
            if (ch == '.') {
                state = sw_first_minor_digit;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NJT_ERROR;
            }

            break;

        /* the first digit of minor HTTP version */
        case sw_first_minor_digit:
            if (ch < '0' || ch > '9') {
                return NJT_ERROR;
            }

            state = sw_minor_digit;
            break;

        /* the minor HTTP version or the end of the request line */
        case sw_minor_digit:
            if (ch == ' ') {
                state = sw_status;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NJT_ERROR;
            }

            break;

        /* HTTP status code */
        case sw_status:
            if (ch == ' ') {
                break;
            }

            if (ch < '0' || ch > '9') {
                return NJT_ERROR;
            }

            ctx->code = ctx->code * 10 + (ch - '0');

            if (++ctx->count == 3) {
                state = sw_space_after_status;
                ctx->header_start = p - 2;
            }

            break;

        /* space or end of line */
        case sw_space_after_status:
            switch (ch) {
            case ' ':
                state = sw_status_text;
                break;
            case '.':                    /* IIS may send 403.1, 403.2, etc */
                state = sw_status_text;
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                ctx->header_end = p;
                goto done;
            default:
                return NJT_ERROR;
            }
            break;

        /* any text until end of line */
        case sw_status_text:
            switch (ch) {
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                ctx->header_end = p;
                goto done;
            }
            break;

        /* end of status line */
        case sw_almost_done:
            switch (ch) {
            case LF:
                ctx->header_end = p - 1;
                goto done;
            default:
                return NJT_ERROR;
            }
        }
    }

    b->pos = p;
    ctx->state = state;

    return NJT_AGAIN;

done:

    b->pos = p + 1;
    ctx->state = sw_start;

    return NJT_OK;
}


static njt_int_t
njt_ssl_ocsp_process_headers(njt_ssl_ocsp_ctx_t *ctx)
{
    size_t     len;
    njt_int_t  rc;

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp process headers");

    for ( ;; ) {
        rc = njt_ssl_ocsp_parse_header_line(ctx);

        if (rc == NJT_OK) {

            njt_log_debug4(NJT_LOG_DEBUG_EVENT, ctx->log, 0,
                           "ssl ocsp header \"%*s: %*s\"",
                           ctx->header_name_end - ctx->header_name_start,
                           ctx->header_name_start,
                           ctx->header_end - ctx->header_start,
                           ctx->header_start);

            len = ctx->header_name_end - ctx->header_name_start;

            if (len == sizeof("Content-Type") - 1
                && njt_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Content-Type",
                                   sizeof("Content-Type") - 1)
                   == 0)
            {
                len = ctx->header_end - ctx->header_start;

                if (len != sizeof("application/ocsp-response") - 1
                    || njt_strncasecmp(ctx->header_start,
                                       (u_char *) "application/ocsp-response",
                                       sizeof("application/ocsp-response") - 1)
                       != 0)
                {
                    njt_log_error(NJT_LOG_ERR, ctx->log, 0,
                                  "OCSP responder sent invalid "
                                  "\"Content-Type\" header: \"%*s\"",
                                  ctx->header_end - ctx->header_start,
                                  ctx->header_start);
                    return NJT_ERROR;
                }

                continue;
            }

            /* TODO: honor Content-Length */

            continue;
        }

        if (rc == NJT_DONE) {
            break;
        }

        if (rc == NJT_AGAIN) {
            return NJT_AGAIN;
        }

        /* rc == NJT_ERROR */

        njt_log_error(NJT_LOG_ERR, ctx->log, 0,
                      "OCSP responder sent invalid response");

        return NJT_ERROR;
    }

    ctx->process = njt_ssl_ocsp_process_body;
    return ctx->process(ctx);
}


static njt_int_t
njt_ssl_ocsp_parse_header_line(njt_ssl_ocsp_ctx_t *ctx)
{
    u_char  c, ch, *p;
    enum {
        sw_start = 0,
        sw_name,
        sw_space_before_value,
        sw_value,
        sw_space_after_value,
        sw_almost_done,
        sw_header_almost_done
    } state;

    state = ctx->state;

    for (p = ctx->response->pos; p < ctx->response->last; p++) {
        ch = *p;

#if 0
        njt_log_debug3(NJT_LOG_DEBUG_EVENT, ctx->log, 0,
                       "s:%d in:'%02Xd:%c'", state, ch, ch);
#endif

        switch (state) {

        /* first char */
        case sw_start:

            switch (ch) {
            case CR:
                ctx->header_end = p;
                state = sw_header_almost_done;
                break;
            case LF:
                ctx->header_end = p;
                goto header_done;
            default:
                state = sw_name;
                ctx->header_name_start = p;

                c = (u_char) (ch | 0x20);
                if (c >= 'a' && c <= 'z') {
                    break;
                }

                if (ch >= '0' && ch <= '9') {
                    break;
                }

                return NJT_ERROR;
            }
            break;

        /* header name */
        case sw_name:
            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                break;
            }

            if (ch == ':') {
                ctx->header_name_end = p;
                state = sw_space_before_value;
                break;
            }

            if (ch == '-') {
                break;
            }

            if (ch >= '0' && ch <= '9') {
                break;
            }

            if (ch == CR) {
                ctx->header_name_end = p;
                ctx->header_start = p;
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            }

            if (ch == LF) {
                ctx->header_name_end = p;
                ctx->header_start = p;
                ctx->header_end = p;
                goto done;
            }

            return NJT_ERROR;

        /* space* before header value */
        case sw_space_before_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                ctx->header_start = p;
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                ctx->header_start = p;
                ctx->header_end = p;
                goto done;
            default:
                ctx->header_start = p;
                state = sw_value;
                break;
            }
            break;

        /* header value */
        case sw_value:
            switch (ch) {
            case ' ':
                ctx->header_end = p;
                state = sw_space_after_value;
                break;
            case CR:
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                ctx->header_end = p;
                goto done;
            }
            break;

        /* space* before end of header line */
        case sw_space_after_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            default:
                state = sw_value;
                break;
            }
            break;

        /* end of header line */
        case sw_almost_done:
            switch (ch) {
            case LF:
                goto done;
            default:
                return NJT_ERROR;
            }

        /* end of header */
        case sw_header_almost_done:
            switch (ch) {
            case LF:
                goto header_done;
            default:
                return NJT_ERROR;
            }
        }
    }

    ctx->response->pos = p;
    ctx->state = state;

    return NJT_AGAIN;

done:

    ctx->response->pos = p + 1;
    ctx->state = sw_start;

    return NJT_OK;

header_done:

    ctx->response->pos = p + 1;
    ctx->state = sw_start;

    return NJT_DONE;
}


static njt_int_t
njt_ssl_ocsp_process_body(njt_ssl_ocsp_ctx_t *ctx)
{
    njt_log_debug0(NJT_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp process body");

    if (ctx->done) {
        ctx->handler(ctx);
        return NJT_DONE;
    }

    return NJT_AGAIN;
}


static njt_int_t
njt_ssl_ocsp_verify(njt_ssl_ocsp_ctx_t *ctx)
{
    int                    n;
    size_t                 len;
    X509_STORE            *store;
    const u_char          *p;
    OCSP_CERTID           *id;
    OCSP_RESPONSE         *ocsp;
    OCSP_BASICRESP        *basic;
    ASN1_GENERALIZEDTIME  *thisupdate, *nextupdate;

    ocsp = NULL;
    basic = NULL;
    id = NULL;

    if (ctx->code != 200) {
        goto error;
    }

    /* check the response */

    len = ctx->response->last - ctx->response->pos;
    p = ctx->response->pos;

    ocsp = d2i_OCSP_RESPONSE(NULL, &p, len);
    if (ocsp == NULL) {
        njt_ssl_error(NJT_LOG_ERR, ctx->log, 0,
                      "d2i_OCSP_RESPONSE() failed");
        goto error;
    }

    n = OCSP_response_status(ocsp);

    if (n != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        njt_log_error(NJT_LOG_ERR, ctx->log, 0,
                      "OCSP response not successful (%d: %s)",
                      n, OCSP_response_status_str(n));
        goto error;
    }

    basic = OCSP_response_get1_basic(ocsp);
    if (basic == NULL) {
        njt_ssl_error(NJT_LOG_ERR, ctx->log, 0,
                      "OCSP_response_get1_basic() failed");
        goto error;
    }

    store = SSL_CTX_get_cert_store(ctx->ssl_ctx);
    if (store == NULL) {
        njt_ssl_error(NJT_LOG_CRIT, ctx->log, 0,
                      "SSL_CTX_get_cert_store() failed");
        goto error;
    }

    if (OCSP_basic_verify(basic, ctx->chain, store, ctx->flags) != 1) {
        njt_ssl_error(NJT_LOG_ERR, ctx->log, 0,
                      "OCSP_basic_verify() failed");
        goto error;
    }

    id = OCSP_cert_to_id(NULL, ctx->cert, ctx->issuer);
    if (id == NULL) {
        njt_ssl_error(NJT_LOG_CRIT, ctx->log, 0,
                      "OCSP_cert_to_id() failed");
        goto error;
    }

    if (OCSP_resp_find_status(basic, id, &ctx->status, NULL, NULL,
                              &thisupdate, &nextupdate)
        != 1)
    {
        njt_log_error(NJT_LOG_ERR, ctx->log, 0,
                      "certificate status not found in the OCSP response");
        goto error;
    }

    if (OCSP_check_validity(thisupdate, nextupdate, 300, -1) != 1) {
        njt_ssl_error(NJT_LOG_ERR, ctx->log, 0,
                      "OCSP_check_validity() failed");
        goto error;
    }

    if (nextupdate) {
        ctx->valid = njt_ssl_stapling_time(nextupdate);
        if (ctx->valid == (time_t) NJT_ERROR) {
            njt_log_error(NJT_LOG_ERR, ctx->log, 0,
                          "invalid nextUpdate time in certificate status");
            goto error;
        }

    } else {
        ctx->valid = NJT_MAX_TIME_T_VALUE;
    }

    OCSP_CERTID_free(id);
    OCSP_BASICRESP_free(basic);
    OCSP_RESPONSE_free(ocsp);

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp response, %s, %uz",
                   OCSP_cert_status_str(ctx->status), len);

    return NJT_OK;

error:

    if (id) {
        OCSP_CERTID_free(id);
    }

    if (basic) {
        OCSP_BASICRESP_free(basic);
    }

    if (ocsp) {
        OCSP_RESPONSE_free(ocsp);
    }

    return NJT_ERROR;
}


njt_int_t
njt_ssl_ocsp_cache_init(njt_shm_zone_t *shm_zone, void *data)
{
    size_t                 len;
    njt_slab_pool_t       *shpool;
    njt_ssl_ocsp_cache_t  *cache;

    if (data) {
        shm_zone->data = data;
        return NJT_OK;
    }

    shpool = (njt_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        shm_zone->data = shpool->data;
        return NJT_OK;
    }

    cache = njt_slab_alloc(shpool, sizeof(njt_ssl_ocsp_cache_t));
    if (cache == NULL) {
        return NJT_ERROR;
    }

    shpool->data = cache;
    shm_zone->data = cache;

    njt_rbtree_init(&cache->rbtree, &cache->sentinel,
                    njt_str_rbtree_insert_value);

    njt_queue_init(&cache->expire_queue);

    len = sizeof(" in OCSP cache \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = njt_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NJT_ERROR;
    }

    njt_sprintf(shpool->log_ctx, " in OCSP cache \"%V\"%Z",
                &shm_zone->shm.name);

    shpool->log_nomem = 0;

    return NJT_OK;
}


static njt_int_t
njt_ssl_ocsp_cache_lookup(njt_ssl_ocsp_ctx_t *ctx)
{
    uint32_t                    hash;
    njt_shm_zone_t             *shm_zone;
    njt_slab_pool_t            *shpool;
    njt_ssl_ocsp_cache_t       *cache;
    njt_ssl_ocsp_cache_node_t  *node;

    shm_zone = ctx->shm_zone;

    if (shm_zone == NULL) {
        return NJT_DECLINED;
    }

    if (njt_ssl_ocsp_create_key(ctx) != NJT_OK) {
        return NJT_ERROR;
    }

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, ctx->log, 0, "ssl ocsp cache lookup");

    cache = shm_zone->data;
    shpool = (njt_slab_pool_t *) shm_zone->shm.addr;
    hash = njt_hash_key(ctx->key.data, ctx->key.len);

    njt_shmtx_lock(&shpool->mutex);

    node = (njt_ssl_ocsp_cache_node_t *)
               njt_str_rbtree_lookup(&cache->rbtree, &ctx->key, hash);

    if (node) {
        if (node->valid > njt_time()) {
            ctx->status = node->status;
            njt_shmtx_unlock(&shpool->mutex);

            njt_log_debug1(NJT_LOG_DEBUG_EVENT, ctx->log, 0,
                           "ssl ocsp cache hit, %s",
                           OCSP_cert_status_str(ctx->status));

            return NJT_OK;
        }

        njt_queue_remove(&node->queue);
        njt_rbtree_delete(&cache->rbtree, &node->node.node);
        njt_slab_free_locked(shpool, node);

        njt_shmtx_unlock(&shpool->mutex);

        njt_log_debug0(NJT_LOG_DEBUG_EVENT, ctx->log, 0,
                       "ssl ocsp cache expired");

        return NJT_DECLINED;
    }

    njt_shmtx_unlock(&shpool->mutex);

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, ctx->log, 0, "ssl ocsp cache miss");

    return NJT_DECLINED;
}


static njt_int_t
njt_ssl_ocsp_cache_store(njt_ssl_ocsp_ctx_t *ctx)
{
    time_t                      now, valid;
    uint32_t                    hash;
    njt_queue_t                *q;
    njt_shm_zone_t             *shm_zone;
    njt_slab_pool_t            *shpool;
    njt_ssl_ocsp_cache_t       *cache;
    njt_ssl_ocsp_cache_node_t  *node;

    shm_zone = ctx->shm_zone;

    if (shm_zone == NULL) {
        return NJT_OK;
    }

    valid = ctx->valid;

    now = njt_time();

    if (valid < now) {
        return NJT_OK;
    }

    if (valid == NJT_MAX_TIME_T_VALUE) {
        valid = now + 3600;
    }

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp cache store, valid:%T", valid - now);

    cache = shm_zone->data;
    shpool = (njt_slab_pool_t *) shm_zone->shm.addr;
    hash = njt_hash_key(ctx->key.data, ctx->key.len);

    njt_shmtx_lock(&shpool->mutex);

    node = njt_slab_calloc_locked(shpool,
                             sizeof(njt_ssl_ocsp_cache_node_t) + ctx->key.len);
    if (node == NULL) {

        if (!njt_queue_empty(&cache->expire_queue)) {
            q = njt_queue_last(&cache->expire_queue);
            node = njt_queue_data(q, njt_ssl_ocsp_cache_node_t, queue);

            njt_rbtree_delete(&cache->rbtree, &node->node.node);
            njt_queue_remove(q);
            njt_slab_free_locked(shpool, node);

            node = njt_slab_alloc_locked(shpool,
                             sizeof(njt_ssl_ocsp_cache_node_t) + ctx->key.len);
        }

        if (node == NULL) {
            njt_shmtx_unlock(&shpool->mutex);
            njt_log_error(NJT_LOG_ALERT, ctx->log, 0,
                          "could not allocate new entry%s", shpool->log_ctx);
            return NJT_ERROR;
        }
    }

    node->node.str.len = ctx->key.len;
    node->node.str.data = (u_char *) node + sizeof(njt_ssl_ocsp_cache_node_t);
    njt_memcpy(node->node.str.data, ctx->key.data, ctx->key.len);
    node->node.node.key = hash;
    node->status = ctx->status;
    node->valid = valid;

    njt_rbtree_insert(&cache->rbtree, &node->node.node);
    njt_queue_insert_head(&cache->expire_queue, &node->queue);

    njt_shmtx_unlock(&shpool->mutex);

    return NJT_OK;
}


static njt_int_t
njt_ssl_ocsp_create_key(njt_ssl_ocsp_ctx_t *ctx)
{
    u_char        *p;
    X509_NAME     *name;
    ASN1_INTEGER  *serial;

    p = njt_pnalloc(ctx->pool, 60);
    if (p == NULL) {
        return NJT_ERROR;
    }

    ctx->key.data = p;
    ctx->key.len = 60;

    name = X509_get_subject_name(ctx->issuer);
    if (X509_NAME_digest(name, EVP_sha1(), p, NULL) == 0) {
        return NJT_ERROR;
    }

    p += 20;

    if (X509_pubkey_digest(ctx->issuer, EVP_sha1(), p, NULL) == 0) {
        return NJT_ERROR;
    }

    p += 20;

    serial = X509_get_serialNumber(ctx->cert);
    if (serial->length > 20) {
        return NJT_ERROR;
    }

    p = njt_cpymem(p, serial->data, serial->length);
    njt_memzero(p, 20 - serial->length);

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, ctx->log, 0,
                   "ssl ocsp key %xV", &ctx->key);

    return NJT_OK;
}


static u_char *
njt_ssl_ocsp_log_error(njt_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;
    njt_ssl_ocsp_ctx_t  *ctx;

    p = buf;

    if (log->action) {
        p = njt_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    ctx = log->data;

    if (ctx) {
        p = njt_snprintf(buf, len, ", responder: %V", &ctx->host);
        len -= p - buf;
        buf = p;
    }

    if (ctx && ctx->peer.name) {
        p = njt_snprintf(buf, len, ", peer: %V", ctx->peer.name);
        len -= p - buf;
        buf = p;
    }

    if (ctx && ctx->name) {
        p = njt_snprintf(buf, len, ", certificate: \"%s\"", ctx->name);
        len -= p - buf;
        buf = p;
    }

    return p;
}


#else


njt_int_t
njt_ssl_stapling(njt_conf_t *cf, njt_ssl_t *ssl, njt_str_t *file,
    njt_str_t *responder, njt_uint_t verify)
{
    njt_log_error(NJT_LOG_WARN, ssl->log, 0,
                  "\"ssl_stapling\" ignored, not supported");

    return NJT_OK;
}


njt_int_t
njt_ssl_stapling_resolver(njt_conf_t *cf, njt_ssl_t *ssl,
    njt_resolver_t *resolver, njt_msec_t resolver_timeout)
{
    return NJT_OK;
}


njt_int_t
njt_ssl_ocsp(njt_conf_t *cf, njt_ssl_t *ssl, njt_str_t *responder,
    njt_uint_t depth, njt_shm_zone_t *shm_zone)
{
    njt_log_error(NJT_LOG_EMERG, ssl->log, 0,
                  "\"ssl_ocsp\" is not supported on this platform");

    return NJT_ERROR;
}


njt_int_t
njt_ssl_ocsp_resolver(njt_conf_t *cf, njt_ssl_t *ssl,
    njt_resolver_t *resolver, njt_msec_t resolver_timeout)
{
    return NJT_OK;
}


njt_int_t
njt_ssl_ocsp_validate(njt_connection_t *c)
{
    return NJT_OK;
}


njt_int_t
njt_ssl_ocsp_get_status(njt_connection_t *c, const char **s)
{
    return NJT_OK;
}


void
njt_ssl_ocsp_cleanup(njt_connection_t *c)
{
}


njt_int_t
njt_ssl_ocsp_cache_init(njt_shm_zone_t *shm_zone, void *data)
{
    return NJT_OK;
}


#endif
