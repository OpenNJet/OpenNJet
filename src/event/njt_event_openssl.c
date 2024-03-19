
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>

#define NJT_SSL_PASSWORD_BUFFER_SIZE  4096

typedef struct {
    njt_uint_t  engine;   /* unsigned  engine:1; */
} njt_openssl_conf_t;


static X509 *njt_ssl_load_certificate(njt_pool_t *pool, char **err,
    njt_str_t *cert, STACK_OF(X509) **chain);
static EVP_PKEY *njt_ssl_load_certificate_key(njt_pool_t *pool, char **err,
    njt_str_t *key, njt_array_t *passwords);
static int njt_ssl_password_callback(char *buf, int size, int rwflag,
    void *userdata);
static int njt_ssl_verify_callback(int ok, X509_STORE_CTX *x509_store);
static void njt_ssl_info_callback(const njt_ssl_conn_t *ssl_conn, int where,
    int ret);
static void njt_ssl_passwords_cleanup(void *data);
static int njt_ssl_new_client_session(njt_ssl_conn_t *ssl_conn,
    njt_ssl_session_t *sess);
#ifdef SSL_READ_EARLY_DATA_SUCCESS
static njt_int_t njt_ssl_try_early_data(njt_connection_t *c);
#endif
static void njt_ssl_handshake_handler(njt_event_t *ev);
#ifdef SSL_READ_EARLY_DATA_SUCCESS
static ssize_t njt_ssl_recv_early(njt_connection_t *c, u_char *buf,
    size_t size);
#endif
static njt_int_t njt_ssl_handle_recv(njt_connection_t *c, int n);
static void njt_ssl_write_handler(njt_event_t *wev);
#ifdef SSL_READ_EARLY_DATA_SUCCESS
static ssize_t njt_ssl_write_early(njt_connection_t *c, u_char *data,
    size_t size);
#endif
static ssize_t njt_ssl_sendfile(njt_connection_t *c, njt_buf_t *file,
    size_t size);
static void njt_ssl_read_handler(njt_event_t *rev);
static void njt_ssl_shutdown_handler(njt_event_t *ev);
static void njt_ssl_connection_error(njt_connection_t *c, int sslerr,
    njt_err_t err, char *text);
static void njt_ssl_clear_error(njt_log_t *log);

static njt_int_t njt_ssl_session_id_context(njt_ssl_t *ssl,
    njt_str_t *sess_ctx, njt_array_t *certificates);
static int njt_ssl_new_session(njt_ssl_conn_t *ssl_conn,
    njt_ssl_session_t *sess);
static njt_ssl_session_t *njt_ssl_get_cached_session(njt_ssl_conn_t *ssl_conn,
#if OPENSSL_VERSION_NUMBER >= 0x10100003L
    const
#endif
    u_char *id, int len, int *copy);
static void njt_ssl_remove_session(SSL_CTX *ssl, njt_ssl_session_t *sess);
static void njt_ssl_expire_sessions(njt_ssl_session_cache_t *cache,
    njt_slab_pool_t *shpool, njt_uint_t n);
static void njt_ssl_session_rbtree_insert_value(njt_rbtree_node_t *temp,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel);

#ifdef SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB
static int njt_ssl_ticket_key_callback(njt_ssl_conn_t *ssl_conn,
    unsigned char *name, unsigned char *iv, EVP_CIPHER_CTX *ectx,
    HMAC_CTX *hctx, int enc);
static njt_int_t njt_ssl_rotate_ticket_keys(SSL_CTX *ssl_ctx, njt_log_t *log);
static void njt_ssl_ticket_keys_cleanup(void *data);
#endif
#if X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT == 0
static njt_int_t njt_ssl_check_name(njt_str_t *name, ASN1_STRING *str);
#endif
static time_t njt_ssl_parse_time(
#if OPENSSL_VERSION_NUMBER > 0x10100000L
    const
#endif
    ASN1_TIME *asn1time, njt_log_t *log);

static void *njt_openssl_create_conf(njt_cycle_t *cycle);
static char *njt_openssl_engine(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static void njt_openssl_exit(njt_cycle_t *cycle);
#if X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT  == 0
static unsigned char *njt_string_data(ASN1_STRING *x)
{
    return x->data;
}
#endif
static njt_command_t  njt_openssl_commands[] = {

    { njt_string("ssl_engine"),
      NJT_MAIN_CONF|NJT_DIRECT_CONF|NJT_CONF_TAKE1,
      njt_openssl_engine,
      0,
      0,
      NULL },

      njt_null_command
};


static njt_core_module_t  njt_openssl_module_ctx = {
    njt_string("openssl"),
    njt_openssl_create_conf,
    NULL
};


njt_module_t  njt_openssl_module = {
    NJT_MODULE_V1,
    &njt_openssl_module_ctx,               /* module context */
    njt_openssl_commands,                  /* module directives */
    NJT_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    njt_openssl_exit,                      /* exit master */
    NJT_MODULE_V1_PADDING
};


int  njt_ssl_connection_index;
int  njt_ssl_server_conf_index;
int  njt_ssl_session_cache_index;
int  njt_ssl_ticket_keys_index;
int  njt_ssl_ocsp_index;
int  njt_ssl_certificate_index;
int  njt_ssl_next_certificate_index;
int  njt_ssl_certificate_name_index;
int  njt_ssl_stapling_index;


njt_int_t
njt_ssl_init(njt_log_t *log)
{
#if (OPENSSL_INIT_LOAD_CONFIG && !defined LIBRESSL_VERSION_NUMBER)

    OPENSSL_INIT_SETTINGS  *init;

    init = OPENSSL_INIT_new();
    if (init == NULL) {
        njt_ssl_error(NJT_LOG_ALERT, log, 0, "OPENSSL_INIT_new() failed");
        return NJT_ERROR;
    }

#ifndef OPENSSL_NO_STDIO
    if (OPENSSL_INIT_set_config_appname(init, "njet") == 0) {
        njt_ssl_error(NJT_LOG_ALERT, log, 0,
                      "OPENSSL_INIT_set_config_appname() failed");
        return NJT_ERROR;
    }
#endif

    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, init) == 0) {
        njt_ssl_error(NJT_LOG_ALERT, log, 0, "OPENSSL_init_ssl() failed");
        return NJT_ERROR;
    }

    OPENSSL_INIT_free(init);

    /*
     * OPENSSL_init_ssl() may leave errors in the error queue
     * while returning success
     */

    ERR_clear_error();

#else

    OPENSSL_config("njet");

    SSL_library_init();
    SSL_load_error_strings();

    OpenSSL_add_all_algorithms();

#endif

#ifndef SSL_OP_NO_COMPRESSION
    {
    /*
     * Disable gzip compression in OpenSSL prior to 1.0.0 version,
     * this saves about 522K per connection.
     */
    int                  n;
    STACK_OF(SSL_COMP)  *ssl_comp_methods;

    ssl_comp_methods = SSL_COMP_get_compression_methods();
    n = sk_SSL_COMP_num(ssl_comp_methods);

    while (n--) {
        (void) sk_SSL_COMP_pop(ssl_comp_methods);
    }
    }
#endif

    njt_ssl_connection_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);

    if (njt_ssl_connection_index == -1) {
        njt_ssl_error(NJT_LOG_ALERT, log, 0, "SSL_get_ex_new_index() failed");
        return NJT_ERROR;
    }

    njt_ssl_server_conf_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL,
                                                         NULL);
    if (njt_ssl_server_conf_index == -1) {
        njt_ssl_error(NJT_LOG_ALERT, log, 0,
                      "SSL_CTX_get_ex_new_index() failed");
        return NJT_ERROR;
    }

    njt_ssl_session_cache_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL,
                                                           NULL);
    if (njt_ssl_session_cache_index == -1) {
        njt_ssl_error(NJT_LOG_ALERT, log, 0,
                      "SSL_CTX_get_ex_new_index() failed");
        return NJT_ERROR;
    }

    njt_ssl_ticket_keys_index = SSL_CTX_get_ex_new_index(0, NULL, NULL,NULL,
                                                         NULL);
    if (njt_ssl_ticket_keys_index == -1) {
        njt_ssl_error(NJT_LOG_ALERT, log, 0,
                      "SSL_CTX_get_ex_new_index() failed");
        return NJT_ERROR;
    }

    njt_ssl_ocsp_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    if (njt_ssl_ocsp_index == -1) {
        njt_ssl_error(NJT_LOG_ALERT, log, 0,
                      "SSL_CTX_get_ex_new_index() failed");
        return NJT_ERROR;
    }

    njt_ssl_certificate_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL,
                                                         NULL);
    if (njt_ssl_certificate_index == -1) {
        njt_ssl_error(NJT_LOG_ALERT, log, 0,
                      "SSL_CTX_get_ex_new_index() failed");
        return NJT_ERROR;
    }

    njt_ssl_next_certificate_index = X509_get_ex_new_index(0, NULL, NULL, NULL,
                                                           NULL);
    if (njt_ssl_next_certificate_index == -1) {
        njt_ssl_error(NJT_LOG_ALERT, log, 0, "X509_get_ex_new_index() failed");
        return NJT_ERROR;
    }

    njt_ssl_certificate_name_index = X509_get_ex_new_index(0, NULL, NULL, NULL,
                                                           NULL);

    if (njt_ssl_certificate_name_index == -1) {
        njt_ssl_error(NJT_LOG_ALERT, log, 0, "X509_get_ex_new_index() failed");
        return NJT_ERROR;
    }

    njt_ssl_stapling_index = X509_get_ex_new_index(0, NULL, NULL, NULL, NULL);

    if (njt_ssl_stapling_index == -1) {
        njt_ssl_error(NJT_LOG_ALERT, log, 0, "X509_get_ex_new_index() failed");
        return NJT_ERROR;
    }

    return NJT_OK;
}


static njt_int_t
njt_ssl_create_proc(njt_ssl_t *ssl, njt_uint_t protocols, void *data)
{
    if (SSL_CTX_set_ex_data(ssl->ctx, njt_ssl_server_conf_index, data) == 0) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set_ex_data() failed");
        return NJT_ERROR;
    }

    if (SSL_CTX_set_ex_data(ssl->ctx, njt_ssl_certificate_index, NULL) == 0) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set_ex_data() failed");
        return NJT_ERROR;
    }

    ssl->buffer_size = NJT_SSL_BUFSIZE;

    /* client side options */

#ifdef SSL_OP_MICROSOFT_SESS_ID_BUG
    SSL_CTX_set_options(ssl->ctx, SSL_OP_MICROSOFT_SESS_ID_BUG);
#endif

#ifdef SSL_OP_NETSCAPE_CHALLENGE_BUG
    SSL_CTX_set_options(ssl->ctx, SSL_OP_NETSCAPE_CHALLENGE_BUG);
#endif

    /* server side options */

#ifdef SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
    SSL_CTX_set_options(ssl->ctx, SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG);
#endif

#ifdef SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER
    SSL_CTX_set_options(ssl->ctx, SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER);
#endif

#ifdef SSL_OP_SSLEAY_080_CLIENT_DH_BUG
    SSL_CTX_set_options(ssl->ctx, SSL_OP_SSLEAY_080_CLIENT_DH_BUG);
#endif

#ifdef SSL_OP_TLS_D5_BUG
    SSL_CTX_set_options(ssl->ctx, SSL_OP_TLS_D5_BUG);
#endif

#ifdef SSL_OP_TLS_BLOCK_PADDING_BUG
    SSL_CTX_set_options(ssl->ctx, SSL_OP_TLS_BLOCK_PADDING_BUG);
#endif

#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
    SSL_CTX_set_options(ssl->ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
#endif

    SSL_CTX_set_options(ssl->ctx, SSL_OP_SINGLE_DH_USE);

#if OPENSSL_VERSION_NUMBER >= 0x009080dfL
    /* only in 0.9.8m+ */
    SSL_CTX_clear_options(ssl->ctx,
                          SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1);
#endif

    if (!(protocols & NJT_SSL_SSLv2)) {
        SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_SSLv2);
    }
    if (!(protocols & NJT_SSL_SSLv3)) {
        SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_SSLv3);
    }
    if (!(protocols & NJT_SSL_TLSv1)) {
        SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_TLSv1);
    }
#ifdef SSL_OP_NO_TLSv1_1
    SSL_CTX_clear_options(ssl->ctx, SSL_OP_NO_TLSv1_1);
    if (!(protocols & NJT_SSL_TLSv1_1)) {
        SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_TLSv1_1);
    }
#endif
#ifdef SSL_OP_NO_TLSv1_2
    SSL_CTX_clear_options(ssl->ctx, SSL_OP_NO_TLSv1_2);
    if (!(protocols & NJT_SSL_TLSv1_2)) {
        SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_TLSv1_2);
    }
#endif
#ifdef SSL_OP_NO_TLSv1_3
    SSL_CTX_clear_options(ssl->ctx, SSL_OP_NO_TLSv1_3);
    if (!(protocols & NJT_SSL_TLSv1_3)) {
        SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_TLSv1_3);
    }
#endif

#ifdef SSL_CTX_set_min_proto_version
    SSL_CTX_set_min_proto_version(ssl->ctx, 0);
    SSL_CTX_set_max_proto_version(ssl->ctx, TLS1_2_VERSION);
#endif

#ifdef TLS1_3_VERSION
    SSL_CTX_set_min_proto_version(ssl->ctx, 0);
    SSL_CTX_set_max_proto_version(ssl->ctx, TLS1_3_VERSION);
#endif

#ifdef SSL_OP_NO_COMPRESSION
    SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_COMPRESSION);
#endif

#ifdef SSL_OP_NO_ANTI_REPLAY
    SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_ANTI_REPLAY);
#endif

#ifdef SSL_OP_NO_CLIENT_RENEGOTIATION
    SSL_CTX_set_options(ssl->ctx, SSL_OP_NO_CLIENT_RENEGOTIATION);
#endif

#ifdef SSL_OP_IGNORE_UNEXPECTED_EOF
    SSL_CTX_set_options(ssl->ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);
#endif

#ifdef SSL_MODE_RELEASE_BUFFERS
    SSL_CTX_set_mode(ssl->ctx, SSL_MODE_RELEASE_BUFFERS);
#endif

#ifdef SSL_MODE_NO_AUTO_CHAIN
    SSL_CTX_set_mode(ssl->ctx, SSL_MODE_NO_AUTO_CHAIN);
#endif

    SSL_CTX_set_read_ahead(ssl->ctx, 1);

    SSL_CTX_set_info_callback(ssl->ctx, njt_ssl_info_callback);

    return NJT_OK;
}


njt_int_t
njt_ssl_create(njt_ssl_t *ssl, njt_uint_t protocols, void *data)
{
    ssl->ctx = SSL_CTX_new(SSLv23_method());

    if (ssl->ctx == NULL) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0, "SSL_CTX_new() failed");
        return NJT_ERROR;
    }

    return njt_ssl_create_proc(ssl, protocols, data);
}


njt_int_t
njt_ssl_certificates(njt_conf_t *cf, njt_ssl_t *ssl, njt_array_t *certs,
    njt_array_t *keys, njt_array_t *passwords)
{
    njt_str_t   *cert, *key;
    njt_uint_t   i;

    cert = certs->elts;
    key = keys->elts;

    for (i = 0; i < certs->nelts; i++) {

        if (njt_ssl_certificate(cf, ssl, &cert[i], &key[i], passwords)
            != NJT_OK)
        {
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


//add by clb
njt_int_t
njt_ssl_set_certificates_type(njt_conf_t *cf, njt_ssl_t *ssl, njt_array_t *certs,
    njt_array_t *keys, njt_array_t *cert_types)
{
    njt_str_t   *cert, *key;
    njt_uint_t   i;
    njt_uint_t   cert_type, *cert_type_item;

    cert = certs->elts;
    key = keys->elts;

    for (i = 0; i < certs->nelts; i++) {
        if (njt_ssl_get_certificate_type(cf, ssl, &cert[i], &key[i], &cert_type)
            != NJT_OK)
        {
            return NJT_ERROR;
        }

        cert_type_item = njt_array_push(cert_types);
        if(cert_type_item != NULL){
            *cert_type_item = cert_type;
        }
    }

    return NJT_OK;
}

//add by clb
njt_int_t
njt_ssl_get_certificate_type(njt_conf_t *cf, njt_ssl_t *ssl, njt_str_t *cert,
    njt_str_t *key, njt_uint_t *cert_type)
{
    char            *err;
    X509            *x509;
    EVP_PKEY        *pkey;
    STACK_OF(X509)  *chain;
    size_t          pidx;
#if (NJT_HAVE_NTLS)
    njt_uint_t       type;
#endif

    *cert_type = 3;      //other type
    x509 = njt_ssl_load_certificate(cf->pool, &err, cert, &chain);
    if (x509 == NULL) {
        if (err != NULL) {
            njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                          "cannot load certificate \"%s\": %s",
                          cert->data, err);
        }

        return NJT_ERROR;
    }

#if (NJT_HAVE_NTLS)
    type = njt_ssl_ntls_type(cert);

    if (type == NJT_SSL_NTLS_CERT_SIGN || type == NJT_SSL_NTLS_CERT_ENC) {
        //ntls type
        *cert_type = 1;
        return NJT_OK;
    }

#endif
    pkey = X509_get0_pubkey(x509);
    if (SSL_CTX_get_certificate_type(pkey, &pidx) == NULL) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0, "unknown certificate type");
        X509_free(x509);
        sk_X509_pop_free(chain, X509_free);
        return NJT_ERROR;
    }

    //# define SSL_PKEY_RSA            0
    //# define SSL_PKEY_ECC            3
    if(pidx == 0){
        *cert_type = 0;       //RSA type
    }else if(pidx == 3){
        *cert_type = 2;       //ECC type
    }

    X509_free(x509);
    sk_X509_pop_free(chain, X509_free);

    return NJT_OK;
}


njt_int_t
njt_ssl_certificate(njt_conf_t *cf, njt_ssl_t *ssl, njt_str_t *cert,
    njt_str_t *key, njt_array_t *passwords)
{
    char            *err;
    X509            *x509;
    EVP_PKEY        *pkey;
    STACK_OF(X509)  *chain;
#if (NJT_HAVE_NTLS)
    njt_uint_t       type;
#endif

    x509 = njt_ssl_load_certificate(cf->pool, &err, cert, &chain);
    if (x509 == NULL) {
        if (err != NULL) {
            njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                          "cannot load certificate \"%s\": %s",
                          cert->data, err);
        }

        return NJT_ERROR;
    }

#if (NJT_HAVE_NTLS)
    type = njt_ssl_ntls_type(cert);

    if (type == NJT_SSL_NTLS_CERT_SIGN) {

        if (SSL_CTX_use_sign_certificate(ssl->ctx, x509) == 0) {
            njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                          "SSL_CTX_use_sign_certificate(\"%s\") failed",
                          cert->data);
            X509_free(x509);
            sk_X509_pop_free(chain, X509_free);
            return NJT_ERROR;
        }

    } else if (type == NJT_SSL_NTLS_CERT_ENC) {

        if (SSL_CTX_use_enc_certificate(ssl->ctx, x509) == 0) {
            njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                          "SSL_CTX_use_enc_certificate(\"%s\") failed",
                          cert->data);
            X509_free(x509);
            sk_X509_pop_free(chain, X509_free);
            return NJT_ERROR;
        }

    } else

#endif

    if (SSL_CTX_use_certificate(ssl->ctx, x509) == 0) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_use_certificate(\"%s\") failed", cert->data);
        X509_free(x509);
        sk_X509_pop_free(chain, X509_free);
        return NJT_ERROR;
    }

    if (X509_set_ex_data(x509, njt_ssl_certificate_name_index, cert->data)
        == 0)
    {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0, "X509_set_ex_data() failed");
        X509_free(x509);
        sk_X509_pop_free(chain, X509_free);
        return NJT_ERROR;
    }

    if (X509_set_ex_data(x509, njt_ssl_next_certificate_index,
                      SSL_CTX_get_ex_data(ssl->ctx, njt_ssl_certificate_index))
        == 0)
    {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0, "X509_set_ex_data() failed");
        X509_free(x509);
        sk_X509_pop_free(chain, X509_free);
        return NJT_ERROR;
    }

    if (SSL_CTX_set_ex_data(ssl->ctx, njt_ssl_certificate_index, x509) == 0) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set_ex_data() failed");
        X509_free(x509);
        sk_X509_pop_free(chain, X509_free);
        return NJT_ERROR;
    }

    /*
     * Note that x509 is not freed here, but will be instead freed in
     * njt_ssl_cleanup_ctx().  This is because we need to preserve all
     * certificates to be able to iterate all of them through exdata
     * (njt_ssl_certificate_index, njt_ssl_next_certificate_index),
     * while OpenSSL can free a certificate if it is replaced with another
     * certificate of the same type.
     */

#ifdef SSL_CTX_set0_chain

    if (SSL_CTX_set0_chain(ssl->ctx, chain) == 0) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set0_chain(\"%s\") failed", cert->data);
        sk_X509_pop_free(chain, X509_free);
        return NJT_ERROR;
    }

#else
    {
    int  n;

    /* SSL_CTX_set0_chain() is only available in OpenSSL 1.0.2+ */

    n = sk_X509_num(chain);

    while (n--) {
        x509 = sk_X509_shift(chain);

        if (SSL_CTX_add_extra_chain_cert(ssl->ctx, x509) == 0) {
            njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                          "SSL_CTX_add_extra_chain_cert(\"%s\") failed",
                          cert->data);
            sk_X509_pop_free(chain, X509_free);
            return NJT_ERROR;
        }
    }

    sk_X509_free(chain);
    }
#endif

    pkey = njt_ssl_load_certificate_key(cf->pool, &err, key, passwords);
    if (pkey == NULL) {
        if (err != NULL) {
            njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                          "cannot load certificate key \"%s\": %s",
                          key->data, err);
        }

        return NJT_ERROR;
    }

#if (NJT_HAVE_NTLS)
    type = njt_ssl_ntls_type(key);

    if (type == NJT_SSL_NTLS_CERT_SIGN) {

        if (SSL_CTX_use_sign_PrivateKey(ssl->ctx, pkey) == 0) {
            njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                          "SSL_CTX_use_sign_PrivateKey(\"%s\") failed",
                          key->data);
            EVP_PKEY_free(pkey);
            return NJT_ERROR;
        }

    } else if (type == NJT_SSL_NTLS_CERT_ENC) {

        if (SSL_CTX_use_enc_PrivateKey(ssl->ctx, pkey) == 0) {
            njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                          "SSL_CTX_use_enc_PrivateKey(\"%s\") failed",
                          key->data);
            EVP_PKEY_free(pkey);
            return NJT_ERROR;
        }

    } else

#endif

    if (SSL_CTX_use_PrivateKey(ssl->ctx, pkey) == 0) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_use_PrivateKey(\"%s\") failed", key->data);
        EVP_PKEY_free(pkey);
        return NJT_ERROR;
    }

    EVP_PKEY_free(pkey);

    return NJT_OK;
}



#if (NJT_HAVE_NTLS)

njt_uint_t
njt_ssl_ntls_type(njt_str_t *s)
{
    if (njt_strncmp(s->data, "sign:", sizeof("sign:") - 1) == 0) {

        return NJT_SSL_NTLS_CERT_SIGN;

    } else if (njt_strncmp(s->data, "enc:", sizeof("enc:") - 1) == 0) {

        return NJT_SSL_NTLS_CERT_ENC;
    }

    return NJT_SSL_NTLS_CERT_REGULAR;
}


void
njt_ssl_ntls_prefix_strip(njt_str_t *s)
{
    if (njt_strncmp(s->data, "sign:", sizeof("sign:") - 1) == 0) {
        s->data += sizeof("sign:") - 1;
        s->len -= sizeof("sign:") - 1;

    } else if (njt_strncmp(s->data, "enc:", sizeof("enc:") - 1) == 0) {
        s->data += sizeof("enc:") - 1;
        s->len -= sizeof("enc:") - 1;
    }
}

#endif



njt_int_t
njt_ssl_connection_certificate(njt_connection_t *c, njt_pool_t *pool,
    njt_str_t *cert, njt_str_t *key, njt_array_t *passwords)
{
    char            *err;
    X509            *x509;
    EVP_PKEY        *pkey;
    STACK_OF(X509)  *chain;
#if (NJT_HAVE_NTLS)
    njt_uint_t       type;
#endif

    x509 = njt_ssl_load_certificate(pool, &err, cert, &chain);
    if (x509 == NULL) {
        if (err != NULL) {
            njt_ssl_error(NJT_LOG_ERR, c->log, 0,
                          "cannot load certificate \"%s\": %s",
                          cert->data, err);
        }

        return NJT_ERROR;
    }

#if (NJT_HAVE_NTLS)
    type = njt_ssl_ntls_type(cert);

    if (type == NJT_SSL_NTLS_CERT_SIGN) {

        if (SSL_use_sign_certificate(c->ssl->connection, x509) == 0) {
            njt_ssl_error(NJT_LOG_ERR, c->log, 0,
                          "SSL_use_sign_certificate(\"%s\") failed",
                          cert->data);
            X509_free(x509);
            sk_X509_pop_free(chain, X509_free);
            return NJT_ERROR;
        }

    } else if (type == NJT_SSL_NTLS_CERT_ENC) {

        if (SSL_use_enc_certificate(c->ssl->connection, x509) == 0) {
            njt_ssl_error(NJT_LOG_ERR, c->log, 0,
                          "SSL_use_enc_certificate(\"%s\") failed",
                          cert->data);
            X509_free(x509);
            sk_X509_pop_free(chain, X509_free);
            return NJT_ERROR;
        }

    } else

#endif

    if (SSL_use_certificate(c->ssl->connection, x509) == 0) {
        njt_ssl_error(NJT_LOG_ERR, c->log, 0,
                      "SSL_use_certificate(\"%s\") failed", cert->data);
        X509_free(x509);
        sk_X509_pop_free(chain, X509_free);
        return NJT_ERROR;
    }

    X509_free(x509);

#ifdef SSL_set0_chain

    /*
     * SSL_set0_chain() is only available in OpenSSL 1.0.2+,
     * but this function is only called via certificate callback,
     * which is only available in OpenSSL 1.0.2+ as well
     */

    if (SSL_set0_chain(c->ssl->connection, chain) == 0) {
        njt_ssl_error(NJT_LOG_ERR, c->log, 0,
                      "SSL_set0_chain(\"%s\") failed", cert->data);
        sk_X509_pop_free(chain, X509_free);
        return NJT_ERROR;
    }

#endif

    pkey = njt_ssl_load_certificate_key(pool, &err, key, passwords);
    if (pkey == NULL) {
        if (err != NULL) {
            njt_ssl_error(NJT_LOG_ERR, c->log, 0,
                          "cannot load certificate key \"%s\": %s",
                          key->data, err);
        }

        return NJT_ERROR;
    }

#if (NJT_HAVE_NTLS)
    type = njt_ssl_ntls_type(key);

    if (type == NJT_SSL_NTLS_CERT_SIGN) {

        if (SSL_use_sign_PrivateKey(c->ssl->connection, pkey) == 0) {
            njt_ssl_error(NJT_LOG_ERR, c->log, 0,
                          "SSL_use_sign_PrivateKey(\"%s\") failed", key->data);
            EVP_PKEY_free(pkey);
            return NJT_ERROR;
        }

    } else if (type == NJT_SSL_NTLS_CERT_ENC) {

        if (SSL_use_enc_PrivateKey(c->ssl->connection, pkey) == 0) {
            njt_ssl_error(NJT_LOG_ERR, c->log, 0,
                          "SSL_use_enc_PrivateKey(\"%s\") failed", key->data);
            EVP_PKEY_free(pkey);
            return NJT_ERROR;
        }

    } else

#endif

    if (SSL_use_PrivateKey(c->ssl->connection, pkey) == 0) {
        njt_ssl_error(NJT_LOG_ERR, c->log, 0,
                      "SSL_use_PrivateKey(\"%s\") failed", key->data);
        EVP_PKEY_free(pkey);
        return NJT_ERROR;
    }

    EVP_PKEY_free(pkey);

    return NJT_OK;
}


static X509 *
njt_ssl_load_certificate(njt_pool_t *pool, char **err, njt_str_t *cert,
    STACK_OF(X509) **chain)
{
    BIO     *bio;
    X509    *x509, *temp;
    u_long   n;

#if (NJT_HAVE_NTLS)
    njt_str_t  tcert;

    tcert = *cert;
    njt_ssl_ntls_prefix_strip(&tcert);
    cert = &tcert;
#endif

    if (njt_strncmp(cert->data, "data:", sizeof("data:") - 1) == 0) {

        bio = BIO_new_mem_buf(cert->data + sizeof("data:") - 1,
                              cert->len - (sizeof("data:") - 1));
        if (bio == NULL) {
            *err = "BIO_new_mem_buf() failed";
            return NULL;
        }

    } else {

        if (njt_get_full_name(pool, (njt_str_t *) &njt_cycle->conf_prefix, cert)
            != NJT_OK)
        {
            *err = NULL;
            return NULL;
        }

        bio = BIO_new_file((char *) cert->data, "r");
        if (bio == NULL) {
            *err = "BIO_new_file() failed";
            return NULL;
        }
    }

    /* certificate itself */

    x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
    if (x509 == NULL) {
        *err = "PEM_read_bio_X509_AUX() failed";
        BIO_free(bio);
        return NULL;
    }

    /* rest of the chain */

    *chain = sk_X509_new_null();
    if (*chain == NULL) {
        *err = "sk_X509_new_null() failed";
        BIO_free(bio);
        X509_free(x509);
        return NULL;
    }

    for ( ;; ) {

        temp = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (temp == NULL) {
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
            X509_free(x509);
            sk_X509_pop_free(*chain, X509_free);
            return NULL;
        }

        if (sk_X509_push(*chain, temp) == 0) {
            *err = "sk_X509_push() failed";
            BIO_free(bio);
            X509_free(x509);
            sk_X509_pop_free(*chain, X509_free);
            return NULL;
        }
    }

    BIO_free(bio);

    return x509;
}


static EVP_PKEY *
njt_ssl_load_certificate_key(njt_pool_t *pool, char **err,
    njt_str_t *key, njt_array_t *passwords)
{
    BIO              *bio;
    EVP_PKEY         *pkey;
    njt_str_t        *pwd;
    njt_uint_t        tries;
    pem_password_cb  *cb;

#if (NJT_HAVE_NTLS)
    njt_str_t  tkey;

    tkey = *key;
    njt_ssl_ntls_prefix_strip(&tkey);
    key = &tkey;
#endif

    if (njt_strncmp(key->data, "engine:", sizeof("engine:") - 1) == 0) {

#ifndef OPENSSL_NO_ENGINE

        u_char  *p, *last;
        ENGINE  *engine;

        p = key->data + sizeof("engine:") - 1;
        last = (u_char *) njt_strchr(p, ':');

        if (last == NULL) {
            *err = "invalid syntax";
            return NULL;
        }

        *last = '\0';

        engine = ENGINE_by_id((char *) p);

        if (engine == NULL) {
            *err = "ENGINE_by_id() failed";
            return NULL;
        }

        *last++ = ':';

        pkey = ENGINE_load_private_key(engine, (char *) last, 0, 0);

        if (pkey == NULL) {
            *err = "ENGINE_load_private_key() failed";
            ENGINE_free(engine);
            return NULL;
        }

        ENGINE_free(engine);

        return pkey;

#else

        *err = "loading \"engine:...\" certificate keys is not supported";
        return NULL;

#endif
    }

    if (njt_strncmp(key->data, "data:", sizeof("data:") - 1) == 0) {

        bio = BIO_new_mem_buf(key->data + sizeof("data:") - 1,
                              key->len - (sizeof("data:") - 1));
        if (bio == NULL) {
            *err = "BIO_new_mem_buf() failed";
            return NULL;
        }

    } else {

        if (njt_get_full_name(pool, (njt_str_t *) &njt_cycle->conf_prefix, key)
            != NJT_OK)
        {
            *err = NULL;
            return NULL;
        }

        bio = BIO_new_file((char *) key->data, "r");
        if (bio == NULL) {
            *err = "BIO_new_file() failed";
            return NULL;
        }
    }

    if (passwords) {
        tries = passwords->nelts;
        pwd = passwords->elts;
        cb = njt_ssl_password_callback;

    } else {
        tries = 1;
        pwd = NULL;
        cb = NULL;
    }

    for ( ;; ) {

        pkey = PEM_read_bio_PrivateKey(bio, NULL, cb, pwd);
        if (pkey != NULL) {
            break;
        }

        if (tries-- > 1) {
            ERR_clear_error();
            (void) BIO_reset(bio);
            pwd++;
            continue;
        }

        *err = "PEM_read_bio_PrivateKey() failed";
        BIO_free(bio);
        return NULL;
    }

    BIO_free(bio);

    return pkey;
}


static int
njt_ssl_password_callback(char *buf, int size, int rwflag, void *userdata)
{
    njt_str_t *pwd = userdata;

    if (rwflag) {
        njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
                      "njt_ssl_password_callback() is called for encryption");
        return 0;
    }

    if (pwd == NULL) {
        return 0;
    }

    if (pwd->len > (size_t) size) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                      "password is truncated to %d bytes", size);
    } else {
        size = pwd->len;
    }

    njt_memcpy(buf, pwd->data, size);

    return size;
}


njt_int_t
njt_ssl_ciphers(njt_conf_t *cf, njt_ssl_t *ssl, njt_str_t *ciphers,
    njt_uint_t prefer_server_ciphers)
{
    if (SSL_CTX_set_cipher_list(ssl->ctx, (char *) ciphers->data) == 0) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set_cipher_list(\"%V\") failed",
                      ciphers);
        return NJT_ERROR;
    }

    if (prefer_server_ciphers) {
        SSL_CTX_set_options(ssl->ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    }

    return NJT_OK;
}


njt_int_t
njt_ssl_client_certificate(njt_conf_t *cf, njt_ssl_t *ssl, njt_str_t *cert,
    njt_int_t depth)
{
    STACK_OF(X509_NAME)  *list;

    SSL_CTX_set_verify(ssl->ctx, SSL_VERIFY_PEER, njt_ssl_verify_callback);

    SSL_CTX_set_verify_depth(ssl->ctx, depth);

    if (cert->len == 0) {
        return NJT_OK;
    }

    if (njt_conf_full_name(cf->cycle, cert, 1) != NJT_OK) {
        return NJT_ERROR;
    }

    if (SSL_CTX_load_verify_locations(ssl->ctx, (char *) cert->data, NULL)
        == 0)
    {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_load_verify_locations(\"%s\") failed",
                      cert->data);
        return NJT_ERROR;
    }

    /*
     * SSL_CTX_load_verify_locations() may leave errors in the error queue
     * while returning success
     */

    ERR_clear_error();

    list = SSL_load_client_CA_file((char *) cert->data);

    if (list == NULL) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "SSL_load_client_CA_file(\"%s\") failed", cert->data);
        return NJT_ERROR;
    }

    SSL_CTX_set_client_CA_list(ssl->ctx, list);

    return NJT_OK;
}


njt_int_t
njt_ssl_trusted_certificate(njt_conf_t *cf, njt_ssl_t *ssl, njt_str_t *cert,
    njt_int_t depth)
{
    SSL_CTX_set_verify(ssl->ctx, SSL_CTX_get_verify_mode(ssl->ctx),
                       njt_ssl_verify_callback);

    SSL_CTX_set_verify_depth(ssl->ctx, depth);

    if (cert->len == 0) {
        return NJT_OK;
    }

    if (njt_conf_full_name(cf->cycle, cert, 1) != NJT_OK) {
        return NJT_ERROR;
    }

    if (SSL_CTX_load_verify_locations(ssl->ctx, (char *) cert->data, NULL)
        == 0)
    {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_load_verify_locations(\"%s\") failed",
                      cert->data);
        return NJT_ERROR;
    }

    /*
     * SSL_CTX_load_verify_locations() may leave errors in the error queue
     * while returning success
     */

    ERR_clear_error();

    return NJT_OK;
}


njt_int_t
njt_ssl_crl(njt_conf_t *cf, njt_ssl_t *ssl, njt_str_t *crl)
{
    X509_STORE   *store;
    X509_LOOKUP  *lookup;

    if (crl->len == 0) {
        return NJT_OK;
    }

    if (njt_conf_full_name(cf->cycle, crl, 1) != NJT_OK) {
        return NJT_ERROR;
    }

    store = SSL_CTX_get_cert_store(ssl->ctx);

    if (store == NULL) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_get_cert_store() failed");
        return NJT_ERROR;
    }

    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());

    if (lookup == NULL) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "X509_STORE_add_lookup() failed");
        return NJT_ERROR;
    }

    if (X509_LOOKUP_load_file(lookup, (char *) crl->data, X509_FILETYPE_PEM)
        == 0)
    {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "X509_LOOKUP_load_file(\"%s\") failed", crl->data);
        return NJT_ERROR;
    }

    X509_STORE_set_flags(store,
                         X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL);

    return NJT_OK;
}


static int
njt_ssl_verify_callback(int ok, X509_STORE_CTX *x509_store)
{
#if (NJT_DEBUG)
    char              *subject, *issuer;
    int                err, depth;
    X509              *cert;
    X509_NAME         *sname, *iname;
    njt_connection_t  *c;
    njt_ssl_conn_t    *ssl_conn;

    ssl_conn = X509_STORE_CTX_get_ex_data(x509_store,
                                          SSL_get_ex_data_X509_STORE_CTX_idx());

    c = njt_ssl_get_connection(ssl_conn);

    if (!(c->log->log_level & NJT_LOG_DEBUG_EVENT)) {
        return 1;
    }

    cert = X509_STORE_CTX_get_current_cert(x509_store);
    err = X509_STORE_CTX_get_error(x509_store);
    depth = X509_STORE_CTX_get_error_depth(x509_store);

    sname = X509_get_subject_name(cert);

    if (sname) {
        subject = X509_NAME_oneline(sname, NULL, 0);
        if (subject == NULL) {
            njt_ssl_error(NJT_LOG_ALERT, c->log, 0,
                          "X509_NAME_oneline() failed");
        }

    } else {
        subject = NULL;
    }

    iname = X509_get_issuer_name(cert);

    if (iname) {
        issuer = X509_NAME_oneline(iname, NULL, 0);
        if (issuer == NULL) {
            njt_ssl_error(NJT_LOG_ALERT, c->log, 0,
                          "X509_NAME_oneline() failed");
        }

    } else {
        issuer = NULL;
    }

    njt_log_debug5(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "verify:%d, error:%d, depth:%d, "
                   "subject:\"%s\", issuer:\"%s\"",
                   ok, err, depth,
                   subject ? subject : "(none)",
                   issuer ? issuer : "(none)");

    if (subject) {
        OPENSSL_free(subject);
    }

    if (issuer) {
        OPENSSL_free(issuer);
    }
#endif

    return 1;
}


static void
njt_ssl_info_callback(const njt_ssl_conn_t *ssl_conn, int where, int ret)
{
    BIO               *rbio, *wbio;
    njt_connection_t  *c;

#ifndef SSL_OP_NO_RENEGOTIATION

    if ((where & SSL_CB_HANDSHAKE_START)
        && SSL_is_server((njt_ssl_conn_t *) ssl_conn))
    {
        c = njt_ssl_get_connection((njt_ssl_conn_t *) ssl_conn);

        if (c->ssl->handshaked) {
            c->ssl->renegotiation = 1;
            njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0, "SSL renegotiation");
        }
    }

#endif

#ifdef TLS1_3_VERSION

    if ((where & SSL_CB_ACCEPT_LOOP) == SSL_CB_ACCEPT_LOOP
        && SSL_version(ssl_conn) == TLS1_3_VERSION)
    {
        time_t        now, time, timeout, conf_timeout;
        SSL_SESSION  *sess;

        /*
         * OpenSSL with TLSv1.3 updates the session creation time on
         * session resumption and keeps the session timeout unmodified,
         * making it possible to maintain the session forever, bypassing
         * client certificate expiration and revocation.  To make sure
         * session timeouts are actually used, we now update the session
         * creation time and reduce the session timeout accordingly.
         *
         * BoringSSL with TLSv1.3 ignores configured session timeouts
         * and uses a hardcoded timeout instead, 7 days.  So we update
         * session timeout to the configured value as soon as a session
         * is created.
         */

        c = njt_ssl_get_connection((njt_ssl_conn_t *) ssl_conn);
        sess = SSL_get0_session(ssl_conn);

        if (!c->ssl->session_timeout_set && sess) {
            c->ssl->session_timeout_set = 1;

            now = njt_time();
            time = SSL_SESSION_get_time(sess);
            timeout = SSL_SESSION_get_timeout(sess);
            conf_timeout = SSL_CTX_get_timeout(c->ssl->session_ctx);

            timeout = njt_min(timeout, conf_timeout);

            if (now - time >= timeout) {
                SSL_SESSION_set1_id_context(sess, (unsigned char *) "", 0);

            } else {
                SSL_SESSION_set_time(sess, now);
                SSL_SESSION_set_timeout(sess, timeout - (now - time));
            }
        }
    }

#endif

    if ((where & SSL_CB_ACCEPT_LOOP) == SSL_CB_ACCEPT_LOOP) {
        c = njt_ssl_get_connection((njt_ssl_conn_t *) ssl_conn);

        if (!c->ssl->handshake_buffer_set) {
            /*
             * By default OpenSSL uses 4k buffer during a handshake,
             * which is too low for long certificate chains and might
             * result in extra round-trips.
             *
             * To adjust a buffer size we detect that buffering was added
             * to write side of the connection by comparing rbio and wbio.
             * If they are different, we assume that it's due to buffering
             * added to wbio, and set buffer size.
             */

            rbio = SSL_get_rbio(ssl_conn);
            wbio = SSL_get_wbio(ssl_conn);

            if (rbio != wbio) {
                (void) BIO_set_write_buffer_size(wbio, NJT_SSL_BUFSIZE);
                c->ssl->handshake_buffer_set = 1;
            }
        }
    }
}


njt_array_t *
njt_ssl_read_password_file(njt_conf_t *cf, njt_str_t *file)
{
    u_char              *p, *last, *end;
    size_t               len;
    ssize_t              n;
    njt_fd_t             fd;
    njt_str_t           *pwd;
    njt_array_t         *passwords;
    njt_pool_cleanup_t  *cln;
    u_char               buf[NJT_SSL_PASSWORD_BUFFER_SIZE];

    if (njt_conf_full_name(cf->cycle, file, 1) != NJT_OK) {
        return NULL;
    }

    passwords = njt_array_create(cf->temp_pool, 4, sizeof(njt_str_t));
    if (passwords == NULL) {
        return NULL;
    }

    cln = njt_pool_cleanup_add(cf->temp_pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = njt_ssl_passwords_cleanup;
    cln->data = passwords;

    fd = njt_open_file(file->data, NJT_FILE_RDONLY, NJT_FILE_OPEN, 0);

    if (fd == NJT_INVALID_FILE) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, njt_errno,
                           njt_open_file_n " \"%s\" failed", file->data);
        return NULL;
    }

    len = 0;
    last = buf;

    do {
        n = njt_read_fd(fd, last, NJT_SSL_PASSWORD_BUFFER_SIZE - len);

        if (n == -1) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, njt_errno,
                               njt_read_fd_n " \"%s\" failed", file->data);
            passwords = NULL;
            goto cleanup;
        }

        end = last + n;

        if (len && n == 0) {
            *end++ = LF;
        }

        p = buf;

        for ( ;; ) {
            last = njt_strlchr(last, end, LF);

            if (last == NULL) {
                break;
            }

            len = last++ - p;

            if (len && p[len - 1] == CR) {
                len--;
            }

            if (len) {
                pwd = njt_array_push(passwords);
                if (pwd == NULL) {
                    passwords = NULL;
                    goto cleanup;
                }

                pwd->len = len;
                pwd->data = njt_pnalloc(cf->temp_pool, len);

                if (pwd->data == NULL) {
                    passwords->nelts--;
                    passwords = NULL;
                    goto cleanup;
                }

                njt_memcpy(pwd->data, p, len);
            }

            p = last;
        }

        len = end - p;

        if (len == NJT_SSL_PASSWORD_BUFFER_SIZE) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "too long line in \"%s\"", file->data);
            passwords = NULL;
            goto cleanup;
        }

        njt_memmove(buf, p, len);
        last = buf + len;

    } while (n != 0);

    if (passwords->nelts == 0) {
        pwd = njt_array_push(passwords);
        if (pwd == NULL) {
            passwords = NULL;
            goto cleanup;
        }

        njt_memzero(pwd, sizeof(njt_str_t));
    }

cleanup:

    if (njt_close_file(fd) == NJT_FILE_ERROR) {
        njt_conf_log_error(NJT_LOG_ALERT, cf, njt_errno,
                           njt_close_file_n " \"%s\" failed", file->data);
    }

    njt_explicit_memzero(buf, NJT_SSL_PASSWORD_BUFFER_SIZE);

    return passwords;
}


njt_array_t *
njt_ssl_preserve_passwords(njt_conf_t *cf, njt_array_t *passwords)
{
    njt_str_t           *opwd, *pwd;
    njt_uint_t           i;
    njt_array_t         *pwds;
    njt_pool_cleanup_t  *cln;
    static njt_array_t   empty_passwords;

    if (passwords == NULL) {

        /*
         * If there are no passwords, an empty array is used
         * to make sure OpenSSL's default password callback
         * won't block on reading from stdin.
         */

        return &empty_passwords;
    }

    /*
     * Passwords are normally allocated from the temporary pool
     * and cleared after parsing configuration.  To be used at
     * runtime they have to be copied to the configuration pool.
     */

    pwds = njt_array_create(cf->pool, passwords->nelts, sizeof(njt_str_t));
    if (pwds == NULL) {
        return NULL;
    }

    cln = njt_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = njt_ssl_passwords_cleanup;
    cln->data = pwds;

    opwd = passwords->elts;

    for (i = 0; i < passwords->nelts; i++) {

        pwd = njt_array_push(pwds);
        if (pwd == NULL) {
            return NULL;
        }

        pwd->len = opwd[i].len;
        pwd->data = njt_pnalloc(cf->pool, pwd->len);

        if (pwd->data == NULL) {
            pwds->nelts--;
            return NULL;
        }

        njt_memcpy(pwd->data, opwd[i].data, opwd[i].len);
    }

    return pwds;
}


static void
njt_ssl_passwords_cleanup(void *data)
{
    njt_array_t *passwords = data;

    njt_str_t   *pwd;
    njt_uint_t   i;

    pwd = passwords->elts;

    for (i = 0; i < passwords->nelts; i++) {
        njt_explicit_memzero(pwd[i].data, pwd[i].len);
    }
}


njt_int_t
njt_ssl_dhparam(njt_conf_t *cf, njt_ssl_t *ssl, njt_str_t *file)
{
    BIO  *bio;

    if (file->len == 0) {
        return NJT_OK;
    }

    if (njt_conf_full_name(cf->cycle, file, 1) != NJT_OK) {
        return NJT_ERROR;
    }

    bio = BIO_new_file((char *) file->data, "r");
    if (bio == NULL) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "BIO_new_file(\"%s\") failed", file->data);
        return NJT_ERROR;
    }

#ifdef SSL_CTX_set_tmp_dh
    {
    DH  *dh;

    dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    if (dh == NULL) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "PEM_read_bio_DHparams(\"%s\") failed", file->data);
        BIO_free(bio);
        return NJT_ERROR;
    }

    if (SSL_CTX_set_tmp_dh(ssl->ctx, dh) != 1) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set_tmp_dh(\"%s\") failed", file->data);
        DH_free(dh);
        BIO_free(bio);
        return NJT_ERROR;
    }

    DH_free(dh);
    }
#else
    {
    EVP_PKEY  *dh;

    /*
     * PEM_read_bio_DHparams() and SSL_CTX_set_tmp_dh()
     * are deprecated in OpenSSL 3.0
     */

    dh = PEM_read_bio_Parameters(bio, NULL);
    if (dh == NULL) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "PEM_read_bio_Parameters(\"%s\") failed", file->data);
        BIO_free(bio);
        return NJT_ERROR;
    }

    if (SSL_CTX_set0_tmp_dh_pkey(ssl->ctx, dh) != 1) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set0_tmp_dh_pkey(\%s\") failed", file->data);
#if (OPENSSL_VERSION_NUMBER >= 0x3000001fL)
        EVP_PKEY_free(dh);
#endif
        BIO_free(bio);
        return NJT_ERROR;
    }
    }
#endif

    BIO_free(bio);

    return NJT_OK;
}


njt_int_t
njt_ssl_ecdh_curve(njt_conf_t *cf, njt_ssl_t *ssl, njt_str_t *name)
{
#ifndef OPENSSL_NO_ECDH

    /*
     * Elliptic-Curve Diffie-Hellman parameters are either "named curves"
     * from RFC 4492 section 5.1.1, or explicitly described curves over
     * binary fields.  OpenSSL only supports the "named curves", which provide
     * maximum interoperability.
     */

#if (defined SSL_CTX_set1_curves_list || defined SSL_CTRL_SET_CURVES_LIST)

    /*
     * OpenSSL 1.0.2+ allows configuring a curve list instead of a single
     * curve previously supported.  By default an internal list is used,
     * with prime256v1 being preferred by server in OpenSSL 1.0.2b+
     * and X25519 in OpenSSL 1.1.0+.
     *
     * By default a curve preferred by the client will be used for
     * key exchange.  The SSL_OP_CIPHER_SERVER_PREFERENCE option can
     * be used to prefer server curves instead, similar to what it
     * does for ciphers.
     */

    SSL_CTX_set_options(ssl->ctx, SSL_OP_SINGLE_ECDH_USE);

#ifdef SSL_CTRL_SET_ECDH_AUTO
    /* not needed in OpenSSL 1.1.0+ */
    (void) SSL_CTX_set_ecdh_auto(ssl->ctx, 1);
#endif

    if (njt_strcmp(name->data, "auto") == 0) {
        return NJT_OK;
    }

    if (SSL_CTX_set1_curves_list(ssl->ctx, (char *) name->data) == 0) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set1_curves_list(\"%s\") failed", name->data);
        return NJT_ERROR;
    }

#else

    int      nid;
    char    *curve;
    EC_KEY  *ecdh;

    if (njt_strcmp(name->data, "auto") == 0) {
        curve = "prime256v1";

    } else {
        curve = (char *) name->data;
    }

    nid = OBJ_sn2nid(curve);
    if (nid == 0) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "OBJ_sn2nid(\"%s\") failed: unknown curve", curve);
        return NJT_ERROR;
    }

    ecdh = EC_KEY_new_by_curve_name(nid);
    if (ecdh == NULL) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "EC_KEY_new_by_curve_name(\"%s\") failed", curve);
        return NJT_ERROR;
    }

    SSL_CTX_set_options(ssl->ctx, SSL_OP_SINGLE_ECDH_USE);

    SSL_CTX_set_tmp_ecdh(ssl->ctx, ecdh);

    EC_KEY_free(ecdh);
#endif
#endif

    return NJT_OK;
}


njt_int_t
njt_ssl_early_data(njt_conf_t *cf, njt_ssl_t *ssl, njt_uint_t enable)
{
    if (!enable) {
        return NJT_OK;
    }

#ifdef SSL_ERROR_EARLY_DATA_REJECTED

    /* BoringSSL */

    SSL_CTX_set_early_data_enabled(ssl->ctx, 1);

#elif defined SSL_READ_EARLY_DATA_SUCCESS

    /* OpenSSL */

    SSL_CTX_set_max_early_data(ssl->ctx, NJT_SSL_BUFSIZE);

#else
    njt_log_error(NJT_LOG_WARN, ssl->log, 0,
                  "\"ssl_early_data\" is not supported on this platform, "
                  "ignored");
#endif

    return NJT_OK;
}


njt_int_t
njt_ssl_conf_commands(njt_conf_t *cf, njt_ssl_t *ssl, njt_array_t *commands)
{
    if (commands == NULL) {
        return NJT_OK;
    }

#ifdef SSL_CONF_FLAG_FILE
    {
    int            type;
    u_char        *key, *value;
    njt_uint_t     i;
    njt_keyval_t  *cmd;
    SSL_CONF_CTX  *cctx;

    cctx = SSL_CONF_CTX_new();
    if (cctx == NULL) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "SSL_CONF_CTX_new() failed");
        return NJT_ERROR;
    }

    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_FILE);
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_SERVER);
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CLIENT);
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CERTIFICATE);
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_SHOW_ERRORS);

    SSL_CONF_CTX_set_ssl_ctx(cctx, ssl->ctx);

    cmd = commands->elts;
    for (i = 0; i < commands->nelts; i++) {

        key = cmd[i].key.data;
        type = SSL_CONF_cmd_value_type(cctx, (char *) key);

        if (type == SSL_CONF_TYPE_FILE || type == SSL_CONF_TYPE_DIR) {
            if (njt_conf_full_name(cf->cycle, &cmd[i].value, 1) != NJT_OK) {
                SSL_CONF_CTX_free(cctx);
                return NJT_ERROR;
            }
        }

        value = cmd[i].value.data;

        if (SSL_CONF_cmd(cctx, (char *) key, (char *) value) <= 0) {
            njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                          "SSL_CONF_cmd(\"%s\", \"%s\") failed", key, value);
            SSL_CONF_CTX_free(cctx);
            return NJT_ERROR;
        }
    }

    if (SSL_CONF_CTX_finish(cctx) != 1) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "SSL_CONF_finish() failed");
        SSL_CONF_CTX_free(cctx);
        return NJT_ERROR;
    }

    SSL_CONF_CTX_free(cctx);

    return NJT_OK;
    }
#else
    njt_log_error(NJT_LOG_EMERG, ssl->log, 0,
                  "SSL_CONF_cmd() is not available on this platform");
    return NJT_ERROR;
#endif
}


njt_int_t
njt_ssl_client_session_cache(njt_conf_t *cf, njt_ssl_t *ssl, njt_uint_t enable)
{
    if (!enable) {
        return NJT_OK;
    }

    SSL_CTX_set_session_cache_mode(ssl->ctx,
                                   SSL_SESS_CACHE_CLIENT
                                   |SSL_SESS_CACHE_NO_INTERNAL);

    SSL_CTX_sess_set_new_cb(ssl->ctx, njt_ssl_new_client_session);

    return NJT_OK;
}


static int
njt_ssl_new_client_session(njt_ssl_conn_t *ssl_conn, njt_ssl_session_t *sess)
{
    njt_connection_t  *c;

    c = njt_ssl_get_connection(ssl_conn);

    if (c->ssl->save_session) {
        c->ssl->session = sess;

        c->ssl->save_session(c);

        c->ssl->session = NULL;
    }

    return 0;
}


njt_int_t
njt_ssl_create_connection(njt_ssl_t *ssl, njt_connection_t *c, njt_uint_t flags)
{
    njt_ssl_connection_t  *sc;

    sc = njt_pcalloc(c->pool, sizeof(njt_ssl_connection_t));
    if (sc == NULL) {
        return NJT_ERROR;
    }

    sc->buffer = ((flags & NJT_SSL_BUFFER) != 0);
    sc->buffer_size = ssl->buffer_size;

    sc->session_ctx = ssl->ctx;

#ifdef SSL_READ_EARLY_DATA_SUCCESS
    if (SSL_CTX_get_max_early_data(ssl->ctx)) {
        sc->try_early_data = 1;
    }
#endif

    sc->connection = SSL_new(ssl->ctx);

    if (sc->connection == NULL) {
        njt_ssl_error(NJT_LOG_ALERT, c->log, 0, "SSL_new() failed");
        return NJT_ERROR;
    }

    if (SSL_set_fd(sc->connection, c->fd) == 0) {
        njt_ssl_error(NJT_LOG_ALERT, c->log, 0, "SSL_set_fd() failed");
        return NJT_ERROR;
    }

    if (flags & NJT_SSL_CLIENT) {
        SSL_set_connect_state(sc->connection);

    } else {
        SSL_set_accept_state(sc->connection);

#ifdef SSL_OP_NO_RENEGOTIATION
        SSL_set_options(sc->connection, SSL_OP_NO_RENEGOTIATION);
#endif
    }

    if (SSL_set_ex_data(sc->connection, njt_ssl_connection_index, c) == 0) {
        njt_ssl_error(NJT_LOG_ALERT, c->log, 0, "SSL_set_ex_data() failed");
        return NJT_ERROR;
    }

    c->ssl = sc;

    return NJT_OK;
}


njt_ssl_session_t *
njt_ssl_get_session(njt_connection_t *c)
{
#ifdef TLS1_3_VERSION
    if (c->ssl->session) {
        SSL_SESSION_up_ref(c->ssl->session);
        return c->ssl->session;
    }
#endif

    return SSL_get1_session(c->ssl->connection);
}


njt_ssl_session_t *
njt_ssl_get0_session(njt_connection_t *c)
{
    if (c->ssl->session) {
        return c->ssl->session;
    }

    return SSL_get0_session(c->ssl->connection);
}


njt_int_t
njt_ssl_set_session(njt_connection_t *c, njt_ssl_session_t *session)
{
    if (session) {
        if (SSL_set_session(c->ssl->connection, session) == 0) {
            njt_ssl_error(NJT_LOG_ALERT, c->log, 0, "SSL_set_session() failed");
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


njt_int_t
njt_ssl_handshake(njt_connection_t *c)
{
    int        n, sslerr;
    njt_err_t  err;
    njt_int_t  rc;

#ifdef SSL_READ_EARLY_DATA_SUCCESS
    if (c->ssl->try_early_data) {
        return njt_ssl_try_early_data(c);
    }
#endif

    if (c->ssl->in_ocsp) {
        return njt_ssl_ocsp_validate(c);
    }

    njt_ssl_clear_error(c->log);

    n = SSL_do_handshake(c->ssl->connection);

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0, "SSL_do_handshake: %d", n);

    if (n == 1) {

        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            return NJT_ERROR;
        }

        if (njt_handle_write_event(c->write, 0) != NJT_OK) {
            return NJT_ERROR;
        }

#if (NJT_DEBUG)
        njt_ssl_handshake_log(c);
#endif

        c->recv = njt_ssl_recv;
        c->send = njt_ssl_write;
        c->recv_chain = njt_ssl_recv_chain;
        c->send_chain = njt_ssl_send_chain;

        c->read->ready = 1;
        c->write->ready = 1;

#ifndef SSL_OP_NO_RENEGOTIATION
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#ifdef SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS

        /* initial handshake done, disable renegotiation (CVE-2009-3555) */
        if (c->ssl->connection->s3 && SSL_is_server(c->ssl->connection)) {
            c->ssl->connection->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
        }

#endif
#endif
#endif

#if (defined BIO_get_ktls_send && !NJT_WIN32)

        if (BIO_get_ktls_send(SSL_get_wbio(c->ssl->connection)) == 1) {
            njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                           "BIO_get_ktls_send(): 1");
            c->ssl->sendfile = 1;
        }

#endif

        rc = njt_ssl_ocsp_validate(c);

        if (rc == NJT_ERROR) {
            return NJT_ERROR;
        }

        if (rc == NJT_AGAIN) {
            c->read->handler = njt_ssl_handshake_handler;
            c->write->handler = njt_ssl_handshake_handler;
            return NJT_AGAIN;
        }

        c->ssl->handshaked = 1;

        return NJT_OK;
    }

    sslerr = SSL_get_error(c->ssl->connection, n);

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);

    if (sslerr == SSL_ERROR_WANT_READ) {
        c->read->ready = 0;
        c->read->handler = njt_ssl_handshake_handler;
        c->write->handler = njt_ssl_handshake_handler;

        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            return NJT_ERROR;
        }

        if (njt_handle_write_event(c->write, 0) != NJT_OK) {
            return NJT_ERROR;
        }

        return NJT_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_WRITE) {
        c->write->ready = 0;
        c->read->handler = njt_ssl_handshake_handler;
        c->write->handler = njt_ssl_handshake_handler;

        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            return NJT_ERROR;
        }

        if (njt_handle_write_event(c->write, 0) != NJT_OK) {
            return NJT_ERROR;
        }

        return NJT_AGAIN;
    }

// openresty patch
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    if (sslerr == SSL_ERROR_WANT_X509_LOOKUP
#   ifdef SSL_ERROR_PENDING_SESSION
         || sslerr == SSL_ERROR_PENDING_SESSION
#   endif
#   ifdef SSL_ERROR_WANT_CLIENT_HELLO_CB
        || sslerr == SSL_ERROR_WANT_CLIENT_HELLO_CB
#   endif
    ) {
        c->read->handler = njt_ssl_handshake_handler;
        c->write->handler = njt_ssl_handshake_handler;

        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            return NJT_ERROR;
        }

        if (njt_handle_write_event(c->write, 0) != NJT_OK) {
            return NJT_ERROR;
        }

        return NJT_AGAIN;
    }
#endif
// openresty patch end

    err = (sslerr == SSL_ERROR_SYSCALL) ? njt_errno : 0;

    c->ssl->no_wait_shutdown = 1;
    c->ssl->no_send_shutdown = 1;
    c->read->eof = 1;

    if (sslerr == SSL_ERROR_ZERO_RETURN || ERR_peek_error() == 0) {
        njt_connection_error(c, err,
                             "peer closed connection in SSL handshake");

        return NJT_ERROR;
    }

    if (c->ssl->handshake_rejected) {
        njt_connection_error(c, err, "handshake rejected");
        ERR_clear_error();

        return NJT_ERROR;
    }

    c->read->error = 1;

    njt_ssl_connection_error(c, sslerr, err, "SSL_do_handshake() failed");

    return NJT_ERROR;
}


#ifdef SSL_READ_EARLY_DATA_SUCCESS

static njt_int_t
njt_ssl_try_early_data(njt_connection_t *c)
{
    int        n, sslerr;
    u_char     buf;
    size_t     readbytes;
    njt_err_t  err;
    njt_int_t  rc;

    njt_ssl_clear_error(c->log);

    readbytes = 0;

    n = SSL_read_early_data(c->ssl->connection, &buf, 1, &readbytes);

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL_read_early_data: %d, %uz", n, readbytes);

    if (n == SSL_READ_EARLY_DATA_FINISH) {
        c->ssl->try_early_data = 0;
        return njt_ssl_handshake(c);
    }

    if (n == SSL_READ_EARLY_DATA_SUCCESS) {

        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            return NJT_ERROR;
        }

        if (njt_handle_write_event(c->write, 0) != NJT_OK) {
            return NJT_ERROR;
        }

#if (NJT_DEBUG)
        njt_ssl_handshake_log(c);
#endif

        c->ssl->try_early_data = 0;

        c->ssl->early_buf = buf;
        c->ssl->early_preread = 1;

        c->ssl->in_early = 1;

        c->recv = njt_ssl_recv;
        c->send = njt_ssl_write;
        c->recv_chain = njt_ssl_recv_chain;
        c->send_chain = njt_ssl_send_chain;

        c->read->ready = 1;
        c->write->ready = 1;

#if (defined BIO_get_ktls_send && !NJT_WIN32)

        if (BIO_get_ktls_send(SSL_get_wbio(c->ssl->connection)) == 1) {
            njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                           "BIO_get_ktls_send(): 1");
            c->ssl->sendfile = 1;
        }

#endif

        rc = njt_ssl_ocsp_validate(c);

        if (rc == NJT_ERROR) {
            return NJT_ERROR;
        }

        if (rc == NJT_AGAIN) {
            c->read->handler = njt_ssl_handshake_handler;
            c->write->handler = njt_ssl_handshake_handler;
            return NJT_AGAIN;
        }

        c->ssl->handshaked = 1;

        return NJT_OK;
    }

    /* SSL_READ_EARLY_DATA_ERROR */

    sslerr = SSL_get_error(c->ssl->connection, n);

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);

    if (sslerr == SSL_ERROR_WANT_READ) {
        c->read->ready = 0;
        c->read->handler = njt_ssl_handshake_handler;
        c->write->handler = njt_ssl_handshake_handler;

        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            return NJT_ERROR;
        }

        if (njt_handle_write_event(c->write, 0) != NJT_OK) {
            return NJT_ERROR;
        }

        return NJT_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_WRITE) {
        c->write->ready = 0;
        c->read->handler = njt_ssl_handshake_handler;
        c->write->handler = njt_ssl_handshake_handler;

        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            return NJT_ERROR;
        }

        if (njt_handle_write_event(c->write, 0) != NJT_OK) {
            return NJT_ERROR;
        }

        return NJT_AGAIN;
    }

    // openresty patch
    if (sslerr == SSL_ERROR_WANT_X509_LOOKUP) {
        c->read->handler = njt_ssl_handshake_handler;
        c->write->handler = njt_ssl_handshake_handler;

        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            return NJT_ERROR;
        }

        if (njt_handle_write_event(c->write, 0) != NJT_OK) {
            return NJT_ERROR;
        }

        return NJT_AGAIN;
    }

#ifdef SSL_ERROR_WANT_CLIENT_HELLO_CB
    if (sslerr == SSL_ERROR_WANT_CLIENT_HELLO_CB) {
        c->read->handler = njt_ssl_handshake_handler;
        c->write->handler = njt_ssl_handshake_handler;

        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            return NJT_ERROR;
        }

        if (njt_handle_write_event(c->write, 0) != NJT_OK) {
            return NJT_ERROR;
        }

        return NJT_AGAIN;
    }
#endif

#ifdef SSL_ERROR_PENDING_SESSION
    if (sslerr == SSL_ERROR_PENDING_SESSION) {
        c->read->handler = njt_ssl_handshake_handler;
        c->write->handler = njt_ssl_handshake_handler;

        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            return NJT_ERROR;
        }

        if (njt_handle_write_event(c->write, 0) != NJT_OK) {
            return NJT_ERROR;
        }

        return NJT_AGAIN;
    }
#endif
    // openresty patch end


    err = (sslerr == SSL_ERROR_SYSCALL) ? njt_errno : 0;

    c->ssl->no_wait_shutdown = 1;
    c->ssl->no_send_shutdown = 1;
    c->read->eof = 1;

    if (sslerr == SSL_ERROR_ZERO_RETURN || ERR_peek_error() == 0) {
        njt_connection_error(c, err,
                             "peer closed connection in SSL handshake");

        return NJT_ERROR;
    }

    c->read->error = 1;

    njt_ssl_connection_error(c, sslerr, err, "SSL_read_early_data() failed");

    return NJT_ERROR;
}

#endif


#if (NJT_DEBUG)

void
njt_ssl_handshake_log(njt_connection_t *c)
{
    char         buf[129], *s, *d;
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
    const
#endif
    SSL_CIPHER  *cipher;

    if (!(c->log->log_level & NJT_LOG_DEBUG_EVENT)) {
        return;
    }

    cipher = SSL_get_current_cipher(c->ssl->connection);

    if (cipher) {
        SSL_CIPHER_description(cipher, &buf[1], 128);

        for (s = &buf[1], d = buf; *s; s++) {
            if (*s == ' ' && *d == ' ') {
                continue;
            }

            if (*s == LF || *s == CR) {
                continue;
            }

            *++d = *s;
        }

        if (*d != ' ') {
            d++;
        }

        *d = '\0';

        njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL: %s, cipher: \"%s\"",
                       SSL_get_version(c->ssl->connection), &buf[1]);

        if (SSL_session_reused(c->ssl->connection)) {
            njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                           "SSL reused session");
        }

    } else {
        njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL no shared ciphers");
    }
}

#endif


static void
njt_ssl_handshake_handler(njt_event_t *ev)
{
    njt_connection_t  *c;

    c = ev->data;

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL handshake handler: %d", ev->write);

    if (ev->timedout) {
        c->ssl->handler(c);
        return;
    }

    if (njt_ssl_handshake(c) == NJT_AGAIN) {
        return;
    }

    c->ssl->handler(c);
}


ssize_t
njt_ssl_recv_chain(njt_connection_t *c, njt_chain_t *cl, off_t limit)
{
    u_char     *last;
    ssize_t     n, bytes, size;
    njt_buf_t  *b;

    bytes = 0;

    b = cl->buf;
    last = b->last;

    for ( ;; ) {
        size = b->end - last;

        if (limit) {
            if (bytes >= limit) {
                return bytes;
            }

            if (bytes + size > limit) {
                size = (ssize_t) (limit - bytes);
            }
        }

        n = njt_ssl_recv(c, last, size);

        if (n > 0) {
            last += n;
            bytes += n;

            if (!c->read->ready) {
                return bytes;
            }

            if (last == b->end) {
                cl = cl->next;

                if (cl == NULL) {
                    return bytes;
                }

                b = cl->buf;
                last = b->last;
            }

            continue;
        }

        if (bytes) {

            if (n == 0 || n == NJT_ERROR) {
                c->read->ready = 1;
            }

            return bytes;
        }

        return n;
    }
}


ssize_t
njt_ssl_recv(njt_connection_t *c, u_char *buf, size_t size)
{
    int  n, bytes;

#ifdef SSL_READ_EARLY_DATA_SUCCESS
    if (c->ssl->in_early) {
        return njt_ssl_recv_early(c, buf, size);
    }
#endif

    if (c->ssl->last == NJT_ERROR) {
        c->read->ready = 0;
        c->read->error = 1;
        return NJT_ERROR;
    }

    if (c->ssl->last == NJT_DONE) {
        c->read->ready = 0;
        c->read->eof = 1;
        return 0;
    }

    bytes = 0;

    njt_ssl_clear_error(c->log);

    /*
     * SSL_read() may return data in parts, so try to read
     * until SSL_read() would return no data
     */

    for ( ;; ) {

        n = SSL_read(c->ssl->connection, buf, size);

        njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0, "SSL_read: %d", n);

        if (n > 0) {
            bytes += n;
        }

        c->ssl->last = njt_ssl_handle_recv(c, n);

        if (c->ssl->last == NJT_OK) {

            size -= n;

            if (size == 0) {
                c->read->ready = 1;

                if (c->read->available >= 0) {
                    c->read->available -= bytes;

                    /*
                     * there can be data buffered at SSL layer,
                     * so we post an event to continue reading on the next
                     * iteration of the event loop
                     */

                    if (c->read->available < 0) {
                        c->read->available = 0;
                        c->read->ready = 0;

                        if (c->read->posted) {
                            njt_delete_posted_event(c->read);
                        }

                        njt_post_event(c->read, &njt_posted_next_events);
                    }

                    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                                   "SSL_read: avail:%d", c->read->available);

                } else {

#if (NJT_HAVE_FIONREAD)

                    if (njt_socket_nread(c->fd, &c->read->available) == -1) {
                        c->read->ready = 0;
                        c->read->error = 1;
                        njt_connection_error(c, njt_socket_errno,
                                             njt_socket_nread_n " failed");
                        return NJT_ERROR;
                    }

                    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                                   "SSL_read: avail:%d", c->read->available);

#endif
                }

                return bytes;
            }

            buf += n;

            continue;
        }

        if (bytes) {
            if (c->ssl->last != NJT_AGAIN) {
                c->read->ready = 1;
            }

            return bytes;
        }

        switch (c->ssl->last) {

        case NJT_DONE:
            c->read->ready = 0;
            c->read->eof = 1;
            return 0;

        case NJT_ERROR:
            c->read->ready = 0;
            c->read->error = 1;

            /* fall through */

        case NJT_AGAIN:
            return c->ssl->last;
        }
    }
}


#ifdef SSL_READ_EARLY_DATA_SUCCESS

static ssize_t
njt_ssl_recv_early(njt_connection_t *c, u_char *buf, size_t size)
{
    int        n, bytes;
    size_t     readbytes;

    if (c->ssl->last == NJT_ERROR) {
        c->read->ready = 0;
        c->read->error = 1;
        return NJT_ERROR;
    }

    if (c->ssl->last == NJT_DONE) {
        c->read->ready = 0;
        c->read->eof = 1;
        return 0;
    }

    bytes = 0;

    njt_ssl_clear_error(c->log);

    if (c->ssl->early_preread) {

        if (size == 0) {
            c->read->ready = 0;
            c->read->eof = 1;
            return 0;
        }

        *buf = c->ssl->early_buf;

        c->ssl->early_preread = 0;

        bytes = 1;
        size -= 1;
        buf += 1;
    }

    if (c->ssl->write_blocked) {
        return NJT_AGAIN;
    }

    /*
     * SSL_read_early_data() may return data in parts, so try to read
     * until SSL_read_early_data() would return no data
     */

    for ( ;; ) {

        readbytes = 0;

        n = SSL_read_early_data(c->ssl->connection, buf, size, &readbytes);

        njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL_read_early_data: %d, %uz", n, readbytes);

        if (n == SSL_READ_EARLY_DATA_SUCCESS) {

            c->ssl->last = njt_ssl_handle_recv(c, 1);

            bytes += readbytes;
            size -= readbytes;

            if (size == 0) {
                c->read->ready = 1;
                return bytes;
            }

            buf += readbytes;

            continue;
        }

        if (n == SSL_READ_EARLY_DATA_FINISH) {

            c->ssl->last = njt_ssl_handle_recv(c, 1);
            c->ssl->in_early = 0;

            if (bytes) {
                c->read->ready = 1;
                return bytes;
            }

            return njt_ssl_recv(c, buf, size);
        }

        /* SSL_READ_EARLY_DATA_ERROR */

        c->ssl->last = njt_ssl_handle_recv(c, 0);

        if (bytes) {
            if (c->ssl->last != NJT_AGAIN) {
                c->read->ready = 1;
            }

            return bytes;
        }

        switch (c->ssl->last) {

        case NJT_DONE:
            c->read->ready = 0;
            c->read->eof = 1;
            return 0;

        case NJT_ERROR:
            c->read->ready = 0;
            c->read->error = 1;

            /* fall through */

        case NJT_AGAIN:
            return c->ssl->last;
        }
    }
}

#endif


static njt_int_t
njt_ssl_handle_recv(njt_connection_t *c, int n)
{
    int        sslerr;
    njt_err_t  err;

#ifndef SSL_OP_NO_RENEGOTIATION

    if (c->ssl->renegotiation) {
        /*
         * disable renegotiation (CVE-2009-3555):
         * OpenSSL (at least up to 0.9.8l) does not handle disabled
         * renegotiation gracefully, so drop connection here
         */

        njt_log_error(NJT_LOG_NOTICE, c->log, 0, "SSL renegotiation disabled");

        while (ERR_peek_error()) {
            njt_ssl_error(NJT_LOG_DEBUG, c->log, 0,
                          "ignoring stale global SSL error");
        }

        ERR_clear_error();

        c->ssl->no_wait_shutdown = 1;
        c->ssl->no_send_shutdown = 1;

        return NJT_ERROR;
    }

#endif

    if (n > 0) {

        if (c->ssl->saved_write_handler) {

            c->write->handler = c->ssl->saved_write_handler;
            c->ssl->saved_write_handler = NULL;
            c->write->ready = 1;

            if (njt_handle_write_event(c->write, 0) != NJT_OK) {
                return NJT_ERROR;
            }

            njt_post_event(c->write, &njt_posted_events);
        }

        return NJT_OK;
    }

    sslerr = SSL_get_error(c->ssl->connection, n);

    err = (sslerr == SSL_ERROR_SYSCALL) ? njt_errno : 0;

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);

    if (sslerr == SSL_ERROR_WANT_READ) {

        if (c->ssl->saved_write_handler) {

            c->write->handler = c->ssl->saved_write_handler;
            c->ssl->saved_write_handler = NULL;
            c->write->ready = 1;

            if (njt_handle_write_event(c->write, 0) != NJT_OK) {
                return NJT_ERROR;
            }

            njt_post_event(c->write, &njt_posted_events);
        }

        c->read->ready = 0;
        return NJT_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_WRITE) {

        njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL_read: want write");

        c->write->ready = 0;

        if (njt_handle_write_event(c->write, 0) != NJT_OK) {
            return NJT_ERROR;
        }

        /*
         * we do not set the timer because there is already the read event timer
         */

        if (c->ssl->saved_write_handler == NULL) {
            c->ssl->saved_write_handler = c->write->handler;
            c->write->handler = njt_ssl_write_handler;
        }

        return NJT_AGAIN;
    }

    c->ssl->no_wait_shutdown = 1;
    c->ssl->no_send_shutdown = 1;

    if (sslerr == SSL_ERROR_ZERO_RETURN || ERR_peek_error() == 0) {
        njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "peer shutdown SSL cleanly");
        return NJT_DONE;
    }

    njt_ssl_connection_error(c, sslerr, err, "SSL_read() failed");

    return NJT_ERROR;
}


static void
njt_ssl_write_handler(njt_event_t *wev)
{
    njt_connection_t  *c;

    c = wev->data;

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0, "SSL write handler");

    c->read->handler(c->read);
}


/*
 * OpenSSL has no SSL_writev() so we copy several bufs into our 16K buffer
 * before the SSL_write() call to decrease a SSL overhead.
 *
 * Besides for protocols such as HTTP it is possible to always buffer
 * the output to decrease a SSL overhead some more.
 */

njt_chain_t *
njt_ssl_send_chain(njt_connection_t *c, njt_chain_t *in, off_t limit)
{
    int           n;
    njt_uint_t    flush;
    ssize_t       send, size, file_size;
    njt_buf_t    *buf;
    njt_chain_t  *cl;

    if (!c->ssl->buffer) {

        while (in) {
            if (njt_buf_special(in->buf)) {
                in = in->next;
                continue;
            }

            n = njt_ssl_write(c, in->buf->pos, in->buf->last - in->buf->pos);

            if (n == NJT_ERROR) {
                return NJT_CHAIN_ERROR;
            }

            if (n == NJT_AGAIN) {
                return in;
            }

            in->buf->pos += n;

            if (in->buf->pos == in->buf->last) {
                in = in->next;
            }
        }

        return in;
    }


    /* the maximum limit size is the maximum int32_t value - the page size */

    if (limit == 0 || limit > (off_t) (NJT_MAX_INT32_VALUE - njt_pagesize)) {
        limit = NJT_MAX_INT32_VALUE - njt_pagesize;
    }

    buf = c->ssl->buf;

    if (buf == NULL) {
        buf = njt_create_temp_buf(c->pool, c->ssl->buffer_size);
        if (buf == NULL) {
            return NJT_CHAIN_ERROR;
        }

        c->ssl->buf = buf;
    }

    if (buf->start == NULL) {
        buf->start = njt_palloc(c->pool, c->ssl->buffer_size);
        if (buf->start == NULL) {
            return NJT_CHAIN_ERROR;
        }

        buf->pos = buf->start;
        buf->last = buf->start;
        buf->end = buf->start + c->ssl->buffer_size;
    }

    send = buf->last - buf->pos;
    flush = (in == NULL) ? 1 : buf->flush;

    for ( ;; ) {

        while (in && buf->last < buf->end && send < limit) {
            if (in->buf->last_buf || in->buf->flush) {
                flush = 1;
            }

            if (njt_buf_special(in->buf)) {
                in = in->next;
                continue;
            }

            if (in->buf->in_file && c->ssl->sendfile) {
                flush = 1;
                break;
            }

            size = in->buf->last - in->buf->pos;

            if (size > buf->end - buf->last) {
                size = buf->end - buf->last;
            }

            if (send + size > limit) {
                size = (ssize_t) (limit - send);
            }

            njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                           "SSL buf copy: %z", size);

            njt_memcpy(buf->last, in->buf->pos, size);

            buf->last += size;
            in->buf->pos += size;
            send += size;

            if (in->buf->pos == in->buf->last) {
                in = in->next;
            }
        }

        if (!flush && send < limit && buf->last < buf->end) {
            break;
        }

        size = buf->last - buf->pos;

        if (size == 0) {

            if (in && in->buf->in_file && send < limit) {

                /* coalesce the neighbouring file bufs */

                cl = in;
                file_size = (size_t) njt_chain_coalesce_file(&cl, limit - send);

                n = njt_ssl_sendfile(c, in->buf, file_size);

                if (n == NJT_ERROR) {
                    return NJT_CHAIN_ERROR;
                }

                if (n == NJT_AGAIN) {
                    break;
                }

                in = njt_chain_update_sent(in, n);

                send += n;
                flush = 0;

                continue;
            }

            buf->flush = 0;
            c->buffered &= ~NJT_SSL_BUFFERED;

            return in;
        }

        n = njt_ssl_write(c, buf->pos, size);

        if (n == NJT_ERROR) {
            return NJT_CHAIN_ERROR;
        }

        if (n == NJT_AGAIN) {
            break;
        }

        buf->pos += n;

        if (n < size) {
            break;
        }

        flush = 0;

        buf->pos = buf->start;
        buf->last = buf->start;

        if (in == NULL || send >= limit) {
            break;
        }
    }

    buf->flush = flush;

    if (buf->pos < buf->last) {
        c->buffered |= NJT_SSL_BUFFERED;

    } else {
        c->buffered &= ~NJT_SSL_BUFFERED;
    }

    return in;
}


ssize_t
njt_ssl_write(njt_connection_t *c, u_char *data, size_t size)
{
    int        n, sslerr;
    njt_err_t  err;

#ifdef SSL_READ_EARLY_DATA_SUCCESS
    if (c->ssl->in_early) {
        return njt_ssl_write_early(c, data, size);
    }
#endif

    njt_ssl_clear_error(c->log);

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0, "SSL to write: %uz", size);

    n = SSL_write(c->ssl->connection, data, size);

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0, "SSL_write: %d", n);

    if (n > 0) {

        if (c->ssl->saved_read_handler) {

            c->read->handler = c->ssl->saved_read_handler;
            c->ssl->saved_read_handler = NULL;
            c->read->ready = 1;

            if (njt_handle_read_event(c->read, 0) != NJT_OK) {
                return NJT_ERROR;
            }

            njt_post_event(c->read, &njt_posted_events);
        }

        c->sent += n;

        return n;
    }

    sslerr = SSL_get_error(c->ssl->connection, n);

    if (sslerr == SSL_ERROR_ZERO_RETURN) {

        /*
         * OpenSSL 1.1.1 fails to return SSL_ERROR_SYSCALL if an error
         * happens during SSL_write() after close_notify alert from the
         * peer, and returns SSL_ERROR_ZERO_RETURN instead,
         * https://git.openssl.org/?p=openssl.git;a=commitdiff;h=8051ab2
         */

        sslerr = SSL_ERROR_SYSCALL;
    }

    err = (sslerr == SSL_ERROR_SYSCALL) ? njt_errno : 0;

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);

    if (sslerr == SSL_ERROR_WANT_WRITE) {

        if (c->ssl->saved_read_handler) {

            c->read->handler = c->ssl->saved_read_handler;
            c->ssl->saved_read_handler = NULL;
            c->read->ready = 1;

            if (njt_handle_read_event(c->read, 0) != NJT_OK) {
                return NJT_ERROR;
            }

            njt_post_event(c->read, &njt_posted_events);
        }

        c->write->ready = 0;
        return NJT_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_READ) {

        njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL_write: want read");

        c->read->ready = 0;

        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            return NJT_ERROR;
        }

        /*
         * we do not set the timer because there is already
         * the write event timer
         */

        if (c->ssl->saved_read_handler == NULL) {
            c->ssl->saved_read_handler = c->read->handler;
            c->read->handler = njt_ssl_read_handler;
        }

        return NJT_AGAIN;
    }

    c->ssl->no_wait_shutdown = 1;
    c->ssl->no_send_shutdown = 1;
    c->write->error = 1;

    njt_ssl_connection_error(c, sslerr, err, "SSL_write() failed");

    return NJT_ERROR;
}


#ifdef SSL_READ_EARLY_DATA_SUCCESS

static ssize_t
njt_ssl_write_early(njt_connection_t *c, u_char *data, size_t size)
{
    int        n, sslerr;
    size_t     written;
    njt_err_t  err;

    njt_ssl_clear_error(c->log);

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0, "SSL to write: %uz", size);

    written = 0;

    n = SSL_write_early_data(c->ssl->connection, data, size, &written);

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL_write_early_data: %d, %uz", n, written);

    if (n > 0) {

        if (c->ssl->saved_read_handler) {

            c->read->handler = c->ssl->saved_read_handler;
            c->ssl->saved_read_handler = NULL;
            c->read->ready = 1;

            if (njt_handle_read_event(c->read, 0) != NJT_OK) {
                return NJT_ERROR;
            }

            njt_post_event(c->read, &njt_posted_events);
        }

        if (c->ssl->write_blocked) {
            c->ssl->write_blocked = 0;
            njt_post_event(c->read, &njt_posted_events);
        }

        c->sent += written;

        return written;
    }

    sslerr = SSL_get_error(c->ssl->connection, n);

    err = (sslerr == SSL_ERROR_SYSCALL) ? njt_errno : 0;

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);

    if (sslerr == SSL_ERROR_WANT_WRITE) {

        njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL_write_early_data: want write");

        if (c->ssl->saved_read_handler) {

            c->read->handler = c->ssl->saved_read_handler;
            c->ssl->saved_read_handler = NULL;
            c->read->ready = 1;

            if (njt_handle_read_event(c->read, 0) != NJT_OK) {
                return NJT_ERROR;
            }

            njt_post_event(c->read, &njt_posted_events);
        }

        /*
         * OpenSSL 1.1.1a fails to handle SSL_read_early_data()
         * if an SSL_write_early_data() call blocked on writing,
         * see https://github.com/openssl/openssl/issues/7757
         */

        c->ssl->write_blocked = 1;

        c->write->ready = 0;
        return NJT_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_READ) {

        njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL_write_early_data: want read");

        c->read->ready = 0;

        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            return NJT_ERROR;
        }

        /*
         * we do not set the timer because there is already
         * the write event timer
         */

        if (c->ssl->saved_read_handler == NULL) {
            c->ssl->saved_read_handler = c->read->handler;
            c->read->handler = njt_ssl_read_handler;
        }

        return NJT_AGAIN;
    }

    c->ssl->no_wait_shutdown = 1;
    c->ssl->no_send_shutdown = 1;
    c->write->error = 1;

    njt_ssl_connection_error(c, sslerr, err, "SSL_write_early_data() failed");

    return NJT_ERROR;
}

#endif


static ssize_t
njt_ssl_sendfile(njt_connection_t *c, njt_buf_t *file, size_t size)
{
#if (defined BIO_get_ktls_send && !NJT_WIN32)

    int        sslerr, flags;
    ssize_t    n;
    njt_err_t  err;

    njt_ssl_clear_error(c->log);

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL to sendfile: @%O %uz",
                   file->file_pos, size);

    njt_set_errno(0);

#if (NJT_HAVE_SENDFILE_NODISKIO)

    flags = (c->busy_count <= 2) ? SF_NODISKIO : 0;

    if (file->file->directio) {
        flags |= SF_NOCACHE;
    }

#else
    flags = 0;
#endif

    n = SSL_sendfile(c->ssl->connection, file->file->fd, file->file_pos,
                     size, flags);

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0, "SSL_sendfile: %z", n);

    if (n > 0) {

        if (c->ssl->saved_read_handler) {

            c->read->handler = c->ssl->saved_read_handler;
            c->ssl->saved_read_handler = NULL;
            c->read->ready = 1;

            if (njt_handle_read_event(c->read, 0) != NJT_OK) {
                return NJT_ERROR;
            }

            njt_post_event(c->read, &njt_posted_events);
        }

#if (NJT_HAVE_SENDFILE_NODISKIO)
        c->busy_count = 0;
#endif

        c->sent += n;

        return n;
    }

    if (n == 0) {

        /*
         * if sendfile returns zero, then someone has truncated the file,
         * so the offset became beyond the end of the file
         */

        njt_log_error(NJT_LOG_ALERT, c->log, 0,
                      "SSL_sendfile() reported that \"%s\" was truncated at %O",
                      file->file->name.data, file->file_pos);

        return NJT_ERROR;
    }

    sslerr = SSL_get_error(c->ssl->connection, n);

    if (sslerr == SSL_ERROR_ZERO_RETURN) {

        /*
         * OpenSSL fails to return SSL_ERROR_SYSCALL if an error
         * happens during writing after close_notify alert from the
         * peer, and returns SSL_ERROR_ZERO_RETURN instead
         */

        sslerr = SSL_ERROR_SYSCALL;
    }

    if (sslerr == SSL_ERROR_SSL
        && ERR_GET_REASON(ERR_peek_error()) == SSL_R_UNINITIALIZED
        && njt_errno != 0)
    {
        /*
         * OpenSSL fails to return SSL_ERROR_SYSCALL if an error
         * happens in sendfile(), and returns SSL_ERROR_SSL with
         * SSL_R_UNINITIALIZED reason instead
         */

        sslerr = SSL_ERROR_SYSCALL;
    }

    err = (sslerr == SSL_ERROR_SYSCALL) ? njt_errno : 0;

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d", sslerr);

    if (sslerr == SSL_ERROR_WANT_WRITE) {

        if (c->ssl->saved_read_handler) {

            c->read->handler = c->ssl->saved_read_handler;
            c->ssl->saved_read_handler = NULL;
            c->read->ready = 1;

            if (njt_handle_read_event(c->read, 0) != NJT_OK) {
                return NJT_ERROR;
            }

            njt_post_event(c->read, &njt_posted_events);
        }

#if (NJT_HAVE_SENDFILE_NODISKIO)

        if (njt_errno == EBUSY) {
            c->busy_count++;

            njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                           "SSL_sendfile() busy, count:%d", c->busy_count);

            if (c->write->posted) {
                njt_delete_posted_event(c->write);
            }

            njt_post_event(c->write, &njt_posted_next_events);
        }

#endif

        c->write->ready = 0;
        return NJT_AGAIN;
    }

    if (sslerr == SSL_ERROR_WANT_READ) {

        njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL_sendfile: want read");

        c->read->ready = 0;

        if (njt_handle_read_event(c->read, 0) != NJT_OK) {
            return NJT_ERROR;
        }

        /*
         * we do not set the timer because there is already
         * the write event timer
         */

        if (c->ssl->saved_read_handler == NULL) {
            c->ssl->saved_read_handler = c->read->handler;
            c->read->handler = njt_ssl_read_handler;
        }

        return NJT_AGAIN;
    }

    c->ssl->no_wait_shutdown = 1;
    c->ssl->no_send_shutdown = 1;
    c->write->error = 1;

    njt_ssl_connection_error(c, sslerr, err, "SSL_sendfile() failed");

#else
    njt_log_error(NJT_LOG_ALERT, c->log, 0,
                  "SSL_sendfile() not available");
#endif

    return NJT_ERROR;
}


static void
njt_ssl_read_handler(njt_event_t *rev)
{
    njt_connection_t  *c;

    c = rev->data;

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0, "SSL read handler");

    c->write->handler(c->write);
}


void
njt_ssl_free_buffer(njt_connection_t *c)
{
    if (c->ssl->buf && c->ssl->buf->start) {
        if (njt_pfree(c->pool, c->ssl->buf->start) == NJT_OK) {
            c->ssl->buf->start = NULL;
        }
    }
}


njt_int_t
njt_ssl_shutdown(njt_connection_t *c)
{
    int         n, sslerr, mode;
    njt_int_t   rc;
    njt_err_t   err;
    njt_uint_t  tries;

#if (NJT_QUIC)
    if (c->quic) {
        /* QUIC streams inherit SSL object */
        return NJT_OK;
    }
#endif

    rc = NJT_OK;

    njt_ssl_ocsp_cleanup(c);

    if (SSL_in_init(c->ssl->connection)) {
        /*
         * OpenSSL 1.0.2f complains if SSL_shutdown() is called during
         * an SSL handshake, while previous versions always return 0.
         * Avoid calling SSL_shutdown() if handshake wasn't completed.
         */

        goto done;
    }

    if (c->timedout || c->error || c->buffered) {
        mode = SSL_RECEIVED_SHUTDOWN|SSL_SENT_SHUTDOWN;
        SSL_set_quiet_shutdown(c->ssl->connection, 1);

    } else {
        mode = SSL_get_shutdown(c->ssl->connection);

        if (c->ssl->no_wait_shutdown) {
            mode |= SSL_RECEIVED_SHUTDOWN;
        }

        if (c->ssl->no_send_shutdown) {
            mode |= SSL_SENT_SHUTDOWN;
        }

        if (c->ssl->no_wait_shutdown && c->ssl->no_send_shutdown) {
            SSL_set_quiet_shutdown(c->ssl->connection, 1);
        }
    }

    SSL_set_shutdown(c->ssl->connection, mode);

    njt_ssl_clear_error(c->log);

    tries = 2;

    for ( ;; ) {

        /*
         * For bidirectional shutdown, SSL_shutdown() needs to be called
         * twice: first call sends the "close notify" alert and returns 0,
         * second call waits for the peer's "close notify" alert.
         */

        n = SSL_shutdown(c->ssl->connection);

        njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0, "SSL_shutdown: %d", n);

        if (n == 1) {
            goto done;
        }

        if (n == 0 && tries-- > 1) {
            continue;
        }

        /* before 0.9.8m SSL_shutdown() returned 0 instead of -1 on errors */

        sslerr = SSL_get_error(c->ssl->connection, n);

        njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL_get_error: %d", sslerr);

        if (sslerr == SSL_ERROR_WANT_READ || sslerr == SSL_ERROR_WANT_WRITE) {
            c->read->handler = njt_ssl_shutdown_handler;
            c->write->handler = njt_ssl_shutdown_handler;

            if (sslerr == SSL_ERROR_WANT_READ) {
                c->read->ready = 0;

            } else {
                c->write->ready = 0;
            }

            if (njt_handle_read_event(c->read, 0) != NJT_OK) {
                goto failed;
            }

            if (njt_handle_write_event(c->write, 0) != NJT_OK) {
                goto failed;
            }

            njt_add_timer(c->read, 3000);

            return NJT_AGAIN;
        }

        if (sslerr == SSL_ERROR_ZERO_RETURN || ERR_peek_error() == 0) {
            goto done;
        }

        err = (sslerr == SSL_ERROR_SYSCALL) ? njt_errno : 0;

        njt_ssl_connection_error(c, sslerr, err, "SSL_shutdown() failed");

        break;
    }

failed:

    rc = NJT_ERROR;

done:

    if (c->ssl->shutdown_without_free) {
        c->ssl->shutdown_without_free = 0;
        c->recv = njt_recv;
        return rc;
    }

    SSL_free(c->ssl->connection);
    c->ssl = NULL;
    c->recv = njt_recv;

    return rc;
}


static void
njt_ssl_shutdown_handler(njt_event_t *ev)
{
    njt_connection_t           *c;
    njt_connection_handler_pt   handler;

    c = ev->data;
    handler = c->ssl->handler;

    if (ev->timedout) {
        c->timedout = 1;
    }

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, ev->log, 0, "SSL shutdown handler");

    if (njt_ssl_shutdown(c) == NJT_AGAIN) {
        return;
    }

    handler(c);
}


static void
njt_ssl_connection_error(njt_connection_t *c, int sslerr, njt_err_t err,
    char *text)
{
    int         n;
    njt_uint_t  level;

    level = NJT_LOG_CRIT;

    if (sslerr == SSL_ERROR_SYSCALL) {

        if (err == NJT_ECONNRESET
#if (NJT_WIN32)
            || err == NJT_ECONNABORTED
#endif
            || err == NJT_EPIPE
            || err == NJT_ENOTCONN
            || err == NJT_ETIMEDOUT
            || err == NJT_ECONNREFUSED
            || err == NJT_ENETDOWN
            || err == NJT_ENETUNREACH
            || err == NJT_EHOSTDOWN
            || err == NJT_EHOSTUNREACH)
        {
            switch (c->log_error) {

            case NJT_ERROR_IGNORE_ECONNRESET:
            case NJT_ERROR_INFO:
                level = NJT_LOG_INFO;
                break;

            case NJT_ERROR_ERR:
                level = NJT_LOG_ERR;
                break;

            default:
                break;
            }
        }

    } else if (sslerr == SSL_ERROR_SSL) {

        n = ERR_GET_REASON(ERR_peek_last_error());

            /* handshake failures */
        if (n == SSL_R_BAD_CHANGE_CIPHER_SPEC                        /*  103 */
#ifdef SSL_R_NO_SUITABLE_KEY_SHARE
            || n == SSL_R_NO_SUITABLE_KEY_SHARE                      /*  101 */
#endif
#ifdef SSL_R_BAD_ALERT
            || n == SSL_R_BAD_ALERT                                  /*  102 */
#endif
#ifdef SSL_R_BAD_KEY_SHARE
            || n == SSL_R_BAD_KEY_SHARE                              /*  108 */
#endif
#ifdef SSL_R_BAD_EXTENSION
            || n == SSL_R_BAD_EXTENSION                              /*  110 */
#endif
            || n == SSL_R_BAD_DIGEST_LENGTH                          /*  111 */
#ifdef SSL_R_MISSING_SIGALGS_EXTENSION
            || n == SSL_R_MISSING_SIGALGS_EXTENSION                  /*  112 */
#endif
            || n == SSL_R_BAD_PACKET_LENGTH                          /*  115 */
#ifdef SSL_R_NO_SUITABLE_SIGNATURE_ALGORITHM
            || n == SSL_R_NO_SUITABLE_SIGNATURE_ALGORITHM            /*  118 */
#endif
#ifdef SSL_R_BAD_KEY_UPDATE
            || n == SSL_R_BAD_KEY_UPDATE                             /*  122 */
#endif
            || n == SSL_R_BLOCK_CIPHER_PAD_IS_WRONG                  /*  129 */
            || n == SSL_R_CCS_RECEIVED_EARLY                         /*  133 */
#ifdef SSL_R_DECODE_ERROR
            || n == SSL_R_DECODE_ERROR                               /*  137 */
#endif
#ifdef SSL_R_DATA_BETWEEN_CCS_AND_FINISHED
            || n == SSL_R_DATA_BETWEEN_CCS_AND_FINISHED              /*  145 */
#endif
            || n == SSL_R_DATA_LENGTH_TOO_LONG                       /*  146 */
            || n == SSL_R_DIGEST_CHECK_FAILED                        /*  149 */
            || n == SSL_R_ENCRYPTED_LENGTH_TOO_LONG                  /*  150 */
            || n == SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST              /*  151 */
            || n == SSL_R_EXCESSIVE_MESSAGE_SIZE                     /*  152 */
#ifdef SSL_R_GOT_A_FIN_BEFORE_A_CCS
            || n == SSL_R_GOT_A_FIN_BEFORE_A_CCS                     /*  154 */
#endif
            || n == SSL_R_HTTPS_PROXY_REQUEST                        /*  155 */
            || n == SSL_R_HTTP_REQUEST                               /*  156 */
            || n == SSL_R_LENGTH_MISMATCH                            /*  159 */
#ifdef SSL_R_LENGTH_TOO_SHORT
            || n == SSL_R_LENGTH_TOO_SHORT                           /*  160 */
#endif
#ifdef SSL_R_NO_RENEGOTIATION
            || n == SSL_R_NO_RENEGOTIATION                           /*  182 */
#endif
#ifdef SSL_R_NO_CIPHERS_PASSED
            || n == SSL_R_NO_CIPHERS_PASSED                          /*  182 */
#endif
            || n == SSL_R_NO_CIPHERS_SPECIFIED                       /*  183 */
#ifdef SSL_R_BAD_CIPHER
            || n == SSL_R_BAD_CIPHER                                 /*  186 */
#endif
            || n == SSL_R_NO_COMPRESSION_SPECIFIED                   /*  187 */
            || n == SSL_R_NO_SHARED_CIPHER                           /*  193 */
#ifdef SSL_R_PACKET_LENGTH_TOO_LONG
            || n == SSL_R_PACKET_LENGTH_TOO_LONG                     /*  198 */
#endif
            || n == SSL_R_RECORD_LENGTH_MISMATCH                     /*  213 */
#ifdef SSL_R_TOO_MANY_WARNING_ALERTS
            || n == SSL_R_TOO_MANY_WARNING_ALERTS                    /*  220 */
#endif
#ifdef SSL_R_CLIENTHELLO_TLSEXT
            || n == SSL_R_CLIENTHELLO_TLSEXT                         /*  226 */
#endif
#ifdef SSL_R_PARSE_TLSEXT
            || n == SSL_R_PARSE_TLSEXT                               /*  227 */
#endif
#ifdef SSL_R_CALLBACK_FAILED
            || n == SSL_R_CALLBACK_FAILED                            /*  234 */
#endif
#ifdef SSL_R_TLS_RSA_ENCRYPTED_VALUE_LENGTH_IS_WRONG
            || n == SSL_R_TLS_RSA_ENCRYPTED_VALUE_LENGTH_IS_WRONG    /*  234 */
#endif
#ifdef SSL_R_NO_APPLICATION_PROTOCOL
            || n == SSL_R_NO_APPLICATION_PROTOCOL                    /*  235 */
#endif
            || n == SSL_R_UNEXPECTED_MESSAGE                         /*  244 */
            || n == SSL_R_UNEXPECTED_RECORD                          /*  245 */
            || n == SSL_R_UNKNOWN_ALERT_TYPE                         /*  246 */
            || n == SSL_R_UNKNOWN_PROTOCOL                           /*  252 */
#ifdef SSL_R_NO_COMMON_SIGNATURE_ALGORITHMS
            || n == SSL_R_NO_COMMON_SIGNATURE_ALGORITHMS             /*  253 */
#endif
#ifdef SSL_R_INVALID_COMPRESSION_LIST
            || n == SSL_R_INVALID_COMPRESSION_LIST                   /*  256 */
#endif
#ifdef SSL_R_MISSING_KEY_SHARE
            || n == SSL_R_MISSING_KEY_SHARE                          /*  258 */
#endif
            || n == SSL_R_UNSUPPORTED_PROTOCOL                       /*  258 */
#ifdef SSL_R_NO_SHARED_GROUP
            || n == SSL_R_NO_SHARED_GROUP                            /*  266 */
#endif
            || n == SSL_R_WRONG_VERSION_NUMBER                       /*  267 */
            || n == SSL_R_BAD_LENGTH                                 /*  271 */
            || n == SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC        /*  281 */
#ifdef SSL_R_APPLICATION_DATA_AFTER_CLOSE_NOTIFY
            || n == SSL_R_APPLICATION_DATA_AFTER_CLOSE_NOTIFY        /*  291 */
#endif
#ifdef SSL_R_APPLICATION_DATA_ON_SHUTDOWN
            || n == SSL_R_APPLICATION_DATA_ON_SHUTDOWN               /*  291 */
#endif
#ifdef SSL_R_BAD_LEGACY_VERSION
            || n == SSL_R_BAD_LEGACY_VERSION                         /*  292 */
#endif
#ifdef SSL_R_MIXED_HANDSHAKE_AND_NON_HANDSHAKE_DATA
            || n == SSL_R_MIXED_HANDSHAKE_AND_NON_HANDSHAKE_DATA     /*  293 */
#endif
#ifdef SSL_R_RECORD_TOO_SMALL
            || n == SSL_R_RECORD_TOO_SMALL                           /*  298 */
#endif
#ifdef SSL_R_SSL3_SESSION_ID_TOO_LONG
            || n == SSL_R_SSL3_SESSION_ID_TOO_LONG                   /*  300 */
#endif
#ifdef SSL_R_BAD_ECPOINT
            || n == SSL_R_BAD_ECPOINT                                /*  306 */
#endif
#ifdef SSL_R_RENEGOTIATE_EXT_TOO_LONG
            || n == SSL_R_RENEGOTIATE_EXT_TOO_LONG                   /*  335 */
            || n == SSL_R_RENEGOTIATION_ENCODING_ERR                 /*  336 */
            || n == SSL_R_RENEGOTIATION_MISMATCH                     /*  337 */
#endif
#ifdef SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED
            || n == SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED       /*  338 */
#endif
#ifdef SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING
            || n == SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING           /*  345 */
#endif
#ifdef SSL_R_INAPPROPRIATE_FALLBACK
            || n == SSL_R_INAPPROPRIATE_FALLBACK                     /*  373 */
#endif
#ifdef SSL_R_NO_SHARED_SIGNATURE_ALGORITHMS
            || n == SSL_R_NO_SHARED_SIGNATURE_ALGORITHMS             /*  376 */
#endif
#ifdef SSL_R_NO_SHARED_SIGATURE_ALGORITHMS
            || n == SSL_R_NO_SHARED_SIGATURE_ALGORITHMS              /*  376 */
#endif
#ifdef SSL_R_CERT_CB_ERROR
            || n == SSL_R_CERT_CB_ERROR                              /*  377 */
#endif
#ifdef SSL_R_VERSION_TOO_LOW
            || n == SSL_R_VERSION_TOO_LOW                            /*  396 */
#endif
#ifdef SSL_R_TOO_MANY_WARN_ALERTS
            || n == SSL_R_TOO_MANY_WARN_ALERTS                       /*  409 */
#endif
#ifdef SSL_R_BAD_RECORD_TYPE
            || n == SSL_R_BAD_RECORD_TYPE                            /*  443 */
#endif
            || n == 1000 /* SSL_R_SSLV3_ALERT_CLOSE_NOTIFY */
#ifdef SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE
            || n == SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE             /* 1010 */
            || n == SSL_R_SSLV3_ALERT_BAD_RECORD_MAC                 /* 1020 */
            || n == SSL_R_TLSV1_ALERT_DECRYPTION_FAILED              /* 1021 */
            || n == SSL_R_TLSV1_ALERT_RECORD_OVERFLOW                /* 1022 */
            || n == SSL_R_SSLV3_ALERT_DECOMPRESSION_FAILURE          /* 1030 */
            || n == SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE              /* 1040 */
            || n == SSL_R_SSLV3_ALERT_NO_CERTIFICATE                 /* 1041 */
            || n == SSL_R_SSLV3_ALERT_BAD_CERTIFICATE                /* 1042 */
            || n == SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE        /* 1043 */
            || n == SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED            /* 1044 */
            || n == SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED            /* 1045 */
            || n == SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN            /* 1046 */
            || n == SSL_R_SSLV3_ALERT_ILLEGAL_PARAMETER              /* 1047 */
            || n == SSL_R_TLSV1_ALERT_UNKNOWN_CA                     /* 1048 */
            || n == SSL_R_TLSV1_ALERT_ACCESS_DENIED                  /* 1049 */
            || n == SSL_R_TLSV1_ALERT_DECODE_ERROR                   /* 1050 */
            || n == SSL_R_TLSV1_ALERT_DECRYPT_ERROR                  /* 1051 */
            || n == SSL_R_TLSV1_ALERT_EXPORT_RESTRICTION             /* 1060 */
            || n == SSL_R_TLSV1_ALERT_PROTOCOL_VERSION               /* 1070 */
            || n == SSL_R_TLSV1_ALERT_INSUFFICIENT_SECURITY          /* 1071 */
            || n == SSL_R_TLSV1_ALERT_INTERNAL_ERROR                 /* 1080 */
            || n == SSL_R_TLSV1_ALERT_USER_CANCELLED                 /* 1090 */
            || n == SSL_R_TLSV1_ALERT_NO_RENEGOTIATION               /* 1100 */
#endif
            )
        {
            switch (c->log_error) {

            case NJT_ERROR_IGNORE_ECONNRESET:
            case NJT_ERROR_INFO:
                level = NJT_LOG_INFO;
                break;

            case NJT_ERROR_ERR:
                level = NJT_LOG_ERR;
                break;

            default:
                break;
            }
        }
    }

    njt_ssl_error(level, c->log, err, text);
}


static void
njt_ssl_clear_error(njt_log_t *log)
{
    while (ERR_peek_error()) {
        njt_ssl_error(NJT_LOG_ALERT, log, 0, "ignoring stale global SSL error");
    }

    ERR_clear_error();
}


void njt_cdecl
njt_ssl_error(njt_uint_t level, njt_log_t *log, njt_err_t err, char *fmt, ...)
{
    int          flags;
    u_long       n;
    va_list      args;
    u_char      *p, *last;
    u_char       errstr[NJT_MAX_CONF_ERRSTR];
    const char  *data;

    last = errstr + NJT_MAX_CONF_ERRSTR;

    va_start(args, fmt);
    p = njt_vslprintf(errstr, last - 1, fmt, args);
    va_end(args);

    if (ERR_peek_error()) {
        p = njt_cpystrn(p, (u_char *) " (SSL:", last - p);

        for ( ;; ) {

            n = ERR_peek_error_data(&data, &flags);

            if (n == 0) {
                break;
            }

            /* ERR_error_string_n() requires at least one byte */

            if (p >= last - 1) {
                goto next;
            }

            *p++ = ' ';

            ERR_error_string_n(n, (char *) p, last - p);

            while (p < last && *p) {
                p++;
            }

            if (p < last && *data && (flags & ERR_TXT_STRING)) {
                *p++ = ':';
                p = njt_cpystrn(p, (u_char *) data, last - p);
            }

        next:

            (void) ERR_get_error();
        }

        if (p < last) {
            *p++ = ')';
        }
    }

    njt_log_error(level, log, err, "%*s", p - errstr, errstr);
}


njt_int_t
njt_ssl_session_cache(njt_ssl_t *ssl, njt_str_t *sess_ctx,
    njt_array_t *certificates, ssize_t builtin_session_cache,
    njt_shm_zone_t *shm_zone, time_t timeout)
{
    long  cache_mode;

    SSL_CTX_set_timeout(ssl->ctx, (long) timeout);

    if (njt_ssl_session_id_context(ssl, sess_ctx, certificates) != NJT_OK) {
        return NJT_ERROR;
    }

    if (builtin_session_cache == NJT_SSL_NO_SCACHE) {
        SSL_CTX_set_session_cache_mode(ssl->ctx, SSL_SESS_CACHE_OFF);
        return NJT_OK;
    }

    if (builtin_session_cache == NJT_SSL_NONE_SCACHE) {

        /*
         * If the server explicitly says that it does not support
         * session reuse (see SSL_SESS_CACHE_OFF above), then
         * Outlook Express fails to upload a sent email to
         * the Sent Items folder on the IMAP server via a separate IMAP
         * connection in the background.  Therefore we have a special
         * mode (SSL_SESS_CACHE_SERVER|SSL_SESS_CACHE_NO_INTERNAL_STORE)
         * where the server pretends that it supports session reuse,
         * but it does not actually store any session.
         */

        SSL_CTX_set_session_cache_mode(ssl->ctx,
                                       SSL_SESS_CACHE_SERVER
                                       |SSL_SESS_CACHE_NO_AUTO_CLEAR
                                       |SSL_SESS_CACHE_NO_INTERNAL_STORE);

        SSL_CTX_sess_set_cache_size(ssl->ctx, 1);

        return NJT_OK;
    }

    cache_mode = SSL_SESS_CACHE_SERVER;

    if (shm_zone && builtin_session_cache == NJT_SSL_NO_BUILTIN_SCACHE) {
        cache_mode |= SSL_SESS_CACHE_NO_INTERNAL;
    }

    SSL_CTX_set_session_cache_mode(ssl->ctx, cache_mode);

    if (builtin_session_cache != NJT_SSL_NO_BUILTIN_SCACHE) {

        if (builtin_session_cache != NJT_SSL_DFLT_BUILTIN_SCACHE) {
            SSL_CTX_sess_set_cache_size(ssl->ctx, builtin_session_cache);
        }
    }

    if (shm_zone) {
        SSL_CTX_sess_set_new_cb(ssl->ctx, njt_ssl_new_session);
        SSL_CTX_sess_set_get_cb(ssl->ctx, njt_ssl_get_cached_session);
        SSL_CTX_sess_set_remove_cb(ssl->ctx, njt_ssl_remove_session);

        if (SSL_CTX_set_ex_data(ssl->ctx, njt_ssl_session_cache_index, shm_zone)
            == 0)
        {
            njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                          "SSL_CTX_set_ex_data() failed");
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


static njt_int_t
njt_ssl_session_id_context(njt_ssl_t *ssl, njt_str_t *sess_ctx,
    njt_array_t *certificates)
{
    int                   n, i;
    X509                 *cert;
    X509_NAME            *name;
    njt_str_t            *certs;
    njt_uint_t            k;
    EVP_MD_CTX           *md;
    unsigned int          len;
    STACK_OF(X509_NAME)  *list;
    u_char                buf[EVP_MAX_MD_SIZE];

    /*
     * Session ID context is set based on the string provided,
     * the server certificates, and the client CA list.
     */

    md = EVP_MD_CTX_create();
    if (md == NULL) {
        return NJT_ERROR;
    }

    if (EVP_DigestInit_ex(md, EVP_sha1(), NULL) == 0) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "EVP_DigestInit_ex() failed");
        goto failed;
    }

    if (EVP_DigestUpdate(md, sess_ctx->data, sess_ctx->len) == 0) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "EVP_DigestUpdate() failed");
        goto failed;
    }

    for (cert = SSL_CTX_get_ex_data(ssl->ctx, njt_ssl_certificate_index);
         cert;
         cert = X509_get_ex_data(cert, njt_ssl_next_certificate_index))
    {
        if (X509_digest(cert, EVP_sha1(), buf, &len) == 0) {
            njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                          "X509_digest() failed");
            goto failed;
        }

        if (EVP_DigestUpdate(md, buf, len) == 0) {
            njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                          "EVP_DigestUpdate() failed");
            goto failed;
        }
    }

    if (SSL_CTX_get_ex_data(ssl->ctx, njt_ssl_certificate_index) == NULL
        && certificates != NULL)
    {
        /*
         * If certificates are loaded dynamically, we use certificate
         * names as specified in the configuration (with variables).
         */

        certs = certificates->elts;
        for (k = 0; k < certificates->nelts; k++) {

            if (EVP_DigestUpdate(md, certs[k].data, certs[k].len) == 0) {
                njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                              "EVP_DigestUpdate() failed");
                goto failed;
            }
        }
    }

    list = SSL_CTX_get_client_CA_list(ssl->ctx);

    if (list != NULL) {
        n = sk_X509_NAME_num(list);

        for (i = 0; i < n; i++) {
            name = sk_X509_NAME_value(list, i);

            if (X509_NAME_digest(name, EVP_sha1(), buf, &len) == 0) {
                njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                              "X509_NAME_digest() failed");
                goto failed;
            }

            if (EVP_DigestUpdate(md, buf, len) == 0) {
                njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                              "EVP_DigestUpdate() failed");
                goto failed;
            }
        }
    }

    if (EVP_DigestFinal_ex(md, buf, &len) == 0) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "EVP_DigestFinal_ex() failed");
        goto failed;
    }

    EVP_MD_CTX_destroy(md);

    if (SSL_CTX_set_session_id_context(ssl->ctx, buf, len) == 0) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set_session_id_context() failed");
        return NJT_ERROR;
    }

    return NJT_OK;

failed:

    EVP_MD_CTX_destroy(md);

    return NJT_ERROR;
}


njt_int_t
njt_ssl_session_cache_init(njt_shm_zone_t *shm_zone, void *data)
{
    size_t                    len;
    njt_slab_pool_t          *shpool;
    njt_ssl_session_cache_t  *cache;

    if (data) {
        shm_zone->data = data;
        return NJT_OK;
    }

    shpool = (njt_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        shm_zone->data = shpool->data;
        return NJT_OK;
    }

    cache = njt_slab_alloc(shpool, sizeof(njt_ssl_session_cache_t));
    if (cache == NULL) {
        return NJT_ERROR;
    }

    shpool->data = cache;
    shm_zone->data = cache;

    njt_rbtree_init(&cache->session_rbtree, &cache->sentinel,
                    njt_ssl_session_rbtree_insert_value);

    njt_queue_init(&cache->expire_queue);

    cache->ticket_keys[0].expire = 0;
    cache->ticket_keys[1].expire = 0;
    cache->ticket_keys[2].expire = 0;

    cache->fail_time = 0;

    len = sizeof(" in SSL session shared cache \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = njt_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NJT_ERROR;
    }

    njt_sprintf(shpool->log_ctx, " in SSL session shared cache \"%V\"%Z",
                &shm_zone->shm.name);

    shpool->log_nomem = 0;

    return NJT_OK;
}


/*
 * The length of the session id is 16 bytes for SSLv2 sessions and
 * between 1 and 32 bytes for SSLv3 and TLS, typically 32 bytes.
 * Typical length of the external ASN1 representation of a session
 * is about 150 bytes plus SNI server name.
 *
 * On 32-bit platforms we allocate an rbtree node, a session id, and
 * an ASN1 representation,  in a single allocation, it typically takes
 * 256 bytes.
 *
 * On 64-bit platforms we allocate separately an rbtree node + session_id,
 * nd an ASN1 representation, they take accordingly 128 and 256 bytes.
 *
 * OpenSSL's i2d_SSL_SESSION() and d2i_SSL_SESSION are slow,
 * so they are outside the code locked by shared pool mutex
 */

static int
njt_ssl_new_session(njt_ssl_conn_t *ssl_conn, njt_ssl_session_t *sess)
{
    int                       len;
    u_char                   *p, *session_id;
    size_t                    n;
    uint32_t                  hash;
    SSL_CTX                  *ssl_ctx;
    unsigned int              session_id_length;
    njt_shm_zone_t           *shm_zone;
    njt_connection_t         *c;
    njt_slab_pool_t          *shpool;
    njt_ssl_sess_id_t        *sess_id;
    njt_ssl_session_cache_t  *cache;
    u_char                    buf[NJT_SSL_MAX_SESSION_SIZE];

#ifdef TLS1_3_VERSION

    /*
     * OpenSSL tries to save TLSv1.3 sessions into session cache
     * even when using tickets for stateless session resumption,
     * "because some applications just want to know about the creation
     * of a session"; do not cache such sessions
     */

    if (SSL_version(ssl_conn) == TLS1_3_VERSION
        && (SSL_get_options(ssl_conn) & SSL_OP_NO_TICKET) == 0)
    {
        return 0;
    }

#endif

    len = i2d_SSL_SESSION(sess, NULL);

    /* do not cache too big session */

    if (len > NJT_SSL_MAX_SESSION_SIZE) {
        return 0;
    }

    p = buf;
    i2d_SSL_SESSION(sess, &p);

    session_id = (u_char *) SSL_SESSION_get_id(sess, &session_id_length);

    /* do not cache sessions with too long session id */

    if (session_id_length > 32) {
        return 0;
    }

    c = njt_ssl_get_connection(ssl_conn);

    ssl_ctx = c->ssl->session_ctx;
    shm_zone = SSL_CTX_get_ex_data(ssl_ctx, njt_ssl_session_cache_index);

    cache = shm_zone->data;
    shpool = (njt_slab_pool_t *) shm_zone->shm.addr;

    njt_shmtx_lock(&shpool->mutex);

    /* drop one or two expired sessions */
    njt_ssl_expire_sessions(cache, shpool, 1);

#if (NJT_PTR_SIZE == 8)
    n = sizeof(njt_ssl_sess_id_t);
#else
    n = offsetof(njt_ssl_sess_id_t, session) + len;
#endif

    sess_id = njt_slab_alloc_locked(shpool, n);

    if (sess_id == NULL) {

        /* drop the oldest non-expired session and try once more */

        njt_ssl_expire_sessions(cache, shpool, 0);

        sess_id = njt_slab_alloc_locked(shpool, n);

        if (sess_id == NULL) {
            goto failed;
        }
    }

#if (NJT_PTR_SIZE == 8)

    sess_id->session = njt_slab_alloc_locked(shpool, len);

    if (sess_id->session == NULL) {

        /* drop the oldest non-expired session and try once more */

        njt_ssl_expire_sessions(cache, shpool, 0);

        sess_id->session = njt_slab_alloc_locked(shpool, len);

        if(sess_id->session == NULL) {
            goto failed;
        }
    }

#endif

    njt_memcpy(sess_id->session, buf, len);
    njt_memcpy(sess_id->id, session_id, session_id_length);

    hash = njt_crc32_short(session_id, session_id_length);

    njt_log_debug3(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "ssl new session: %08XD:%ud:%d",
                   hash, session_id_length, len);

    sess_id->node.key = hash;
    sess_id->node.data = (u_char) session_id_length;
    sess_id->len = len;

    sess_id->expire = njt_time() + SSL_CTX_get_timeout(ssl_ctx);

    njt_queue_insert_head(&cache->expire_queue, &sess_id->queue);

    njt_rbtree_insert(&cache->session_rbtree, &sess_id->node);

    njt_shmtx_unlock(&shpool->mutex);

    return 0;

failed:

    if (sess_id) {
        njt_slab_free_locked(shpool, sess_id);
    }

    njt_shmtx_unlock(&shpool->mutex);

    if (cache->fail_time != njt_time()) {
        cache->fail_time = njt_time();
        njt_log_error(NJT_LOG_WARN, c->log, 0,
                      "could not allocate new session%s", shpool->log_ctx);
    }

    return 0;
}


static njt_ssl_session_t *
njt_ssl_get_cached_session(njt_ssl_conn_t *ssl_conn,
#if OPENSSL_VERSION_NUMBER >= 0x10100003L
    const
#endif
    u_char *id, int len, int *copy)
{
    size_t                    slen;
    uint32_t                  hash;
    njt_int_t                 rc;
    const u_char             *p;
    njt_shm_zone_t           *shm_zone;
    njt_slab_pool_t          *shpool;
    njt_rbtree_node_t        *node, *sentinel;
    njt_ssl_session_t        *sess;
    njt_ssl_sess_id_t        *sess_id;
    njt_ssl_session_cache_t  *cache;
    u_char                    buf[NJT_SSL_MAX_SESSION_SIZE];
    njt_connection_t         *c;

    hash = njt_crc32_short((u_char *) (uintptr_t) id, (size_t) len);
    *copy = 0;

    c = njt_ssl_get_connection(ssl_conn);

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "ssl get session: %08XD:%d", hash, len);

    shm_zone = SSL_CTX_get_ex_data(c->ssl->session_ctx,
                                   njt_ssl_session_cache_index);

    cache = shm_zone->data;

    sess = NULL;

    shpool = (njt_slab_pool_t *) shm_zone->shm.addr;

    njt_shmtx_lock(&shpool->mutex);

    node = cache->session_rbtree.root;
    sentinel = cache->session_rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        sess_id = (njt_ssl_sess_id_t *) node;

        rc = njt_memn2cmp((u_char *) (uintptr_t) id, sess_id->id,
                          (size_t) len, (size_t) node->data);

        if (rc == 0) {

            if (sess_id->expire > njt_time()) {
                slen = sess_id->len;

                njt_memcpy(buf, sess_id->session, slen);

                njt_shmtx_unlock(&shpool->mutex);

                p = buf;
                sess = d2i_SSL_SESSION(NULL, &p, slen);

                return sess;
            }

            njt_queue_remove(&sess_id->queue);

            njt_rbtree_delete(&cache->session_rbtree, node);

            njt_explicit_memzero(sess_id->session, sess_id->len);

#if (NJT_PTR_SIZE == 8)
            njt_slab_free_locked(shpool, sess_id->session);
#endif
            njt_slab_free_locked(shpool, sess_id);

            sess = NULL;

            goto done;
        }

        node = (rc < 0) ? node->left : node->right;
    }

done:

    njt_shmtx_unlock(&shpool->mutex);

    return sess;
}


void
njt_ssl_remove_cached_session(SSL_CTX *ssl, njt_ssl_session_t *sess)
{
    SSL_CTX_remove_session(ssl, sess);

    njt_ssl_remove_session(ssl, sess);
}


static void
njt_ssl_remove_session(SSL_CTX *ssl, njt_ssl_session_t *sess)
{
    u_char                   *id;
    uint32_t                  hash;
    njt_int_t                 rc;
    unsigned int              len;
    njt_shm_zone_t           *shm_zone;
    njt_slab_pool_t          *shpool;
    njt_rbtree_node_t        *node, *sentinel;
    njt_ssl_sess_id_t        *sess_id;
    njt_ssl_session_cache_t  *cache;

    shm_zone = SSL_CTX_get_ex_data(ssl, njt_ssl_session_cache_index);

    if (shm_zone == NULL) {
        return;
    }

    cache = shm_zone->data;

    id = (u_char *) SSL_SESSION_get_id(sess, &len);

    hash = njt_crc32_short(id, len);

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, njt_cycle->log, 0,
                   "ssl remove session: %08XD:%ud", hash, len);

    shpool = (njt_slab_pool_t *) shm_zone->shm.addr;

    njt_shmtx_lock(&shpool->mutex);

    node = cache->session_rbtree.root;
    sentinel = cache->session_rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        sess_id = (njt_ssl_sess_id_t *) node;

        rc = njt_memn2cmp(id, sess_id->id, len, (size_t) node->data);

        if (rc == 0) {

            njt_queue_remove(&sess_id->queue);

            njt_rbtree_delete(&cache->session_rbtree, node);

            njt_explicit_memzero(sess_id->session, sess_id->len);

#if (NJT_PTR_SIZE == 8)
            njt_slab_free_locked(shpool, sess_id->session);
#endif
            njt_slab_free_locked(shpool, sess_id);

            goto done;
        }

        node = (rc < 0) ? node->left : node->right;
    }

done:

    njt_shmtx_unlock(&shpool->mutex);
}


static void
njt_ssl_expire_sessions(njt_ssl_session_cache_t *cache,
    njt_slab_pool_t *shpool, njt_uint_t n)
{
    time_t              now;
    njt_queue_t        *q;
    njt_ssl_sess_id_t  *sess_id;

    now = njt_time();

    while (n < 3) {

        if (njt_queue_empty(&cache->expire_queue)) {
            return;
        }

        q = njt_queue_last(&cache->expire_queue);

        sess_id = njt_queue_data(q, njt_ssl_sess_id_t, queue);

        if (n++ != 0 && sess_id->expire > now) {
            return;
        }

        njt_queue_remove(q);

        njt_log_debug1(NJT_LOG_DEBUG_EVENT, njt_cycle->log, 0,
                       "expire session: %08Xi", sess_id->node.key);

        njt_rbtree_delete(&cache->session_rbtree, &sess_id->node);

        njt_explicit_memzero(sess_id->session, sess_id->len);

#if (NJT_PTR_SIZE == 8)
        njt_slab_free_locked(shpool, sess_id->session);
#endif
        njt_slab_free_locked(shpool, sess_id);
    }
}


static void
njt_ssl_session_rbtree_insert_value(njt_rbtree_node_t *temp,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel)
{
    njt_rbtree_node_t  **p;
    njt_ssl_sess_id_t   *sess_id, *sess_id_temp;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            sess_id = (njt_ssl_sess_id_t *) node;
            sess_id_temp = (njt_ssl_sess_id_t *) temp;

            p = (njt_memn2cmp(sess_id->id, sess_id_temp->id,
                              (size_t) node->data, (size_t) temp->data)
                 < 0) ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    njt_rbt_red(node);
}


#ifdef SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB

njt_int_t
njt_ssl_session_ticket_keys(njt_conf_t *cf, njt_ssl_t *ssl, njt_array_t *paths)
{
    u_char                 buf[80];
    size_t                 size;
    ssize_t                n;
    njt_str_t             *path;
    njt_file_t             file;
    njt_uint_t             i;
    njt_array_t           *keys;
    njt_file_info_t        fi;
    njt_pool_cleanup_t    *cln;
    njt_ssl_ticket_key_t  *key;

    if (paths == NULL
        && SSL_CTX_get_ex_data(ssl->ctx, njt_ssl_session_cache_index) == NULL)
    {
        return NJT_OK;
    }

    keys = njt_array_create(cf->pool, paths ? paths->nelts : 3,
                            sizeof(njt_ssl_ticket_key_t));
    if (keys == NULL) {
        return NJT_ERROR;
    }

    cln = njt_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NJT_ERROR;
    }

    cln->handler = njt_ssl_ticket_keys_cleanup;
    cln->data = keys;

    if (SSL_CTX_set_ex_data(ssl->ctx, njt_ssl_ticket_keys_index, keys) == 0) {
        njt_ssl_error(NJT_LOG_EMERG, ssl->log, 0,
                      "SSL_CTX_set_ex_data() failed");
        return NJT_ERROR;
    }

    if (SSL_CTX_set_tlsext_ticket_key_cb(ssl->ctx, njt_ssl_ticket_key_callback)
        == 0)
    {
        njt_log_error(NJT_LOG_WARN, cf->log, 0,
                      "nginx was built with Session Tickets support, however, "
                      "now it is linked dynamically to an OpenSSL library "
                      "which has no tlsext support, therefore Session Tickets "
                      "are not available");
        return NJT_OK;
    }

    if (paths == NULL) {

        /* placeholder for keys in shared memory */

        key = njt_array_push_n(keys, 3);
        key[0].shared = 1;
        key[0].expire = 0;
        key[1].shared = 1;
        key[1].expire = 0;
        key[2].shared = 1;
        key[2].expire = 0;

        return NJT_OK;
    }

    path = paths->elts;
    for (i = 0; i < paths->nelts; i++) {

        if (njt_conf_full_name(cf->cycle, &path[i], 1) != NJT_OK) {
            return NJT_ERROR;
        }

        njt_memzero(&file, sizeof(njt_file_t));
        file.name = path[i];
        file.log = cf->log;

        file.fd = njt_open_file(file.name.data, NJT_FILE_RDONLY,
                                NJT_FILE_OPEN, 0);

        if (file.fd == NJT_INVALID_FILE) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, njt_errno,
                               njt_open_file_n " \"%V\" failed", &file.name);
            return NJT_ERROR;
        }

        if (njt_fd_info(file.fd, &fi) == NJT_FILE_ERROR) {
            njt_conf_log_error(NJT_LOG_CRIT, cf, njt_errno,
                               njt_fd_info_n " \"%V\" failed", &file.name);
            goto failed;
        }

        size = njt_file_size(&fi);

        if (size != 48 && size != 80) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "\"%V\" must be 48 or 80 bytes", &file.name);
            goto failed;
        }

        n = njt_read_file(&file, buf, size, 0);

        if (n == NJT_ERROR) {
            njt_conf_log_error(NJT_LOG_CRIT, cf, njt_errno,
                               njt_read_file_n " \"%V\" failed", &file.name);
            goto failed;
        }

        if ((size_t) n != size) {
            njt_conf_log_error(NJT_LOG_CRIT, cf, 0,
                               njt_read_file_n " \"%V\" returned only "
                               "%z bytes instead of %uz", &file.name, n, size);
            goto failed;
        }

        key = njt_array_push(keys);
        if (key == NULL) {
            goto failed;
        }

        key->shared = 0;
        key->expire = 1;

        if (size == 48) {
            key->size = 48;
            njt_memcpy(key->name, buf, 16);
            njt_memcpy(key->aes_key, buf + 16, 16);
            njt_memcpy(key->hmac_key, buf + 32, 16);

        } else {
            key->size = 80;
            njt_memcpy(key->name, buf, 16);
            njt_memcpy(key->hmac_key, buf + 16, 32);
            njt_memcpy(key->aes_key, buf + 48, 32);
        }

        if (njt_close_file(file.fd) == NJT_FILE_ERROR) {
            njt_log_error(NJT_LOG_ALERT, cf->log, njt_errno,
                          njt_close_file_n " \"%V\" failed", &file.name);
        }

        njt_explicit_memzero(&buf, 80);
    }

    return NJT_OK;

failed:

    if (njt_close_file(file.fd) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_ALERT, cf->log, njt_errno,
                      njt_close_file_n " \"%V\" failed", &file.name);
    }

    njt_explicit_memzero(&buf, 80);

    return NJT_ERROR;
}


static int
njt_ssl_ticket_key_callback(njt_ssl_conn_t *ssl_conn,
    unsigned char *name, unsigned char *iv, EVP_CIPHER_CTX *ectx,
    HMAC_CTX *hctx, int enc)
{
    size_t                 size;
    SSL_CTX               *ssl_ctx;
    njt_uint_t             i;
    njt_array_t           *keys;
    njt_connection_t      *c;
    njt_ssl_ticket_key_t  *key;
    const EVP_MD          *digest;
    const EVP_CIPHER      *cipher;

    c = njt_ssl_get_connection(ssl_conn);
    ssl_ctx = c->ssl->session_ctx;

    if (njt_ssl_rotate_ticket_keys(ssl_ctx, c->log) != NJT_OK) {
        return -1;
    }

#ifdef OPENSSL_NO_SHA256
    digest = EVP_sha1();
#else
    digest = EVP_sha256();
#endif

    keys = SSL_CTX_get_ex_data(ssl_ctx, njt_ssl_ticket_keys_index);
    if (keys == NULL) {
        return -1;
    }

    key = keys->elts;

    if (enc == 1) {
        /* encrypt session ticket */

        njt_log_debug3(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "ssl ticket encrypt, key: \"%*xs\" (%s session)",
                       (size_t) 16, key[0].name,
                       SSL_session_reused(ssl_conn) ? "reused" : "new");

        if (key[0].size == 48) {
            cipher = EVP_aes_128_cbc();
            size = 16;

        } else {
            cipher = EVP_aes_256_cbc();
            size = 32;
        }

        if (RAND_bytes(iv, EVP_CIPHER_iv_length(cipher)) != 1) {
            njt_ssl_error(NJT_LOG_ALERT, c->log, 0, "RAND_bytes() failed");
            return -1;
        }

        if (EVP_EncryptInit_ex(ectx, cipher, NULL, key[0].aes_key, iv) != 1) {
            njt_ssl_error(NJT_LOG_ALERT, c->log, 0,
                          "EVP_EncryptInit_ex() failed");
            return -1;
        }

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
        if (HMAC_Init_ex(hctx, key[0].hmac_key, size, digest, NULL) != 1) {
            njt_ssl_error(NJT_LOG_ALERT, c->log, 0, "HMAC_Init_ex() failed");
            return -1;
        }
#else
        HMAC_Init_ex(hctx, key[0].hmac_key, size, digest, NULL);
#endif

        njt_memcpy(name, key[0].name, 16);

        return 1;

    } else {
        /* decrypt session ticket */

        for (i = 0; i < keys->nelts; i++) {
            if (njt_memcmp(name, key[i].name, 16) == 0) {
                goto found;
            }
        }

        njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "ssl ticket decrypt, key: \"%*xs\" not found",
                       (size_t) 16, name);

        return 0;

    found:

        njt_log_debug3(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "ssl ticket decrypt, key: \"%*xs\"%s",
                       (size_t) 16, key[i].name, (i == 0) ? " (default)" : "");

        if (key[i].size == 48) {
            cipher = EVP_aes_128_cbc();
            size = 16;

        } else {
            cipher = EVP_aes_256_cbc();
            size = 32;
        }

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
        if (HMAC_Init_ex(hctx, key[i].hmac_key, size, digest, NULL) != 1) {
            njt_ssl_error(NJT_LOG_ALERT, c->log, 0, "HMAC_Init_ex() failed");
            return -1;
        }
#else
        HMAC_Init_ex(hctx, key[i].hmac_key, size, digest, NULL);
#endif

        if (EVP_DecryptInit_ex(ectx, cipher, NULL, key[i].aes_key, iv) != 1) {
            njt_ssl_error(NJT_LOG_ALERT, c->log, 0,
                          "EVP_DecryptInit_ex() failed");
            return -1;
        }

        /* renew if TLSv1.3 */

#ifdef TLS1_3_VERSION
        if (SSL_version(ssl_conn) == TLS1_3_VERSION) {
            return 2;
        }
#endif

        /* renew if non-default key */

        if (i != 0 && key[i].expire) {
            return 2;
        }

        return 1;
    }
}


static njt_int_t
njt_ssl_rotate_ticket_keys(SSL_CTX *ssl_ctx, njt_log_t *log)
{
    time_t                    now, expire;
    njt_array_t              *keys;
    njt_shm_zone_t           *shm_zone;
    njt_slab_pool_t          *shpool;
    njt_ssl_ticket_key_t     *key;
    njt_ssl_session_cache_t  *cache;
    u_char                    buf[80];

    keys = SSL_CTX_get_ex_data(ssl_ctx, njt_ssl_ticket_keys_index);
    if (keys == NULL) {
        return NJT_OK;
    }

    key = keys->elts;

    if (!key[0].shared) {
        return NJT_OK;
    }

    /*
     * if we don't need to update expiration of the current key
     * and the previous key is still needed, don't sync with shared
     * memory to save some work; in the worst case other worker process
     * will switch to the next key, but this process will still be able
     * to decrypt tickets encrypted with it
     */

    now = njt_time();
    expire = now + SSL_CTX_get_timeout(ssl_ctx);

    if (key[0].expire >= expire && key[1].expire >= now) {
        return NJT_OK;
    }

    shm_zone = SSL_CTX_get_ex_data(ssl_ctx, njt_ssl_session_cache_index);

    cache = shm_zone->data;
    shpool = (njt_slab_pool_t *) shm_zone->shm.addr;

    njt_shmtx_lock(&shpool->mutex);

    key = cache->ticket_keys;

    if (key[0].expire == 0) {

        /* initialize the current key */

        if (RAND_bytes(buf, 80) != 1) {
            njt_ssl_error(NJT_LOG_ALERT, log, 0, "RAND_bytes() failed");
            njt_shmtx_unlock(&shpool->mutex);
            return NJT_ERROR;
        }

        key[0].shared = 1;
        key[0].expire = expire;
        key[0].size = 80;
        njt_memcpy(key[0].name, buf, 16);
        njt_memcpy(key[0].hmac_key, buf + 16, 32);
        njt_memcpy(key[0].aes_key, buf + 48, 32);

        njt_explicit_memzero(&buf, 80);

        njt_log_debug2(NJT_LOG_DEBUG_EVENT, log, 0,
                       "ssl ticket key: \"%*xs\"",
                       (size_t) 16, key[0].name);
        
        /*
         * copy the current key to the next key, as initialization of
         * the previous key will replace the current key with the next
         * key
         */

        key[2] = key[0];
    }

    if (key[1].expire < now) {

        /*
         * if the previous key is no longer needed (or not initialized),
         * replace it with the current key, replace the current key with
         * he next key, and generate new next key
         */

        key[1] = key[0];
        key[0] = key[2];

        if (RAND_bytes(buf, 80) != 1) {
            njt_ssl_error(NJT_LOG_ALERT, log, 0, "RAND_bytes() failed");
            njt_shmtx_unlock(&shpool->mutex);
            return NJT_ERROR;
        }

        key[2].shared = 1;
        key[2].expire = 0;
        key[2].size = 80;
        njt_memcpy(key[2].name, buf, 16);
        njt_memcpy(key[2].hmac_key, buf + 16, 32);
        njt_memcpy(key[2].aes_key, buf + 48, 32);

        njt_explicit_memzero(&buf, 80);

        njt_log_debug2(NJT_LOG_DEBUG_EVENT, log, 0,
                       "ssl ticket key: \"%*xs\"",
                       (size_t) 16, key[2].name);
    }

    /*
     * update expiration of the current key: it is going to be needed
     * at least till the session being created expires
     */

    if (expire > key[0].expire) {
        key[0].expire = expire;
    }

    /* sync keys to the worker process memory */

    njt_memcpy(keys->elts, cache->ticket_keys,
               2 * sizeof(njt_ssl_ticket_key_t));

    njt_shmtx_unlock(&shpool->mutex);

    return NJT_OK;
}



static void
njt_ssl_ticket_keys_cleanup(void *data)
{
    njt_array_t  *keys = data;

    njt_explicit_memzero(keys->elts,
                         keys->nelts * sizeof(njt_ssl_ticket_key_t));
}

#else

njt_int_t
njt_ssl_session_ticket_keys(njt_conf_t *cf, njt_ssl_t *ssl, njt_array_t *paths)
{
    if (paths) {
        njt_log_error(NJT_LOG_WARN, ssl->log, 0,
                      "\"ssl_session_ticket_key\" ignored, not supported");
    }

    return NJT_OK;
}

#endif


void
njt_ssl_cleanup_ctx(void *data)
{
    njt_ssl_t  *ssl = data;

    X509  *cert, *next;

    cert = SSL_CTX_get_ex_data(ssl->ctx, njt_ssl_certificate_index);

    while (cert) {
        next = X509_get_ex_data(cert, njt_ssl_next_certificate_index);
        X509_free(cert);
        cert = next;
    }

    SSL_CTX_free(ssl->ctx);
}


njt_int_t
njt_ssl_check_host(njt_connection_t *c, njt_str_t *name)
{
    X509   *cert;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return NJT_ERROR;
    }
#if  X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT 

    /* X509_check_host() is only available in OpenSSL 1.0.2+ */

    if (name->len == 0) {
        goto failed;
    }

    if (X509_check_host(cert, (char *) name->data, name->len, 0, NULL) != 1) {
        njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "X509_check_host(): no match");
        goto failed;
    }

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "X509_check_host(): match");

    goto found;

#else
    {
    int                      n, i;
    X509_NAME               *sname;
    ASN1_STRING             *str;
    X509_NAME_ENTRY         *entry;
    GENERAL_NAME            *altname;
    STACK_OF(GENERAL_NAME)  *altnames;

    /*
     * As per RFC6125 and RFC2818, we check subjectAltName extension,
     * and if it's not present - commonName in Subject is checked.
     */

    altnames = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);

    if (altnames) {
        n = sk_GENERAL_NAME_num(altnames);

        for (i = 0; i < n; i++) {
            altname = sk_GENERAL_NAME_value(altnames, i);

            if (altname->type != GEN_DNS && altname->type != GEN_URI) {
                continue;
            }

            str = altname->d.dNSName;
	   /*
            njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                           "SSL subjectAltName: \"%*s\"",
                           ASN1_STRING_length(str), ASN1_STRING_data(str));
		*/
            if (njt_ssl_check_name(name, str) == NJT_OK) {
               // njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
               //                "SSL subjectAltName: match");
                GENERAL_NAMES_free(altnames);
                goto found;
            }
        }

        njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL subjectAltName: no match");

        GENERAL_NAMES_free(altnames);
        goto failed;
    }

    /*
     * If there is no subjectAltName extension, check commonName
     * in Subject.  While RFC2818 requires to only check "most specific"
     * CN, both Apache and OpenSSL check all CNs, and so do we.
     */

    sname = X509_get_subject_name(cert);

    if (sname == NULL) {
        goto failed;
    }

    i = -1;
    for ( ;; ) {
        i = X509_NAME_get_index_by_NID(sname, NID_commonName, i);

        if (i < 0) {
            break;
        }

        entry = X509_NAME_get_entry(sname, i);
        str = X509_NAME_ENTRY_get_data(entry);
	/*
        njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "SSL commonName: \"%*s\"",
                       ASN1_STRING_length(str), ASN1_STRING_data(str));
	*/
        if (njt_ssl_check_name(name, str) == NJT_OK) {
            njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                           "SSL commonName: match");
            goto found;
        }
    }

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL commonName: no match");
    }
#endif

failed:

    X509_free(cert);
    return NJT_ERROR;

found:

    X509_free(cert);
    return NJT_OK;
}


#if X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT  == 0
static njt_int_t
njt_ssl_check_name(njt_str_t *name, ASN1_STRING *pattern)
{
    u_char  *s, *p, *end;
    size_t   slen, plen;

    s = name->data;
    slen = name->len;

    p = njt_string_data(pattern);
    plen = ASN1_STRING_length(pattern);

    if (slen == plen && njt_strncasecmp(s, p, plen) == 0) {
        return NJT_OK;
    }

    if (plen > 2 && p[0] == '*' && p[1] == '.') {
        plen -= 1;
        p += 1;

        end = s + slen;
        s = njt_strlchr(s, end, '.');

        if (s == NULL) {
            return NJT_ERROR;
        }

        slen = end - s;

        if (plen == slen && njt_strncasecmp(s, p, plen) == 0) {
            return NJT_OK;
        }
    }

    return NJT_ERROR;
}
#endif


njt_int_t
njt_ssl_get_protocol(njt_connection_t *c, njt_pool_t *pool, njt_str_t *s)
{
    s->data = (u_char *) SSL_get_version(c->ssl->connection);
    return NJT_OK;
}


njt_int_t
njt_ssl_get_cipher_name(njt_connection_t *c, njt_pool_t *pool, njt_str_t *s)
{
    s->data = (u_char *) SSL_get_cipher_name(c->ssl->connection);
    return NJT_OK;
}


njt_int_t
njt_ssl_get_ciphers(njt_connection_t *c, njt_pool_t *pool, njt_str_t *s)
{
#ifdef SSL_CTRL_GET_RAW_CIPHERLIST

    int                n, i, bytes;
    size_t             len;
    u_char            *ciphers, *p;
    const SSL_CIPHER  *cipher;

    bytes = SSL_get0_raw_cipherlist(c->ssl->connection, NULL);
    n = SSL_get0_raw_cipherlist(c->ssl->connection, &ciphers);

    if (n <= 0) {
        s->len = 0;
        return NJT_OK;
    }

    len = 0;
    n /= bytes;

    for (i = 0; i < n; i++) {
        cipher = SSL_CIPHER_find(c->ssl->connection, ciphers + i * bytes);

        if (cipher) {
            len += njt_strlen(SSL_CIPHER_get_name(cipher));

        } else {
            len += sizeof("0x") - 1 + bytes * (sizeof("00") - 1);
        }

        len += sizeof(":") - 1;
    }

    s->data = njt_pnalloc(pool, len);
    if (s->data == NULL) {
        return NJT_ERROR;
    }

    p = s->data;

    for (i = 0; i < n; i++) {
        cipher = SSL_CIPHER_find(c->ssl->connection, ciphers + i * bytes);

        if (cipher) {
            p = njt_sprintf(p, "%s", SSL_CIPHER_get_name(cipher));

        } else {
            p = njt_sprintf(p, "0x");
            p = njt_hex_dump(p, ciphers + i * bytes, bytes);
        }

        *p++ = ':';
    }

    p--;

    s->len = p - s->data;

#else

    u_char  buf[4096];

    if (SSL_get_shared_ciphers(c->ssl->connection, (char *) buf, 4096)
        == NULL)
    {
        s->len = 0;
        return NJT_OK;
    }

    s->len = njt_strlen(buf);
    s->data = njt_pnalloc(pool, s->len);
    if (s->data == NULL) {
        return NJT_ERROR;
    }

    njt_memcpy(s->data, buf, s->len);

#endif

    return NJT_OK;
}


njt_int_t
njt_ssl_get_curve(njt_connection_t *c, njt_pool_t *pool, njt_str_t *s)
{
#ifdef SSL_get_negotiated_group

    int  nid;

    nid = SSL_get_negotiated_group(c->ssl->connection);

    if (nid != NID_undef) {

        if ((nid & TLSEXT_nid_unknown) == 0) {
            s->len = njt_strlen(OBJ_nid2sn(nid));
            s->data = (u_char *) OBJ_nid2sn(nid);
            return NJT_OK;
        }

        s->len = sizeof("0x0000") - 1;

        s->data = njt_pnalloc(pool, s->len);
        if (s->data == NULL) {
            return NJT_ERROR;
        }

        njt_sprintf(s->data, "0x%04xd", nid & 0xffff);

        return NJT_OK;
    }

#endif

    s->len = 0;
    return NJT_OK;
}


njt_int_t
njt_ssl_get_curves(njt_connection_t *c, njt_pool_t *pool, njt_str_t *s)
{
#ifdef SSL_CTRL_GET_CURVES

    int         *curves, n, i, nid;
    u_char      *p;
    size_t       len;

    n = SSL_get1_curves(c->ssl->connection, NULL);

    if (n <= 0) {
        s->len = 0;
        return NJT_OK;
    }

    curves = njt_palloc(pool, n * sizeof(int));

    n = SSL_get1_curves(c->ssl->connection, curves);
    len = 0;

    for (i = 0; i < n; i++) {
        nid = curves[i];

        if (nid & TLSEXT_nid_unknown) {
            len += sizeof("0x0000") - 1;

        } else {
            len += njt_strlen(OBJ_nid2sn(nid));
        }

        len += sizeof(":") - 1;
    }

    s->data = njt_pnalloc(pool, len);
    if (s->data == NULL) {
        return NJT_ERROR;
    }

    p = s->data;

    for (i = 0; i < n; i++) {
        nid = curves[i];

        if (nid & TLSEXT_nid_unknown) {
            p = njt_sprintf(p, "0x%04xd", nid & 0xffff);

        } else {
            p = njt_sprintf(p, "%s", OBJ_nid2sn(nid));
        }

        *p++ = ':';
    }

    p--;

    s->len = p - s->data;

#else

    s->len = 0;

#endif

    return NJT_OK;
}


njt_int_t
njt_ssl_get_session_id(njt_connection_t *c, njt_pool_t *pool, njt_str_t *s)
{
    u_char        *buf;
    SSL_SESSION   *sess;
    unsigned int   len;

    sess = SSL_get0_session(c->ssl->connection);
    if (sess == NULL) {
        s->len = 0;
        return NJT_OK;
    }

    buf = (u_char *) SSL_SESSION_get_id(sess, &len);

    s->len = 2 * len;
    s->data = njt_pnalloc(pool, 2 * len);
    if (s->data == NULL) {
        return NJT_ERROR;
    }

    njt_hex_dump(s->data, buf, len);

    return NJT_OK;
}


njt_int_t
njt_ssl_get_session_reused(njt_connection_t *c, njt_pool_t *pool, njt_str_t *s)
{
    if (SSL_session_reused(c->ssl->connection)) {
        njt_str_set(s, "r");

    } else {
        njt_str_set(s, ".");
    }

    return NJT_OK;
}


njt_int_t
njt_ssl_get_early_data(njt_connection_t *c, njt_pool_t *pool, njt_str_t *s)
{
    s->len = 0;

#ifdef SSL_ERROR_EARLY_DATA_REJECTED

    /* BoringSSL */

    if (SSL_in_early_data(c->ssl->connection)) {
        njt_str_set(s, "1");
    }

#elif defined SSL_READ_EARLY_DATA_SUCCESS

    /* OpenSSL */

    if (!SSL_is_init_finished(c->ssl->connection)) {
        njt_str_set(s, "1");
    }

#endif

    return NJT_OK;
}


njt_int_t
njt_ssl_get_server_name(njt_connection_t *c, njt_pool_t *pool, njt_str_t *s)
{
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

    size_t       len;
    const char  *name;

    name = SSL_get_servername(c->ssl->connection, TLSEXT_NAMETYPE_host_name);

    if (name) {
        len = njt_strlen(name);

        s->len = len;
        s->data = njt_pnalloc(pool, len);
        if (s->data == NULL) {
            return NJT_ERROR;
        }

        njt_memcpy(s->data, name, len);

        return NJT_OK;
    }

#endif

    s->len = 0;
    return NJT_OK;
}


njt_int_t
njt_ssl_get_alpn_protocol(njt_connection_t *c, njt_pool_t *pool, njt_str_t *s)
{
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation

    unsigned int          len;
    const unsigned char  *data;

    SSL_get0_alpn_selected(c->ssl->connection, &data, &len);

    if (len > 0) {

        s->data = njt_pnalloc(pool, len);
        if (s->data == NULL) {
            return NJT_ERROR;
        }

        njt_memcpy(s->data, data, len);
        s->len = len;

        return NJT_OK;
    }

#endif

    s->len = 0;
    return NJT_OK;
}


njt_int_t
njt_ssl_get_raw_certificate(njt_connection_t *c, njt_pool_t *pool, njt_str_t *s)
{
    size_t   len;
    BIO     *bio;
    X509    *cert;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return NJT_OK;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        njt_ssl_error(NJT_LOG_ALERT, c->log, 0, "BIO_new() failed");
        X509_free(cert);
        return NJT_ERROR;
    }

    if (PEM_write_bio_X509(bio, cert) == 0) {
        njt_ssl_error(NJT_LOG_ALERT, c->log, 0, "PEM_write_bio_X509() failed");
        goto failed;
    }

    len = BIO_pending(bio);
    s->len = len;

    s->data = njt_pnalloc(pool, len);
    if (s->data == NULL) {
        goto failed;
    }

    BIO_read(bio, s->data, len);

    BIO_free(bio);
    X509_free(cert);

    return NJT_OK;

failed:

    BIO_free(bio);
    X509_free(cert);

    return NJT_ERROR;
}


njt_int_t
njt_ssl_get_certificate(njt_connection_t *c, njt_pool_t *pool, njt_str_t *s)
{
    u_char      *p;
    size_t       len;
    njt_uint_t   i;
    njt_str_t    cert;

    if (njt_ssl_get_raw_certificate(c, pool, &cert) != NJT_OK) {
        return NJT_ERROR;
    }

    if (cert.len == 0) {
        s->len = 0;
        return NJT_OK;
    }

    len = cert.len - 1;

    for (i = 0; i < cert.len - 1; i++) {
        if (cert.data[i] == LF) {
            len++;
        }
    }

    s->len = len;
    s->data = njt_pnalloc(pool, len);
    if (s->data == NULL) {
        return NJT_ERROR;
    }

    p = s->data;

    for (i = 0; i < cert.len - 1; i++) {
        *p++ = cert.data[i];
        if (cert.data[i] == LF) {
            *p++ = '\t';
        }
    }

    return NJT_OK;
}


njt_int_t
njt_ssl_get_escaped_certificate(njt_connection_t *c, njt_pool_t *pool,
    njt_str_t *s)
{
    njt_str_t  cert;
    uintptr_t  n;

    if (njt_ssl_get_raw_certificate(c, pool, &cert) != NJT_OK) {
        return NJT_ERROR;
    }

    if (cert.len == 0) {
        s->len = 0;
        return NJT_OK;
    }

    n = njt_escape_uri(NULL, cert.data, cert.len, NJT_ESCAPE_URI_COMPONENT);

    s->len = cert.len + n * 2;
    s->data = njt_pnalloc(pool, s->len);
    if (s->data == NULL) {
        return NJT_ERROR;
    }

    njt_escape_uri(s->data, cert.data, cert.len, NJT_ESCAPE_URI_COMPONENT);

    return NJT_OK;
}


njt_int_t
njt_ssl_get_subject_dn(njt_connection_t *c, njt_pool_t *pool, njt_str_t *s)
{
    BIO        *bio;
    X509       *cert;
    X509_NAME  *name;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return NJT_OK;
    }

    name = X509_get_subject_name(cert);
    if (name == NULL) {
        X509_free(cert);
        return NJT_ERROR;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        njt_ssl_error(NJT_LOG_ALERT, c->log, 0, "BIO_new() failed");
        X509_free(cert);
        return NJT_ERROR;
    }

    if (X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253) < 0) {
        njt_ssl_error(NJT_LOG_ALERT, c->log, 0, "X509_NAME_print_ex() failed");
        goto failed;
    }

    s->len = BIO_pending(bio);
    s->data = njt_pnalloc(pool, s->len);
    if (s->data == NULL) {
        goto failed;
    }

    BIO_read(bio, s->data, s->len);

    BIO_free(bio);
    X509_free(cert);

    return NJT_OK;

failed:

    BIO_free(bio);
    X509_free(cert);

    return NJT_ERROR;
}


njt_int_t
njt_ssl_get_issuer_dn(njt_connection_t *c, njt_pool_t *pool, njt_str_t *s)
{
    BIO        *bio;
    X509       *cert;
    X509_NAME  *name;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return NJT_OK;
    }

    name = X509_get_issuer_name(cert);
    if (name == NULL) {
        X509_free(cert);
        return NJT_ERROR;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        njt_ssl_error(NJT_LOG_ALERT, c->log, 0, "BIO_new() failed");
        X509_free(cert);
        return NJT_ERROR;
    }

    if (X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253) < 0) {
        njt_ssl_error(NJT_LOG_ALERT, c->log, 0, "X509_NAME_print_ex() failed");
        goto failed;
    }

    s->len = BIO_pending(bio);
    s->data = njt_pnalloc(pool, s->len);
    if (s->data == NULL) {
        goto failed;
    }

    BIO_read(bio, s->data, s->len);

    BIO_free(bio);
    X509_free(cert);

    return NJT_OK;

failed:

    BIO_free(bio);
    X509_free(cert);

    return NJT_ERROR;
}


njt_int_t
njt_ssl_get_subject_dn_legacy(njt_connection_t *c, njt_pool_t *pool,
    njt_str_t *s)
{
    char       *p;
    size_t      len;
    X509       *cert;
    X509_NAME  *name;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return NJT_OK;
    }

    name = X509_get_subject_name(cert);
    if (name == NULL) {
        X509_free(cert);
        return NJT_ERROR;
    }

    p = X509_NAME_oneline(name, NULL, 0);
    if (p == NULL) {
        njt_ssl_error(NJT_LOG_ALERT, c->log, 0, "X509_NAME_oneline() failed");
        X509_free(cert);
        return NJT_ERROR;
    }

    for (len = 0; p[len]; len++) { /* void */ }

    s->len = len;
    s->data = njt_pnalloc(pool, len);
    if (s->data == NULL) {
        OPENSSL_free(p);
        X509_free(cert);
        return NJT_ERROR;
    }

    njt_memcpy(s->data, p, len);

    OPENSSL_free(p);
    X509_free(cert);

    return NJT_OK;
}


njt_int_t
njt_ssl_get_issuer_dn_legacy(njt_connection_t *c, njt_pool_t *pool,
    njt_str_t *s)
{
    char       *p;
    size_t      len;
    X509       *cert;
    X509_NAME  *name;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return NJT_OK;
    }

    name = X509_get_issuer_name(cert);
    if (name == NULL) {
        X509_free(cert);
        return NJT_ERROR;
    }

    p = X509_NAME_oneline(name, NULL, 0);
    if (p == NULL) {
        njt_ssl_error(NJT_LOG_ALERT, c->log, 0, "X509_NAME_oneline() failed");
        X509_free(cert);
        return NJT_ERROR;
    }

    for (len = 0; p[len]; len++) { /* void */ }

    s->len = len;
    s->data = njt_pnalloc(pool, len);
    if (s->data == NULL) {
        OPENSSL_free(p);
        X509_free(cert);
        return NJT_ERROR;
    }

    njt_memcpy(s->data, p, len);

    OPENSSL_free(p);
    X509_free(cert);

    return NJT_OK;
}


njt_int_t
njt_ssl_get_serial_number(njt_connection_t *c, njt_pool_t *pool, njt_str_t *s)
{
    size_t   len;
    X509    *cert;
    BIO     *bio;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return NJT_OK;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        njt_ssl_error(NJT_LOG_ALERT, c->log, 0, "BIO_new() failed");
        X509_free(cert);
        return NJT_ERROR;
    }

    i2a_ASN1_INTEGER(bio, X509_get_serialNumber(cert));
    len = BIO_pending(bio);

    s->len = len;
    s->data = njt_pnalloc(pool, len);
    if (s->data == NULL) {
        BIO_free(bio);
        X509_free(cert);
        return NJT_ERROR;
    }

    BIO_read(bio, s->data, len);
    BIO_free(bio);
    X509_free(cert);

    return NJT_OK;
}


njt_int_t
njt_ssl_get_fingerprint(njt_connection_t *c, njt_pool_t *pool, njt_str_t *s)
{
    X509          *cert;
    unsigned int   len;
    u_char         buf[EVP_MAX_MD_SIZE];

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return NJT_OK;
    }

    if (!X509_digest(cert, EVP_sha1(), buf, &len)) {
        njt_ssl_error(NJT_LOG_ALERT, c->log, 0, "X509_digest() failed");
        X509_free(cert);
        return NJT_ERROR;
    }

    s->len = 2 * len;
    s->data = njt_pnalloc(pool, 2 * len);
    if (s->data == NULL) {
        X509_free(cert);
        return NJT_ERROR;
    }

    njt_hex_dump(s->data, buf, len);

    X509_free(cert);

    return NJT_OK;
}


njt_int_t
njt_ssl_get_client_verify(njt_connection_t *c, njt_pool_t *pool, njt_str_t *s)
{
    X509        *cert;
    long         rc;
    const char  *str;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        njt_str_set(s, "NONE");
        return NJT_OK;
    }

    X509_free(cert);

    rc = SSL_get_verify_result(c->ssl->connection);

    if (rc == X509_V_OK) {
        if (njt_ssl_ocsp_get_status(c, &str) == NJT_OK) {
            njt_str_set(s, "SUCCESS");
            return NJT_OK;
        }

    } else {
        str = X509_verify_cert_error_string(rc);
    }

    s->data = njt_pnalloc(pool, sizeof("FAILED:") - 1 + njt_strlen(str));
    if (s->data == NULL) {
        return NJT_ERROR;
    }

    s->len = njt_sprintf(s->data, "FAILED:%s", str) - s->data;

    return NJT_OK;
}


njt_int_t
njt_ssl_get_client_v_start(njt_connection_t *c, njt_pool_t *pool, njt_str_t *s)
{
    BIO     *bio;
    X509    *cert;
    size_t   len;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return NJT_OK;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        njt_ssl_error(NJT_LOG_ALERT, c->log, 0, "BIO_new() failed");
        X509_free(cert);
        return NJT_ERROR;
    }

#if OPENSSL_VERSION_NUMBER > 0x10100000L
    ASN1_TIME_print(bio, X509_get0_notBefore(cert));
#else
    ASN1_TIME_print(bio, X509_get_notBefore(cert));
#endif

    len = BIO_pending(bio);

    s->len = len;
    s->data = njt_pnalloc(pool, len);
    if (s->data == NULL) {
        BIO_free(bio);
        X509_free(cert);
        return NJT_ERROR;
    }

    BIO_read(bio, s->data, len);
    BIO_free(bio);
    X509_free(cert);

    return NJT_OK;
}


njt_int_t
njt_ssl_get_client_v_end(njt_connection_t *c, njt_pool_t *pool, njt_str_t *s)
{
    BIO     *bio;
    X509    *cert;
    size_t   len;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return NJT_OK;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        njt_ssl_error(NJT_LOG_ALERT, c->log, 0, "BIO_new() failed");
        X509_free(cert);
        return NJT_ERROR;
    }

#if OPENSSL_VERSION_NUMBER > 0x10100000L
    ASN1_TIME_print(bio, X509_get0_notAfter(cert));
#else
    ASN1_TIME_print(bio, X509_get_notAfter(cert));
#endif

    len = BIO_pending(bio);

    s->len = len;
    s->data = njt_pnalloc(pool, len);
    if (s->data == NULL) {
        BIO_free(bio);
        X509_free(cert);
        return NJT_ERROR;
    }

    BIO_read(bio, s->data, len);
    BIO_free(bio);
    X509_free(cert);

    return NJT_OK;
}


njt_int_t
njt_ssl_get_client_v_remain(njt_connection_t *c, njt_pool_t *pool, njt_str_t *s)
{
    X509    *cert;
    time_t   now, end;

    s->len = 0;

    cert = SSL_get_peer_certificate(c->ssl->connection);
    if (cert == NULL) {
        return NJT_OK;
    }

#if OPENSSL_VERSION_NUMBER > 0x10100000L
    end = njt_ssl_parse_time(X509_get0_notAfter(cert), c->log);
#else
    end = njt_ssl_parse_time(X509_get_notAfter(cert), c->log);
#endif

    if (end == (time_t) NJT_ERROR) {
        X509_free(cert);
        return NJT_OK;
    }

    now = njt_time();

    if (end < now + 86400) {
        njt_str_set(s, "0");
        X509_free(cert);
        return NJT_OK;
    }

    s->data = njt_pnalloc(pool, NJT_TIME_T_LEN);
    if (s->data == NULL) {
        X509_free(cert);
        return NJT_ERROR;
    }

    s->len = njt_sprintf(s->data, "%T", (end - now) / 86400) - s->data;

    X509_free(cert);

    return NJT_OK;
}


static time_t
njt_ssl_parse_time(
#if OPENSSL_VERSION_NUMBER > 0x10100000L
    const
#endif
    ASN1_TIME *asn1time, njt_log_t *log)
{
    BIO     *bio;
    char    *value;
    size_t   len;
    time_t   time;

    /*
     * OpenSSL doesn't provide a way to convert ASN1_TIME
     * into time_t.  To do this, we use ASN1_TIME_print(),
     * which uses the "MMM DD HH:MM:SS YYYY [GMT]" format (e.g.,
     * "Feb  3 00:55:52 2015 GMT"), and parse the result.
     */

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        njt_ssl_error(NJT_LOG_ALERT, log, 0, "BIO_new() failed");
        return NJT_ERROR;
    }

    /* fake weekday prepended to match C asctime() format */

    BIO_write(bio, "Tue ", sizeof("Tue ") - 1);
    ASN1_TIME_print(bio, asn1time);
    len = BIO_get_mem_data(bio, &value);

    time = njt_parse_http_time((u_char *) value, len);

    BIO_free(bio);

    return time;
}


#if (NJT_HTTP_MULTICERT || NJT_STREAM_MULTICERT)

char *
njt_ssl_certificate_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    char  *p = conf;

    njt_str_t    *value, *s;
    njt_array_t  **a;
#if (NJT_HAVE_NTLS)
    u_char       *data;
#endif

    a = (njt_array_t **) (p + cmd->offset);

    if (*a == NJT_CONF_UNSET_PTR) {

        *a = njt_array_create(cf->pool, 4, sizeof(njt_str_t));
        if (*a == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    s = njt_array_push(*a);
    if (s == NULL) {
        return NJT_CONF_ERROR;
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2) {
        *s = value[1];
        return NJT_CONF_OK;
    }

#if (NJT_HAVE_NTLS)

    /* prefix certificate paths with 'sign:' and 'enc:', null-terminate */

    s->len = sizeof("sign:") - 1 + value[1].len;

    s->data = njt_pcalloc(cf->pool, s->len + 1);
    if (s->data == NULL) {
        return NJT_CONF_ERROR;
    }

    data = njt_cpymem(s->data, "sign:", sizeof("sign:") - 1);
    njt_memcpy(data, value[1].data, value[1].len);

    s = njt_array_push(*a);
    if (s == NULL) {
        return NJT_CONF_ERROR;
    }

    s->len = sizeof("enc:") - 1 + value[2].len;

    s->data = njt_pcalloc(cf->pool, s->len + 1);
    if (s->data == NULL) {
        return NJT_CONF_ERROR;
    }

    data = njt_cpymem(s->data, "enc:", sizeof("enc:") - 1);
    njt_memcpy(data, value[2].data, value[2].len);

    return NJT_CONF_OK;

#else

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "NTLS support is not enabled, dual certs not supported");

    return NJT_CONF_ERROR;

#endif
}

#endif


static void *
njt_openssl_create_conf(njt_cycle_t *cycle)
{
    njt_openssl_conf_t  *oscf;

    oscf = njt_pcalloc(cycle->pool, sizeof(njt_openssl_conf_t));
    if (oscf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     oscf->engine = 0;
     */

    return oscf;
}


static char *
njt_openssl_engine(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
#ifndef OPENSSL_NO_ENGINE

    njt_openssl_conf_t *oscf = conf;

    ENGINE     *engine;
    njt_str_t  *value;

    if (oscf->engine) {
        return "is duplicate";
    }

    oscf->engine = 1;

    value = cf->args->elts;

    engine = ENGINE_by_id((char *) value[1].data);

    if (engine == NULL) {
        njt_ssl_error(NJT_LOG_EMERG, cf->log, 0,
                      "ENGINE_by_id(\"%V\") failed", &value[1]);
        return NJT_CONF_ERROR;
    }

    if (ENGINE_set_default(engine, ENGINE_METHOD_ALL) == 0) {
        njt_ssl_error(NJT_LOG_EMERG, cf->log, 0,
                      "ENGINE_set_default(\"%V\", ENGINE_METHOD_ALL) failed",
                      &value[1]);

        ENGINE_free(engine);

        return NJT_CONF_ERROR;
    }

    ENGINE_free(engine);

    return NJT_CONF_OK;

#else

    return "is not supported";

#endif
}


static void
njt_openssl_exit(njt_cycle_t *cycle)
{
#if OPENSSL_VERSION_NUMBER < 0x10100003L

    EVP_cleanup();
#ifndef OPENSSL_NO_ENGINE
    ENGINE_cleanup();
#endif

#endif
}
