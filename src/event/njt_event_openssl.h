
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_EVENT_OPENSSL_H_INCLUDED_
#define _NJT_EVENT_OPENSSL_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>

#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/ssl.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/evp.h>
#if (NJT_QUIC)
#ifdef OPENSSL_IS_BORINGSSL
#include <openssl/hkdf.h>
#include <openssl/chacha.h>
#else
#include <openssl/kdf.h>
#endif
#endif
#include <openssl/hmac.h>
#ifndef OPENSSL_NO_OCSP
#include <openssl/ocsp.h>
#endif
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define NJT_SSL_NAME     "OpenSSL"


#if (defined LIBRESSL_VERSION_NUMBER && OPENSSL_VERSION_NUMBER == 0x20000000L)
#undef OPENSSL_VERSION_NUMBER
#if (LIBRESSL_VERSION_NUMBER >= 0x2080000fL)
#define OPENSSL_VERSION_NUMBER  0x1010000fL
#else
#define OPENSSL_VERSION_NUMBER  0x1000107fL
#endif
#endif


#if (OPENSSL_VERSION_NUMBER >= 0x10100001L)

#define njt_ssl_version()       OpenSSL_version(OPENSSL_VERSION)

#else

#define njt_ssl_version()       SSLeay_version(SSLEAY_VERSION)

#endif


#define njt_ssl_session_t       SSL_SESSION
#define njt_ssl_conn_t          SSL


#if (OPENSSL_VERSION_NUMBER < 0x10002000L)
#define SSL_is_server(s)        (s)->server
#endif


#if (OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined SSL_get_peer_certificate)
#define SSL_get_peer_certificate(s)  SSL_get1_peer_certificate(s)
#endif


#if (OPENSSL_VERSION_NUMBER < 0x30000000L && !defined ERR_peek_error_data)
#define ERR_peek_error_data(d, f)    ERR_peek_error_line_data(NULL, NULL, d, f)
#endif


typedef struct njt_ssl_ocsp_s  njt_ssl_ocsp_t;


struct njt_ssl_s {
    SSL_CTX                    *ctx;
    njt_log_t                  *log;
    size_t                      buffer_size;
};


struct njt_ssl_connection_s {
    njt_ssl_conn_t             *connection;
    SSL_CTX                    *session_ctx;

    njt_int_t                   last;
    njt_buf_t                  *buf;
    size_t                      buffer_size;

    njt_connection_handler_pt   handler;

    njt_ssl_session_t          *session;
    njt_connection_handler_pt   save_session;

    njt_event_handler_pt        saved_read_handler;
    njt_event_handler_pt        saved_write_handler;

    njt_ssl_ocsp_t             *ocsp;

    u_char                      early_buf;

    unsigned                    handshaked:1;
    unsigned                    handshake_rejected:1;
    unsigned                    renegotiation:1;
    unsigned                    buffer:1;
    unsigned                    sendfile:1;
    unsigned                    no_wait_shutdown:1;
    unsigned                    no_send_shutdown:1;
    unsigned                    shutdown_without_free:1;
    unsigned                    handshake_buffer_set:1;
    unsigned                    session_timeout_set:1;
    unsigned                    try_early_data:1;
    unsigned                    in_early:1;
    unsigned                    in_ocsp:1;
    unsigned                    early_preread:1;
    unsigned                    write_blocked:1;
};


#define NJT_SSL_NO_SCACHE            -2
#define NJT_SSL_NONE_SCACHE          -3
#define NJT_SSL_NO_BUILTIN_SCACHE    -4
#define NJT_SSL_DFLT_BUILTIN_SCACHE  -5


#define NJT_SSL_MAX_SESSION_SIZE  4096

typedef struct njt_ssl_sess_id_s  njt_ssl_sess_id_t;

struct njt_ssl_sess_id_s {
    njt_rbtree_node_t           node;
    size_t                      len;
    njt_queue_t                 queue;
    time_t                      expire;
    u_char                      id[32];
#if (NJT_PTR_SIZE == 8)
    u_char                      *session;
#else
    u_char                      session[1];
#endif
};


typedef struct {
    u_char                      name[16];
    u_char                      hmac_key[32];
    u_char                      aes_key[32];
    time_t                      expire;
    unsigned                    size:8;
    unsigned                    shared:1;
} njt_ssl_ticket_key_t;


typedef struct {
    njt_rbtree_t                session_rbtree;
    njt_rbtree_node_t           sentinel;
    njt_queue_t                 expire_queue;
    njt_ssl_ticket_key_t        ticket_keys[3];
    time_t                      fail_time;
} njt_ssl_session_cache_t;


#define NJT_SSL_SSLv2    0x0002
#define NJT_SSL_SSLv3    0x0004
#define NJT_SSL_TLSv1    0x0008
#define NJT_SSL_TLSv1_1  0x0010
#define NJT_SSL_TLSv1_2  0x0020
#define NJT_SSL_TLSv1_3  0x0040


#define NJT_SSL_BUFFER   1
#define NJT_SSL_CLIENT   2

#define NJT_SSL_BUFSIZE  16384

#if (NJT_HAVE_NTLS)

#define NJT_SSL_NTLS_CERT_REGULAR     0
#define NJT_SSL_NTLS_CERT_SIGN        1
#define NJT_SSL_NTLS_CERT_ENC         2

#endif


njt_int_t njt_ssl_init(njt_log_t *log);
njt_int_t njt_ssl_create(njt_ssl_t *ssl, njt_uint_t protocols, void *data);

//add by clb
njt_int_t njt_ssl_get_certificate_type(njt_conf_t *cf, njt_ssl_t *ssl, njt_str_t *cert,
    njt_str_t *key, njt_uint_t *cert_type);
njt_int_t njt_ssl_set_certificates_type(njt_conf_t *cf, njt_ssl_t *ssl, njt_array_t *certs,
    njt_array_t *keys, njt_array_t *cert_types);
//add by clb end

njt_int_t njt_ssl_certificates(njt_conf_t *cf, njt_ssl_t *ssl,
    njt_array_t *certs, njt_array_t *keys, njt_array_t *passwords);
njt_int_t njt_ssl_certificate(njt_conf_t *cf, njt_ssl_t *ssl,
    njt_str_t *cert, njt_str_t *key, njt_array_t *passwords);
njt_int_t njt_ssl_connection_certificate(njt_connection_t *c, njt_pool_t *pool,
    njt_str_t *cert, njt_str_t *key, njt_array_t *passwords);
#if (NJT_HAVE_NTLS)
void njt_ssl_ntls_prefix_strip(njt_str_t *s);
njt_uint_t njt_ssl_ntls_type(njt_str_t *s);
#endif

njt_int_t njt_ssl_ciphers(njt_conf_t *cf, njt_ssl_t *ssl, njt_str_t *ciphers,
    njt_uint_t prefer_server_ciphers);
njt_int_t njt_ssl_client_certificate(njt_conf_t *cf, njt_ssl_t *ssl,
    njt_str_t *cert, njt_int_t depth);
njt_int_t njt_ssl_trusted_certificate(njt_conf_t *cf, njt_ssl_t *ssl,
    njt_str_t *cert, njt_int_t depth);
njt_int_t njt_ssl_crl(njt_conf_t *cf, njt_ssl_t *ssl, njt_str_t *crl);
njt_int_t njt_ssl_stapling(njt_conf_t *cf, njt_ssl_t *ssl,
    njt_str_t *file, njt_str_t *responder, njt_uint_t verify);
njt_int_t njt_ssl_stapling_resolver(njt_conf_t *cf, njt_ssl_t *ssl,
    njt_resolver_t *resolver, njt_msec_t resolver_timeout);
njt_int_t njt_ssl_ocsp(njt_conf_t *cf, njt_ssl_t *ssl, njt_str_t *responder,
    njt_uint_t depth, njt_shm_zone_t *shm_zone);
njt_int_t njt_ssl_ocsp_resolver(njt_conf_t *cf, njt_ssl_t *ssl,
    njt_resolver_t *resolver, njt_msec_t resolver_timeout);

njt_int_t njt_ssl_ocsp_validate(njt_connection_t *c);
njt_int_t njt_ssl_ocsp_get_status(njt_connection_t *c, const char **s);
void njt_ssl_ocsp_cleanup(njt_connection_t *c);
njt_int_t njt_ssl_ocsp_cache_init(njt_shm_zone_t *shm_zone, void *data);

njt_array_t *njt_ssl_read_password_file(njt_conf_t *cf, njt_str_t *file);
njt_array_t *njt_ssl_preserve_passwords(njt_conf_t *cf,
    njt_array_t *passwords);
njt_int_t njt_ssl_dhparam(njt_conf_t *cf, njt_ssl_t *ssl, njt_str_t *file);
njt_int_t njt_ssl_ecdh_curve(njt_conf_t *cf, njt_ssl_t *ssl, njt_str_t *name);
njt_int_t njt_ssl_early_data(njt_conf_t *cf, njt_ssl_t *ssl,
    njt_uint_t enable);
njt_int_t njt_ssl_conf_commands(njt_conf_t *cf, njt_ssl_t *ssl,
    njt_array_t *commands);

njt_int_t njt_ssl_client_session_cache(njt_conf_t *cf, njt_ssl_t *ssl,
    njt_uint_t enable);
njt_int_t njt_ssl_session_cache(njt_ssl_t *ssl, njt_str_t *sess_ctx,
    njt_array_t *certificates, ssize_t builtin_session_cache,
    njt_shm_zone_t *shm_zone, time_t timeout);
njt_int_t njt_ssl_session_ticket_keys(njt_conf_t *cf, njt_ssl_t *ssl,
    njt_array_t *paths);
njt_int_t njt_ssl_session_cache_init(njt_shm_zone_t *shm_zone, void *data);

njt_int_t njt_ssl_create_connection(njt_ssl_t *ssl, njt_connection_t *c,
    njt_uint_t flags);

void njt_ssl_remove_cached_session(SSL_CTX *ssl, njt_ssl_session_t *sess);
njt_int_t njt_ssl_set_session(njt_connection_t *c, njt_ssl_session_t *session);
njt_ssl_session_t *njt_ssl_get_session(njt_connection_t *c);
njt_ssl_session_t *njt_ssl_get0_session(njt_connection_t *c);
#define njt_ssl_free_session        SSL_SESSION_free
#define njt_ssl_get_connection(ssl_conn)                                      \
    SSL_get_ex_data(ssl_conn, njt_ssl_connection_index)
#define njt_ssl_get_server_conf(ssl_ctx)                                      \
    SSL_CTX_get_ex_data(ssl_ctx, njt_ssl_server_conf_index)

#define njt_ssl_verify_error_optional(n)                                      \
    (n == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT                              \
     || n == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN                             \
     || n == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY                     \
     || n == X509_V_ERR_CERT_UNTRUSTED                                        \
     || n == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE)

njt_int_t njt_ssl_check_host(njt_connection_t *c, njt_str_t *name);


njt_int_t njt_ssl_get_protocol(njt_connection_t *c, njt_pool_t *pool,
    njt_str_t *s);
njt_int_t njt_ssl_get_cipher_name(njt_connection_t *c, njt_pool_t *pool,
    njt_str_t *s);
njt_int_t njt_ssl_get_ciphers(njt_connection_t *c, njt_pool_t *pool,
    njt_str_t *s);
njt_int_t njt_ssl_get_curve(njt_connection_t *c, njt_pool_t *pool,
    njt_str_t *s);
njt_int_t njt_ssl_get_curves(njt_connection_t *c, njt_pool_t *pool,
    njt_str_t *s);
njt_int_t njt_ssl_get_session_id(njt_connection_t *c, njt_pool_t *pool,
    njt_str_t *s);
njt_int_t njt_ssl_get_session_reused(njt_connection_t *c, njt_pool_t *pool,
    njt_str_t *s);
njt_int_t njt_ssl_get_early_data(njt_connection_t *c, njt_pool_t *pool,
    njt_str_t *s);
njt_int_t njt_ssl_get_server_name(njt_connection_t *c, njt_pool_t *pool,
    njt_str_t *s);
njt_int_t njt_ssl_get_alpn_protocol(njt_connection_t *c, njt_pool_t *pool,
    njt_str_t *s);
njt_int_t njt_ssl_get_raw_certificate(njt_connection_t *c, njt_pool_t *pool,
    njt_str_t *s);
njt_int_t njt_ssl_get_certificate(njt_connection_t *c, njt_pool_t *pool,
    njt_str_t *s);
njt_int_t njt_ssl_get_escaped_certificate(njt_connection_t *c, njt_pool_t *pool,
    njt_str_t *s);
njt_int_t njt_ssl_get_subject_dn(njt_connection_t *c, njt_pool_t *pool,
    njt_str_t *s);
njt_int_t njt_ssl_get_issuer_dn(njt_connection_t *c, njt_pool_t *pool,
    njt_str_t *s);
njt_int_t njt_ssl_get_subject_dn_legacy(njt_connection_t *c, njt_pool_t *pool,
    njt_str_t *s);
njt_int_t njt_ssl_get_issuer_dn_legacy(njt_connection_t *c, njt_pool_t *pool,
    njt_str_t *s);
njt_int_t njt_ssl_get_serial_number(njt_connection_t *c, njt_pool_t *pool,
    njt_str_t *s);
njt_int_t njt_ssl_get_fingerprint(njt_connection_t *c, njt_pool_t *pool,
    njt_str_t *s);
njt_int_t njt_ssl_get_client_verify(njt_connection_t *c, njt_pool_t *pool,
    njt_str_t *s);
njt_int_t njt_ssl_get_client_v_start(njt_connection_t *c, njt_pool_t *pool,
    njt_str_t *s);
njt_int_t njt_ssl_get_client_v_end(njt_connection_t *c, njt_pool_t *pool,
    njt_str_t *s);
njt_int_t njt_ssl_get_client_v_remain(njt_connection_t *c, njt_pool_t *pool,
    njt_str_t *s);


njt_int_t njt_ssl_handshake(njt_connection_t *c);
#if (NJT_DEBUG)
void njt_ssl_handshake_log(njt_connection_t *c);
#endif
ssize_t njt_ssl_recv(njt_connection_t *c, u_char *buf, size_t size);
ssize_t njt_ssl_write(njt_connection_t *c, u_char *data, size_t size);
ssize_t njt_ssl_recv_chain(njt_connection_t *c, njt_chain_t *cl, off_t limit);
njt_chain_t *njt_ssl_send_chain(njt_connection_t *c, njt_chain_t *in,
    off_t limit);
void njt_ssl_free_buffer(njt_connection_t *c);
njt_int_t njt_ssl_shutdown(njt_connection_t *c);
void njt_cdecl njt_ssl_error(njt_uint_t level, njt_log_t *log, njt_err_t err,
    char *fmt, ...);
void njt_ssl_cleanup_ctx(void *data);

#if (NJT_HTTP_MULTICERT || NJT_STREAM_MULTICERT)
char *njt_ssl_certificate_slot(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
#endif

extern int  njt_ssl_connection_index;
extern int  njt_ssl_server_conf_index;
extern int  njt_ssl_session_cache_index;
extern int  njt_ssl_ticket_keys_index;
extern int  njt_ssl_ocsp_index;
extern int  njt_ssl_certificate_index;
extern int  njt_ssl_next_certificate_index;
extern int  njt_ssl_certificate_name_index;
extern int  njt_ssl_stapling_index;


#endif /* _NJT_EVENT_OPENSSL_H_INCLUDED_ */
