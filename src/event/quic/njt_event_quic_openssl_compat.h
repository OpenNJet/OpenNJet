
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_EVENT_QUIC_OPENSSL_COMPAT_H_INCLUDED_
#define _NJT_EVENT_QUIC_OPENSSL_COMPAT_H_INCLUDED_

#if defined SSL_R_MISSING_QUIC_TRANSPORT_PARAMETERS_EXTENSION                 \
    || defined LIBRESSL_VERSION_NUMBER
#undef NJT_QUIC_OPENSSL_COMPAT
#else


#include <njt_config.h>
#include <njt_core.h>


typedef struct njt_quic_compat_s  njt_quic_compat_t;


enum ssl_encryption_level_t {
    ssl_encryption_initial = 0,
    ssl_encryption_early_data,
    ssl_encryption_handshake,
    ssl_encryption_application
};


typedef struct ssl_quic_method_st {
    int (*set_read_secret)(SSL *ssl, enum ssl_encryption_level_t level,
                           const SSL_CIPHER *cipher,
                           const uint8_t *rsecret, size_t secret_len);
    int (*set_write_secret)(SSL *ssl, enum ssl_encryption_level_t level,
                            const SSL_CIPHER *cipher,
                            const uint8_t *wsecret, size_t secret_len);
    int (*add_handshake_data)(SSL *ssl, enum ssl_encryption_level_t level,
                              const uint8_t *data, size_t len);
    int (*flush_flight)(SSL *ssl);
    int (*send_alert)(SSL *ssl, enum ssl_encryption_level_t level,
                      uint8_t alert);
} SSL_QUIC_METHOD;


njt_int_t njt_quic_compat_init(njt_conf_t *cf, SSL_CTX *ctx);

int SSL_set_quic_method(SSL *ssl, const SSL_QUIC_METHOD *quic_method);
int SSL_provide_quic_data(SSL *ssl, enum ssl_encryption_level_t level,
    const uint8_t *data, size_t len);
int SSL_set_quic_transport_params(SSL *ssl, const uint8_t *params,
    size_t params_len);
void SSL_get_peer_quic_transport_params(const SSL *ssl,
    const uint8_t **out_params, size_t *out_params_len);


#endif /* TLSEXT_TYPE_quic_transport_parameters */

#endif /* _NJT_EVENT_QUIC_OPENSSL_COMPAT_H_INCLUDED_ */
