
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_EVENT_QUIC_PROTECTION_H_INCLUDED_
#define _NJT_EVENT_QUIC_PROTECTION_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>

#include <njt_event_quic_transport.h>


#define NJT_QUIC_ENCRYPTION_LAST  ((ssl_encryption_application) + 1)

/* RFC 5116, 5.1/5.3 and RFC 8439, 2.3/2.5 for all supported ciphers */
#define NJT_QUIC_IV_LEN               12
#define NJT_QUIC_TAG_LEN              16

/* largest hash used in TLS is SHA-384 */
#define NJT_QUIC_MAX_MD_SIZE          48


#ifdef OPENSSL_IS_BORINGSSL
#define njt_quic_cipher_t             EVP_AEAD
#define njt_quic_crypto_ctx_t         EVP_AEAD_CTX
#else
#define njt_quic_cipher_t             EVP_CIPHER
#define njt_quic_crypto_ctx_t         EVP_CIPHER_CTX
#endif


typedef struct {
    size_t                    len;
    u_char                    data[NJT_QUIC_MAX_MD_SIZE];
} njt_quic_md_t;


typedef struct {
    size_t                    len;
    u_char                    data[NJT_QUIC_IV_LEN];
} njt_quic_iv_t;


typedef struct {
    njt_quic_md_t             secret;
    njt_quic_iv_t             iv;
    njt_quic_md_t             hp;
    njt_quic_crypto_ctx_t    *ctx;
    EVP_CIPHER_CTX           *hp_ctx;
} njt_quic_secret_t;


typedef struct {
    njt_quic_secret_t         client;
    njt_quic_secret_t         server;
} njt_quic_secrets_t;


struct njt_quic_keys_s {
    njt_quic_secrets_t        secrets[NJT_QUIC_ENCRYPTION_LAST];
    njt_quic_secrets_t        next_key;
    njt_uint_t                cipher;
};


typedef struct {
    const njt_quic_cipher_t  *c;
    const EVP_CIPHER         *hp;
    const EVP_MD             *d;
} njt_quic_ciphers_t;


typedef struct {
    size_t                    out_len;
    u_char                   *out;

    size_t                    prk_len;
    const uint8_t            *prk;

    size_t                    label_len;
    const u_char             *label;
} njt_quic_hkdf_t;

#define njt_quic_hkdf_set(seq, _label, _out, _prk)                            \
    (seq)->out_len = (_out)->len; (seq)->out = (_out)->data;                  \
    (seq)->prk_len = (_prk)->len, (seq)->prk = (_prk)->data,                  \
    (seq)->label_len = (sizeof(_label) - 1); (seq)->label = (u_char *)(_label);


njt_int_t njt_quic_keys_set_initial_secret(njt_quic_keys_t *keys,
    njt_str_t *secret, njt_log_t *log);
njt_int_t njt_quic_keys_set_encryption_secret(njt_log_t *log,
    njt_uint_t is_write, njt_quic_keys_t *keys,
    enum ssl_encryption_level_t level, const SSL_CIPHER *cipher,
    const uint8_t *secret, size_t secret_len);
njt_uint_t njt_quic_keys_available(njt_quic_keys_t *keys,
    enum ssl_encryption_level_t level, njt_uint_t is_write);
void njt_quic_keys_discard(njt_quic_keys_t *keys,
    enum ssl_encryption_level_t level);
void njt_quic_keys_switch(njt_connection_t *c, njt_quic_keys_t *keys);
void njt_quic_keys_update(njt_event_t *ev);
void njt_quic_keys_cleanup(njt_quic_keys_t *keys);
njt_int_t njt_quic_encrypt(njt_quic_header_t *pkt, njt_str_t *res);
njt_int_t njt_quic_decrypt(njt_quic_header_t *pkt, uint64_t *largest_pn);
void njt_quic_compute_nonce(u_char *nonce, size_t len, uint64_t pn);
njt_int_t njt_quic_ciphers(njt_uint_t id, njt_quic_ciphers_t *ciphers);
njt_int_t njt_quic_crypto_init(const njt_quic_cipher_t *cipher,
    njt_quic_secret_t *s, njt_quic_md_t *key, njt_int_t enc, njt_log_t *log);
njt_int_t njt_quic_crypto_seal(njt_quic_secret_t *s, njt_str_t *out,
    u_char *nonce, njt_str_t *in, njt_str_t *ad, njt_log_t *log);
void njt_quic_crypto_cleanup(njt_quic_secret_t *s);
njt_int_t njt_quic_hkdf_expand(njt_quic_hkdf_t *hkdf, const EVP_MD *digest,
    njt_log_t *log);


#endif /* _NJT_EVENT_QUIC_PROTECTION_H_INCLUDED_ */
