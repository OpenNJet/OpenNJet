
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_event_quic_connection.h>


#if (NJT_QUIC_OPENSSL_COMPAT)

#define NJT_QUIC_COMPAT_RECORD_SIZE          1024

#define NJT_QUIC_COMPAT_SSL_TP_EXT           0x39

#define NJT_QUIC_COMPAT_CLIENT_HANDSHAKE     "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
#define NJT_QUIC_COMPAT_SERVER_HANDSHAKE     "SERVER_HANDSHAKE_TRAFFIC_SECRET"
#define NJT_QUIC_COMPAT_CLIENT_APPLICATION   "CLIENT_TRAFFIC_SECRET_0"
#define NJT_QUIC_COMPAT_SERVER_APPLICATION   "SERVER_TRAFFIC_SECRET_0"


typedef struct {
    njt_quic_secret_t             secret;
    njt_uint_t                    cipher;
} njt_quic_compat_keys_t;


typedef struct {
    njt_log_t                    *log;

    u_char                        type;
    njt_str_t                     payload;
    uint64_t                      number;
    njt_quic_compat_keys_t       *keys;

    enum ssl_encryption_level_t   level;
} njt_quic_compat_record_t;


struct njt_quic_compat_s {
    const SSL_QUIC_METHOD        *method;

    enum ssl_encryption_level_t   write_level;

    uint64_t                      read_record;
    njt_quic_compat_keys_t        keys;

    njt_str_t                     tp;
    njt_str_t                     ctp;
};


static void njt_quic_compat_keylog_callback(const SSL *ssl, const char *line);
static njt_int_t njt_quic_compat_set_encryption_secret(njt_connection_t *c,
    njt_quic_compat_keys_t *keys, enum ssl_encryption_level_t level,
    const SSL_CIPHER *cipher, const uint8_t *secret, size_t secret_len);
static void njt_quic_compat_cleanup_encryption_secret(void *data);
static int njt_quic_compat_add_transport_params_callback(SSL *ssl,
    unsigned int ext_type, unsigned int context, const unsigned char **out,
    size_t *outlen, X509 *x, size_t chainidx, int *al, void *add_arg);
static int njt_quic_compat_parse_transport_params_callback(SSL *ssl,
    unsigned int ext_type, unsigned int context, const unsigned char *in,
    size_t inlen, X509 *x, size_t chainidx, int *al, void *parse_arg);
static void njt_quic_compat_message_callback(int write_p, int version,
    int content_type, const void *buf, size_t len, SSL *ssl, void *arg);
static size_t njt_quic_compat_create_header(njt_quic_compat_record_t *rec,
    u_char *out, njt_uint_t plain);
static njt_int_t njt_quic_compat_create_record(njt_quic_compat_record_t *rec,
    njt_str_t *res);


njt_int_t
njt_quic_compat_init(njt_conf_t *cf, SSL_CTX *ctx)
{
    SSL_CTX_set_keylog_callback(ctx, njt_quic_compat_keylog_callback);

    if (SSL_CTX_has_client_custom_ext(ctx, NJT_QUIC_COMPAT_SSL_TP_EXT)) {
        return NJT_OK;
    }

    if (SSL_CTX_add_custom_ext(ctx, NJT_QUIC_COMPAT_SSL_TP_EXT,
                               SSL_EXT_CLIENT_HELLO
                               |SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                               njt_quic_compat_add_transport_params_callback,
                               NULL,
                               NULL,
                               njt_quic_compat_parse_transport_params_callback,
                               NULL)
        == 0)
    {
        njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                      "SSL_CTX_add_custom_ext() failed");
        return NJT_ERROR;
    }

    return NJT_OK;
}


static void
njt_quic_compat_keylog_callback(const SSL *ssl, const char *line)
{
    u_char                        ch, *p, *start, value;
    size_t                        n;
    njt_uint_t                    write;
    const SSL_CIPHER             *cipher;
    njt_quic_compat_t            *com;
    njt_connection_t             *c;
    njt_quic_connection_t        *qc;
    enum ssl_encryption_level_t   level;
    u_char                        secret[EVP_MAX_MD_SIZE];

    c = njt_ssl_get_connection(ssl);
    if (c->type != SOCK_DGRAM) {
        return;
    }

    p = (u_char *) line;

    for (start = p; *p && *p != ' '; p++);

    n = p - start;

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic compat secret %*s", n, start);

    if (n == sizeof(NJT_QUIC_COMPAT_CLIENT_HANDSHAKE) - 1
        && njt_strncmp(start, NJT_QUIC_COMPAT_CLIENT_HANDSHAKE, n) == 0)
    {
        level = ssl_encryption_handshake;
        write = 0;

    } else if (n == sizeof(NJT_QUIC_COMPAT_SERVER_HANDSHAKE) - 1
               && njt_strncmp(start, NJT_QUIC_COMPAT_SERVER_HANDSHAKE, n) == 0)
    {
        level = ssl_encryption_handshake;
        write = 1;

    } else if (n == sizeof(NJT_QUIC_COMPAT_CLIENT_APPLICATION) - 1
               && njt_strncmp(start, NJT_QUIC_COMPAT_CLIENT_APPLICATION, n)
                  == 0)
    {
        level = ssl_encryption_application;
        write = 0;

    } else if (n == sizeof(NJT_QUIC_COMPAT_SERVER_APPLICATION) - 1
               && njt_strncmp(start, NJT_QUIC_COMPAT_SERVER_APPLICATION, n)
                   == 0)
    {
        level = ssl_encryption_application;
        write = 1;

    } else {
        return;
    }

    if (*p++ == '\0') {
        return;
    }

    for ( /* void */ ; *p && *p != ' '; p++);

    if (*p++ == '\0') {
        return;
    }

    for (n = 0, start = p; *p; p++) {
        ch = *p;

        if (ch >= '0' && ch <= '9') {
            value = ch - '0';
            goto next;
        }

        ch = (u_char) (ch | 0x20);

        if (ch >= 'a' && ch <= 'f') {
            value = ch - 'a' + 10;
            goto next;
        }

        njt_log_error(NJT_LOG_EMERG, c->log, 0,
                      "invalid OpenSSL QUIC secret format");

        return;

    next:

        if ((p - start) % 2) {
            secret[n++] += value;

        } else {
            if (n >= EVP_MAX_MD_SIZE) {
                njt_log_error(NJT_LOG_EMERG, c->log, 0,
                              "too big OpenSSL QUIC secret");
                return;
            }

            secret[n] = (value << 4);
        }
    }

    qc = njt_quic_get_connection(c);
    com = qc->compat;
    cipher = SSL_get_current_cipher(ssl);

    if (write) {
        com->method->set_write_secret((SSL *) ssl, level, cipher, secret, n);
        com->write_level = level;

    } else {
        com->method->set_read_secret((SSL *) ssl, level, cipher, secret, n);
        com->read_record = 0;

        (void) njt_quic_compat_set_encryption_secret(c, &com->keys, level,
                                                     cipher, secret, n);
    }

    njt_explicit_memzero(secret, n);
}


static njt_int_t
njt_quic_compat_set_encryption_secret(njt_connection_t *c,
    njt_quic_compat_keys_t *keys, enum ssl_encryption_level_t level,
    const SSL_CIPHER *cipher, const uint8_t *secret, size_t secret_len)
{
    njt_int_t            key_len;
    njt_str_t            secret_str;
    njt_uint_t           i;
    njt_quic_md_t        key;
    njt_quic_hkdf_t      seq[2];
    njt_quic_secret_t   *peer_secret;
    njt_quic_ciphers_t   ciphers;
    njt_pool_cleanup_t  *cln;

    peer_secret = &keys->secret;

    keys->cipher = SSL_CIPHER_get_id(cipher);

    key_len = njt_quic_ciphers(keys->cipher, &ciphers);

    if (key_len == NJT_ERROR) {
        njt_ssl_error(NJT_LOG_INFO, c->log, 0, "unexpected cipher");
        return NJT_ERROR;
    }

    key.len = key_len;

    peer_secret->iv.len = NJT_QUIC_IV_LEN;

    secret_str.len = secret_len;
    secret_str.data = (u_char *) secret;

    njt_quic_hkdf_set(&seq[0], "tls13 key", &key, &secret_str);
    njt_quic_hkdf_set(&seq[1], "tls13 iv", &peer_secret->iv, &secret_str);

    for (i = 0; i < (sizeof(seq) / sizeof(seq[0])); i++) {
        if (njt_quic_hkdf_expand(&seq[i], ciphers.d, c->log) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    /* register cleanup handler once */

    if (peer_secret->ctx) {
        njt_quic_crypto_cleanup(peer_secret);

    } else {
        cln = njt_pool_cleanup_add(c->pool, 0);
        if (cln == NULL) {
            return NJT_ERROR;
        }

        cln->handler = njt_quic_compat_cleanup_encryption_secret;
        cln->data = peer_secret;
    }

    if (njt_quic_crypto_init(ciphers.c, peer_secret, &key, 1, c->log)
        == NJT_ERROR)
    {
        return NJT_ERROR;
    }

    njt_explicit_memzero(key.data, key.len);

    return NJT_OK;
}


static void
njt_quic_compat_cleanup_encryption_secret(void *data)
{
    njt_quic_secret_t *secret = data;

    njt_quic_crypto_cleanup(secret);
}


static int
njt_quic_compat_add_transport_params_callback(SSL *ssl, unsigned int ext_type,
    unsigned int context, const unsigned char **out, size_t *outlen, X509 *x,
    size_t chainidx, int *al, void *add_arg)
{
    njt_connection_t       *c;
    njt_quic_compat_t      *com;
    njt_quic_connection_t  *qc;

    c = njt_ssl_get_connection(ssl);
    if (c->type != SOCK_DGRAM) {
        return 0;
    }

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic compat add transport params");

    qc = njt_quic_get_connection(c);
    com = qc->compat;

    *out = com->tp.data;
    *outlen = com->tp.len;

    return 1;
}


static int
njt_quic_compat_parse_transport_params_callback(SSL *ssl, unsigned int ext_type,
    unsigned int context, const unsigned char *in, size_t inlen, X509 *x,
    size_t chainidx, int *al, void *parse_arg)
{
    u_char                 *p;
    njt_connection_t       *c;
    njt_quic_compat_t      *com;
    njt_quic_connection_t  *qc;

    c = njt_ssl_get_connection(ssl);
    if (c->type != SOCK_DGRAM) {
        return 0;
    }

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic compat parse transport params");

    qc = njt_quic_get_connection(c);
    com = qc->compat;

    p = njt_pnalloc(c->pool, inlen);
    if (p == NULL) {
        return 0;
    }

    njt_memcpy(p, in, inlen);

    com->ctp.data = p;
    com->ctp.len = inlen;

    return 1;
}


int
SSL_set_quic_method(SSL *ssl, const SSL_QUIC_METHOD *quic_method)
{
    BIO                    *rbio, *wbio;
    njt_connection_t       *c;
    njt_quic_compat_t      *com;
    njt_quic_connection_t  *qc;

    c = njt_ssl_get_connection(ssl);

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0, "quic compat set method");

    qc = njt_quic_get_connection(c);

    qc->compat = njt_pcalloc(c->pool, sizeof(njt_quic_compat_t));
    if (qc->compat == NULL) {
        return 0;
    }

    com = qc->compat;
    com->method = quic_method;

    rbio = BIO_new(BIO_s_mem());
    if (rbio == NULL) {
        return 0;
    }

    wbio = BIO_new(BIO_s_null());
    if (wbio == NULL) {
        return 0;
    }

    SSL_set_bio(ssl, rbio, wbio);

    SSL_set_msg_callback(ssl, njt_quic_compat_message_callback);

    /* early data is not supported */
    SSL_set_max_early_data(ssl, 0);

    return 1;
}


static void
njt_quic_compat_message_callback(int write_p, int version, int content_type,
    const void *buf, size_t len, SSL *ssl, void *arg)
{
    njt_uint_t                    alert;
    njt_connection_t             *c;
    njt_quic_compat_t            *com;
    njt_quic_connection_t        *qc;
    enum ssl_encryption_level_t   level;

    if (!write_p) {
        return;
    }

    c = njt_ssl_get_connection(ssl);
    qc = njt_quic_get_connection(c);

    if (qc == NULL) {
        /* closing */
        return;
    }

    com = qc->compat;
    level = com->write_level;

    switch (content_type) {

    case SSL3_RT_HANDSHAKE:
        njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "quic compat tx %s len:%uz ",
                       njt_quic_level_name(level), len);

        if (com->method->add_handshake_data(ssl, level, buf, len) != 1) {
            goto failed;
        }

        break;

    case SSL3_RT_ALERT:
        if (len >= 2) {
            alert = ((u_char *) buf)[1];

            njt_log_debug3(NJT_LOG_DEBUG_EVENT, c->log, 0,
                           "quic compat %s alert:%ui len:%uz ",
                           njt_quic_level_name(level), alert, len);

            if (com->method->send_alert(ssl, level, alert) != 1) {
                goto failed;
            }
        }

        break;
    }

    return;

failed:

    njt_post_event(&qc->close, &njt_posted_events);
}


int
SSL_provide_quic_data(SSL *ssl, enum ssl_encryption_level_t level,
    const uint8_t *data, size_t len)
{
    BIO                       *rbio;
    size_t                     n;
    u_char                    *p;
    njt_str_t                  res;
    njt_connection_t          *c;
    njt_quic_compat_t         *com;
    njt_quic_connection_t     *qc;
    njt_quic_compat_record_t   rec;
    u_char                     in[NJT_QUIC_COMPAT_RECORD_SIZE + 1];
    u_char                     out[NJT_QUIC_COMPAT_RECORD_SIZE + 1
                                   + SSL3_RT_HEADER_LENGTH
                                   + NJT_QUIC_TAG_LEN];

    c = njt_ssl_get_connection(ssl);

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0, "quic compat rx %s len:%uz",
                   njt_quic_level_name(level), len);

    qc = njt_quic_get_connection(c);
    com = qc->compat;
    rbio = SSL_get_rbio(ssl);

    while (len) {
        njt_memzero(&rec, sizeof(njt_quic_compat_record_t));

        rec.type = SSL3_RT_HANDSHAKE;
        rec.log = c->log;
        rec.number = com->read_record++;
        rec.keys = &com->keys;
        rec.level = level;

        if (level == ssl_encryption_initial) {
            n = njt_min(len, 65535);

            rec.payload.len = n;
            rec.payload.data = (u_char *) data;

            njt_quic_compat_create_header(&rec, out, 1);

            BIO_write(rbio, out, SSL3_RT_HEADER_LENGTH);
            BIO_write(rbio, data, n);

#if defined(NJT_QUIC_DEBUG_CRYPTO) && defined(NJT_QUIC_DEBUG_PACKETS)
            njt_log_debug5(NJT_LOG_DEBUG_EVENT, c->log, 0,
                           "quic compat record len:%uz %*xs%*xs",
                           n + SSL3_RT_HEADER_LENGTH,
                           (size_t) SSL3_RT_HEADER_LENGTH, out, n, data);
#endif

        } else {
            n = njt_min(len, NJT_QUIC_COMPAT_RECORD_SIZE);

            p = njt_cpymem(in, data, n);
            *p++ = SSL3_RT_HANDSHAKE;

            rec.payload.len = p - in;
            rec.payload.data = in;

            res.data = out;

            if (njt_quic_compat_create_record(&rec, &res) != NJT_OK) {
                return 0;
            }

#if defined(NJT_QUIC_DEBUG_CRYPTO) && defined(NJT_QUIC_DEBUG_PACKETS)
            njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                           "quic compat record len:%uz %xV", res.len, &res);
#endif

            BIO_write(rbio, res.data, res.len);
        }

        data += n;
        len -= n;
    }

    return 1;
}


static size_t
njt_quic_compat_create_header(njt_quic_compat_record_t *rec, u_char *out,
    njt_uint_t plain)
{
    u_char  type;
    size_t  len;

    len = rec->payload.len;

    if (plain) {
        type = rec->type;

    } else {
        type = SSL3_RT_APPLICATION_DATA;
        len += NJT_QUIC_TAG_LEN;
    }

    out[0] = type;
    out[1] = 0x03;
    out[2] = 0x03;
    out[3] = (len >> 8);
    out[4] = len;

    return 5;
}


static njt_int_t
njt_quic_compat_create_record(njt_quic_compat_record_t *rec, njt_str_t *res)
{
    njt_str_t           ad, out;
    njt_quic_secret_t  *secret;
    u_char              nonce[NJT_QUIC_IV_LEN];

    ad.data = res->data;
    ad.len = njt_quic_compat_create_header(rec, ad.data, 0);

    out.len = rec->payload.len + NJT_QUIC_TAG_LEN;
    out.data = res->data + ad.len;

#ifdef NJT_QUIC_DEBUG_CRYPTO
    njt_log_debug2(NJT_LOG_DEBUG_EVENT, rec->log, 0,
                   "quic compat ad len:%uz %xV", ad.len, &ad);
#endif

    secret = &rec->keys->secret;

    njt_memcpy(nonce, secret->iv.data, secret->iv.len);
    njt_quic_compute_nonce(nonce, sizeof(nonce), rec->number);

    if (njt_quic_crypto_seal(secret, &out, nonce, &rec->payload, &ad, rec->log)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    res->len = ad.len + out.len;

    return NJT_OK;
}


int
SSL_set_quic_transport_params(SSL *ssl, const uint8_t *params,
    size_t params_len)
{
    njt_connection_t       *c;
    njt_quic_compat_t      *com;
    njt_quic_connection_t  *qc;

    c = njt_ssl_get_connection(ssl);
    qc = njt_quic_get_connection(c);
    com = qc->compat;

    com->tp.len = params_len;
    com->tp.data = (u_char *) params;

    return 1;
}


void
SSL_get_peer_quic_transport_params(const SSL *ssl, const uint8_t **out_params,
    size_t *out_params_len)
{
    njt_connection_t       *c;
    njt_quic_compat_t      *com;
    njt_quic_connection_t  *qc;

    c = njt_ssl_get_connection(ssl);
    qc = njt_quic_get_connection(c);
    com = qc->compat;

    *out_params = com->ctp.data;
    *out_params_len = com->ctp.len;
}

#endif /* NJT_QUIC_OPENSSL_COMPAT */
