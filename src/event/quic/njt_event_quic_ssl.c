
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_event_quic_connection.h>


#if defined OPENSSL_IS_BORINGSSL                                              \
    || defined LIBRESSL_VERSION_NUMBER                                        \
    || defined BABASSL_VERSION_NUMBER                                         \
    || NJT_QUIC_OPENSSL_COMPAT
#define NJT_QUIC_BORINGSSL_API   1
#endif


/*
 * RFC 9000, 7.5.  Cryptographic Message Buffering
 *
 * Implementations MUST support buffering at least 4096 bytes of data
 */
#define NJT_QUIC_MAX_BUFFERED    65535


#if (NJT_QUIC_BORINGSSL_API)
static int njt_quic_set_read_secret(njt_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const SSL_CIPHER *cipher,
    const uint8_t *secret, size_t secret_len);
static int njt_quic_set_write_secret(njt_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const SSL_CIPHER *cipher,
    const uint8_t *secret, size_t secret_len);
#else
static int njt_quic_set_encryption_secrets(njt_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const uint8_t *read_secret,
    const uint8_t *write_secret, size_t secret_len);
#endif

static int njt_quic_add_handshake_data(njt_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const uint8_t *data, size_t len);
static int njt_quic_flush_flight(njt_ssl_conn_t *ssl_conn);
static int njt_quic_send_alert(njt_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, uint8_t alert);
static njt_int_t njt_quic_crypto_input(njt_connection_t *c, njt_chain_t *data,
    enum ssl_encryption_level_t level);


#if (NJT_QUIC_BORINGSSL_API)

static int
njt_quic_set_read_secret(njt_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const SSL_CIPHER *cipher,
    const uint8_t *rsecret, size_t secret_len)
{
    njt_connection_t       *c;
    njt_quic_connection_t  *qc;

    c = njt_ssl_get_connection((njt_ssl_conn_t *) ssl_conn);
    qc = njt_quic_get_connection(c);

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic njt_quic_set_read_secret() level:%d", level);
#ifdef NJT_QUIC_DEBUG_CRYPTO
    njt_log_debug3(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic read secret len:%uz %*xs", secret_len,
                   secret_len, rsecret);
#endif

    if (njt_quic_keys_set_encryption_secret(c->log, 0, qc->keys, level,
                                            cipher, rsecret, secret_len)
        != NJT_OK)
    {
        return 0;
    }

    return 1;
}


static int
njt_quic_set_write_secret(njt_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const SSL_CIPHER *cipher,
    const uint8_t *wsecret, size_t secret_len)
{
    njt_connection_t       *c;
    njt_quic_connection_t  *qc;

    c = njt_ssl_get_connection((njt_ssl_conn_t *) ssl_conn);
    qc = njt_quic_get_connection(c);

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic njt_quic_set_write_secret() level:%d", level);
#ifdef NJT_QUIC_DEBUG_CRYPTO
    njt_log_debug3(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic write secret len:%uz %*xs", secret_len,
                   secret_len, wsecret);
#endif

    if (njt_quic_keys_set_encryption_secret(c->log, 1, qc->keys, level,
                                            cipher, wsecret, secret_len)
        != NJT_OK)
    {
        return 0;
    }

    return 1;
}

#else

static int
njt_quic_set_encryption_secrets(njt_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const uint8_t *rsecret,
    const uint8_t *wsecret, size_t secret_len)
{
    njt_connection_t       *c;
    const SSL_CIPHER       *cipher;
    njt_quic_connection_t  *qc;

    c = njt_ssl_get_connection((njt_ssl_conn_t *) ssl_conn);
    qc = njt_quic_get_connection(c);

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic njt_quic_set_encryption_secrets() level:%d", level);
#ifdef NJT_QUIC_DEBUG_CRYPTO
    njt_log_debug3(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic read secret len:%uz %*xs", secret_len,
                   secret_len, rsecret);
#endif

    cipher = SSL_get_current_cipher(ssl_conn);

    if (njt_quic_keys_set_encryption_secret(c->log, 0, qc->keys, level,
                                            cipher, rsecret, secret_len)
        != NJT_OK)
    {
        return 0;
    }

    if (level == ssl_encryption_early_data) {
        return 1;
    }

#ifdef NJT_QUIC_DEBUG_CRYPTO
    njt_log_debug3(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic write secret len:%uz %*xs", secret_len,
                   secret_len, wsecret);
#endif

    if (njt_quic_keys_set_encryption_secret(c->log, 1, qc->keys, level,
                                            cipher, wsecret, secret_len)
        != NJT_OK)
    {
        return 0;
    }

    return 1;
}

#endif


static int
njt_quic_add_handshake_data(njt_ssl_conn_t *ssl_conn,
    enum ssl_encryption_level_t level, const uint8_t *data, size_t len)
{
    u_char                 *p, *end;
    size_t                  client_params_len;
    njt_chain_t            *out;
    const uint8_t          *client_params;
    njt_quic_tp_t           ctp;
    njt_quic_frame_t       *frame;
    njt_connection_t       *c;
    njt_quic_send_ctx_t    *ctx;
    njt_quic_connection_t  *qc;
#if defined(TLSEXT_TYPE_application_layer_protocol_negotiation)
    unsigned int            alpn_len;
    const unsigned char    *alpn_data;
#endif

    c = njt_ssl_get_connection((njt_ssl_conn_t *) ssl_conn);
    qc = njt_quic_get_connection(c);

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic njt_quic_add_handshake_data");

    if (!qc->client_tp_done) {
        /*
         * things to do once during handshake: check ALPN and transport
         * parameters; we want to break handshake if something is wrong
         * here;
         */

#if defined(TLSEXT_TYPE_application_layer_protocol_negotiation)

        SSL_get0_alpn_selected(ssl_conn, &alpn_data, &alpn_len);

        if (alpn_len == 0) {
            qc->error = NJT_QUIC_ERR_CRYPTO(SSL_AD_NO_APPLICATION_PROTOCOL);
            qc->error_reason = "unsupported protocol in ALPN extension";

            njt_log_error(NJT_LOG_INFO, c->log, 0,
                          "quic unsupported protocol in ALPN extension");
            return 0;
        }

#endif

        SSL_get_peer_quic_transport_params(ssl_conn, &client_params,
                                           &client_params_len);

        njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0,
                       "quic SSL_get_peer_quic_transport_params():"
                       " params_len:%ui", client_params_len);

        if (client_params_len == 0) {
            /* RFC 9001, 8.2.  QUIC Transport Parameters Extension */
            qc->error = NJT_QUIC_ERR_CRYPTO(SSL_AD_MISSING_EXTENSION);
            qc->error_reason = "missing transport parameters";

            njt_log_error(NJT_LOG_INFO, c->log, 0,
                          "missing transport parameters");
            return 0;
        }

        p = (u_char *) client_params;
        end = p + client_params_len;

        /* defaults for parameters not sent by client */
        njt_memcpy(&ctp, &qc->ctp, sizeof(njt_quic_tp_t));

        if (njt_quic_parse_transport_params(p, end, &ctp, c->log)
            != NJT_OK)
        {
            qc->error = NJT_QUIC_ERR_TRANSPORT_PARAMETER_ERROR;
            qc->error_reason = "failed to process transport parameters";

            return 0;
        }

        if (njt_quic_apply_transport_params(c, &ctp) != NJT_OK) {
            return 0;
        }

        qc->client_tp_done = 1;
    }

    ctx = njt_quic_get_send_ctx(qc, level);

    out = njt_quic_copy_buffer(c, (u_char *) data, len);
    if (out == NJT_CHAIN_ERROR) {
        return 0;
    }

    frame = njt_quic_alloc_frame(c);
    if (frame == NULL) {
        return 0;
    }

    frame->data = out;
    frame->level = level;
    frame->type = NJT_QUIC_FT_CRYPTO;
    frame->u.crypto.offset = ctx->crypto_sent;
    frame->u.crypto.length = len;

    ctx->crypto_sent += len;

    njt_quic_queue_frame(qc, frame);

    return 1;
}


static int
njt_quic_flush_flight(njt_ssl_conn_t *ssl_conn)
{
#if (NJT_DEBUG)
    njt_connection_t  *c;

    c = njt_ssl_get_connection((njt_ssl_conn_t *) ssl_conn);

    njt_log_debug0(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic njt_quic_flush_flight()");
#endif
    return 1;
}


static int
njt_quic_send_alert(njt_ssl_conn_t *ssl_conn, enum ssl_encryption_level_t level,
    uint8_t alert)
{
    njt_connection_t       *c;
    njt_quic_connection_t  *qc;

    c = njt_ssl_get_connection((njt_ssl_conn_t *) ssl_conn);

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic njt_quic_send_alert() level:%s alert:%d",
                   njt_quic_level_name(level), (int) alert);

    /* already closed on regular shutdown */

    qc = njt_quic_get_connection(c);
    if (qc == NULL) {
        return 1;
    }

    qc->error = NJT_QUIC_ERR_CRYPTO(alert);
    qc->error_reason = "handshake failed";

    return 1;
}


njt_int_t
njt_quic_handle_crypto_frame(njt_connection_t *c, njt_quic_header_t *pkt,
    njt_quic_frame_t *frame)
{
    uint64_t                  last;
    njt_chain_t              *cl;
    njt_quic_send_ctx_t      *ctx;
    njt_quic_connection_t    *qc;
    njt_quic_crypto_frame_t  *f;

    qc = njt_quic_get_connection(c);
    ctx = njt_quic_get_send_ctx(qc, pkt->level);
    f = &frame->u.crypto;

    /* no overflow since both values are 62-bit */
    last = f->offset + f->length;

    if (last > ctx->crypto.offset + NJT_QUIC_MAX_BUFFERED) {
        qc->error = NJT_QUIC_ERR_CRYPTO_BUFFER_EXCEEDED;
        return NJT_ERROR;
    }

    if (last <= ctx->crypto.offset) {
        if (pkt->level == ssl_encryption_initial) {
            /* speeding up handshake completion */

            if (!njt_queue_empty(&ctx->sent)) {
                njt_quic_resend_frames(c, ctx);

                ctx = njt_quic_get_send_ctx(qc, ssl_encryption_handshake);
                while (!njt_queue_empty(&ctx->sent)) {
                    njt_quic_resend_frames(c, ctx);
                }
            }
        }

        return NJT_OK;
    }

    if (f->offset == ctx->crypto.offset) {
        if (njt_quic_crypto_input(c, frame->data, pkt->level) != NJT_OK) {
            return NJT_ERROR;
        }

        njt_quic_skip_buffer(c, &ctx->crypto, last);

    } else {
        if (njt_quic_write_buffer(c, &ctx->crypto, frame->data, f->length,
                                  f->offset)
            == NJT_CHAIN_ERROR)
        {
            return NJT_ERROR;
        }
    }

    cl = njt_quic_read_buffer(c, &ctx->crypto, (uint64_t) -1);

    if (cl) {
        if (njt_quic_crypto_input(c, cl, pkt->level) != NJT_OK) {
            return NJT_ERROR;
        }

        njt_quic_free_chain(c, cl);
    }

    return NJT_OK;
}


static njt_int_t
njt_quic_crypto_input(njt_connection_t *c, njt_chain_t *data,
    enum ssl_encryption_level_t level)
{
    int                     n, sslerr;
    njt_buf_t              *b;
    njt_chain_t            *cl;
    njt_ssl_conn_t         *ssl_conn;
    njt_quic_frame_t       *frame;
    njt_quic_connection_t  *qc;

    qc = njt_quic_get_connection(c);

    ssl_conn = c->ssl->connection;

    for (cl = data; cl; cl = cl->next) {
        b = cl->buf;

        if (!SSL_provide_quic_data(ssl_conn, level, b->pos, b->last - b->pos)) {
            njt_ssl_error(NJT_LOG_INFO, c->log, 0,
                          "SSL_provide_quic_data() failed");
            return NJT_ERROR;
        }
    }

    n = SSL_do_handshake(ssl_conn);

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0, "SSL_do_handshake: %d", n);

    if (n <= 0) {
        sslerr = SSL_get_error(ssl_conn, n);

        njt_log_debug1(NJT_LOG_DEBUG_EVENT, c->log, 0, "SSL_get_error: %d",
                       sslerr);

        if (sslerr != SSL_ERROR_WANT_READ) {

            if (c->ssl->handshake_rejected) {
                njt_connection_error(c, 0, "handshake rejected");
                ERR_clear_error();

                return NJT_ERROR;
            }

            njt_ssl_error(NJT_LOG_ERR, c->log, 0, "SSL_do_handshake() failed");
            return NJT_ERROR;
        }
    }

    if (n <= 0 || SSL_in_init(ssl_conn)) {
        if (njt_quic_keys_available(qc->keys, ssl_encryption_early_data, 0)
            && qc->client_tp_done)
        {
            if (njt_quic_init_streams(c) != NJT_OK) {
                return NJT_ERROR;
            }
        }

        return NJT_OK;
    }

#if (NJT_DEBUG)
    njt_ssl_handshake_log(c);
#endif

    c->ssl->handshaked = 1;

    frame = njt_quic_alloc_frame(c);
    if (frame == NULL) {
        return NJT_ERROR;
    }

    frame->level = ssl_encryption_application;
    frame->type = NJT_QUIC_FT_HANDSHAKE_DONE;
    njt_quic_queue_frame(qc, frame);

    if (qc->conf->retry) {
        if (njt_quic_send_new_token(c, qc->path) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    /*
     * RFC 9001, 9.5.  Header Protection Timing Side Channels
     *
     * Generating next keys before a key update is received.
     */

    njt_post_event(&qc->key_update, &njt_posted_events);

    /*
     * RFC 9001, 4.9.2.  Discarding Handshake Keys
     *
     * An endpoint MUST discard its Handshake keys
     * when the TLS handshake is confirmed.
     */
    njt_quic_discard_ctx(c, ssl_encryption_handshake);

    njt_quic_discover_path_mtu(c, qc->path);

    /* start accepting clients on negotiated number of server ids */
    if (njt_quic_create_sockets(c) != NJT_OK) {
        return NJT_ERROR;
    }

    if (njt_quic_init_streams(c) != NJT_OK) {
        return NJT_ERROR;
    }

    return NJT_OK;
}


njt_int_t
njt_quic_init_connection(njt_connection_t *c)
{
    u_char                  *p;
    size_t                   clen;
    ssize_t                  len;
    njt_str_t                dcid;
    njt_ssl_conn_t          *ssl_conn;
    njt_quic_socket_t       *qsock;
    njt_quic_connection_t   *qc;
    static SSL_QUIC_METHOD   quic_method;

    qc = njt_quic_get_connection(c);

    if (njt_ssl_create_connection(qc->conf->ssl, c, 0) != NJT_OK) {
        return NJT_ERROR;
    }

    c->ssl->no_wait_shutdown = 1;

    ssl_conn = c->ssl->connection;

    if (!quic_method.send_alert) {
#if (NJT_QUIC_BORINGSSL_API)
        quic_method.set_read_secret = njt_quic_set_read_secret;
        quic_method.set_write_secret = njt_quic_set_write_secret;
#else
        quic_method.set_encryption_secrets = njt_quic_set_encryption_secrets;
#endif
        quic_method.add_handshake_data = njt_quic_add_handshake_data;
        quic_method.flush_flight = njt_quic_flush_flight;
        quic_method.send_alert = njt_quic_send_alert;
    }

    if (SSL_set_quic_method(ssl_conn, &quic_method) == 0) {
        njt_log_error(NJT_LOG_INFO, c->log, 0,
                      "quic SSL_set_quic_method() failed");
        return NJT_ERROR;
    }

#ifdef OPENSSL_INFO_QUIC
    if (SSL_CTX_get_max_early_data(qc->conf->ssl->ctx)) {
        SSL_set_quic_early_data_enabled(ssl_conn, 1);
    }
#endif

    qsock = njt_quic_get_socket(c);

    dcid.data = qsock->sid.id;
    dcid.len = qsock->sid.len;

    if (njt_quic_new_sr_token(c, &dcid, qc->conf->sr_token_key, qc->tp.sr_token)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    len = njt_quic_create_transport_params(NULL, NULL, &qc->tp, &clen);
    /* always succeeds */

    p = njt_pnalloc(c->pool, len);
    if (p == NULL) {
        return NJT_ERROR;
    }

    len = njt_quic_create_transport_params(p, p + len, &qc->tp, NULL);
    if (len < 0) {
        return NJT_ERROR;
    }

#ifdef NJT_QUIC_DEBUG_PACKETS
    njt_log_debug3(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic transport parameters len:%uz %*xs", len, len, p);
#endif

    if (SSL_set_quic_transport_params(ssl_conn, p, len) == 0) {
        njt_log_error(NJT_LOG_INFO, c->log, 0,
                      "quic SSL_set_quic_transport_params() failed");
        return NJT_ERROR;
    }

#ifdef OPENSSL_IS_BORINGSSL
    if (SSL_set_quic_early_data_context(ssl_conn, p, clen) == 0) {
        njt_log_error(NJT_LOG_INFO, c->log, 0,
                      "quic SSL_set_quic_early_data_context() failed");
        return NJT_ERROR;
    }
#endif

    return NJT_OK;
}
