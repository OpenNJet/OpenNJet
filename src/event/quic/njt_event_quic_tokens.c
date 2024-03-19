
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_sha1.h>
#include <njt_event_quic_connection.h>


static void njt_quic_address_hash(struct sockaddr *sockaddr, socklen_t socklen,
    njt_uint_t no_port, u_char buf[20]);


njt_int_t
njt_quic_new_sr_token(njt_connection_t *c, njt_str_t *cid, u_char *secret,
    u_char *token)
{
    njt_str_t  tmp;

    tmp.data = secret;
    tmp.len = NJT_QUIC_SR_KEY_LEN;

    if (njt_quic_derive_key(c->log, "sr_token_key", &tmp, cid, token,
                            NJT_QUIC_SR_TOKEN_LEN)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    njt_log_debug2(NJT_LOG_DEBUG_EVENT, c->log, 0,
                   "quic stateless reset token %*xs",
                    (size_t) NJT_QUIC_SR_TOKEN_LEN, token);

    return NJT_OK;
}


njt_int_t
njt_quic_new_token(njt_log_t *log, struct sockaddr *sockaddr,
    socklen_t socklen, u_char *key, njt_str_t *token, njt_str_t *odcid,
    time_t exp, njt_uint_t is_retry)
{
    int                len, iv_len;
    u_char            *p, *iv;
    EVP_CIPHER_CTX    *ctx;
    const EVP_CIPHER  *cipher;

    u_char             in[NJT_QUIC_MAX_TOKEN_SIZE];

    njt_quic_address_hash(sockaddr, socklen, !is_retry, in);

    p = in + 20;

    p = njt_cpymem(p, &exp, sizeof(time_t));

    *p++ = is_retry ? 1 : 0;

    if (odcid) {
        *p++ = odcid->len;
        p = njt_cpymem(p, odcid->data, odcid->len);

    } else {
        *p++ = 0;
    }

    len = p - in;

    cipher = EVP_aes_256_gcm();
    iv_len = NJT_QUIC_AES_256_GCM_IV_LEN;

    if ((size_t) (iv_len + len + NJT_QUIC_AES_256_GCM_TAG_LEN) > token->len) {
        njt_log_error(NJT_LOG_ALERT, log, 0, "quic token buffer is too small");
        return NJT_ERROR;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return NJT_ERROR;
    }

    iv = token->data;

    if (RAND_bytes(iv, iv_len) <= 0
        || !EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv))
    {
        EVP_CIPHER_CTX_free(ctx);
        return NJT_ERROR;
    }

    token->len = iv_len;

    if (EVP_EncryptUpdate(ctx, token->data + token->len, &len, in, len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return NJT_ERROR;
    }

    token->len += len;

    if (EVP_EncryptFinal_ex(ctx, token->data + token->len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return NJT_ERROR;
    }

    token->len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                            NJT_QUIC_AES_256_GCM_TAG_LEN,
                            token->data + token->len)
        == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        return NJT_ERROR;
    }

    token->len += NJT_QUIC_AES_256_GCM_TAG_LEN;

    EVP_CIPHER_CTX_free(ctx);

#ifdef NJT_QUIC_DEBUG_PACKETS
    njt_log_debug2(NJT_LOG_DEBUG_EVENT, log, 0,
                   "quic new token len:%uz %xV", token->len, token);
#endif

    return NJT_OK;
}


static void
njt_quic_address_hash(struct sockaddr *sockaddr, socklen_t socklen,
    njt_uint_t no_port, u_char buf[20])
{
    size_t                len;
    u_char               *data;
    njt_sha1_t            sha1;
    struct sockaddr_in   *sin;
#if (NJT_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    len = (size_t) socklen;
    data = (u_char *) sockaddr;

    if (no_port) {
        switch (sockaddr->sa_family) {

#if (NJT_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) sockaddr;

            len = sizeof(struct in6_addr);
            data = sin6->sin6_addr.s6_addr;

            break;
#endif

        case AF_INET:
            sin = (struct sockaddr_in *) sockaddr;

            len = sizeof(in_addr_t);
            data = (u_char *) &sin->sin_addr;

            break;
        }
    }

    njt_sha1_init(&sha1);
    njt_sha1_update(&sha1, data, len);
    njt_sha1_final(buf, &sha1);
}


njt_int_t
njt_quic_validate_token(njt_connection_t *c, u_char *key,
    njt_quic_header_t *pkt)
{
    int                len, tlen, iv_len;
    u_char            *iv, *p;
    time_t             now, exp;
    size_t             total;
    njt_str_t          odcid;
    EVP_CIPHER_CTX    *ctx;
    const EVP_CIPHER  *cipher;

    u_char             addr_hash[20];
    u_char             tdec[NJT_QUIC_MAX_TOKEN_SIZE];

#if NJT_SUPPRESS_WARN
    njt_str_null(&odcid);
#endif

    /* Retry token or NEW_TOKEN in a previous connection */

    cipher = EVP_aes_256_gcm();
    iv = pkt->token.data;
    iv_len = NJT_QUIC_AES_256_GCM_IV_LEN;

    /* sanity checks */

    if (pkt->token.len < (size_t) iv_len + NJT_QUIC_AES_256_GCM_TAG_LEN) {
        goto garbage;
    }

    if (pkt->token.len > (size_t) iv_len + NJT_QUIC_MAX_TOKEN_SIZE
                         + NJT_QUIC_AES_256_GCM_TAG_LEN)
    {
        goto garbage;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return NJT_ERROR;
    }

    if (!EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return NJT_ERROR;
    }

    p = pkt->token.data + iv_len;
    len = pkt->token.len - iv_len - NJT_QUIC_AES_256_GCM_TAG_LEN;

    if (EVP_DecryptUpdate(ctx, tdec, &tlen, p, len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        goto garbage;
    }
    total = tlen;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                            NJT_QUIC_AES_256_GCM_TAG_LEN, p + len)
        == 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        goto garbage;
    }

    if (EVP_DecryptFinal_ex(ctx, tdec + tlen, &tlen) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        goto garbage;
    }
    total += tlen;

    EVP_CIPHER_CTX_free(ctx);

    if (total < (20 + sizeof(time_t) + 2)) {
        goto garbage;
    }

    p = tdec + 20;

    njt_memcpy(&exp, p, sizeof(time_t));
    p += sizeof(time_t);

    pkt->retried = (*p++ == 1);

    njt_quic_address_hash(c->sockaddr, c->socklen, !pkt->retried, addr_hash);

    if (njt_memcmp(tdec, addr_hash, 20) != 0) {
        goto bad_token;
    }

    odcid.len = *p++;
    if (odcid.len) {
        if (odcid.len > NJT_QUIC_MAX_CID_LEN) {
            goto bad_token;
        }

        if ((size_t)(tdec + total - p) < odcid.len) {
            goto bad_token;
        }

        odcid.data = p;
    }

    now = njt_time();

    if (now > exp) {
        njt_log_error(NJT_LOG_INFO, c->log, 0, "quic expired token");
        return NJT_DECLINED;
    }

    if (odcid.len) {
        pkt->odcid.len = odcid.len;
        pkt->odcid.data = pkt->odcid_buf;
        njt_memcpy(pkt->odcid.data, odcid.data, odcid.len);

    } else {
        pkt->odcid = pkt->dcid;
    }

    pkt->validated = 1;

    return NJT_OK;

garbage:

    njt_log_error(NJT_LOG_INFO, c->log, 0, "quic garbage token");

    return NJT_ABORT;

bad_token:

    njt_log_error(NJT_LOG_INFO, c->log, 0, "quic invalid token");

    return NJT_DECLINED;
}
