/*
 * Copyright 2006-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include "crypto/evp.h"
#include "crypto/sm2.h"
#include "crypto/sm2err.h"

/* EC pkey context structure */

typedef struct {
    /* Key and paramgen group */
    EC_GROUP *gen_group;
    /* message digest */
    const EVP_MD *md;
    /* Distinguishing Identifier, ISO/IEC 15946-3 */
    uint8_t *id;
    size_t id_len;
    /* id_set indicates if the 'id' field is set (1) or not (0) */
    int id_set;
    /* peer id for SM2 key exchange only */
    uint8_t *peer_id;
    size_t peer_id_len;
    int peer_id_set;
    /* self ephemeral key for SM2 key exchange only */
    EC_KEY *ekey;
    /* peer ephemeral key for SM2 key exchange only */
    EC_KEY *peer_ekey;
    /* for SM2 key exchange only */
    int responsor;
} SM2_PKEY_CTX;

static int pkey_sm2_init(EVP_PKEY_CTX *ctx)
{
    SM2_PKEY_CTX *smctx;

    if ((smctx = OPENSSL_zalloc(sizeof(*smctx))) == NULL) {
        SM2err(SM2_F_PKEY_SM2_INIT, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    ctx->data = smctx;
    return 1;
}

static void pkey_sm2_cleanup(EVP_PKEY_CTX *ctx)
{
    SM2_PKEY_CTX *smctx = ctx->data;

    if (smctx != NULL) {
        EC_KEY_free(smctx->ekey);
        EC_KEY_free(smctx->peer_ekey);
        EC_GROUP_free(smctx->gen_group);
        OPENSSL_free(smctx->id);
        OPENSSL_free(smctx->peer_id);
        OPENSSL_free(smctx);
        ctx->data = NULL;
    }
}

static int pkey_sm2_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    SM2_PKEY_CTX *dctx, *sctx;

    if (!pkey_sm2_init(dst))
        return 0;
    sctx = src->data;
    dctx = dst->data;
    if (sctx->ekey != NULL) {
        dctx->ekey = EC_KEY_dup(sctx->ekey);
        if (dctx->ekey == NULL) {
            pkey_sm2_cleanup(dst);
            return 0;
        }
    }
    if (sctx->peer_ekey != NULL) {
        dctx->peer_ekey = EC_KEY_dup(sctx->peer_ekey);
        if (dctx->peer_ekey == NULL) {
            pkey_sm2_cleanup(dst);
            return 0;
        }
    }
    if (sctx->gen_group != NULL) {
        dctx->gen_group = EC_GROUP_dup(sctx->gen_group);
        if (dctx->gen_group == NULL) {
            pkey_sm2_cleanup(dst);
            return 0;
        }
    }
    if (sctx->id != NULL) {
        dctx->id = OPENSSL_malloc(sctx->id_len);
        if (dctx->id == NULL) {
            SM2err(SM2_F_PKEY_SM2_COPY, ERR_R_MALLOC_FAILURE);
            pkey_sm2_cleanup(dst);
            return 0;
        }
        memcpy(dctx->id, sctx->id, sctx->id_len);
    }
    dctx->id_len = sctx->id_len;
    dctx->id_set = sctx->id_set;
    if (sctx->peer_id != NULL) {
        dctx->peer_id = OPENSSL_malloc(sctx->peer_id_len);
        if (dctx->peer_id == NULL) {
            SM2err(SM2_F_PKEY_SM2_COPY, ERR_R_MALLOC_FAILURE);
            pkey_sm2_cleanup(dst);
            return 0;
        }
        memcpy(dctx->peer_id, sctx->peer_id, sctx->peer_id_len);
    }
    dctx->peer_id_len = sctx->peer_id_len;
    dctx->peer_id_set = sctx->peer_id_set;
    dctx->md = sctx->md;

    return 1;
}

static int pkey_sm2_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    EC_KEY *ec = NULL;
    SM2_PKEY_CTX *dctx = ctx->data;
    int ret;

    if (dctx->gen_group == NULL) {
        dctx->gen_group = EC_GROUP_new_by_curve_name(NID_sm2);
        if (dctx->gen_group == NULL) {
            return 0;
        }
    }
    ec = EC_KEY_new();
    if (ec == NULL)
      return 0;
    if (!(ret = EC_KEY_set_group(ec, dctx->gen_group))
                || !ossl_assert(ret = EVP_PKEY_assign_EC_KEY(pkey, ec)))
      EC_KEY_free(ec);
    
    if (!EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2)) {
        return 0;
    }
    return ret;
}

static int pkey_sm2_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    EC_KEY *ec = NULL;
    SM2_PKEY_CTX *dctx = ctx->data;
    int ret;

    ec = EC_KEY_new();
    if (ec == NULL)
        return 0;
    if (!ossl_assert(EVP_PKEY_assign_EC_KEY(pkey, ec))) {
        EC_KEY_free(ec);
        return 0;
    }
    if (!EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2)) {
        return 0;
    }
    if (dctx->gen_group == NULL) {
        dctx->gen_group = EC_GROUP_new_by_curve_name(NID_sm2);
        if (dctx->gen_group == NULL) {
            return 0;
        }
    }
    /* Note: if error is returned, we count on caller to free pkey->pkey.ec */
    if (ctx->pkey != NULL)
        ret = EVP_PKEY_copy_parameters(pkey, ctx->pkey);
    else
        ret = EC_KEY_set_group(ec, dctx->gen_group);

    return ret ? EC_KEY_generate_key(ec) : 0;
}

static int pkey_sm2_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                         const unsigned char *tbs, size_t tbslen)
{
    int ret;
    unsigned int sltmp;
    EC_KEY *ec = ctx->pkey->pkey.ec;
    const int sig_sz = ECDSA_size(ctx->pkey->pkey.ec);

    if (sig_sz <= 0) {
        return 0;
    }

    if (sig == NULL) {
        *siglen = (size_t)sig_sz;
        return 1;
    }

    if (*siglen < (size_t)sig_sz) {
        SM2err(SM2_F_PKEY_SM2_SIGN, SM2_R_BUFFER_TOO_SMALL);
        return 0;
    }

    ret = sm2_sign(tbs, tbslen, sig, &sltmp, ec);

    if (ret <= 0)
        return ret;
    *siglen = (size_t)sltmp;
    return 1;
}

static int pkey_sm2_verify(EVP_PKEY_CTX *ctx,
                           const unsigned char *sig, size_t siglen,
                           const unsigned char *tbs, size_t tbslen)
{
    EC_KEY *ec = ctx->pkey->pkey.ec;

    return sm2_verify(tbs, tbslen, sig, siglen, ec);
}

static int pkey_sm2_encrypt(EVP_PKEY_CTX *ctx,
                            unsigned char *out, size_t *outlen,
                            const unsigned char *in, size_t inlen)
{
    EC_KEY *ec = ctx->pkey->pkey.ec;
    SM2_PKEY_CTX *dctx = ctx->data;
    const EVP_MD *md = (dctx->md == NULL) ? EVP_sm3() : dctx->md;

    if (out == NULL) {
        if (!sm2_ciphertext_size(ec, md, inlen, outlen))
            return -1;
        else
            return 1;
    }

    return sm2_encrypt(ec, md, in, inlen, out, outlen);
}

static int pkey_sm2_decrypt(EVP_PKEY_CTX *ctx,
                            unsigned char *out, size_t *outlen,
                            const unsigned char *in, size_t inlen)
{
    EC_KEY *ec = ctx->pkey->pkey.ec;
    SM2_PKEY_CTX *dctx = ctx->data;
    const EVP_MD *md = (dctx->md == NULL) ? EVP_sm3() : dctx->md;

    if (out == NULL) {
        if (!sm2_plaintext_size(in, inlen, outlen))
            return -1;
        else
            return 1;
    }

    return sm2_decrypt(ec, md, in, inlen, out, outlen);
}

static int pkey_sm2_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
            size_t *keylen)
{
    int ret;                                                                                
    SM2_PKEY_CTX *dctx = ctx->data;                                                         

    if (!ctx->pkey || !ctx->peerkey) {
        ECerr(EC_F_PKEY_SM2_DERIVE, EC_R_KEYS_NOT_SET);
        return 0;
    }

    if (!dctx->ekey || !dctx->peer_ekey) {
        ECerr(EC_F_PKEY_SM2_DERIVE, EC_R_EKEYS_NOT_SET);
        return 0;
    }

    if (!key || (*keylen == 0))
    {
        ECerr(EC_F_PKEY_SM2_DERIVE, EC_R_MISSING_PARAMETERS);
        return 0;
    }

    ret = SM2Kap_compute_key(key, *keylen, dctx->responsor,
                dctx->peer_id_set ? (const char *)dctx->peer_id : SM2_DEFAULT_USERID,
                dctx->peer_id_set ? dctx->peer_id_len : sizeof(SM2_DEFAULT_USERID)-1,
                dctx->id_set ? (const char *)dctx->id : SM2_DEFAULT_USERID,
                dctx->id_set ? dctx->id_len : sizeof(SM2_DEFAULT_USERID)-1,
                dctx->peer_ekey, dctx->ekey,
                ctx->peerkey->pkey.ec, ctx->pkey->pkey.ec, dctx->md ? dctx->md : EVP_sm3());
    if (ret <= 0)
      return 0;
    return 1;
}

static int pkey_sm2_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    SM2_PKEY_CTX *smctx = ctx->data;
    EC_GROUP *group;
    uint8_t *tmp_id;
    EC_KEY *ekey = NULL;

    switch (type) {
    case EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID:
        group = EC_GROUP_new_by_curve_name(p1);
        if (group == NULL) {
            SM2err(SM2_F_PKEY_SM2_CTRL, SM2_R_INVALID_CURVE);
            return 0;
        }
        EC_GROUP_free(smctx->gen_group);
        smctx->gen_group = group;
        return 1;

    case EVP_PKEY_CTRL_EC_PARAM_ENC:
        if (smctx->gen_group == NULL) {
            SM2err(SM2_F_PKEY_SM2_CTRL, SM2_R_NO_PARAMETERS_SET);
            return 0;
        }
        EC_GROUP_set_asn1_flag(smctx->gen_group, p1);
        return 1;

    case EVP_PKEY_CTRL_MD:
        smctx->md = p2;
        return 1;

    case EVP_PKEY_CTRL_GET_MD:
        *(const EVP_MD **)p2 = smctx->md;
        return 1;

    case EVP_PKEY_CTRL_SET1_ID:
        if (p1 > 0) {
            tmp_id = OPENSSL_malloc(p1);
            if (tmp_id == NULL) {
                SM2err(SM2_F_PKEY_SM2_CTRL, ERR_R_MALLOC_FAILURE);
                return 0;
            }
            memcpy(tmp_id, p2, p1);
            OPENSSL_free(smctx->id);
            smctx->id = tmp_id;
        } else {
            /* set null-ID */
            OPENSSL_free(smctx->id);
            smctx->id = NULL;
        }
        smctx->id_len = (size_t)p1;
        smctx->id_set = 1;
        return 1;

    case EVP_PKEY_CTRL_SET1_PEER_ID:
        if (p1 > 0) {
            tmp_id = OPENSSL_malloc(p1);
            if (tmp_id == NULL) {
                SM2err(SM2_F_PKEY_SM2_CTRL, ERR_R_MALLOC_FAILURE);
                return 0;
            }
            memcpy(tmp_id, p2, p1);
            OPENSSL_free(smctx->peer_id);
            smctx->peer_id = tmp_id;
        } else {
            /* set null-ID */
            OPENSSL_free(smctx->peer_id);
            smctx->peer_id = NULL;
        }
        smctx->peer_id_len = (size_t)p1;
        smctx->peer_id_set = 1;
        return 1;

    case EVP_PKEY_CTRL_GET1_ID:
        memcpy(p2, smctx->id, smctx->id_len);
        return 1;

    case EVP_PKEY_CTRL_GET1_PEER_ID:
        memcpy(p2, smctx->peer_id, smctx->peer_id_len);
        return 1;

    case EVP_PKEY_CTRL_GET1_ID_LEN:
        *(size_t *)p2 = smctx->id_len;
        return 1;

    case EVP_PKEY_CTRL_GET1_PEER_ID_LEN:
        *(size_t *)p2 = smctx->peer_id_len;
        return 1;

    case EVP_PKEY_CTRL_SET_RESPONSOR:
        smctx->responsor = p1;
        return 1;

    case EVP_PKEY_CTRL_SET1_EKEY:
        ekey = EC_KEY_dup(EVP_PKEY_get0_EC_KEY((EVP_PKEY *)p2));
        if (NULL == ekey)
          return 0;
        EC_KEY_free(smctx->ekey);
        smctx->ekey = ekey;
        return 1;

    case EVP_PKEY_CTRL_SET1_PEER_EKEY:
        ekey = EC_KEY_dup(EVP_PKEY_get0_EC_KEY((EVP_PKEY *)p2));
        if (NULL == ekey)
          return 0;
        EC_KEY_free(smctx->peer_ekey);
        smctx->peer_ekey = ekey;
        return 1;

    case EVP_PKEY_CTRL_PKCS7_ENCRYPT:
    case EVP_PKEY_CTRL_PKCS7_DECRYPT:
    case EVP_PKEY_CTRL_PEER_KEY:
    case EVP_PKEY_CTRL_DIGESTINIT:
        /* nothing to be inited, this is to suppress the error... */
        return 1;

    default:
        return -2;
    }
}

static int pkey_sm2_ctrl_str(EVP_PKEY_CTX *ctx,
                             const char *type, const char *value)
{
    if (strcmp(type, "ec_paramgen_curve") == 0) {
        int nid = NID_undef;

        if (((nid = EC_curve_nist2nid(value)) == NID_undef)
            && ((nid = OBJ_sn2nid(value)) == NID_undef)
            && ((nid = OBJ_ln2nid(value)) == NID_undef)) {
            SM2err(SM2_F_PKEY_SM2_CTRL_STR, SM2_R_INVALID_CURVE);
            return 0;
        }
        return EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
    } else if (strcmp(type, "ec_param_enc") == 0) {
        int param_enc;

        if (strcmp(value, "explicit") == 0)
            param_enc = 0;
        else if (strcmp(value, "named_curve") == 0)
            param_enc = OPENSSL_EC_NAMED_CURVE;
        else
            return -2;
        return EVP_PKEY_CTX_set_ec_param_enc(ctx, param_enc);
    }

    return -2;
}

static int pkey_sm2_digest_custom(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
    uint8_t z[EVP_MAX_MD_SIZE];
    SM2_PKEY_CTX *smctx = ctx->data;
    EC_KEY *ec = ctx->pkey->pkey.ec;
    const EVP_MD *md = EVP_MD_CTX_md(mctx);
    int mdlen = EVP_MD_size(md);

    if (mdlen < 0) {
        SM2err(SM2_F_PKEY_SM2_DIGEST_CUSTOM, SM2_R_INVALID_DIGEST);
        return 0;
    }

    /* get hashed prefix 'z' of tbs message */
    if (!sm2_compute_z_digest(z, md, smctx->id_set ? smctx->id : (const uint8_t *)SM2_DEFAULT_USERID,
                    smctx->id_set ? smctx->id_len : sizeof(SM2_DEFAULT_USERID)-1, ec))
      return 0;

    return EVP_DigestUpdate(mctx, z, (size_t)mdlen);
}

const EVP_PKEY_METHOD sm2_pkey_meth = {
    EVP_PKEY_SM2,
    0,
    pkey_sm2_init,
    pkey_sm2_copy,
    pkey_sm2_cleanup,

    0,
    pkey_sm2_paramgen,

    0,
    pkey_sm2_keygen,
    0,
    pkey_sm2_sign,
    0,
    pkey_sm2_verify,

    0, 0,

    0, 0, 0, 0,

    0,
    pkey_sm2_encrypt,

    0,
    pkey_sm2_decrypt,

    0,
    pkey_sm2_derive,
    pkey_sm2_ctrl,
    pkey_sm2_ctrl_str,

    0, 0,

    0, 0, 0,

    pkey_sm2_digest_custom
};
