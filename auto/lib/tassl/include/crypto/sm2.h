/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 * Ported from Ribose contributions from Botan.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_SM2_H
# define OSSL_CRYPTO_SM2_H
# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_SM2

#  include <openssl/ec.h>

# ifdef  __cplusplus
extern "C" {
# endif

typedef struct SM2_Ciphertext_st SM2_Ciphertext;
DECLARE_ASN1_FUNCTIONS(SM2_Ciphertext)

#ifndef OPENSSL_NO_CNSM
/*described in section 7.4, GMT 0009/2014.
 * add by ysc at 20210305*/
typedef struct SM2_Enveloped_Key_st SM2_Enveloped_Key;
DECLARE_ASN1_FUNCTIONS(SM2_Enveloped_Key)
BIO *SM2_Enveloped_Key_dataDecode(SM2_Enveloped_Key *sm2evpkey, EVP_PKEY *pkey );
#endif

#ifndef OPENSSL_NO_CNSM
int SM2_Ciphertext_get0(const SM2_Ciphertext *cipher,
            const BIGNUM **pC1x, const BIGNUM **pC1y,
            const ASN1_OCTET_STRING **pC3, const ASN1_OCTET_STRING **pC2);

const BIGNUM *SM2_Ciphertext_get0_C1x(const SM2_Ciphertext *cipher);

const BIGNUM *SM2_Ciphertext_get0_C1y(const SM2_Ciphertext *cipher);

const ASN1_OCTET_STRING *SM2_Ciphertext_get0_C3(const SM2_Ciphertext *cipher);

const ASN1_OCTET_STRING *SM2_Ciphertext_get0_C2(const SM2_Ciphertext *cipher);

int SM2_Ciphertext_set0(SM2_Ciphertext *cipher, BIGNUM *C1x, BIGNUM *C1y, ASN1_OCTET_STRING *C3, ASN1_OCTET_STRING *C2);
#endif

/* The default user id as specified in GM/T 0009-2012 */
#  define SM2_DEFAULT_USERID "1234567812345678"

int sm2_compute_z_digest(uint8_t *out,
                         const EVP_MD *digest,
                         const uint8_t *id,
                         const size_t id_len,
                         const EC_KEY *key);

/*
 * SM2 signature operation. Computes Z and then signs H(Z || msg) using SM2
 */
ECDSA_SIG *sm2_do_sign(const EC_KEY *key,
                       const EVP_MD *digest,
                       const uint8_t *id,
                       const size_t id_len,
                       const uint8_t *msg, size_t msg_len);

int sm2_do_verify(const EC_KEY *key,
                  const EVP_MD *digest,
                  const ECDSA_SIG *signature,
                  const uint8_t *id,
                  const size_t id_len,
                  const uint8_t *msg, size_t msg_len);

/*
 * SM2 signature generation.
 */
int sm2_sign(const unsigned char *dgst, int dgstlen,
             unsigned char *sig, unsigned int *siglen, EC_KEY *eckey);

/*
 * SM2 signature verification.
 */
int sm2_verify(const unsigned char *dgst, int dgstlen,
               const unsigned char *sig, int siglen, EC_KEY *eckey);

/*
 * SM2 encryption
 */
int sm2_ciphertext_size(const EC_KEY *key, const EVP_MD *digest, size_t msg_len,
                        size_t *ct_size);

int sm2_plaintext_size(const unsigned char *ct, size_t ct_size, size_t *pt_size);

int sm2_encrypt(const EC_KEY *key,
                const EVP_MD *digest,
                const uint8_t *msg,
                size_t msg_len,
                uint8_t *ciphertext_buf, size_t *ciphertext_len);

int sm2_decrypt(const EC_KEY *key,
                const EVP_MD *digest,
                const uint8_t *ciphertext,
                size_t ciphertext_len, uint8_t *ptext_buf, size_t *ptext_len);

int SM2Kap_compute_key(void *out, size_t outlen, int responsor,\
    const char *peer_uid, int peer_uid_len, const char *self_uid, int self_uid_len, \
    const EC_KEY *peer_ecdhe_key, const EC_KEY *self_ecdhe_key, const EC_KEY *peer_pub_key, const EC_KEY *self_eckey, \
    const EVP_MD *md);

int ECDSA_sm2_get_Z(const EC_KEY *ec_key, const EVP_MD *md, const char *uid, int uid_len, unsigned char *z_buf, size_t *z_len);
# ifdef __cplusplus
}
# endif

# endif /* OPENSSL_NO_SM2 */
#endif
