/*
 * Written by caichenghang for the TaSSL project.
 */
/* ====================================================================
 * Copyright (c) 2016 - 2018 Beijing JN TASS Technology Co.,Ltd.  All
 * rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by Beijing JN TASS
 *    Technology Co.,Ltd. TaSSL Project.(http://www.tass.com.cn/)"
 *
 * 4. The name "TaSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    TaSSL@tass.com.cn.
 *
 * 5. Products derived from this software may not be called "TaSSL"
 *    nor may "TaSSL" appear in their names without prior written
 *    permission of the TaSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Beijing JN TASS
 *    Technology Co.,Ltd. TaSSL Project.(http://www.tass.com.cn/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE TASSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE TASSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes software developed by the TaSSL Project
 * for use in the OpenSSL Toolkit (http://www.openssl.org/).
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "openssl/evp.h"
#include "openssl/sm2.h"
#include "crypto/include/internal/evp_int.h"
#include "crypto/evp/evp_locl.h"

int main(int argc, char *argv[])
{
    EVP_PKEY *sm2key = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned char *out = NULL;
    size_t len;
    int loop, ilen;
    
    if (argc < 2)
    {
        printf("Usage: %s testmessage\n", argv[0]);
        exit(0);
    }
    
    OpenSSL_add_all_algorithms();

    /*First Generate SM2 Key*/
    sm2key = EVP_PKEY_new();
    if (!sm2key)
    {
        printf("Alloc EVP_PKEY Object error.\n");
        goto err;
    }

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx)
    {
        printf("Create EVP_PKEY_CTX Object error.\n");
        goto err;
    }
    
    EVP_PKEY_keygen_init(pctx);
    if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_sm2))
    {
        printf("Set EC curve name error.\n");
        goto err;
    }
    
    if (!EVP_PKEY_CTX_set_ec_param_enc(pctx, OPENSSL_EC_NAMED_CURVE))
    {
        printf("Set EC curve is named curve error.\n");
        goto err;
    }
    
    if (EVP_PKEY_keygen(pctx, &sm2key) <= 0)
    {
        printf("Generate SM2 key error.\n");
        goto err;
    }
    
    /*OUTPUT EVP PKEY*/
    len = i2d_PrivateKey(sm2key, &out);
    if (len <= 0)
    {
        printf("Output SM2 Private Key Error.\n");
        goto err;
    }
    
    printf("Generated SM2 Key: [");
    for (loop = 0; loop < len; loop++)
        printf("%02X", out[loop] & 0xff);
    printf("]\n");

    /*Calculate Z value*/
    len = sizeof(digest);
    if (!ECDSA_sm2_get_Z(sm2key->pkey.ec, NULL, NULL, 0, digest, &len))
    {
        printf("Calculate Z value Error.\n");
        goto err;
    }
    
    printf("Calculate Z-value: [");
    for (loop = 0; loop < len; loop++)
        printf("%02X", digest[loop] & 0xff);
    printf("]\n");

    /*Calculate DIGEST*/
    //EVP_MD_CTX_init(md_ctx_ptr);
    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        printf("EVP_MD_CTX_new() fail!\n");
        goto err;
    }
    EVP_SignInit(md_ctx, EVP_sm3());
    EVP_SignUpdate(md_ctx, digest, len);
    EVP_SignUpdate(md_ctx, argv[1], (size_t)strlen(argv[1]));
    if (!EVP_SignFinal(md_ctx, NULL, (unsigned int *)&ilen, sm2key))
    {
        printf("Calculate Signature Length error!\n");
        goto err;
    }
    
    /*ALLOC Sign BUFFER*/
    if (out) OPENSSL_free(out);
    out = OPENSSL_malloc(ilen);
    if (!out)
    {
        printf("Error of alloc memory.\n");
        goto err;
    }

    /*SIGN*/
    if (!EVP_SignFinal(md_ctx, out, (unsigned int *)&ilen, sm2key))
    {
        printf("Calculate Signature Length error!\n");
        goto err;
    }
    
    printf("[%s] Signature: [", argv[1]);
    for (loop = 0; loop < ilen; loop++)
        printf("%02X", out[loop] & 0xff);
    printf("]\n");
    
    EVP_MD_CTX_free(md_ctx);

    /*VERIFY*/
    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        printf("EVP_MD_CTX_new() fail!\n");
        goto err;
    }
    EVP_VerifyInit(md_ctx, EVP_sm3());
    EVP_VerifyUpdate(md_ctx, digest, len);
    EVP_VerifyUpdate(md_ctx, argv[1], (size_t)strlen(argv[1]));
    if (EVP_VerifyFinal(md_ctx, (const unsigned char *)out, (unsigned int)ilen, sm2key) <= 0)
    {    
        printf("EVP_PKEY_verify Error.\n");
    }
    else
    {
        printf("EVP_PKEY_verify Successed.\n");
    }

err:
    if (sm2key) EVP_PKEY_free(sm2key);
    if (pctx) EVP_PKEY_CTX_free(pctx);
    if (out) OPENSSL_free(out);

    return 0;
}
