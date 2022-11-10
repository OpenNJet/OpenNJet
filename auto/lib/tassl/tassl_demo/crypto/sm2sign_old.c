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
#include "crypto/include/internal/sm2.h"
#include "crypto/include/internal/sm3.h"

/*This Demo for SM2 Signature And Verify*/
/*First: Generate A key, And output it*/
/*Second: Signature input And Output Result*/
/*Third: Verify it*/
int main(int argc, char *argv[])
{
    EC_GROUP *sm2group = NULL;
    EC_KEY *sm2key = NULL;
    SM3_CTX sm3_ctx;
    char *out = NULL;
    unsigned char *sig = NULL;
    unsigned char digest[SM3_DIGEST_LENGTH];
    size_t dgst_len;
    int loop, siglen;

    if (argc < 2)
    {
        printf("Usage: %s testmessage\n", argv[0]);
        exit(0);
    }

    /*Gain SM2 Group Object*/
    sm2group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (!sm2group)
    {
        printf("Error Of Gain SM2 Group Object.\n");
        goto err;
    }

    /*Generate SM2 Key*/
    sm2key = EC_KEY_new();
    if (!sm2key)
    {
        printf("Error Of Alloc Memory for SM2 Key.\n");
        goto err;
    }

    if (EC_KEY_set_group(sm2key, (const EC_GROUP *)sm2group) == 0)
    {
        printf("Error Of Set SM2 Group into key.\n");
        goto err;
    }

    if (EC_KEY_generate_key(sm2key) == 0)
    {
        printf("Error Of Generate SM2 Key.\n");
        goto err;
    }

    /*Output SM2 Key*/
    out = BN_bn2hex(EC_KEY_get0_private_key(sm2key));
    if (!out)
    {
        printf("Error Of Output SM2 Private key.\n");
        goto err;
    }

    printf("Generated SM2 Private Key: [%s]\n", out);
    OPENSSL_free(out);
    out = EC_POINT_point2hex(sm2group, EC_KEY_get0_public_key(sm2key), POINT_CONVERSION_UNCOMPRESSED, NULL);
    if (!out)
    {
        printf("Error Of Output SM2 Public key.\n");
        goto err;
    }

    printf("              Public Key: [%s]\n", out);
    OPENSSL_free(out);
    out = NULL;

 #if 0
    /*Now Compute Z value*/
    dgst_len = sizeof(digest);
    if (!ECDSA_sm2_get_Z((const EC_KEY *)sm2key, NULL, NULL, 0, digest, &dgst_len))
    {
        printf("Error Of Compute Z\n");
        goto err;
    }
#endif 
	memset(digest , 0x00, sizeof(digest));
    if(!sm2_compute_z_digest(digest, EVP_sm3(), "1234567812345678", strlen("1234567812345678"), sm2key)){
        printf("Error Of Compute Z\n");
        goto err;
    }

    printf("Z_value: [");
    for (loop = 0; loop < 32; loop++)
        printf("%02X", digest[loop] & 0xFF);
    printf("]\n");

    /*Now Compute Digest*/
    sm3_init(&sm3_ctx);
    sm3_update(&sm3_ctx, digest, dgst_len);
    sm3_update(&sm3_ctx, argv[1], (size_t)strlen(argv[1]));
    sm3_final(digest, &sm3_ctx);

    printf("[%s] SM3 Digest: [", argv[1]);
    for (loop = 0; loop < SM3_DIGEST_LENGTH; loop++)
        printf("%02X", digest[loop] & 0xFF);
    printf("]\n");

    /*NOW CALL SM2 Sign:*/
    siglen = ECDSA_size((const EC_KEY *)sm2key);
    sig = OPENSSL_malloc(siglen);
    if (!sig)
    {
        printf("Error Of Alloc Memory.\n");
        goto err;
    }

    /*Of course, you can call ECDSA_do_sign, sm2_do_sign instead of following function*/    
    if (ECDSA_sign(0, digest, (int)dgst_len, sig, &siglen, sm2key) == 0)
    {
        printf("Error Of SM2 Signature.\n");
        goto err;
    }

    printf("[%s] SM2 Sig: [", argv[1]);
    for (loop = 0; loop < siglen; loop++)
        printf("%02X", sig[loop] & 0xFF);
    printf("]\n");

    /*Now Verify it*/
    if (ECDSA_verify(0, digest, (int)dgst_len, (const unsigned char *)sig, siglen, sm2key) <= 0)
    {
        printf("Error Of SM2 Verify.\n");
    }
    else
    {
        printf("SM2 Verify successed.\n");
    }

err:
    if (sm2group) EC_GROUP_free(sm2group);
    if (sm2key) EC_KEY_free(sm2key);
    if (out) OPENSSL_free(out);
    if (sig) OPENSSL_free(sig);

    return 0;
}
