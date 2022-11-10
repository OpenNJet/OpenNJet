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
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/sm2.h"
#include "openssl/sm3.h"

/*This Demo for SM2 Signature And Verify*/
/*First: Generate A key, And output it*/
/*Second: Signature input And Output Result*/
/*Third: Verify it*/

/*Compute SM2 sign extra data: Z = HASH256(ENTL + ID + a + b + Gx + Gy + Xa + Ya)*/
int ECDSA_sm2_get_Z(const EC_KEY *ec_key, const EVP_MD *md, const char *uid, int uid_len, unsigned char *z_buf, size_t *z_len)
{
    EVP_MD_CTX *ctx;
    const EC_GROUP *group = NULL;
    BIGNUM *a = NULL, *b = NULL;
    const EC_POINT *point = NULL;
    unsigned char *z_source = NULL;
    int retval = 0;
    int deep, z_s_len;

    EC_POINT *pub_key = NULL;
    const BIGNUM *priv_key = NULL;

    if (md == NULL) md = EVP_sm3();
    if (*z_len < EVP_MD_size(EVP_sm3()))
    {
       printf("1\n");
        return 0;
    }

    group = EC_KEY_get0_group(ec_key);
    if (group == NULL)
    {
        printf("2\n");
        goto err;
    }

    a = BN_new(), b = BN_new();
    if ((a == NULL) || (b == NULL))
    {
        printf("3\n");
        goto err;
    }
    
    if (!EC_GROUP_get_curve_GFp(group, NULL, a, b, NULL))
    {
        printf("4\n");
        goto err;
    }
    
    if ((point = EC_GROUP_get0_generator(group)) == NULL)
    {
        printf("5\n");
        goto err;
    }
    
    deep = (EC_GROUP_get_degree(group) + 7) / 8;
    if ((uid == NULL) || (uid_len <= 0))
    {
        uid = (const char *)"1234567812345678";
        uid_len = 16;
    }
   
    /*alloc z_source buffer*/
    while (!(z_source = (unsigned char *)OPENSSL_malloc(1 + 4 * deep)));

    /*ready to digest*/
    ctx = EVP_MD_CTX_create();
    EVP_DigestInit(ctx, md);

    z_s_len = 0;
    /*first: set the two bytes of uid bits + uid*/
    uid_len = uid_len * 8;
    
    z_source[z_s_len++] = (unsigned char)((uid_len >> 8) & 0xFF);
    z_source[z_s_len++] = (unsigned char)(uid_len & 0xFF);
    uid_len /= 8;
    EVP_DigestUpdate(ctx, z_source, z_s_len);
    EVP_DigestUpdate(ctx, uid, uid_len);

    /*second: add a and b*/
    BN_bn2bin(a, z_source + deep - BN_num_bytes(a));
    EVP_DigestUpdate(ctx, z_source, deep);
    BN_bn2bin(b, z_source + deep - BN_num_bytes(a));
    EVP_DigestUpdate(ctx, z_source, deep);
    
    /*third: add Gx and Gy*/
    z_s_len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, z_source, (1 + 4 * deep), NULL);
    /*must exclude PC*/
    EVP_DigestUpdate(ctx, z_source + 1, z_s_len - 1);
    
    /*forth: add public key*/
    point = EC_KEY_get0_public_key(ec_key);
    if (!point)
    {
        priv_key = EC_KEY_get0_private_key(ec_key);
        if (!priv_key)
        {
            printf("6\n");
            goto err;
        }

        pub_key = EC_POINT_new(group);
        if (!pub_key)
        {
            printf("7\n");
            goto err;
        }

        if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, NULL))
        {
            printf("8\n");
            goto err;
        }

        point = (const EC_POINT *)pub_key;
    }

    z_s_len = EC_POINT_point2oct(group, /*EC_KEY_get0_public_key(ec_key)*/point, POINT_CONVERSION_UNCOMPRESSED, z_source, (1 + 4 * deep), NULL);
    /*must exclude PC*/
    EVP_DigestUpdate(ctx, z_source + 1, z_s_len - 1);
    
    /*fifth: output digest*/
    EVP_DigestFinal(ctx, z_buf, (unsigned *)z_len);
    EVP_MD_CTX_destroy(ctx);
    
    retval = (int)(*z_len);

err:
    if (z_source) OPENSSL_free(z_source);
    if (pub_key) EC_POINT_free(pub_key);
    if (a) BN_free(a);
    if (b) BN_free(b);
    
    return retval;
}


int b2s(char *bin, char *outs)
{
        int i = 0;
        char tmpbuf[4];
        int iRet = 0;
        char *ptr = bin;
        for(i = 0; i<strlen(bin)/2; i++){
                memset(tmpbuf, 0x00, sizeof(tmpbuf));
                memcpy(tmpbuf, ptr, 2);
                ptr += 2;
                iRet = strtol(tmpbuf, NULL, 16);
                #ifndef NO_DEBUG
                //printf("the iRet =[%d]\n", iRet);
                #endif
                
                memset(outs++, iRet, 1);
        }
        return i;
}

EC_KEY *CalcSm2PublicKey(const char *pubkey_hex_string, char* private_hex_x)
{

    int bn_len = 0;
    char raw_buf[128] ={0};
    BIGNUM *k = NULL;


    EC_KEY *ec_key = NULL;
    EC_POINT *pubkey = NULL;
    EC_GROUP *ec_group = NULL;

    ec_group = EC_GROUP_new_by_curve_name(OBJ_sn2nid("SM2"));
    if (ec_group == NULL)
        goto err;

    pubkey = EC_POINT_hex2point(ec_group, (const char *)pubkey_hex_string, NULL, NULL);
    if (!pubkey)
        goto err;

    ec_key = EC_KEY_new();
    if (!ec_key) goto err;
    if (!EC_KEY_set_group(ec_key, ec_group))
    {
        EC_KEY_free(ec_key);
        ec_key = NULL;
        goto err;
    }

    if (!EC_KEY_set_public_key(ec_key, pubkey))
    {
        EC_KEY_free(ec_key);
        ec_key = NULL;
        goto err;
    }
   
   
    if(private_hex_x != NULL){
        bn_len = b2s(private_hex_x, raw_buf);
        printf("bn_len = [%d]\n", bn_len);

        k = BN_new();
        if(BN_bin2bn((const unsigned char*)raw_buf, bn_len, k) == NULL){
                        printf("bin2bn fail!\n");
                        exit(0);

        }


        if (!EC_KEY_set_private_key(ec_key, k))
        {
            EC_KEY_free(ec_key);
            ec_key = NULL;
            goto err;
        }

    }



err:
    if(k) BN_free(k);
    if (pubkey) EC_POINT_free(pubkey);
    if (ec_group) EC_GROUP_free(ec_group);

    return ec_key;
}



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

	#if 0
		sm2key = CalcSm2PublicKey("0436A4D03D940769C8348CDAE53717C9BACDF1CE4988E01D9355B685B3B61A4527FC65E76292AF4FD1E4D323DC7D8D12FD130D8F914378200BD806E63E8E2796B5", NULL);
		if(sm2key == NULL){
			printf("sm2key = NULL\n");
			exit(0);
		}
	#endif
		
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
    
    
    /*Now Compute Z value*/
    dgst_len = sizeof(digest);
    if (!ECDSA_sm2_get_Z((const EC_KEY *)sm2key, NULL, NULL, 0, digest, &dgst_len))
    {
        printf("Error Of Compute Z\n");
        goto err;
    }
     printf("Z_value: [");
    for (loop = 0; loop < dgst_len; loop++)
        printf("%02X", digest[loop] & 0xFF);
    printf("]\n");
    
    
    memset(digest , 0x00, sizeof(digest));
    if(!sm2_compute_z_digest(digest, EVP_sm3(), "1234567812345678", strlen("1234567812345678"), sm2key)){
    	printf("Error Of Compute Z\n");
    	goto err;
    }
    
    dgst_len =  EVP_MD_size(EVP_sm3());

    printf("Z_value: [");
    for (loop = 0; loop < dgst_len; loop++)
        printf("%02X", digest[loop] & 0xFF);
    printf("]\n");

   ECDSA_SIG *  sig_der = NULL;
   sig_der = sm2_do_sign(sm2key, EVP_sm3(),"1234567812345678", strlen("1234567812345678"), argv[1], strlen(argv[1]));
   char * hex_r = NULL;
   hex_r = BN_bn2hex(ECDSA_SIG_get0_r(sig_der));
   char * hex_s = NULL;
   hex_s = BN_bn2hex(ECDSA_SIG_get0_s(sig_der));
   
   unsigned char *ptr_sig = NULL;
   unsigned char tmp_buf_sig[128] = {0};
   
   
	siglen = i2d_ECDSA_SIG(sig_der, &sig);

 
	#if 0
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
	#endif

		
	if(sm2_do_verify(sm2key, EVP_sm3(), sig_der, "1234567812345678", strlen("1234567812345678"), argv[1], strlen(argv[1])) != 1){
		printf("sm2_do_verify fail!\n");
		exit(0);
	}
	else{
		printf("sm2_do_verify OK!\n");
	}
		
	#if 0
	char raw_buf[128] = {0};
	int bn_len = b2s("3044022007C1AD0720CED0F14B9A7BBADE9D8B48E710356309EABE2351C13857EE0C0F8B0220299F976B5FF2EE831B32730545D0A3562F6312C2C1CE53A770FFB0666C384CD0", raw_buf);
        printf("bn_len = [%d]\n", bn_len);

	char raw_buf_digest[128] = {0};
	int bn_len_digest = b2s("B07CBC4BFF89D8E27C18A268D22A123CE60B8987F8D377CD740E5076BA84EE0E", raw_buf_digest);
        printf("bn_len_digest = [%d]\n", bn_len_digest);
    if (ECDSA_verify(0, raw_buf_digest, bn_len_digest, raw_buf, bn_len, sm2key) == 0)
    {
        printf("Error Of SM2 Signature.\n");
        goto err;
    }
    {
	printf("verify OK!\n");
    }
	#endif
err:
	 OPENSSL_clear_free(sig, siglen);
	 //ECDSA_SIG_free(sig_der);
    if (sm2group) EC_GROUP_free(sm2group);
    if (sm2key) EC_KEY_free(sm2key);
    if (out) OPENSSL_free(out);

    return 0;
}
