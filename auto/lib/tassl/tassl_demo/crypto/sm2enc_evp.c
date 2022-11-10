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
#include "openssl/ec.h"


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



EC_KEY *CalculateKey(const EC_GROUP *ec_group, const char *privkey_hex_string)
{
	EC_KEY *ec_key = NULL;
	EC_POINT *pubkey = NULL;
	BIGNUM *privkey = NULL;

	if (!BN_hex2bn(&privkey, (const char *)privkey_hex_string)) return NULL;
	if ((pubkey = EC_POINT_new(ec_group)) == NULL) goto err;
	if (!ec_key)
	{
		ec_key = EC_KEY_new();
		if (!ec_key) goto err;
		if (!EC_KEY_set_group(ec_key, ec_group))
		{
			EC_KEY_free(ec_key);
			ec_key = NULL;
			goto err;
		}
	}

	if (!EC_POINT_mul(ec_group, pubkey, privkey, NULL, NULL, NULL))
	{
		EC_KEY_free(ec_key);
		ec_key = NULL;
		goto err;
	}

	if (!EC_KEY_set_private_key(ec_key, privkey) || !EC_KEY_set_public_key(ec_key, pubkey))
	{
		EC_KEY_free(ec_key);
		ec_key = NULL;
		goto err;
	}

err:
	if (privkey) BN_free(privkey);
	if (pubkey) EC_POINT_free(pubkey);

	return ec_key;
}

EC_KEY *CalculatePubKey(const EC_GROUP *ec_group, const char *pub_hex_string)
{
	EC_KEY *ec_key = NULL;
	EC_POINT *pubkey = NULL;

	if ((pubkey = EC_POINT_new(ec_group)) == NULL) goto err;
	if (!EC_POINT_hex2point(ec_group, pub_hex_string, pubkey, NULL)) goto err;
    
	if (!ec_key)
	{
		ec_key = EC_KEY_new();
		if (!ec_key) goto err;
		if (!EC_KEY_set_group(ec_key, ec_group))
		{
			EC_KEY_free(ec_key);
			ec_key = NULL;
			goto err;
		}
	}

	if (!EC_KEY_set_public_key(ec_key, pubkey))
	{
		EC_KEY_free(ec_key);
		ec_key = NULL;
		goto err;
	}

err:
	if (pubkey) EC_POINT_free(pubkey);

	return ec_key;
}

int main(int argc, char *argv[])
{
	EVP_PKEY *sm2key = NULL;
	EC_GROUP *sm2group = NULL;
    	EVP_PKEY_CTX *pctx = NULL;
	size_t outlen;
	unsigned char *out = NULL;
	int retval;

	if (argc < 4)
	{
		printf("Usage: \n\t%s e|E sm2pubkey text\n", argv[0]);
		printf("\t%s d|D sm2privatekey hex_ciphertext\n", argv[0]);
		return 0;
	}
    
	sm2group = EC_GROUP_new_by_curve_name(NID_sm2);
	if (!sm2group)
	{
		goto err;
	}
    
    sm2key = EVP_PKEY_new();
    if (!sm2key)
    {
        printf("Create EVP_PKEY Object Error.\n");
        goto err;
    }

	if (!strcasecmp(argv[1], "E"))
	{
	    /*Encrypt*/
    	EC_KEY *tmp = CalculatePubKey((const EC_GROUP *)sm2group, argv[2]);

		if (!tmp)
		{
			printf("Error Of Calculate SM2 Public Key.\n");
			goto err;
		}
        
    	EVP_PKEY_assign_SM2_KEY(sm2key, tmp);
    	
    	pctx = EVP_PKEY_CTX_new(sm2key, NULL);
    	if (!pctx)
    	{
        	printf("Create EVP_PKEY_CTX Error.\n");
        	goto err;
    	}
    	
    	if (EVP_PKEY_encrypt_init(pctx) <= 0)
    	{
        	printf("Error Of EVP_PKEY_encrypt_init.\n");
        	goto err;
    	}
    	
    	/*Set SM2 Encrypt EVP_MD. If it not set, SM2 default is EVP_sm3(), Other curve default is sha1*/
    	EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_CTRL_MD, 0, (void *)EVP_sm3());
    	
    	/*Set sm2 encdata format, 0 for ASN1(default), 1 for C1C3C2*/
    	/*EVP_PKEY_CTX_set_sm2_encdata_format(ctx, 1);*/
    	
    	/*Calculate Cipher Text Length*/
    	if (EVP_PKEY_encrypt(pctx, NULL, &outlen, (const unsigned char *)argv[3], (size_t)strlen(argv[3])) < 0)
    	{
        	printf("Calculate SM2 Cipher text length error.\n");
        	goto err;
    	}
    	
    	out = OPENSSL_malloc(outlen);
    	if (!out)
    	{
        	printf("Error Of Alloc memory.\n");
        	goto err;
    	}
		
    	if (EVP_PKEY_encrypt(pctx, out, &outlen, (const unsigned char *)argv[3], (size_t)strlen(argv[3])) < 0)
    	{
        	printf("EVP_PKEY_encrypt error.\n");
        	goto err;
    	}
    	
    	/*OK, output cipher*/
    	printf("[%s] SM2 Encrypt Cipher Text:\n\tLength: [%ld]\n\tContent: [", argv[3], outlen);
    	for (retval = 0; retval < outlen; retval++)
        	printf("%02X", out[retval] & 0xff);
    	printf("]\n");
	}
	else if (!strcasecmp(argv[1], "D"))
	{
    	EC_KEY *tmp = NULL;
		unsigned char *in = NULL;
		size_t inlen = strlen(argv[3]) / 2;
        
		/*Decrypt*/
		tmp = CalculateKey((const EC_GROUP *)sm2group, argv[2]);
		if (!tmp)
		{
			printf("Error Of Calculate SM2 Private Key.\n");
			goto err;
		}
        
    	EVP_PKEY_assign_SM2_KEY(sm2key, tmp);
    	        
    	pctx = EVP_PKEY_CTX_new(sm2key, NULL);
    	if (!pctx)
    	{
        	printf("Create EVP_PKEY_CTX Error.\n");
        	goto err;
    	}
    	
    	if (EVP_PKEY_decrypt_init(pctx) <= 0)
    	{
        	printf("Error Of EVP_PKEY_encrypt_init.\n");
        	goto err;
    	}
    	
    	/*Set SM2 Encrypt EVP_MD. If it not set, SM2 default is EVP_sm3(), Other curve default is sha1*/
    	EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_CTRL_MD, 0, (void *)EVP_sm3());
    	
    	in = OPENSSL_malloc(inlen);
    	if (!in)
    	{
        	printf("Error Of Alloc Memory.\n");
        	goto err;
    	}

    	//hex2bin((const unsigned char *)argv[3], inlen * 2, in);
	b2s(argv[3], in);

    	/*Set sm2 encdata format, 0 for ASN1(default), 1 for C1C3C2*/
    	/*EVP_PKEY_CTX_set_sm2_encdata_format(ctx, 1);*/
    	
    	/*Calculate plain text length*/
    	if (EVP_PKEY_decrypt(pctx, NULL, &outlen, (const unsigned char *)in, inlen) < 0)
    	{
        	OPENSSL_free(in);
        	printf("Calculate SM2 plain text length error.\n");
        	goto err;
    	}
    	
		out = OPENSSL_malloc(outlen);
		if (!out)
		{
    		OPENSSL_free(in);
			printf("Error Of Alloc Memory.\n");
			goto err;
		}

		memset(out, 0, outlen);
    	if (EVP_PKEY_decrypt(pctx, out, &outlen, (const unsigned char *)in, inlen) < 0)
		{
    		OPENSSL_free(in);
			printf("Error Of EVP_PKEY_decrypt.\n");
			/*Your Can't get error detail*/
			goto err;
		}
		out[outlen] = '\0';
        
		printf("[%s] SM2 Decrypt plain Text:\n\tLength: [%ld]\n\tContent: [%s]\n", argv[3], outlen, (char *)out);
		/*for (retval = 0; retval < outlen; retval++)
		    printf("%02X", out[retval] & 0xff);
		printf("]\n");*/
	}
	else
	{
		printf("Error Of Option.\n");
	}
    
err:
	if (sm2group) EC_GROUP_free(sm2group);
	if (sm2key) EVP_PKEY_free(sm2key);
    if (pctx) EVP_PKEY_CTX_free(pctx);
	if (out) OPENSSL_free(out);
    
	return 0;
}
