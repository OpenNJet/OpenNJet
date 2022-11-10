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
#include "openssl/sm2.h"

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
	EC_KEY *sm2key = NULL;
	EC_GROUP *sm2group = NULL;
	size_t outlen;
	unsigned char *out = NULL;
	int retval;
	SM2ENC *sm2enc = NULL;

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
    
	if (!strcasecmp(argv[1], "E"))
	{
	    /*Encrypt*/
		sm2key = CalculatePubKey((const EC_GROUP *)sm2group, argv[2]);
		if (!sm2key)
		{
			printf("Error Of Calculate SM2 Public Key.\n");
			goto err;
		}
        
		sm2enc = sm2_encrypt((const unsigned char *)argv[3], (size_t)strlen(argv[3]), NULL/*EVP_sm3()*/, sm2key);
		if (!sm2enc)
		{
			printf("Error Of calculate cipher text length.\n");
			goto err;
		}

		outlen = i2d_SM2ENC((const SM2ENC *)sm2enc, &out);
		if (!outlen)
			goto err;
        
		printf("[%s] SM2 Encrypt Cipher Text:\n\tLength: [%ld]\n\tASN1 Content: [", argv[3], outlen);
		for (retval = 0; retval < outlen; retval++)
			printf("%02X", out[retval] & 0xff);
		printf("]\n");		
	}
	else if (!strcasecmp(argv[1], "D"))
	{
		unsigned char *in = NULL;
		const unsigned char *p;
		size_t inlen = strlen(argv[3]) / 2;
        
		/*Decrypt*/
		sm2key = CalculateKey((const EC_GROUP *)sm2group, argv[2]);
		if (!sm2key)
		{
			printf("Error Of Calculate SM2 Private Key.\n");
			goto err;
		}
        
		in = OPENSSL_malloc(inlen);
		if (!in)
		{
			printf("Error Of Alloc Memory.\n");
			goto err;
		}
        
		hex2bin((const unsigned char *)argv[3], inlen * 2, in);
		p = (const unsigned char *)in;
		sm2enc = d2i_SM2ENC(NULL, (const unsigned char **)&p, inlen);

		retval = sm2_decrypt(NULL, &outlen, (const SM2ENC *)sm2enc, NULL/*EVP_sm3()*/, sm2key);
		if (!retval)
		{
			OPENSSL_free(in);
			printf("Error Of calculate plain text length.\n");
			goto err;
		}

		out = OPENSSL_malloc(outlen + 2);
		if (!out)
		{
			OPENSSL_free(in);
			printf("Error Of Alloc Memory.\n");
			goto err;
		}

		memset(out, 0, outlen + 2);
		retval = sm2_decrypt(out, &outlen, (const SM2ENC *)sm2enc, NULL/*EVP_sm3()*/, sm2key);
		OPENSSL_free(in);
		if (!retval)
		{
			printf("Error Of SM2 Decrypt.\n");
			/*Your Can't get error detail*/
			goto err;
		}
        
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
	if (sm2key) EC_KEY_free(sm2key);
	if (out) OPENSSL_free(out);
	if (sm2enc) SM2ENC_free(sm2enc);
    
	return 0;
}
