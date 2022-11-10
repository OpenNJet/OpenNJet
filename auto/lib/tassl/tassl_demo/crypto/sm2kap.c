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
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include "openssl/crypto.h"
#include "openssl/evp.h"
#include "openssl/sm2.h"

/*TEST KAP*/

int main(int argc, char *argv[])
{
	point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
	int asn1_flag = OPENSSL_EC_NAMED_CURVE;
	const EC_POINT *point;
	BIGNUM *p = NULL, *a = NULL, *b = NULL, *order = NULL, *g = NULL;
	EC_GROUP *group = NULL;
	EC_POINT *pubkey = NULL;
	EC_KEY *ec_key = NULL;
	EC_KEY *peer_pub_key = NULL, *self_ecdhe_key = NULL, *peer_ecdhe_key = NULL;
	int loop, retval;
	unsigned char Buffer[256];
	size_t keylen;

	int server;

	if (argc < 2)
	{
		printf("Usage: %s server_tag(1|0) [key length]\n", argv[0]);
		exit(0);
	}
	else
	{
		server = atoi(argv[1]);
		if (argc > 2)
			keylen = atoi(argv[2]);
		else
			keylen = 48;
	}

	OpenSSL_add_all_algorithms();

	p = BN_new();
	a = BN_new();
	b = BN_new();
	g = BN_new();
	order = BN_new();
	if (order == NULL)
	{
		printf("Error Of Alloc Bignum\n");
		goto err;
	}

	/*首先设定SM2曲线*/
	/*Tested for NONE SM2DH_TEST*/
	group = EC_GROUP_new_by_curve_name(NID_sm2/*OBJ_sn2nid("SM2")*/);
	if (group == NULL)
	{
		printf("Error Of Create curve to SM2\n");
		goto err;
	}

	ec_key = EC_KEY_new();
	peer_pub_key = EC_KEY_new();
	peer_ecdhe_key = EC_KEY_new();
	self_ecdhe_key = EC_KEY_new();

	if (!ec_key || !peer_pub_key || !peer_ecdhe_key || !self_ecdhe_key)
		goto err;

	if (!EC_KEY_set_group(ec_key, group) || !EC_KEY_set_group(peer_pub_key, group) || !EC_KEY_set_group(peer_ecdhe_key, group) || !EC_KEY_set_group(self_ecdhe_key, group))
		goto err;

	if (!server)
	{
		printf("----------------Test Calculate By Side A:------------------\n");
		if (EC_KEY_generate_key(ec_key) == 0)
			goto err;

		if (EC_KEY_generate_key(self_ecdhe_key) == 0)
			goto err;

		memset(Buffer, 0, (retval = (int)sizeof(Buffer)));
		printf("Pa : [%s]\n", EC_POINT_point2hex(group, EC_KEY_get0_public_key(ec_key), POINT_CONVERSION_UNCOMPRESSED, NULL));
		printf("Ra : [%s]\n", EC_POINT_point2hex(group, EC_KEY_get0_public_key(self_ecdhe_key), POINT_CONVERSION_UNCOMPRESSED, NULL));

		printf("Input Pb (hex string) : ");
		memset(Buffer, 0, sizeof(Buffer));
		fgets(Buffer, sizeof(Buffer), stdin);
	        if(Buffer[strlen(Buffer) - 1] == '\n') Buffer[strlen(Buffer) - 1] = '\0';

		if (pubkey) EC_POINT_free(pubkey);
		pubkey = EC_POINT_hex2point(group, (const char *)Buffer, NULL, NULL);
		EC_KEY_set_public_key(peer_pub_key, pubkey);

		printf("Input Rb (hex string) : ");
		memset(Buffer, 0, sizeof(Buffer));
		fgets(Buffer, sizeof(Buffer), stdin);
	        if(Buffer[strlen(Buffer) - 1] == '\n') Buffer[strlen(Buffer) - 1] = '\0';
		if (pubkey) EC_POINT_free(pubkey);
		pubkey = EC_POINT_hex2point(group, (const char *)Buffer, NULL, NULL);
		EC_KEY_set_public_key(peer_ecdhe_key, pubkey);

		memset(Buffer, 0, sizeof(Buffer));

		/*retval = SM2Kap_compute_key(Buffer, 46, 0, "BILL456@YAHOO.COM", 17, "ALICE123@YAHOO.COM", 18, peer_ecdhe_key, self_ecdhe_key, peer_pub_key, ec_key, EVP_sm3());*/
		retval = SM2Kap_compute_key(Buffer, keylen, 0, NULL, 0, NULL, 0, peer_ecdhe_key, self_ecdhe_key, peer_pub_key, ec_key, EVP_sm3());

		if (retval <= 0)
		{
			printf("Compute ECDHE Key Error\n");
			goto err;
		}

		printf("SM2 Shared Key: [");
		for (loop = 0; loop < retval; loop++)
			printf("%02X", Buffer[loop] & 0xff);
		printf("]\n");

	}
	else
	{
		printf("----------------Test Calculate By Side B:------------------\n");
		if (EC_KEY_generate_key(ec_key) == 0)
			goto err;

		if (EC_KEY_generate_key(self_ecdhe_key) == 0)
			goto err;

		memset(Buffer, 0, (retval = (int)sizeof(Buffer)));
		printf("Pb : [%s]\n", EC_POINT_point2hex(group, EC_KEY_get0_public_key(ec_key), POINT_CONVERSION_UNCOMPRESSED, NULL));
		printf("Rb : [%s]\n", EC_POINT_point2hex(group, EC_KEY_get0_public_key(self_ecdhe_key), POINT_CONVERSION_UNCOMPRESSED, NULL));

		printf("Input Pa (hex string) : ");
		memset(Buffer, 0, sizeof(Buffer));
		fgets(Buffer, sizeof(Buffer), stdin);
	        if(Buffer[strlen(Buffer) - 1] == '\n') Buffer[strlen(Buffer) - 1] = '\0';
		if (pubkey) EC_POINT_free(pubkey);
		pubkey = EC_POINT_hex2point(group, (const char *)Buffer, NULL, NULL);
		EC_KEY_set_public_key(peer_pub_key, pubkey);

		printf("Input Ra (hex string) : ");
		memset(Buffer, 0, sizeof(Buffer));
		fgets(Buffer, sizeof(Buffer), stdin);
	        if(Buffer[strlen(Buffer) - 1] == '\n') Buffer[strlen(Buffer) - 1] = '\0';
		if (pubkey) EC_POINT_free(pubkey);
		pubkey = EC_POINT_hex2point(group, (const char *)Buffer, NULL, NULL);
		EC_KEY_set_public_key(peer_ecdhe_key, pubkey);

		memset(Buffer, 0, sizeof(Buffer));

    	/*retval = SM2Kap_compute_key(Buffer, keylen, 1, "ALICE123@YAHOO.COM", 18, "BILL456@YAHOO.COM", 17, peer_ecdhe_key, self_ecdhe_key, peer_pub_key, ec_key, EVP_sm3());*/
		retval = SM2Kap_compute_key(Buffer, keylen, 1, NULL, 0, NULL, 0, peer_ecdhe_key, self_ecdhe_key, peer_pub_key, ec_key, EVP_sm3());

		if (retval <= 0)
		{
			printf("Compute ECDHE Key Error\n");
			goto err;
		}

		printf("SM2 Shared Key: [");
		for (loop = 0; loop < retval; loop++)
			printf("%02X", Buffer[loop] & 0xff);
		printf("]\n");

	}

err:
	if (ec_key) EC_KEY_free(ec_key);
	if (peer_pub_key) EC_KEY_free(peer_pub_key);
	if (peer_ecdhe_key) EC_KEY_free(peer_ecdhe_key);
	if (self_ecdhe_key) EC_KEY_free(self_ecdhe_key);
	if (p) BN_free(p);
	if (a) BN_free(a);
	if (b) BN_free(b);
	if (g) BN_free(g);
	if (order) BN_free(order);
	if (group) EC_GROUP_free(group);
	if (pubkey) EC_POINT_free(pubkey);

	CRYPTO_cleanup_all_ex_data();

	return 0;
}



