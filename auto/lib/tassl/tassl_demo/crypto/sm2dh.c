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
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/sm2.h>

/*
THIS PROGRAM DEMO FOR
    ECDH_compute_key
    &
    SM2DH_compute_key
*/

/*
int SM2DH_set_checksum(EC_KEY *eckey, int checksum)
{
    SM2DH_DATA *sm2dhdata = NULL;
    const EVP_MD *md = EVP_sm3();

    sm2dhdata = (SM2DH_DATA *)SM2DH_get_ex_data(eckey);

    if (sm2dhdata == NULL)
    {
        return 0;
    }

    sm2dhdata->checksum = (checksum ? 1 : 0);

    return SM2DH_set_ex_data(eckey, (void *)sm2dhdata);
}
*/

int SM2DH_set_peer_kap_pubkey(EC_KEY *eckey, const unsigned char *peer_pubkey, int peer_pubkey_len)
{
    SM2DH_DATA *sm2dhdata = NULL;
    const EVP_MD *md = EVP_sm3();

    sm2dhdata = (SM2DH_DATA *)SM2DH_get_ex_data(eckey);

    if (sm2dhdata == NULL)
    {
        return 0;
    }

    memcpy(sm2dhdata->Rp, peer_pubkey, peer_pubkey_len);
    sm2dhdata->Rp_len = peer_pubkey_len;

    return SM2DH_set_ex_data(eckey, (void *)sm2dhdata);
}

EC_KEY *CalculateKey(const EC_GROUP *ec_group, const unsigned char *privkey_hex_string)
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

int ShowResultInfo(EC_KEY *ec_key)
{
    SM2DH_DATA *sm2dhdata = NULL;
    int loop;

    sm2dhdata = (SM2DH_DATA *)SM2DH_get_ex_data(ec_key);
    if (!sm2dhdata)
    {
        printf("Get Result Information Structure Error\n");
        return 0;
    }

    printf("e_checksum: [");
    for (loop = 0; loop < 32; loop++)
        printf("%02X", sm2dhdata->e_checksum[loop] & 0xff);
    printf("]\n");

    printf("s_checksum: [");
    for (loop = 0; loop < 32; loop++)
        printf("%02X", sm2dhdata->s_checksum[loop] & 0xff);
    printf("]\n");

    return 1;
}

int main(int argc, char *argv[])
{
    point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
    int asn1_flag = OPENSSL_EC_NAMED_CURVE;
    const EC_POINT *point;
    BIGNUM *p = NULL, *a = NULL, *b = NULL, *order = NULL, *g = NULL;
    EC_GROUP *group = NULL;
    BIGNUM *privkey = NULL;
    EC_POINT *pubkey = NULL;
    EC_KEY *ec_key = NULL;
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
    if (!ec_key)
    {
        printf("Error Of EC KEY new\n");
        goto err;
    }

    if (!EC_KEY_set_group(ec_key, group))
    {
        printf("Error Of EC_KEY Set Group\n");
        goto err;
    }

    if (!EC_KEY_generate_key(ec_key))
    {
        printf("Error Of Generator EC KEY\n");
        goto err;
    }

    if (!server)
    {
        printf("----------------Test Calculate By Side A:------------------\n");
        printf("Pa : [%s]\n", EC_POINT_point2hex(group, EC_KEY_get0_public_key(ec_key), POINT_CONVERSION_UNCOMPRESSED, NULL));
        memset(Buffer, 0, (retval = (int)sizeof(Buffer)));
        if (SM2DH_prepare(ec_key, 0, Buffer, (size_t *)&retval) != 1)
        {
            printf("Error Of Prepare Key Agreements\n");
            goto err;
        }
        printf("Ra : [");
        for (loop = 0; loop < retval; loop++)
            printf("%02X", Buffer[loop] & 0xff);
        printf("]\n");

        printf("Input Pb (hex string) : ");
        memset(Buffer, 0, sizeof(Buffer));

	fgets(Buffer, sizeof(Buffer), stdin);
	if(Buffer[strlen(Buffer) - 1] == '\n') Buffer[strlen(Buffer) - 1] = '\0';

        pubkey = EC_POINT_hex2point((const EC_GROUP *)group, (const char *)Buffer, NULL, NULL);
        if (!pubkey) goto err;

        printf("Input Rb (hex string) : ");
        memset(Buffer, 0, sizeof(Buffer));
	fgets(Buffer, sizeof(Buffer), stdin);
        if(Buffer[strlen(Buffer) - 1] == '\n') Buffer[strlen(Buffer) - 1] = '\0';
        if (!BN_hex2bn(&g, (const char *)Buffer))
        {
            printf("Invalid Bignum!\n");
            goto err;
        }
        memset(Buffer, 0, sizeof(Buffer));
        retval = BN_bn2bin(g, Buffer);
        if (!retval)
        {
            printf("Error Of BN_LIB\n");
            goto err;
        }

        SM2DH_set_checksum(ec_key, 1);
        if (!SM2DH_set_peer_kap_pubkey(ec_key, (const unsigned char *)Buffer, retval))
            goto err;
        retval = SM2DH_compute_key(Buffer, keylen, pubkey, ec_key, NULL);
        /*retval = ECDH_compute_key(Buffer, keylen, pubkey, ec_key, NULL);*/
        if (retval > 0)
        {
            printf("SM2 Shared Key: [");
            for (loop = 0; loop < keylen; loop++)
                printf("%02X", Buffer[loop] & 0xff);
            printf("]\n");

            ShowResultInfo(ec_key);
        }
    }
    else
    {
        printf("----------------Test Calculate By Side B:------------------\n");
        printf("Pb : [%s]\n", EC_POINT_point2hex(group, EC_KEY_get0_public_key(ec_key), POINT_CONVERSION_UNCOMPRESSED, NULL));
        memset(Buffer, 0, (retval = (int)sizeof(Buffer)));
        if (SM2DH_prepare(ec_key, 1, Buffer, (size_t *)&retval) != 1)
        {
            printf("Error Of Prepare Key Agreements\n");
            goto err;
        }
        printf("Rb : [");
        for (loop = 0; loop < retval; loop++)
            printf("%02X", Buffer[loop] & 0xff);
        printf("]\n");

        printf("Input Pa (hex string) : ");
        memset(Buffer, 0, sizeof(Buffer));
	fgets(Buffer, sizeof(Buffer), stdin);
        if(Buffer[strlen(Buffer) - 1] == '\n') Buffer[strlen(Buffer) - 1] = '\0';
        pubkey = EC_POINT_hex2point((const EC_GROUP *)group, (const char *)Buffer, NULL, NULL);
        if (!pubkey) goto err;

        printf("Input Ra (hex string) : ");
        memset(Buffer, 0, sizeof(Buffer));
	fgets(Buffer, sizeof(Buffer), stdin);
        if(Buffer[strlen(Buffer) - 1] == '\n') Buffer[strlen(Buffer) - 1] = '\0';
        if (!BN_hex2bn(&g, (const char *)Buffer))
        {
            printf("Invalid Bignum!\n");
            goto err;
        }
        memset(Buffer, 0, sizeof(Buffer));
        retval = BN_bn2bin(g, Buffer);
        if (!retval)
        {
            printf("Error Of BN_LIB\n");
            goto err;
        }

        SM2DH_set_checksum(ec_key, 1);
        if (!SM2DH_set_peer_kap_pubkey(ec_key, (const unsigned char *)Buffer, retval))
            goto err;

        /*retval = SM2DH_compute_key(Buffer, keylen, pubkey, ec_key, NULL);*/
        retval = ECDH_compute_key(Buffer, keylen, pubkey, ec_key, NULL);
        if (retval > 0)
        {
            printf("SM2 Shared Key: [");
            for (loop = 0; loop < keylen; loop++)
                printf("%02X", Buffer[loop] & 0xff);
            printf("]\n");

            ShowResultInfo(ec_key);
        }
    }

err:
    if (ec_key) EC_KEY_free(ec_key);
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


