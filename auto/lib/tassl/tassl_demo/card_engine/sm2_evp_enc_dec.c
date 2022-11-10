#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "openssl/evp.h"
#include "openssl/ec.h"
#include "openssl/engine.h"

int main(int argc, char *argv[])
{
	EVP_PKEY *pkey_card = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	EVP_PKEY_CTX *pctx_dec = NULL;
	size_t cipher_len;
	size_t plain_len;
	unsigned char *cipher = NULL;
	unsigned char *plain = NULL;
	int retval;

	if (argc < 3)
	{
		printf("Usage: \n\t%s  key_index text\n", argv[0]);
		return 0;
	}
    
    ENGINE_load_builtin_engines();
    
    /*111111 初始化引擎*/
    const char *engine_name_sm2 = "tasscard_sm2";
    ENGINE *tasscardsm2_e = NULL;
    
    if ((tasscardsm2_e = ENGINE_by_id(engine_name_sm2)) == NULL) {
        printf("ENGINE load id=[%s] fail!\n", engine_name_sm2);
	  	exit(0);
    }
    else{
       ENGINE_init(tasscardsm2_e);
    }
    
    /*222222 通过引擎索引号加载私钥 */
    pkey_card = ENGINE_load_private_key(tasscardsm2_e, argv[1], NULL, NULL);
    if(pkey_card == NULL){
        printf("ENGINE_load_private_key fail, key_index =[%s]\n", argv[1]);
        goto err;
    }
    
    /*333333 加密 */
    pctx = EVP_PKEY_CTX_new(pkey_card, NULL);
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
    
    EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_CTRL_MD, 0, (void *)EVP_sm3());
    
    /*Calculate Cipher Text Length*/
    if (EVP_PKEY_encrypt(pctx, NULL, &cipher_len, (const unsigned char *)argv[2], (size_t)strlen(argv[2])) != 1)
    {
    	printf("Calculate SM2 Cipher text length error.\n");
    	goto err;
    }
    
    cipher = OPENSSL_malloc(cipher_len);
    if (!cipher)
    {
    	printf("Error Of Alloc memory.\n");
    	goto err;
    }
    
    if (EVP_PKEY_encrypt(pctx, cipher, &cipher_len, (const unsigned char *)argv[2], (size_t)strlen(argv[2])) != 1)
    {
    	printf("EVP_PKEY_encrypt error.\n");
    	goto err;
    }
    
    printf("[%s] SM2 Encrypt Cipher Text:\n\tLength: [%ld]\n\tContent: [", argv[2], cipher_len);
    for (retval = 0; retval < cipher_len; retval++)
    	printf("%02X", cipher[retval] & 0xff);
    printf("]\n");
    
    	
    /*444444 解密 */
    pctx_dec = EVP_PKEY_CTX_new(pkey_card, NULL);
    if (!pctx_dec)
    {
    	printf("Create EVP_PKEY_CTX Error.\n");
    	goto err;
    }
    
    if (EVP_PKEY_decrypt_init(pctx_dec) <= 0)
    {
    	printf("Error Of EVP_PKEY_encrypt_init.\n");
    	goto err;
    }
    
    /*Set SM2 Encrypt EVP_MD. If it not set, SM2 default is EVP_sm3(), Other curve default is sha1*/
    EVP_PKEY_CTX_ctrl(pctx_dec, -1, EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_CTRL_MD, 0, (void *)EVP_sm3());
    
    /*Calculate plain text length*/
    if (EVP_PKEY_decrypt(pctx_dec, NULL, &plain_len, (const unsigned char *)cipher, cipher_len) != 1)
    {
    	printf("Calculate SM2 plain text length error.\n");
    	goto err;
    }
    
    plain = OPENSSL_malloc(plain_len+1);
    if (!plain)
    {
    	printf("Error Of Alloc Memory.\n");
    	goto err;
    }
    
    memset(plain, 0, plain_len);
    if (EVP_PKEY_decrypt(pctx_dec, plain, &plain_len, (const unsigned char *)cipher, cipher_len) != 1)
    {
    	printf("Error Of EVP_PKEY_decrypt.\n");
    	goto err;
    }
    plain[plain_len] = '\0';
    
    printf("[%s] SM2 Decrypt plain Text:\n\tLength: [%ld]\n\tContent: [%s]\n", argv[2], plain_len, (char *)plain);
    
err:
	if (pkey_card) EVP_PKEY_free(pkey_card);
    if (pctx) EVP_PKEY_CTX_free(pctx);
    if (pctx_dec) EVP_PKEY_CTX_free(pctx_dec);
	if (cipher) OPENSSL_free(cipher);
	if (plain) OPENSSL_free(plain);
	    
    if(tasscardsm2_e){
        ENGINE_finish(tasscardsm2_e);
        ENGINE_free(tasscardsm2_e);
    }
	return 0;
}
