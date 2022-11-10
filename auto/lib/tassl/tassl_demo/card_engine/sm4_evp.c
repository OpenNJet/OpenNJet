#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <unistd.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/sm4.h"
#include "openssl/engine.h"


int main(int argc, char **argv)
{
    unsigned char iv[] = "1234567812345678";
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char outbuf[1024] = {0};
    char *inbuf = "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
    int outlen = 0;
    int tmplen = 0;

    if (argc < 2)
	{
		printf("Usage: \n\t%s  key_index\n", argv[0]);
		return 0;
	}
	

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const char *engine_name_sm4 = "tasscard_sm4";
    ENGINE *tasscardsm4_e = NULL;

    if ((tasscardsm4_e = ENGINE_by_id(engine_name_sm4)) == NULL) {
      printf("ENGINE load id=[%s] fail!\n", engine_name_sm4);
      exit(0);
    }
    else{
        ENGINE_init(tasscardsm4_e);
        ENGINE_register_ciphers(tasscardsm4_e);
        ENGINE_set_default_RAND(tasscardsm4_e);
    }


    if((ctx = EVP_CIPHER_CTX_new()) == NULL){
        printf("ctx new fail!\n");
        exit(0);
    }
    EVP_CIPHER_CTX_init(ctx);

    //使用引擎，在加密卡中生成50号SM4秘钥，并初始化
    EVP_CipherKeygen(ctx, tasscardsm4_e, NID_sm4_cbc, NULL, argv[1]);
    EVP_CipherInit_ex(ctx, EVP_sm4_cbc(), tasscardsm4_e, argv[1], iv, 1);

    if(!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, strlen(inbuf)))
    {
        printf("EVP_CipherUpdate fail!\n");
        return 0;
    }

    if(!EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen))
    {
        printf("EVP_EncryptFinal_ex fail!\n");
        return 0;
    }
    outlen += tmplen;

    printf("Cipherd by SM4:");
    int i =0;
    for(i=0; i<outlen; i++){
        printf("%02X", outbuf[i]);
    }
    printf("\n");
    
    
    EVP_CIPHER_CTX_cleanup(ctx);
    return 1;
}
