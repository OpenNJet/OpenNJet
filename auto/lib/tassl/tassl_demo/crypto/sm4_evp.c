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
    unsigned char key[] = "1234567890123456";
    unsigned char iv[] = "1234567812345678";
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char outbuf[1024] = {0};
    char *inbuf = "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
    int outlen = 0;
    int tmplen = 0;

    if((ctx = EVP_CIPHER_CTX_new()) == NULL){
        printf("ctx new fail!\n");
        exit(0);
    }
    EVP_CIPHER_CTX_init(ctx);
    EVP_CipherInit_ex(ctx, EVP_sm4_cbc(), NULL, key, iv, 1);

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
