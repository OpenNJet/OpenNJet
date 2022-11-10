#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "openssl/evp.h"
#include "openssl/ec.h"
#include "openssl/engine.h"


int main(int argc, char *argv[])
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *pkey_card = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    unsigned char *sig = NULL;
    unsigned char *out = NULL;
    size_t len;
    int loop;
    
    
    if (argc < 3)
    {
        printf("Usage: \n\t%s key_index message\n", argv[0]);
        exit(0);
    }
    
    OpenSSL_add_all_algorithms();
    ENGINE_load_builtin_engines();
    
    /*1111111 初始化引擎 */
    const char *engine_name_sm2 = "tasscard_sm2";
    ENGINE *tasscardsm2_e = NULL;
    
    if ((tasscardsm2_e = ENGINE_by_id(engine_name_sm2)) == NULL) {
      printf("ENGINE load id=[%s] fail!\n", engine_name_sm2);
	  	exit(0);
    }
    else{
       ENGINE_init(tasscardsm2_e);
    }
    
    
    /*222222 通过引擎索引加载签名私钥 */
    pkey_card = ENGINE_load_private_key(tasscardsm2_e, argv[1], NULL, NULL);
    if(pkey_card == NULL){
        printf("ENGINE_load_private_key fail, key_index =[%s]\n", argv[1]);
        goto err;
    }
    
    
    /*333333 签名 */
    len = EVP_PKEY_size(pkey_card);
    sig = OPENSSL_malloc(len);
    if (!sig)
    {
        printf("Alloc Memory Error.\n");
        goto err;
    }

    md_ctx = EVP_MD_CTX_create();
    if (!md_ctx)
    {
        printf("Error of Create EVP_MD_CTX Object Error.\n");
        goto err;
    }
    
    EVP_MD_CTX_init(md_ctx);
    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sm3(), NULL, pkey_card) != 1)
    {
        printf("Init DigestSign CTX Error.\n");
        goto err;
    }
    
    EVP_DigestSignUpdate(md_ctx, argv[2], strlen(argv[2]));
    EVP_DigestSignFinal(md_ctx, sig, &len);
    
    printf("[%s] SM2 Signature: [", argv[2]);
    for (loop = 0; loop < len; loop++)
        printf("%02X", sig[loop] & 0xff);
    printf("]\n");
    
    EVP_MD_CTX_destroy(md_ctx);
    
    
    /*444444 延签 */
    md_ctx = EVP_MD_CTX_create();
    if (!md_ctx)
        goto err;
    
    EVP_MD_CTX_init(md_ctx);
    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sm3(), NULL, pkey_card) != 1)
    {
        printf("Init DigestVerify CTX Error.\n");
        goto err;
    }
    
    EVP_DigestVerifyUpdate(md_ctx, argv[2], strlen(argv[2]));
    loop = EVP_DigestVerifyFinal(md_ctx, (const unsigned char *)sig, len);
    if (loop <= 0)
    {
        printf("EVP_DigestVerify Error.\n");
    }
    else
    {
        printf("EVP_DigestVerify Successed.\n");
    }
    
err:
    if (pkey_card) EVP_PKEY_free(pkey_card);
    if (md_ctx) EVP_MD_CTX_destroy(md_ctx);
    if (sig) OPENSSL_free(sig);
    if (out) OPENSSL_free(out);
    
    if(tasscardsm2_e){
        ENGINE_finish(tasscardsm2_e);
        ENGINE_free(tasscardsm2_e);
    }
        
    return 0;
}
