#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "openssl/err.h"
#include "openssl/ec.h"
#include "openssl/obj_mac.h"
#include "openssl/evperr.h"
#include "openssl/evp.h"
//#include "include/internal/evp_int.h"
#include "openssl/sm3.h"


char g_pcDerPub1[]={"04187da34b1cf8c017cddc2c3763bffd4d5a18ed73ec62e7a52d02d4fe08418fd4aadcf2dea7845d3c02ff39adba75370c8d201b5c33499d67936aab032d69013c"};
//转为无符号数数是2048
char g_data[]={"31323334353637383930313233343536374839"};

char g_sm2id[]={"1234567812345678"};

int Data_PackBCD( char *InBuf, unsigned char *OutBuf, int InLen )
{
        int	    rc;		/* Return Value */
        register int     ActiveNibble;	/* Active Nibble Flag */
        char     CharIn;	/* Character from source buffer */
        unsigned char   CharOut;	/* Character from target buffer */

        rc = 0;		/* Assume everything OK. */
        ActiveNibble = 0;	/* Set Most Sign Nibble (MSN) */

        for ( ; (InLen > 0); InLen--, InBuf++ )
        {
                CharIn = *InBuf;
                if ( !isxdigit ( CharIn ) )	/* validate character */
                {
                        return -1;
                }

                if ( CharIn > '9')
                {
                        CharIn += 9;	/* Adjust Nibble for A-F */
                }

                CharOut = *OutBuf;
                if ( ActiveNibble )		
                {
                        *OutBuf++ = (unsigned char)( (CharOut & 0xF0) | (CharIn  & 0x0F) );
                }
                else
                {
                        *OutBuf = (unsigned char)( (CharOut & 0x0F) | ( (CharIn & 0x0F) << 4) );
                }
                ActiveNibble ^= 1;	/* Change Active Nibble */
        }

        return 0;
}
printHex(const unsigned char *title, const unsigned char *s, int len)
{
        int     n;

        printf("%s:", title);
        for (n = 0; n < len; ++n) {
                if ((n % 16) == 0) {
                        printf("\n%04x", n);
                }
                printf(" %02x", s[n]);
        }
        printf("\n");
}

static int Get_HashType( int iHashType, char *pcHashType )
{
        int rv = 0;
        if ( iHashType == 5 ) //SHA224
        {   
                strcpy( pcHashType, "sha224" );
        }   
        else if ( iHashType == 6 ) 
        {   
                strcpy( pcHashType, "sha256" );
        }   
        else if (iHashType == 7)
        {   
                strcpy( pcHashType, "sha384" );
        }   
        else if (iHashType == 8)
        {   
                strcpy( pcHashType, "sha512" );
        } 
        else if (iHashType == 20)  
        {
        		strcpy( pcHashType, "sm3" );
        }
        else
             rv = 1;
        return rv;
 }

//产生带userid的SM3 hash
int evp_sm3_id(int iHashFlag,unsigned char *sm2_id, int idLen, unsigned char *pub, int plen, unsigned char *in, size_t inlen, unsigned char *hash, int *ihashlen)
{
	int rv = 0;
	int nid = NID_sm2;
	
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *sctx = NULL;
	const EVP_MD *md = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	unsigned char default_id[]={0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};    
	char pcHashType[128]={0x0};
	
	
	
	Get_HashType( iHashFlag, pcHashType );
	md = EVP_get_digestbyname(pcHashType); 
	//获取公钥
	pkey = EVP_PKEY_new();
    if (pkey == NULL) 
    {
            rv = 1;
            return rv;
    }
    
    //pkey->pkey.ec = EC_KEY_new_by_curve_name( nid );
    //EVP_PKEY_get0_EC_KEY(pkey) = EC_KEY_new_by_curve_name( nid );
	printf(" evp_getsm3_id***********1***********\n");
	
    if( !d2i_PublicKey( EVP_PKEY_EC, &pkey, (const unsigned char **)(&pub), plen) )
    {
            rv = 2;
            goto err;
    }
    
    //修改类型。
    //因为前面函数，例：EVP_PKEY_CTX_set_ec_paramgen_curve_nid是默认使用EVP_PKEY_EC类型     
    if ((EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2)) != 1)
    {
            rv = 3;
            goto err;	
    }
    
    if(!(md_ctx  = EVP_MD_CTX_new()))
    {
            printf("******4****\n");
            rv = 4;
            goto err;
    }
    
    if (!(sctx = EVP_PKEY_CTX_new(pkey, NULL)))
    {
            printf("******5****\n");
            rv = 5;
            goto err;
    }
	
	//验证密钥的正确性
	if((EVP_PKEY_check(sctx)) != 1) 
	{
		printf("******6****\n");
            rv = 6;
            goto err;	
	}
	
    if (idLen == 0)
    {
            //使用默认sm2_id
            sm2_id = default_id;
            idLen = sizeof(default_id);

            printHex("evp_ecc_sign sm2_id", sm2_id, idLen);
    }        
			
    if ( 1 != (EVP_PKEY_CTX_set1_id(sctx, sm2_id, idLen)))
    {
            printf("******7****\n");
            rv = 7;
            goto err;
    }
    
    //将sctx赋值到md_ctx中
    EVP_MD_CTX_set_pkey_ctx(md_ctx, sctx);
    
    //hash_init update, final 成功返回1,失败返回0
 
	if((rv = sm3_init(EVP_MD_CTX_md_data(md_ctx))) != 1)
	{
		printf("******8****\n");
            rv = 8;
            goto err;	
	}
	
	if((rv = sm3_update(EVP_MD_CTX_md_data(md_ctx),in, inlen)) != 1)
	{
		printf("******9****\n");
            rv = 9;
            goto err;		
	}
	
	if((rv = sm3_final(hash, EVP_MD_CTX_md_data(md_ctx))) != 1)
	{
		printf("******10****\n");
            rv = 10;
            goto err;		
	}
	
	printHex("evp_sm3_id hash", hash, 64);

  	rv = 0;
err:

        if( pkey )
                EVP_PKEY_free(pkey);
                
        if (md_ctx)
                EVP_MD_CTX_free(md_ctx);

        if (sctx)
                EVP_PKEY_CTX_free(sctx);  
                        	
	return rv;
}


int main()
{
	int rv = 0;
	int iHashFlag = 20;

  	unsigned char sm2_id[64];
  	unsigned char pub[4096];
  	unsigned char data[4096];
  	unsigned char hash[64];
  	int idlen = 0;
  	int datalen = 0;
  	int publen = 0;
  	int ihashlen = 0;
  		
	memset(sm2_id, 0x0, sizeof(sm2_id));  
	memset(pub, 0x0, sizeof(pub));
	memset( data, 0x0, sizeof(data));
	memset( hash, 0x0, sizeof(hash));	
	
	publen = strlen(g_pcDerPub1)/2;
    Data_PackBCD( g_pcDerPub1, pub, publen*2);
    
    memset(sm2_id, 0x0, sizeof(sm2_id));                
    idlen = strlen(g_sm2id);
    memcpy( sm2_id , g_sm2id, idlen);
    
    datalen = strlen(g_data)/2;
    Data_PackBCD( g_data, data, datalen*2); 
	
	rv = evp_sm3_id(iHashFlag,sm2_id, idlen, pub, publen, data, datalen, hash, &ihashlen);	
	if (rv)
	{
		printf("evp_sm3_id failed rv= %d\n",rv);
		return rv;
	}
	
	return 0;
}
