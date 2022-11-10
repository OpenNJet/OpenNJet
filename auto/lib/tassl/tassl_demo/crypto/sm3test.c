/* crypto/sm3/sm3test.c */
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
#include "crypto/include/internal/sm3.h"
#include "openssl/evp.h"

int run;

void time_out(int sig)
{
        signal(SIGALRM, time_out);
        run = 0;
}

const char *test1digest = "\x66\xC7\xF0\xF4\x62\xEE\xED\xD9\xD1\xF2\xD4\x6B\xDC\x10\xE4\xE2\x41\x67\xC4\x87\x5C\xF2\xF7\xA2\x29\x7D\xA0\x2B\x8F\x4B\xA8\xE0";
const char *test2digest = "\xDE\xBE\x9F\xF9\x22\x75\xB8\xA1\x38\x60\x48\x89\xC1\x8E\x5A\x4D\x6F\xDB\x70\xE5\x38\x7E\x57\x65\x29\x3D\xCB\xA3\x9C\x0C\x57\x32";

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

int main(int argc, char **argv)
{
        int i;
        unsigned char digest[32];
	EVP_MD_CTX *ctx;
	EVP_MD *md = NULL;
	char buf_out[2048] = {0};
	char *buf_in = "0080303132333435363738303132333435363738";
//FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E9332C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0943FA313CBFAF22FD58573A23A4FD25B688887888F204DB968F5C58D78D07676D8FBD9367739120C87F4CE5D50C349B5680563C4808E3E41B3F048AEEEC11131";
	
	i = b2s(buf_in, buf_out);
	printf("the i =[%d]\n", i);

        signal(SIGALRM, time_out);
        memset(digest, 0, sizeof(digest));
	
	md = EVP_sm3();
	ctx = EVP_MD_CTX_create();
        EVP_DigestInit(ctx, md);
	
        EVP_DigestUpdate(ctx, buf_out, i);
        EVP_DigestFinal(ctx, digest, (unsigned *)&i);

        //SM3((unsigned char *)"abc", 3, digest);
        printf("SM3 Test1 verifid: [%s]\n", ((!memcmp(digest, test1digest, 32)) ? "OK" : "ER"));
        printf("abc SM3 digest: [");
        for (i = 0; i < 32; i++)
                printf(" %02X", digest[i]);

        printf(" ]\ni===================================================\n");
        EVP_MD_CTX_destroy(ctx);
	exit(0);
        memset(digest, 0, sizeof(digest));
        SM3((unsigned char *)"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd", 64, digest);
        printf("SM3 Test2 verifid: [%s]\n", ((!memcmp(digest, test2digest, 32)) ? "OK" : "ER"));
        printf("Test 2 Digest: [");
        for (i = 0; i < 32; i++)
                printf(" %02X", digest[i]);

        printf(" ]\n");

        printf("Now test 20 seconds encrypt ...\n");
        i = 0;
        alarm(20);
        for (run = 1; run; i++)
                SM3((unsigned char *)"12324524alsdkf", 12, digest);

        printf("SM3 digest times in 20 seconds: [%ld]\n", i);

        return 0;

}


