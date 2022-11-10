/* crypto/sm4/sm4test.c */
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
#include <unistd.h>
#include <signal.h>
#include "openssl/sm4.h"

uint32_t run;

void time_out(int sig)
{
    signal(SIGALRM, time_out);
    run = 0;
}

const char *test1result = "\x68\x1E\xDF\x34\xD2\x06\x96\x5E\x86\xB3\xE9\x4F\x53\x6E\x42\x46";
const char *test2result = "\x59\x52\x98\xC7\xC6\xFD\x27\x1F\x04\x02\xF8\x04\xC3\x3D\x3F\x66";

int main(int argc, char **argv)
{
    SM4_KEY key;
    unsigned char out[16];
    
    unsigned char plaintext[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    unsigned char user_key[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    
    int loop;
    
    signal(SIGALRM, time_out);
    SM4_set_key((const unsigned char *)user_key, 16, &key);
    
    /*输出轮密钥*/
    for (loop = 0; loop < 32; loop++)
    {
        printf("\trk[%02d]=0x%08X", loop, key.key[loop]);
        if (!((loop + 1) % 4)) printf("\n");
    }
    
    SM4_encrypt((const unsigned char *)plaintext, out, &key);
    printf("SM4 Test1 verified: [%s]\n", ((!memcmp(out, test1result, 16)) ? "OK" : "ER"));
    printf("ECB Encrypt Result:[");
    for (loop = 0; loop < 16; loop++)
    {
        printf(" %02X", out[loop] & 0xff);
    }
    printf(" ]\n");
    
    SM4_decrypt((const unsigned char *)out, out, &key);
    printf("ECB Decrypt Result:[");
    for (loop = 0; loop < 16; loop++)
    {
        printf(" %02X", out[loop] & 0xff);
    }
    printf(" ]\n");
    
    memcpy(out, plaintext, 16);
    for (loop = 0; loop < 1000000; loop++)
        SM4_encrypt((const unsigned char *)out, out, &key);
    printf("SM4 Test2 verified: [%s]\n", ((!memcmp(out, test2result, 16)) ? "OK" : "ER"));
    
    printf("ECB Encrypt 1 000 0000 times Result:[");
    for (loop = 0; loop < 16; loop++)
    {
        printf(" %02X", out[loop] & 0xff);
    }
    printf(" ]\n");
    
    for (loop = 0; loop < 1000000; loop++)
        SM4_decrypt((const unsigned char *)out, out, &key);
    
    printf("ECB Decrypt 1 000 0000 times Result:[");
    for (loop = 0; loop < 16; loop++)
    {
        printf(" %02X", out[loop] & 0xff);
    }
    printf(" ]\n");
    
    printf("Now test 20 seconds encrypt ...\n");
    loop = 0;
    alarm(20);
    for (run = 1; run; loop++)
        SM4_encrypt((const unsigned char *)out, out, &key);
    
    printf("Now SM4_encrypt times: [%ld]\n", loop);

    return 0;
}



