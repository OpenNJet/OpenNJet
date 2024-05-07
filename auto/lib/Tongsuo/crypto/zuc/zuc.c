/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/crypto.h>
#include <openssl/e_os2.h>
#include "crypto/zuc.h"

/*
 * The ZUC is a stream cipher defined originally in Chinese cipher standard
 * GM/T 0001.1-2012, which is Chinese only.
 *
 * ZUC is also standardized by 3GPP in the 'release 11' spec as an cryptographic
 * method for LTE. So two new names were given in the 3GPP specs: 128-EEA3 and
 * 128-EIA3, indicating the ZUC encryption method and ZUC MAC method.
 *
 * This part focuses on the keystream generation. The following implamentation
 * utilze the sample code in 3GPP's specification as a reference.
 *
 */

/* S-Box S0 and S1 */
static unsigned char S0[256] = {
    0x3E, 0x72, 0x5B, 0x47, 0xCA, 0xE0, 0x00, 0x33, 0x04, 0xD1, 0x54, 0x98, 0x09, 0xB9, 0x6D, 0xCB,
    0x7B, 0x1B, 0xF9, 0x32, 0xAF, 0x9D, 0x6A, 0xA5, 0xB8, 0x2D, 0xFC, 0x1D, 0x08, 0x53, 0x03, 0x90,
    0x4D, 0x4E, 0x84, 0x99, 0xE4, 0xCE, 0xD9, 0x91, 0xDD, 0xB6, 0x85, 0x48, 0x8B, 0x29, 0x6E, 0xAC,
    0xCD, 0xC1, 0xF8, 0x1E, 0x73, 0x43, 0x69, 0xC6, 0xB5, 0xBD, 0xFD, 0x39, 0x63, 0x20, 0xD4, 0x38,
    0x76, 0x7D, 0xB2, 0xA7, 0xCF, 0xED, 0x57, 0xC5, 0xF3, 0x2C, 0xBB, 0x14, 0x21, 0x06, 0x55, 0x9B,
    0xE3, 0xEF, 0x5E, 0x31, 0x4F, 0x7F, 0x5A, 0xA4, 0x0D, 0x82, 0x51, 0x49, 0x5F, 0xBA, 0x58, 0x1C,
    0x4A, 0x16, 0xD5, 0x17, 0xA8, 0x92, 0x24, 0x1F, 0x8C, 0xFF, 0xD8, 0xAE, 0x2E, 0x01, 0xD3, 0xAD,
    0x3B, 0x4B, 0xDA, 0x46, 0xEB, 0xC9, 0xDE, 0x9A, 0x8F, 0x87, 0xD7, 0x3A, 0x80, 0x6F, 0x2F, 0xC8,
    0xB1, 0xB4, 0x37, 0xF7, 0x0A, 0x22, 0x13, 0x28, 0x7C, 0xCC, 0x3C, 0x89, 0xC7, 0xC3, 0x96, 0x56,
    0x07, 0xBF, 0x7E, 0xF0, 0x0B, 0x2B, 0x97, 0x52, 0x35, 0x41, 0x79, 0x61, 0xA6, 0x4C, 0x10, 0xFE,
    0xBC, 0x26, 0x95, 0x88, 0x8A, 0xB0, 0xA3, 0xFB, 0xC0, 0x18, 0x94, 0xF2, 0xE1, 0xE5, 0xE9, 0x5D,
    0xD0, 0xDC, 0x11, 0x66, 0x64, 0x5C, 0xEC, 0x59, 0x42, 0x75, 0x12, 0xF5, 0x74, 0x9C, 0xAA, 0x23,
    0x0E, 0x86, 0xAB, 0xBE, 0x2A, 0x02, 0xE7, 0x67, 0xE6, 0x44, 0xA2, 0x6C, 0xC2, 0x93, 0x9F, 0xF1,
    0xF6, 0xFA, 0x36, 0xD2, 0x50, 0x68, 0x9E, 0x62, 0x71, 0x15, 0x3D, 0xD6, 0x40, 0xC4, 0xE2, 0x0F,
    0x8E, 0x83, 0x77, 0x6B, 0x25, 0x05, 0x3F, 0x0C, 0x30, 0xEA, 0x70, 0xB7, 0xA1, 0xE8, 0xA9, 0x65,
    0x8D, 0x27, 0x1A, 0xDB, 0x81, 0xB3, 0xA0, 0xF4, 0x45, 0x7A, 0x19, 0xDF, 0xEE, 0x78, 0x34, 0x60,
};

static unsigned char S1[256] = {
    0x55, 0xC2, 0x63, 0x71, 0x3B, 0xC8, 0x47, 0x86, 0x9F, 0x3C, 0xDA, 0x5B, 0x29, 0xAA, 0xFD, 0x77,
    0x8C, 0xC5, 0x94, 0x0C, 0xA6, 0x1A, 0x13, 0x00, 0xE3, 0xA8, 0x16, 0x72, 0x40, 0xF9, 0xF8, 0x42,
    0x44, 0x26, 0x68, 0x96, 0x81, 0xD9, 0x45, 0x3E, 0x10, 0x76, 0xC6, 0xA7, 0x8B, 0x39, 0x43, 0xE1,
    0x3A, 0xB5, 0x56, 0x2A, 0xC0, 0x6D, 0xB3, 0x05, 0x22, 0x66, 0xBF, 0xDC, 0x0B, 0xFA, 0x62, 0x48,
    0xDD, 0x20, 0x11, 0x06, 0x36, 0xC9, 0xC1, 0xCF, 0xF6, 0x27, 0x52, 0xBB, 0x69, 0xF5, 0xD4, 0x87,
    0x7F, 0x84, 0x4C, 0xD2, 0x9C, 0x57, 0xA4, 0xBC, 0x4F, 0x9A, 0xDF, 0xFE, 0xD6, 0x8D, 0x7A, 0xEB,
    0x2B, 0x53, 0xD8, 0x5C, 0xA1, 0x14, 0x17, 0xFB, 0x23, 0xD5, 0x7D, 0x30, 0x67, 0x73, 0x08, 0x09,
    0xEE, 0xB7, 0x70, 0x3F, 0x61, 0xB2, 0x19, 0x8E, 0x4E, 0xE5, 0x4B, 0x93, 0x8F, 0x5D, 0xDB, 0xA9,
    0xAD, 0xF1, 0xAE, 0x2E, 0xCB, 0x0D, 0xFC, 0xF4, 0x2D, 0x46, 0x6E, 0x1D, 0x97, 0xE8, 0xD1, 0xE9,
    0x4D, 0x37, 0xA5, 0x75, 0x5E, 0x83, 0x9E, 0xAB, 0x82, 0x9D, 0xB9, 0x1C, 0xE0, 0xCD, 0x49, 0x89,
    0x01, 0xB6, 0xBD, 0x58, 0x24, 0xA2, 0x5F, 0x38, 0x78, 0x99, 0x15, 0x90, 0x50, 0xB8, 0x95, 0xE4,
    0xD0, 0x91, 0xC7, 0xCE, 0xED, 0x0F, 0xB4, 0x6F, 0xA0, 0xCC, 0xF0, 0x02, 0x4A, 0x79, 0xC3, 0xDE,
    0xA3, 0xEF, 0xEA, 0x51, 0xE6, 0x6B, 0x18, 0xEC, 0x1B, 0x2C, 0x80, 0xF7, 0x74, 0xE7, 0xFF, 0x21,
    0x5A, 0x6A, 0x54, 0x1E, 0x41, 0x31, 0x92, 0x35, 0xC4, 0x33, 0x07, 0x0A, 0xBA, 0x7E, 0x0E, 0x34,
    0x88, 0xB1, 0x98, 0x7C, 0xF3, 0x3D, 0x60, 0x6C, 0x7B, 0xCA, 0xD3, 0x1F, 0x32, 0x65, 0x04, 0x28,
    0x64, 0xBE, 0x85, 0x9B, 0x2F, 0x59, 0x8A, 0xD7, 0xB0, 0x25, 0xAC, 0xAF, 0x12, 0x03, 0xE2, 0xF2,
};

/* D */
static uint32_t D[16] = {
    0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF,
    0x4D78, 0x2F13, 0x6BC4, 0x1AF1, 0x5E26, 0x3C4D, 0x789A, 0x47AC,
};

/*
 * This is a method to calculate a + b mod (2 ^ 31 -1),
 * described in ZUC specification.
 */
static ossl_inline uint32_t modular_add(uint32_t a, uint32_t b)
{
    uint32_t c = a + b;

    return (c & 0x7FFFFFFF) + (c >> 31);
}

static ossl_inline uint32_t mulp2(uint32_t a, uint32_t b)
{
    return ((a << b) | (a >> (31 - b))) & 0x7FFFFFFF;
}

/* LFSR with initialization mode */
static void zuc_lfsr_init_mode(ZUC_KEY *zk, uint32_t u)
{
    uint32_t tmp, v, s16;

    v = mulp2(zk->s15, 15);
    tmp = mulp2(zk->s13, 17);
    v = modular_add(tmp, v);
    tmp = mulp2(zk->s10, 21);
    v = modular_add(tmp, v);
    tmp = mulp2(zk->s4, 20);
    v = modular_add(tmp, v);
    tmp = mulp2(zk->s0, 8);
    v = modular_add(tmp, v);
    v = modular_add(zk->s0, v);

    /* s16... */
    s16 = modular_add(v, u);

    zk->s0 = zk->s1;
    zk->s1 = zk->s2;
    zk->s2 = zk->s3;
    zk->s3 = zk->s4;
    zk->s4 = zk->s5;
    zk->s5 = zk->s6;
    zk->s6 = zk->s7;
    zk->s7 = zk->s8;
    zk->s8 = zk->s9;
    zk->s9 = zk->s10;
    zk->s10 = zk->s11;
    zk->s11 = zk->s12;
    zk->s12 = zk->s13;
    zk->s13 = zk->s14;
    zk->s14 = zk->s15;
    zk->s15 = s16;
}

/* LFSR with work mode */
static void zuc_lfsr_work_mode(ZUC_KEY *zk)
{
    uint32_t tmp, s16;

    s16 = zk->s0;
    tmp = mulp2(zk->s0, 8);
    s16 = modular_add(s16, tmp);
    tmp = mulp2(zk->s4, 20);
    s16 = modular_add(s16, tmp);
    tmp = mulp2(zk->s10, 21);
    s16 = modular_add(s16, tmp);
    tmp = mulp2(zk->s13, 17);
    s16 = modular_add(s16, tmp);
    tmp = mulp2(zk->s15, 15);
    s16 = modular_add(s16, tmp);

    zk->s0 = zk->s1;
    zk->s1 = zk->s2;
    zk->s2 = zk->s3;
    zk->s3 = zk->s4;
    zk->s4 = zk->s5;
    zk->s5 = zk->s6;
    zk->s6 = zk->s7;
    zk->s7 = zk->s8;
    zk->s8 = zk->s9;
    zk->s9 = zk->s10;
    zk->s10 = zk->s11;
    zk->s11 = zk->s12;
    zk->s12 = zk->s13;
    zk->s13 = zk->s14;
    zk->s14 = zk->s15;
    zk->s15 = s16;
}

/* bit reorganization */
static ossl_inline void zuc_br(ZUC_KEY *zk)
{
    zk->X0 = ((zk->s15 & 0x7FFF8000) << 1) | (zk->s14 & 0xFFFF);
    zk->X1 = ((zk->s11 & 0xFFFF) << 16) | (zk->s9 >> 15);
    zk->X2 = ((zk->s7 & 0xFFFF) << 16) | (zk->s5 >> 15);
    zk->X3 = ((zk->s2 & 0xFFFF) << 16) | (zk->s0 >> 15);
}

#define ROT(a, k) (((a) << k) | ((a) >> (32 - k)))

/* L1 */
static ossl_inline uint32_t L1(uint32_t X)
{
    return (X ^ ROT(X, 2) ^ ROT(X, 10) ^ ROT(X, 18) ^ ROT(X, 24));
}

/* L2 */
static ossl_inline uint32_t L2(uint32_t X)
{
    return (X ^ ROT(X, 8) ^ ROT(X, 14) ^ ROT(X, 22) ^ ROT(X, 30));
}

#define MAKEU32(a, b, c, d) \
    (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | ((uint32_t)(d)))

static ossl_inline uint32_t zuc_f_function(ZUC_KEY *zk)
{
    uint32_t W, W1, W2, u, v;

    W = (zk->X0 ^ zk->R1) + zk->R2;
    W1 = zk->R1 + zk->X1;
    W2 = zk->R2 ^ zk->X2;
    u = L1((W1 << 16) | (W2 >> 16));
    v = L2((W2 << 16) | (W1 >> 16));
    /* S-Box... */
    zk->R1 = MAKEU32(S0[u >> 24], S1[(u >> 16) & 0xFF],
                     S0[(u >> 8) & 0xFF], S1[u & 0xFF]);
    zk->R2 = MAKEU32(S0[v >> 24], S1[(v >> 16) & 0xFF],
                     S0[(v >> 8) & 0xFF], S1[v & 0xFF]);
    return W;
}

#define MAKEU31(a, b, c) (((uint32_t)(a) << 23) | ((uint32_t)(b) << 8) | (uint32_t)(c))

/* initialize */
void ZUC_init(ZUC_KEY *zk)
{
    uint32_t w, count = 32;

    if (zk->inited)
        return;

    /* expand key */
    zk->s0 = MAKEU31(zk->k[0], D[0], zk->iv[0]);
    zk->s1 = MAKEU31(zk->k[1], D[1], zk->iv[1]);
    zk->s2 = MAKEU31(zk->k[2], D[2], zk->iv[2]);
    zk->s3 = MAKEU31(zk->k[3], D[3], zk->iv[3]);
    zk->s4 = MAKEU31(zk->k[4], D[4], zk->iv[4]);
    zk->s5 = MAKEU31(zk->k[5], D[5], zk->iv[5]);
    zk->s6 = MAKEU31(zk->k[6], D[6], zk->iv[6]);
    zk->s7 = MAKEU31(zk->k[7], D[7], zk->iv[7]);
    zk->s8 = MAKEU31(zk->k[8], D[8], zk->iv[8]);
    zk->s9 = MAKEU31(zk->k[9], D[9], zk->iv[9]);
    zk->s10 = MAKEU31(zk->k[10], D[10], zk->iv[10]);
    zk->s11 = MAKEU31(zk->k[11], D[11], zk->iv[11]);
    zk->s12 = MAKEU31(zk->k[12], D[12], zk->iv[12]);
    zk->s13 = MAKEU31(zk->k[13], D[13], zk->iv[13]);
    zk->s14 = MAKEU31(zk->k[14], D[14], zk->iv[14]);
    zk->s15 = MAKEU31(zk->k[15], D[15], zk->iv[15]);

    zk->R1 = 0;
    zk->R2 = 0;

    while (count > 0) {
        zuc_br(zk);
        w = zuc_f_function(zk);
        zuc_lfsr_init_mode(zk, w >> 1);
        count--;
    }

    /* this part is arranged in the working stage in the ZUC spec */
    zuc_br(zk);
    zuc_f_function(zk);
    zuc_lfsr_work_mode(zk);

    zk->inited = 1;

    return;
}

int ZUC_generate_keystream(ZUC_KEY *zk)
{
    int i, len;
    uint32_t keystream;
    uint32_t pos = 0;

    if (!zk->inited)
        return 0;

    zk->L = (sizeof(zk->keystream) * 8 + 31) / 32;
    len = zk->L * sizeof(uint32_t);

    zk->keystream_tail[0] = zk->keystream[len - 4];
    zk->keystream_tail[1] = zk->keystream[len - 3];
    zk->keystream_tail[2] = zk->keystream[len - 2];
    zk->keystream_tail[3] = zk->keystream[len - 1];

    for (i = 0; i < zk->L; i++) {
        zuc_br(zk);
        keystream = zuc_f_function(zk) ^ zk->X3;
        zuc_lfsr_work_mode(zk);

        /* break 4-byte 'keystream' into key bytes */
        zk->keystream[pos] = (keystream >> 24) & 0xFF;
        zk->keystream[pos + 1] = (keystream >> 16) & 0xFF;
        zk->keystream[pos + 2] = (keystream >> 8) & 0xFF;
        zk->keystream[pos + 3] = keystream & 0xFF;

        pos += 4;
    }

    zk->keystream_tail[4] = zk->keystream[0];
    zk->keystream_tail[5] = zk->keystream[1];
    zk->keystream_tail[6] = zk->keystream[2];
    zk->keystream_tail[7] = zk->keystream[3];

    zk->keystream_len += len;

    return 1;
}

void ZUC_destroy_keystream(ZUC_KEY *zk)
{
    return;
}

int ZUC_keystream_get_word(ZUC_KEY *zk, int i)
{
    uint32_t word = 0, ti, j = i / 8, k, len;
    uint8_t *data;

    if (zk == NULL)
        return 0;

    len = zk->L * sizeof(uint32_t);
    data = zk->keystream;
    k = j % len;

    if ((k + 4) >= len) {
        data = zk->keystream_tail;
        j = k + 4 - len;
    } else {
        j = k;
    }

    ti = i % 8;
    if (ti == 0) {
        word = (uint32_t)data[j] << 24;
        word |= ((uint32_t)data[j + 1] << 16);
        word |= ((uint32_t)data[j + 2] << 8);
        word |= data[j + 3];
    } else {
        word = (uint32_t)((uint8_t)(data[j] << ti) | (uint8_t)(data[j + 1] >> (8 - ti))) << 24;
        word |= (uint32_t)((uint8_t)(data[j + 1] << ti) | (uint8_t)(data[j + 2] >> (8 - ti))) << 16;
        word |= (uint32_t)((uint8_t)(data[j + 2] << ti) | (uint8_t)(data[j + 3] >> (8 - ti))) << 8;
        word |= (data[j + 3] << ti) | (data[j + 4] >> (8 - ti));
    }

    return word;
}

int ZUC_keystream_get_byte(ZUC_KEY *zk, int i)
{
    return zk->keystream[i % (zk->L * sizeof(uint32_t))];
}
