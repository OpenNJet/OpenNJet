
/*
 * Copyright (C) Maxim Dounin
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_crypt.h>
#include <njt_md5.h>
#include <njt_sha1.h>


#if (NJT_CRYPT)

static njt_int_t njt_crypt_apr1(njt_pool_t *pool, u_char *key, u_char *salt,
    u_char **encrypted);
static njt_int_t njt_crypt_plain(njt_pool_t *pool, u_char *key, u_char *salt,
    u_char **encrypted);
static njt_int_t njt_crypt_ssha(njt_pool_t *pool, u_char *key, u_char *salt,
    u_char **encrypted);
static njt_int_t njt_crypt_sha(njt_pool_t *pool, u_char *key, u_char *salt,
    u_char **encrypted);


static u_char *njt_crypt_to64(u_char *p, uint32_t v, size_t n);


njt_int_t
njt_crypt(njt_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    if (njt_strncmp(salt, "$apr1$", sizeof("$apr1$") - 1) == 0) {
        return njt_crypt_apr1(pool, key, salt, encrypted);

    } else if (njt_strncmp(salt, "{PLAIN}", sizeof("{PLAIN}") - 1) == 0) {
        return njt_crypt_plain(pool, key, salt, encrypted);

    } else if (njt_strncmp(salt, "{SSHA}", sizeof("{SSHA}") - 1) == 0) {
        return njt_crypt_ssha(pool, key, salt, encrypted);

    } else if (njt_strncmp(salt, "{SHA}", sizeof("{SHA}") - 1) == 0) {
        return njt_crypt_sha(pool, key, salt, encrypted);
    }

    /* fallback to libc crypt() */

    return njt_libc_crypt(pool, key, salt, encrypted);
}


static njt_int_t
njt_crypt_apr1(njt_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    njt_int_t          n;
    njt_uint_t         i;
    u_char            *p, *last, final[16];
    size_t             saltlen, keylen;
    njt_md5_t          md5, ctx1;

    /* Apache's apr1 crypt is Poul-Henning Kamp's md5 crypt with $apr1$ magic */

    keylen = njt_strlen(key);

    /* true salt: no magic, max 8 chars, stop at first $ */

    salt += sizeof("$apr1$") - 1;
    last = salt + 8;
    for (p = salt; *p && *p != '$' && p < last; p++) { /* void */ }
    saltlen = p - salt;

    /* hash key and salt */

    njt_md5_init(&md5);
    njt_md5_update(&md5, key, keylen);
    njt_md5_update(&md5, (u_char *) "$apr1$", sizeof("$apr1$") - 1);
    njt_md5_update(&md5, salt, saltlen);

    njt_md5_init(&ctx1);
    njt_md5_update(&ctx1, key, keylen);
    njt_md5_update(&ctx1, salt, saltlen);
    njt_md5_update(&ctx1, key, keylen);
    njt_md5_final(final, &ctx1);

    for (n = keylen; n > 0; n -= 16) {
        njt_md5_update(&md5, final, n > 16 ? 16 : n);
    }

    njt_memzero(final, sizeof(final));

    for (i = keylen; i; i >>= 1) {
        if (i & 1) {
            njt_md5_update(&md5, final, 1);

        } else {
            njt_md5_update(&md5, key, 1);
        }
    }

    njt_md5_final(final, &md5);

    for (i = 0; i < 1000; i++) {
        njt_md5_init(&ctx1);

        if (i & 1) {
            njt_md5_update(&ctx1, key, keylen);

        } else {
            njt_md5_update(&ctx1, final, 16);
        }

        if (i % 3) {
            njt_md5_update(&ctx1, salt, saltlen);
        }

        if (i % 7) {
            njt_md5_update(&ctx1, key, keylen);
        }

        if (i & 1) {
            njt_md5_update(&ctx1, final, 16);

        } else {
            njt_md5_update(&ctx1, key, keylen);
        }

        njt_md5_final(final, &ctx1);
    }

    /* output */

    *encrypted = njt_pnalloc(pool, sizeof("$apr1$") - 1 + saltlen + 1 + 22 + 1);
    if (*encrypted == NULL) {
        return NJT_ERROR;
    }

    p = njt_cpymem(*encrypted, "$apr1$", sizeof("$apr1$") - 1);
    p = njt_copy(p, salt, saltlen);
    *p++ = '$';

    p = njt_crypt_to64(p, (final[ 0]<<16) | (final[ 6]<<8) | final[12], 4);
    p = njt_crypt_to64(p, (final[ 1]<<16) | (final[ 7]<<8) | final[13], 4);
    p = njt_crypt_to64(p, (final[ 2]<<16) | (final[ 8]<<8) | final[14], 4);
    p = njt_crypt_to64(p, (final[ 3]<<16) | (final[ 9]<<8) | final[15], 4);
    p = njt_crypt_to64(p, (final[ 4]<<16) | (final[10]<<8) | final[ 5], 4);
    p = njt_crypt_to64(p, final[11], 2);
    *p = '\0';

    return NJT_OK;
}


static u_char *
njt_crypt_to64(u_char *p, uint32_t v, size_t n)
{
    static u_char   itoa64[] =
        "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    while (n--) {
        *p++ = itoa64[v & 0x3f];
        v >>= 6;
    }

    return p;
}


static njt_int_t
njt_crypt_plain(njt_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    size_t   len;
    u_char  *p;

    len = njt_strlen(key);

    *encrypted = njt_pnalloc(pool, sizeof("{PLAIN}") - 1 + len + 1);
    if (*encrypted == NULL) {
        return NJT_ERROR;
    }

    p = njt_cpymem(*encrypted, "{PLAIN}", sizeof("{PLAIN}") - 1);
    njt_memcpy(p, key, len + 1);

    return NJT_OK;
}


static njt_int_t
njt_crypt_ssha(njt_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    size_t       len;
    njt_int_t    rc;
    njt_str_t    encoded, decoded;
    njt_sha1_t   sha1;

    /* "{SSHA}" base64(SHA1(key salt) salt) */

    /* decode base64 salt to find out true salt */

    encoded.data = salt + sizeof("{SSHA}") - 1;
    encoded.len = njt_strlen(encoded.data);

    len = njt_max(njt_base64_decoded_length(encoded.len), 20);

    decoded.data = njt_pnalloc(pool, len);
    if (decoded.data == NULL) {
        return NJT_ERROR;
    }

    rc = njt_decode_base64(&decoded, &encoded);

    if (rc != NJT_OK || decoded.len < 20) {
        decoded.len = 20;
    }

    /* update SHA1 from key and salt */

    njt_sha1_init(&sha1);
    njt_sha1_update(&sha1, key, njt_strlen(key));
    njt_sha1_update(&sha1, decoded.data + 20, decoded.len - 20);
    njt_sha1_final(decoded.data, &sha1);

    /* encode it back to base64 */

    len = sizeof("{SSHA}") - 1 + njt_base64_encoded_length(decoded.len) + 1;

    *encrypted = njt_pnalloc(pool, len);
    if (*encrypted == NULL) {
        return NJT_ERROR;
    }

    encoded.data = njt_cpymem(*encrypted, "{SSHA}", sizeof("{SSHA}") - 1);
    njt_encode_base64(&encoded, &decoded);
    encoded.data[encoded.len] = '\0';

    return NJT_OK;
}


static njt_int_t
njt_crypt_sha(njt_pool_t *pool, u_char *key, u_char *salt, u_char **encrypted)
{
    size_t      len;
    njt_str_t   encoded, decoded;
    njt_sha1_t  sha1;
    u_char      digest[20];

    /* "{SHA}" base64(SHA1(key)) */

    decoded.len = sizeof(digest);
    decoded.data = digest;

    njt_sha1_init(&sha1);
    njt_sha1_update(&sha1, key, njt_strlen(key));
    njt_sha1_final(digest, &sha1);

    len = sizeof("{SHA}") - 1 + njt_base64_encoded_length(decoded.len) + 1;

    *encrypted = njt_pnalloc(pool, len);
    if (*encrypted == NULL) {
        return NJT_ERROR;
    }

    encoded.data = njt_cpymem(*encrypted, "{SHA}", sizeof("{SHA}") - 1);
    njt_encode_base64(&encoded, &decoded);
    encoded.data[encoded.len] = '\0';

    return NJT_OK;
}

#endif /* NJT_CRYPT */
