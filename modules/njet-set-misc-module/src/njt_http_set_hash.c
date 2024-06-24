#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"

#include "njt_http_set_hash.h"

#if NJT_HAVE_SHA1
#include "njt_sha1.h"

#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif

#endif

#include "njt_md5.h"


#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16
#endif

enum {
#if NJT_HAVE_SHA1
    SHA_HEX_LENGTH = SHA_DIGEST_LENGTH * 2,
#endif
    MD5_HEX_LENGTH = MD5_DIGEST_LENGTH * 2
};


#if NJT_HAVE_SHA1
njt_int_t
njt_http_set_misc_set_sha1(njt_http_request_t *r, njt_str_t *res,
    njt_http_variable_value_t *v)
{
    u_char                  *p;
    njt_sha1_t               sha;
    u_char                   sha_buf[SHA_DIGEST_LENGTH];

    p = njt_palloc(r->pool, SHA_HEX_LENGTH);
    if (p == NULL) {
        return NJT_ERROR;
    }

    njt_sha1_init(&sha);
    njt_sha1_update(&sha, v->data, v->len);
    njt_sha1_final(sha_buf, &sha);

    njt_hex_dump(p, sha_buf, sizeof(sha_buf));

    res->data = p;
    res->len = SHA_HEX_LENGTH;

    return NJT_OK;
}
#endif


njt_int_t
njt_http_set_misc_set_md5(njt_http_request_t *r, njt_str_t *res,
    njt_http_variable_value_t *v)
{
    u_char                  *p;
    njt_md5_t                md5;
    u_char                   md5_buf[MD5_DIGEST_LENGTH];

    p = njt_palloc(r->pool, MD5_HEX_LENGTH);
    if (p == NULL) {
        return NJT_ERROR;
    }

    njt_md5_init(&md5);
    njt_md5_update(&md5, v->data, v->len);
    njt_md5_final(md5_buf, &md5);

    njt_hex_dump(p, md5_buf, sizeof(md5_buf));

    res->data = p;
    res->len = MD5_HEX_LENGTH;

    return NJT_OK;
}
