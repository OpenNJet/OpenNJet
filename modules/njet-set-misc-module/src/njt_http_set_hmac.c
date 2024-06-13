#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"

#include <ndk.h>

#include "njt_http_set_hmac.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>


/* this function's implementation is partly borrowed from
 * https://github.com/anomalizer/njt_aws_auth */
static njt_int_t
njt_http_set_misc_set_hmac(njt_http_request_t *r, njt_str_t *res,
    njt_http_variable_value_t *v, const EVP_MD *evp_md)
{
    njt_http_variable_value_t   *secret, *string_to_sign;
    unsigned int                 md_len = 0;
    unsigned char                md[EVP_MAX_MD_SIZE];

    secret = v;
    string_to_sign = v + 1;

    dd("secret=%.*s, string_to_sign=%.*s", (int) secret->len, secret->data,
       (int) string_to_sign->len, string_to_sign->data);

    HMAC(evp_md, secret->data, secret->len, string_to_sign->data,
         string_to_sign->len, md, &md_len);

    /* defensive test if there is something wrong with openssl */
    if (md_len == 0 || md_len > EVP_MAX_MD_SIZE) {
        res->len = 0;
        return NJT_ERROR;
    }

    res->len = md_len;
    ndk_palloc_re(res->data, r->pool, md_len);

    njt_memcpy(res->data,
               &md,
               md_len);

    return NJT_OK;
}


njt_int_t
njt_http_set_misc_set_hmac_sha1(njt_http_request_t *r, njt_str_t *res,
    njt_http_variable_value_t *v)
{
    return njt_http_set_misc_set_hmac(r, res, v, EVP_sha1());
}


njt_int_t
njt_http_set_misc_set_hmac_sha256(njt_http_request_t *r, njt_str_t *res,
    njt_http_variable_value_t *v)
{
    return njt_http_set_misc_set_hmac(r, res, v, EVP_sha256());
}
