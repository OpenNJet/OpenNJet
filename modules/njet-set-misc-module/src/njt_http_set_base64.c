#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"

#include    <ndk.h>
#include "njt_http_set_base64.h"


njt_int_t
njt_http_set_misc_set_decode_base64(njt_http_request_t *r, njt_str_t *res,
    njt_http_variable_value_t *v)
{
    njt_str_t        src;

    src.len = v->len;
    src.data = v->data;

    res->len = njt_base64_decoded_length(v->len);
    ndk_palloc_re(res->data, r->pool, res->len);

    if (njt_decode_base64(res, &src) != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "set_decode_base64: invalid value");
        return NJT_ERROR;
    }

    return NJT_OK;
}


njt_int_t
njt_http_set_misc_set_encode_base64(njt_http_request_t *r, njt_str_t *res,
    njt_http_variable_value_t *v)
{
    njt_str_t        src;

    src.len = v->len;
    src.data = v->data;

    res->len = njt_base64_encoded_length(v->len);
    ndk_palloc_re(res->data, r->pool, res->len);

    njt_encode_base64(res, &src);

    return NJT_OK;
}

