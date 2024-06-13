#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"

#include <ndk.h>
#include "njt_http_set_hex.h"


njt_int_t
njt_http_set_misc_set_decode_hex(njt_http_request_t *r, njt_str_t *res,
    njt_http_variable_value_t *v)
{
    u_char      *p;
    njt_int_t    n;
    njt_uint_t   i;
    size_t       len;

    if (v->len % 2 != 0) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "set_decode_hex: invalid value");
        return NJT_ERROR;
    }

    p = v->data;
    len = v->len >> 1;

    res->data = njt_palloc(r->pool, len);
    if (res->data == NULL) {
        return NJT_ERROR;
    }

    for (i = 0; i < len; i++) {
        n = njt_hextoi(p, 2);
        if (n == NJT_ERROR || n > 255) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "set_decode_hex: invalid value");
            return NJT_ERROR;
        }

        p += 2;
        res->data[i] = (u_char) n;
    }

    res->len = len;
    return NJT_OK;
}


njt_int_t
njt_http_set_misc_set_encode_hex(njt_http_request_t *r, njt_str_t *res,
    njt_http_variable_value_t *v)
{
    res->len = v->len << 1;
    res->data = njt_palloc(r->pool, res->len);
    if (res->data == NULL) {
        return NJT_ERROR;
    }

    njt_hex_dump(res->data, v->data, v->len);
    return NJT_OK;
}
