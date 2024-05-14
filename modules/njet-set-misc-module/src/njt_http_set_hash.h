#ifndef NJT_HTTP_SET_HASH_H
#define NJT_HTTP_SET_HASH_H


#include "njt_http_set_misc_module.h"


njt_int_t njt_http_set_misc_set_sha1(njt_http_request_t *r,
        njt_str_t *res, njt_http_variable_value_t *v);


njt_int_t njt_http_set_misc_set_md5(njt_http_request_t *r,
        njt_str_t *res, njt_http_variable_value_t *v);

#endif /* NJT_HTTP_SET_HASH_H */
