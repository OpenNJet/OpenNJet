#include <njt_core.h>
#include <njt_config.h>
#include <njt_http.h>

njt_int_t njt_http_set_misc_set_hmac_sha1(njt_http_request_t *r,
        njt_str_t *res, njt_http_variable_value_t *v);

njt_int_t njt_http_set_misc_set_hmac_sha256(njt_http_request_t *r,
        njt_str_t *res, njt_http_variable_value_t *v);
