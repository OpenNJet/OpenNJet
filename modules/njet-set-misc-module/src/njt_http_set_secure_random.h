#ifndef NJT_SET_SECURE_RANDOM_H
#define NJT_SET_SECURE_RANDOM_H

#include <njt_core.h>
#include <njt_config.h>
#include <njt_http.h>

njt_int_t njt_http_set_misc_set_secure_random_alphanum(njt_http_request_t *r,
        njt_str_t *res, njt_http_variable_value_t *v);

njt_int_t njt_http_set_misc_set_secure_random_lcalpha(njt_http_request_t *r,
        njt_str_t *res, njt_http_variable_value_t *v);

#endif /* NJT_SET_SECURE_RANDOM_H */

