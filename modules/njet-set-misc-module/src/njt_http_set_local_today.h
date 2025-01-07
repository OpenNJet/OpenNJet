#include <njt_core.h>
#include <njt_config.h>
#include <njt_http.h>


njt_int_t njt_http_set_local_today(njt_http_request_t *r, njt_str_t *res,
        njt_http_variable_value_t *v);

njt_int_t njt_http_set_formatted_gmt_time(njt_http_request_t *r, njt_str_t *res,
        njt_http_variable_value_t *v);

njt_int_t njt_http_set_formatted_local_time(njt_http_request_t *r,
        njt_str_t *res, njt_http_variable_value_t *v);
