#ifndef NJT_HTTP_REDIS2_UTIL_H
#define NJT_HTTP_REDIS2_UTIL_H


#include "njt_http_redis2_module.h"


#ifndef njt_str_set
#define njt_str_set(str, text)                                               \
    (str)->len = sizeof(text) - 1; (str)->data = (u_char *) text
#endif


char *njt_http_redis2_set_complex_value_slot(njt_conf_t *cf,
        njt_command_t *cmd, void *conf);
njt_http_upstream_srv_conf_t *njt_http_redis2_upstream_add(
        njt_http_request_t *r, njt_url_t *url);
njt_int_t njt_http_redis2_build_query(njt_http_request_t *r,
        njt_array_t *queries, njt_buf_t **b);

#endif /* NJT_HTTP_REDIS2_UTIL_H */

