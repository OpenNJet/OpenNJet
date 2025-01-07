#ifndef NJT_HTTP_SET_MISC_ROTATE_H
#define NJT_HTTP_SET_MISC_ROTATE_H


#include <njt_core.h>
#include <njt_config.h>
#include <njt_http.h>


char *njt_http_set_rotate(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);

njt_int_t njt_http_set_misc_set_rotate(njt_http_request_t *r,
    njt_str_t *res, njt_http_variable_value_t *v);


#endif /* NJT_HTTP_SET_MISC_ROTATE_H */

