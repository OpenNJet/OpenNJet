#ifndef NJT_HTTP_SET_HASHED_UPSTREAM
#define NJT_HTTP_SET_HASHED_UPSTREAM


#include <njt_core.h>
#include <njt_config.h>
#include <njt_http.h>
#include <ndk.h>


typedef enum {
    njt_http_set_misc_distribution_modula,
    njt_http_set_misc_distribution_random /* XXX not used */
} njt_http_set_misc_distribution_t;


njt_uint_t njt_http_set_misc_apply_distribution(njt_log_t *log, njt_uint_t hash,
    ndk_upstream_list_t *ul, njt_http_set_misc_distribution_t type);

char *njt_http_set_hashed_upstream(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);

njt_int_t njt_http_set_misc_set_hashed_upstream(njt_http_request_t *r,
    njt_str_t *res, njt_http_variable_value_t *v, void *data);


#endif /* NJT_HTTP_SET_HASHED_UPSTREAM */
