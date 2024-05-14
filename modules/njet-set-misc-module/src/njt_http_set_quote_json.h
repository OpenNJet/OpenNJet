#ifndef NJT_HTTP_SET_QUOTE_JSON_H
#define NJT_HTTP_SET_QUOTE_JSON_H


#include <njt_core.h>
#include <njt_config.h>
#include <njt_http.h>


njt_int_t njt_http_set_misc_quote_json_str(njt_http_request_t *r,
        njt_str_t *res, njt_http_variable_value_t *v);
uintptr_t njt_http_set_misc_escape_json_str(u_char *dst, u_char *src,
        size_t size);


#endif /* NJT_HTTP_SET_QUOTE_JSON_H */
