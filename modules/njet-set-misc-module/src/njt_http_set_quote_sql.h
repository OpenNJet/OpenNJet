#ifndef NJT_SET_QUOTE_SQL_H
#define NJT_SET_QUOTE_SQL_H


#include <njt_core.h>
#include <njt_config.h>
#include <njt_http.h>


uintptr_t njt_http_set_misc_escape_sql_str(u_char *dst, u_char *src,
        size_t size);

njt_int_t njt_http_set_misc_quote_sql_str(njt_http_request_t *r,
        njt_str_t *res, njt_http_variable_value_t *v);

njt_int_t njt_http_set_misc_quote_pgsql_str(njt_http_request_t *r,
        njt_str_t *res, njt_http_variable_value_t *v);


#endif /* NJT_SET_QUOTE_SQL_H */

