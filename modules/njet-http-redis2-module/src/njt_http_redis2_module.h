#ifndef NJT_HTTP_REDIS2_MODULE_H
#define NJT_HTTP_REDIS2_MODULE_H


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


extern njt_module_t  njt_http_redis2_module;

typedef struct {
    njt_http_upstream_conf_t   upstream;
    njt_str_t                  literal_query; /* for redis2_literal_raw_query */
    njt_http_complex_value_t  *complex_query; /* for redis2_raw_query */
    njt_http_complex_value_t  *complex_query_count; /* for redis2_raw_query */
    njt_http_complex_value_t  *complex_target; /* for redis2_pass */
    njt_array_t               *queries; /* for redis2_query */

} njt_http_redis2_loc_conf_t;


typedef struct njt_http_redis2_ctx_s  njt_http_redis2_ctx_t;

typedef njt_int_t (*njt_http_redis2_filter_handler_ptr)
    (njt_http_redis2_ctx_t *ctx, ssize_t bytes);


struct njt_http_redis2_ctx_s {
    njt_int_t                  query_count;
    njt_http_request_t        *request;
    int                        state;
    size_t                     chunk_size;
    size_t                     chunk_bytes_read;
    size_t                     chunks_read;
    size_t                     chunk_count;

    njt_http_redis2_filter_handler_ptr  filter;
};


#endif /* NJT_HTTP_REDIS2_MODULE_H */

