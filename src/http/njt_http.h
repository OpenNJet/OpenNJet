
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_H_INCLUDED_
#define _NJT_HTTP_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


typedef struct njt_http_request_s     njt_http_request_t;
typedef struct njt_http_upstream_s    njt_http_upstream_t;
typedef struct njt_http_cache_s       njt_http_cache_t;
typedef struct njt_http_file_cache_s  njt_http_file_cache_t;
typedef struct njt_http_log_ctx_s     njt_http_log_ctx_t;
typedef struct njt_http_chunked_s     njt_http_chunked_t;
typedef struct njt_http_v2_stream_s   njt_http_v2_stream_t;
typedef struct njt_http_v3_parse_s    njt_http_v3_parse_t;
typedef struct njt_http_v3_session_s  njt_http_v3_session_t;

typedef njt_int_t (*njt_http_header_handler_pt)(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset);
typedef u_char *(*njt_http_log_handler_pt)(njt_http_request_t *r,
    njt_http_request_t *sr, u_char *buf, size_t len);


#include <njt_http_variables.h>
#include <njt_http_config.h>
#include <njt_http_request.h>
#include <njt_http_script.h>
#include <njt_http_upstream.h>
#include <njt_http_upstream_round_robin.h>
#include <njt_http_core_module.h>

#if (NJT_HTTP_V2)
#include <njt_http_v2.h>
#endif
#if (NJT_HTTP_V3)
#include <njt_http_v3.h>
#endif
#if (NJT_HTTP_CACHE)
#include <njt_http_cache.h>
#endif
#if (NJT_HTTP_SSI)
#include <njt_http_ssi_filter_module.h>
#endif
#if (NJT_HTTP_SSL)
#include <njt_http_ssl_module.h>
#endif


struct njt_http_log_ctx_s {
    njt_connection_t    *connection;
    njt_http_request_t  *request;
    njt_http_request_t  *current_request;
};


struct njt_http_chunked_s {
    njt_uint_t           state;
    off_t                size;
    off_t                length;
};


typedef struct {
    njt_uint_t           http_version;
    njt_uint_t           code;
    njt_uint_t           count;
    u_char              *start;
    u_char              *end;
} njt_http_status_t;

typedef struct {
    njt_array_t  *codes;        /* uintptr_t */
    
    njt_uint_t    stack_size;

    njt_flag_t    log;
    njt_flag_t    uninitialized_variable_warn;
	#if (NJT_HTTP_DYNAMIC_LOC)
		 njt_array_t  var_names;  
    		 njt_array_t  *mul_codes;        /* uintptr_t */
		 njt_int_t    ret;
	#endif
} njt_http_rewrite_loc_conf_t;


#define njt_http_get_module_ctx(r, module)  (r)->ctx[module.ctx_index]
#define njt_http_set_ctx(r, c, module)      r->ctx[module.ctx_index] = c;


njt_int_t njt_http_add_location(njt_conf_t *cf, njt_queue_t **locations,
    njt_http_core_loc_conf_t *clcf);
njt_int_t njt_http_add_listen(njt_conf_t *cf, njt_http_core_srv_conf_t *cscf,
    njt_http_listen_opt_t *lsopt);


void njt_http_init_connection(njt_connection_t *c);
void njt_http_close_connection(njt_connection_t *c);

#if (NJT_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)
int njt_http_ssl_servername(njt_ssl_conn_t *ssl_conn, int *ad, void *arg);
#endif
#if (NJT_HTTP_SSL && defined SSL_R_CERT_CB_ERROR)
int njt_http_ssl_certificate(njt_ssl_conn_t *ssl_conn, void *arg);
#endif


njt_int_t njt_http_parse_request_line(njt_http_request_t *r, njt_buf_t *b);
njt_int_t njt_http_parse_uri(njt_http_request_t *r);
njt_int_t njt_http_parse_complex_uri(njt_http_request_t *r,
    njt_uint_t merge_slashes);
njt_int_t njt_http_parse_status_line(njt_http_request_t *r, njt_buf_t *b,
    njt_http_status_t *status);
njt_int_t njt_http_parse_unsafe_uri(njt_http_request_t *r, njt_str_t *uri,
    njt_str_t *args, njt_uint_t *flags);
njt_int_t njt_http_parse_header_line(njt_http_request_t *r, njt_buf_t *b,
    njt_uint_t allow_underscores);
njt_table_elt_t *njt_http_parse_multi_header_lines(njt_http_request_t *r,
    njt_table_elt_t *headers, njt_str_t *name, njt_str_t *value);
njt_table_elt_t *njt_http_parse_set_cookie_lines(njt_http_request_t *r,
    njt_table_elt_t *headers, njt_str_t *name, njt_str_t *value);
njt_int_t njt_http_arg(njt_http_request_t *r, u_char *name, size_t len,
    njt_str_t *value);
void njt_http_split_args(njt_http_request_t *r, njt_str_t *uri,
    njt_str_t *args);
njt_int_t njt_http_parse_chunked(njt_http_request_t *r, njt_buf_t *b,
    njt_http_chunked_t *ctx);

njt_int_t njt_http_init_new_locations(njt_conf_t *cf,
    njt_http_core_srv_conf_t *cscf, njt_http_core_loc_conf_t *pclcf);

njt_int_t njt_http_init_new_static_location_trees(njt_conf_t *cf,
    njt_http_core_loc_conf_t *pclcf);

char *njt_http_merge_servers(njt_conf_t *cf,
    njt_http_core_main_conf_t *cmcf, njt_http_module_t *module,
    njt_uint_t ctx_index);

njt_http_request_t *njt_http_create_request(njt_connection_t *c);
njt_int_t njt_http_process_request_uri(njt_http_request_t *r);
njt_int_t njt_http_process_request_header(njt_http_request_t *r);
void njt_http_process_request(njt_http_request_t *r);
void njt_http_update_location_config(njt_http_request_t *r);
void njt_http_handler(njt_http_request_t *r);
void njt_http_run_posted_requests(njt_connection_t *c);
njt_int_t njt_http_post_request(njt_http_request_t *r,
    njt_http_posted_request_t *pr);
njt_int_t njt_http_set_virtual_server(njt_http_request_t *r,
    njt_str_t *host);
njt_int_t njt_http_validate_host(njt_str_t *host, njt_pool_t *pool,
    njt_uint_t alloc);
void njt_http_close_request(njt_http_request_t *r, njt_int_t rc);
void njt_http_finalize_request(njt_http_request_t *r, njt_int_t rc);
void njt_http_free_request(njt_http_request_t *r, njt_int_t rc);

void njt_http_empty_handler(njt_event_t *wev);
void njt_http_request_empty_handler(njt_http_request_t *r);


#define NJT_HTTP_LAST   1
#define NJT_HTTP_FLUSH  2

njt_int_t njt_http_send_special(njt_http_request_t *r, njt_uint_t flags);

char *njt_http_merge_locations(njt_conf_t *cf,
    njt_queue_t *locations, void **loc_conf, njt_http_module_t *module,
    njt_uint_t ctx_index);
njt_int_t njt_http_read_client_request_body(njt_http_request_t *r,
    njt_http_client_body_handler_pt post_handler);
njt_int_t njt_http_read_unbuffered_request_body(njt_http_request_t *r);

njt_int_t njt_http_send_header(njt_http_request_t *r);
njt_int_t njt_http_special_response_handler(njt_http_request_t *r,
    njt_int_t error);
njt_int_t njt_http_filter_finalize_request(njt_http_request_t *r,
    njt_module_t *m, njt_int_t error);
void njt_http_clean_header(njt_http_request_t *r);


njt_int_t njt_http_discard_request_body(njt_http_request_t *r);
void njt_http_discarded_request_body_handler(njt_http_request_t *r);
void njt_http_block_reading(njt_http_request_t *r);
void njt_http_test_reading(njt_http_request_t *r);


char *njt_http_types_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *njt_http_merge_types(njt_conf_t *cf, njt_array_t **keys,
    njt_hash_t *types_hash, njt_array_t **prev_keys,
    njt_hash_t *prev_types_hash, njt_str_t *default_types);
njt_int_t njt_http_set_default_types(njt_conf_t *cf, njt_array_t **types,
    njt_str_t *default_type);

njt_int_t
njt_http_add_if_location(njt_conf_t *cf, njt_queue_t **locations,
                      njt_http_core_loc_conf_t *clcf);
#if (NJT_HTTP_DEGRADATION)
njt_uint_t  njt_http_degraded(njt_http_request_t *);
#endif


#if (NJT_HTTP_V2 || NJT_HTTP_V3)
njt_int_t njt_http_huff_decode(u_char *state, u_char *src, size_t len,
    u_char **dst, njt_uint_t last, njt_log_t *log);
size_t njt_http_huff_encode(u_char *src, size_t len, u_char *dst,
    njt_uint_t lower);
#endif


extern njt_module_t  njt_http_module;

extern njt_str_t  njt_http_html_default_types[];


extern njt_http_output_header_filter_pt  njt_http_top_header_filter;
extern njt_http_output_body_filter_pt    njt_http_top_body_filter;
extern njt_http_request_body_filter_pt   njt_http_top_request_body_filter;

char *
njt_http_rewrite_if_condition(njt_conf_t *cf, njt_http_rewrite_loc_conf_t *lcf);
#endif /* _NJT_HTTP_H_INCLUDED_ */
