
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_str_util.h>
// by chengxu
#if (NJT_HTTP_CACHE_PURGE)
#include <njt_cache_purge.h>
#endif
// end

#if (NJT_HTTP_CACHE)
static njt_int_t njt_http_upstream_cache(njt_http_request_t *r,
    njt_http_upstream_t *u);
static njt_int_t njt_http_upstream_cache_get(njt_http_request_t *r,
    njt_http_upstream_t *u, njt_http_file_cache_t **cache);
static njt_int_t njt_http_upstream_cache_send(njt_http_request_t *r,
    njt_http_upstream_t *u);
static njt_int_t njt_http_upstream_cache_background_update(
    njt_http_request_t *r, njt_http_upstream_t *u);
static njt_int_t njt_http_upstream_cache_check_range(njt_http_request_t *r,
    njt_http_upstream_t *u);
static njt_int_t njt_http_upstream_cache_status(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_upstream_cache_last_modified(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_upstream_cache_etag(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
#endif
extern njt_int_t njt_http_proxy_create_request(njt_http_request_t *r);
static void njt_http_upstream_init_request(njt_http_request_t *r);
static void njt_http_upstream_resolve_handler(njt_resolver_ctx_t *ctx);
static void njt_http_upstream_rd_check_broken_connection(njt_http_request_t *r);
static void njt_http_upstream_wr_check_broken_connection(njt_http_request_t *r);
static void njt_http_upstream_check_broken_connection(njt_http_request_t *r,
    njt_event_t *ev);
static void njt_http_upstream_connect(njt_http_request_t *r,
    njt_http_upstream_t *u);
static njt_int_t njt_http_upstream_reinit(njt_http_request_t *r,
    njt_http_upstream_t *u);
static void njt_http_upstream_send_request(njt_http_request_t *r,
    njt_http_upstream_t *u, njt_uint_t do_write);
static njt_int_t njt_http_upstream_send_request_body(njt_http_request_t *r,
    njt_http_upstream_t *u, njt_uint_t do_write);
 void njt_http_upstream_send_request_handler(njt_http_request_t *r,
    njt_http_upstream_t *u);
static void njt_http_upstream_read_request_handler(njt_http_request_t *r);
void njt_http_upstream_process_header(njt_http_request_t *r,
    njt_http_upstream_t *u);
static njt_int_t njt_http_upstream_test_next(njt_http_request_t *r,
    njt_http_upstream_t *u);
static njt_int_t njt_http_upstream_intercept_errors(njt_http_request_t *r,
    njt_http_upstream_t *u);
static njt_int_t njt_http_upstream_test_connect(njt_connection_t *c);
static njt_int_t njt_http_upstream_process_headers(njt_http_request_t *r,
    njt_http_upstream_t *u);
static njt_int_t njt_http_upstream_process_trailers(njt_http_request_t *r,
    njt_http_upstream_t *u);
static void njt_http_upstream_send_response(njt_http_request_t *r,
    njt_http_upstream_t *u);
static void njt_http_upstream_upgrade(njt_http_request_t *r,
    njt_http_upstream_t *u);
static void njt_http_upstream_upgraded_read_downstream(njt_http_request_t *r);
static void njt_http_upstream_upgraded_write_downstream(njt_http_request_t *r);
static void njt_http_upstream_upgraded_read_upstream(njt_http_request_t *r,
    njt_http_upstream_t *u);
static void njt_http_upstream_upgraded_write_upstream(njt_http_request_t *r,
    njt_http_upstream_t *u);
static void njt_http_upstream_process_upgraded(njt_http_request_t *r,
    njt_uint_t from_upstream, njt_uint_t do_write);
static void
    njt_http_upstream_process_non_buffered_downstream(njt_http_request_t *r);
static void
    njt_http_upstream_process_non_buffered_upstream(njt_http_request_t *r,
    njt_http_upstream_t *u);
static void
    njt_http_upstream_process_non_buffered_request(njt_http_request_t *r,
    njt_uint_t do_write);
#if (NJT_THREADS)
static njt_int_t njt_http_upstream_thread_handler(njt_thread_task_t *task,
    njt_file_t *file);
static void njt_http_upstream_thread_event_handler(njt_event_t *ev);
#endif
static njt_int_t njt_http_upstream_output_filter(void *data,
    njt_chain_t *chain);
static void njt_http_upstream_process_downstream(njt_http_request_t *r);
static void njt_http_upstream_process_upstream(njt_http_request_t *r,
    njt_http_upstream_t *u);
static void njt_http_upstream_process_request(njt_http_request_t *r,
    njt_http_upstream_t *u);
static void njt_http_upstream_store(njt_http_request_t *r,
    njt_http_upstream_t *u);
static void njt_http_upstream_dummy_handler(njt_http_request_t *r,
    njt_http_upstream_t *u);
static void njt_http_upstream_next(njt_http_request_t *r,
    njt_http_upstream_t *u, njt_uint_t ft_type);
static void njt_http_upstream_cleanup(void *data);
static void njt_http_upstream_finalize_request(njt_http_request_t *r,
    njt_http_upstream_t *u, njt_int_t rc);

static njt_int_t njt_http_upstream_process_header_line(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset);
static njt_int_t
    njt_http_upstream_process_multi_header_lines(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset);
static njt_int_t njt_http_upstream_process_content_length(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset);
static njt_int_t njt_http_upstream_process_last_modified(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset);
static njt_int_t njt_http_upstream_process_set_cookie(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset);
static njt_int_t
    njt_http_upstream_process_cache_control(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset);
static njt_int_t njt_http_upstream_ignore_header_line(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset);
static njt_int_t njt_http_upstream_process_expires(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset);
static njt_int_t njt_http_upstream_process_accel_expires(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset);
static njt_int_t njt_http_upstream_process_limit_rate(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset);
static njt_int_t njt_http_upstream_process_buffering(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset);
static njt_int_t njt_http_upstream_process_charset(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset);
static njt_int_t njt_http_upstream_process_connection(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset);
static njt_int_t
    njt_http_upstream_process_transfer_encoding(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset);
static njt_int_t njt_http_upstream_process_vary(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset);
static njt_int_t njt_http_upstream_copy_header_line(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset);
static njt_int_t
    njt_http_upstream_copy_multi_header_lines(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset);
static njt_int_t njt_http_upstream_copy_content_type(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset);
static njt_int_t njt_http_upstream_copy_last_modified(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset);
static njt_int_t njt_http_upstream_rewrite_location(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset);
static njt_int_t njt_http_upstream_rewrite_refresh(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset);
static njt_int_t njt_http_upstream_rewrite_set_cookie(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset);
static njt_int_t njt_http_upstream_copy_allow_ranges(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset);

static njt_int_t njt_http_upstream_add_variables(njt_conf_t *cf);
static njt_int_t njt_http_upstream_addr_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_upstream_status_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_upstream_response_time_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_upstream_response_length_variable(
    njt_http_request_t *r, njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_upstream_header_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_upstream_trailer_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_upstream_cookie_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);

static char *njt_http_upstream(njt_conf_t *cf, njt_command_t *cmd, void *dummy);
//static char *njt_http_upstream_server(njt_conf_t *cf, njt_command_t *cmd,
//    void *conf);

static njt_int_t njt_http_upstream_set_local(njt_http_request_t *r,
  njt_http_upstream_t *u, njt_http_upstream_local_t *local);

static void *njt_http_upstream_create_main_conf(njt_conf_t *cf);
static char *njt_http_upstream_init_main_conf(njt_conf_t *cf, void *conf);

#if (NJT_HTTP_SSL)
static void njt_http_upstream_ssl_init_connection(njt_http_request_t *,
    njt_http_upstream_t *u, njt_connection_t *c);
static void njt_http_upstream_ssl_handshake_handler(njt_connection_t *c);
static void njt_http_upstream_ssl_handshake(njt_http_request_t *,
    njt_http_upstream_t *u, njt_connection_t *c);
static void njt_http_upstream_ssl_save_session(njt_connection_t *c);
static njt_int_t njt_http_upstream_ssl_name(njt_http_request_t *r,
    njt_http_upstream_t *u, njt_connection_t *c);
static njt_int_t njt_http_upstream_ssl_certificate(njt_http_request_t *r,
    njt_http_upstream_t *u, njt_connection_t *c);
#if (NJT_HTTP_MULTICERT)
static njt_int_t njt_http_upstream_ssl_certificates(njt_http_request_t *r,
    njt_http_upstream_t *u, njt_connection_t *c);
#endif

#endif


static njt_http_upstream_header_t  njt_http_upstream_headers_in[] = {

    { njt_string("Status"),
                 njt_http_upstream_process_header_line,
                 offsetof(njt_http_upstream_headers_in_t, status),
                 njt_http_upstream_copy_header_line, 0, 0 },

    { njt_string("Content-Type"),
                 njt_http_upstream_process_header_line,
                 offsetof(njt_http_upstream_headers_in_t, content_type),
                 njt_http_upstream_copy_content_type, 0, 1 },

    { njt_string("Content-Length"),
                 njt_http_upstream_process_content_length, 0,
                 njt_http_upstream_ignore_header_line, 0, 0 },

    { njt_string("Date"),
                 njt_http_upstream_process_header_line,
                 offsetof(njt_http_upstream_headers_in_t, date),
                 njt_http_upstream_copy_header_line,
                 offsetof(njt_http_headers_out_t, date), 0 },

    { njt_string("Last-Modified"),
                 njt_http_upstream_process_last_modified, 0,
                 njt_http_upstream_copy_last_modified, 0, 0 },

    { njt_string("ETag"),
                 njt_http_upstream_process_header_line,
                 offsetof(njt_http_upstream_headers_in_t, etag),
                 njt_http_upstream_copy_header_line,
                 offsetof(njt_http_headers_out_t, etag), 0 },

    { njt_string("Server"),
                 njt_http_upstream_process_header_line,
                 offsetof(njt_http_upstream_headers_in_t, server),
                 njt_http_upstream_copy_header_line,
                 offsetof(njt_http_headers_out_t, server), 0 },

    { njt_string("WWW-Authenticate"),
                 njt_http_upstream_process_multi_header_lines,
                 offsetof(njt_http_upstream_headers_in_t, www_authenticate),
                 njt_http_upstream_copy_header_line, 0, 0 },

    { njt_string("Location"),
                 njt_http_upstream_process_header_line,
                 offsetof(njt_http_upstream_headers_in_t, location),
                 njt_http_upstream_rewrite_location, 0, 0 },

    { njt_string("Refresh"),
                 njt_http_upstream_process_header_line,
                 offsetof(njt_http_upstream_headers_in_t, refresh),
                 njt_http_upstream_rewrite_refresh, 0, 0 },

    { njt_string("Set-Cookie"),
                 njt_http_upstream_process_set_cookie,
                 offsetof(njt_http_upstream_headers_in_t, set_cookie),
                 njt_http_upstream_rewrite_set_cookie, 0, 1 },

    { njt_string("Content-Disposition"),
                 njt_http_upstream_ignore_header_line, 0,
                 njt_http_upstream_copy_header_line, 0, 1 },

    { njt_string("Cache-Control"),
                 njt_http_upstream_process_cache_control, 0,
                 njt_http_upstream_copy_multi_header_lines,
                 offsetof(njt_http_headers_out_t, cache_control), 1 },

    { njt_string("Expires"),
                 njt_http_upstream_process_expires, 0,
                 njt_http_upstream_copy_header_line,
                 offsetof(njt_http_headers_out_t, expires), 1 },

    { njt_string("Accept-Ranges"),
                 njt_http_upstream_ignore_header_line, 0,
                 njt_http_upstream_copy_allow_ranges,
                 offsetof(njt_http_headers_out_t, accept_ranges), 1 },

    { njt_string("Content-Range"),
                 njt_http_upstream_ignore_header_line, 0,
                 njt_http_upstream_copy_header_line,
                 offsetof(njt_http_headers_out_t, content_range), 0 },

    { njt_string("Connection"),
                 njt_http_upstream_process_connection, 0,
                 njt_http_upstream_ignore_header_line, 0, 0 },

    { njt_string("Keep-Alive"),
                 njt_http_upstream_ignore_header_line, 0,
                 njt_http_upstream_ignore_header_line, 0, 0 },

    { njt_string("Vary"),
                 njt_http_upstream_process_vary, 0,
                 njt_http_upstream_copy_header_line, 0, 0 },

    { njt_string("Link"),
                 njt_http_upstream_ignore_header_line, 0,
                 njt_http_upstream_copy_multi_header_lines,
                 offsetof(njt_http_headers_out_t, link), 0 },

    { njt_string("X-Accel-Expires"),
                 njt_http_upstream_process_accel_expires, 0,
                 njt_http_upstream_copy_header_line, 0, 0 },

    { njt_string("X-Accel-Redirect"),
                 njt_http_upstream_process_header_line,
                 offsetof(njt_http_upstream_headers_in_t, x_accel_redirect),
                 njt_http_upstream_copy_header_line, 0, 0 },

    { njt_string("X-Accel-Limit-Rate"),
                 njt_http_upstream_process_limit_rate, 0,
                 njt_http_upstream_copy_header_line, 0, 0 },

    { njt_string("X-Accel-Buffering"),
                 njt_http_upstream_process_buffering, 0,
                 njt_http_upstream_copy_header_line, 0, 0 },

    { njt_string("X-Accel-Charset"),
                 njt_http_upstream_process_charset, 0,
                 njt_http_upstream_copy_header_line, 0, 0 },

    { njt_string("Transfer-Encoding"),
                 njt_http_upstream_process_transfer_encoding, 0,
                 njt_http_upstream_ignore_header_line, 0, 0 },

    { njt_string("Content-Encoding"),
                 njt_http_upstream_ignore_header_line, 0,
                 njt_http_upstream_copy_header_line,
                 offsetof(njt_http_headers_out_t, content_encoding), 0 },

    { njt_null_string, NULL, 0, NULL, 0, 0 }
};


static njt_command_t  njt_http_upstream_commands[] = {

    { njt_string("upstream"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_BLOCK|NJT_CONF_TAKE1,
      njt_http_upstream,
      0,
      0,
      NULL },
/* by zyg.  add njt_http_upstream_dynamic_servers.c
    { njt_string("server"),
      NJT_HTTP_UPS_CONF|NJT_CONF_1MORE,
      njt_http_upstream_server,
      NJT_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },
*/
      njt_null_command
};


static njt_http_module_t  njt_http_upstream_module_ctx = {
    njt_http_upstream_add_variables,       /* preconfiguration */
    NULL,                                  /* postconfiguration */

    njt_http_upstream_create_main_conf,    /* create main configuration */
    njt_http_upstream_init_main_conf,      /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


njt_module_t  njt_http_upstream_module = {
    NJT_MODULE_V1,
    &njt_http_upstream_module_ctx,         /* module context */
    njt_http_upstream_commands,            /* module directives */
    NJT_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};


static njt_http_variable_t  njt_http_upstream_vars[] = {

    { njt_string("upstream_addr"), NULL,
      njt_http_upstream_addr_variable, 0,
      NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("upstream_status"), NULL,
      njt_http_upstream_status_variable, 0,
      NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("upstream_connect_time"), NULL,
      njt_http_upstream_response_time_variable, 2,
      NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("upstream_header_time"), NULL,
      njt_http_upstream_response_time_variable, 1,
      NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("upstream_response_time"), NULL,
      njt_http_upstream_response_time_variable, 0,
      NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("upstream_response_length"), NULL,
      njt_http_upstream_response_length_variable, 0,
      NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("upstream_bytes_received"), NULL,
      njt_http_upstream_response_length_variable, 1,
      NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("upstream_bytes_sent"), NULL,
      njt_http_upstream_response_length_variable, 2,
      NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

#if (NJT_HTTP_CACHE)

    { njt_string("upstream_cache_status"), NULL,
      njt_http_upstream_cache_status, 0,
      NJT_HTTP_VAR_NOCACHEABLE, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("upstream_cache_last_modified"), NULL,
      njt_http_upstream_cache_last_modified, 0,
      NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_NOHASH, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("upstream_cache_etag"), NULL,
      njt_http_upstream_cache_etag, 0,
      NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_NOHASH, 0, NJT_VAR_INIT_REF_COUNT },

#endif

    { njt_string("upstream_http_"), NULL, njt_http_upstream_header_variable,
      0, NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_PREFIX, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("upstream_trailer_"), NULL, njt_http_upstream_trailer_variable,
      0, NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_PREFIX, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("upstream_cookie_"), NULL, njt_http_upstream_cookie_variable,
      0, NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_PREFIX, 0, NJT_VAR_INIT_REF_COUNT },

      njt_http_null_variable
};


static njt_http_upstream_next_t  njt_http_upstream_next_errors[] = {
    { 500, NJT_HTTP_UPSTREAM_FT_HTTP_500 },
    { 502, NJT_HTTP_UPSTREAM_FT_HTTP_502 },
    { 503, NJT_HTTP_UPSTREAM_FT_HTTP_503 },
    { 504, NJT_HTTP_UPSTREAM_FT_HTTP_504 },
    { 403, NJT_HTTP_UPSTREAM_FT_HTTP_403 },
    { 404, NJT_HTTP_UPSTREAM_FT_HTTP_404 },
    { 429, NJT_HTTP_UPSTREAM_FT_HTTP_429 },
    { 0, 0 }
};


njt_conf_bitmask_t  njt_http_upstream_cache_method_mask[] = {
    { njt_string("GET"), NJT_HTTP_GET },
    { njt_string("HEAD"), NJT_HTTP_HEAD },
    { njt_string("POST"), NJT_HTTP_POST },
    { njt_null_string, 0 }
};


njt_conf_bitmask_t  njt_http_upstream_ignore_headers_masks[] = {
    { njt_string("X-Accel-Redirect"), NJT_HTTP_UPSTREAM_IGN_XA_REDIRECT },
    { njt_string("X-Accel-Expires"), NJT_HTTP_UPSTREAM_IGN_XA_EXPIRES },
    { njt_string("X-Accel-Limit-Rate"), NJT_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE },
    { njt_string("X-Accel-Buffering"), NJT_HTTP_UPSTREAM_IGN_XA_BUFFERING },
    { njt_string("X-Accel-Charset"), NJT_HTTP_UPSTREAM_IGN_XA_CHARSET },
    { njt_string("Expires"), NJT_HTTP_UPSTREAM_IGN_EXPIRES },
    { njt_string("Cache-Control"), NJT_HTTP_UPSTREAM_IGN_CACHE_CONTROL },
    { njt_string("Set-Cookie"), NJT_HTTP_UPSTREAM_IGN_SET_COOKIE },
    { njt_string("Vary"), NJT_HTTP_UPSTREAM_IGN_VARY },
    { njt_null_string, 0 }
};


njt_int_t
njt_http_upstream_create(njt_http_request_t *r)
{
    njt_http_upstream_t  *u;

    u = r->upstream;

    if (u && u->cleanup) {
        r->main->count++;
        njt_http_upstream_cleanup(r);
    }

    u = njt_pcalloc(r->pool, sizeof(njt_http_upstream_t));
    if (u == NULL) {
        return NJT_ERROR;
    }

    r->upstream = u;

    u->peer.log = r->connection->log;
    u->peer.log_error = NJT_ERROR_ERR;

#if (NJT_HTTP_CACHE)
    r->cache = NULL;
#endif

    u->headers_in.content_length_n = -1;
    u->headers_in.last_modified_time = -1;

    return NJT_OK;
}


void
njt_http_upstream_init(njt_http_request_t *r)
{
    njt_connection_t     *c;
    njt_http_upstream_t  *u; // openresty patch

    c = r->connection;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http init upstream, client timer: %d", c->read->timer_set);

    // openresty patch
    u = r->upstream;

    u->connect_timeout = u->conf->connect_timeout;
    u->send_timeout = u->conf->send_timeout;
    u->read_timeout = u->conf->read_timeout;
    // openresty patch end

#if (NJT_HTTP_V2)
    if (r->stream) {
        njt_http_upstream_init_request(r);
        return;
    }
#endif

#if (NJT_HTTP_V3)
    if (c->quic) {
        njt_http_upstream_init_request(r);
        return;
    }
#endif

    if (c->read->timer_set) {
        njt_del_timer(c->read);
    }

    if (njt_event_flags & NJT_USE_CLEAR_EVENT) {

        if (!c->write->active) {
            if (njt_add_event(c->write, NJT_WRITE_EVENT, NJT_CLEAR_EVENT)
                == NJT_ERROR)
            {
                njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
        }
    }

    njt_http_upstream_init_request(r);
}


static void
njt_http_upstream_init_request(njt_http_request_t *r)
{
    njt_str_t                      *host;
    njt_uint_t                      i;
    njt_resolver_ctx_t             *ctx, temp;
    njt_http_cleanup_t             *cln;
    njt_http_upstream_t            *u;
    njt_http_core_loc_conf_t       *clcf;
    njt_http_upstream_srv_conf_t   *uscf, **uscfp;
    njt_http_upstream_main_conf_t  *umcf;
    njt_time_t                     *tp;
    njt_msec_int_t                  ms;

    if (r->aio) {
        return;
    }

    u = r->upstream;
    njt_time_update();
    tp = njt_timeofday();
    ms = (njt_msec_int_t) ((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));
    u->req_delay = njt_max(ms, 0);

#if (NJT_HTTP_CACHE)

    if (u->conf->cache) {
        njt_int_t  rc;

        rc = njt_http_upstream_cache(r, u);

        if (rc == NJT_BUSY) {
            r->write_event_handler = njt_http_upstream_init_request;
            return;
        }

        r->write_event_handler = njt_http_request_empty_handler;

        if (rc == NJT_ERROR) {
            njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        if (rc == NJT_OK) {
            rc = njt_http_upstream_cache_send(r, u);

            if (rc == NJT_DONE) {
                return;
            }

            if (rc == NJT_HTTP_UPSTREAM_INVALID_HEADER) {
                rc = NJT_DECLINED;
                r->cached = 0;
                u->buffer.start = NULL;
                u->cache_status = NJT_HTTP_CACHE_MISS;
                u->request_sent = 1;
            }
        }

        if (rc != NJT_DECLINED) {
            njt_http_finalize_request(r, rc);
            return;
        }
    }

#endif

    u->store = u->conf->store;

    if (!u->store && !r->post_action && !u->conf->ignore_client_abort) {

        if (r->connection->read->ready) {
            njt_post_event(r->connection->read, &njt_posted_events);

        } else {
            if (njt_handle_read_event(r->connection->read, 0) != NJT_OK) {
                njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
        }

        r->read_event_handler = njt_http_upstream_rd_check_broken_connection;
        r->write_event_handler = njt_http_upstream_wr_check_broken_connection;
    }

    if (r->request_body) {
        u->request_bufs = r->request_body->bufs;
    }
    if (u->create_request(r) != NJT_OK) {
        njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (njt_http_upstream_set_local(r, u, u->conf->local) != NJT_OK) {
        njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (u->conf->socket_keepalive) {
        u->peer.so_keepalive = 1;
    }

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    u->output.alignment = clcf->directio_alignment;
    u->output.pool = r->pool;
    u->output.bufs.num = 1;
    u->output.bufs.size = clcf->client_body_buffer_size;

    if (u->output.output_filter == NULL) {
        u->output.output_filter = njt_chain_writer;
        u->output.filter_ctx = &u->writer;
    }

    u->writer.pool = r->pool;

    if (r->upstream_states == NULL) {

        r->upstream_states = njt_array_create(r->pool, 1,
                                            sizeof(njt_http_upstream_state_t));
        if (r->upstream_states == NULL) {
            njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

    } else {

        u->state = njt_array_push(r->upstream_states);
        if (u->state == NULL) {
            njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        njt_memzero(u->state, sizeof(njt_http_upstream_state_t));
    }

    cln = njt_http_cleanup_add(r, 0);
    if (cln == NULL) {
        njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    cln->handler = njt_http_upstream_cleanup;
    cln->data = r;
    u->cleanup = &cln->handler;

    if (u->resolved == NULL) {

        uscf = u->conf->upstream;

    } else {

#if (NJT_HTTP_SSL)
        u->ssl_name = u->resolved->host;
#endif

        host = &u->resolved->host;

        umcf = njt_http_get_module_main_conf(r, njt_http_upstream_module);

        uscfp = umcf->upstreams.elts;

        for (i = 0; i < umcf->upstreams.nelts; i++) {

            uscf = uscfp[i];

            if (uscf->host.len == host->len
                && ((uscf->port == 0 && u->resolved->no_port)
                     || uscf->port == u->resolved->port)
                && njt_strncasecmp(uscf->host.data, host->data, host->len) == 0)
            {
                goto found;
            }
        }

        if (u->resolved->sockaddr) {

            if (u->resolved->port == 0
                && u->resolved->sockaddr->sa_family != AF_UNIX)
            {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "no port in upstream \"%V\"", host);
                njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            if (njt_http_upstream_create_round_robin_peer(r, u->resolved)
                != NJT_OK)
            {
                njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            njt_http_upstream_connect(r, u);

            return;
        }

        if (u->resolved->port == 0) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "no port in upstream \"%V\"", host);
            njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        temp.name = *host;

        ctx = njt_resolve_start(clcf->resolver, &temp);
        if (ctx == NULL) {
            njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        if (ctx == NJT_NO_RESOLVER) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "no resolver defined to resolve %V", host);

            njt_http_upstream_finalize_request(r, u, NJT_HTTP_BAD_GATEWAY);
            return;
        }

        ctx->name = *host;
        ctx->handler = njt_http_upstream_resolve_handler;
        ctx->data = r;
        ctx->timeout = clcf->resolver_timeout;

        u->resolved->ctx = ctx;

        if (njt_resolve_name(ctx) != NJT_OK) {
            u->resolved->ctx = NULL;
            njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        return;
    }

found:

    if (uscf == NULL) {
        njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
                      "no upstream configuration");
        njt_http_upstream_finalize_request(r, u,
                                           NJT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->upstream = uscf;

#if (NJT_HTTP_SSL)
    u->ssl_name = uscf->host;
#endif

    if (uscf->peer.init(r, uscf) != NJT_OK) {
        njt_http_upstream_finalize_request(r, u,
                                           NJT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->peer.start_time = njt_current_msec;

    if (u->conf->next_upstream_tries
        && u->peer.tries > u->conf->next_upstream_tries)
    {
        u->peer.tries = u->conf->next_upstream_tries;
    }

    njt_http_upstream_connect(r, u);
}

#if (NJT_HTTP_CACHE)

static njt_int_t
njt_http_upstream_cache(njt_http_request_t *r, njt_http_upstream_t *u)
{
    njt_int_t               rc;
    njt_http_cache_t       *c;
    njt_http_file_cache_t  *cache;

    c = r->cache;

    if (c == NULL) {
        
        // by chengxu
#if (NJT_HTTP_CACHE_PURGE)
        njt_http_cache_t       *old_c;
        
        old_c = c = r->cache;
        rc = njt_http_upstream_cache_get(r, u, &cache);

        if (rc != NJT_OK) {
            return rc;
        }

        if (r->method == NJT_HTTP_HEAD && u->conf->cache_convert_head) {
            u->method = njt_http_core_get_method;
        }

        if (njt_http_file_cache_new(r) != NJT_OK) {
            return NJT_ERROR;
        }

        //生成key
        if (u->create_key(r) != NJT_OK) {
            return NJT_ERROR;
        }

        njt_http_file_cache_create_key(r);
        njt_http_file_cache_set_request_key(r);

        if (r->cache->header_start + 256 > u->conf->buffer_size) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "%V_buffer_size %uz is not enough for cache key, "
                          "it should be increased to at least %uz",
                          &u->conf->module, u->conf->buffer_size,
                          njt_align(r->cache->header_start + 256, 1024));

            r->cache = NULL;
            return NJT_DECLINED;
        }
        // cx修改该赋值流程，解决置purged状态位的问题
        c = r->cache;

        c->body_start = u->conf->buffer_size;
        c->min_uses = u->conf->cache_min_uses;
        c->file_cache = cache;
        // end

        rc = njt_http_cache_purge_filter(r);
        if (rc != NJT_OK){
            if(rc == NJT_DONE){
                return rc;
            }
            return NJT_ERROR;
        }
        // cx修改该判断流程，非purge后检查请求方式是否合法
        if(old_c == NULL) {
            if (!(r->method & u->conf->cache_methods)) {
                return NJT_DECLINED;
            }
        }
        u->cacheable = 1;
#else
        if (!(r->method & u->conf->cache_methods)) {
            return NJT_DECLINED;
        }

        rc = njt_http_upstream_cache_get(r, u, &cache);

        if (rc != NJT_OK) {
            return rc;
        }

        if (r->method == NJT_HTTP_HEAD && u->conf->cache_convert_head) {
            u->method = njt_http_core_get_method;
        }

        if (njt_http_file_cache_new(r) != NJT_OK) {
            return NJT_ERROR;
        }

        if (u->create_key(r) != NJT_OK) {
            return NJT_ERROR;
        }

        /* TODO: add keys */

        njt_http_file_cache_create_key(r);

        if (r->cache->header_start + 256 > u->conf->buffer_size) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "%V_buffer_size %uz is not enough for cache key, "
                          "it should be increased to at least %uz",
                          &u->conf->module, u->conf->buffer_size,
                          njt_align(r->cache->header_start + 256, 1024));

            r->cache = NULL;
            return NJT_DECLINED;
        }

        u->cacheable = 1;

        c = r->cache;

        c->body_start = u->conf->buffer_size;
        c->min_uses = u->conf->cache_min_uses;
        c->file_cache = cache;
#endif
        // end

        switch (njt_http_test_predicates(r, u->conf->cache_bypass)) {

        case NJT_ERROR:
            return NJT_ERROR;

        case NJT_DECLINED:
            u->cache_status = NJT_HTTP_CACHE_BYPASS;
            return NJT_DECLINED;

        default: /* NJT_OK */
            break;
        }

        c->lock = u->conf->cache_lock;
        c->lock_timeout = u->conf->cache_lock_timeout;
        c->lock_age = u->conf->cache_lock_age;

        u->cache_status = NJT_HTTP_CACHE_MISS;
    }

    rc = njt_http_file_cache_open(r);

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream cache: %i", rc);

    switch (rc) {

    case NJT_HTTP_CACHE_STALE:

        if (((u->conf->cache_use_stale & NJT_HTTP_UPSTREAM_FT_UPDATING)
             || c->stale_updating) && !r->background
            && u->conf->cache_background_update)
        {
            if (njt_http_upstream_cache_background_update(r, u) == NJT_OK) {
                r->cache->background = 1;
                u->cache_status = rc;
                rc = NJT_OK;

            } else {
                rc = NJT_ERROR;
            }
        }

        break;

    case NJT_HTTP_CACHE_UPDATING:

        if (((u->conf->cache_use_stale & NJT_HTTP_UPSTREAM_FT_UPDATING)
             || c->stale_updating) && !r->background)
        {
            u->cache_status = rc;
            rc = NJT_OK;

        } else {
            rc = NJT_HTTP_CACHE_STALE;
        }

        break;

    case NJT_OK:
        u->cache_status = NJT_HTTP_CACHE_HIT;
    }

    switch (rc) {

    case NJT_OK:

        return NJT_OK;

    case NJT_HTTP_CACHE_STALE:

        c->valid_sec = 0;
        c->updating_sec = 0;
        c->error_sec = 0;

        u->buffer.start = NULL;
        u->cache_status = NJT_HTTP_CACHE_EXPIRED;

        break;

    case NJT_DECLINED:

        if ((size_t) (u->buffer.end - u->buffer.start) < u->conf->buffer_size) {
            u->buffer.start = NULL;

        } else {
            u->buffer.pos = u->buffer.start + c->header_start;
            u->buffer.last = u->buffer.pos;
        }

        break;

    case NJT_HTTP_CACHE_SCARCE:

        u->cacheable = 0;

        break;

    case NJT_AGAIN:

        return NJT_BUSY;

    case NJT_ERROR:

        return NJT_ERROR;

    default:

        /* cached NJT_HTTP_BAD_GATEWAY, NJT_HTTP_GATEWAY_TIME_OUT, etc. */

        u->cache_status = NJT_HTTP_CACHE_HIT;

        return rc;
    }

    if (njt_http_upstream_cache_check_range(r, u) == NJT_DECLINED) {
        u->cacheable = 0;
    }

    r->cached = 0;

    return NJT_DECLINED;
}


static njt_int_t
njt_http_upstream_cache_get(njt_http_request_t *r, njt_http_upstream_t *u,
    njt_http_file_cache_t **cache)
{
    njt_str_t               *name, val;
    njt_uint_t               i;
    njt_http_file_cache_t  **caches;

    if (u->conf->cache_zone) {
        *cache = u->conf->cache_zone->data;
        return NJT_OK;
    }

    if (njt_http_complex_value(r, u->conf->cache_value, &val) != NJT_OK) {
        return NJT_ERROR;
    }

    if (val.len == 0
        || (val.len == 3 && njt_strncmp(val.data, "off", 3) == 0))
    {
        return NJT_DECLINED;
    }

    caches = u->caches->elts;

    for (i = 0; i < u->caches->nelts; i++) {
        name = &caches[i]->shm_zone->shm.name;

        if (name->len == val.len
            && njt_strncmp(name->data, val.data, val.len) == 0)
        {
            *cache = caches[i];
            return NJT_OK;
        }
    }

    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                  "cache \"%V\" not found", &val);

    return NJT_ERROR;
}


static njt_int_t
njt_http_upstream_cache_send(njt_http_request_t *r, njt_http_upstream_t *u)
{
    njt_int_t          rc;
    njt_http_cache_t  *c;

    r->cached = 1;
    c = r->cache;

    if (c->header_start == c->body_start) {
        r->http_version = NJT_HTTP_VERSION_9;
        return njt_http_cache_send(r);
    }

    /* TODO: cache stack */

    u->buffer = *c->buf;
    u->buffer.pos += c->header_start;

    njt_memzero(&u->headers_in, sizeof(njt_http_upstream_headers_in_t));
    u->headers_in.content_length_n = -1;
    u->headers_in.last_modified_time = -1;

    if (njt_list_init(&u->headers_in.headers, r->pool, 8,
                      sizeof(njt_table_elt_t))
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    if (njt_list_init(&u->headers_in.trailers, r->pool, 2,
                      sizeof(njt_table_elt_t))
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    rc = u->process_header(r);

    if (rc == NJT_OK) {

        if (njt_http_upstream_process_headers(r, u) != NJT_OK) {
            return NJT_DONE;
        }

        return njt_http_cache_send(r);
    }

    if (rc == NJT_ERROR) {
        return NJT_ERROR;
    }

    if (rc == NJT_AGAIN) {
        rc = NJT_HTTP_UPSTREAM_INVALID_HEADER;
    }

    /* rc == NJT_HTTP_UPSTREAM_INVALID_HEADER */

    njt_log_error(NJT_LOG_CRIT, r->connection->log, 0,
                  "cache file \"%s\" contains invalid header",
                  c->file.name.data);

    /* TODO: delete file */

    return rc;
}


static njt_int_t
njt_http_upstream_cache_background_update(njt_http_request_t *r,
    njt_http_upstream_t *u)
{
    njt_http_request_t  *sr;

    if (r == r->main) {
        r->preserve_body = 1;
    }

    if (njt_http_subrequest(r, &r->uri, &r->args, &sr, NULL,
                            NJT_HTTP_SUBREQUEST_CLONE
                            |NJT_HTTP_SUBREQUEST_BACKGROUND)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    sr->header_only = 1;

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_cache_check_range(njt_http_request_t *r,
    njt_http_upstream_t *u)
{
    off_t             offset;
    u_char           *p, *start;
    njt_table_elt_t  *h;

    h = r->headers_in.range;

    if (h == NULL
        || !u->cacheable
        || u->conf->cache_max_range_offset == NJT_MAX_OFF_T_VALUE)
    {
        return NJT_OK;
    }

    if (u->conf->cache_max_range_offset == 0) {
        return NJT_DECLINED;
    }

    if (h->value.len < 7
        || njt_strncasecmp(h->value.data, (u_char *) "bytes=", 6) != 0)
    {
        return NJT_OK;
    }

    p = h->value.data + 6;

    while (*p == ' ') { p++; }

    if (*p == '-') {
        return NJT_DECLINED;
    }

    start = p;

    while (*p >= '0' && *p <= '9') { p++; }

    offset = njt_atoof(start, p - start);

    if (offset >= u->conf->cache_max_range_offset) {
        return NJT_DECLINED;
    }

    return NJT_OK;
}

#endif


static void
njt_http_upstream_resolve_handler(njt_resolver_ctx_t *ctx)
{
    njt_uint_t                     run_posted;
    njt_connection_t              *c;
    njt_http_request_t            *r;
    njt_http_upstream_t           *u;
    njt_http_upstream_resolved_t  *ur;

    run_posted = ctx->async;

    r = ctx->data;
    c = r->connection;

    u = r->upstream;
    ur = u->resolved;

    njt_http_set_log_request(c->log, r);

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream resolve: \"%V?%V\"", &r->uri, &r->args);

    if (ctx->state) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &ctx->name, ctx->state,
                      njt_resolver_strerror(ctx->state));

        njt_http_upstream_finalize_request(r, u, NJT_HTTP_BAD_GATEWAY);
        goto failed;
    }

    ur->naddrs = ctx->naddrs;
    ur->addrs = ctx->addrs;

#if (NJT_DEBUG)
    {
    u_char      text[NJT_SOCKADDR_STRLEN];
    njt_str_t   addr;
    njt_uint_t  i;

    addr.data = text;

    for (i = 0; i < ctx->naddrs; i++) {
        addr.len = njt_sock_ntop(ur->addrs[i].sockaddr, ur->addrs[i].socklen,
                                 text, NJT_SOCKADDR_STRLEN, 0);

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "name was resolved to %V", &addr);
    }
    }
#endif

    if (njt_http_upstream_create_round_robin_peer(r, ur) != NJT_OK) {
        njt_http_upstream_finalize_request(r, u,
                                           NJT_HTTP_INTERNAL_SERVER_ERROR);
        goto failed;
    }

    njt_resolve_name_done(ctx);
    ur->ctx = NULL;

    u->peer.start_time = njt_current_msec;

    if (u->conf->next_upstream_tries
        && u->peer.tries > u->conf->next_upstream_tries)
    {
        u->peer.tries = u->conf->next_upstream_tries;
    }

    njt_http_upstream_connect(r, u);

failed:

    if (run_posted) {
        njt_http_run_posted_requests(c);
    }
}


 void
njt_http_upstream_handler(njt_event_t *ev)
{
    njt_connection_t     *c;
    njt_http_request_t   *r;
    njt_http_upstream_t  *u;

    c = ev->data;
    r = c->data;

    u = r->upstream;
    c = r->connection;

    njt_http_set_log_request(c->log, r);

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream request: \"%V?%V\"", &r->uri, &r->args);

    if (ev->delayed && ev->timedout) {
        ev->delayed = 0;
        ev->timedout = 0;
    }

    if (ev->write) {
        u->write_event_handler(r, u);

    } else {
        u->read_event_handler(r, u);
    }

    njt_http_run_posted_requests(c);
}


static void
njt_http_upstream_rd_check_broken_connection(njt_http_request_t *r)
{
    njt_http_upstream_check_broken_connection(r, r->connection->read);
}


static void
njt_http_upstream_wr_check_broken_connection(njt_http_request_t *r)
{
    njt_http_upstream_check_broken_connection(r, r->connection->write);
}


static void
njt_http_upstream_check_broken_connection(njt_http_request_t *r,
    njt_event_t *ev)
{
    int                  n;
    char                 buf[1];
    njt_err_t            err;
    njt_int_t            event;
    njt_connection_t     *c;
    njt_http_upstream_t  *u;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, ev->log, 0,
                   "http upstream check client, write event:%d, \"%V\"",
                   ev->write, &r->uri);

    c = r->connection;
    u = r->upstream;

    if (c->error) {
        if ((njt_event_flags & NJT_USE_LEVEL_EVENT) && ev->active) {

            event = ev->write ? NJT_WRITE_EVENT : NJT_READ_EVENT;

            if (njt_del_event(ev, event, 0) != NJT_OK) {
                njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
        }

        if (!u->cacheable) {
            njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_CLIENT_CLOSED_REQUEST);
        }

        return;
    }

#if (NJT_HTTP_V2)
    if (r->stream) {
        return;
    }
#endif

#if (NJT_HTTP_V3)

    if (c->quic) {
        if (c->write->error) {
            njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_CLIENT_CLOSED_REQUEST);
        }

        return;
    }

#endif

#if (NJT_HAVE_KQUEUE)

    if (njt_event_flags & NJT_USE_KQUEUE_EVENT) {

        if (!ev->pending_eof) {
            return;
        }

        ev->eof = 1;
        c->error = 1;

        if (ev->kq_errno) {
            ev->error = 1;
        }

        if (!u->cacheable && u->peer.connection) {
            njt_log_error(NJT_LOG_INFO, ev->log, ev->kq_errno,
                          "kevent() reported that client prematurely closed "
                          "connection, so upstream connection is closed too");
            njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_CLIENT_CLOSED_REQUEST);
            return;
        }

        njt_log_error(NJT_LOG_INFO, ev->log, ev->kq_errno,
                      "kevent() reported that client prematurely closed "
                      "connection");

        if (u->peer.connection == NULL) {
            njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_CLIENT_CLOSED_REQUEST);
        }

        return;
    }

#endif

#if (NJT_HAVE_EPOLLRDHUP)

    if ((njt_event_flags & NJT_USE_EPOLL_EVENT) && njt_use_epoll_rdhup) {
        socklen_t  len;

        if (!ev->pending_eof) {
            return;
        }

        ev->eof = 1;
        c->error = 1;

        err = 0;
        len = sizeof(njt_err_t);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = njt_socket_errno;
        }

        if (err) {
            ev->error = 1;
        }

        if (!u->cacheable && u->peer.connection) {
            njt_log_error(NJT_LOG_INFO, ev->log, err,
                        "epoll_wait() reported that client prematurely closed "
                        "connection, so upstream connection is closed too");
            njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_CLIENT_CLOSED_REQUEST);
            return;
        }

        njt_log_error(NJT_LOG_INFO, ev->log, err,
                      "epoll_wait() reported that client prematurely closed "
                      "connection");

        if (u->peer.connection == NULL) {
            njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_CLIENT_CLOSED_REQUEST);
        }

        return;
    }

#endif

    n = recv(c->fd, buf, 1, MSG_PEEK);

    err = njt_socket_errno;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, ev->log, err,
                   "http upstream recv(): %d", n);

    if (ev->write && (n >= 0 || err == NJT_EAGAIN)) {
        return;
    }

    if ((njt_event_flags & NJT_USE_LEVEL_EVENT) && ev->active) {

        event = ev->write ? NJT_WRITE_EVENT : NJT_READ_EVENT;

        if (njt_del_event(ev, event, 0) != NJT_OK) {
            njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (n > 0) {
        return;
    }

    if (n == -1) {
        if (err == NJT_EAGAIN) {
            return;
        }

        ev->error = 1;

    } else { /* n == 0 */
        err = 0;
    }

    ev->eof = 1;
    c->error = 1;

    if (!u->cacheable && u->peer.connection) {
        njt_log_error(NJT_LOG_INFO, ev->log, err,
                      "client prematurely closed connection, "
                      "so upstream connection is closed too");
        njt_http_upstream_finalize_request(r, u,
                                           NJT_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }

    njt_log_error(NJT_LOG_INFO, ev->log, err,
                  "client prematurely closed connection");

    if (u->peer.connection == NULL) {
        njt_http_upstream_finalize_request(r, u,
                                           NJT_HTTP_CLIENT_CLOSED_REQUEST);
    }
}


static void
njt_http_upstream_connect(njt_http_request_t *r, njt_http_upstream_t *u)
{
    njt_int_t                  rc;
    njt_connection_t          *c;
    njt_http_core_loc_conf_t  *clcf;

	
    r->connection->log->action = "connecting to upstream";

    if (u->state && u->state->response_time == (njt_msec_t) -1) {
        u->state->response_time = njt_current_msec - u->start_time;
    }

    u->state = njt_array_push(r->upstream_states);
    if (u->state == NULL) {
        njt_http_upstream_finalize_request(r, u,
                                           NJT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    njt_memzero(u->state, sizeof(njt_http_upstream_state_t));

    u->start_time = njt_current_msec;

    u->state->response_time = (njt_msec_t) -1;
    u->state->connect_time = (njt_msec_t) -1;
    u->state->header_time = (njt_msec_t) -1;

    rc = njt_event_connect_peer(&u->peer);
	
    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream connect: %i", rc);

    if (rc == NJT_ERROR) {
        njt_http_upstream_finalize_request(r, u,
                                           NJT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->state->peer = u->peer.name;

    if (rc == NJT_BUSY) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "no live upstreams");
        njt_http_upstream_next(r, u, NJT_HTTP_UPSTREAM_FT_NOLIVE);
        return;
    }

    if (rc == NJT_DECLINED) {
        njt_http_upstream_next(r, u, NJT_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    /* rc == NJT_OK || rc == NJT_AGAIN || rc == NJT_DONE */
	/*
    if (u->create_request(r) != NJT_OK) {
        njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }*/

    c = u->peer.connection;

    c->requests++;

    c->data = r;

    c->write->handler = njt_http_upstream_handler;
    c->read->handler = njt_http_upstream_handler;

    u->write_event_handler = njt_http_upstream_send_request_handler;
    u->read_event_handler = njt_http_upstream_process_header;

    c->sendfile &= r->connection->sendfile;
    u->output.sendfile = c->sendfile;

    if (r->connection->tcp_nopush == NJT_TCP_NOPUSH_DISABLED) {
        c->tcp_nopush = NJT_TCP_NOPUSH_DISABLED;
    }

    if (c->pool == NULL) {

        /* we need separate pool here to be able to cache SSL connections */

        c->pool = njt_create_pool(128, r->connection->log);
        if (c->pool == NULL) {
            njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    c->log = r->connection->log;
    c->pool->log = c->log;
    c->read->log = c->log;
    c->write->log = c->log;

    /* init or reinit the njt_output_chain() and njt_chain_writer() contexts */

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    u->writer.out = NULL;
    u->writer.last = &u->writer.out;
    u->writer.connection = c;
    u->writer.limit = clcf->sendfile_max_chunk;

    if (u->request_sent) {
        if (njt_http_upstream_reinit(r, u) != NJT_OK) {
            njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (r->request_body
        && r->request_body->buf
        && r->request_body->temp_file
        && r == r->main)
    {
        /*
         * the r->request_body->buf can be reused for one request only,
         * the subrequests should allocate their own temporary bufs
         */

        u->output.free = njt_alloc_chain_link(r->pool);
        if (u->output.free == NULL) {
            njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        u->output.free->buf = r->request_body->buf;
        u->output.free->next = NULL;
        u->output.allocated = 1;

        r->request_body->buf->pos = r->request_body->buf->start;
        r->request_body->buf->last = r->request_body->buf->start;
        r->request_body->buf->tag = u->output.tag;
    }

    u->request_sent = 0;
    u->request_body_sent = 0;
    u->request_body_blocked = 0;

    if (rc == NJT_AGAIN) {
        // njt_add_timer(c->write, u->conf->connect_timeout); openresty patch
        njt_add_timer(c->write, u->connect_timeout); // openresty patch
        return;
    }

#if (NJT_HTTP_SSL)

    if (u->ssl && c->ssl == NULL) {
        njt_http_upstream_ssl_init_connection(r, u, c);
        return;
    }

#endif

    njt_http_upstream_send_request(r, u, 1);
}


#if (NJT_HTTP_SSL)

static void
njt_http_upstream_ssl_init_connection(njt_http_request_t *r,
    njt_http_upstream_t *u, njt_connection_t *c)
{
    njt_int_t                  rc;
    njt_http_core_loc_conf_t  *clcf;

    if (njt_http_upstream_test_connect(c) != NJT_OK) {
        njt_http_upstream_next(r, u, NJT_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

#if (NJT_HAVE_NTLS)
    if (u->conf->ssl_ntls) {

        SSL_CTX_set_ssl_version(u->conf->ssl->ctx, NTLS_method());
        SSL_CTX_set_cipher_list(u->conf->ssl->ctx,
                                (char *) u->conf->ssl_ciphers.data);
        SSL_CTX_enable_ntls(u->conf->ssl->ctx);
    }
#endif

    if (njt_ssl_create_connection(u->conf->ssl, c,
                                  NJT_SSL_BUFFER|NJT_SSL_CLIENT)
        != NJT_OK)
    {
        njt_http_upstream_finalize_request(r, u,
                                           NJT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (u->conf->ssl_server_name || u->conf->ssl_verify) {
        if (njt_http_upstream_ssl_name(r, u, c) != NJT_OK) {
            njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

#if (NJT_HTTP_MULTICERT)
    if (u->conf->ssl_certificate_values) {
        if (njt_http_upstream_ssl_certificates(r, u, c) != NJT_OK) {
            njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

    } else
#endif

    if (u->conf->ssl_certificate
        && u->conf->ssl_certificate->value.len
        && (u->conf->ssl_certificate->lengths
            || u->conf->ssl_certificate_key->lengths))
    {
        if (njt_http_upstream_ssl_certificate(r, u, c) != NJT_OK) {
            njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (u->conf->ssl_session_reuse) {
        c->ssl->save_session = njt_http_upstream_ssl_save_session;

        if (u->peer.set_session(&u->peer, u->peer.data) != NJT_OK) {
            njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        /* abbreviated SSL handshake may interact badly with Nagle */

        clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

        if (clcf->tcp_nodelay && njt_tcp_nodelay(c) != NJT_OK) {
            njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    r->connection->log->action = "SSL handshaking to upstream";

    rc = njt_ssl_handshake(c);

    if (rc == NJT_AGAIN) {

        if (!c->write->timer_set) {
            // njt_add_timer(c->write, u->conf->connect_timeout); openresty patch
            njt_add_timer(c->write, u->connect_timeout); // openresty patch
        }

        c->ssl->handler = njt_http_upstream_ssl_handshake_handler;
        return;
    }

    njt_http_upstream_ssl_handshake(r, u, c);
}


static void
njt_http_upstream_ssl_handshake_handler(njt_connection_t *c)
{
    njt_http_request_t   *r;
    njt_http_upstream_t  *u;

    r = c->data;

    u = r->upstream;
    c = r->connection;

    njt_http_set_log_request(c->log, r);

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream ssl handshake: \"%V?%V\"",
                   &r->uri, &r->args);

    njt_http_upstream_ssl_handshake(r, u, u->peer.connection);

    njt_http_run_posted_requests(c);
}


static void
njt_http_upstream_ssl_handshake(njt_http_request_t *r, njt_http_upstream_t *u,
    njt_connection_t *c)
{
    long  rc;

    if (c->ssl->handshaked) {

        if (u->conf->ssl_verify) {
            rc = SSL_get_verify_result(c->ssl->connection);

            if (rc != X509_V_OK) {
                njt_log_error(NJT_LOG_ERR, c->log, 0,
                              "upstream SSL certificate verify error: (%l:%s)",
                              rc, X509_verify_cert_error_string(rc));
                goto failed;
            }

            if (njt_ssl_check_host(c, &u->ssl_name) != NJT_OK) {
                njt_log_error(NJT_LOG_ERR, c->log, 0,
                              "upstream SSL certificate does not match \"%V\"",
                              &u->ssl_name);
                goto failed;
            }
        }

        if (!c->ssl->sendfile) {
            c->sendfile = 0;
            u->output.sendfile = 0;
        }

        c->write->handler = njt_http_upstream_handler;
        c->read->handler = njt_http_upstream_handler;

        njt_http_upstream_send_request(r, u, 1);

        return;
    }

    if (c->write->timedout) {
        njt_http_upstream_next(r, u, NJT_HTTP_UPSTREAM_FT_TIMEOUT);
        return;
    }

failed:

    njt_http_upstream_next(r, u, NJT_HTTP_UPSTREAM_FT_ERROR);
}


static void
njt_http_upstream_ssl_save_session(njt_connection_t *c)
{
    njt_http_request_t   *r;
    njt_http_upstream_t  *u;

    if (c->idle) {
        return;
    }

    r = c->data;

    u = r->upstream;
    c = r->connection;

    njt_http_set_log_request(c->log, r);

    u->peer.save_session(&u->peer, u->peer.data);
}


static njt_int_t
njt_http_upstream_ssl_name(njt_http_request_t *r, njt_http_upstream_t *u,
    njt_connection_t *c)
{
    u_char     *p, *last;
    njt_str_t   name;
    njt_str_t   uri;

    if (u->conf->ssl_name) {
        if (njt_http_complex_value(r, u->conf->ssl_name, &name) != NJT_OK) {
            return NJT_ERROR;
        }

    } else {
        name = u->ssl_name;
    }

    if (name.len == 0) {
        goto done;
    }

    /*
     * ssl name here may contain port, notably if derived from $proxy_host
     * or $http_host; we have to strip it
     */
    uri = name;
    p = name.data;
    last = name.data + name.len;

    if (*p == '[') {
        p = njt_strlchr(p, last, ']');

        if (p == NULL) {
            p = name.data;
        }
    }

    p = njt_strlchr(p, last, ':');

    if (p != NULL) {
        name.len = p - name.data;
    }

    if (!u->conf->ssl_server_name) {
        goto done;
    }

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

    /* as per RFC 6066, literal IPv4 and IPv6 addresses are not permitted */

    if (name.len == 0 || *name.data == '[') {
        goto done;
    }

    if (njt_inet_addr(name.data, name.len) != INADDR_NONE) {
        goto done;
    }

    /*
     * SSL_set_tlsext_host_name() needs a null-terminated string,
     * hence we explicitly null-terminate name here
     */

    p = njt_pnalloc(r->pool, name.len + 1);
    if (p == NULL) {
        return NJT_ERROR;
    }

    (void) njt_cpystrn(p, name.data, name.len + 1);

    name.data = p;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "upstream SSL server name: \"%s\"", name.data);

    if (SSL_set_tlsext_host_name(c->ssl->connection,
                                 (char *) name.data)
        == 0)
    {
        njt_ssl_error(NJT_LOG_ERR, r->connection->log, 0,
                      "SSL_set_tlsext_host_name(\"%s\") failed", name.data);
        return NJT_ERROR;
    }

#endif

done:
    if(njt_strncmp(uri.data, "spiffe://",9) == 0) {
    	u->ssl_name = uri;
    } else {
	u->ssl_name = name;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_ssl_certificate(njt_http_request_t *r,
    njt_http_upstream_t *u, njt_connection_t *c)
{
    njt_str_t  cert, key;

    if (njt_http_complex_value(r, u->conf->ssl_certificate, &cert)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream ssl cert: \"%s\"", cert.data);

    if (*cert.data == '\0') {
        return NJT_OK;
    }

    if (njt_http_complex_value(r, u->conf->ssl_certificate_key, &key)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream ssl key: \"%s\"", key.data);

    if (njt_ssl_connection_certificate(c, r->pool, &cert, &key,
                                       u->conf->ssl_passwords)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    return NJT_OK;
}

#if (NJT_HTTP_MULTICERT)

static njt_int_t
njt_http_upstream_ssl_certificates(njt_http_request_t *r,
    njt_http_upstream_t *u, njt_connection_t *c)
{
    njt_str_t                 *certp, *keyp, cert, key;
    njt_uint_t                 i, nelts;
    njt_http_complex_value_t  *certs, *keys;
#if (NJT_HAVE_NTLS)
    njt_str_t                  tcert, tkey;
#endif

    nelts = u->conf->ssl_certificate_values->nelts;
    certs = u->conf->ssl_certificate_values->elts;
    keys = u->conf->ssl_certificate_key_values->elts;

    for (i = 0; i < nelts; i++) {
        certp = &cert;
        keyp = &key;

        if (njt_http_complex_value(r, &certs[i], certp) != NJT_OK) {
            return NJT_ERROR;
        }

#if (NJT_HAVE_NTLS)
        tcert = *certp;
        njt_ssl_ntls_prefix_strip(&tcert);
        certp = &cert;
#endif

        if (*certp->data == 0) {
            continue;
        }

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http upstream ssl cert: \"%s\"", certp->data);

        if (njt_http_complex_value(r, &keys[i], keyp) != NJT_OK) {
            return NJT_ERROR;
        }

#if (NJT_HAVE_NTLS)
        tkey = *keyp;
        njt_ssl_ntls_prefix_strip(&tkey);
        keyp = &key;
#endif

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http upstream ssl key: \"%s\"", keyp->data);

        if (njt_ssl_connection_certificate(c, r->pool, certp, keyp,
                                           u->conf->ssl_passwords)
            != NJT_OK)
        {
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}

#endif

#endif


static njt_int_t
njt_http_upstream_reinit(njt_http_request_t *r, njt_http_upstream_t *u)
{
    off_t         file_pos;
    njt_chain_t  *cl;

    if (u->reinit_request(r) != NJT_OK) {
        return NJT_ERROR;
    }

    u->keepalive = 0;
    u->upgrade = 0;
    u->error = 0;

    njt_memzero(&u->headers_in, sizeof(njt_http_upstream_headers_in_t));
    u->headers_in.content_length_n = -1;
    u->headers_in.last_modified_time = -1;

    if (njt_list_init(&u->headers_in.headers, r->pool, 8,
                      sizeof(njt_table_elt_t))
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    if (njt_list_init(&u->headers_in.trailers, r->pool, 2,
                      sizeof(njt_table_elt_t))
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    /* reinit the request chain */

    file_pos = 0;

    for (cl = u->request_bufs; cl; cl = cl->next) {
        cl->buf->pos = cl->buf->start;

        /* there is at most one file */

        if (cl->buf->in_file) {
            cl->buf->file_pos = file_pos;
            file_pos = cl->buf->file_last;
        }
    }

    /* reinit the subrequest's njt_output_chain() context */

    if (r->request_body && r->request_body->temp_file
        && r != r->main && u->output.buf)
    {
        u->output.free = njt_alloc_chain_link(r->pool);
        if (u->output.free == NULL) {
            return NJT_ERROR;
        }

        u->output.free->buf = u->output.buf;
        u->output.free->next = NULL;

        u->output.buf->pos = u->output.buf->start;
        u->output.buf->last = u->output.buf->start;
    }

    u->output.buf = NULL;
    u->output.in = NULL;
    u->output.busy = NULL;

    /* reinit u->buffer */

    u->buffer.pos = u->buffer.start;

#if (NJT_HTTP_CACHE)

    if (r->cache) {
        u->buffer.pos += r->cache->header_start;
    }

#endif

    u->buffer.last = u->buffer.pos;

    return NJT_OK;
}


 void
njt_http_upstream_send_request(njt_http_request_t *r, njt_http_upstream_t *u,
    njt_uint_t do_write)
{
    njt_int_t          rc;
    njt_connection_t  *c;

    c = u->peer.connection;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream send request");

    if (u->state->connect_time == (njt_msec_t) -1) {
        u->state->connect_time = njt_current_msec - u->start_time;
    }

    if (!u->request_sent && njt_http_upstream_test_connect(c) != NJT_OK) {
        njt_http_upstream_next(r, u, NJT_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    c->log->action = "sending request to upstream";

    rc = njt_http_upstream_send_request_body(r, u, do_write);

    if (rc == NJT_ERROR) {
        njt_http_upstream_next(r, u, NJT_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    if (rc >= NJT_HTTP_SPECIAL_RESPONSE) {
        njt_http_upstream_finalize_request(r, u, rc);
        return;
    }

    if (rc == NJT_AGAIN) {
        if (!c->write->ready || u->request_body_blocked) {
            // njt_add_timer(c->write, u->conf->send_timeout); openresty patch
            njt_add_timer(c->write, u->send_timeout); // openresty patch

        } else if (c->write->timer_set) {
            njt_del_timer(c->write);
        }

        if (njt_handle_write_event(c->write, u->conf->send_lowat) != NJT_OK) {
            njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        if (c->write->ready && c->tcp_nopush == NJT_TCP_NOPUSH_SET) {
            if (njt_tcp_push(c->fd) == -1) {
                njt_log_error(NJT_LOG_CRIT, c->log, njt_socket_errno,
                              njt_tcp_push_n " failed");
                njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            c->tcp_nopush = NJT_TCP_NOPUSH_UNSET;
        }

        if (c->read->ready) {
            njt_post_event(c->read, &njt_posted_events);
        }

        return;
    }

    /* rc == NJT_OK */

    if (c->write->timer_set) {
        njt_del_timer(c->write);
    }

    if (c->tcp_nopush == NJT_TCP_NOPUSH_SET) {
        if (njt_tcp_push(c->fd) == -1) {
            njt_log_error(NJT_LOG_CRIT, c->log, njt_socket_errno,
                          njt_tcp_push_n " failed");
            njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        c->tcp_nopush = NJT_TCP_NOPUSH_UNSET;
    }

    if (!u->conf->preserve_output) {
        u->write_event_handler = njt_http_upstream_dummy_handler;
    }

    if (njt_handle_write_event(c->write, 0) != NJT_OK) {
        njt_http_upstream_finalize_request(r, u,
                                           NJT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (!u->request_body_sent) {
        u->request_body_sent = 1;

        if (u->header_sent) {
            return;
        }

        // njt_add_timer(c->read, u->conf->read_timeout); openresty patch
        njt_add_timer(c->read, u->read_timeout); // openresty patch

        if (c->read->ready) {
            njt_http_upstream_process_header(r, u);
            return;
        }
    }
}


static njt_int_t
njt_http_upstream_send_request_body(njt_http_request_t *r,
    njt_http_upstream_t *u, njt_uint_t do_write)
{
    njt_int_t                  rc;
    njt_chain_t               *out, *cl, *ln;
    njt_connection_t          *c;
    njt_http_core_loc_conf_t  *clcf;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream send request body");

    if (!r->request_body_no_buffering) {

        /* buffered request body */

        if (!u->request_sent) {
            u->request_sent = 1;
            out = u->request_bufs;

        } else {
            out = NULL;
        }

        rc = njt_output_chain(&u->output, out);

        if (rc == NJT_AGAIN) {
            u->request_body_blocked = 1;

        } else {
            u->request_body_blocked = 0;
        }

        return rc;
    }

    if (!u->request_sent) {
        u->request_sent = 1;
        out = u->request_bufs;

        if (r->request_body->bufs) {
            for (cl = out; cl->next; cl = cl->next) { /* void */ }
            cl->next = r->request_body->bufs;
            r->request_body->bufs = NULL;
        }

        c = u->peer.connection;
        clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

        if (clcf->tcp_nodelay && njt_tcp_nodelay(c) != NJT_OK) {
            return NJT_ERROR;
        }

        r->read_event_handler = njt_http_upstream_read_request_handler;

    } else {
        out = NULL;
    }

    for ( ;; ) {

        if (do_write) {
            rc = njt_output_chain(&u->output, out);

            if (rc == NJT_ERROR) {
                return NJT_ERROR;
            }

            while (out) {
                ln = out;
                out = out->next;
                njt_free_chain(r->pool, ln);
            }

            if (rc == NJT_AGAIN) {
                u->request_body_blocked = 1;

            } else {
                u->request_body_blocked = 0;
            }

            if (rc == NJT_OK && !r->reading_body) {
                break;
            }
        }

        if (r->reading_body) {
            /* read client request body */

            rc = njt_http_read_unbuffered_request_body(r);

            if (rc >= NJT_HTTP_SPECIAL_RESPONSE) {
                return rc;
            }

            out = r->request_body->bufs;
            r->request_body->bufs = NULL;
        }

        /* stop if there is nothing to send */

        if (out == NULL) {
            rc = NJT_AGAIN;
            break;
        }

        do_write = 1;
    }

    if (!r->reading_body) {
        if (!u->store && !r->post_action && !u->conf->ignore_client_abort) {
            r->read_event_handler =
                                  njt_http_upstream_rd_check_broken_connection;
        }
    }

    return rc;
}


 void
njt_http_upstream_send_request_handler(njt_http_request_t *r,
    njt_http_upstream_t *u)
{
    njt_connection_t  *c;

    c = u->peer.connection;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream send request handler");

    if (c->write->timedout) {
        njt_http_upstream_next(r, u, NJT_HTTP_UPSTREAM_FT_TIMEOUT);
        return;
    }

#if (NJT_HTTP_SSL)

    if (u->ssl && c->ssl == NULL) {
        njt_http_upstream_ssl_init_connection(r, u, c);
        return;
    }

#endif

    // if (u->header_sent && !u->conf->preserve_output) { // openresty patch
    if (u->request_body_sent && !u->conf->preserve_output) { // openresty patch
        u->write_event_handler = njt_http_upstream_dummy_handler;

        (void) njt_handle_write_event(c->write, 0);

        return;
    }

    njt_http_upstream_send_request(r, u, 1);
}


static void
njt_http_upstream_read_request_handler(njt_http_request_t *r)
{
    njt_connection_t     *c;
    njt_http_upstream_t  *u;

    c = r->connection;
    u = r->upstream;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream read request handler");

    if (c->read->timedout) {
        c->timedout = 1;
        njt_http_upstream_finalize_request(r, u, NJT_HTTP_REQUEST_TIME_OUT);
        return;
    }

    njt_http_upstream_send_request(r, u, 0);
}


 void
njt_http_upstream_process_header(njt_http_request_t *r, njt_http_upstream_t *u)
{
    ssize_t            n;
    njt_int_t          rc;
    njt_connection_t  *c;

    c = u->peer.connection;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process header");

    c->log->action = "reading response header from upstream";

    if (c->read->timedout) {
        njt_http_upstream_next(r, u, NJT_HTTP_UPSTREAM_FT_TIMEOUT);
        return;
    }

    if (!u->request_sent && njt_http_upstream_test_connect(c) != NJT_OK) {
        njt_http_upstream_next(r, u, NJT_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    if (u->buffer.start == NULL) {
        u->buffer.start = njt_palloc(r->pool, u->conf->buffer_size);
        if (u->buffer.start == NULL) {
            njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        u->buffer.pos = u->buffer.start;
        u->buffer.last = u->buffer.start;
        u->buffer.end = u->buffer.start + u->conf->buffer_size;
        u->buffer.temporary = 1;

        u->buffer.tag = u->output.tag;

        if (njt_list_init(&u->headers_in.headers, r->pool, 8,
                          sizeof(njt_table_elt_t))
            != NJT_OK)
        {
            njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        if (njt_list_init(&u->headers_in.trailers, r->pool, 2,
                          sizeof(njt_table_elt_t))
            != NJT_OK)
        {
            njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

#if (NJT_HTTP_CACHE)

        if (r->cache) {
            u->buffer.pos += r->cache->header_start;
            u->buffer.last = u->buffer.pos;
        }
#endif
    }

    for ( ;; ) {

        n = c->recv(c, u->buffer.last, u->buffer.end - u->buffer.last);

        if (n == NJT_AGAIN) {
#if 0
            njt_add_timer(rev, u->read_timeout);
#endif

            if (njt_handle_read_event(c->read, 0) != NJT_OK) {
                njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            return;
        }

        if (n == 0) {
            njt_log_error(NJT_LOG_ERR, c->log, 0,
                          "upstream prematurely closed connection");
        }

        if (n == NJT_ERROR || n == 0) {
            njt_http_upstream_next(r, u, NJT_HTTP_UPSTREAM_FT_ERROR);
            return;
        }

        u->state->bytes_received += n;

        u->buffer.last += n;

#if 0
        u->valid_header_in = 0;

        u->peer.cached = 0;
#endif

        rc = u->process_header(r);

        if (rc == NJT_AGAIN) {

            if (u->buffer.last == u->buffer.end) {
                njt_log_error(NJT_LOG_ERR, c->log, 0,
                              "upstream sent too big header");

                njt_http_upstream_next(r, u,
                                       NJT_HTTP_UPSTREAM_FT_INVALID_HEADER);
                return;
            }

            continue;
        }

        break;
    }

    if (rc == NJT_HTTP_UPSTREAM_INVALID_HEADER) {
        njt_http_upstream_next(r, u, NJT_HTTP_UPSTREAM_FT_INVALID_HEADER);
        return;
    }

    if (rc == NJT_ERROR) {
        njt_http_upstream_finalize_request(r, u,
                                           NJT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    /* rc == NJT_OK */

    u->state->header_time = njt_current_msec - u->start_time;

    if (u->headers_in.status_n >= NJT_HTTP_SPECIAL_RESPONSE) {

        if (njt_http_upstream_test_next(r, u) == NJT_OK) {
            return;
        }

        if (njt_http_upstream_intercept_errors(r, u) == NJT_OK) {
            return;
        }
    }

    if (njt_http_upstream_process_headers(r, u) != NJT_OK) {
        return;
    }

    njt_http_upstream_send_response(r, u);
}


static njt_int_t
njt_http_upstream_test_next(njt_http_request_t *r, njt_http_upstream_t *u)
{
    njt_msec_t                 timeout;
    njt_uint_t                 status, mask;
    njt_http_upstream_next_t  *un;

    status = u->headers_in.status_n;

    for (un = njt_http_upstream_next_errors; un->status; un++) {

        if (status != un->status) {
            continue;
        }

        timeout = u->conf->next_upstream_timeout;

        if (u->request_sent
            && (r->method & (NJT_HTTP_POST|NJT_HTTP_LOCK|NJT_HTTP_PATCH)))
        {
            mask = un->mask | NJT_HTTP_UPSTREAM_FT_NON_IDEMPOTENT;

        } else {
            mask = un->mask;
        }

        if (u->peer.tries > 1
            && ((u->conf->next_upstream & mask) == mask)
            && !(u->request_sent && r->request_body_no_buffering)
            && !(timeout && njt_current_msec - u->peer.start_time >= timeout))
        {
            njt_http_upstream_next(r, u, un->mask);
            return NJT_OK;
        }

#if (NJT_HTTP_CACHE)

        if (u->cache_status == NJT_HTTP_CACHE_EXPIRED
            && (u->conf->cache_use_stale & un->mask))
        {
            njt_int_t  rc;

            rc = u->reinit_request(r);

            if (rc != NJT_OK) {
                njt_http_upstream_finalize_request(r, u, rc);
                return NJT_OK;
            }

            u->cache_status = NJT_HTTP_CACHE_STALE;
            rc = njt_http_upstream_cache_send(r, u);

            if (rc == NJT_DONE) {
                return NJT_OK;
            }

            if (rc == NJT_HTTP_UPSTREAM_INVALID_HEADER) {
                rc = NJT_HTTP_INTERNAL_SERVER_ERROR;
            }

            njt_http_upstream_finalize_request(r, u, rc);
            return NJT_OK;
        }

#endif

        break;
    }

#if (NJT_HTTP_CACHE)

    if (status == NJT_HTTP_NOT_MODIFIED
        && u->cache_status == NJT_HTTP_CACHE_EXPIRED
        && u->conf->cache_revalidate)
    {
        time_t     now, valid, updating, error;
        njt_int_t  rc;

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http upstream not modified");

        now = njt_time();

        valid = r->cache->valid_sec;
        updating = r->cache->updating_sec;
        error = r->cache->error_sec;

        rc = u->reinit_request(r);

        if (rc != NJT_OK) {
            njt_http_upstream_finalize_request(r, u, rc);
            return NJT_OK;
        }

        u->cache_status = NJT_HTTP_CACHE_REVALIDATED;
        rc = njt_http_upstream_cache_send(r, u);

        if (rc == NJT_DONE) {
            return NJT_OK;
        }

        if (rc == NJT_HTTP_UPSTREAM_INVALID_HEADER) {
            rc = NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (valid == 0) {
            valid = r->cache->valid_sec;
            updating = r->cache->updating_sec;
            error = r->cache->error_sec;
        }

        if (valid == 0) {
            valid = njt_http_file_cache_valid(u->conf->cache_valid,
                                              u->headers_in.status_n);
            if (valid) {
                valid = now + valid;
            }
        }

        if (valid) {
            r->cache->valid_sec = valid;
            r->cache->updating_sec = updating;
            r->cache->error_sec = error;

            r->cache->date = now;

            njt_http_file_cache_update_header(r);
        }

        njt_http_upstream_finalize_request(r, u, rc);
        return NJT_OK;
    }

#endif

    return NJT_DECLINED;
}


static njt_int_t
njt_http_upstream_intercept_errors(njt_http_request_t *r,
    njt_http_upstream_t *u)
{
    njt_int_t                  status;
    njt_uint_t                 i;
    njt_table_elt_t           *h, *ho, **ph;
    njt_http_err_page_t       *err_page;
    njt_http_core_loc_conf_t  *clcf;

    status = u->headers_in.status_n;

    if (status == NJT_HTTP_NOT_FOUND && u->conf->intercept_404) {
        njt_http_upstream_finalize_request(r, u, NJT_HTTP_NOT_FOUND);
        return NJT_OK;
    }

    if (!u->conf->intercept_errors) {
        return NJT_DECLINED;
    }

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    if (clcf->error_pages == NULL) {
        return NJT_DECLINED;
    }

    err_page = clcf->error_pages->elts;
    for (i = 0; i < clcf->error_pages->nelts; i++) {

        if (err_page[i].status == status) {

            if (status == NJT_HTTP_UNAUTHORIZED
                && u->headers_in.www_authenticate)
            {
                h = u->headers_in.www_authenticate;
                ph = &r->headers_out.www_authenticate;

                while (h) {
                    ho = njt_list_push(&r->headers_out.headers);

                    if (ho == NULL) {
                        njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
                        return NJT_OK;
                    }

                    *ho = *h;
                    ho->next = NULL;

                    *ph = ho;
                    ph = &ho->next;

                    h = h->next;
                }
            }

#if (NJT_HTTP_CACHE)

            if (r->cache) {

                if (u->headers_in.no_cache || u->headers_in.expired) {
                    u->cacheable = 0;
                }

                if (u->cacheable) {
                    time_t  valid;

                    valid = r->cache->valid_sec;

                    if (valid == 0) {
                        valid = njt_http_file_cache_valid(u->conf->cache_valid,
                                                          status);
                        if (valid) {
                            r->cache->valid_sec = njt_time() + valid;
                        }
                    }

                    if (valid) {
                        r->cache->error = status;
                    }
                }

                njt_http_file_cache_free(r->cache, u->pipe->temp_file);
            }
#endif
            njt_http_upstream_finalize_request(r, u, status);

            return NJT_OK;
        }
    }

    return NJT_DECLINED;
}


static njt_int_t
njt_http_upstream_test_connect(njt_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (NJT_HAVE_KQUEUE)

    if (njt_event_flags & NJT_USE_KQUEUE_EVENT)  {
        if (c->write->pending_eof || c->read->pending_eof) {
            if (c->write->pending_eof) {
                err = c->write->kq_errno;

            } else {
                err = c->read->kq_errno;
            }

            c->log->action = "connecting to upstream";
            (void) njt_connection_error(c, err,
                                    "kevent() reported that connect() failed");
            return NJT_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = njt_socket_errno;
        }

        if (err) {
            c->log->action = "connecting to upstream";
            (void) njt_connection_error(c, err, "connect() failed");
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_process_headers(njt_http_request_t *r, njt_http_upstream_t *u)
{
    njt_str_t                       uri, args;
    njt_uint_t                      i, flags;
    njt_list_part_t                *part;
    njt_table_elt_t                *h;
    njt_http_upstream_header_t     *hh;
    njt_http_upstream_main_conf_t  *umcf;

    umcf = njt_http_get_module_main_conf(r, njt_http_upstream_module);

    if (u->headers_in.no_cache || u->headers_in.expired) {
        u->cacheable = 0;
    }

    if (u->headers_in.x_accel_redirect
        && !(u->conf->ignore_headers & NJT_HTTP_UPSTREAM_IGN_XA_REDIRECT))
    {
        njt_http_upstream_finalize_request(r, u, NJT_DECLINED);

        part = &u->headers_in.headers.part;
        h = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                h = part->elts;
                i = 0;
            }

            if (h[i].hash == 0) {
                continue;
            }

            hh = njt_hash_find(&umcf->headers_in_hash, h[i].hash,
                               h[i].lowcase_key, h[i].key.len);

            if (hh && hh->redirect) {
                if (hh->copy_handler(r, &h[i], hh->conf) != NJT_OK) {
                    njt_http_finalize_request(r,
                                              NJT_HTTP_INTERNAL_SERVER_ERROR);
                    return NJT_DONE;
                }
            }
        }

        uri = u->headers_in.x_accel_redirect->value;

        if (uri.data[0] == '@') {
            njt_http_named_location(r, &uri);

        } else {
            njt_str_null(&args);
            flags = NJT_HTTP_LOG_UNSAFE;

            if (njt_http_parse_unsafe_uri(r, &uri, &args, &flags) != NJT_OK) {
                njt_http_finalize_request(r, NJT_HTTP_NOT_FOUND);
                return NJT_DONE;
            }

            if (r->method != NJT_HTTP_HEAD) {
                r->method = NJT_HTTP_GET;
                r->method_name = njt_http_core_get_method;
            }

            njt_http_internal_redirect(r, &uri, &args);
        }

        njt_http_finalize_request(r, NJT_DONE);
        return NJT_DONE;
    }

    part = &u->headers_in.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].hash == 0) {
            continue;
        }

        if (njt_hash_find(&u->conf->hide_headers_hash, h[i].hash,
                          h[i].lowcase_key, h[i].key.len))
        {
            continue;
        }

        hh = njt_hash_find(&umcf->headers_in_hash, h[i].hash,
                           h[i].lowcase_key, h[i].key.len);

        if (hh) {
            if (hh->copy_handler(r, &h[i], hh->conf) != NJT_OK) {
                njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
                return NJT_DONE;
            }

            continue;
        }

        if (njt_http_upstream_copy_header_line(r, &h[i], 0) != NJT_OK) {
            njt_http_upstream_finalize_request(r, u,
                                               NJT_HTTP_INTERNAL_SERVER_ERROR);
            return NJT_DONE;
        }
    }

    if (r->headers_out.server && r->headers_out.server->value.data == NULL) {
        r->headers_out.server->hash = 0;
    }

    if (r->headers_out.date && r->headers_out.date->value.data == NULL) {
        r->headers_out.date->hash = 0;
    }

    r->headers_out.status = u->headers_in.status_n;
    r->headers_out.status_line = u->headers_in.status_line;

    r->headers_out.content_length_n = u->headers_in.content_length_n;

    r->disable_not_modified = !u->cacheable;

    if (u->conf->force_ranges) {
        r->allow_ranges = 1;
        r->single_range = 1;

#if (NJT_HTTP_CACHE)
        if (r->cached) {
            r->single_range = 0;
        }
#endif
    }

    u->length = -1;

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_process_trailers(njt_http_request_t *r,
    njt_http_upstream_t *u)
{
    njt_uint_t        i;
    njt_list_part_t  *part;
    njt_table_elt_t  *h, *ho;

    if (!u->conf->pass_trailers) {
        return NJT_OK;
    }

    part = &u->headers_in.trailers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (njt_hash_find(&u->conf->hide_headers_hash, h[i].hash,
                          h[i].lowcase_key, h[i].key.len))
        {
            continue;
        }

        ho = njt_list_push(&r->headers_out.trailers);
        if (ho == NULL) {
            return NJT_ERROR;
        }

        *ho = h[i];
    }

    return NJT_OK;
}


static void
njt_http_upstream_send_response(njt_http_request_t *r, njt_http_upstream_t *u)
{
    ssize_t                    n;
    njt_int_t                  rc;
    njt_event_pipe_t          *p;
    njt_connection_t          *c;
    njt_http_core_loc_conf_t  *clcf;

    rc = njt_http_send_header(r);

    if (rc == NJT_ERROR || rc > NJT_OK || r->post_action) {
        njt_http_upstream_finalize_request(r, u, rc);
        return;
    }

    u->header_sent = 1;

    if (u->upgrade) {

#if (NJT_HTTP_CACHE)

        if (r->cache) {
            njt_http_file_cache_free(r->cache, u->pipe->temp_file);
        }

#endif

        njt_http_upstream_upgrade(r, u);
        return;
    }

    c = r->connection;

    if (r->header_only) {

        if (!u->buffering) {
            njt_http_upstream_finalize_request(r, u, rc);
            return;
        }

        if (!u->cacheable && !u->store) {
            njt_http_upstream_finalize_request(r, u, rc);
            return;
        }

        u->pipe->downstream_error = 1;
    }

    if (r->request_body && r->request_body->temp_file
        && r == r->main && !r->preserve_body
        && !u->conf->preserve_output)
    {
        njt_pool_run_cleanup_file(r->pool, r->request_body->temp_file->file.fd);
        r->request_body->temp_file->file.fd = NJT_INVALID_FILE;
    }

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    if (!u->buffering) {

#if (NJT_HTTP_CACHE)

        if (r->cache) {
            njt_http_file_cache_free(r->cache, u->pipe->temp_file);
        }

#endif

        if (u->input_filter == NULL) {
            u->input_filter_init = njt_http_upstream_non_buffered_filter_init;
            u->input_filter = njt_http_upstream_non_buffered_filter;
            u->input_filter_ctx = r;
        }

        u->read_event_handler = njt_http_upstream_process_non_buffered_upstream;
        r->write_event_handler =
                             njt_http_upstream_process_non_buffered_downstream;

        r->limit_rate = 0;
        r->limit_rate_set = 1;

        if (u->input_filter_init(u->input_filter_ctx) == NJT_ERROR) {
            njt_http_upstream_finalize_request(r, u, NJT_ERROR);
            return;
        }

        if (clcf->tcp_nodelay && njt_tcp_nodelay(c) != NJT_OK) {
            njt_http_upstream_finalize_request(r, u, NJT_ERROR);
            return;
        }

        n = u->buffer.last - u->buffer.pos;

        if (n) {
            u->buffer.last = u->buffer.pos;

            u->state->response_length += n;

            if (u->input_filter(u->input_filter_ctx, n) == NJT_ERROR) {
                njt_http_upstream_finalize_request(r, u, NJT_ERROR);
                return;
            }

            njt_http_upstream_process_non_buffered_downstream(r);

        } else {
            u->buffer.pos = u->buffer.start;
            u->buffer.last = u->buffer.start;

            if (njt_http_send_special(r, NJT_HTTP_FLUSH) == NJT_ERROR) {
                njt_http_upstream_finalize_request(r, u, NJT_ERROR);
                return;
            }

            njt_http_upstream_process_non_buffered_upstream(r, u);
        }

        return;
    }

    /* TODO: preallocate event_pipe bufs, look "Content-Length" */

#if (NJT_HTTP_CACHE)

    if (r->cache && r->cache->file.fd != NJT_INVALID_FILE) {
        njt_pool_run_cleanup_file(r->pool, r->cache->file.fd);
        r->cache->file.fd = NJT_INVALID_FILE;
    }

    switch (njt_http_test_predicates(r, u->conf->no_cache)) {

    case NJT_ERROR:
        njt_http_upstream_finalize_request(r, u, NJT_ERROR);
        return;

    case NJT_DECLINED:
        u->cacheable = 0;
        break;

    default: /* NJT_OK */

        if (u->cache_status == NJT_HTTP_CACHE_BYPASS) {

            /* create cache if previously bypassed */

            if (njt_http_file_cache_create(r) != NJT_OK) {
                njt_http_upstream_finalize_request(r, u, NJT_ERROR);
                return;
            }
        }

        break;
    }

    if (u->cacheable) {
        time_t  now, valid;

        now = njt_time();

        valid = r->cache->valid_sec;

        if (valid == 0) {
            valid = njt_http_file_cache_valid(u->conf->cache_valid,
                                              u->headers_in.status_n);
            if (valid) {
                r->cache->valid_sec = now + valid;
            }
        }

        if (valid) {
            r->cache->date = now;
            r->cache->body_start = (u_short) (u->buffer.pos - u->buffer.start);

            if (u->headers_in.status_n == NJT_HTTP_OK
                || u->headers_in.status_n == NJT_HTTP_PARTIAL_CONTENT)
            {
                r->cache->last_modified = u->headers_in.last_modified_time;

                if (u->headers_in.etag) {
                    r->cache->etag = u->headers_in.etag->value;

                } else {
                    njt_str_null(&r->cache->etag);
                }

            } else {
                r->cache->last_modified = -1;
                njt_str_null(&r->cache->etag);
            }

            if (njt_http_file_cache_set_header(r, u->buffer.start) != NJT_OK) {
                njt_http_upstream_finalize_request(r, u, NJT_ERROR);
                return;
            }

        } else {
            u->cacheable = 0;
        }
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http cacheable: %d", u->cacheable);

    if (u->cacheable == 0 && r->cache) {
        njt_http_file_cache_free(r->cache, u->pipe->temp_file);
    }

    if (r->header_only && !u->cacheable && !u->store) {
        njt_http_upstream_finalize_request(r, u, 0);
        return;
    }

#endif

    p = u->pipe;

    p->output_filter = njt_http_upstream_output_filter;
    p->output_ctx = r;
    p->tag = u->output.tag;
    p->bufs = u->conf->bufs;
    p->busy_size = u->conf->busy_buffers_size;
    p->upstream = u->peer.connection;
    p->downstream = c;
    p->pool = r->pool;
    p->log = c->log;
    p->limit_rate = u->conf->limit_rate;
    p->start_sec = njt_time();

    p->cacheable = u->cacheable || u->store;

    p->temp_file = njt_pcalloc(r->pool, sizeof(njt_temp_file_t));
    if (p->temp_file == NULL) {
        njt_http_upstream_finalize_request(r, u, NJT_ERROR);
        return;
    }

    p->temp_file->file.fd = NJT_INVALID_FILE;
    p->temp_file->file.log = c->log;
    p->temp_file->path = u->conf->temp_path;
    p->temp_file->pool = r->pool;

    if (p->cacheable) {
        p->temp_file->persistent = 1;

#if (NJT_HTTP_CACHE)
        if (r->cache && !r->cache->file_cache->use_temp_path) {
            p->temp_file->path = r->cache->file_cache->path;
            p->temp_file->file.name = r->cache->file.name;
        }
#endif

    } else {
        p->temp_file->log_level = NJT_LOG_WARN;
        p->temp_file->warn = "an upstream response is buffered "
                             "to a temporary file";
    }

    p->max_temp_file_size = u->conf->max_temp_file_size;
    p->temp_file_write_size = u->conf->temp_file_write_size;

#if (NJT_THREADS)
    if (clcf->aio == NJT_HTTP_AIO_THREADS && clcf->aio_write) {
        p->thread_handler = njt_http_upstream_thread_handler;
        p->thread_ctx = r;
    }
#endif

    p->preread_bufs = njt_alloc_chain_link(r->pool);
    if (p->preread_bufs == NULL) {
        njt_http_upstream_finalize_request(r, u, NJT_ERROR);
        return;
    }

    p->preread_bufs->buf = &u->buffer;
    p->preread_bufs->next = NULL;
    u->buffer.recycled = 1;

    p->preread_size = u->buffer.last - u->buffer.pos;

    if (u->cacheable) {

        p->buf_to_file = njt_calloc_buf(r->pool);
        if (p->buf_to_file == NULL) {
            njt_http_upstream_finalize_request(r, u, NJT_ERROR);
            return;
        }

        p->buf_to_file->start = u->buffer.start;
        p->buf_to_file->pos = u->buffer.start;
        p->buf_to_file->last = u->buffer.pos;
        p->buf_to_file->temporary = 1;
    }

    if (njt_event_flags & NJT_USE_IOCP_EVENT) {
        /* the posted aio operation may corrupt a shadow buffer */
        p->single_buf = 1;
    }

    /* TODO: p->free_bufs = 0 if use njt_create_chain_of_bufs() */
    p->free_bufs = 1;

    /*
     * event_pipe would do u->buffer.last += p->preread_size
     * as though these bytes were read
     */
    u->buffer.last = u->buffer.pos;

    if (u->conf->cyclic_temp_file) {

        /*
         * we need to disable the use of sendfile() if we use cyclic temp file
         * because the writing a new data may interfere with sendfile()
         * that uses the same kernel file pages (at least on FreeBSD)
         */

        p->cyclic_temp_file = 1;
        c->sendfile = 0;

    } else {
        p->cyclic_temp_file = 0;
    }

    // p->read_timeout = u->conf->read_timeout; openresty patch
    p->read_timeout = u->read_timeout; // openresty patch
    p->send_timeout = clcf->send_timeout;
    p->send_lowat = clcf->send_lowat;

    p->length = -1;

    if (u->input_filter_init
        && u->input_filter_init(p->input_ctx) != NJT_OK)
    {
        njt_http_upstream_finalize_request(r, u, NJT_ERROR);
        return;
    }

    u->read_event_handler = njt_http_upstream_process_upstream;
    r->write_event_handler = njt_http_upstream_process_downstream;

    njt_http_upstream_process_upstream(r, u);
}


static void
njt_http_upstream_upgrade(njt_http_request_t *r, njt_http_upstream_t *u)
{
    njt_connection_t          *c;
    njt_http_core_loc_conf_t  *clcf;

    c = r->connection;
    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    /* TODO: prevent upgrade if not requested or not possible */

    if (r != r->main) {
        njt_log_error(NJT_LOG_ERR, c->log, 0,
                      "connection upgrade in subrequest");
        njt_http_upstream_finalize_request(r, u, NJT_ERROR);
        return;
    }

    r->keepalive = 0;
    c->log->action = "proxying upgraded connection";

    u->read_event_handler = njt_http_upstream_upgraded_read_upstream;
    u->write_event_handler = njt_http_upstream_upgraded_write_upstream;
    r->read_event_handler = njt_http_upstream_upgraded_read_downstream;
    r->write_event_handler = njt_http_upstream_upgraded_write_downstream;

    if (clcf->tcp_nodelay) {

        if (njt_tcp_nodelay(c) != NJT_OK) {
            njt_http_upstream_finalize_request(r, u, NJT_ERROR);
            return;
        }

        if (njt_tcp_nodelay(u->peer.connection) != NJT_OK) {
            njt_http_upstream_finalize_request(r, u, NJT_ERROR);
            return;
        }
    }

    if (njt_http_send_special(r, NJT_HTTP_FLUSH) == NJT_ERROR) {
        njt_http_upstream_finalize_request(r, u, NJT_ERROR);
        return;
    }

    if (u->peer.connection->read->ready
        || u->buffer.pos != u->buffer.last)
    {
        njt_post_event(c->read, &njt_posted_events);
        njt_http_upstream_process_upgraded(r, 1, 1);
        return;
    }

    njt_http_upstream_process_upgraded(r, 0, 1);
}


static void
njt_http_upstream_upgraded_read_downstream(njt_http_request_t *r)
{
    njt_http_upstream_process_upgraded(r, 0, 0);
}


static void
njt_http_upstream_upgraded_write_downstream(njt_http_request_t *r)
{
    njt_http_upstream_process_upgraded(r, 1, 1);
}


static void
njt_http_upstream_upgraded_read_upstream(njt_http_request_t *r,
    njt_http_upstream_t *u)
{
    njt_http_upstream_process_upgraded(r, 1, 0);
}


static void
njt_http_upstream_upgraded_write_upstream(njt_http_request_t *r,
    njt_http_upstream_t *u)
{
    njt_http_upstream_process_upgraded(r, 0, 1);
}


static void
njt_http_upstream_process_upgraded(njt_http_request_t *r,
    njt_uint_t from_upstream, njt_uint_t do_write)
{
    size_t                     size;
    ssize_t                    n;
    njt_buf_t                 *b;
    njt_uint_t                 flags;
    njt_connection_t          *c, *downstream, *upstream, *dst, *src;
    njt_http_upstream_t       *u;
    njt_http_core_loc_conf_t  *clcf;

    c = r->connection;
    u = r->upstream;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process upgraded, fu:%ui", from_upstream);

    downstream = c;
    upstream = u->peer.connection;

    if (downstream->write->timedout) {
        c->timedout = 1;
        njt_connection_error(c, NJT_ETIMEDOUT, "client timed out");
        njt_http_upstream_finalize_request(r, u, NJT_HTTP_REQUEST_TIME_OUT);
        return;
    }

    if (upstream->read->timedout || upstream->write->timedout) {
        njt_connection_error(c, NJT_ETIMEDOUT, "upstream timed out");
        njt_http_upstream_finalize_request(r, u, NJT_HTTP_GATEWAY_TIME_OUT);
        return;
    }

    if (from_upstream) {
        src = upstream;
        dst = downstream;
        b = &u->buffer;

    } else {
        src = downstream;
        dst = upstream;
        b = &u->from_client;

        if (r->header_in->last > r->header_in->pos) {
            b = r->header_in;
            b->end = b->last;
            do_write = 1;
        }

        if (b->start == NULL) {
            b->start = njt_palloc(r->pool, u->conf->buffer_size);
            if (b->start == NULL) {
                njt_http_upstream_finalize_request(r, u, NJT_ERROR);
                return;
            }

            b->pos = b->start;
            b->last = b->start;
            b->end = b->start + u->conf->buffer_size;
            b->temporary = 1;
            b->tag = u->output.tag;
        }
    }

    for ( ;; ) {

        if (do_write) {

            size = b->last - b->pos;

            if (size && dst->write->ready) {

                n = dst->send(dst, b->pos, size);

                if (n == NJT_ERROR) {
                    njt_http_upstream_finalize_request(r, u, NJT_ERROR);
                    return;
                }

                if (n > 0) {
                    b->pos += n;

                    if (b->pos == b->last) {
                        b->pos = b->start;
                        b->last = b->start;
                    }
                }
            }
        }

        size = b->end - b->last;

        if (size && src->read->ready) {

            n = src->recv(src, b->last, size);

            if (n == NJT_AGAIN || n == 0) {
                break;
            }

            if (n > 0) {
                do_write = 1;
                b->last += n;

                if (from_upstream) {
                    u->state->bytes_received += n;
                }

                continue;
            }

            if (n == NJT_ERROR) {
                src->read->eof = 1;
            }
        }

        break;
    }

    if ((upstream->read->eof && u->buffer.pos == u->buffer.last)
        || (downstream->read->eof && u->from_client.pos == u->from_client.last)
        || (downstream->read->eof && upstream->read->eof))
    {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http upstream upgraded done");
        njt_http_upstream_finalize_request(r, u, 0);
        return;
    }

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    if (njt_handle_write_event(upstream->write, u->conf->send_lowat)
        != NJT_OK)
    {
        njt_http_upstream_finalize_request(r, u, NJT_ERROR);
        return;
    }

    if (upstream->write->active && !upstream->write->ready) {
        // njt_add_timer(upstream->write, u->conf->send_timeout); openresty patch
        njt_add_timer(upstream->write, u->send_timeout); // openresty patch

    } else if (upstream->write->timer_set) {
        njt_del_timer(upstream->write);
    }

    if (upstream->read->eof || upstream->read->error) {
        flags = NJT_CLOSE_EVENT;

    } else {
        flags = 0;
    }

    if (njt_handle_read_event(upstream->read, flags) != NJT_OK) {
        njt_http_upstream_finalize_request(r, u, NJT_ERROR);
        return;
    }

    if (upstream->read->active && !upstream->read->ready) {
        // njt_add_timer(upstream->read, u->conf->read_timeout); openresty patch
        njt_add_timer(upstream->read, u->read_timeout); // openresty patch

    } else if (upstream->read->timer_set) {
        njt_del_timer(upstream->read);
    }

    if (njt_handle_write_event(downstream->write, clcf->send_lowat)
        != NJT_OK)
    {
        njt_http_upstream_finalize_request(r, u, NJT_ERROR);
        return;
    }

    if (downstream->read->eof || downstream->read->error) {
        flags = NJT_CLOSE_EVENT;

    } else {
        flags = 0;
    }

    if (njt_handle_read_event(downstream->read, flags) != NJT_OK) {
        njt_http_upstream_finalize_request(r, u, NJT_ERROR);
        return;
    }

    if (downstream->write->active && !downstream->write->ready) {
        njt_add_timer(downstream->write, clcf->send_timeout);

    } else if (downstream->write->timer_set) {
        njt_del_timer(downstream->write);
    }
}


static void
njt_http_upstream_process_non_buffered_downstream(njt_http_request_t *r)
{
    njt_event_t          *wev;
    njt_connection_t     *c;
    njt_http_upstream_t  *u;

    c = r->connection;
    u = r->upstream;
    wev = c->write;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process non buffered downstream");

    c->log->action = "sending to client";

    if (wev->timedout) {
        c->timedout = 1;
        njt_connection_error(c, NJT_ETIMEDOUT, "client timed out");
        njt_http_upstream_finalize_request(r, u, NJT_HTTP_REQUEST_TIME_OUT);
        return;
    }

    njt_http_upstream_process_non_buffered_request(r, 1);
}


static void
njt_http_upstream_process_non_buffered_upstream(njt_http_request_t *r,
    njt_http_upstream_t *u)
{
    njt_connection_t  *c;

    c = u->peer.connection;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process non buffered upstream");

    c->log->action = "reading upstream";

    if (c->read->timedout) {
        njt_connection_error(c, NJT_ETIMEDOUT, "upstream timed out");
        njt_http_upstream_finalize_request(r, u, NJT_HTTP_GATEWAY_TIME_OUT);
        return;
    }

    njt_http_upstream_process_non_buffered_request(r, 0);
}


static void
njt_http_upstream_process_non_buffered_request(njt_http_request_t *r,
    njt_uint_t do_write)
{
    size_t                     size;
    ssize_t                    n;
    njt_buf_t                 *b;
    njt_int_t                  rc;
    njt_uint_t                 flags;
    njt_connection_t          *downstream, *upstream;
    njt_http_upstream_t       *u;
    njt_http_core_loc_conf_t  *clcf;

    u = r->upstream;
    downstream = r->connection;
    upstream = u->peer.connection;

    b = &u->buffer;

    do_write = do_write || u->length == 0;

    for ( ;; ) {

        if (do_write) {

            if (u->out_bufs || u->busy_bufs || downstream->buffered) {
                rc = njt_http_output_filter(r, u->out_bufs);

                if (rc == NJT_ERROR) {
                    njt_http_upstream_finalize_request(r, u, NJT_ERROR);
                    return;
                }

                njt_chain_update_chains(r->pool, &u->free_bufs, &u->busy_bufs,
                                        &u->out_bufs, u->output.tag);
            }

            if (u->busy_bufs == NULL) {

                if (u->length == 0
                    || (upstream->read->eof && u->length == -1))
                {
                    njt_http_upstream_finalize_request(r, u, 0);
                    return;
                }

                if (upstream->read->eof) {
                    njt_log_error(NJT_LOG_ERR, upstream->log, 0,
                                  "upstream prematurely closed connection");

                    njt_http_upstream_finalize_request(r, u,
                                                       NJT_HTTP_BAD_GATEWAY);
                    return;
                }

                if (upstream->read->error || u->error) {
                    njt_http_upstream_finalize_request(r, u,
                                                       NJT_HTTP_BAD_GATEWAY);
                    return;
                }

                b->pos = b->start;
                b->last = b->start;
            }
        }

        size = b->end - b->last;

        if (size && upstream->read->ready) {

            n = upstream->recv(upstream, b->last, size);

            if (n == NJT_AGAIN) {
                break;
            }

            if (n > 0) {
                u->state->bytes_received += n;
                u->state->response_length += n;

                if (u->input_filter(u->input_filter_ctx, n) == NJT_ERROR) {
                    njt_http_upstream_finalize_request(r, u, NJT_ERROR);
                    return;
                }
            }

            do_write = 1;

            continue;
        }

        break;
    }

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    if (downstream->data == r) {
        if (njt_handle_write_event(downstream->write, clcf->send_lowat)
            != NJT_OK)
        {
            njt_http_upstream_finalize_request(r, u, NJT_ERROR);
            return;
        }
    }

    if (downstream->write->active && !downstream->write->ready) {
        njt_add_timer(downstream->write, clcf->send_timeout);

    } else if (downstream->write->timer_set) {
        njt_del_timer(downstream->write);
    }

    if (upstream->read->eof || upstream->read->error) {
        flags = NJT_CLOSE_EVENT;

    } else {
        flags = 0;
    }

    if (njt_handle_read_event(upstream->read, flags) != NJT_OK) {
        njt_http_upstream_finalize_request(r, u, NJT_ERROR);
        return;
    }

    if (upstream->read->active && !upstream->read->ready) {
        // njt_add_timer(upstream->read, u->conf->read_timeout); openresty patch
        njt_add_timer(upstream->read, u->read_timeout); // openresty patch

    } else if (upstream->read->timer_set) {
        njt_del_timer(upstream->read);
    }
}


njt_int_t
njt_http_upstream_non_buffered_filter_init(void *data)
{
    return NJT_OK;
}


njt_int_t
njt_http_upstream_non_buffered_filter(void *data, ssize_t bytes)
{
    njt_http_request_t  *r = data;

    njt_buf_t            *b;
    njt_chain_t          *cl, **ll;
    njt_http_upstream_t  *u;

    u = r->upstream;

    if (u->length == 0) {
        njt_log_error(NJT_LOG_WARN, r->connection->log, 0,
                      "upstream sent more data than specified in "
                      "\"Content-Length\" header");
        return NJT_OK;
    }

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = njt_chain_get_free_buf(r->pool, &u->free_bufs);
    if (cl == NULL) {
        return NJT_ERROR;
    }

    *ll = cl;

    cl->buf->flush = 1;
    cl->buf->memory = 1;

    b = &u->buffer;

    cl->buf->pos = b->last;
    b->last += bytes;
    cl->buf->last = b->last;
    cl->buf->tag = u->output.tag;

    if (u->length == -1) {
        return NJT_OK;
    }

    if (bytes > u->length) {

        njt_log_error(NJT_LOG_WARN, r->connection->log, 0,
                      "upstream sent more data than specified in "
                      "\"Content-Length\" header");

        cl->buf->last = cl->buf->pos + u->length;
        u->length = 0;

        return NJT_OK;
    }

    u->length -= bytes;

    return NJT_OK;
}


#if (NJT_THREADS)

static njt_int_t
njt_http_upstream_thread_handler(njt_thread_task_t *task, njt_file_t *file)
{
    njt_str_t                  name;
    njt_event_pipe_t          *p;
    njt_connection_t          *c;
    njt_thread_pool_t         *tp;
    njt_http_request_t        *r;
    njt_http_core_loc_conf_t  *clcf;

    r = file->thread_ctx;
    p = r->upstream->pipe;

    if (r->aio) {
        /*
         * tolerate sendfile() calls if another operation is already
         * running; this can happen due to subrequests, multiple calls
         * of the next body filter from a filter, or in HTTP/2 due to
         * a write event on the main connection
         */

        c = r->connection;

#if (NJT_HTTP_V2)
        if (r->stream) {
            c = r->stream->connection->connection;
        }
#endif

        if (task == c->sendfile_task) {
            return NJT_OK;
        }
    }

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);
    tp = clcf->thread_pool;

    if (tp == NULL) {
        if (njt_http_complex_value(r, clcf->thread_pool_value, &name)
            != NJT_OK)
        {
            return NJT_ERROR;
        }

        tp = njt_thread_pool_get((njt_cycle_t *) njt_cycle, &name);

        if (tp == NULL) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "thread pool \"%V\" not found", &name);
            return NJT_ERROR;
        }
    }

    task->event.data = r;
    task->event.handler = njt_http_upstream_thread_event_handler;

    if (njt_thread_task_post(tp, task) != NJT_OK) {
        return NJT_ERROR;
    }

    r->main->blocked++;
    r->aio = 1;
    p->aio = 1;

    return NJT_OK;
}


static void
njt_http_upstream_thread_event_handler(njt_event_t *ev)
{
    njt_connection_t    *c;
    njt_http_request_t  *r;

    r = ev->data;
    c = r->connection;

    njt_http_set_log_request(c->log, r);

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream thread: \"%V?%V\"", &r->uri, &r->args);

    r->main->blocked--;
    r->aio = 0;

#if (NJT_HTTP_V2)

    if (r->stream) {
        /*
         * for HTTP/2, update write event to make sure processing will
         * reach the main connection to handle sendfile() in threads
         */

        c->write->ready = 1;
        c->write->active = 0;
    }

#endif

    if (r->done) {
        /*
         * trigger connection event handler if the subrequest was
         * already finalized; this can happen if the handler is used
         * for sendfile() in threads
         */

        c->write->handler(c->write);

    } else {
        r->write_event_handler(r);
        njt_http_run_posted_requests(c);
    }
}

#endif


static njt_int_t
njt_http_upstream_output_filter(void *data, njt_chain_t *chain)
{
    njt_int_t            rc;
    njt_event_pipe_t    *p;
    njt_http_request_t  *r;

    r = data;
    p = r->upstream->pipe;

    rc = njt_http_output_filter(r, chain);

    p->aio = r->aio;

    return rc;
}


static void
njt_http_upstream_process_downstream(njt_http_request_t *r)
{
    njt_event_t          *wev;
    njt_connection_t     *c;
    njt_event_pipe_t     *p;
    njt_http_upstream_t  *u;

    c = r->connection;
    u = r->upstream;
    p = u->pipe;
    wev = c->write;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process downstream");

    c->log->action = "sending to client";

#if (NJT_THREADS)
    p->aio = r->aio;
#endif

    if (wev->timedout) {

        p->downstream_error = 1;
        c->timedout = 1;
        njt_connection_error(c, NJT_ETIMEDOUT, "client timed out");

    } else {

        if (wev->delayed) {

            njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                           "http downstream delayed");

            if (njt_handle_write_event(wev, p->send_lowat) != NJT_OK) {
                njt_http_upstream_finalize_request(r, u, NJT_ERROR);
            }

            return;
        }

        if (njt_event_pipe(p, 1) == NJT_ABORT) {
            njt_http_upstream_finalize_request(r, u, NJT_ERROR);
            return;
        }
    }

    njt_http_upstream_process_request(r, u);
}


static void
njt_http_upstream_process_upstream(njt_http_request_t *r,
    njt_http_upstream_t *u)
{
    njt_event_t       *rev;
    njt_event_pipe_t  *p;
    njt_connection_t  *c;

    c = u->peer.connection;
    p = u->pipe;
    rev = c->read;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process upstream");

    c->log->action = "reading upstream";

    if (rev->timedout) {

        p->upstream_error = 1;
        njt_connection_error(c, NJT_ETIMEDOUT, "upstream timed out");

    } else {

        if (rev->delayed) {

            njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                           "http upstream delayed");

            if (njt_handle_read_event(rev, 0) != NJT_OK) {
                njt_http_upstream_finalize_request(r, u, NJT_ERROR);
            }

            return;
        }

        if (njt_event_pipe(p, 0) == NJT_ABORT) {
            njt_http_upstream_finalize_request(r, u, NJT_ERROR);
            return;
        }
    }

    njt_http_upstream_process_request(r, u);
}


static void
njt_http_upstream_process_request(njt_http_request_t *r,
    njt_http_upstream_t *u)
{
    njt_temp_file_t   *tf;
    njt_event_pipe_t  *p;

    p = u->pipe;

#if (NJT_THREADS)

    if (p->writing && !p->aio) {

        /*
         * make sure to call njt_event_pipe()
         * if there is an incomplete aio write
         */

        if (njt_event_pipe(p, 1) == NJT_ABORT) {
            njt_http_upstream_finalize_request(r, u, NJT_ERROR);
            return;
        }
    }

    if (p->writing) {
        return;
    }

#endif

    if (u->peer.connection) {

        if (u->store) {

            if (p->upstream_eof || p->upstream_done) {

                tf = p->temp_file;

                if (u->headers_in.status_n == NJT_HTTP_OK
                    && (p->upstream_done || p->length == -1)
                    && (u->headers_in.content_length_n == -1
                        || u->headers_in.content_length_n == tf->offset))
                {
                    njt_http_upstream_store(r, u);
                }
            }
        }

#if (NJT_HTTP_CACHE)

        if (u->cacheable) {

            if (p->upstream_done) {
                njt_http_file_cache_update(r, p->temp_file);

            } else if (p->upstream_eof) {

                tf = p->temp_file;

                if (p->length == -1
                    && (u->headers_in.content_length_n == -1
                        || u->headers_in.content_length_n
                           == tf->offset - (off_t) r->cache->body_start))
                {
                    njt_http_file_cache_update(r, tf);

                } else {
                    njt_http_file_cache_free(r->cache, tf);
                }

            } else if (p->upstream_error) {
                njt_http_file_cache_free(r->cache, p->temp_file);
            }
        }

#endif

        if (p->upstream_done || p->upstream_eof || p->upstream_error) {
            njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http upstream exit: %p", p->out);

            if (p->upstream_done
                || (p->upstream_eof && p->length == -1))
            {
                njt_http_upstream_finalize_request(r, u, 0);
                return;
            }

            if (p->upstream_eof) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream prematurely closed connection");
            }

            njt_http_upstream_finalize_request(r, u, NJT_HTTP_BAD_GATEWAY);
            return;
        }
    }

    if (p->downstream_error) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http upstream downstream error");

        if (!u->cacheable && !u->store && u->peer.connection) {
            njt_http_upstream_finalize_request(r, u, NJT_ERROR);
        }
    }
}


static void
njt_http_upstream_store(njt_http_request_t *r, njt_http_upstream_t *u)
{
    size_t                  root;
    time_t                  lm;
    njt_str_t               path;
    njt_temp_file_t        *tf;
    njt_ext_rename_file_t   ext;

    tf = u->pipe->temp_file;

    if (tf->file.fd == NJT_INVALID_FILE) {

        /* create file for empty 200 response */

        tf = njt_pcalloc(r->pool, sizeof(njt_temp_file_t));
        if (tf == NULL) {
            return;
        }

        tf->file.fd = NJT_INVALID_FILE;
        tf->file.log = r->connection->log;
        tf->path = u->conf->temp_path;
        tf->pool = r->pool;
        tf->persistent = 1;

        if (njt_create_temp_file(&tf->file, tf->path, tf->pool,
                                 tf->persistent, tf->clean, tf->access)
            != NJT_OK)
        {
            return;
        }

        u->pipe->temp_file = tf;
    }

    ext.access = u->conf->store_access;
    ext.path_access = u->conf->store_access;
    ext.time = -1;
    ext.create_path = 1;
    ext.delete_file = 1;
    ext.log = r->connection->log;

    if (u->headers_in.last_modified) {

        lm = njt_parse_http_time(u->headers_in.last_modified->value.data,
                                 u->headers_in.last_modified->value.len);

        if (lm != NJT_ERROR) {
            ext.time = lm;
            ext.fd = tf->file.fd;
        }
    }

    if (u->conf->store_lengths == NULL) {

        if (njt_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
            return;
        }

    } else {
        if (njt_http_script_run(r, &path, u->conf->store_lengths->elts, 0,
                                u->conf->store_values->elts)
            == NULL)
        {
            return;
        }
    }

    path.len--;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "upstream stores \"%s\" to \"%s\"",
                   tf->file.name.data, path.data);

    (void) njt_ext_rename_file(&tf->file.name, &path, &ext);

    u->store = 0;
}


static void
njt_http_upstream_dummy_handler(njt_http_request_t *r, njt_http_upstream_t *u)
{
    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream dummy handler");
}


static void
njt_http_upstream_next(njt_http_request_t *r, njt_http_upstream_t *u,
    njt_uint_t ft_type)
{
    njt_msec_t  timeout;
    njt_uint_t  status, state;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http next upstream, %xi", ft_type);

    if (u->peer.sockaddr) {

        if (u->peer.connection) {
            u->state->bytes_sent = u->peer.connection->sent;
        }

        if (ft_type == NJT_HTTP_UPSTREAM_FT_HTTP_403
            || ft_type == NJT_HTTP_UPSTREAM_FT_HTTP_404)
        {
            state = NJT_PEER_NEXT;

        } else {
            state = NJT_PEER_FAILED;
        }

        u->peer.free(&u->peer, u->peer.data, state);
        u->peer.sockaddr = NULL;
    }

    if (ft_type == NJT_HTTP_UPSTREAM_FT_TIMEOUT) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, NJT_ETIMEDOUT,
                      "upstream timed out");
    }

    if (u->peer.cached && ft_type == NJT_HTTP_UPSTREAM_FT_ERROR) {
        /* TODO: inform balancer instead */
        u->peer.tries++;
    }

    switch (ft_type) {

    case NJT_HTTP_UPSTREAM_FT_TIMEOUT:
    case NJT_HTTP_UPSTREAM_FT_HTTP_504:
        status = NJT_HTTP_GATEWAY_TIME_OUT;
        break;

    case NJT_HTTP_UPSTREAM_FT_HTTP_500:
        status = NJT_HTTP_INTERNAL_SERVER_ERROR;
        break;

    case NJT_HTTP_UPSTREAM_FT_HTTP_503:
        status = NJT_HTTP_SERVICE_UNAVAILABLE;
        break;

    case NJT_HTTP_UPSTREAM_FT_HTTP_403:
        status = NJT_HTTP_FORBIDDEN;
        break;

    case NJT_HTTP_UPSTREAM_FT_HTTP_404:
        status = NJT_HTTP_NOT_FOUND;
        break;

    case NJT_HTTP_UPSTREAM_FT_HTTP_429:
        status = NJT_HTTP_TOO_MANY_REQUESTS;
        break;

    /*
     * NJT_HTTP_UPSTREAM_FT_BUSY_LOCK and NJT_HTTP_UPSTREAM_FT_MAX_WAITING
     * never reach here
     */

    default:
        status = NJT_HTTP_BAD_GATEWAY;
    }

    if (r->connection->error) {
        njt_http_upstream_finalize_request(r, u,
                                           NJT_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }

    u->state->status = status;

    timeout = u->conf->next_upstream_timeout;

    if (u->request_sent
        && (r->method & (NJT_HTTP_POST|NJT_HTTP_LOCK|NJT_HTTP_PATCH)))
    {
        ft_type |= NJT_HTTP_UPSTREAM_FT_NON_IDEMPOTENT;
    }

    if (u->peer.tries == 0
        || ((u->conf->next_upstream & ft_type) != ft_type)
        || (u->request_sent && r->request_body_no_buffering)
        || (timeout && njt_current_msec - u->peer.start_time >= timeout))
    {
#if (NJT_HTTP_CACHE)

        if (u->cache_status == NJT_HTTP_CACHE_EXPIRED
            && ((u->conf->cache_use_stale & ft_type) || r->cache->stale_error))
        {
            njt_int_t  rc;

            rc = u->reinit_request(r);

            if (rc != NJT_OK) {
                njt_http_upstream_finalize_request(r, u, rc);
                return;
            }

            u->cache_status = NJT_HTTP_CACHE_STALE;
            rc = njt_http_upstream_cache_send(r, u);

            if (rc == NJT_DONE) {
                return;
            }

            if (rc == NJT_HTTP_UPSTREAM_INVALID_HEADER) {
                rc = NJT_HTTP_INTERNAL_SERVER_ERROR;
            }

            njt_http_upstream_finalize_request(r, u, rc);
            return;
        }
#endif

        njt_http_upstream_finalize_request(r, u, status);
        return;
    }

    if (u->peer.connection) {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "close http upstream connection: %d",
                       u->peer.connection->fd);
#if (NJT_HTTP_SSL)

        if (u->peer.connection->ssl) {
            u->peer.connection->ssl->no_wait_shutdown = 1;
            u->peer.connection->ssl->no_send_shutdown = 1;

            (void) njt_ssl_shutdown(u->peer.connection);
        }
#endif

        if (u->peer.connection->pool) {
            njt_destroy_pool(u->peer.connection->pool);
        }

        njt_close_connection(u->peer.connection);
        u->peer.connection = NULL;
    }

    njt_http_upstream_connect(r, u);
}


static void
njt_http_upstream_cleanup(void *data)
{
    njt_http_request_t *r = data;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cleanup http upstream request: \"%V\"", &r->uri);

    njt_http_upstream_finalize_request(r, r->upstream, NJT_DONE);
}


static void
njt_http_upstream_finalize_request(njt_http_request_t *r,
    njt_http_upstream_t *u, njt_int_t rc)
{
    njt_uint_t  flush;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http upstream request: %i", rc);

    if (u->cleanup == NULL) {
        /* the request was already finalized */
        njt_http_finalize_request(r, NJT_DONE);
        return;
    }

    *u->cleanup = NULL;
    u->cleanup = NULL;

    if (u->resolved && u->resolved->ctx) {
        njt_resolve_name_done(u->resolved->ctx);
        u->resolved->ctx = NULL;
    }

    if (u->state && u->state->response_time == (njt_msec_t) -1) {
        u->state->response_time = njt_current_msec - u->start_time;

        if (u->pipe && u->pipe->read_length) {
            u->state->bytes_received += u->pipe->read_length
                                        - u->pipe->preread_size;
            u->state->response_length = u->pipe->read_length;
        }

        if (u->peer.connection) {
            u->state->bytes_sent = u->peer.connection->sent;
        }
    }

    u->finalize_request(r, rc);

    if (u->peer.free && u->peer.sockaddr) {
        u->peer.free(&u->peer, u->peer.data, 0);
        u->peer.sockaddr = NULL;
    }

    if (u->peer.connection) {

#if (NJT_HTTP_SSL)

        /* TODO: do not shutdown persistent connection */

        if (u->peer.connection->ssl) {

            /*
             * We send the "close notify" shutdown alert to the upstream only
             * and do not wait its "close notify" shutdown alert.
             * It is acceptable according to the TLS standard.
             */

            u->peer.connection->ssl->no_wait_shutdown = 1;

            (void) njt_ssl_shutdown(u->peer.connection);
        }
#endif

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "close http upstream connection: %d",
                       u->peer.connection->fd);

        if (u->peer.connection->pool) {
            njt_destroy_pool(u->peer.connection->pool);
        }

        njt_close_connection(u->peer.connection);
    }

    u->peer.connection = NULL;

    if (u->pipe && u->pipe->temp_file) {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http upstream temp fd: %d",
                       u->pipe->temp_file->file.fd);
    }

    if (u->store && u->pipe && u->pipe->temp_file
        && u->pipe->temp_file->file.fd != NJT_INVALID_FILE)
    {
        if (njt_delete_file(u->pipe->temp_file->file.name.data)
            == NJT_FILE_ERROR)
        {
            njt_log_error(NJT_LOG_CRIT, r->connection->log, njt_errno,
                          njt_delete_file_n " \"%s\" failed",
                          u->pipe->temp_file->file.name.data);
        }
    }

#if (NJT_HTTP_CACHE)

    if (r->cache) {

        if (u->cacheable) {

            if (rc == NJT_HTTP_BAD_GATEWAY || rc == NJT_HTTP_GATEWAY_TIME_OUT) {
                time_t  valid;

                valid = njt_http_file_cache_valid(u->conf->cache_valid, rc);

                if (valid) {
                    r->cache->valid_sec = njt_time() + valid;
                    r->cache->error = rc;
                }
            }
        }
	if(u->pipe != NULL) {
        	njt_http_file_cache_free(r->cache, u->pipe->temp_file);
	}
    }

#endif

    r->read_event_handler = njt_http_block_reading;

    if (rc == NJT_DECLINED) {
        return;
    }

    r->connection->log->action = "sending to client";

    if (!u->header_sent
        || rc == NJT_HTTP_REQUEST_TIME_OUT
        || rc == NJT_HTTP_CLIENT_CLOSED_REQUEST)
    {
        njt_http_finalize_request(r, rc);
        return;
    }

    flush = 0;

    if (rc >= NJT_HTTP_SPECIAL_RESPONSE) {
        rc = NJT_ERROR;
        flush = 1;
    }

    if (r->header_only
        || (u->pipe && u->pipe->downstream_error))
    {
        njt_http_finalize_request(r, rc);
        return;
    }

    if (rc == 0) {

        if (njt_http_upstream_process_trailers(r, u) != NJT_OK) {
            njt_http_finalize_request(r, NJT_ERROR);
            return;
        }

        rc = njt_http_send_special(r, NJT_HTTP_LAST);

    } else if (flush) {
        r->keepalive = 0;
        rc = njt_http_send_special(r, NJT_HTTP_FLUSH);
    }

    njt_http_finalize_request(r, rc);
}


static njt_int_t
njt_http_upstream_process_header_line(njt_http_request_t *r, njt_table_elt_t *h,
    njt_uint_t offset)
{
    njt_table_elt_t  **ph;

    ph = (njt_table_elt_t **) ((char *) &r->upstream->headers_in + offset);

    if (*ph) {
        njt_log_error(NJT_LOG_WARN, r->connection->log, 0,
                      "upstream sent duplicate header line: \"%V: %V\", "
                      "previous value: \"%V: %V\", ignored",
                      &h->key, &h->value,
                      &(*ph)->key, &(*ph)->value);
        h->hash = 0;
        return NJT_OK;
    }

    *ph = h;
    h->next = NULL;

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_process_multi_header_lines(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset)
{
    njt_table_elt_t  **ph;

    ph = (njt_table_elt_t **) ((char *) &r->upstream->headers_in + offset);

    while (*ph) { ph = &(*ph)->next; }

    *ph = h;
    h->next = NULL;

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_ignore_header_line(njt_http_request_t *r, njt_table_elt_t *h,
    njt_uint_t offset)
{
    return NJT_OK;
}


static njt_int_t
njt_http_upstream_process_content_length(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset)
{
    njt_http_upstream_t  *u;

    u = r->upstream;

    if (u->headers_in.content_length) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "upstream sent duplicate header line: \"%V: %V\", "
                      "previous value: \"%V: %V\"",
                      &h->key, &h->value,
                      &u->headers_in.content_length->key,
                      &u->headers_in.content_length->value);
        return NJT_HTTP_UPSTREAM_INVALID_HEADER;
    }

    if (u->headers_in.transfer_encoding) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "upstream sent \"Content-Length\" and "
                      "\"Transfer-Encoding\" headers at the same time");
        return NJT_HTTP_UPSTREAM_INVALID_HEADER;
    }

    h->next = NULL;
    u->headers_in.content_length = h;
    u->headers_in.content_length_n = njt_atoof(h->value.data, h->value.len);

    if (u->headers_in.content_length_n == NJT_ERROR) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "upstream sent invalid \"Content-Length\" header: "
                      "\"%V: %V\"", &h->key, &h->value);
        return NJT_HTTP_UPSTREAM_INVALID_HEADER;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_process_last_modified(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset)
{
    njt_http_upstream_t  *u;

    u = r->upstream;

    if (u->headers_in.last_modified) {
        njt_log_error(NJT_LOG_WARN, r->connection->log, 0,
                      "upstream sent duplicate header line: \"%V: %V\", "
                      "previous value: \"%V: %V\", ignored",
                      &h->key, &h->value,
                      &u->headers_in.last_modified->key,
                      &u->headers_in.last_modified->value);
        h->hash = 0;
        return NJT_OK;
    }

    h->next = NULL;
    u->headers_in.last_modified = h;
    u->headers_in.last_modified_time = njt_parse_http_time(h->value.data,
                                                           h->value.len);

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_process_set_cookie(njt_http_request_t *r, njt_table_elt_t *h,
    njt_uint_t offset)
{
    njt_table_elt_t      **ph;
    njt_http_upstream_t   *u;

    u = r->upstream;
    ph = &u->headers_in.set_cookie;

    while (*ph) { ph = &(*ph)->next; }

    *ph = h;
    h->next = NULL;

#if (NJT_HTTP_CACHE)
    if (!(u->conf->ignore_headers & NJT_HTTP_UPSTREAM_IGN_SET_COOKIE)) {
        u->cacheable = 0;
    }
#endif

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_process_cache_control(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset)
{
    njt_table_elt_t      **ph;
    njt_http_upstream_t   *u;

    u = r->upstream;
    ph = &u->headers_in.cache_control;

    while (*ph) { ph = &(*ph)->next; }

    *ph = h;
    h->next = NULL;

#if (NJT_HTTP_CACHE)
    {
    u_char     *p, *start, *last;
    njt_int_t   n;

    if (u->conf->ignore_headers & NJT_HTTP_UPSTREAM_IGN_CACHE_CONTROL) {
        return NJT_OK;
    }

    if (r->cache == NULL) {
        return NJT_OK;
    }

    start = h->value.data;
    last = start + h->value.len;

    if (r->cache->valid_sec != 0 && u->headers_in.x_accel_expires != NULL) {
        goto extensions;
    }

    if (njt_strlcasestrn(start, last, (u_char *) "no-cache", 8 - 1) != NULL
        || njt_strlcasestrn(start, last, (u_char *) "no-store", 8 - 1) != NULL
        || njt_strlcasestrn(start, last, (u_char *) "private", 7 - 1) != NULL)
    {
        u->headers_in.no_cache = 1;
        return NJT_OK;
    }

    p = njt_strlcasestrn(start, last, (u_char *) "s-maxage=", 9 - 1);
    offset = 9;

    if (p == NULL) {
        p = njt_strlcasestrn(start, last, (u_char *) "max-age=", 8 - 1);
        offset = 8;
    }

    if (p) {
        n = 0;

        for (p += offset; p < last; p++) {
            if (*p == ',' || *p == ';' || *p == ' ') {
                break;
            }

            if (*p >= '0' && *p <= '9') {
                n = n * 10 + (*p - '0');
                continue;
            }

            u->cacheable = 0;
            return NJT_OK;
        }

        if (n == 0) {
            u->headers_in.no_cache = 1;
            return NJT_OK;
        }

        r->cache->valid_sec = njt_time() + n;
        u->headers_in.expired = 0;
    }

extensions:

    p = njt_strlcasestrn(start, last, (u_char *) "stale-while-revalidate=",
                         23 - 1);

    if (p) {
        n = 0;

        for (p += 23; p < last; p++) {
            if (*p == ',' || *p == ';' || *p == ' ') {
                break;
            }

            if (*p >= '0' && *p <= '9') {
                n = n * 10 + (*p - '0');
                continue;
            }

            u->cacheable = 0;
            return NJT_OK;
        }

        r->cache->updating_sec = n;
        r->cache->error_sec = n;
    }

    p = njt_strlcasestrn(start, last, (u_char *) "stale-if-error=", 15 - 1);

    if (p) {
        n = 0;

        for (p += 15; p < last; p++) {
            if (*p == ',' || *p == ';' || *p == ' ') {
                break;
            }

            if (*p >= '0' && *p <= '9') {
                n = n * 10 + (*p - '0');
                continue;
            }

            u->cacheable = 0;
            return NJT_OK;
        }

        r->cache->error_sec = n;
    }
    }
#endif

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_process_expires(njt_http_request_t *r, njt_table_elt_t *h,
    njt_uint_t offset)
{
    njt_http_upstream_t  *u;

    u = r->upstream;

    if (u->headers_in.expires) {
        njt_log_error(NJT_LOG_WARN, r->connection->log, 0,
                      "upstream sent duplicate header line: \"%V: %V\", "
                      "previous value: \"%V: %V\", ignored",
                      &h->key, &h->value,
                      &u->headers_in.expires->key,
                      &u->headers_in.expires->value);
        h->hash = 0;
        return NJT_OK;
    }

    u->headers_in.expires = h;
    h->next = NULL;

#if (NJT_HTTP_CACHE)
    {
    time_t  expires;

    if (u->conf->ignore_headers & NJT_HTTP_UPSTREAM_IGN_EXPIRES) {
        return NJT_OK;
    }

    if (r->cache == NULL) {
        return NJT_OK;
    }

    if (r->cache->valid_sec != 0) {
        return NJT_OK;
    }

    expires = njt_parse_http_time(h->value.data, h->value.len);

    if (expires == NJT_ERROR || expires < njt_time()) {
        u->headers_in.expired = 1;
        return NJT_OK;
    }

    r->cache->valid_sec = expires;
    }
#endif

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_process_accel_expires(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset)
{
    njt_http_upstream_t  *u;

    u = r->upstream;

    if (u->headers_in.x_accel_expires) {
        njt_log_error(NJT_LOG_WARN, r->connection->log, 0,
                      "upstream sent duplicate header line: \"%V: %V\", "
                      "previous value: \"%V: %V\", ignored",
                      &h->key, &h->value,
                      &u->headers_in.x_accel_expires->key,
                      &u->headers_in.x_accel_expires->value);
        h->hash = 0;
        return NJT_OK;
    }

    u->headers_in.x_accel_expires = h;
    h->next = NULL;

#if (NJT_HTTP_CACHE)
    {
    u_char     *p;
    size_t      len;
    njt_int_t   n;

    if (u->conf->ignore_headers & NJT_HTTP_UPSTREAM_IGN_XA_EXPIRES) {
        return NJT_OK;
    }

    if (r->cache == NULL) {
        return NJT_OK;
    }

    len = h->value.len;
    p = h->value.data;

    if (p[0] != '@') {
        n = njt_atoi(p, len);

        switch (n) {
        case 0:
            u->cacheable = 0;
            /* fall through */

        case NJT_ERROR:
            return NJT_OK;

        default:
            r->cache->valid_sec = njt_time() + n;
            u->headers_in.no_cache = 0;
            u->headers_in.expired = 0;
            return NJT_OK;
        }
    }

    p++;
    len--;

    n = njt_atoi(p, len);

    if (n != NJT_ERROR) {
        r->cache->valid_sec = n;
        u->headers_in.no_cache = 0;
        u->headers_in.expired = 0;
    }
    }
#endif

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_process_limit_rate(njt_http_request_t *r, njt_table_elt_t *h,
    njt_uint_t offset)
{
    njt_int_t             n;
    njt_http_upstream_t  *u;

    u = r->upstream;

    if (u->headers_in.x_accel_limit_rate) {
        njt_log_error(NJT_LOG_WARN, r->connection->log, 0,
                      "upstream sent duplicate header line: \"%V: %V\", "
                      "previous value: \"%V: %V\", ignored",
                      &h->key, &h->value,
                      &u->headers_in.x_accel_limit_rate->key,
                      &u->headers_in.x_accel_limit_rate->value);
        h->hash = 0;
        return NJT_OK;
    }

    u->headers_in.x_accel_limit_rate = h;
    h->next = NULL;

    if (u->conf->ignore_headers & NJT_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE) {
        return NJT_OK;
    }

    n = njt_atoi(h->value.data, h->value.len);

    if (n != NJT_ERROR) {
        r->limit_rate = (size_t) n;
        r->limit_rate_set = 1;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_process_buffering(njt_http_request_t *r, njt_table_elt_t *h,
    njt_uint_t offset)
{
    u_char                c0, c1, c2;
    njt_http_upstream_t  *u;

    u = r->upstream;

    if (u->conf->ignore_headers & NJT_HTTP_UPSTREAM_IGN_XA_BUFFERING) {
        return NJT_OK;
    }

    if (u->conf->change_buffering) {

        if (h->value.len == 2) {
            c0 = njt_tolower(h->value.data[0]);
            c1 = njt_tolower(h->value.data[1]);

            if (c0 == 'n' && c1 == 'o') {
                u->buffering = 0;
            }

        } else if (h->value.len == 3) {
            c0 = njt_tolower(h->value.data[0]);
            c1 = njt_tolower(h->value.data[1]);
            c2 = njt_tolower(h->value.data[2]);

            if (c0 == 'y' && c1 == 'e' && c2 == 's') {
                u->buffering = 1;
            }
        }
    }

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_process_charset(njt_http_request_t *r, njt_table_elt_t *h,
    njt_uint_t offset)
{
    njt_http_upstream_t  *u;

    u = r->upstream;

    if (u->conf->ignore_headers & NJT_HTTP_UPSTREAM_IGN_XA_CHARSET) {
        return NJT_OK;
    }

    r->headers_out.override_charset = &h->value;

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_process_connection(njt_http_request_t *r, njt_table_elt_t *h,
    njt_uint_t offset)
{
    njt_table_elt_t      **ph;
    njt_http_upstream_t   *u;

    u = r->upstream;
    ph = &u->headers_in.connection;

    while (*ph) { ph = &(*ph)->next; }

    *ph = h;
    h->next = NULL;

    if (njt_strlcasestrn(h->value.data, h->value.data + h->value.len,
                         (u_char *) "close", 5 - 1)
        != NULL)
    {
        u->headers_in.connection_close = 1;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_process_transfer_encoding(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset)
{
    njt_http_upstream_t  *u;

    u = r->upstream;

    if (u->headers_in.transfer_encoding) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "upstream sent duplicate header line: \"%V: %V\", "
                      "previous value: \"%V: %V\"",
                      &h->key, &h->value,
                      &u->headers_in.transfer_encoding->key,
                      &u->headers_in.transfer_encoding->value);
        return NJT_HTTP_UPSTREAM_INVALID_HEADER;
    }

    if (u->headers_in.content_length) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "upstream sent \"Content-Length\" and "
                      "\"Transfer-Encoding\" headers at the same time");
        return NJT_HTTP_UPSTREAM_INVALID_HEADER;
    }

    u->headers_in.transfer_encoding = h;
    h->next = NULL;

    if (h->value.len == 7
        && njt_strncasecmp(h->value.data, (u_char *) "chunked", 7) == 0)
    {
        u->headers_in.chunked = 1;

    } else {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "upstream sent unknown \"Transfer-Encoding\": \"%V\"",
                      &h->value);
        return NJT_HTTP_UPSTREAM_INVALID_HEADER;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_process_vary(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset)
{
    njt_table_elt_t      **ph;
    njt_http_upstream_t   *u;

    u = r->upstream;
    ph = &u->headers_in.vary;

    while (*ph) { ph = &(*ph)->next; }

    *ph = h;
    h->next = NULL;

#if (NJT_HTTP_CACHE)
    {
    u_char     *p;
    size_t      len;
    njt_str_t   vary;

    if (u->conf->ignore_headers & NJT_HTTP_UPSTREAM_IGN_VARY) {
        return NJT_OK;
    }

    if (r->cache == NULL || !u->cacheable) {
        return NJT_OK;
    }

    if (h->value.len == 1 && h->value.data[0] == '*') {
        u->cacheable = 0;
        return NJT_OK;
    }

    if (u->headers_in.vary->next) {

        len = 0;

        for (h = u->headers_in.vary; h; h = h->next) {
            len += h->value.len + 2;
        }

        len -= 2;

        p = njt_pnalloc(r->pool, len);
        if (p == NULL) {
            return NJT_ERROR;
        }

        vary.len = len;
        vary.data = p;

        for (h = u->headers_in.vary; h; h = h->next) {
            p = njt_copy(p, h->value.data, h->value.len);

            if (h->next == NULL) {
                break;
            }

            *p++ = ','; *p++ = ' ';
        }

    } else {
        vary = h->value;
    }

    if (vary.len > NJT_HTTP_CACHE_VARY_LEN) {
        u->cacheable = 0;
    }

    r->cache->vary = vary;
    }
#endif

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_copy_header_line(njt_http_request_t *r, njt_table_elt_t *h,
    njt_uint_t offset)
{
    njt_table_elt_t  *ho, **ph;

    ho = njt_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NJT_ERROR;
    }

    *ho = *h;

    if (offset) {
        ph = (njt_table_elt_t **) ((char *) &r->headers_out + offset);
        *ph = ho;
        ho->next = NULL;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_copy_multi_header_lines(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset)
{
    njt_table_elt_t  *ho, **ph;

    ho = njt_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NJT_ERROR;
    }

    *ho = *h;

    ph = (njt_table_elt_t **) ((char *) &r->headers_out + offset);

    while (*ph) { ph = &(*ph)->next; }

    *ph = ho;
    ho->next = NULL;

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_copy_content_type(njt_http_request_t *r, njt_table_elt_t *h,
    njt_uint_t offset)
{
    u_char  *p, *last;

    r->headers_out.content_type_len = h->value.len;
    r->headers_out.content_type = h->value;
    r->headers_out.content_type_lowcase = NULL;

    for (p = h->value.data; *p; p++) {

        if (*p != ';') {
            continue;
        }

        last = p;

        while (*++p == ' ') { /* void */ }

        if (*p == '\0') {
            return NJT_OK;
        }

        if (njt_strncasecmp(p, (u_char *) "charset=", 8) != 0) {
            continue;
        }

        p += 8;

        r->headers_out.content_type_len = last - h->value.data;

        if (*p == '"') {
            p++;
        }

        last = h->value.data + h->value.len;

        if (*(last - 1) == '"') {
            last--;
        }

        r->headers_out.charset.len = last - p;
        r->headers_out.charset.data = p;

        return NJT_OK;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_copy_last_modified(njt_http_request_t *r, njt_table_elt_t *h,
    njt_uint_t offset)
{
    njt_table_elt_t  *ho;

    ho = njt_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NJT_ERROR;
    }

    *ho = *h;
    ho->next = NULL;

    r->headers_out.last_modified = ho;
    r->headers_out.last_modified_time =
                                    r->upstream->headers_in.last_modified_time;

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_rewrite_location(njt_http_request_t *r, njt_table_elt_t *h,
    njt_uint_t offset)
{
    njt_int_t         rc;
    njt_table_elt_t  *ho;

    ho = njt_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NJT_ERROR;
    }

    *ho = *h;
    ho->next = NULL;

    if (r->upstream->rewrite_redirect) {
        rc = r->upstream->rewrite_redirect(r, ho, 0);

        if (rc == NJT_DECLINED) {
            return NJT_OK;
        }

        if (rc == NJT_OK) {
            r->headers_out.location = ho;

            njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "rewritten location: \"%V\"", &ho->value);
        }

        return rc;
    }

    if (ho->value.data[0] != '/') {
        r->headers_out.location = ho;
    }

    /*
     * we do not set r->headers_out.location here to avoid handling
     * relative redirects in njt_http_header_filter()
     */

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_rewrite_refresh(njt_http_request_t *r, njt_table_elt_t *h,
    njt_uint_t offset)
{
    u_char           *p;
    njt_int_t         rc;
    njt_table_elt_t  *ho;

    ho = njt_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NJT_ERROR;
    }

    *ho = *h;
    ho->next = NULL;

    if (r->upstream->rewrite_redirect) {

        p = njt_strcasestrn(ho->value.data, "url=", 4 - 1);

        if (p) {
            rc = r->upstream->rewrite_redirect(r, ho, p + 4 - ho->value.data);

        } else {
            return NJT_OK;
        }

        if (rc == NJT_DECLINED) {
            return NJT_OK;
        }

        if (rc == NJT_OK) {
            r->headers_out.refresh = ho;

            njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "rewritten refresh: \"%V\"", &ho->value);
        }

        return rc;
    }

    r->headers_out.refresh = ho;

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_rewrite_set_cookie(njt_http_request_t *r, njt_table_elt_t *h,
    njt_uint_t offset)
{
    njt_int_t         rc;
    njt_table_elt_t  *ho;

    ho = njt_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NJT_ERROR;
    }

    *ho = *h;
    ho->next = NULL;

    if (r->upstream->rewrite_cookie) {
        rc = r->upstream->rewrite_cookie(r, ho);

        if (rc == NJT_DECLINED) {
            return NJT_OK;
        }

#if (NJT_DEBUG)
        if (rc == NJT_OK) {
            njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "rewritten cookie: \"%V\"", &ho->value);
        }
#endif

        return rc;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_copy_allow_ranges(njt_http_request_t *r,
    njt_table_elt_t *h, njt_uint_t offset)
{
    njt_table_elt_t  *ho;

    if (r->upstream->conf->force_ranges) {
        return NJT_OK;
    }

#if (NJT_HTTP_CACHE)

    if (r->cached) {
        r->allow_ranges = 1;
        return NJT_OK;
    }

    if (r->upstream->cacheable) {
        r->allow_ranges = 1;
        r->single_range = 1;
        return NJT_OK;
    }

#endif

    ho = njt_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NJT_ERROR;
    }

    *ho = *h;
    ho->next = NULL;

    r->headers_out.accept_ranges = ho;

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_add_variables(njt_conf_t *cf)
{
    njt_http_variable_t  *var, *v;

    for (v = njt_http_upstream_vars; v->name.len; v++) {
        var = njt_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NJT_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_addr_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    size_t                      len;
    njt_uint_t                  i;
    njt_http_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
        v->not_found = 1;
        return NJT_OK;
    }

    len = 0;
    state = r->upstream_states->elts;

    for (i = 0; i < r->upstream_states->nelts; i++) {
        if (state[i].peer) {
            len += state[i].peer->len + 2;

        } else {
            len += 3;
        }
    }

    p = njt_pnalloc(r->pool, len);
    if (p == NULL) {
        return NJT_ERROR;
    }

    v->data = p;

    i = 0;

    for ( ;; ) {
        if (state[i].peer) {
            p = njt_cpymem(p, state[i].peer->data, state[i].peer->len);
        }

        if (++i == r->upstream_states->nelts) {
            break;
        }

        if (state[i].peer) {
            *p++ = ',';
            *p++ = ' ';

        } else {
            *p++ = ' ';
            *p++ = ':';
            *p++ = ' ';

            if (++i == r->upstream_states->nelts) {
                break;
            }

            continue;
        }
    }

    v->len = p - v->data;

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_status_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    size_t                      len;
    njt_uint_t                  i;
    njt_http_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
        v->not_found = 1;
        return NJT_OK;
    }

    len = r->upstream_states->nelts * (3 + 2);

    p = njt_pnalloc(r->pool, len);
    if (p == NULL) {
        return NJT_ERROR;
    }

    v->data = p;

    i = 0;
    state = r->upstream_states->elts;

    for ( ;; ) {
        if (state[i].status) {
            p = njt_sprintf(p, "%ui", state[i].status);

        } else {
            *p++ = '-';
        }

        if (++i == r->upstream_states->nelts) {
            break;
        }

        if (state[i].peer) {
            *p++ = ',';
            *p++ = ' ';

        } else {
            *p++ = ' ';
            *p++ = ':';
            *p++ = ' ';

            if (++i == r->upstream_states->nelts) {
                break;
            }

            continue;
        }
    }

    v->len = p - v->data;

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_response_time_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    size_t                      len;
    njt_uint_t                  i;
    njt_msec_int_t              ms;
    njt_http_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
        v->not_found = 1;
        return NJT_OK;
    }

    len = r->upstream_states->nelts * (NJT_TIME_T_LEN + 4 + 2);

    p = njt_pnalloc(r->pool, len);
    if (p == NULL) {
        return NJT_ERROR;
    }

    v->data = p;

    i = 0;
    state = r->upstream_states->elts;

    for ( ;; ) {

        if (data == 1) {
            ms = state[i].header_time;

        } else if (data == 2) {
            ms = state[i].connect_time;

        } else {
            ms = state[i].response_time;
        }

        if (ms != -1) {
            ms = njt_max(ms, 0);
            p = njt_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000);

        } else {
            *p++ = '-';
        }

        if (++i == r->upstream_states->nelts) {
            break;
        }

        if (state[i].peer) {
            *p++ = ',';
            *p++ = ' ';

        } else {
            *p++ = ' ';
            *p++ = ':';
            *p++ = ' ';

            if (++i == r->upstream_states->nelts) {
                break;
            }

            continue;
        }
    }

    v->len = p - v->data;

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_response_length_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    size_t                      len;
    njt_uint_t                  i;
    njt_http_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
        v->not_found = 1;
        return NJT_OK;
    }

    len = r->upstream_states->nelts * (NJT_OFF_T_LEN + 2);

    p = njt_pnalloc(r->pool, len);
    if (p == NULL) {
        return NJT_ERROR;
    }

    v->data = p;

    i = 0;
    state = r->upstream_states->elts;

    for ( ;; ) {

        if (data == 1) {
            p = njt_sprintf(p, "%O", state[i].bytes_received);

        } else if (data == 2) {
            p = njt_sprintf(p, "%O", state[i].bytes_sent);

        } else {
            p = njt_sprintf(p, "%O", state[i].response_length);
        }

        if (++i == r->upstream_states->nelts) {
            break;
        }

        if (state[i].peer) {
            *p++ = ',';
            *p++ = ' ';

        } else {
            *p++ = ' ';
            *p++ = ':';
            *p++ = ' ';

            if (++i == r->upstream_states->nelts) {
                break;
            }

            continue;
        }
    }

    v->len = p - v->data;

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_header_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    if (r->upstream == NULL) {
        v->not_found = 1;
        return NJT_OK;
    }

    return njt_http_variable_unknown_header(r, v, (njt_str_t *) data,
                                         &r->upstream->headers_in.headers.part,
                                         sizeof("upstream_http_") - 1);
}


static njt_int_t
njt_http_upstream_trailer_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    if (r->upstream == NULL) {
        v->not_found = 1;
        return NJT_OK;
    }

    return njt_http_variable_unknown_header(r, v, (njt_str_t *) data,
                                        &r->upstream->headers_in.trailers.part,
                                        sizeof("upstream_trailer_") - 1);
}


static njt_int_t
njt_http_upstream_cookie_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_str_t  *name = (njt_str_t *) data;

    njt_str_t   cookie, s;

    if (r->upstream == NULL) {
        v->not_found = 1;
        return NJT_OK;
    }

    s.len = name->len - (sizeof("upstream_cookie_") - 1);
    s.data = name->data + sizeof("upstream_cookie_") - 1;

    if (njt_http_parse_set_cookie_lines(r, r->upstream->headers_in.set_cookie,
                                        &s, &cookie)
        == NULL)
    {
        v->not_found = 1;
        return NJT_OK;
    }

    v->len = cookie.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = cookie.data;

    return NJT_OK;
}


#if (NJT_HTTP_CACHE)

static njt_int_t
njt_http_upstream_cache_status(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_uint_t  n;

    if (r->upstream == NULL || r->upstream->cache_status == 0) {
        v->not_found = 1;
        return NJT_OK;
    }

    n = r->upstream->cache_status - 1;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = njt_http_cache_status[n].len;
    v->data = njt_http_cache_status[n].data;

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_cache_last_modified(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    if (r->upstream == NULL
        || !r->upstream->conf->cache_revalidate
        || r->upstream->cache_status != NJT_HTTP_CACHE_EXPIRED
        || r->cache->last_modified == -1)
    {
        v->not_found = 1;
        return NJT_OK;
    }

    p = njt_pnalloc(r->pool, sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1);
    if (p == NULL) {
        return NJT_ERROR;
    }

    v->len = njt_http_time(p, r->cache->last_modified) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NJT_OK;
}


static njt_int_t
njt_http_upstream_cache_etag(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    if (r->upstream == NULL
        || !r->upstream->conf->cache_revalidate
        || r->upstream->cache_status != NJT_HTTP_CACHE_EXPIRED
        || r->cache->etag.len == 0)
    {
        v->not_found = 1;
        return NJT_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = r->cache->etag.len;
    v->data = r->cache->etag.data;

    return NJT_OK;
}

#endif


static char *
njt_http_upstream(njt_conf_t *cf, njt_command_t *cmd, void *dummy)
{
    char                          *rv;
    void                          *mconf;
    njt_str_t                     *value;
    njt_url_t                      u;
    njt_uint_t                     m;
    njt_conf_t                     pcf;
    njt_http_module_t             *module;
    njt_http_conf_ctx_t           *ctx, *http_ctx;
    njt_http_upstream_srv_conf_t  *uscf;

    njt_memzero(&u, sizeof(njt_url_t));

    value = cf->args->elts;
    u.host = value[1];
    u.no_resolve = 1;
    u.no_port = 1;

    uscf = njt_http_upstream_add(cf, &u, NJT_HTTP_UPSTREAM_CREATE
                                         |NJT_HTTP_UPSTREAM_WEIGHT
                                         |NJT_HTTP_UPSTREAM_MAX_CONNS
                                         |NJT_HTTP_UPSTREAM_MAX_FAILS
                                         |NJT_HTTP_UPSTREAM_FAIL_TIMEOUT
                                         |NJT_HTTP_UPSTREAM_DOWN
                                         |NJT_HTTP_UPSTREAM_BACKUP
					 |NJT_HTTP_UPSTREAM_SLOW_START);
    if (uscf == NULL) {
        return NJT_CONF_ERROR;
    }


    ctx = njt_pcalloc(cf->pool, sizeof(njt_http_conf_ctx_t));
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }

    http_ctx = cf->ctx;
    ctx->main_conf = http_ctx->main_conf;

    /* the upstream{}'s srv_conf */

    ctx->srv_conf = njt_pcalloc(cf->pool, sizeof(void *) * njt_http_max_module);
    if (ctx->srv_conf == NULL) {
        return NJT_CONF_ERROR;
    }

    ctx->srv_conf[njt_http_upstream_module.ctx_index] = uscf;

    uscf->srv_conf = ctx->srv_conf;


    /* the upstream{}'s loc_conf */

    ctx->loc_conf = njt_pcalloc(cf->pool, sizeof(void *) * njt_http_max_module);
    if (ctx->loc_conf == NULL) {
        return NJT_CONF_ERROR;
    }
    // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
    njt_pool_t *old_pool,*new_pool,*old_temp_pool;
    njt_int_t rc;

    old_pool = cf->pool;
    old_temp_pool = cf->temp_pool;
    new_pool = njt_create_dynamic_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
    if (new_pool == NULL) {
        return NJT_CONF_ERROR;
    }
    rc = njt_sub_pool(cf->cycle->pool,new_pool);
    if (rc != NJT_OK) {
        return NJT_CONF_ERROR;
    }
#endif
    //end
    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NJT_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return NJT_CONF_ERROR;
            }

            ctx->srv_conf[cf->cycle->modules[m]->ctx_index] = mconf;
        }
        // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
        cf->pool = new_pool;
        cf->temp_pool = new_pool;
#endif
        //end
        if (module->create_loc_conf) {
            mconf = module->create_loc_conf(cf);
            if (mconf == NULL) {
                return NJT_CONF_ERROR;
            }

            ctx->loc_conf[cf->cycle->modules[m]->ctx_index] = mconf;
        }
        // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
        cf->pool = old_pool;
        cf->temp_pool = old_temp_pool;
#endif
        //end
    }

    uscf->servers = njt_array_create(cf->pool, 4,
                                     sizeof(njt_http_upstream_server_t));
    if (uscf->servers == NULL) {
        return NJT_CONF_ERROR;
    }


    /* parse inside upstream{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NJT_HTTP_UPS_CONF;

    rv = njt_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv != NJT_CONF_OK) {
        return rv;
    }
   /*
    if (uscf->servers->nelts == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "no servers are inside upstream");
        return NJT_CONF_ERROR;
    }*/

    return rv;
}

/*
static char *
njt_http_upstream_server(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_upstream_srv_conf_t  *uscf = conf;

    time_t                       fail_timeout;
    njt_str_t                   *value, s;
    njt_url_t                    u;
    njt_int_t                    weight, max_conns, max_fails;
    njt_uint_t                   i;
    njt_http_upstream_server_t  *us;

    us = njt_array_push(uscf->servers);
    if (us == NULL) {
        return NJT_CONF_ERROR;
    }

    njt_memzero(us, sizeof(njt_http_upstream_server_t));

    value = cf->args->elts;

    weight = 1;
    max_conns = 0;
    max_fails = 1;
    fail_timeout = 10;

    for (i = 2; i < cf->args->nelts; i++) {

        if (njt_strncmp(value[i].data, "weight=", 7) == 0) {

            if (!(uscf->flags & NJT_HTTP_UPSTREAM_WEIGHT)) {
                goto not_supported;
            }

            weight = njt_atoi(&value[i].data[7], value[i].len - 7);

            if (weight == NJT_ERROR || weight == 0) {
                goto invalid;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "max_conns=", 10) == 0) {

            if (!(uscf->flags & NJT_HTTP_UPSTREAM_MAX_CONNS)) {
                goto not_supported;
            }

            max_conns = njt_atoi(&value[i].data[10], value[i].len - 10);

            if (max_conns == NJT_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "max_fails=", 10) == 0) {

            if (!(uscf->flags & NJT_HTTP_UPSTREAM_MAX_FAILS)) {
                goto not_supported;
            }

            max_fails = njt_atoi(&value[i].data[10], value[i].len - 10);

            if (max_fails == NJT_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "fail_timeout=", 13) == 0) {

            if (!(uscf->flags & NJT_HTTP_UPSTREAM_FAIL_TIMEOUT)) {
                goto not_supported;
            }

            s.len = value[i].len - 13;
            s.data = &value[i].data[13];

            fail_timeout = njt_parse_time(&s, 1);

            if (fail_timeout == (time_t) NJT_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (njt_strcmp(value[i].data, "backup") == 0) {

            if (!(uscf->flags & NJT_HTTP_UPSTREAM_BACKUP)) {
                goto not_supported;
            }

            us->backup = 1;

            continue;
        }

        if (njt_strcmp(value[i].data, "down") == 0) {

            if (!(uscf->flags & NJT_HTTP_UPSTREAM_DOWN)) {
                goto not_supported;
            }

            us->down = 1;

            continue;
        }

        goto invalid;
    }

    njt_memzero(&u, sizeof(njt_url_t));

    u.url = value[1];
    u.default_port = 80;

    if (njt_parse_url(cf->pool, &u) != NJT_OK) {
        if (u.err) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "%s in upstream \"%V\"", u.err, &u.url);
        }

        return NJT_CONF_ERROR;
    }

    us->name = u.url;
    us->addrs = u.addrs;
    us->naddrs = u.naddrs;
    us->weight = weight;
    us->max_conns = max_conns;
    us->max_fails = max_fails;
    us->fail_timeout = fail_timeout;

    return NJT_CONF_OK;

invalid:

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);

    return NJT_CONF_ERROR;

not_supported:

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "balancing method does not support parameter \"%V\"",
                       &value[i]);

    return NJT_CONF_ERROR;
}*/


njt_http_upstream_srv_conf_t *
njt_http_upstream_add(njt_conf_t *cf, njt_url_t *u, njt_uint_t flags)
{
    njt_uint_t                      i;
    njt_http_upstream_server_t     *us;
    njt_http_upstream_srv_conf_t   *uscf, **uscfp;
    njt_http_upstream_main_conf_t  *umcf;
#if (NJT_HTTP_DYNAMIC_UPSTREAM)
     njt_int_t rc;
    njt_pool_t                     *old_pool;
    njt_http_upstream_init_pt       init;  
    njt_pool_t  *new_pool = njt_create_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
    if (NULL == new_pool) {
        return NULL;
    }
    old_pool = cf->pool;
    cf->pool = new_pool;
#endif
    if (!(flags & NJT_HTTP_UPSTREAM_CREATE)) {

        if (njt_parse_url(cf->pool, u) != NJT_OK) {
            if (u->err) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "%s in upstream \"%V\"", u->err, &u->url);
            }

            goto error;
        }
    }

    umcf = njt_http_conf_get_module_main_conf(cf, njt_http_upstream_module);

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        if (uscfp[i]->host.len != u->host.len
            || njt_strncasecmp(uscfp[i]->host.data, u->host.data, u->host.len)
               != 0)
        {
            continue;
        }

        if ((flags & NJT_HTTP_UPSTREAM_CREATE)
             && (uscfp[i]->flags & NJT_HTTP_UPSTREAM_CREATE))
        {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "duplicate upstream \"%V\"", &u->host);
             goto error;
        }

        if ((uscfp[i]->flags & NJT_HTTP_UPSTREAM_CREATE) && !u->no_port) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "upstream \"%V\" may not have port %d",
                               &u->host, u->port);
             goto error;
        }

        if ((flags & NJT_HTTP_UPSTREAM_CREATE) && !uscfp[i]->no_port) {
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "upstream \"%V\" may not have port %d in %s:%ui",
                          &u->host, uscfp[i]->port,
                          uscfp[i]->file_name, uscfp[i]->line);
             goto error;
        }

        if (uscfp[i]->port && u->port
            && uscfp[i]->port != u->port)
        {
            continue;
        }

        if (flags & NJT_HTTP_UPSTREAM_CREATE) {
            uscfp[i]->flags = flags;
            uscfp[i]->port = 0;
        }
#if (NJT_HTTP_DYNAMIC_UPSTREAM)
      cf->pool = old_pool;
     njt_destroy_pool(new_pool);
     uscfp[i]->ref_count ++;
#endif
        return uscfp[i];
    }

    uscf = njt_pcalloc(cf->pool, sizeof(njt_http_upstream_srv_conf_t));
    if (uscf == NULL) {
         goto error;
    }

    uscf->flags = flags;
    uscf->host = u->host;
    uscf->file_name = cf->conf_file->file.name.data;
    uscf->line = cf->conf_file->line;
    uscf->port = u->port;
    uscf->no_port = u->no_port;
  

    if (u->naddrs == 1 && (u->port || u->family == AF_UNIX)) {
        uscf->servers = njt_array_create(cf->pool, 1,
                                         sizeof(njt_http_upstream_server_t));
        if (uscf->servers == NULL) {
             goto error;
        }

        us = njt_array_push(uscf->servers);
        if (us == NULL) {
             goto error;
        }

        njt_memzero(us, sizeof(njt_http_upstream_server_t));

        us->addrs = u->addrs;
        us->naddrs = 1;
    }
#if (NJT_HTTP_DYNAMIC_UPSTREAM)
    uscf->ref_count = 1;
    uscf->pool = new_pool;
    njt_str_copy_pool(new_pool,uscf->host,u->host,goto error);
   if(cf->dynamic == 1) {
   init = njt_http_upstream_init_round_robin;
    if (init(cf,uscf) != NJT_OK) {
            goto error;
    } 
   }
    rc = njt_sub_pool(cf->cycle->pool,new_pool);
    if (rc != NJT_OK) {
         goto error;
    }
    cf->pool = old_pool;
#endif
    uscfp = njt_array_push(&umcf->upstreams);
    if (uscfp == NULL) {
         goto error;
    }

    *uscfp = uscf;
    return uscf;


error:
#if (NJT_HTTP_DYNAMIC_UPSTREAM)
     cf->pool = old_pool;
     njt_destroy_pool(new_pool);
#endif
     return NULL;

}


char *
njt_http_upstream_bind_set_slot(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    njt_int_t                           rc;
    njt_str_t                          *value;
    njt_http_complex_value_t            cv;
    njt_http_upstream_local_t         **plocal, *local;
    njt_http_compile_complex_value_t    ccv;

    plocal = (njt_http_upstream_local_t **) (p + cmd->offset);

    if (*plocal != NJT_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2 && njt_strcmp(value[1].data, "off") == 0) {
        *plocal = NULL;
        return NJT_CONF_OK;
    }

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    local = njt_pcalloc(cf->pool, sizeof(njt_http_upstream_local_t));
    if (local == NULL) {
        return NJT_CONF_ERROR;
    }

    *plocal = local;

    if (cv.lengths) {
        local->value = njt_palloc(cf->pool, sizeof(njt_http_complex_value_t));
        if (local->value == NULL) {
            return NJT_CONF_ERROR;
        }

        *local->value = cv;

    } else {
        local->addr = njt_palloc(cf->pool, sizeof(njt_addr_t));
        if (local->addr == NULL) {
            return NJT_CONF_ERROR;
        }

        rc = njt_parse_addr_port(cf->pool, local->addr, value[1].data,
                                 value[1].len);

        switch (rc) {
        case NJT_OK:
            local->addr->name = value[1];
            break;

        case NJT_DECLINED:
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid address \"%V\"", &value[1]);
            /* fall through */

        default:
            return NJT_CONF_ERROR;
        }
    }

    if (cf->args->nelts > 2) {
        if (njt_strcmp(value[2].data, "transparent") == 0) {
#if (NJT_HAVE_TRANSPARENT_PROXY)
            njt_core_conf_t  *ccf;

            ccf = (njt_core_conf_t *) njt_get_conf(cf->cycle->conf_ctx,
                                                   njt_core_module);

            ccf->transparent = 1;
            local->transparent = 1;
#else
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "transparent proxying is not supported "
                               "on this platform, ignored");
#endif
        } else {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return NJT_CONF_ERROR;
        }
    }

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_upstream_set_local(njt_http_request_t *r, njt_http_upstream_t *u,
    njt_http_upstream_local_t *local)
{
    njt_int_t    rc;
    njt_str_t    val;
    njt_addr_t  *addr;

    if (local == NULL) {
        u->peer.local = NULL;
        return NJT_OK;
    }

#if (NJT_HAVE_TRANSPARENT_PROXY)
    u->peer.transparent = local->transparent;
#endif

    if (local->value == NULL) {
        u->peer.local = local->addr;
        return NJT_OK;
    }

    if (njt_http_complex_value(r, local->value, &val) != NJT_OK) {
        return NJT_ERROR;
    }

    if (val.len == 0) {
        return NJT_OK;
    }

    addr = njt_palloc(r->pool, sizeof(njt_addr_t));
    if (addr == NULL) {
        return NJT_ERROR;
    }

    rc = njt_parse_addr_port(r->pool, addr, val.data, val.len);
    if (rc == NJT_ERROR) {
        return NJT_ERROR;
    }

    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "invalid local address \"%V\"", &val);
        return NJT_OK;
    }

    addr->name = val;
    u->peer.local = addr;

    return NJT_OK;
}


char *
njt_http_upstream_param_set_slot(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    njt_str_t                   *value;
    njt_array_t                **a;
    njt_http_upstream_param_t   *param;

    a = (njt_array_t **) (p + cmd->offset);

    if (*a == NULL) {
        *a = njt_array_create(cf->pool, 4, sizeof(njt_http_upstream_param_t));
        if (*a == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    param = njt_array_push(*a);
    if (param == NULL) {
        return NJT_CONF_ERROR;
    }

    value = cf->args->elts;

    param->key = value[1];
    param->value = value[2];
    param->skip_empty = 0;

    if (cf->args->nelts == 4) {
        if (njt_strcmp(value[3].data, "if_not_empty") != 0) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[3]);
            return NJT_CONF_ERROR;
        }

        param->skip_empty = 1;
    }

    return NJT_CONF_OK;
}


njt_int_t
njt_http_upstream_hide_headers_hash(njt_conf_t *cf,
    njt_http_upstream_conf_t *conf, njt_http_upstream_conf_t *prev,
    njt_str_t *default_hide_headers, njt_hash_init_t *hash)
{
    njt_str_t       *h;
    njt_uint_t       i, j;
    njt_array_t      hide_headers;
    njt_hash_key_t  *hk;

    if (conf->hide_headers == NJT_CONF_UNSET_PTR
        && conf->pass_headers == NJT_CONF_UNSET_PTR)
    {
        conf->hide_headers = prev->hide_headers;
        conf->pass_headers = prev->pass_headers;

        conf->hide_headers_hash = prev->hide_headers_hash;

        if (conf->hide_headers_hash.buckets) {
            return NJT_OK;
        }

    } else {
        if (conf->hide_headers == NJT_CONF_UNSET_PTR) {
            conf->hide_headers = prev->hide_headers;
        }

        if (conf->pass_headers == NJT_CONF_UNSET_PTR) {
            conf->pass_headers = prev->pass_headers;
        }
    }

    if (njt_array_init(&hide_headers, cf->temp_pool, 4, sizeof(njt_hash_key_t))
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    for (h = default_hide_headers; h->len; h++) {
        hk = njt_array_push(&hide_headers);
        if (hk == NULL) {
            return NJT_ERROR;
        }

        hk->key = *h;
        hk->key_hash = njt_hash_key_lc(h->data, h->len);
        hk->value = (void *) 1;
    }

    if (conf->hide_headers != NJT_CONF_UNSET_PTR) {

        h = conf->hide_headers->elts;

        for (i = 0; i < conf->hide_headers->nelts; i++) {

            hk = hide_headers.elts;

            for (j = 0; j < hide_headers.nelts; j++) {
                if (njt_strcasecmp(h[i].data, hk[j].key.data) == 0) {
                    goto exist;
                }
            }

            hk = njt_array_push(&hide_headers);
            if (hk == NULL) {
                return NJT_ERROR;
            }

            hk->key = h[i];
            hk->key_hash = njt_hash_key_lc(h[i].data, h[i].len);
            hk->value = (void *) 1;

        exist:

            continue;
        }
    }

    if (conf->pass_headers != NJT_CONF_UNSET_PTR) {

        h = conf->pass_headers->elts;
        hk = hide_headers.elts;

        for (i = 0; i < conf->pass_headers->nelts; i++) {
            for (j = 0; j < hide_headers.nelts; j++) {

                if (hk[j].key.data == NULL) {
                    continue;
                }

                if (njt_strcasecmp(h[i].data, hk[j].key.data) == 0) {
                    hk[j].key.data = NULL;
                    break;
                }
            }
        }
    }

    hash->hash = &conf->hide_headers_hash;
    hash->key = njt_hash_key_lc;
    hash->pool = cf->pool;
    hash->temp_pool = NULL;

    if (njt_hash_init(hash, hide_headers.elts, hide_headers.nelts) != NJT_OK) {
        return NJT_ERROR;
    }

    /*
     * special handling to preserve conf->hide_headers_hash
     * in the "http" section to inherit it to all servers
     */

    if (prev->hide_headers_hash.buckets == NULL
        && conf->hide_headers == prev->hide_headers
        && conf->pass_headers == prev->pass_headers)
    {
        prev->hide_headers_hash = conf->hide_headers_hash;
    }

    return NJT_OK;
}


static void *
njt_http_upstream_create_main_conf(njt_conf_t *cf)
{
    njt_http_upstream_main_conf_t  *umcf;

    umcf = njt_pcalloc(cf->pool, sizeof(njt_http_upstream_main_conf_t));
    if (umcf == NULL) {
        return NULL;
    }

    if (njt_array_init(&umcf->upstreams, cf->pool, 4,
                       sizeof(njt_http_upstream_srv_conf_t *))
        != NJT_OK)
    {
        return NULL;
    }

    return umcf;
}


static char *
njt_http_upstream_init_main_conf(njt_conf_t *cf, void *conf)
{
    njt_http_upstream_main_conf_t  *umcf = conf;

    njt_uint_t                      i;
    njt_array_t                     headers_in;
    njt_hash_key_t                 *hk;
    njt_hash_init_t                 hash;
    njt_http_upstream_init_pt       init;
    njt_http_upstream_header_t     *header;
    njt_http_upstream_srv_conf_t  **uscfp;

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        init = uscfp[i]->peer.init_upstream ? uscfp[i]->peer.init_upstream:
                                            njt_http_upstream_init_round_robin;

        if (init(cf, uscfp[i]) != NJT_OK) {
            return NJT_CONF_ERROR;
        }
    }


    /* upstream_headers_in_hash */

    if (njt_array_init(&headers_in, cf->temp_pool, 32, sizeof(njt_hash_key_t))
        != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    for (header = njt_http_upstream_headers_in; header->name.len; header++) {
        hk = njt_array_push(&headers_in);
        if (hk == NULL) {
            return NJT_CONF_ERROR;
        }

        hk->key = header->name;
        hk->key_hash = njt_hash_key_lc(header->name.data, header->name.len);
        hk->value = header;
    }

    hash.hash = &umcf->headers_in_hash;
    hash.key = njt_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = njt_align(64, njt_cacheline_size);
    hash.name = "upstream_headers_in_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (njt_hash_init(&hash, headers_in.elts, headers_in.nelts) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}



