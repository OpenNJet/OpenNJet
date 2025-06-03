
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 * Copyright (C) 2024 JD Technology Information Technology Co., Ltd.
 * Copyright (C) 2023 Web Server LLC
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_http_proxy_module.h>
#include <njt_http_util.h>

#if (NJT_HTTP_FAULT_INJECT)
#include <njt_http_fault_inject_module.h>
#endif

#if (NJT_HTTP_V3 && NJT_QUIC_OPENSSL_COMPAT)
#include <njt_event_quic_openssl_compat.h>
#endif

#define  NJT_HTTP_PROXY_COOKIE_SECURE           0x0001
#define  NJT_HTTP_PROXY_COOKIE_SECURE_ON        0x0002
#define  NJT_HTTP_PROXY_COOKIE_SECURE_OFF       0x0004
#define  NJT_HTTP_PROXY_COOKIE_HTTPONLY         0x0008
#define  NJT_HTTP_PROXY_COOKIE_HTTPONLY_ON      0x0010
#define  NJT_HTTP_PROXY_COOKIE_HTTPONLY_OFF     0x0020
#define  NJT_HTTP_PROXY_COOKIE_SAMESITE         0x0040
#define  NJT_HTTP_PROXY_COOKIE_SAMESITE_STRICT  0x0080
#define  NJT_HTTP_PROXY_COOKIE_SAMESITE_LAX     0x0100
#define  NJT_HTTP_PROXY_COOKIE_SAMESITE_NONE    0x0200
#define  NJT_HTTP_PROXY_COOKIE_SAMESITE_OFF     0x0400


static njt_int_t njt_http_proxy_eval(njt_http_request_t *r,
    njt_http_proxy_ctx_t *ctx, njt_http_proxy_loc_conf_t *plcf);
#if (NJT_HTTP_CACHE)
static njt_int_t njt_http_proxy_create_key(njt_http_request_t *r);
#endif
 njt_int_t njt_http_proxy_create_request(njt_http_request_t *r);
static njt_int_t njt_http_proxy_reinit_request(njt_http_request_t *r);
static njt_int_t njt_http_proxy_body_output_filter(void *data, njt_chain_t *in);
static njt_int_t njt_http_proxy_process_status_line(njt_http_request_t *r);
static njt_int_t njt_http_proxy_process_header(njt_http_request_t *r);
static njt_int_t njt_http_proxy_input_filter_init(void *data);
static njt_int_t njt_http_proxy_copy_filter(njt_event_pipe_t *p,
    njt_buf_t *buf);
static njt_int_t njt_http_proxy_chunked_filter(njt_event_pipe_t *p,
    njt_buf_t *buf);
static njt_int_t njt_http_proxy_non_buffered_copy_filter(void *data,
    ssize_t bytes);
static njt_int_t njt_http_proxy_non_buffered_chunked_filter(void *data,
    ssize_t bytes);
static njt_int_t njt_http_proxy_process_trailer(njt_http_request_t *r,
    njt_buf_t *buf);
static void njt_http_proxy_abort_request(njt_http_request_t *r);
static void njt_http_proxy_finalize_request(njt_http_request_t *r,
    njt_int_t rc);

static njt_int_t njt_http_proxy_host_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_proxy_port_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t
    njt_http_proxy_add_x_forwarded_for_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t
    njt_http_proxy_internal_body_length_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_proxy_internal_chunked_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_proxy_rewrite_redirect(njt_http_request_t *r,
    njt_table_elt_t *h, size_t prefix);
static njt_int_t njt_http_proxy_rewrite_cookie(njt_http_request_t *r,
    njt_table_elt_t *h);
static njt_int_t njt_http_proxy_parse_cookie(njt_str_t *value,
    njt_array_t *attrs);
static njt_int_t njt_http_proxy_rewrite_cookie_value(njt_http_request_t *r,
    njt_str_t *value, njt_array_t *rewrites);
static njt_int_t njt_http_proxy_rewrite_cookie_flags(njt_http_request_t *r,
    njt_array_t *attrs, njt_array_t *flags);
static njt_int_t njt_http_proxy_edit_cookie_flags(njt_http_request_t *r,
    njt_array_t *attrs, njt_uint_t flags);
static njt_int_t njt_http_proxy_rewrite(njt_http_request_t *r,
    njt_str_t *value, size_t prefix, size_t len, njt_str_t *replacement);

static njt_int_t njt_http_proxy_add_variables(njt_conf_t *cf);
static void *njt_http_proxy_create_main_conf(njt_conf_t *cf);
static void *njt_http_proxy_create_loc_conf(njt_conf_t *cf);
static char *njt_http_proxy_merge_loc_conf(njt_conf_t *cf,
    void *parent, void *child);
static njt_int_t njt_http_proxy_init_headers(njt_conf_t *cf,
    njt_http_proxy_loc_conf_t *conf, njt_http_proxy_headers_t *headers,
    njt_keyval_t *default_headers);

static char *njt_http_proxy_pass(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_proxy_redirect(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_proxy_cookie_domain(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_proxy_cookie_path(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_proxy_cookie_flags(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_proxy_store(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
#if (NJT_HTTP_CACHE)
static char *njt_http_proxy_cache(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_proxy_cache_key(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
#endif
#if (NJT_HTTP_SSL)
static char *njt_http_proxy_ssl_certificate_cache(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);
static char *njt_http_proxy_ssl_password_file(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);
#endif

static char *njt_http_proxy_lowat_check(njt_conf_t *cf, void *post, void *data);
#if (NJT_HTTP_SSL)
static char *njt_http_proxy_ssl_conf_command_check(njt_conf_t *cf, void *post,
    void *data);
#endif

static njt_int_t njt_http_proxy_rewrite_regex(njt_conf_t *cf,
    njt_http_proxy_rewrite_t *pr, njt_str_t *regex, njt_uint_t caseless);

#if (NJT_HTTP_SSL)
static njt_int_t njt_http_proxy_merge_ssl(njt_conf_t *cf,
    njt_http_proxy_loc_conf_t *conf, njt_http_proxy_loc_conf_t *prev);
static njt_int_t njt_http_proxy_set_ssl(njt_conf_t *cf,
    njt_http_proxy_loc_conf_t *plcf);
#endif


#if (NJT_HAVE_SET_ALPN)
static char *
njt_http_proxy_ssl_alpn(njt_conf_t *cf, njt_command_t *cmd, void *conf);
#endif

#if (NJT_HTTP_V2)

/* context for creating http/2 request */
typedef struct {
    /* calculated length of request */
    size_t                         n;

    /* encode method state */
    njt_str_t                      method;

    /* encode path state */
    size_t                         loc_len;
    size_t                         uri_len;
    uintptr_t                      escape;
    njt_uint_t                     unparsed_uri;

    /* tmp buff */
    u_char                         *tmp;
    size_t                         max_tmp_len;

    /* encode headers state */
    size_t                         max_head;
    njt_http_proxy_headers_t      *headers;
    njt_http_script_engine_t       le;
    njt_http_script_engine_t       e;

} njt_http_v2_proxy_ctx_t;

static njt_int_t njt_http_v2_proxy_create_request(njt_http_request_t *r);
static njt_int_t njt_http_v2_proxy_encode_method(njt_http_request_t *r,
    njt_http_v2_proxy_ctx_t *v2c, njt_buf_t *b);
static njt_inline njt_uint_t njt_http_v2_map_method(njt_uint_t method);
static njt_int_t njt_http_v2_proxy_encode_path(njt_http_request_t *r,
    njt_http_v2_proxy_ctx_t *v2c, njt_buf_t *b);
static njt_int_t njt_http_v2_proxy_encode_authority(njt_http_request_t *r,
    njt_http_v2_proxy_ctx_t *v2c, njt_buf_t *b);
static njt_int_t njt_http_v2_proxy_encode_headers(njt_http_request_t *r,
    njt_http_v2_proxy_ctx_t *v2c, njt_buf_t *b);
static njt_int_t njt_http_v2_proxy_body_length(njt_http_request_t *r,
    njt_http_v2_proxy_ctx_t *v2c);
static njt_chain_t *njt_http_v2_proxy_encode_body(njt_http_request_t *r,
    njt_http_v2_proxy_ctx_t *v2c);
static njt_int_t njt_http_v2_proxy_reinit_request(njt_http_request_t *r);
static njt_int_t njt_http_v2_proxy_process_header(njt_http_request_t *r);
static void njt_http_v2_proxy_abort_request(njt_http_request_t *r);
static void njt_http_v2_proxy_finalize_request(njt_http_request_t *r,
    njt_int_t rc);
#endif
#if (NJT_HTTP_V3)

/* context for creating http/3 request */
typedef struct {
    /* calculated length of request */
    size_t                         n;

    /* encode method state */
    njt_str_t                      method;

    /* encode path state */
    size_t                         loc_len;
    size_t                         uri_len;
    uintptr_t                      escape;
    njt_uint_t                     unparsed_uri;

    /* encode headers state */
    size_t                         max_head;
    njt_http_proxy_headers_t      *headers;
    njt_http_script_engine_t       le;
    njt_http_script_engine_t       e;

} njt_http_v3_proxy_ctx_t;


static char *njt_http_v3_proxy_host_key(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static njt_int_t njt_http_v3_proxy_merge_quic(njt_conf_t *cf,
    njt_http_proxy_loc_conf_t *conf, njt_http_proxy_loc_conf_t *prev);

static njt_int_t njt_http_v3_proxy_create_request(njt_http_request_t *r);

static njt_chain_t *njt_http_v3_create_headers_frame(njt_http_request_t *r,
    njt_buf_t *hbuf);
static njt_chain_t *njt_http_v3_create_data_frame(njt_http_request_t *r,
    njt_chain_t *body, size_t size);
static njt_inline njt_uint_t njt_http_v3_map_method(njt_uint_t method);
static njt_int_t njt_http_v3_proxy_encode_method(njt_http_request_t *r,
    njt_http_v3_proxy_ctx_t *v3c, njt_buf_t *b);
static njt_int_t njt_http_v3_proxy_encode_authority(njt_http_request_t *r,
    njt_http_v3_proxy_ctx_t *v3c, njt_buf_t *b);
static njt_int_t njt_http_v3_proxy_encode_path(njt_http_request_t *r,
    njt_http_v3_proxy_ctx_t *v3c, njt_buf_t *b);
static njt_int_t njt_http_v3_proxy_encode_headers(njt_http_request_t *r,
    njt_http_v3_proxy_ctx_t *v3c, njt_buf_t *b);
static njt_int_t njt_http_v3_proxy_body_length(njt_http_request_t *r,
    njt_http_v3_proxy_ctx_t *v3c);
static njt_chain_t *njt_http_v3_proxy_encode_body(njt_http_request_t *r,
    njt_http_v3_proxy_ctx_t *v3c);
static njt_int_t njt_http_v3_proxy_body_output_filter(void *data,
    njt_chain_t *in);

static njt_int_t njt_http_v3_proxy_reinit_request(njt_http_request_t *r);
static njt_int_t njt_http_v3_proxy_process_status_line(njt_http_request_t *r);
static void njt_http_v3_proxy_abort_request(njt_http_request_t *r);
static void njt_http_v3_proxy_finalize_request(njt_http_request_t *r,
    njt_int_t rc);
static njt_int_t njt_http_v3_proxy_process_header(njt_http_request_t *r,
    njt_str_t *name, njt_str_t *value);

static njt_int_t njt_http_v3_proxy_headers_done(njt_http_request_t *r);
static njt_int_t njt_http_v3_proxy_process_pseudo_header(njt_http_request_t *r,
    njt_str_t *name, njt_str_t *value);
static njt_int_t njt_http_v3_proxy_input_filter_init(void *data);
static njt_int_t njt_http_v3_proxy_copy_filter(njt_event_pipe_t *p,
    njt_buf_t *buf);
static njt_int_t njt_http_v3_proxy_non_buffered_copy_filter(void *data,
    ssize_t bytes);
static njt_int_t njt_http_v3_proxy_construct_cookie_header(
    njt_http_request_t *r);

static njt_str_t  njt_http_v3_proxy_quic_salt = njt_string("njt_quic");
#endif

static njt_conf_post_t  njt_http_proxy_lowat_post =
    { njt_http_proxy_lowat_check };


static njt_conf_bitmask_t  njt_http_proxy_next_upstream_masks[] = {
    { njt_string("error"), NJT_HTTP_UPSTREAM_FT_ERROR },
    { njt_string("timeout"), NJT_HTTP_UPSTREAM_FT_TIMEOUT },
    { njt_string("invalid_header"), NJT_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { njt_string("non_idempotent"), NJT_HTTP_UPSTREAM_FT_NON_IDEMPOTENT },
    { njt_string("http_500"), NJT_HTTP_UPSTREAM_FT_HTTP_500 },
    { njt_string("http_502"), NJT_HTTP_UPSTREAM_FT_HTTP_502 },
    { njt_string("http_503"), NJT_HTTP_UPSTREAM_FT_HTTP_503 },
    { njt_string("http_504"), NJT_HTTP_UPSTREAM_FT_HTTP_504 },
    { njt_string("http_403"), NJT_HTTP_UPSTREAM_FT_HTTP_403 },
    { njt_string("http_404"), NJT_HTTP_UPSTREAM_FT_HTTP_404 },
    { njt_string("http_429"), NJT_HTTP_UPSTREAM_FT_HTTP_429 },
    { njt_string("updating"), NJT_HTTP_UPSTREAM_FT_UPDATING },
    { njt_string("off"), NJT_HTTP_UPSTREAM_FT_OFF },
    { njt_null_string, 0 }
};


#if (NJT_HTTP_SSL)

static njt_conf_bitmask_t  njt_http_proxy_ssl_protocols[] = {
    { njt_string("SSLv2"), NJT_SSL_SSLv2 },
    { njt_string("SSLv3"), NJT_SSL_SSLv3 },
    { njt_string("TLSv1"), NJT_SSL_TLSv1 },
    { njt_string("TLSv1.1"), NJT_SSL_TLSv1_1 },
    { njt_string("TLSv1.2"), NJT_SSL_TLSv1_2 },
    { njt_string("TLSv1.3"), NJT_SSL_TLSv1_3 },
    { njt_null_string, 0 }
};

static njt_conf_post_t  njt_http_proxy_ssl_conf_command_post =
    { njt_http_proxy_ssl_conf_command_check };

#endif


static njt_conf_enum_t  njt_http_proxy_http_version[] = {
    { njt_string("1.0"), NJT_HTTP_VERSION_10 },
    { njt_string("1.1"), NJT_HTTP_VERSION_11 },
    { njt_string("2"), NJT_HTTP_VERSION_20 },
    { njt_string("3"), NJT_HTTP_VERSION_30 },
    { njt_null_string, 0 }
};


njt_module_t  njt_http_proxy_module;
extern njt_module_t njt_http_fault_inject_module;

static njt_command_t  njt_http_proxy_commands[] = {

    { njt_string("proxy_pass"),
      NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_HTTP_LMT_CONF|NJT_CONF_TAKE1,
      njt_http_proxy_pass,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("proxy_redirect"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE12,
      njt_http_proxy_redirect,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("proxy_cookie_domain"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE12,
      njt_http_proxy_cookie_domain,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("proxy_cookie_path"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE12,
      njt_http_proxy_cookie_path,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("proxy_cookie_flags"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1234,
      njt_http_proxy_cookie_flags,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("proxy_store"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_proxy_store,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("proxy_store_access"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE123,
      njt_conf_set_access_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.store_access),
      NULL },

    { njt_string("proxy_buffering"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.buffering),
      NULL },

    { njt_string("proxy_request_buffering"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.request_buffering),
      NULL },

    { njt_string("proxy_ignore_client_abort"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.ignore_client_abort),
      NULL },

    { njt_string("proxy_bind"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE12,
      njt_http_upstream_bind_set_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.local),
      NULL },

    { njt_string("proxy_socket_keepalive"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.socket_keepalive),
      NULL },

    { njt_string("proxy_connect_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.connect_timeout),
      NULL },

    { njt_string("proxy_send_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.send_timeout),
      NULL },

    { njt_string("proxy_send_lowat"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.send_lowat),
      &njt_http_proxy_lowat_post },

    { njt_string("proxy_intercept_errors"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.intercept_errors),
      NULL },

    { njt_string("proxy_set_header"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE2,
      njt_conf_set_keyval_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, headers_source),
      NULL },

    { njt_string("proxy_headers_hash_max_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, headers_hash_max_size),
      NULL },

    { njt_string("proxy_headers_hash_bucket_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, headers_hash_bucket_size),
      NULL },

    { njt_string("proxy_set_body"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, body_source),
      NULL },

    { njt_string("proxy_method"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_set_complex_value_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, method),
      NULL },

    { njt_string("proxy_pass_request_headers"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.pass_request_headers),
      NULL },

    { njt_string("proxy_pass_request_body"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.pass_request_body),
      NULL },

    { njt_string("proxy_pass_trailers"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.pass_trailers),
      NULL },

    { njt_string("proxy_buffer_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.buffer_size),
      NULL },

    { njt_string("proxy_read_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.read_timeout),
      NULL },

    { njt_string("proxy_buffers"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE2,
      njt_conf_set_bufs_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.bufs),
      NULL },

    { njt_string("proxy_busy_buffers_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.busy_buffers_size_conf),
      NULL },

    { njt_string("proxy_force_ranges"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.force_ranges),
      NULL },

    { njt_string("proxy_limit_rate"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_set_complex_value_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.limit_rate),
      NULL },

#if (NJT_HTTP_CACHE)

    { njt_string("proxy_cache"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_proxy_cache,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("proxy_cache_key"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_proxy_cache_key,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("proxy_cache_path"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_2MORE,
      njt_http_file_cache_set_slot,
      NJT_HTTP_MAIN_CONF_OFFSET,
      offsetof(njt_http_proxy_main_conf_t, caches),
      &njt_http_proxy_module },

    { njt_string("proxy_cache_bypass"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_http_set_predicate_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.cache_bypass),
      NULL },

    { njt_string("proxy_no_cache"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_http_set_predicate_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.no_cache),
      NULL },

    { njt_string("proxy_cache_valid"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_http_file_cache_valid_set_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.cache_valid),
      NULL },

    { njt_string("proxy_cache_min_uses"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.cache_min_uses),
      NULL },

    { njt_string("proxy_cache_max_range_offset"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_off_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.cache_max_range_offset),
      NULL },

    { njt_string("proxy_cache_use_stale"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.cache_use_stale),
      &njt_http_proxy_next_upstream_masks },

    { njt_string("proxy_cache_methods"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.cache_methods),
      &njt_http_upstream_cache_method_mask },

    { njt_string("proxy_cache_lock"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.cache_lock),
      NULL },

    { njt_string("proxy_cache_lock_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.cache_lock_timeout),
      NULL },

    { njt_string("proxy_cache_lock_age"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.cache_lock_age),
      NULL },

    { njt_string("proxy_cache_revalidate"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.cache_revalidate),
      NULL },

    { njt_string("proxy_cache_convert_head"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.cache_convert_head),
      NULL },

    { njt_string("proxy_cache_background_update"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.cache_background_update),
      NULL },

#endif

    { njt_string("proxy_temp_path"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1234,
      njt_conf_set_path_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.temp_path),
      NULL },

    { njt_string("proxy_max_temp_file_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.max_temp_file_size_conf),
      NULL },

    { njt_string("proxy_temp_file_write_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.temp_file_write_size_conf),
      NULL },

    { njt_string("proxy_next_upstream"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.next_upstream),
      &njt_http_proxy_next_upstream_masks },

    { njt_string("proxy_next_upstream_tries"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.next_upstream_tries),
      NULL },

    { njt_string("proxy_next_upstream_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.next_upstream_timeout),
      NULL },

    { njt_string("proxy_pass_header"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_array_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.pass_headers),
      NULL },

    { njt_string("proxy_hide_header"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_array_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.hide_headers),
      NULL },

    { njt_string("proxy_ignore_headers"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.ignore_headers),
      &njt_http_upstream_ignore_headers_masks },

    { njt_string("proxy_http_version"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF
      |NJT_HTTP_LIF_CONF|NJT_HTTP_LMT_CONF|NJT_CONF_TAKE1,
      njt_conf_set_enum_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, http_version),
      &njt_http_proxy_http_version },

#if (NJT_HTTP_SSL)

    { njt_string("proxy_ssl_session_reuse"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.ssl_session_reuse),
      NULL },

    { njt_string("proxy_ssl_protocols"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, ssl_protocols),
      &njt_http_proxy_ssl_protocols },

    { njt_string("proxy_ssl_ciphers"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, ssl_ciphers),
      NULL },

    { njt_string("proxy_ssl_name"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_set_complex_value_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.ssl_name),
      NULL },

    { njt_string("proxy_ssl_server_name"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.ssl_server_name),
      NULL },

    { njt_string("proxy_ssl_verify"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.ssl_verify),
      NULL },

    { njt_string("proxy_ssl_verify_depth"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, ssl_verify_depth),
      NULL },

    { njt_string("proxy_ssl_trusted_certificate"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, ssl_trusted_certificate),
      NULL },

    { njt_string("proxy_ssl_crl"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, ssl_crl),
      NULL },

#if (NJT_HTTP_MULTICERT)

    { njt_string("proxy_ssl_certificate"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE12,
      njt_ssl_certificate_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.ssl_certificates),
      NULL },

    { njt_string("proxy_ssl_certificate_key"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE12,
      njt_ssl_certificate_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.ssl_certificate_keys),
      NULL },

#else

    { njt_string("proxy_ssl_certificate"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_set_complex_value_zero_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.ssl_certificate),
      NULL },

    { njt_string("proxy_ssl_certificate_key"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_set_complex_value_zero_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.ssl_certificate_key),
      NULL },

#endif

    { njt_string("proxy_ssl_certificate_cache"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE123,
      njt_http_proxy_ssl_certificate_cache,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("proxy_ssl_password_file"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_proxy_ssl_password_file,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("proxy_ssl_conf_command"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE2,
      njt_conf_set_keyval_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, ssl_conf_commands),
      &njt_http_proxy_ssl_conf_command_post },

#if (NJT_HAVE_NTLS)
    { njt_string("proxy_ssl_ntls"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.ssl_ntls),
      NULL },
#endif
#if (NJT_HAVE_SET_ALPN)
      { njt_string("proxy_ssl_alpn"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_http_proxy_ssl_alpn,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
#endif


#endif
#if (NJT_HTTP_V2)
     { njt_string("http2_max_concurrent_streams"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, 
               upstream.h2_conf.concurrent_streams),
      NULL },   

    { njt_string("http2_streams_index_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, 
              upstream.h2_conf.streams_index_mask),
      NULL },

    { njt_string("http2_streams_recv_window"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, 
               upstream.h2_conf.recv_window),
      NULL },

#endif
#if (NJT_HTTP_V3)

    { njt_string("proxy_http3_max_concurrent_streams"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t,
               upstream.quic.max_concurrent_streams_bidi),
      NULL },

    { njt_string("proxy_http3_stream_buffer_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.quic.stream_buffer_size),
      NULL },

    { njt_string("proxy_quic_gso"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, upstream.quic.gso_enabled),
      NULL },

    { njt_string("proxy_quic_host_key"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_v3_proxy_host_key,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("proxy_quic_active_connection_id_limit"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t,
               upstream.quic.active_connection_id_limit),
      NULL },

    { njt_string("proxy_http3_hq"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_proxy_loc_conf_t, enable_hq),
      NULL },
#endif

      njt_null_command
};


static njt_http_module_t  njt_http_proxy_module_ctx = {
    njt_http_proxy_add_variables,          /* preconfiguration */
    NULL,                                  /* postconfiguration */

    njt_http_proxy_create_main_conf,       /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_proxy_create_loc_conf,        /* create location configuration */
    njt_http_proxy_merge_loc_conf          /* merge location configuration */
};


njt_module_t  njt_http_proxy_module = {
    NJT_MODULE_V1,
    &njt_http_proxy_module_ctx,            /* module context */
    njt_http_proxy_commands,               /* module directives */
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


static char  njt_http_proxy_version[] = " HTTP/1.0" CRLF;
static char  njt_http_proxy_version_11[] = " HTTP/1.1" CRLF;


static njt_keyval_t  njt_http_proxy_headers[] = {
    { njt_string("Host"), njt_string("$proxy_host") },
    { njt_string("Connection"), njt_string("close") },
    { njt_string("Content-Length"), njt_string("$proxy_internal_body_length") },
    { njt_string("Transfer-Encoding"), njt_string("$proxy_internal_chunked") },
    { njt_string("TE"), njt_string("") },
    { njt_string("Keep-Alive"), njt_string("") },
    { njt_string("Expect"), njt_string("") },
    { njt_string("Upgrade"), njt_string("") },
    { njt_null_string, njt_null_string }
};

#if (NJT_HTTP_V3 || NJT_HTTP_V2)

/*
 * RFC 9114  4.2 HTTP Fields
 *
 * An intermediary transforming an HTTP/1.x message to HTTP/3 MUST remove
 * connection-specific header fields as discussed in Section 7.6.1 of [HTTP],
 * or their messages will be treated by other HTTP/3 endpoints as malformed.
 */
static njt_keyval_t  njt_http_v3_proxy_headers[] = {
    { njt_string("Content-Length"), njt_string("$proxy_internal_body_length") },
#if 0
    /* TODO: trailers */
    { njt_string("TE"), njt_string("$v3_proxy_internal_trailers") },
#endif
    { njt_string("Host"), njt_string("") },
    { njt_string("Connection"), njt_string("") },
    { njt_string("Transfer-Encoding"), njt_string("") },
    { njt_string("Keep-Alive"), njt_string("") },
    { njt_string("Expect"), njt_string("") },
    { njt_string("Upgrade"), njt_string("") },
    { njt_null_string, njt_null_string }
};

#if (NJT_HTTP_CACHE)

static njt_keyval_t  njt_http_v3_proxy_cache_headers[] = {
    { njt_string("Host"), njt_string("") },
    { njt_string("Connection"), njt_string("") },
    { njt_string("Content-Length"), njt_string("$proxy_internal_body_length") },
    { njt_string("Transfer-Encoding"), njt_string("") },
    { njt_string("TE"), njt_string("") },
    { njt_string("Keep-Alive"), njt_string("") },
    { njt_string("Expect"), njt_string("") },
    { njt_string("Upgrade"), njt_string("") },
    { njt_string("If-Modified-Since"),
      njt_string("$upstream_cache_last_modified") },
    { njt_string("If-Unmodified-Since"), njt_string("") },
    { njt_string("If-None-Match"), njt_string("$upstream_cache_etag") },
    { njt_string("If-Match"), njt_string("") },
    { njt_string("Range"), njt_string("") },
    { njt_string("If-Range"), njt_string("") },
    { njt_null_string, njt_null_string }
};

#endif

#endif

static njt_str_t  njt_http_proxy_hide_headers[] = {
    njt_string("Date"),
    njt_string("Server"),
    njt_string("X-Pad"),
    njt_string("X-Accel-Expires"),
    njt_string("X-Accel-Redirect"),
    njt_string("X-Accel-Limit-Rate"),
    njt_string("X-Accel-Buffering"),
    njt_string("X-Accel-Charset"),
    njt_null_string
};


#if (NJT_HTTP_CACHE)

static njt_keyval_t  njt_http_proxy_cache_headers[] = {
    { njt_string("Host"), njt_string("$proxy_host") },
    { njt_string("Connection"), njt_string("close") },
    { njt_string("Content-Length"), njt_string("$proxy_internal_body_length") },
    { njt_string("Transfer-Encoding"), njt_string("$proxy_internal_chunked") },
    { njt_string("TE"), njt_string("") },
    { njt_string("Keep-Alive"), njt_string("") },
    { njt_string("Expect"), njt_string("") },
    { njt_string("Upgrade"), njt_string("") },
    { njt_string("If-Modified-Since"),
      njt_string("$upstream_cache_last_modified") },
    { njt_string("If-Unmodified-Since"), njt_string("") },
    { njt_string("If-None-Match"), njt_string("$upstream_cache_etag") },
    { njt_string("If-Match"), njt_string("") },
    { njt_string("Range"), njt_string("") },
    { njt_string("If-Range"), njt_string("") },
    { njt_null_string, njt_null_string }
};

#endif


static njt_http_variable_t  njt_http_proxy_vars[] = {

    { njt_string("proxy_host"), NULL, njt_http_proxy_host_variable, 0,
      NJT_HTTP_VAR_CHANGEABLE|NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_NOHASH, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("proxy_port"), NULL, njt_http_proxy_port_variable, 0,
      NJT_HTTP_VAR_CHANGEABLE|NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_NOHASH, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("proxy_add_x_forwarded_for"), NULL,
      njt_http_proxy_add_x_forwarded_for_variable, 0, NJT_HTTP_VAR_NOHASH, 0, NJT_VAR_INIT_REF_COUNT },

#if 0
    { njt_string("proxy_add_via"), NULL, NULL, 0, NJT_HTTP_VAR_NOHASH, 0, NJT_VAR_INIT_REF_COUNT },
#endif

    { njt_string("proxy_internal_body_length"), NULL,
      njt_http_proxy_internal_body_length_variable, 0,
      NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_NOHASH, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("proxy_internal_chunked"), NULL,
      njt_http_proxy_internal_chunked_variable, 0,
      NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_NOHASH, 0, NJT_VAR_INIT_REF_COUNT },

      njt_http_null_variable
};


static njt_path_init_t  njt_http_proxy_temp_path = {
    njt_string(NJT_HTTP_PROXY_TEMP_PATH), { 1, 2, 0 }
};


static njt_conf_bitmask_t  njt_http_proxy_cookie_flags_masks[] = {

    { njt_string("secure"),
      NJT_HTTP_PROXY_COOKIE_SECURE|NJT_HTTP_PROXY_COOKIE_SECURE_ON },

    { njt_string("nosecure"),
      NJT_HTTP_PROXY_COOKIE_SECURE|NJT_HTTP_PROXY_COOKIE_SECURE_OFF },

    { njt_string("httponly"),
      NJT_HTTP_PROXY_COOKIE_HTTPONLY|NJT_HTTP_PROXY_COOKIE_HTTPONLY_ON },

    { njt_string("nohttponly"),
      NJT_HTTP_PROXY_COOKIE_HTTPONLY|NJT_HTTP_PROXY_COOKIE_HTTPONLY_OFF },

    { njt_string("samesite=strict"),
      NJT_HTTP_PROXY_COOKIE_SAMESITE|NJT_HTTP_PROXY_COOKIE_SAMESITE_STRICT },

    { njt_string("samesite=lax"),
      NJT_HTTP_PROXY_COOKIE_SAMESITE|NJT_HTTP_PROXY_COOKIE_SAMESITE_LAX },

    { njt_string("samesite=none"),
      NJT_HTTP_PROXY_COOKIE_SAMESITE|NJT_HTTP_PROXY_COOKIE_SAMESITE_NONE },

    { njt_string("nosamesite"),
      NJT_HTTP_PROXY_COOKIE_SAMESITE|NJT_HTTP_PROXY_COOKIE_SAMESITE_OFF },

    { njt_null_string, 0 }
};
#if(NJT_HTTP_DYN_PROXY_PASS)
    static njt_int_t
    njt_http_proxy_copy_vars(njt_http_request_t *r,njt_http_proxy_vars_t *dst, njt_http_proxy_vars_t *src) {
        njt_http_proxy_loc_conf_t   *plcf;
        plcf = njt_http_get_module_loc_conf(r, njt_http_proxy_module);
        if(plcf->pool == NULL) {  //原始的，不会释放。
            return NJT_OK;
        }

        dst->key_start.len = src->key_start.len;
        dst->key_start.data = njt_pstrdup(r->pool,&src->key_start);

        dst->schema.len = src->schema.len;
        dst->schema.data = njt_pstrdup(r->pool,&src->schema);

        dst->host_header.len = src->host_header.len;
        dst->host_header.data = njt_pstrdup(r->pool,&src->host_header);

        dst->port.len = src->port.len;
        dst->port.data = njt_pstrdup(r->pool,&src->port);

        dst->uri.len = src->uri.len;
        dst->uri.data = njt_pstrdup(r->pool,&src->uri);
        if(dst->key_start.data == NULL || dst->schema.data == NULL || dst->host_header.data == NULL || dst->port.data == NULL || dst->uri.data == NULL) {
             return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

    return NJT_OK;
    }
#endif

static njt_int_t
njt_http_proxy_handler(njt_http_request_t *r)
{
    njt_int_t                    rc;
    njt_http_upstream_t         *u;
    njt_http_proxy_ctx_t        *ctx;
    njt_http_proxy_loc_conf_t   *plcf;
    // njt_http_fault_inject_conf_t *ficf;
#if (NJT_HTTP_CACHE)
    njt_http_proxy_main_conf_t  *pmcf;
#endif

    if (njt_http_upstream_create(r) != NJT_OK) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = njt_pcalloc(r->pool, sizeof(njt_http_proxy_ctx_t));
    if (ctx == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    njt_http_set_ctx(r, ctx, njt_http_proxy_module);

    plcf = njt_http_get_module_loc_conf(r, njt_http_proxy_module);

    u = r->upstream;

    if (plcf->proxy_lengths == NULL) {
#if (NJT_HTTP_V3 || NJT_HTTP_V2)
        ctx->host = plcf->host;
#endif
        ctx->vars = plcf->vars;
        u->schema = plcf->vars.schema;
#if(NJT_HTTP_DYN_PROXY_PASS)
        njt_http_proxy_copy_vars(r,&ctx->vars,&plcf->vars);
        u->schema = ctx->vars.schema;
#endif

#if (NJT_HTTP_SSL)
        u->ssl = plcf->ssl;
#endif

    } else {
        if (njt_http_proxy_eval(r, ctx, plcf) != NJT_OK) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    u->output.tag = (njt_buf_tag_t) &njt_http_proxy_module;

    u->conf = &plcf->upstream;

#if (NJT_HTTP_CACHE)
    pmcf = njt_http_get_module_main_conf(r, njt_http_proxy_module);

    u->caches = &pmcf->caches;
    u->create_key = njt_http_proxy_create_key;
#endif

    u->create_request = njt_http_proxy_create_request;
    u->reinit_request = njt_http_proxy_reinit_request;
    u->process_header = njt_http_proxy_process_status_line;
    u->abort_request = njt_http_proxy_abort_request;
    u->finalize_request = njt_http_proxy_finalize_request;
#if (NJT_HTTP_V3)
    if (plcf->http_version == NJT_HTTP_VERSION_30) {

        u->h3 = 1;
        u->peer.type = SOCK_DGRAM;

        if (plcf->enable_hq) {
            u->hq = 1;

        } else {
            u->create_request = njt_http_v3_proxy_create_request;
            u->reinit_request = njt_http_v3_proxy_reinit_request;
            u->process_header = njt_http_v3_proxy_process_status_line;
            u->abort_request = njt_http_v3_proxy_abort_request;
            u->finalize_request = njt_http_v3_proxy_finalize_request;
        }

        ctx->v3_parse = njt_pcalloc(r->pool, sizeof(njt_http_v3_parse_t));
        if (ctx->v3_parse == NULL) {
            return NJT_ERROR;
        }
    }
#endif
    r->state = 0;

#if (NJT_HTTP_V2)
    if (plcf->http_version == NJT_HTTP_VERSION_20) {
        u->h2 = 1;
    
        u->create_request = njt_http_v2_proxy_create_request;
        u->reinit_request = njt_http_v2_proxy_reinit_request;
        u->process_header = njt_http_v2_proxy_process_header;
        u->abort_request = njt_http_v2_proxy_abort_request;
        u->finalize_request = njt_http_v2_proxy_finalize_request;
    }
#endif

    if (plcf->redirects) {
        u->rewrite_redirect = njt_http_proxy_rewrite_redirect;
    }

    if (plcf->cookie_domains || plcf->cookie_paths || plcf->cookie_flags) {
        u->rewrite_cookie = njt_http_proxy_rewrite_cookie;
    }

    u->buffering = plcf->upstream.buffering;

    u->pipe = njt_pcalloc(r->pool, sizeof(njt_event_pipe_t));
    if (u->pipe == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    u->pipe->input_filter = njt_http_proxy_copy_filter;

    u->input_filter_init = njt_http_proxy_input_filter_init;
    u->input_filter = njt_http_proxy_non_buffered_copy_filter;
#if (NJT_HTTP_V3)
    if (plcf->http_version == NJT_HTTP_VERSION_30 && !plcf->enable_hq) {
        u->pipe->input_filter = njt_http_v3_proxy_copy_filter;

        u->input_filter_init = njt_http_v3_proxy_input_filter_init;
        u->input_filter = njt_http_v3_proxy_non_buffered_copy_filter;
    }
#endif
    u->pipe->input_ctx = r;
    u->input_filter_ctx = r;

    u->accel = 1;

    if (!plcf->upstream.request_buffering
        && plcf->body_values == NULL && plcf->upstream.pass_request_body
        && (!r->headers_in.chunked
            || (plcf->http_version == NJT_HTTP_VERSION_11
#if (NJT_HTTP_V3)
                || plcf->http_version == NJT_HTTP_VERSION_30
#endif
#if (NJT_HTTP_V2)
                || plcf->http_version == NJT_HTTP_VERSION_20
#endif
           )))
    {
        r->request_body_no_buffering = 1;
    }
// rc = njt_http_read_client_request_body(r, njt_http_upstream_init);
    //add by clb
#if (NJT_HTTP_FAULT_INJECT)
    rc = njt_http_read_client_request_body(r, njt_http_fault_inject_handler);
#else
    rc = njt_http_read_client_request_body(r, njt_http_upstream_init);
#endif

    if (rc >= NJT_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NJT_DONE;
}


static njt_int_t
njt_http_proxy_eval(njt_http_request_t *r, njt_http_proxy_ctx_t *ctx,
    njt_http_proxy_loc_conf_t *plcf)
{
    u_char               *p;
    size_t                add;
    u_short               port;
    njt_str_t             proxy;
    njt_url_t             url;
    njt_http_upstream_t  *u;

    if (njt_http_script_run(r, &proxy, plcf->proxy_lengths->elts, 0,
                            plcf->proxy_values->elts)
        == NULL)
    {
        return NJT_ERROR;
    }

    if (proxy.len > 7
        && njt_strncasecmp(proxy.data, (u_char *) "http://", 7) == 0)
    {
        add = 7;
        port = 80;
#if (NJT_HTTP_V3)
        if (plcf->http_version == NJT_HTTP_VERSION_30) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "http/3 requires https prefix");
            return NJT_ERROR;
        }
#endif
#if (NJT_HTTP_SSL)

    } else if (proxy.len > 8
               && njt_strncasecmp(proxy.data, (u_char *) "https://", 8) == 0)
    {
        add = 8;
        port = 443;
        r->upstream->ssl = 1;

#endif

    } else {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "invalid URL prefix in \"%V\"", &proxy);
        return NJT_ERROR;
    }

    u = r->upstream;

    u->schema.len = add;
    u->schema.data = proxy.data;

    njt_memzero(&url, sizeof(njt_url_t));

    url.url.len = proxy.len - add;
    url.url.data = proxy.data + add;
    url.default_port = port;
    url.uri_part = 1;
    url.no_resolve = 1;

    if (njt_parse_url(r->pool, &url) != NJT_OK) {
        if (url.err) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "%s in upstream \"%V\"", url.err, &url.url);
        }

        return NJT_ERROR;
    }

    if (url.uri.len) {
        if (url.uri.data[0] == '?') {
            p = njt_pnalloc(r->pool, url.uri.len + 1);
            if (p == NULL) {
                return NJT_ERROR;
            }

            *p++ = '/';
            njt_memcpy(p, url.uri.data, url.uri.len);

            url.uri.len++;
            url.uri.data = p - 1;
        }
    }

    ctx->vars.key_start = u->schema;

    njt_http_proxy_set_vars(&url, &ctx->vars);

    u->resolved = njt_pcalloc(r->pool, sizeof(njt_http_upstream_resolved_t));
    if (u->resolved == NULL) {
        return NJT_ERROR;
    }

    if (url.addrs) {
        u->resolved->sockaddr = url.addrs[0].sockaddr;
        u->resolved->socklen = url.addrs[0].socklen;
        u->resolved->name = url.addrs[0].name;
        u->resolved->naddrs = 1;
    }

    u->resolved->host = url.host;
    u->resolved->port = (in_port_t) (url.no_port ? port : url.port);
    u->resolved->no_port = url.no_port;

#if (NJT_HTTP_V3)
    if (url.family != AF_UNIX) {

        if (url.no_port) {
            ctx->host = url.host;

        } else {
            ctx->host.len = url.host.len + 1 + url.port_text.len;
            ctx->host.data = url.host.data;
        }

    } else {
        njt_str_set(&ctx->host, "localhost");
    }
#endif

#if (NJT_HTTP_V3 || NJT_HTTP_V2)
    if (url.family != AF_UNIX) {

        if (url.no_port) {
            ctx->host = url.host;

        } else {
            ctx->host.len = url.host.len + 1 + url.port_text.len;
            ctx->host.data = url.host.data;
        }

    } else {
        njt_str_set(&ctx->host, "localhost");
    }
#endif
    return NJT_OK;
}


#if (NJT_HTTP_CACHE)

static njt_int_t
njt_http_proxy_create_file_key(njt_http_request_t *r)
{
    size_t                      len, loc_len;
    u_char                     *p;
    uintptr_t                   escape;
    njt_str_t                  *key;
    njt_http_upstream_t        *u;
    njt_http_proxy_ctx_t       *ctx;
    njt_http_proxy_loc_conf_t  *plcf;
    njt_http_core_loc_conf_t    *clcf;
    u = r->upstream;

    plcf = njt_http_get_module_loc_conf(r, njt_http_proxy_module);
    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);
    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    key = njt_array_push(&r->cache->file_keys);
    if (key == NULL) {
        return NJT_ERROR;
    }

    if (plcf->cache_file_key.value.data) {
        if (njt_http_complex_value(r, &plcf->cache_file_key, key) != NJT_OK) {
            return NJT_ERROR;
        }
        return NJT_OK;
    }
    *key = ctx->vars.key_start;

    key = njt_array_push(&r->cache->file_keys);
    if (key == NULL) {
        return NJT_ERROR;
    }

    if (plcf->proxy_lengths && ctx->vars.uri.len) {

        *key = ctx->vars.uri;
        u->uri = ctx->vars.uri;

        return NJT_OK;

    } else if (ctx->vars.uri.len == 0 && r->valid_unparsed_uri) {
        *key = r->unparsed_uri;
        u->uri = r->unparsed_uri;

        return NJT_OK;
    }

    loc_len = (r->valid_location && ctx->vars.uri.len) ? plcf->location.len : 0;
#if (NJT_HTTP_DYNAMIC_LOC)
	if(clcf->if_loc == 1) {  //by zyg
	  loc_len = (r->valid_location && ctx->vars.uri.len) ?
                      r->uri.len : 0;
	}
#endif

    if (r->quoted_uri || r->internal) {
        escape = 2 * njt_escape_uri(NULL, r->uri.data + loc_len,
                                    r->uri.len - loc_len, NJT_ESCAPE_URI);
    } else {
        escape = 0;
    }

    len = ctx->vars.uri.len + r->uri.len - loc_len + escape
          + sizeof("?") - 1 + r->args.len;

    p = njt_pnalloc(r->pool, len);
    if (p == NULL) {
        return NJT_ERROR;
    }

    key->data = p;

    if (r->valid_location) {
        p = njt_copy(p, ctx->vars.uri.data, ctx->vars.uri.len);
    }

    if (escape) {
        njt_escape_uri(p, r->uri.data + loc_len,
                       r->uri.len - loc_len, NJT_ESCAPE_URI);
        p += r->uri.len - loc_len + escape;

    } else {
        p = njt_copy(p, r->uri.data + loc_len, r->uri.len - loc_len);
    }

    if (r->args.len > 0) {
        *p++ = '?';
        p = njt_copy(p, r->args.data, r->args.len);
    }

    key->len = p - key->data;
    u->uri = *key;

    return NJT_OK;
}


static njt_int_t
njt_http_proxy_create_key(njt_http_request_t *r)
{
    size_t                      len, loc_len;
    u_char                     *p;
    uintptr_t                   escape;
    njt_str_t                  *key;
    njt_http_upstream_t        *u;
    njt_http_proxy_ctx_t       *ctx;
    njt_http_proxy_loc_conf_t  *plcf;
    njt_http_core_loc_conf_t    *clcf;
    u = r->upstream;

    plcf = njt_http_get_module_loc_conf(r, njt_http_proxy_module);
    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);
    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    njt_http_proxy_create_file_key(r);

    key = njt_array_push(&r->cache->keys);
    if (key == NULL) {
        return NJT_ERROR;
    }

    if (plcf->cache_key.value.data) {

        if (njt_http_complex_value(r, &plcf->cache_key, key) != NJT_OK) {
            return NJT_ERROR;
        }

        return NJT_OK;
    }

    *key = ctx->vars.key_start;

    key = njt_array_push(&r->cache->keys);
    if (key == NULL) {
        return NJT_ERROR;
    }

    if (plcf->proxy_lengths && ctx->vars.uri.len) {

        *key = ctx->vars.uri;
        u->uri = ctx->vars.uri;

        return NJT_OK;

    } else if (ctx->vars.uri.len == 0 && r->valid_unparsed_uri) {
        *key = r->unparsed_uri;
        u->uri = r->unparsed_uri;

        return NJT_OK;
    }

    loc_len = (r->valid_location && ctx->vars.uri.len) ? plcf->location.len : 0;
#if (NJT_HTTP_DYNAMIC_LOC)
	if(clcf->if_loc == 1) {  //by zyg
	  loc_len = (r->valid_location && ctx->vars.uri.len) ?
                      r->uri.len : 0;
	}
#endif

    if (r->quoted_uri || r->internal) {
        escape = 2 * njt_escape_uri(NULL, r->uri.data + loc_len,
                                    r->uri.len - loc_len, NJT_ESCAPE_URI);
    } else {
        escape = 0;
    }

    len = ctx->vars.uri.len + r->uri.len - loc_len + escape
          + sizeof("?") - 1 + r->args.len;

    p = njt_pnalloc(r->pool, len);
    if (p == NULL) {
        return NJT_ERROR;
    }

    key->data = p;

    if (r->valid_location) {
        p = njt_copy(p, ctx->vars.uri.data, ctx->vars.uri.len);
    }

    if (escape) {
        njt_escape_uri(p, r->uri.data + loc_len,
                       r->uri.len - loc_len, NJT_ESCAPE_URI);
        p += r->uri.len - loc_len + escape;

    } else {
        p = njt_copy(p, r->uri.data + loc_len, r->uri.len - loc_len);
    }

    if (r->args.len > 0) {
        *p++ = '?';
        p = njt_copy(p, r->args.data, r->args.len);
    }

    key->len = p - key->data;
    u->uri = *key;

    return NJT_OK;
}

#endif


 njt_int_t
njt_http_proxy_create_request(njt_http_request_t *r)
{
    size_t                        len, uri_len, loc_len, body_len,
                                  key_len, val_len;
    uintptr_t                     escape;
    njt_buf_t                    *b;
    njt_str_t                     method;
    njt_uint_t                    i, unparsed_uri;
    njt_chain_t                  *cl, *body;
    njt_list_part_t              *part;
    njt_table_elt_t              *header;
    njt_http_upstream_t          *u;
    njt_http_proxy_ctx_t         *ctx;
    njt_http_script_code_pt       code;
    njt_http_proxy_headers_t     *headers;
    njt_http_script_engine_t      e, le;
    njt_http_proxy_loc_conf_t    *plcf;
    njt_http_script_len_code_pt   lcode;
    njt_http_core_loc_conf_t    *clcf;

    u = r->upstream;

    plcf = njt_http_get_module_loc_conf(r, njt_http_proxy_module);
    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

#if (NJT_HTTP_CACHE)
    headers = u->cacheable ? &plcf->headers_cache : &plcf->headers;
#else
    headers = &plcf->headers;
#endif

    if (u->method.len) {
        /* HEAD was changed to GET to cache response */
        method = u->method;

    } else if (plcf->method) {
        if (njt_http_complex_value(r, plcf->method, &method) != NJT_OK) {
            return NJT_ERROR;
        }

    } else {
        method = r->method_name;
    }

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    if (method.len == 4
        && njt_strncasecmp(method.data, (u_char *) "HEAD", 4) == 0)
    {
        ctx->head = 1;
    }

    len = method.len + 1 + sizeof(njt_http_proxy_version) - 1
          + sizeof(CRLF) - 1;

    escape = 0;
    loc_len = 0;
    unparsed_uri = 0;

    if (plcf->proxy_lengths && ctx->vars.uri.len) {
        uri_len = ctx->vars.uri.len;

    } else if (ctx->vars.uri.len == 0 && r->valid_unparsed_uri) {
        unparsed_uri = 1;
        uri_len = r->unparsed_uri.len;

    } else {
        loc_len = (r->valid_location && ctx->vars.uri.len) ?
                      plcf->location.len : 0;
#if (NJT_HTTP_DYNAMIC_LOC)
	if(clcf->if_loc == 1) {  //by zyg
	  loc_len = (r->valid_location && ctx->vars.uri.len) ?
                      r->uri.len : 0;
	}
#endif
        if (r->quoted_uri || r->internal) {
            escape = 2 * njt_escape_uri(NULL, r->uri.data + loc_len,
                                        r->uri.len - loc_len, NJT_ESCAPE_URI);
        }

        uri_len = ctx->vars.uri.len + r->uri.len - loc_len + escape
                  + sizeof("?") - 1 + r->args.len;
    }

    if (uri_len == 0) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "zero length URI to proxy");
        return NJT_ERROR;
    }

    len += uri_len;

    njt_memzero(&le, sizeof(njt_http_script_engine_t));

    njt_http_script_flush_no_cacheable_variables(r, plcf->body_flushes);
    njt_http_script_flush_no_cacheable_variables(r, headers->flushes);

    if (plcf->body_lengths) {
        le.ip = plcf->body_lengths->elts;
        le.request = r;
        le.flushed = 1;
        body_len = 0;

        while (*(uintptr_t *) le.ip) {
            lcode = *(njt_http_script_len_code_pt *) le.ip;
            body_len += lcode(&le);
        }

        ctx->internal_body_length = body_len;
        len += body_len;

    } else if (r->headers_in.chunked && r->reading_body) {
        ctx->internal_body_length = -1;
        ctx->internal_chunked = 1;

    } else {
        ctx->internal_body_length = r->headers_in.content_length_n;
    }

    le.ip = headers->lengths->elts;
    le.request = r;
    le.flushed = 1;

    while (*(uintptr_t *) le.ip) {

        lcode = *(njt_http_script_len_code_pt *) le.ip;
        key_len = lcode(&le);

        for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
            lcode = *(njt_http_script_len_code_pt *) le.ip;
        }
        le.ip += sizeof(uintptr_t);

        if (val_len == 0) {
            continue;
        }

        len += key_len + sizeof(": ") - 1 + val_len + sizeof(CRLF) - 1;
    }


    if (plcf->upstream.pass_request_headers) {
        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (njt_hash_find(&headers->hash, header[i].hash,
                              header[i].lowcase_key, header[i].key.len))
            {
                continue;
            }

            len += header[i].key.len + sizeof(": ") - 1
                + header[i].value.len + sizeof(CRLF) - 1;
        }
    }


    b = njt_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NJT_ERROR;
    }

    cl = njt_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NJT_ERROR;
    }

    cl->buf = b;


    /* the request line */

    b->last = njt_copy(b->last, method.data, method.len);
    *b->last++ = ' ';

    u->uri.data = b->last;

    if (plcf->proxy_lengths && ctx->vars.uri.len) {
        b->last = njt_copy(b->last, ctx->vars.uri.data, ctx->vars.uri.len);

    } else if (unparsed_uri) {
        b->last = njt_copy(b->last, r->unparsed_uri.data, r->unparsed_uri.len);

    } else {
        if (r->valid_location) {
            b->last = njt_copy(b->last, ctx->vars.uri.data, ctx->vars.uri.len);
        }

        if (escape) {
            njt_escape_uri(b->last, r->uri.data + loc_len,
                           r->uri.len - loc_len, NJT_ESCAPE_URI);
            b->last += r->uri.len - loc_len + escape;

        } else {
            b->last = njt_copy(b->last, r->uri.data + loc_len,
                               r->uri.len - loc_len);
        }

        if (r->args.len > 0) {
            *b->last++ = '?';
            b->last = njt_copy(b->last, r->args.data, r->args.len);
        }
    }

    u->uri.len = b->last - u->uri.data;

#if (NJT_HTTP_V3)
    if (plcf->http_version == NJT_HTTP_VERSION_30 && plcf->enable_hq) {
        goto nover;
    }
#endif

    if (plcf->http_version == NJT_HTTP_VERSION_11) {
        b->last = njt_cpymem(b->last, njt_http_proxy_version_11,
                             sizeof(njt_http_proxy_version_11) - 1);

    } else {
        b->last = njt_cpymem(b->last, njt_http_proxy_version,
                             sizeof(njt_http_proxy_version) - 1);
    }

#if (NJT_HTTP_V3)
nover:
#endif

    njt_memzero(&e, sizeof(njt_http_script_engine_t));

    e.ip = headers->values->elts;
    e.pos = b->last;
    e.request = r;
    e.flushed = 1;

    le.ip = headers->lengths->elts;

    while (*(uintptr_t *) le.ip) {

        lcode = *(njt_http_script_len_code_pt *) le.ip;
        (void) lcode(&le);

        for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
            lcode = *(njt_http_script_len_code_pt *) le.ip;
        }
        le.ip += sizeof(uintptr_t);

        if (val_len == 0) {
            e.skip = 1;

            while (*(uintptr_t *) e.ip) {
                code = *(njt_http_script_code_pt *) e.ip;
                code((njt_http_script_engine_t *) &e);
            }
            e.ip += sizeof(uintptr_t);

            e.skip = 0;

            continue;
        }

        code = *(njt_http_script_code_pt *) e.ip;
        code((njt_http_script_engine_t *) &e);

        *e.pos++ = ':'; *e.pos++ = ' ';

        while (*(uintptr_t *) e.ip) {
            code = *(njt_http_script_code_pt *) e.ip;
            code((njt_http_script_engine_t *) &e);
        }
        e.ip += sizeof(uintptr_t);

        *e.pos++ = CR; *e.pos++ = LF;
    }

    b->last = e.pos;


    if (plcf->upstream.pass_request_headers) {
        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (njt_hash_find(&headers->hash, header[i].hash,
                              header[i].lowcase_key, header[i].key.len))
            {
                continue;
            }

            b->last = njt_copy(b->last, header[i].key.data, header[i].key.len);

            *b->last++ = ':'; *b->last++ = ' ';

            b->last = njt_copy(b->last, header[i].value.data,
                               header[i].value.len);

            *b->last++ = CR; *b->last++ = LF;

            njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header: \"%V: %V\"",
                           &header[i].key, &header[i].value);
        }
    }


    /* add "\r\n" at the header end */
    *b->last++ = CR; *b->last++ = LF;

    if (plcf->body_values) {
        e.ip = plcf->body_values->elts;
        e.pos = b->last;
        e.skip = 0;

        while (*(uintptr_t *) e.ip) {
            code = *(njt_http_script_code_pt *) e.ip;
            code((njt_http_script_engine_t *) &e);
        }

        b->last = e.pos;
    }

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy header:%N\"%*s\"",
                   (size_t) (b->last - b->pos), b->pos);

    if (r->request_body_no_buffering) {

        u->request_bufs = cl;

        if (ctx->internal_chunked) {
            u->output.output_filter = njt_http_proxy_body_output_filter;
            u->output.filter_ctx = r;
        }

    } else if (plcf->body_values == NULL && plcf->upstream.pass_request_body) {

        body = u->request_bufs;
        u->request_bufs = cl;

        while (body) {
            b = njt_alloc_buf(r->pool);
            if (b == NULL) {
                return NJT_ERROR;
            }

            njt_memcpy(b, body->buf, sizeof(njt_buf_t));

            cl->next = njt_alloc_chain_link(r->pool);
            if (cl->next == NULL) {
                return NJT_ERROR;
            }

            cl = cl->next;
            cl->buf = b;

            body = body->next;
        }

    } else {
        u->request_bufs = cl;
    }

    b->flush = 1;
    cl->next = NULL;

    return NJT_OK;
}


static njt_int_t
njt_http_proxy_reinit_request(njt_http_request_t *r)
{
    njt_http_proxy_ctx_t  *ctx;

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    if (ctx == NULL) {
        return NJT_OK;
    }

    ctx->status.code = 0;
    ctx->status.count = 0;
    ctx->status.start = NULL;
    ctx->status.end = NULL;
    ctx->chunked.state = 0;

    r->upstream->process_header = njt_http_proxy_process_status_line;
    r->upstream->pipe->input_filter = njt_http_proxy_copy_filter;
    r->upstream->input_filter = njt_http_proxy_non_buffered_copy_filter;
    r->state = 0;

    return NJT_OK;
}


static njt_int_t
njt_http_proxy_body_output_filter(void *data, njt_chain_t *in)
{
    njt_http_request_t  *r = data;

    off_t                  size;
    u_char                *chunk;
    njt_int_t              rc;
    njt_buf_t             *b;
    njt_chain_t           *out, *cl, *tl, **ll, **fl;
    njt_http_proxy_ctx_t  *ctx;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "proxy output filter");

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    if (in == NULL) {
        out = in;
        goto out;
    }

    out = NULL;
    ll = &out;

    if (!ctx->header_sent) {
        /* first buffer contains headers, pass it unmodified */

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "proxy output header");

        ctx->header_sent = 1;

        tl = njt_alloc_chain_link(r->pool);
        if (tl == NULL) {
            return NJT_ERROR;
        }

        tl->buf = in->buf;
        *ll = tl;
        ll = &tl->next;

        in = in->next;

        if (in == NULL) {
            tl->next = NULL;
            goto out;
        }
    }

    size = 0;
    cl = in;
    fl = ll;

    for ( ;; ) {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "proxy output chunk: %O", njt_buf_size(cl->buf));

        size += njt_buf_size(cl->buf);

        if (cl->buf->flush
            || cl->buf->sync
            || njt_buf_in_memory(cl->buf)
            || cl->buf->in_file)
        {
            tl = njt_alloc_chain_link(r->pool);
            if (tl == NULL) {
                return NJT_ERROR;
            }

            tl->buf = cl->buf;
            *ll = tl;
            ll = &tl->next;
        }

        if (cl->next == NULL) {
            break;
        }

        cl = cl->next;
    }

    if (size) {
        tl = njt_chain_get_free_buf(r->pool, &ctx->free);
        if (tl == NULL) {
            return NJT_ERROR;
        }

        b = tl->buf;
        chunk = b->start;

        if (chunk == NULL) {
            /* the "0000000000000000" is 64-bit hexadecimal string */

            chunk = njt_palloc(r->pool, sizeof("0000000000000000" CRLF) - 1);
            if (chunk == NULL) {
                return NJT_ERROR;
            }

            b->start = chunk;
            b->end = chunk + sizeof("0000000000000000" CRLF) - 1;
        }

        b->tag = (njt_buf_tag_t) &njt_http_proxy_body_output_filter;
        b->memory = 0;
        b->temporary = 1;
        b->pos = chunk;
        b->last = njt_sprintf(chunk, "%xO" CRLF, size);

        tl->next = *fl;
        *fl = tl;
    }

    if (cl->buf->last_buf) {
        tl = njt_chain_get_free_buf(r->pool, &ctx->free);
        if (tl == NULL) {
            return NJT_ERROR;
        }

        b = tl->buf;

        b->tag = (njt_buf_tag_t) &njt_http_proxy_body_output_filter;
        b->temporary = 0;
        b->memory = 1;
        b->last_buf = 1;
        b->pos = (u_char *) CRLF "0" CRLF CRLF;
        b->last = b->pos + 7;

        cl->buf->last_buf = 0;

        *ll = tl;

        if (size == 0) {
            b->pos += 2;
        }

    } else if (size > 0) {
        tl = njt_chain_get_free_buf(r->pool, &ctx->free);
        if (tl == NULL) {
            return NJT_ERROR;
        }

        b = tl->buf;

        b->tag = (njt_buf_tag_t) &njt_http_proxy_body_output_filter;
        b->temporary = 0;
        b->memory = 1;
        b->pos = (u_char *) CRLF;
        b->last = b->pos + 2;

        *ll = tl;

    } else {
        *ll = NULL;
    }

out:

    rc = njt_chain_writer(&r->upstream->writer, out);

    njt_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
                            (njt_buf_tag_t) &njt_http_proxy_body_output_filter);

    return rc;
}


static njt_int_t
njt_http_proxy_process_status_line(njt_http_request_t *r)
{
    size_t                 len;
    njt_int_t              rc;
    njt_http_upstream_t   *u;
    njt_http_proxy_ctx_t  *ctx;

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    if (ctx == NULL) {
        return NJT_ERROR;
    }

    u = r->upstream;

    rc = njt_http_parse_status_line(r, &u->buffer, &ctx->status);

    if (rc == NJT_AGAIN) {
        return rc;
    }

    if (rc == NJT_ERROR) {

#if (NJT_HTTP_CACHE)

        if (r->cache) {
            r->http_version = NJT_HTTP_VERSION_9;
            return NJT_OK;
        }

#endif

#if (NJT_HTTP_V3)
        {

        njt_http_proxy_loc_conf_t  *plcf;

        plcf = njt_http_get_module_loc_conf(r, njt_http_proxy_module);

        if (plcf->http_version == NJT_HTTP_VERSION_30 && plcf->enable_hq) {
            r->http_version = NJT_HTTP_VERSION_9;
            u->state->status = NJT_HTTP_OK;
            u->headers_in.connection_close = 1;

            return NJT_OK;
        }

        }
#endif
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "upstream sent no valid HTTP/1.0 header");

#if 0
        if (u->accel) {
            return NJT_HTTP_UPSTREAM_INVALID_HEADER;
        }
#endif

        r->http_version = NJT_HTTP_VERSION_9;
        u->state->status = NJT_HTTP_OK;
        u->headers_in.connection_close = 1;

        return NJT_OK;
    }

    if (u->state && u->state->status == 0) {
        u->state->status = ctx->status.code;
    }

    u->headers_in.status_n = ctx->status.code;

    len = ctx->status.end - ctx->status.start;
    u->headers_in.status_line.len = len;

    u->headers_in.status_line.data = njt_pnalloc(r->pool, len);
    if (u->headers_in.status_line.data == NULL) {
        return NJT_ERROR;
    }

    njt_memcpy(u->headers_in.status_line.data, ctx->status.start, len);

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy status %ui \"%V\"",
                   u->headers_in.status_n, &u->headers_in.status_line);

    if (ctx->status.http_version < NJT_HTTP_VERSION_11) {
        u->headers_in.connection_close = 1;
    }

    u->process_header = njt_http_proxy_process_header;

    return njt_http_proxy_process_header(r);
}


static njt_int_t
njt_http_proxy_process_header(njt_http_request_t *r)
{
    njt_int_t                       rc;
    njt_table_elt_t                *h;
    njt_http_upstream_t            *u;
    njt_http_proxy_ctx_t           *ctx;
    njt_http_upstream_header_t     *hh;
    njt_http_upstream_main_conf_t  *umcf;

    umcf = njt_http_get_module_main_conf(r, njt_http_upstream_module);

    for ( ;; ) {

        rc = njt_http_parse_header_line(r, &r->upstream->buffer, 1);

        if (rc == NJT_OK) {

            /* a header line has been parsed successfully */

            h = njt_list_push(&r->upstream->headers_in.headers);
            if (h == NULL) {
                return NJT_ERROR;
            }

            h->hash = r->header_hash;

            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;

            h->key.data = njt_pnalloc(r->pool,
                               h->key.len + 1 + h->value.len + 1 + h->key.len);
            if (h->key.data == NULL) {
                h->hash = 0;
                return NJT_ERROR;
            }

            h->value.data = h->key.data + h->key.len + 1;
            h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

            njt_memcpy(h->key.data, r->header_name_start, h->key.len);
            h->key.data[h->key.len] = '\0';
            njt_memcpy(h->value.data, r->header_start, h->value.len);
            h->value.data[h->value.len] = '\0';

            if (h->key.len == r->lowcase_index) {
                njt_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

            } else {
                njt_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            hh = njt_hash_find(&umcf->headers_in_hash, h->hash,
                               h->lowcase_key, h->key.len);

            if (hh) {
                rc = hh->handler(r, h, hh->offset);

                if (rc != NJT_OK) {
                    return rc;
                }
            }

            njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header: \"%V: %V\"",
                           &h->key, &h->value);

            continue;
        }

        if (rc == NJT_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header done");

            /*
             * if no "Server" and "Date" in header line,
             * then add the special empty headers
             */

            if (r->upstream->headers_in.server == NULL) {
                h = njt_list_push(&r->upstream->headers_in.headers);
                if (h == NULL) {
                    return NJT_ERROR;
                }

                h->hash = njt_hash(njt_hash(njt_hash(njt_hash(
                                    njt_hash('s', 'e'), 'r'), 'v'), 'e'), 'r');

                njt_str_set(&h->key, "Server");
                njt_str_null(&h->value);
                h->lowcase_key = (u_char *) "server";
                h->next = NULL;
            }

            if (r->upstream->headers_in.date == NULL) {
                h = njt_list_push(&r->upstream->headers_in.headers);
                if (h == NULL) {
                    return NJT_ERROR;
                }

                h->hash = njt_hash(njt_hash(njt_hash('d', 'a'), 't'), 'e');

                njt_str_set(&h->key, "Date");
                njt_str_null(&h->value);
                h->lowcase_key = (u_char *) "date";
                h->next = NULL;
            }

            /* clear content length if response is chunked */

            u = r->upstream;

            if (u->headers_in.chunked) {
                u->headers_in.content_length_n = -1;
            }

            /*
             * set u->keepalive if response has no body; this allows to keep
             * connections alive in case of r->header_only or X-Accel-Redirect
             */

            ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

            if (u->headers_in.status_n == NJT_HTTP_NO_CONTENT
                || u->headers_in.status_n == NJT_HTTP_NOT_MODIFIED
                || ctx->head
                || (!u->headers_in.chunked
                    && u->headers_in.content_length_n == 0))
            {
                u->keepalive = !u->headers_in.connection_close;
            }

            if (u->headers_in.status_n == NJT_HTTP_SWITCHING_PROTOCOLS) {
                u->keepalive = 0;

                if (r->headers_in.upgrade) {
                    u->upgrade = 1;
                }
            }

            return NJT_OK;
        }

        if (rc == NJT_AGAIN) {
            return NJT_AGAIN;
        }

        /* rc == NJT_HTTP_PARSE_INVALID_HEADER */

        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "upstream sent invalid header: \"%*s\\x%02xd...\"",
                      r->header_end - r->header_name_start,
                      r->header_name_start, *r->header_end);

        return NJT_HTTP_UPSTREAM_INVALID_HEADER;
    }
}


static njt_int_t
njt_http_proxy_input_filter_init(void *data)
{
    njt_http_request_t    *r = data;
    njt_http_upstream_t   *u;
    njt_http_proxy_ctx_t  *ctx;

    u = r->upstream;
    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    if (ctx == NULL) {
        return NJT_ERROR;
    }

    njt_log_debug4(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy filter init s:%ui h:%d c:%d l:%O",
                   u->headers_in.status_n, ctx->head, u->headers_in.chunked,
                   u->headers_in.content_length_n);

    /* as per RFC2616, 4.4 Message Length */

    if (u->headers_in.status_n == NJT_HTTP_NO_CONTENT
        || u->headers_in.status_n == NJT_HTTP_NOT_MODIFIED
        || ctx->head)
    {
        /* 1xx, 204, and 304 and replies to HEAD requests */
        /* no 1xx since we don't send Expect and Upgrade */

        u->pipe->length = 0;
        u->length = 0;
        u->keepalive = !u->headers_in.connection_close;

    } else if (u->headers_in.chunked) {
        /* chunked */

        u->pipe->input_filter = njt_http_proxy_chunked_filter;
        u->pipe->length = 3; /* "0" LF LF */

        u->input_filter = njt_http_proxy_non_buffered_chunked_filter;
        u->length = 1;

    } else if (u->headers_in.content_length_n == 0) {
        /* empty body: special case as filter won't be called */

        u->pipe->length = 0;
        u->length = 0;
        u->keepalive = !u->headers_in.connection_close;

    } else {
        /* content length or connection close */

        u->pipe->length = u->headers_in.content_length_n;
        u->length = u->headers_in.content_length_n;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_proxy_copy_filter(njt_event_pipe_t *p, njt_buf_t *buf)
{
    njt_buf_t           *b;
    njt_chain_t         *cl;
    njt_http_request_t  *r;

    if (buf->pos == buf->last) {
        return NJT_OK;
    }

    if (p->upstream_done) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, p->log, 0,
                       "http proxy data after close");
        return NJT_OK;
    }

    if (p->length == 0) {

        njt_log_error(NJT_LOG_WARN, p->log, 0,
                      "upstream sent more data than specified in "
                      "\"Content-Length\" header");

        r = p->input_ctx;
        r->upstream->keepalive = 0;
        p->upstream_done = 1;

        return NJT_OK;
    }

    cl = njt_chain_get_free_buf(p->pool, &p->free);
    if (cl == NULL) {
        return NJT_ERROR;
    }

    b = cl->buf;

    njt_memcpy(b, buf, sizeof(njt_buf_t));
    b->shadow = buf;
    b->tag = p->tag;
    b->last_shadow = 1;
    b->recycled = 1;
    buf->shadow = b;

    njt_log_debug1(NJT_LOG_DEBUG_EVENT, p->log, 0, "input buf #%d", b->num);

    if (p->in) {
        *p->last_in = cl;
    } else {
        p->in = cl;
    }
    p->last_in = &cl->next;

    if (p->length == -1) {
        return NJT_OK;
    }

    if (b->last - b->pos > p->length) {

        njt_log_error(NJT_LOG_WARN, p->log, 0,
                      "upstream sent more data than specified in "
                      "\"Content-Length\" header");

        b->last = b->pos + p->length;
        p->upstream_done = 1;

        return NJT_OK;
    }

    p->length -= b->last - b->pos;

    if (p->length == 0) {
        r = p->input_ctx;
        r->upstream->keepalive = !r->upstream->headers_in.connection_close;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_proxy_chunked_filter(njt_event_pipe_t *p, njt_buf_t *buf)
{
    njt_int_t                   rc;
    njt_buf_t                  *b, **prev;
    njt_chain_t                *cl;
    njt_http_request_t         *r;
    njt_http_proxy_ctx_t       *ctx;
    njt_http_proxy_loc_conf_t  *plcf;

    if (buf->pos == buf->last) {
        return NJT_OK;
    }

    r = p->input_ctx;
    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    if (ctx == NULL) {
        return NJT_ERROR;
    }

    if (p->upstream_done) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, p->log, 0,
                       "http proxy data after close");
        return NJT_OK;
    }

    if (p->length == 0) {

        njt_log_error(NJT_LOG_WARN, p->log, 0,
                      "upstream sent data after final chunk");

        r->upstream->keepalive = 0;
        p->upstream_done = 1;

        return NJT_OK;
    }

    b = NULL;

    if (ctx->trailers) {
        rc = njt_http_proxy_process_trailer(r, buf);

        if (rc == NJT_ERROR) {
            return NJT_ERROR;
        }

        if (rc == NJT_OK) {

            /* a whole response has been parsed successfully */

            p->length = 0;
            r->upstream->keepalive = !r->upstream->headers_in.connection_close;

           if (buf->pos != buf->last) {
                njt_log_error(NJT_LOG_WARN, p->log, 0,
                              "upstream sent data after trailers");
                r->upstream->keepalive = 0;
            }
        }

        goto free_buf;
    }

    plcf = njt_http_get_module_loc_conf(r, njt_http_proxy_module);

    prev = &buf->shadow;

    for ( ;; ) {

        rc = njt_http_parse_chunked(r, buf, &ctx->chunked,
                                    plcf->upstream.pass_trailers);

        if (rc == NJT_OK) {

            /* a chunk has been parsed successfully */

            cl = njt_chain_get_free_buf(p->pool, &p->free);
            if (cl == NULL) {
                return NJT_ERROR;
            }

            b = cl->buf;

            njt_memzero(b, sizeof(njt_buf_t));

            b->pos = buf->pos;
            b->start = buf->start;
            b->end = buf->end;
            b->tag = p->tag;
            b->temporary = 1;
            b->recycled = 1;

            *prev = b;
            prev = &b->shadow;

            if (p->in) {
                *p->last_in = cl;
            } else {
                p->in = cl;
            }
            p->last_in = &cl->next;

            /* STUB */ b->num = buf->num;

            njt_log_debug2(NJT_LOG_DEBUG_EVENT, p->log, 0,
                           "input buf #%d %p", b->num, b->pos);

            if (buf->last - buf->pos >= ctx->chunked.size) {

                buf->pos += (size_t) ctx->chunked.size;
                b->last = buf->pos;
                ctx->chunked.size = 0;

                continue;
            }

            ctx->chunked.size -= buf->last - buf->pos;
            buf->pos = buf->last;
            b->last = buf->last;

            continue;
        }

        if (rc == NJT_DONE) {

            if (plcf->upstream.pass_trailers) {
                rc = njt_http_proxy_process_trailer(r, buf);

                if (rc == NJT_ERROR) {
                    return NJT_ERROR;
                }

                if (rc == NJT_AGAIN) {
                    p->length = 1;
                    break;
                }
            }

            /* a whole response has been parsed successfully */

            p->length = 0;
            r->upstream->keepalive = !r->upstream->headers_in.connection_close;

            if (buf->pos != buf->last) {
                njt_log_error(NJT_LOG_WARN, p->log, 0,
                              "upstream sent data after final chunk");
                r->upstream->keepalive = 0;
            }

            break;
        }

        if (rc == NJT_AGAIN) {

            /* set p->length, minimal amount of data we want to see */

            p->length = ctx->chunked.length;

            break;
        }

        /* invalid response */

        njt_log_error(NJT_LOG_ERR, p->log, 0,
                      "upstream sent invalid chunked response");

        return NJT_ERROR;
    }

free_buf:

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, p->log, 0,
                   "http proxy chunked state %ui, length %O",
                   ctx->chunked.state, p->length);

    if (b) {
        b->shadow = buf;
        b->last_shadow = 1;

        njt_log_debug2(NJT_LOG_DEBUG_EVENT, p->log, 0,
                       "input buf %p %z", b->pos, b->last - b->pos);

        return NJT_OK;
    }

    /* there is no data record in the buf, add it to free chain */

    if (njt_event_pipe_add_free_buf(p, buf) != NJT_OK) {
        return NJT_ERROR;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_proxy_non_buffered_copy_filter(void *data, ssize_t bytes)
{
    njt_http_request_t   *r = data;

    njt_buf_t            *b;
    njt_chain_t          *cl, **ll;
    njt_http_upstream_t  *u;

    u = r->upstream;

    if (u->length == 0) {
        njt_log_error(NJT_LOG_WARN, r->connection->log, 0,
                      "upstream sent more data than specified in "
                      "\"Content-Length\" header");
        u->keepalive = 0;
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

    if (u->length == 0) {
        u->keepalive = !u->headers_in.connection_close;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_proxy_non_buffered_chunked_filter(void *data, ssize_t bytes)
{
    njt_http_request_t   *r = data;

    njt_int_t                   rc;
    njt_buf_t                  *b, *buf;
    njt_chain_t                *cl, **ll;
    njt_http_upstream_t        *u;
    njt_http_proxy_ctx_t       *ctx;
    njt_http_proxy_loc_conf_t  *plcf;

    plcf = njt_http_get_module_loc_conf(r, njt_http_proxy_module);

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    if (ctx == NULL) {
        return NJT_ERROR;
    }

    u = r->upstream;
    buf = &u->buffer;

    buf->pos = buf->last;
    buf->last += bytes;

    if (ctx->trailers) {
        rc = njt_http_proxy_process_trailer(r, buf);

        if (rc == NJT_ERROR) {
            return NJT_ERROR;
        }

        if (rc == NJT_OK) {

            /* a whole response has been parsed successfully */

            r->upstream->keepalive = !u->headers_in.connection_close;
            u->length = 0;

            if (buf->pos != buf->last) {
                njt_log_error(NJT_LOG_WARN, r->connection->log, 0,
                              "upstream sent data after trailers");
                u->keepalive = 0;
            }
        }

        return NJT_OK;
    }

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    for ( ;; ) {

        rc = njt_http_parse_chunked(r, buf, &ctx->chunked,
                                    plcf->upstream.pass_trailers);

        if (rc == NJT_OK) {

            /* a chunk has been parsed successfully */

            cl = njt_chain_get_free_buf(r->pool, &u->free_bufs);
            if (cl == NULL) {
                return NJT_ERROR;
            }

            *ll = cl;
            ll = &cl->next;

            b = cl->buf;

            b->flush = 1;
            b->memory = 1;

            b->pos = buf->pos;
            b->tag = u->output.tag;

            if (buf->last - buf->pos >= ctx->chunked.size) {
                buf->pos += (size_t) ctx->chunked.size;
                b->last = buf->pos;
                ctx->chunked.size = 0;

            } else {
                ctx->chunked.size -= buf->last - buf->pos;
                buf->pos = buf->last;
                b->last = buf->last;
            }

            njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy out buf %p %z",
                           b->pos, b->last - b->pos);

            continue;
        }

        if (rc == NJT_DONE) {

            if (plcf->upstream.pass_trailers) {
                rc = njt_http_proxy_process_trailer(r, buf);

                if (rc == NJT_ERROR) {
                    return NJT_ERROR;
                }

                if (rc == NJT_AGAIN) {
                    u->length = 1;
                    break;
                }
            }

            /* a whole response has been parsed successfully */

            u->keepalive = !u->headers_in.connection_close;
            u->length = 0;

            if (buf->pos != buf->last) {
                njt_log_error(NJT_LOG_WARN, r->connection->log, 0,
                              "upstream sent data after final chunk");
                u->keepalive = 0;
            }

            break;
        }

        if (rc == NJT_AGAIN) {
            break;
        }

        /* invalid response */

        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "upstream sent invalid chunked response");

        return NJT_ERROR;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_proxy_process_trailer(njt_http_request_t *r, njt_buf_t *buf)
{
    size_t                      len;
    njt_int_t                   rc;
    njt_buf_t                  *b;
    njt_table_elt_t            *h;
    njt_http_proxy_ctx_t       *ctx;
    njt_http_proxy_loc_conf_t  *plcf;

    plcf = njt_http_get_module_loc_conf(r, njt_http_proxy_module);

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    if (ctx->trailers == NULL) {
        ctx->trailers = njt_create_temp_buf(r->pool,
                                            plcf->upstream.buffer_size);
        if (ctx->trailers == NULL) {
            return NJT_ERROR;
        }
    }

    b = ctx->trailers;
    len = njt_min(buf->last - buf->pos, b->end - b->last);

    b->last = njt_cpymem(b->last, buf->pos, len);

    for ( ;; ) {

        rc = njt_http_parse_header_line(r, b, 1);

        if (rc == NJT_OK) {

            /* a header line has been parsed successfully */

            h = njt_list_push(&r->upstream->headers_in.trailers);
            if (h == NULL) {
                return NJT_ERROR;
            }

            h->hash = r->header_hash;

            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;

            h->key.data = njt_pnalloc(r->pool,
                               h->key.len + 1 + h->value.len + 1 + h->key.len);
            if (h->key.data == NULL) {
                h->hash = 0;
                return NJT_ERROR;
            }

            h->value.data = h->key.data + h->key.len + 1;
            h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

            njt_memcpy(h->key.data, r->header_name_start, h->key.len);
            h->key.data[h->key.len] = '\0';
            njt_memcpy(h->value.data, r->header_start, h->value.len);
            h->value.data[h->value.len] = '\0';

            if (h->key.len == r->lowcase_index) {
                njt_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

            } else {
                njt_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy trailer: \"%V: %V\"",
                           &h->key, &h->value);
            continue;
        }

        if (rc == NJT_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            buf->pos += len - (b->last - b->pos);

            njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy trailer done");

            return NJT_OK;
        }

        if (rc == NJT_AGAIN) {
            buf->pos += len;

            if (b->last == b->end) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream sent too big trailers");
                return NJT_ERROR;
            }

            return NJT_AGAIN;
        }

        /* rc == NGX_HTTP_PARSE_INVALID_HEADER */

        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "upstream sent invalid trailer: \"%*s\\x%02xd...\"",
                      r->header_end - r->header_name_start,
                      r->header_name_start, *r->header_end);

        return NJT_ERROR;
    }
}

static void
njt_http_proxy_abort_request(njt_http_request_t *r)
{
    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http proxy request");

    return;
}


static void
njt_http_proxy_finalize_request(njt_http_request_t *r, njt_int_t rc)
{
    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http proxy request");

    return;
}


static njt_int_t
njt_http_proxy_host_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_http_proxy_ctx_t  *ctx;

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NJT_OK;
    }

    v->len = ctx->vars.host_header.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->vars.host_header.data;

    return NJT_OK;
}


static njt_int_t
njt_http_proxy_port_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_http_proxy_ctx_t  *ctx;

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NJT_OK;
    }

    v->len = ctx->vars.port.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->vars.port.data;

    return NJT_OK;
}


static njt_int_t
njt_http_proxy_add_x_forwarded_for_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    size_t            len;
    u_char           *p;
    njt_table_elt_t  *h, *xfwd;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    xfwd = r->headers_in.x_forwarded_for;

    len = 0;

    for (h = xfwd; h; h = h->next) {
        len += h->value.len + sizeof(", ") - 1;
    }

    if (len == 0) {
        v->len = r->connection->addr_text.len;
        v->data = r->connection->addr_text.data;
        return NJT_OK;
    }

    len += r->connection->addr_text.len;

    p = njt_pnalloc(r->pool, len);
    if (p == NULL) {
        return NJT_ERROR;
    }

    v->len = len;
    v->data = p;

    for (h = xfwd; h; h = h->next) {
        p = njt_copy(p, h->value.data, h->value.len);
        *p++ = ','; *p++ = ' ';
    }

    njt_memcpy(p, r->connection->addr_text.data, r->connection->addr_text.len);

    return NJT_OK;
}


static njt_int_t
njt_http_proxy_internal_body_length_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_http_proxy_ctx_t  *ctx;

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    if (ctx == NULL || ctx->internal_body_length < 0) {
        v->not_found = 1;
        return NJT_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = njt_pnalloc(r->pool, NJT_OFF_T_LEN);

    if (v->data == NULL) {
        return NJT_ERROR;
    }

    v->len = njt_sprintf(v->data, "%O", ctx->internal_body_length) - v->data;

    return NJT_OK;
}


static njt_int_t
njt_http_proxy_internal_chunked_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_http_proxy_ctx_t  *ctx;

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    if (ctx == NULL || !ctx->internal_chunked) {
        v->not_found = 1;
        return NJT_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = (u_char *) "chunked";
    v->len = sizeof("chunked") - 1;

    return NJT_OK;
}


static njt_int_t
njt_http_proxy_rewrite_redirect(njt_http_request_t *r, njt_table_elt_t *h,
    size_t prefix)
{
    size_t                      len;
    njt_int_t                   rc;
    njt_uint_t                  i;
    njt_http_proxy_rewrite_t   *pr;
    njt_http_proxy_loc_conf_t  *plcf;

    plcf = njt_http_get_module_loc_conf(r, njt_http_proxy_module);

    pr = plcf->redirects->elts;

    if (pr == NULL) {
        return NJT_DECLINED;
    }

    len = h->value.len - prefix;

    for (i = 0; i < plcf->redirects->nelts; i++) {
        rc = pr[i].handler(r, &h->value, prefix, len, &pr[i]);

        if (rc != NJT_DECLINED) {
            return rc;
        }
    }

    return NJT_DECLINED;
}


static njt_int_t
njt_http_proxy_rewrite_cookie(njt_http_request_t *r, njt_table_elt_t *h)
{
    u_char                     *p;
    size_t                      len;
    njt_int_t                   rc, rv;
    njt_str_t                  *key, *value;
    njt_uint_t                  i;
    njt_array_t                 attrs;
    njt_keyval_t               *attr;
    njt_http_proxy_loc_conf_t  *plcf;

    if (njt_array_init(&attrs, r->pool, 2, sizeof(njt_keyval_t)) != NJT_OK) {
        return NJT_ERROR;
    }

    if (njt_http_proxy_parse_cookie(&h->value, &attrs) != NJT_OK) {
        return NJT_ERROR;
    }

    attr = attrs.elts;

    if (attr[0].value.data == NULL) {
        return NJT_DECLINED;
    }

    rv = NJT_DECLINED;

    plcf = njt_http_get_module_loc_conf(r, njt_http_proxy_module);

    for (i = 1; i < attrs.nelts; i++) {

        key = &attr[i].key;
        value = &attr[i].value;

        if (plcf->cookie_domains && key->len == 6
            && njt_strncasecmp(key->data, (u_char *) "domain", 6) == 0
            && value->data)
        {
            rc = njt_http_proxy_rewrite_cookie_value(r, value,
                                                     plcf->cookie_domains);
            if (rc == NJT_ERROR) {
                return NJT_ERROR;
            }

            if (rc != NJT_DECLINED) {
                rv = rc;
            }
        }

        if (plcf->cookie_paths && key->len == 4
            && njt_strncasecmp(key->data, (u_char *) "path", 4) == 0
            && value->data)
        {
            rc = njt_http_proxy_rewrite_cookie_value(r, value,
                                                     plcf->cookie_paths);
            if (rc == NJT_ERROR) {
                return NJT_ERROR;
            }

            if (rc != NJT_DECLINED) {
                rv = rc;
            }
        }
    }

    if (plcf->cookie_flags) {
        rc = njt_http_proxy_rewrite_cookie_flags(r, &attrs,
                                                 plcf->cookie_flags);
        if (rc == NJT_ERROR) {
            return NJT_ERROR;
        }

        if (rc != NJT_DECLINED) {
            rv = rc;
        }

        attr = attrs.elts;
    }

    if (rv != NJT_OK) {
        return rv;
    }

    len = 0;

    for (i = 0; i < attrs.nelts; i++) {

        if (attr[i].key.data == NULL) {
            continue;
        }

        if (i > 0) {
            len += 2;
        }

        len += attr[i].key.len;

        if (attr[i].value.data) {
            len += 1 + attr[i].value.len;
        }
    }

    p = njt_pnalloc(r->pool, len + 1);
    if (p == NULL) {
        return NJT_ERROR;
    }

    h->value.data = p;
    h->value.len = len;

    for (i = 0; i < attrs.nelts; i++) {

        if (attr[i].key.data == NULL) {
            continue;
        }

        if (i > 0) {
            *p++ = ';';
            *p++ = ' ';
        }

        p = njt_cpymem(p, attr[i].key.data, attr[i].key.len);

        if (attr[i].value.data) {
            *p++ = '=';
            p = njt_cpymem(p, attr[i].value.data, attr[i].value.len);
        }
    }

    *p = '\0';

    return NJT_OK;
}


static njt_int_t
njt_http_proxy_parse_cookie(njt_str_t *value, njt_array_t *attrs)
{
    u_char        *start, *end, *p, *last;
    njt_str_t      name, val;
    njt_keyval_t  *attr;

    start = value->data;
    end = value->data + value->len;

    for ( ;; ) {

        last = (u_char *) njt_strchr(start, ';');

        if (last == NULL) {
            last = end;
        }

        while (start < last && *start == ' ') { start++; }

        for (p = start; p < last && *p != '='; p++) { /* void */ }

        name.data = start;
        name.len = p - start;

        while (name.len && name.data[name.len - 1] == ' ') {
            name.len--;
        }

        if (p < last) {

            p++;

            while (p < last && *p == ' ') { p++; }

            val.data = p;
            val.len = last - val.data;

            while (val.len && val.data[val.len - 1] == ' ') {
                val.len--;
            }

        } else {
            njt_str_null(&val);
        }

        attr = njt_array_push(attrs);
        if (attr == NULL) {
            return NJT_ERROR;
        }

        attr->key = name;
        attr->value = val;

        if (last == end) {
            break;
        }

        start = last + 1;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_proxy_rewrite_cookie_value(njt_http_request_t *r, njt_str_t *value,
    njt_array_t *rewrites)
{
    njt_int_t                  rc;
    njt_uint_t                 i;
    njt_http_proxy_rewrite_t  *pr;

    pr = rewrites->elts;

    for (i = 0; i < rewrites->nelts; i++) {
        rc = pr[i].handler(r, value, 0, value->len, &pr[i]);

        if (rc != NJT_DECLINED) {
            return rc;
        }
    }

    return NJT_DECLINED;
}


static njt_int_t
njt_http_proxy_rewrite_cookie_flags(njt_http_request_t *r, njt_array_t *attrs,
    njt_array_t *flags)
{
    njt_str_t                       pattern, value;
#if (NJT_PCRE)
    njt_int_t                       rc;
#endif
    njt_uint_t                      i, m, f, nelts;
    njt_keyval_t                   *attr;
    njt_conf_bitmask_t             *mask;
    njt_http_complex_value_t       *flags_values;
    njt_http_proxy_cookie_flags_t  *pcf;

    attr = attrs->elts;
    pcf = flags->elts;

    for (i = 0; i < flags->nelts; i++) {

#if (NJT_PCRE)
        if (pcf[i].regex) {
            rc = njt_http_regex_exec(r, pcf[i].cookie.regex, &attr[0].key);

            if (rc == NJT_ERROR) {
                return NJT_ERROR;
            }

            if (rc == NJT_OK) {
                break;
            }

            /* NJT_DECLINED */

            continue;
        }
#endif

        if (njt_http_complex_value(r, &pcf[i].cookie.complex, &pattern)
            != NJT_OK)
        {
            return NJT_ERROR;
        }

        if (pattern.len == attr[0].key.len
            && njt_strncasecmp(attr[0].key.data, pattern.data, pattern.len)
               == 0)
        {
            break;
        }
    }

    if (i == flags->nelts) {
        return NJT_DECLINED;
    }

    nelts = pcf[i].flags_values.nelts;
    flags_values = pcf[i].flags_values.elts;

    mask = njt_http_proxy_cookie_flags_masks;
    f = 0;

    for (i = 0; i < nelts; i++) {

        if (njt_http_complex_value(r, &flags_values[i], &value) != NJT_OK) {
            return NJT_ERROR;
        }

        if (value.len == 0) {
            continue;
        }

        for (m = 0; mask[m].name.len != 0; m++) {

            if (mask[m].name.len != value.len
                || njt_strncasecmp(mask[m].name.data, value.data, value.len)
                   != 0)
            {
                continue;
            }

            f |= mask[m].mask;

            break;
        }

        if (mask[m].name.len == 0) {
            njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "invalid proxy_cookie_flags flag \"%V\"", &value);
        }
    }

    if (f == 0) {
        return NJT_DECLINED;
    }

    return njt_http_proxy_edit_cookie_flags(r, attrs, f);
}


static njt_int_t
njt_http_proxy_edit_cookie_flags(njt_http_request_t *r, njt_array_t *attrs,
    njt_uint_t flags)
{
    njt_str_t     *key, *value;
    njt_uint_t     i;
    njt_keyval_t  *attr;

    attr = attrs->elts;

    for (i = 1; i < attrs->nelts; i++) {
        key = &attr[i].key;

        if (key->len == 6
            && njt_strncasecmp(key->data, (u_char *) "secure", 6) == 0)
        {
            if (flags & NJT_HTTP_PROXY_COOKIE_SECURE_ON) {
                flags &= ~NJT_HTTP_PROXY_COOKIE_SECURE_ON;

            } else if (flags & NJT_HTTP_PROXY_COOKIE_SECURE_OFF) {
                key->data = NULL;
            }

            continue;
        }

        if (key->len == 8
            && njt_strncasecmp(key->data, (u_char *) "httponly", 8) == 0)
        {
            if (flags & NJT_HTTP_PROXY_COOKIE_HTTPONLY_ON) {
                flags &= ~NJT_HTTP_PROXY_COOKIE_HTTPONLY_ON;

            } else if (flags & NJT_HTTP_PROXY_COOKIE_HTTPONLY_OFF) {
                key->data = NULL;
            }

            continue;
        }

        if (key->len == 8
            && njt_strncasecmp(key->data, (u_char *) "samesite", 8) == 0)
        {
            value = &attr[i].value;

            if (flags & NJT_HTTP_PROXY_COOKIE_SAMESITE_STRICT) {
                flags &= ~NJT_HTTP_PROXY_COOKIE_SAMESITE_STRICT;

                if (value->len != 6
                    || njt_strncasecmp(value->data, (u_char *) "strict", 6)
                       != 0)
                {
                    njt_str_set(key, "SameSite");
                    njt_str_set(value, "Strict");
                }

            } else if (flags & NJT_HTTP_PROXY_COOKIE_SAMESITE_LAX) {
                flags &= ~NJT_HTTP_PROXY_COOKIE_SAMESITE_LAX;

                if (value->len != 3
                    || njt_strncasecmp(value->data, (u_char *) "lax", 3) != 0)
                {
                    njt_str_set(key, "SameSite");
                    njt_str_set(value, "Lax");
                }

            } else if (flags & NJT_HTTP_PROXY_COOKIE_SAMESITE_NONE) {
                flags &= ~NJT_HTTP_PROXY_COOKIE_SAMESITE_NONE;

                if (value->len != 4
                    || njt_strncasecmp(value->data, (u_char *) "none", 4) != 0)
                {
                    njt_str_set(key, "SameSite");
                    njt_str_set(value, "None");
                }

            } else if (flags & NJT_HTTP_PROXY_COOKIE_SAMESITE_OFF) {
                key->data = NULL;
            }

            continue;
        }
    }

    if (flags & NJT_HTTP_PROXY_COOKIE_SECURE_ON) {
        attr = njt_array_push(attrs);
        if (attr == NULL) {
            return NJT_ERROR;
        }

        njt_str_set(&attr->key, "Secure");
        njt_str_null(&attr->value);
    }

    if (flags & NJT_HTTP_PROXY_COOKIE_HTTPONLY_ON) {
        attr = njt_array_push(attrs);
        if (attr == NULL) {
            return NJT_ERROR;
        }

        njt_str_set(&attr->key, "HttpOnly");
        njt_str_null(&attr->value);
    }

    if (flags & (NJT_HTTP_PROXY_COOKIE_SAMESITE_STRICT
                 |NJT_HTTP_PROXY_COOKIE_SAMESITE_LAX
                 |NJT_HTTP_PROXY_COOKIE_SAMESITE_NONE))
    {
        attr = njt_array_push(attrs);
        if (attr == NULL) {
            return NJT_ERROR;
        }

        njt_str_set(&attr->key, "SameSite");

        if (flags & NJT_HTTP_PROXY_COOKIE_SAMESITE_STRICT) {
            njt_str_set(&attr->value, "Strict");

        } else if (flags & NJT_HTTP_PROXY_COOKIE_SAMESITE_LAX) {
            njt_str_set(&attr->value, "Lax");

        } else {
            njt_str_set(&attr->value, "None");
        }
    }

    return NJT_OK;
}


static njt_int_t
njt_http_proxy_rewrite_complex_handler(njt_http_request_t *r, njt_str_t *value,
    size_t prefix, size_t len, njt_http_proxy_rewrite_t *pr)
{
    njt_str_t  pattern, replacement;

    if (njt_http_complex_value(r, &pr->pattern.complex, &pattern) != NJT_OK) {
        return NJT_ERROR;
    }

    if (pattern.len > len
        || njt_rstrncmp(value->data + prefix, pattern.data, pattern.len) != 0)
    {
        return NJT_DECLINED;
    }

    if (njt_http_complex_value(r, &pr->replacement, &replacement) != NJT_OK) {
        return NJT_ERROR;
    }

    return njt_http_proxy_rewrite(r, value, prefix, pattern.len, &replacement);
}


#if (NJT_PCRE)

static njt_int_t
njt_http_proxy_rewrite_regex_handler(njt_http_request_t *r, njt_str_t *value,
    size_t prefix, size_t len, njt_http_proxy_rewrite_t *pr)
{
    njt_str_t  pattern, replacement;

    pattern.len = len;
    pattern.data = value->data + prefix;

    if (njt_http_regex_exec(r, pr->pattern.regex, &pattern) != NJT_OK) {
        return NJT_DECLINED;
    }

    if (njt_http_complex_value(r, &pr->replacement, &replacement) != NJT_OK) {
        return NJT_ERROR;
    }

    return njt_http_proxy_rewrite(r, value, prefix, len, &replacement);
}

#endif


static njt_int_t
njt_http_proxy_rewrite_domain_handler(njt_http_request_t *r, njt_str_t *value,
    size_t prefix, size_t len, njt_http_proxy_rewrite_t *pr)
{
    u_char     *p;
    njt_str_t   pattern, replacement;

    if (njt_http_complex_value(r, &pr->pattern.complex, &pattern) != NJT_OK) {
        return NJT_ERROR;
    }

    p = value->data + prefix;

    if (len && p[0] == '.') {
        p++;
        prefix++;
        len--;
    }

    if (pattern.len != len || njt_rstrncasecmp(pattern.data, p, len) != 0) {
        return NJT_DECLINED;
    }

    if (njt_http_complex_value(r, &pr->replacement, &replacement) != NJT_OK) {
        return NJT_ERROR;
    }

    return njt_http_proxy_rewrite(r, value, prefix, len, &replacement);
}


static njt_int_t
njt_http_proxy_rewrite(njt_http_request_t *r, njt_str_t *value, size_t prefix,
    size_t len, njt_str_t *replacement)
{
    u_char  *p, *data;
    size_t   new_len;

    if (len == value->len) {
        *value = *replacement;
        return NJT_OK;
    }

    new_len = replacement->len + value->len - len;

    if (replacement->len > len) {

        data = njt_pnalloc(r->pool, new_len + 1);
        if (data == NULL) {
            return NJT_ERROR;
        }

        p = njt_copy(data, value->data, prefix);
        p = njt_copy(p, replacement->data, replacement->len);

        njt_memcpy(p, value->data + prefix + len,
                   value->len - len - prefix + 1);

        value->data = data;

    } else {
        p = njt_copy(value->data + prefix, replacement->data, replacement->len);

        njt_memmove(p, value->data + prefix + len,
                    value->len - len - prefix + 1);
    }

    value->len = new_len;

    return NJT_OK;
}


static njt_int_t
njt_http_proxy_add_variables(njt_conf_t *cf)
{
    njt_http_variable_t  *var, *v;

    for (v = njt_http_proxy_vars; v->name.len; v++) {
        var = njt_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NJT_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NJT_OK;
}


static void *
njt_http_proxy_create_main_conf(njt_conf_t *cf)
{
    njt_http_proxy_main_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_proxy_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

#if (NJT_HTTP_CACHE)
    if (njt_array_init(&conf->caches, cf->pool, 4,
                       sizeof(njt_http_file_cache_t *))
        != NJT_OK)
    {
        return NULL;
    }
#endif

    return conf;
}


static void *
njt_http_proxy_create_loc_conf(njt_conf_t *cf)
{
    njt_http_proxy_loc_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_proxy_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->upstream.bufs.num = 0;
     *     conf->upstream.ignore_headers = 0;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.cache_zone = NULL;
     *     conf->upstream.cache_use_stale = 0;
     *     conf->upstream.cache_methods = 0;
     *     conf->upstream.temp_path = NULL;
     *     conf->upstream.hide_headers_hash = { NULL, 0 };
     *     conf->upstream.store_lengths = NULL;
     *     conf->upstream.store_values = NULL;
     *
     *     conf->location = NULL;
     *     conf->url = { 0, NULL };
     *     conf->headers.lengths = NULL;
     *     conf->headers.values = NULL;
     *     conf->headers.hash = { NULL, 0 };
     *     conf->headers_cache.lengths = NULL;
     *     conf->headers_cache.values = NULL;
     *     conf->headers_cache.hash = { NULL, 0 };
     *     conf->body_lengths = NULL;
     *     conf->body_values = NULL;
     *     conf->body_source = { 0, NULL };
     *     conf->redirects = NULL;
     *     conf->ssl = 0;
     *     conf->ssl_protocols = 0;
     *     conf->ssl_ciphers = { 0, NULL };
     *     conf->ssl_trusted_certificate = { 0, NULL };
     *     conf->ssl_crl = { 0, NULL };
     * 
     *     conf->ssl_certificate = NULL;
     *     conf->ssl_certificate_key = NULL;
     *
     *     conf->upstream.quic.host_key = { 0, NULL }
     *     conf->upstream.quic.stream_reject_code_uni = 0;
     *     conf->upstream.quic.disable_active_migration = 0;
     *     conf->upstream.quic.idle_timeout = 0;
     *     conf->upstream.quic.handshake_timeout = 0;
     *     conf->upstream.quic.retry = 0;
     */

    conf->upstream.store = NJT_CONF_UNSET;
    conf->upstream.store_access = NJT_CONF_UNSET_UINT;
    conf->upstream.next_upstream_tries = NJT_CONF_UNSET_UINT;
    conf->upstream.buffering = NJT_CONF_UNSET;
    conf->upstream.request_buffering = NJT_CONF_UNSET;
    conf->upstream.ignore_client_abort = NJT_CONF_UNSET;
    conf->upstream.force_ranges = NJT_CONF_UNSET;

    conf->upstream.local = NJT_CONF_UNSET_PTR;
    conf->upstream.socket_keepalive = NJT_CONF_UNSET;

    conf->upstream.connect_timeout = NJT_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NJT_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NJT_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_timeout = NJT_CONF_UNSET_MSEC;

    conf->upstream.send_lowat = NJT_CONF_UNSET_SIZE;
    conf->upstream.buffer_size = NJT_CONF_UNSET_SIZE;
    conf->upstream.limit_rate = NJT_CONF_UNSET_PTR;

    conf->upstream.busy_buffers_size_conf = NJT_CONF_UNSET_SIZE;
    conf->upstream.max_temp_file_size_conf = NJT_CONF_UNSET_SIZE;
    conf->upstream.temp_file_write_size_conf = NJT_CONF_UNSET_SIZE;

    conf->upstream.pass_request_headers = NJT_CONF_UNSET;
    conf->upstream.pass_request_body = NJT_CONF_UNSET;
    conf->upstream.pass_trailers = NJT_CONF_UNSET;

#if (NJT_HTTP_CACHE)
    conf->upstream.cache = NJT_CONF_UNSET;
    conf->upstream.cache_min_uses = NJT_CONF_UNSET_UINT;
    conf->upstream.cache_max_range_offset = NJT_CONF_UNSET;
    conf->upstream.cache_bypass = NJT_CONF_UNSET_PTR;
    conf->upstream.no_cache = NJT_CONF_UNSET_PTR;
    conf->upstream.cache_valid = NJT_CONF_UNSET_PTR;
    conf->upstream.cache_lock = NJT_CONF_UNSET;
    conf->upstream.cache_lock_timeout = NJT_CONF_UNSET_MSEC;
    conf->upstream.cache_lock_age = NJT_CONF_UNSET_MSEC;
    conf->upstream.cache_revalidate = NJT_CONF_UNSET;
    conf->upstream.cache_convert_head = NJT_CONF_UNSET;
    conf->upstream.cache_background_update = NJT_CONF_UNSET;
#endif

    conf->upstream.hide_headers = NJT_CONF_UNSET_PTR;
    conf->upstream.pass_headers = NJT_CONF_UNSET_PTR;

    conf->upstream.intercept_errors = NJT_CONF_UNSET;

#if (NJT_HTTP_SSL)
    conf->upstream.ssl_session_reuse = NJT_CONF_UNSET;
    conf->upstream.ssl_name = NJT_CONF_UNSET_PTR;
    conf->upstream.ssl_server_name = NJT_CONF_UNSET;
    conf->upstream.ssl_verify = NJT_CONF_UNSET;
#if (NJT_HTTP_MULTICERT)
    conf->upstream.ssl_certificates = NJT_CONF_UNSET_PTR;
    conf->upstream.ssl_certificate_keys = NJT_CONF_UNSET_PTR;
#else
    conf->upstream.ssl_certificate = NJT_CONF_UNSET_PTR;
    conf->upstream.ssl_certificate_key = NJT_CONF_UNSET_PTR;
#endif
    conf->upstream.ssl_certificate_cache = NJT_CONF_UNSET_PTR;
    conf->upstream.ssl_passwords = NJT_CONF_UNSET_PTR;
    conf->ssl_verify_depth = NJT_CONF_UNSET_UINT;
    conf->ssl_conf_commands = NJT_CONF_UNSET_PTR;
#if (NJT_HAVE_NTLS)
    conf->upstream.ssl_ntls = NJT_CONF_UNSET;
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
    /* add by hlyan for tls1.3 sm2ecdh */
    conf->upstream.tls13_sm_ecdh = NJT_CONF_UNSET;
#endif
#endif
#endif

    /* "proxy_cyclic_temp_file" is disabled */
    conf->upstream.cyclic_temp_file = 0;

    conf->upstream.change_buffering = 1;

    conf->headers_source = NJT_CONF_UNSET_PTR;

    conf->method = NJT_CONF_UNSET_PTR;

    conf->redirect = NJT_CONF_UNSET;

    conf->cookie_domains = NJT_CONF_UNSET_PTR;
    conf->cookie_paths = NJT_CONF_UNSET_PTR;
    conf->cookie_flags = NJT_CONF_UNSET_PTR;

    conf->http_version = NJT_CONF_UNSET_UINT;

    conf->headers_hash_max_size = NJT_CONF_UNSET_UINT;
    conf->headers_hash_bucket_size = NJT_CONF_UNSET_UINT;

    njt_str_set(&conf->upstream.module, "proxy");

#if (NJT_HTTP_V3)

    conf->upstream.quic.stream_buffer_size = NJT_CONF_UNSET_SIZE;
    conf->upstream.quic.max_concurrent_streams_bidi = NJT_CONF_UNSET_UINT;
    conf->upstream.quic.max_concurrent_streams_uni =
                                                   NJT_HTTP_V3_MAX_UNI_STREAMS;
    conf->upstream.quic.gso_enabled = NJT_CONF_UNSET;

    conf->upstream.quic.active_connection_id_limit = NJT_CONF_UNSET_UINT;

    conf->upstream.quic.stream_close_code = NJT_HTTP_V3_ERR_NO_ERROR;
    conf->upstream.quic.stream_reject_code_bidi =
                                              NJT_HTTP_V3_ERR_REQUEST_REJECTED;

    conf->upstream.quic.shutdown = njt_http_v3_shutdown;

    conf->enable_hq = NJT_CONF_UNSET;
#endif
#if (NJT_HTTP_V2)
    conf->upstream.h2_conf.recv_window = NJT_CONF_UNSET_SIZE;
    conf->upstream.h2_conf.concurrent_streams = NJT_CONF_UNSET_UINT;
    conf->upstream.h2_conf.streams_index_mask = NJT_CONF_UNSET_UINT;
#endif
    return conf;
}


static char *
njt_http_proxy_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_proxy_loc_conf_t *prev = parent;
    njt_http_proxy_loc_conf_t *conf = child;

    u_char                     *p;
    size_t                      size;
    njt_int_t                   rc;
    njt_keyval_t               *proxy_headers;
    njt_hash_init_t             hash;
    njt_http_core_loc_conf_t   *clcf;
    njt_http_proxy_rewrite_t   *pr;
    njt_http_script_compile_t   sc;

#if (NJT_HTTP_CACHE)

    if (conf->upstream.store > 0) {
        conf->upstream.cache = 0;
    }

    if (conf->upstream.cache > 0) {
        conf->upstream.store = 0;
    }

#endif

    if (conf->upstream.store == NJT_CONF_UNSET) {
        njt_conf_merge_value(conf->upstream.store,
                              prev->upstream.store, 0);

        conf->upstream.store_lengths = prev->upstream.store_lengths;
        conf->upstream.store_values = prev->upstream.store_values;
    }

    njt_conf_merge_uint_value(conf->upstream.store_access,
                              prev->upstream.store_access, 0600);

    njt_conf_merge_uint_value(conf->upstream.next_upstream_tries,
                              prev->upstream.next_upstream_tries, 0);

    njt_conf_merge_value(conf->upstream.buffering,
                              prev->upstream.buffering, 1);

    njt_conf_merge_value(conf->upstream.request_buffering,
                              prev->upstream.request_buffering, 1);

    njt_conf_merge_value(conf->upstream.ignore_client_abort,
                              prev->upstream.ignore_client_abort, 0);

    njt_conf_merge_value(conf->upstream.force_ranges,
                              prev->upstream.force_ranges, 0);

    njt_conf_merge_ptr_value(conf->upstream.local,
                              prev->upstream.local, NULL);

    njt_conf_merge_value(conf->upstream.socket_keepalive,
                              prev->upstream.socket_keepalive, 0);

    njt_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    njt_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    njt_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    njt_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
                              prev->upstream.next_upstream_timeout, 0);

    njt_conf_merge_size_value(conf->upstream.send_lowat,
                              prev->upstream.send_lowat, 0);

    njt_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) njt_pagesize);

    njt_conf_merge_ptr_value(conf->upstream.limit_rate,
                              prev->upstream.limit_rate, NULL);

    njt_conf_merge_bufs_value(conf->upstream.bufs, prev->upstream.bufs,
                              8, njt_pagesize);

    if (conf->upstream.bufs.num < 2) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "there must be at least 2 \"proxy_buffers\"");
        return NJT_CONF_ERROR;
    }


    size = conf->upstream.buffer_size;
    if (size < conf->upstream.bufs.size) {
        size = conf->upstream.bufs.size;
    }


    njt_conf_merge_size_value(conf->upstream.busy_buffers_size_conf,
                              prev->upstream.busy_buffers_size_conf,
                              NJT_CONF_UNSET_SIZE);

    if (conf->upstream.busy_buffers_size_conf == NJT_CONF_UNSET_SIZE) {
        conf->upstream.busy_buffers_size = 2 * size;
    } else {
        conf->upstream.busy_buffers_size =
                                         conf->upstream.busy_buffers_size_conf;
    }

    if (conf->upstream.busy_buffers_size < size) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
             "\"proxy_busy_buffers_size\" must be equal to or greater than "
             "the maximum of the value of \"proxy_buffer_size\" and "
             "one of the \"proxy_buffers\"");

        return NJT_CONF_ERROR;
    }

    if (conf->upstream.busy_buffers_size
        > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size)
    {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
             "\"proxy_busy_buffers_size\" must be less than "
             "the size of all \"proxy_buffers\" minus one buffer");

        return NJT_CONF_ERROR;
    }


    njt_conf_merge_size_value(conf->upstream.temp_file_write_size_conf,
                              prev->upstream.temp_file_write_size_conf,
                              NJT_CONF_UNSET_SIZE);

    if (conf->upstream.temp_file_write_size_conf == NJT_CONF_UNSET_SIZE) {
        conf->upstream.temp_file_write_size = 2 * size;
    } else {
        conf->upstream.temp_file_write_size =
                                      conf->upstream.temp_file_write_size_conf;
    }

    if (conf->upstream.temp_file_write_size < size) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
             "\"proxy_temp_file_write_size\" must be equal to or greater "
             "than the maximum of the value of \"proxy_buffer_size\" and "
             "one of the \"proxy_buffers\"");

        return NJT_CONF_ERROR;
    }

    njt_conf_merge_size_value(conf->upstream.max_temp_file_size_conf,
                              prev->upstream.max_temp_file_size_conf,
                              NJT_CONF_UNSET_SIZE);

    if (conf->upstream.max_temp_file_size_conf == NJT_CONF_UNSET_SIZE) {
        conf->upstream.max_temp_file_size = 1024 * 1024 * 1024;
    } else {
        conf->upstream.max_temp_file_size =
                                        conf->upstream.max_temp_file_size_conf;
    }

    if (conf->upstream.max_temp_file_size != 0
        && conf->upstream.max_temp_file_size < size)
    {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
             "\"proxy_max_temp_file_size\" must be equal to zero to disable "
             "temporary files usage or must be equal to or greater than "
             "the maximum of the value of \"proxy_buffer_size\" and "
             "one of the \"proxy_buffers\"");

        return NJT_CONF_ERROR;
    }


    njt_conf_merge_bitmask_value(conf->upstream.ignore_headers,
                              prev->upstream.ignore_headers,
                              NJT_CONF_BITMASK_SET);


    njt_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (NJT_CONF_BITMASK_SET
                               |NJT_HTTP_UPSTREAM_FT_ERROR
                               |NJT_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NJT_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NJT_CONF_BITMASK_SET
                                       |NJT_HTTP_UPSTREAM_FT_OFF;
    }

    if (njt_conf_merge_path_value(cf, &conf->upstream.temp_path,
                              prev->upstream.temp_path,
                              &njt_http_proxy_temp_path)
        != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }


#if (NJT_HTTP_CACHE)

    if (conf->upstream.cache == NJT_CONF_UNSET) {
        njt_conf_merge_value(conf->upstream.cache,
                              prev->upstream.cache, 0);

        conf->upstream.cache_zone = prev->upstream.cache_zone;
        conf->upstream.cache_value = prev->upstream.cache_value;
    }

    if (conf->upstream.cache_zone && conf->upstream.cache_zone->data == NULL) {
        njt_shm_zone_t  *shm_zone;

        shm_zone = conf->upstream.cache_zone;

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "\"proxy_cache\" zone \"%V\" is unknown",
                           &shm_zone->shm.name);

        return NJT_CONF_ERROR;
    }

    njt_conf_merge_uint_value(conf->upstream.cache_min_uses,
                              prev->upstream.cache_min_uses, 1);

    njt_conf_merge_off_value(conf->upstream.cache_max_range_offset,
                              prev->upstream.cache_max_range_offset,
                              NJT_MAX_OFF_T_VALUE);

    njt_conf_merge_bitmask_value(conf->upstream.cache_use_stale,
                              prev->upstream.cache_use_stale,
                              (NJT_CONF_BITMASK_SET
                               |NJT_HTTP_UPSTREAM_FT_OFF));

    if (conf->upstream.cache_use_stale & NJT_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.cache_use_stale = NJT_CONF_BITMASK_SET
                                         |NJT_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.cache_use_stale & NJT_HTTP_UPSTREAM_FT_ERROR) {
        conf->upstream.cache_use_stale |= NJT_HTTP_UPSTREAM_FT_NOLIVE;
    }

    if (conf->upstream.cache_methods == 0) {
        conf->upstream.cache_methods = prev->upstream.cache_methods;
    }

    conf->upstream.cache_methods |= NJT_HTTP_GET|NJT_HTTP_HEAD;

    njt_conf_merge_ptr_value(conf->upstream.cache_bypass,
                             prev->upstream.cache_bypass, NULL);

    njt_conf_merge_ptr_value(conf->upstream.no_cache,
                             prev->upstream.no_cache, NULL);

    njt_conf_merge_ptr_value(conf->upstream.cache_valid,
                             prev->upstream.cache_valid, NULL);

    if (conf->cache_key.value.data == NULL) {
        conf->cache_key = prev->cache_key;
    }
    if (conf->cache_file_key.value.data == NULL) {
        conf->cache_file_key = prev->cache_file_key;
    }

    njt_conf_merge_value(conf->upstream.cache_lock,
                              prev->upstream.cache_lock, 0);

    njt_conf_merge_msec_value(conf->upstream.cache_lock_timeout,
                              prev->upstream.cache_lock_timeout, 5000);

    njt_conf_merge_msec_value(conf->upstream.cache_lock_age,
                              prev->upstream.cache_lock_age, 5000);

    njt_conf_merge_value(conf->upstream.cache_revalidate,
                              prev->upstream.cache_revalidate, 0);

    njt_conf_merge_value(conf->upstream.cache_convert_head,
                              prev->upstream.cache_convert_head, 1);

    njt_conf_merge_value(conf->upstream.cache_background_update,
                              prev->upstream.cache_background_update, 0);

#endif

    njt_conf_merge_value(conf->upstream.pass_request_headers,
                              prev->upstream.pass_request_headers, 1);
    njt_conf_merge_value(conf->upstream.pass_request_body,
                              prev->upstream.pass_request_body, 1);

    njt_conf_merge_value(conf->upstream.pass_trailers,
                              prev->upstream.pass_trailers, 0);

    njt_conf_merge_value(conf->upstream.intercept_errors,
                              prev->upstream.intercept_errors, 0);

#if (NJT_HTTP_SSL)

    if (njt_http_proxy_merge_ssl(cf, conf, prev) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    njt_conf_merge_value(conf->upstream.ssl_session_reuse,
                              prev->upstream.ssl_session_reuse, 1);

    njt_conf_merge_bitmask_value(conf->ssl_protocols, prev->ssl_protocols,
                              (NJT_CONF_BITMASK_SET|NJT_SSL_DEFAULT_PROTOCOLS));

    njt_conf_merge_str_value(conf->ssl_ciphers, prev->ssl_ciphers,
                             "DEFAULT");

    njt_conf_merge_ptr_value(conf->upstream.ssl_name,
                              prev->upstream.ssl_name, NULL);
    njt_conf_merge_value(conf->upstream.ssl_server_name,
                              prev->upstream.ssl_server_name, 0);
    njt_conf_merge_value(conf->upstream.ssl_verify,
                              prev->upstream.ssl_verify, 0);
    njt_conf_merge_uint_value(conf->ssl_verify_depth,
                              prev->ssl_verify_depth, 1);
    njt_conf_merge_str_value(conf->ssl_trusted_certificate,
                              prev->ssl_trusted_certificate, "");
    njt_conf_merge_str_value(conf->ssl_crl, prev->ssl_crl, "");
#if (NJT_HTTP_MULTICERT)
    njt_conf_merge_ptr_value(conf->upstream.ssl_certificates,
                              prev->upstream.ssl_certificates, NULL);
    njt_conf_merge_ptr_value(conf->upstream.ssl_certificate_keys,
                              prev->upstream.ssl_certificate_keys, NULL);
#else
     njt_conf_merge_ptr_value(conf->upstream.ssl_certificate,
                               prev->upstream.ssl_certificate, NULL);
     njt_conf_merge_ptr_value(conf->upstream.ssl_certificate_key,
                               prev->upstream.ssl_certificate_key, NULL);
#endif
    njt_conf_merge_ptr_value(conf->upstream.ssl_passwords,
                              prev->upstream.ssl_passwords, NULL);

    njt_conf_merge_ptr_value(conf->ssl_conf_commands,
                              prev->ssl_conf_commands, NULL);

#if (NJT_HAVE_NTLS)
    njt_conf_merge_value(conf->upstream.ssl_ntls,
                              prev->upstream.ssl_ntls, 0);

    if (conf->upstream.ssl_ntls) {
        conf->upstream.ssl_ciphers = conf->ssl_ciphers;
    }
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
    /* add by hlyan for tls1.3 sm2ecdh */
    njt_conf_merge_value(conf->upstream.tls13_sm_ecdh, prev->upstream.tls13_sm_ecdh, 0);
#endif
#endif
#if (NJT_HAVE_SET_ALPN)
   njt_conf_merge_str_value(conf->proxy_ssl_alpn, prev->proxy_ssl_alpn, "");
#endif

    if (conf->ssl && njt_http_proxy_set_ssl(cf, conf) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

#endif

    njt_conf_merge_ptr_value(conf->method, prev->method, NULL);

    njt_conf_merge_value(conf->redirect, prev->redirect, 1);

    if (conf->redirect) {

        if (conf->redirects == NULL) {
            conf->redirects = prev->redirects;
        }

        if (conf->redirects == NULL && conf->url.data) {

            conf->redirects = njt_array_create(cf->pool, 1,
                                             sizeof(njt_http_proxy_rewrite_t));
            if (conf->redirects == NULL) {
                return NJT_CONF_ERROR;
            }

            pr = njt_array_push(conf->redirects);
            if (pr == NULL) {
                return NJT_CONF_ERROR;
            }

            njt_memzero(&pr->pattern.complex,
                        sizeof(njt_http_complex_value_t));

            njt_memzero(&pr->replacement, sizeof(njt_http_complex_value_t));

            pr->handler = njt_http_proxy_rewrite_complex_handler;

            if (conf->vars.uri.len) {
                pr->pattern.complex.value = conf->url;
                pr->replacement.value = conf->location;

            } else {
                pr->pattern.complex.value.len = conf->url.len
                                                + sizeof("/") - 1;

                p = njt_pnalloc(cf->pool, pr->pattern.complex.value.len);
                if (p == NULL) {
                    return NJT_CONF_ERROR;
                }

                pr->pattern.complex.value.data = p;

                p = njt_cpymem(p, conf->url.data, conf->url.len);
                *p = '/';

                njt_str_set(&pr->replacement.value, "/");
            }
        }
    }

    njt_conf_merge_ptr_value(conf->cookie_domains, prev->cookie_domains, NULL);

    njt_conf_merge_ptr_value(conf->cookie_paths, prev->cookie_paths, NULL);

    njt_conf_merge_ptr_value(conf->cookie_flags, prev->cookie_flags, NULL);

    njt_conf_merge_uint_value(conf->http_version, prev->http_version,
                              NJT_HTTP_VERSION_10);

    njt_conf_merge_uint_value(conf->headers_hash_max_size,
                              prev->headers_hash_max_size, 512);

    njt_conf_merge_uint_value(conf->headers_hash_bucket_size,
                              prev->headers_hash_bucket_size, 64);

    conf->headers_hash_bucket_size = njt_align(conf->headers_hash_bucket_size,
                                               njt_cacheline_size);

    hash.max_size = conf->headers_hash_max_size;
    hash.bucket_size = conf->headers_hash_bucket_size;
    hash.name = "proxy_headers_hash";

#if (NJT_HTTP_V2 )
    if (conf->http_version == NJT_HTTP_VERSION_20) {
        conf->upstream.alpn.data = (unsigned char *)
                                            NJT_HTTP_V2_ALPN_PROTO;
         conf->upstream.alpn.len = sizeof(NJT_HTTP_V2_ALPN_PROTO) - 1;

    } 
#endif
    if (njt_http_upstream_hide_headers_hash(cf, &conf->upstream,
            &prev->upstream, njt_http_proxy_hide_headers, &hash)
        != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

#if (NJT_HTTP_V3)

    if (conf->http_version == NJT_HTTP_VERSION_30) {
        if (njt_http_v3_proxy_merge_quic(cf, conf, prev) != NJT_OK) {
            return NJT_CONF_ERROR;
        }
    }

#endif

    clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);

    if (clcf->noname
        && conf->upstream.upstream == NULL && conf->proxy_lengths == NULL)
    {
        #if (NJT_HTTP_DYNAMIC_UPSTREAM)
            if(prev->upstream.upstream != NULL) {
                prev->upstream.upstream->ref_count++; 
                //jt_conf_log_error(NJT_LOG_EMERG, cf, 0,"merge upstream =%p, ref_count=%i",prev->upstream.upstream,prev->upstream.upstream->ref_count);
            }
        #endif
        conf->upstream.upstream = prev->upstream.upstream;
        conf->location = prev->location;
        conf->vars = prev->vars;

#if (NJT_HTTP_V3 || NJT_HTTP_V2)
        conf->host = prev->host;
#endif
        conf->proxy_lengths = prev->proxy_lengths;
        conf->proxy_values = prev->proxy_values;

#if (NJT_HTTP_SSL)
        conf->ssl = prev->ssl;
#endif
    }

    if (clcf->lmt_excpt && clcf->handler == NULL
        && (conf->upstream.upstream || conf->proxy_lengths))
    {
        clcf->handler = njt_http_proxy_handler;
    }

    if (conf->body_source.data == NULL) {
        conf->body_flushes = prev->body_flushes;
        conf->body_source = prev->body_source;
        conf->body_lengths = prev->body_lengths;
        conf->body_values = prev->body_values;
    }

    if (conf->body_source.data && conf->body_lengths == NULL) {

        njt_memzero(&sc, sizeof(njt_http_script_compile_t));

        sc.cf = cf;
        sc.source = &conf->body_source;
        sc.flushes = &conf->body_flushes;
        sc.lengths = &conf->body_lengths;
        sc.values = &conf->body_values;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (njt_http_script_compile(&sc) != NJT_OK) {
            return NJT_CONF_ERROR;
        }
    }

    njt_conf_merge_ptr_value(conf->headers_source, prev->headers_source, NULL);

    if (conf->headers_source == prev->headers_source
 #if (NJT_HTTP_V3 || NJT_HTTP_V2)
         /* H3 uses own set of headers, so do not inherit on version change */
        && !((conf->http_version >= NJT_HTTP_VERSION_20
              || prev->http_version >= NJT_HTTP_VERSION_20)
             && conf->http_version != prev->http_version)
 #endif
    ) 
    {       
        conf->headers = prev->headers;
#if (NJT_HTTP_CACHE)
        conf->headers_cache = prev->headers_cache;
#endif
#if (NJT_HTTP_V3 || NJT_HTTP_V2)
        conf->host_set = prev->host_set;
#endif
    }
    proxy_headers = njt_http_proxy_headers;

#if (NJT_HTTP_V3 || NJT_HTTP_V2)
    if (conf->http_version == NJT_HTTP_VERSION_20 ||
         conf->http_version == NJT_HTTP_VERSION_30) {
        proxy_headers = njt_http_v3_proxy_headers;
    }
#endif
    rc = njt_http_proxy_init_headers(cf, conf, &conf->headers,
                                     proxy_headers);
    if (rc != NJT_OK) {
        return NJT_CONF_ERROR;
    }

#if (NJT_HTTP_CACHE)

    if (conf->upstream.cache) {

        proxy_headers = njt_http_proxy_cache_headers;

#if (NJT_HTTP_V3 || NJT_HTTP_V2)
        if (conf->http_version == NJT_HTTP_VERSION_20 ||
            conf->http_version == NJT_HTTP_VERSION_30) {
            proxy_headers = njt_http_v3_proxy_cache_headers;
        }
#endif
        rc = njt_http_proxy_init_headers(cf, conf, &conf->headers_cache,
                                         proxy_headers);
        if (rc != NJT_OK) {
            return NJT_CONF_ERROR;
        }
    }

#endif

    /*
     * special handling to preserve conf->headers in the "http" section
     * to inherit it to all servers
     */

    if (prev->headers.hash.buckets == NULL
        && conf->headers_source == prev->headers_source)
    {
        prev->headers = conf->headers;
#if (NJT_HTTP_CACHE)
        prev->headers_cache = conf->headers_cache;
#endif
#if (NJT_HTTP_V3 || NJT_HTTP_V2)
        prev->host_set = conf->host_set;
#endif
    }
#if (NJT_HTTP_V2 )
    njt_conf_merge_size_value(conf->upstream.h2_conf.recv_window,
                        prev->upstream.h2_conf.recv_window, 65536);
    njt_conf_merge_uint_value(conf->upstream.h2_conf.concurrent_streams,
                        prev->upstream.h2_conf.concurrent_streams, 128);
    njt_conf_merge_uint_value(conf->upstream.h2_conf.streams_index_mask,
                        prev->upstream.h2_conf.streams_index_mask, 32 - 1);
#endif
    return NJT_CONF_OK;
}


static njt_int_t
njt_http_proxy_init_headers(njt_conf_t *cf, njt_http_proxy_loc_conf_t *conf,
    njt_http_proxy_headers_t *headers, njt_keyval_t *default_headers)
{
    u_char                       *p;
    size_t                        size;
    uintptr_t                    *code;
    njt_uint_t                    i;
    njt_array_t                   headers_names, headers_merged;
    njt_keyval_t                 *src, *s, *h;
    njt_hash_key_t               *hk;
    njt_hash_init_t               hash;
    njt_http_script_compile_t     sc;
    njt_http_script_copy_code_t  *copy;

    if (headers->hash.buckets) {
        return NJT_OK;
    }

    if (njt_array_init(&headers_names, cf->temp_pool, 4, sizeof(njt_hash_key_t))
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    if (njt_array_init(&headers_merged, cf->temp_pool, 4, sizeof(njt_keyval_t))
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    headers->lengths = njt_array_create(cf->pool, 64, 1);
    if (headers->lengths == NULL) {
        return NJT_ERROR;
    }

    headers->values = njt_array_create(cf->pool, 512, 1);
    if (headers->values == NULL) {
        return NJT_ERROR;
    }

    if (conf->headers_source) {

        src = conf->headers_source->elts;
        for (i = 0; i < conf->headers_source->nelts; i++) {

#if (NJT_HTTP_V3 || NJT_HTTP_V2)
            if (src[i].key.len == 4
                && njt_strncasecmp(src[i].key.data, (u_char *) "Host", 4) == 0)
            {
                conf->host_set = 1;
            }
#endif
            s = njt_array_push(&headers_merged);
            if (s == NULL) {
                return NJT_ERROR;
            }

            *s = src[i];
        }
    }

    h = default_headers;

    while (h->key.len) {

        src = headers_merged.elts;
        for (i = 0; i < headers_merged.nelts; i++) {
            if (njt_strcasecmp(h->key.data, src[i].key.data) == 0) {
                goto next;
            }
        }

        s = njt_array_push(&headers_merged);
        if (s == NULL) {
            return NJT_ERROR;
        }

        *s = *h;

    next:

        h++;
    }


    src = headers_merged.elts;
    for (i = 0; i < headers_merged.nelts; i++) {

        hk = njt_array_push(&headers_names);
        if (hk == NULL) {
            return NJT_ERROR;
        }

        hk->key = src[i].key;
        hk->key_hash = njt_hash_key_lc(src[i].key.data, src[i].key.len);
        hk->value = (void *) 1;

        if (src[i].value.len == 0) {
            continue;
        }

        copy = njt_array_push_n(headers->lengths,
                                sizeof(njt_http_script_copy_code_t));
        if (copy == NULL) {
            return NJT_ERROR;
        }

        copy->code = (njt_http_script_code_pt) (void *)
                                                 njt_http_script_copy_len_code;
        copy->len = src[i].key.len;

        size = (sizeof(njt_http_script_copy_code_t)
                + src[i].key.len + sizeof(uintptr_t) - 1)
               & ~(sizeof(uintptr_t) - 1);

        copy = njt_array_push_n(headers->values, size);
        if (copy == NULL) {
            return NJT_ERROR;
        }

        copy->code = njt_http_script_copy_code;
        copy->len = src[i].key.len;

        p = (u_char *) copy + sizeof(njt_http_script_copy_code_t);
        njt_memcpy(p, src[i].key.data, src[i].key.len);

        njt_memzero(&sc, sizeof(njt_http_script_compile_t));

        sc.cf = cf;
        sc.source = &src[i].value;
        sc.flushes = &headers->flushes;
        sc.lengths = &headers->lengths;
        sc.values = &headers->values;

        if (njt_http_script_compile(&sc) != NJT_OK) {
            return NJT_ERROR;
        }

        code = njt_array_push_n(headers->lengths, sizeof(uintptr_t));
        if (code == NULL) {
            return NJT_ERROR;
        }

        *code = (uintptr_t) NULL;

        code = njt_array_push_n(headers->values, sizeof(uintptr_t));
        if (code == NULL) {
            return NJT_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    code = njt_array_push_n(headers->lengths, sizeof(uintptr_t));
    if (code == NULL) {
        return NJT_ERROR;
    }

    *code = (uintptr_t) NULL;


    hash.hash = &headers->hash;
    hash.key = njt_hash_key_lc;
    hash.max_size = conf->headers_hash_max_size;
    hash.bucket_size = conf->headers_hash_bucket_size;
    hash.name = "proxy_headers_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    return njt_hash_init(&hash, headers_names.elts, headers_names.nelts);
}


static char *
njt_http_proxy_pass(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_proxy_loc_conf_t *plcf = conf;

    size_t                      add;
    u_short                     port;
    njt_str_t                  *value, *url;
    njt_url_t                   u;
    njt_uint_t                  n;
    njt_http_core_loc_conf_t   *clcf;
    njt_http_script_compile_t   sc;

    if (plcf->upstream.upstream || plcf->proxy_lengths) {
        return "is duplicate";
    }

    clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);

    clcf->handler = njt_http_proxy_handler;

    if (clcf->name.len && clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    value = cf->args->elts;
    url = &value[1];

    n = njt_http_script_variables_count(url);
    if (n) {

        njt_memzero(&sc, sizeof(njt_http_script_compile_t));

        sc.cf = cf;
        sc.source = url;
        sc.lengths = &plcf->proxy_lengths;
        sc.values = &plcf->proxy_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (njt_http_script_compile(&sc) != NJT_OK) {
            return NJT_CONF_ERROR;
        }

#if (NJT_HTTP_SSL)
        plcf->ssl = 1;
#endif
#if(NJT_HTTP_DYN_PROXY_PASS)
   plcf->ori_url = *url;
#endif
        return NJT_CONF_OK;
    }

    if (njt_strncasecmp(url->data, (u_char *) "http://", 7) == 0) {
        add = 7;
        port = 80;

    } else if (njt_strncasecmp(url->data, (u_char *) "https://", 8) == 0) {

#if (NJT_HTTP_SSL)
        plcf->ssl = 1;

        add = 8;
        port = 443;
#else
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "https protocol requires SSL support");
        return NJT_CONF_ERROR;
#endif

    } else {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "invalid URL prefix");
        return NJT_CONF_ERROR;
    }

    njt_memzero(&u, sizeof(njt_url_t));

    u.url.len = url->len - add;
    u.url.data = url->data + add;
    u.default_port = port;
    u.uri_part = 1;
    u.no_resolve = 1;

    plcf->upstream.upstream = njt_http_upstream_add(cf, &u, 0);
    if (plcf->upstream.upstream == NULL) {
        return NJT_CONF_ERROR;
    }
#if(NJT_HTTP_ADD_DYNAMIC_UPSTREAM)
    if(plcf->upstream.upstream->type != NULL) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "upstream type:[%V] error!",plcf->upstream.upstream->type);
         return NJT_CONF_ERROR;
    }
#endif
    plcf->vars.schema.len = add;
    plcf->vars.schema.data = url->data;
    plcf->vars.key_start = plcf->vars.schema;

#if (NJT_HTTP_V3 || NJT_HTTP_V2)
    if (u.family != AF_UNIX) {

        if (u.no_port) {
            plcf->host = u.host;

        } else {
            plcf->host.len = u.host.len + 1 + u.port_text.len;
            plcf->host.data = u.host.data;
        }

    } else {
        njt_str_set(&plcf->host, "localhost");
    }
#endif

    njt_http_proxy_set_vars(&u, &plcf->vars);

    plcf->location = clcf->name;
    
    if (clcf->named
#if (NJT_PCRE)
        || clcf->regex
#endif
        || clcf->noname)
    {
        if (plcf->vars.uri.len) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "\"proxy_pass\" cannot have URI part in "
                               "location given by regular expression, "
                               "or inside named location, "
                               "or inside \"if\" statement, "
                               "or inside \"limit_except\" block");
            return NJT_CONF_ERROR;
        }

        plcf->location.len = 0;
    }

    plcf->url = *url;
#if(NJT_HTTP_DYN_PROXY_PASS)
   plcf->ori_url = *url;
#endif

    return NJT_CONF_OK;
}


static char *
njt_http_proxy_redirect(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_proxy_loc_conf_t *plcf = conf;

    u_char                            *p;
    njt_str_t                         *value;
    njt_http_proxy_rewrite_t          *pr;
    njt_http_compile_complex_value_t   ccv;

    if (plcf->redirect == 0) {
        return "is duplicate";
    }

    plcf->redirect = 1;

    value = cf->args->elts;

    if (cf->args->nelts == 2) {
        if (njt_strcmp(value[1].data, "off") == 0) {

            if (plcf->redirects) {
                return "is duplicate";
            }

            plcf->redirect = 0;
            return NJT_CONF_OK;
        }

        if (njt_strcmp(value[1].data, "default") != 0) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[1]);
            return NJT_CONF_ERROR;
        }
    }

    if (plcf->redirects == NULL) {
        plcf->redirects = njt_array_create(cf->pool, 1,
                                           sizeof(njt_http_proxy_rewrite_t));
        if (plcf->redirects == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    pr = njt_array_push(plcf->redirects);
    if (pr == NULL) {
        return NJT_CONF_ERROR;
    }

    if (cf->args->nelts == 2
        && njt_strcmp(value[1].data, "default") == 0)
    {
        if (plcf->proxy_lengths) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "\"proxy_redirect default\" cannot be used "
                               "with \"proxy_pass\" directive with variables");
            return NJT_CONF_ERROR;
        }

        if (plcf->url.data == NULL) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "\"proxy_redirect default\" should be placed "
                               "after the \"proxy_pass\" directive");
            return NJT_CONF_ERROR;
        }

        pr->handler = njt_http_proxy_rewrite_complex_handler;

        njt_memzero(&pr->pattern.complex, sizeof(njt_http_complex_value_t));

        njt_memzero(&pr->replacement, sizeof(njt_http_complex_value_t));

        if (plcf->vars.uri.len) {
            pr->pattern.complex.value = plcf->url;
            pr->replacement.value = plcf->location;

        } else {
            pr->pattern.complex.value.len = plcf->url.len + sizeof("/") - 1;

            p = njt_pnalloc(cf->pool, pr->pattern.complex.value.len);
            if (p == NULL) {
                return NJT_CONF_ERROR;
            }

            pr->pattern.complex.value.data = p;

            p = njt_cpymem(p, plcf->url.data, plcf->url.len);
            *p = '/';

            njt_str_set(&pr->replacement.value, "/");
        }

        return NJT_CONF_OK;
    }


    if (value[1].data[0] == '~') {
        value[1].len--;
        value[1].data++;

        if (value[1].data[0] == '*') {
            value[1].len--;
            value[1].data++;

            if (njt_http_proxy_rewrite_regex(cf, pr, &value[1], 1) != NJT_OK) {
                return NJT_CONF_ERROR;
            }

        } else {
            if (njt_http_proxy_rewrite_regex(cf, pr, &value[1], 0) != NJT_OK) {
                return NJT_CONF_ERROR;
            }
        }

    } else {

        njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[1];
        ccv.complex_value = &pr->pattern.complex;

        if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
            return NJT_CONF_ERROR;
        }

        pr->handler = njt_http_proxy_rewrite_complex_handler;
    }


    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &pr->replacement;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static char *
njt_http_proxy_cookie_domain(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_proxy_loc_conf_t *plcf = conf;

    njt_str_t                         *value;
    njt_http_proxy_rewrite_t          *pr;
    njt_http_compile_complex_value_t   ccv;

    if (plcf->cookie_domains == NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2) {

        if (njt_strcmp(value[1].data, "off") == 0) {

            if (plcf->cookie_domains != NJT_CONF_UNSET_PTR) {
                return "is duplicate";
            }

            plcf->cookie_domains = NULL;
            return NJT_CONF_OK;
        }

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[1]);
        return NJT_CONF_ERROR;
    }

    if (plcf->cookie_domains == NJT_CONF_UNSET_PTR) {
        plcf->cookie_domains = njt_array_create(cf->pool, 1,
                                     sizeof(njt_http_proxy_rewrite_t));
        if (plcf->cookie_domains == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    pr = njt_array_push(plcf->cookie_domains);
    if (pr == NULL) {
        return NJT_CONF_ERROR;
    }

    if (value[1].data[0] == '~') {
        value[1].len--;
        value[1].data++;

        if (njt_http_proxy_rewrite_regex(cf, pr, &value[1], 1) != NJT_OK) {
            return NJT_CONF_ERROR;
        }

    } else {

        if (value[1].data[0] == '.') {
            value[1].len--;
            value[1].data++;
        }

        njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[1];
        ccv.complex_value = &pr->pattern.complex;

        if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
            return NJT_CONF_ERROR;
        }

        pr->handler = njt_http_proxy_rewrite_domain_handler;

        if (value[2].data[0] == '.') {
            value[2].len--;
            value[2].data++;
        }
    }

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &pr->replacement;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static char *
njt_http_proxy_cookie_path(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_proxy_loc_conf_t *plcf = conf;

    njt_str_t                         *value;
    njt_http_proxy_rewrite_t          *pr;
    njt_http_compile_complex_value_t   ccv;

    if (plcf->cookie_paths == NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2) {

        if (njt_strcmp(value[1].data, "off") == 0) {

            if (plcf->cookie_paths != NJT_CONF_UNSET_PTR) {
                return "is duplicate";
            }

            plcf->cookie_paths = NULL;
            return NJT_CONF_OK;
        }

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[1]);
        return NJT_CONF_ERROR;
    }

    if (plcf->cookie_paths == NJT_CONF_UNSET_PTR) {
        plcf->cookie_paths = njt_array_create(cf->pool, 1,
                                     sizeof(njt_http_proxy_rewrite_t));
        if (plcf->cookie_paths == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    pr = njt_array_push(plcf->cookie_paths);
    if (pr == NULL) {
        return NJT_CONF_ERROR;
    }

    if (value[1].data[0] == '~') {
        value[1].len--;
        value[1].data++;

        if (value[1].data[0] == '*') {
            value[1].len--;
            value[1].data++;

            if (njt_http_proxy_rewrite_regex(cf, pr, &value[1], 1) != NJT_OK) {
                return NJT_CONF_ERROR;
            }

        } else {
            if (njt_http_proxy_rewrite_regex(cf, pr, &value[1], 0) != NJT_OK) {
                return NJT_CONF_ERROR;
            }
        }

    } else {

        njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[1];
        ccv.complex_value = &pr->pattern.complex;

        if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
            return NJT_CONF_ERROR;
        }

        pr->handler = njt_http_proxy_rewrite_complex_handler;
    }

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &pr->replacement;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static char *
njt_http_proxy_cookie_flags(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_proxy_loc_conf_t *plcf = conf;

    njt_str_t                         *value;
    njt_uint_t                         i;
    njt_http_complex_value_t          *cv;
    njt_http_proxy_cookie_flags_t     *pcf;
    njt_http_compile_complex_value_t   ccv;
#if (NJT_PCRE)
    njt_regex_compile_t                rc;
    u_char                             errstr[NJT_MAX_CONF_ERRSTR];
#endif

    if (plcf->cookie_flags == NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2) {

        if (njt_strcmp(value[1].data, "off") == 0) {

            if (plcf->cookie_flags != NJT_CONF_UNSET_PTR) {
                return "is duplicate";
            }

            plcf->cookie_flags = NULL;
            return NJT_CONF_OK;
        }

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[1]);
        return NJT_CONF_ERROR;
    }

    if (plcf->cookie_flags == NJT_CONF_UNSET_PTR) {
        plcf->cookie_flags = njt_array_create(cf->pool, 1,
                                        sizeof(njt_http_proxy_cookie_flags_t));
        if (plcf->cookie_flags == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    pcf = njt_array_push(plcf->cookie_flags);
    if (pcf == NULL) {
        return NJT_CONF_ERROR;
    }

    pcf->regex = 0;

    if (value[1].data[0] == '~') {
        value[1].len--;
        value[1].data++;

#if (NJT_PCRE)
        njt_memzero(&rc, sizeof(njt_regex_compile_t));

        rc.pattern = value[1];
        rc.err.len = NJT_MAX_CONF_ERRSTR;
        rc.err.data = errstr;
        rc.options = NJT_REGEX_CASELESS;

        pcf->cookie.regex = njt_http_regex_compile(cf, &rc);
        if (pcf->cookie.regex == NULL) {
            return NJT_CONF_ERROR;
        }

        pcf->regex = 1;
#else
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "using regex \"%V\" requires PCRE library",
                           &value[1]);
        return NJT_CONF_ERROR;
#endif

    } else {

        njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[1];
        ccv.complex_value = &pcf->cookie.complex;

        if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
            return NJT_CONF_ERROR;
        }
    }

    if (njt_array_init(&pcf->flags_values, cf->pool, cf->args->nelts - 2,
                       sizeof(njt_http_complex_value_t))
        != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    for (i = 2; i < cf->args->nelts; i++) {

        cv = njt_array_push(&pcf->flags_values);
        if (cv == NULL) {
            return NJT_CONF_ERROR;
        }

        njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[i];
        ccv.complex_value = cv;

        if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
            return NJT_CONF_ERROR;
        }
    }

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_proxy_rewrite_regex(njt_conf_t *cf, njt_http_proxy_rewrite_t *pr,
    njt_str_t *regex, njt_uint_t caseless)
{
#if (NJT_PCRE)
    u_char               errstr[NJT_MAX_CONF_ERRSTR];
    njt_regex_compile_t  rc;

    njt_memzero(&rc, sizeof(njt_regex_compile_t));

    rc.pattern = *regex;
    rc.err.len = NJT_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    if (caseless) {
        rc.options = NJT_REGEX_CASELESS;
    }

    pr->pattern.regex = njt_http_regex_compile(cf, &rc);
    if (pr->pattern.regex == NULL) {
        return NJT_ERROR;
    }

    pr->handler = njt_http_proxy_rewrite_regex_handler;

    return NJT_OK;

#else

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "using regex \"%V\" requires PCRE library", regex);
    return NJT_ERROR;

#endif
}


static char *
njt_http_proxy_store(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_proxy_loc_conf_t *plcf = conf;

    njt_str_t                  *value;
    njt_http_script_compile_t   sc;

    if (plcf->upstream.store != NJT_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (njt_strcmp(value[1].data, "off") == 0) {
        plcf->upstream.store = 0;
        return NJT_CONF_OK;
    }

    if (value[1].len == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "empty path");
        return NJT_CONF_ERROR;
    }

#if (NJT_HTTP_CACHE)
    if (plcf->upstream.cache > 0) {
        return "is incompatible with \"proxy_cache\"";
    }
#endif

    plcf->upstream.store = 1;

    if (njt_strcmp(value[1].data, "on") == 0) {
        return NJT_CONF_OK;
    }

    /* include the terminating '\0' into script */
    value[1].len++;

    njt_memzero(&sc, sizeof(njt_http_script_compile_t));

    sc.cf = cf;
    sc.source = &value[1];
    sc.lengths = &plcf->upstream.store_lengths;
    sc.values = &plcf->upstream.store_values;
    sc.variables = njt_http_script_variables_count(&value[1]);
    sc.complete_lengths = 1;
    sc.complete_values = 1;

    if (njt_http_script_compile(&sc) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


#if (NJT_HTTP_CACHE)

static char *
njt_http_proxy_cache(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_proxy_loc_conf_t *plcf = conf;

    njt_str_t                         *value;
    njt_http_complex_value_t           cv;
    njt_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (plcf->upstream.cache != NJT_CONF_UNSET) {
        return "is duplicate";
    }

    if (njt_strcmp(value[1].data, "off") == 0) {
        plcf->upstream.cache = 0;
        return NJT_CONF_OK;
    }

    if (plcf->upstream.store > 0) {
        return "is incompatible with \"proxy_store\"";
    }

    plcf->upstream.cache = 1;

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    if (cv.lengths != NULL) {

        plcf->upstream.cache_value = njt_palloc(cf->pool,
                                             sizeof(njt_http_complex_value_t));
        if (plcf->upstream.cache_value == NULL) {
            return NJT_CONF_ERROR;
        }

        *plcf->upstream.cache_value = cv;

        return NJT_CONF_OK;
    }

    plcf->upstream.cache_zone = njt_shared_memory_add(cf, &value[1], 0,
                                                      &njt_http_proxy_module);
    if (plcf->upstream.cache_zone == NULL) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static char *
njt_http_proxy_cache_key(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_proxy_loc_conf_t *plcf = conf;
    njt_str_t                  key,old_key,*value;
    njt_http_compile_complex_value_t   ccv,file_cvv;
    u_char                     *file_key=NULL,*index,*start;

    value = cf->args->elts;

    if (plcf->cache_key.value.data) {
        return "is duplicate";
    }

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));
    njt_memzero(&file_cvv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &plcf->cache_key;

    file_cvv = ccv;
    file_cvv.complex_value = &plcf->cache_file_key;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }
    old_key =value[1];
    index = njt_strnstr(old_key.data, "$slice_range", old_key.len);
    if ( old_key.data != NULL &&  old_key.len > 0 ) {
        file_key = njt_pcalloc(cf->pool,old_key.len);
        if(file_key == NULL){
            return NJT_CONF_ERROR;
        }
    }
    start = old_key.data;
    key.len = 0;
    while (index != NULL && file_key != NULL){
        njt_memcpy(file_key + key.len,start,index-start);
        key.len += index-start;
        start = index + njt_strlen("$slice_range");
        index = njt_strnstr(start, "$slice_range", old_key.len - (start - plcf->cache_key.value.data));
    }
    if(old_key.len - (start - plcf->cache_key.value.data) > 0 ){
        njt_memcpy(file_key+key.len,start,old_key.len - (start - plcf->cache_key.value.data) );
        key.len += old_key.len - (start - plcf->cache_key.value.data);
    }
    key.data = file_key;
    file_cvv.value = &key;
    if (njt_http_compile_complex_value(&file_cvv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}

#endif


#if (NJT_HTTP_SSL)

static char *
njt_http_proxy_ssl_certificate_cache(njt_conf_t *cf, njt_command_t *cmd,
    void *conf)
{
    njt_http_proxy_loc_conf_t *plcf = conf;

    time_t       inactive, valid;
    njt_str_t   *value, s;
    njt_int_t    max;
    njt_uint_t   i;

    if (plcf->upstream.ssl_certificate_cache != NJT_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    max = 0;
    inactive = 10;
    valid = 60;

    for (i = 1; i < cf->args->nelts; i++) {

        if (njt_strncmp(value[i].data, "max=", 4) == 0) {

            max = njt_atoi(value[i].data + 4, value[i].len - 4);
            if (max <= 0) {
                goto failed;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "inactive=", 9) == 0) {

            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            inactive = njt_parse_time(&s, 1);
            if (inactive == (time_t) NJT_ERROR) {
                goto failed;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "valid=", 6) == 0) {

            s.len = value[i].len - 6;
            s.data = value[i].data + 6;

            valid = njt_parse_time(&s, 1);
            if (valid == (time_t) NJT_ERROR) {
                goto failed;
            }

            continue;
       }

        if (njt_strcmp(value[i].data, "off") == 0) {

            plcf->upstream.ssl_certificate_cache = NULL;

            continue;
        }

    failed:

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NJT_CONF_ERROR;
    }

    if (plcf->upstream.ssl_certificate_cache == NULL) {
        return NJT_CONF_OK;
    }

    if (max == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "\"proxy_ssl_certificate_cache\" must have "
                           "the \"max\" parameter");
        return NJT_CONF_ERROR;
    }

    plcf->upstream.ssl_certificate_cache = njt_ssl_cache_init(cf->pool, max,
                                                              valid, inactive);
    if (plcf->upstream.ssl_certificate_cache == NULL) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static char *
njt_http_proxy_ssl_password_file(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_proxy_loc_conf_t *plcf = conf;

    njt_str_t  *value;

    if (plcf->upstream.ssl_passwords != NJT_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    plcf->upstream.ssl_passwords = njt_ssl_read_password_file(cf, &value[1]);

    if (plcf->upstream.ssl_passwords == NULL) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}

#endif


static char *
njt_http_proxy_lowat_check(njt_conf_t *cf, void *post, void *data)
{
#if (NJT_FREEBSD)
    ssize_t *np = data;

    if ((u_long) *np >= njt_freebsd_net_inet_tcp_sendspace) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "\"proxy_send_lowat\" must be less than %d "
                           "(sysctl net.inet.tcp.sendspace)",
                           njt_freebsd_net_inet_tcp_sendspace);

        return NJT_CONF_ERROR;
    }

#elif !(NJT_HAVE_SO_SNDLOWAT)
    ssize_t *np = data;

    njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                       "\"proxy_send_lowat\" is not supported, ignored");

    *np = 0;

#endif

    return NJT_CONF_OK;
}


#if (NJT_HTTP_SSL)

static char *
njt_http_proxy_ssl_conf_command_check(njt_conf_t *cf, void *post, void *data)
{
#ifndef SSL_CONF_FLAG_FILE
    return "is not supported on this platform";
#else
    return NJT_CONF_OK;
#endif
}


static njt_int_t
njt_http_proxy_merge_ssl(njt_conf_t *cf, njt_http_proxy_loc_conf_t *conf,
    njt_http_proxy_loc_conf_t *prev)
{
    njt_uint_t  preserve;

    if (conf->ssl_protocols == 0
        && conf->ssl_ciphers.data == NULL
#if (NJT_HTTP_MULTICERT)
        && conf->upstream.ssl_certificates == NJT_CONF_UNSET_PTR
        && conf->upstream.ssl_certificate_keys == NJT_CONF_UNSET_PTR
#else
        && conf->upstream.ssl_certificate == NJT_CONF_UNSET_PTR
        && conf->upstream.ssl_certificate_key == NJT_CONF_UNSET_PTR
#endif
        && conf->upstream.ssl_passwords == NJT_CONF_UNSET_PTR
        && conf->upstream.ssl_verify == NJT_CONF_UNSET
        && conf->ssl_verify_depth == NJT_CONF_UNSET_UINT
        && conf->ssl_trusted_certificate.data == NULL
        && conf->ssl_crl.data == NULL
        && conf->upstream.ssl_session_reuse == NJT_CONF_UNSET
#if (NJT_HAVE_NTLS)
        && conf->upstream.ssl_ntls == NJT_CONF_UNSET
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
        /* add by hlyan for tls1.3 sm2ecdh */
        && conf->upstream.tls13_sm_ecdh == NJT_CONF_UNSET
#endif
#endif
        && conf->ssl_conf_commands == NJT_CONF_UNSET_PTR)
    {
        if (prev->upstream.ssl) {
            conf->upstream.ssl = prev->upstream.ssl;
            conf->preserve = prev->preserve;
            return NJT_OK;
        }

        preserve = 1;
	conf->preserve = preserve;

    } else {
        preserve = 0;
    }

    conf->upstream.ssl = njt_pcalloc(cf->pool, sizeof(njt_ssl_t));
    if (conf->upstream.ssl == NULL) {
        return NJT_ERROR;
    }

    conf->upstream.ssl->log = cf->log;

    /*
     * special handling to preserve conf->upstream.ssl
     * in the "http" section to inherit it to all servers
     */

    if (preserve) {
        prev->upstream.ssl = conf->upstream.ssl;
	prev->preserve = conf->preserve;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_proxy_set_ssl(njt_conf_t *cf, njt_http_proxy_loc_conf_t *plcf)
{
    njt_pool_cleanup_t       *cln;
 
    if (plcf->upstream.ssl->ctx) {
        return NJT_OK;
    }

    if (njt_ssl_create(plcf->upstream.ssl, plcf->ssl_protocols, NULL)
        != NJT_OK)
    {
        return NJT_ERROR;
    }
#if (NJT_HTTP_V3 && NJT_QUIC_OPENSSL_COMPAT)
    if (njt_quic_compat_init(cf, plcf->upstream.ssl->ctx) != NJT_OK) {
        return NJT_ERROR;
    }
#endif
#if(NJT_HTTP_DYNAMIC_UPSTREAM)
    if(plcf->preserve == 1) {
	    cln = njt_pool_cleanup_add(cf->cycle->pool, 0);
    } else {
	    cln = njt_pool_cleanup_add(cf->pool, 0);
    }
#else
    cln = njt_pool_cleanup_add(cf->pool, 0);
#endif
    if (cln == NULL) {
        njt_ssl_cleanup_ctx(plcf->upstream.ssl);
        return NJT_ERROR;
    }

    cln->handler = njt_ssl_cleanup_ctx;
    cln->data = plcf->upstream.ssl;

    if (njt_ssl_ciphers(cf, plcf->upstream.ssl, &plcf->ssl_ciphers, 0)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

#if (NJT_HTTP_MULTICERT)
    if (plcf->upstream.ssl_certificates) {
        njt_str_t                cert;
        njt_http_ssl_srv_conf_t  scf;

        cert = *((njt_str_t *) plcf->upstream.ssl_certificates->elts);
#if (NJT_HAVE_NTLS)
        njt_ssl_ntls_prefix_strip(&cert);
#endif

        if (plcf->upstream.ssl_certificates->nelts == 1 && cert.len == 0) {
            /* single empty certificate: cancel certificate loading */
            goto skip;
        }

        if (plcf->upstream.ssl_certificate_keys == NULL) {
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "no \"proxy_ssl_certificate_key\" is defined "
                          "for proxy_ssl_certificate \"%V\"", &cert);
            return NJT_ERROR;
        }

        if (plcf->upstream.ssl_certificate_keys->nelts
            < plcf->upstream.ssl_certificates->nelts)
        {
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "number of \"proxy_ssl_certificate_key\" does not "
                          "correspond \"proxy_ssl_ssl_certificate\"");
            return NJT_ERROR;
        }

        njt_memzero(&scf, sizeof(njt_http_ssl_srv_conf_t));

        scf.certificates = plcf->upstream.ssl_certificates;
        scf.certificate_keys = plcf->upstream.ssl_certificate_keys;
        scf.passwords = plcf->upstream.ssl_passwords;

        if (njt_http_ssl_compile_certificates(cf, &scf) != NJT_OK) {
            return NJT_ERROR;
        }

        plcf->upstream.ssl_passwords = scf.passwords;
        plcf->upstream.ssl_certificate_values = scf.certificate_values;
        plcf->upstream.ssl_certificate_key_values = scf.certificate_key_values;

        if (plcf->upstream.ssl_certificate_values == NULL) {
            if (njt_ssl_certificates(cf, plcf->upstream.ssl,
                                     plcf->upstream.ssl_certificates,
                                     plcf->upstream.ssl_certificate_keys,
                                     plcf->upstream.ssl_passwords)
                != NJT_OK)
            {
                return NJT_ERROR;
            }
        }
    }

skip:

#else

    if (plcf->upstream.ssl_certificate
        && plcf->upstream.ssl_certificate->value.len)
    {
        if (plcf->upstream.ssl_certificate_key == NULL) {
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "no \"proxy_ssl_certificate_key\" is defined "
                          "for certificate \"%V\"",
                          &plcf->upstream.ssl_certificate->value);
            return NJT_ERROR;
        }

        if (plcf->upstream.ssl_certificate->lengths
            || plcf->upstream.ssl_certificate_key->lengths)
        {
            plcf->upstream.ssl_passwords =
                  njt_ssl_preserve_passwords(cf, plcf->upstream.ssl_passwords);
            if (plcf->upstream.ssl_passwords == NULL) {
                return NJT_ERROR;
            }

        } else {
            if (njt_ssl_certificate(cf, plcf->upstream.ssl,
                                    &plcf->upstream.ssl_certificate->value,
                                    &plcf->upstream.ssl_certificate_key->value,
                                    plcf->upstream.ssl_passwords)
                != NJT_OK)
            {
                return NJT_ERROR;
            }
        }
    }

#endif

    if (plcf->upstream.ssl_verify) {
        if (plcf->ssl_trusted_certificate.len == 0) {
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                      "no proxy_ssl_trusted_certificate for proxy_ssl_verify");
            return NJT_ERROR;
        }

        if (njt_ssl_trusted_certificate(cf, plcf->upstream.ssl,
                                        &plcf->ssl_trusted_certificate,
                                        plcf->ssl_verify_depth)
            != NJT_OK)
        {
            return NJT_ERROR;
        }

        if (njt_ssl_crl(cf, plcf->upstream.ssl, &plcf->ssl_crl) != NJT_OK) {
            return NJT_ERROR;
        }
    }


#if (NJT_HAVE_NTLS && OPENSSL_VERSION_NUMBER < 0x30000000L)
    /* add by hlyan for tls1.3 sm2ecdh */
    if (plcf->upstream.ssl_ntls != 0 && (plcf->http_version & NJT_HTTP_VERSION_30)) {
        SSL_CTX_enable_tls13_sm_ecdh(plcf->upstream.ssl->ctx);
    }
#endif

    if (njt_ssl_client_session_cache(cf, plcf->upstream.ssl,
                                     plcf->upstream.ssl_session_reuse)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    if (njt_ssl_conf_commands(cf, plcf->upstream.ssl, plcf->ssl_conf_commands)
        != NJT_OK)
    {
        return NJT_ERROR;
    }
#if (NJT_HAVE_SET_ALPN)
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
    if(plcf->proxy_ssl_alpn.len >  0) {
   
     if (SSL_CTX_set_alpn_protos(plcf->upstream.ssl->ctx,
                                (u_char *)plcf->proxy_ssl_alpn.data,plcf->proxy_ssl_alpn.len)
        != 0)
    {
        njt_ssl_error(NJT_LOG_EMERG, cf->log, 0,
                      "SSL_CTX_set_alpn_protos() failed");
        return NJT_ERROR;
    }
    }
#endif
#endif
    return NJT_OK;
}

#endif


 void
njt_http_proxy_set_vars(njt_url_t *u, njt_http_proxy_vars_t *v)
{
    if (u->family != AF_UNIX) {

        if (u->no_port || u->port == u->default_port) {

            v->host_header = u->host;

            if (u->default_port == 80) {
                njt_str_set(&v->port, "80");

            } else {
                njt_str_set(&v->port, "443");
            }

        } else {
            v->host_header.len = u->host.len + 1 + u->port_text.len;
            v->host_header.data = u->host.data;
            v->port = u->port_text;
        }

        v->key_start.len += v->host_header.len;

    } else {
        njt_str_set(&v->host_header, "localhost");
        njt_str_null(&v->port);
        v->key_start.len += sizeof("unix:") - 1 + u->host.len + 1;
    }

    v->uri = u->uri;
}

#if (NJT_HAVE_SET_ALPN)
static char *
njt_http_proxy_ssl_alpn(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation

    njt_http_proxy_loc_conf_t  *scf = conf;

    u_char      *p;
    size_t       len;
    njt_str_t   *value;
    njt_uint_t   i;

    if (scf->proxy_ssl_alpn.len) {
        return "is duplicate";
    }

    value = cf->args->elts;

    len = 0;

    for (i = 1; i < cf->args->nelts; i++) {

        if (value[i].len > 255) {
            return "protocol too long";
        }

        len += value[i].len + 1;
    }

    scf->proxy_ssl_alpn.data = njt_pnalloc(cf->pool, len);
    if (scf->proxy_ssl_alpn.data == NULL) {
        return NJT_CONF_ERROR;
    }

    p = scf->proxy_ssl_alpn.data;

    for (i = 1; i < cf->args->nelts; i++) {
        *p++ = value[i].len;
        p = njt_cpymem(p, value[i].data, value[i].len);
    }

    scf->proxy_ssl_alpn.len = len;

    return NJT_CONF_OK;

#else
    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "the \"proxy_ssl_alpn\" directive requires OpenSSL "
                       "with ALPN support");
    return NJT_CONF_ERROR;
#endif
}
#endif

#if (NJT_HTTP_V2)

static njt_int_t
njt_http_v2_proxy_create_request(njt_http_request_t *r)
{
    njt_buf_t                  *b;
    njt_chain_t                *cl ,*out, *body;
    njt_http_upstream_t        *u;
    njt_http_proxy_ctx_t       *ctx;
    njt_http_v2_proxy_ctx_t     v2c;  
    njt_http_proxy_headers_t   *headers;
    njt_http_proxy_loc_conf_t  *plcf;   

    /*
     * HTTP/3 Request:
     *
     * HEADERS FRAME
     *    :method:
     *    :scheme:
     *    :path:
     *    :authority:
     *     proxy headers[]
     *     client headers[]
     *
     * DATA FRAME
     *    body
     *
     * HEADERS FRAME
     *    trailers[]
     */
 
    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http2 proxy create request");
    u = r->upstream;

    plcf = njt_http_get_module_loc_conf(r, njt_http_proxy_module);

#if (NJT_HTTP_CACHE)
    headers = u->cacheable ? &plcf->headers_cache : &plcf->headers;
#else
    headers = &plcf->headers;
#endif   
    njt_memzero(&v2c,sizeof(njt_http_v2_proxy_ctx_t));

    njt_http_script_flush_no_cacheable_variables(r, plcf->body_flushes);
    njt_http_script_flush_no_cacheable_variables(r, headers->flushes);

    v2c.headers = headers;
    /* calculate lengths */

    njt_http_v2_proxy_encode_method(r, &v2c, NULL);

    //schme 
    v2c.n += 1;

    if (njt_http_v2_proxy_encode_path(r, &v2c, NULL) != NJT_OK) {
        return NJT_ERROR;
    }

    if (njt_http_v2_proxy_encode_authority(r, &v2c, NULL) != NJT_OK) {
        return NJT_ERROR;
    }

    if (njt_http_v2_proxy_body_length(r, &v2c) != NJT_OK) {
        return NJT_ERROR;
    }

    if (njt_http_v2_proxy_encode_headers(r, &v2c, NULL) != NJT_OK) {
        return NJT_ERROR;
    }

    /* generate HTTP/2 request of known size */

    b = njt_create_temp_buf(r->pool, v2c.n);
    if (b == NULL) {
        return NJT_ERROR;
    }

    if (v2c.max_tmp_len > 0) {
        v2c.tmp = njt_pnalloc(r->pool,v2c.max_tmp_len);
        if (v2c.tmp == NULL) {
            return NJT_ERROR;
        }
    }    

    if (njt_http_v2_proxy_encode_method(r, &v2c, b) != NJT_OK) {
        return NJT_ERROR;
    }

    *b->last++ = njt_http_v2_indexed(NJT_HTTP_V2_SCHEME_HTTPS_INDEX);
   
    
    if (njt_http_v2_proxy_encode_path(r, &v2c, b) != NJT_OK) {
        return NJT_ERROR;
    }

    if (njt_http_v2_proxy_encode_authority(r, &v2c, b) != NJT_OK) {
        return NJT_ERROR;
    }

    if (njt_http_v2_proxy_encode_headers(r, &v2c, b) != NJT_OK) {
        return NJT_ERROR;
    }
    
    cl = njt_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NJT_ERROR;
    }

    if (r->stream) {
        b->last_buf = r->stream->in_closed || 
            (r->headers_in.content_length_n <= 0 && !r->headers_in.chunked);
    } else {
        b->last_buf = r->headers_in.content_length_n <= 0 && !r->headers_in.chunked;
    }

    cl->buf = b;
    cl->next = NULL;
    out = cl;

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    if (r->request_body_no_buffering || ctx->internal_chunked) {
        //http2 在fake client层封包，不需要特殊处理，缺省即可
        u->output.output_filter = njt_chain_writer;        
        u->output.filter_ctx =  &u->writer;

    } else if (ctx->internal_body_length != -1) {

        body = njt_http_v2_proxy_encode_body(r, &v2c);
        if (body == NJT_CHAIN_ERROR) {
            return NJT_ERROR;
        }

        for (cl = out; cl->next; cl = cl->next) { }
        cl->next = body;
    }

    /* TODO: trailers */
    u->request_bufs = out;

    return NJT_OK;
}

static njt_int_t
njt_http_v2_proxy_encode_method(njt_http_request_t *r,
    njt_http_v2_proxy_ctx_t *v2c, njt_buf_t *b)
{
    size_t                      n;
    njt_str_t                   method;
    njt_uint_t                  v3method;
    njt_http_upstream_t        *u;
    njt_http_proxy_ctx_t       *ctx;
    njt_http_proxy_loc_conf_t  *plcf;

    static njt_str_t njt_http_v2_header_method = njt_string(":method");

    if (b == NULL) {
        /* calculate length */

        plcf = njt_http_get_module_loc_conf(r, njt_http_proxy_module);
        ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

        method.len = 0;
        n = 0;

        u = r->upstream;

        if (u->method.len) {
            /* HEAD was changed to GET to cache response */
            method = u->method;

        } else if (plcf->method) {
            if (njt_http_complex_value(r, plcf->method, &method) != NJT_OK) {
                return NJT_ERROR;
            }
        } else {
            method = r->method_name;
        }

        if (method.len == 4
            && njt_strncasecmp(method.data, (u_char *) "HEAD", 4) == 0)
        {
            ctx->head = 1;
        }

        if (method.len) {
            n = 1 + NJT_HTTP_V2_INT_OCTETS + njt_http_v2_header_method.len 
                  + NJT_HTTP_V2_INT_OCTETS + method.len;
        } else {

            v3method = njt_http_v2_map_method(r->method);

            if (v3method) {
                n = 1;

            } else {
                n = 1 + NJT_HTTP_V2_INT_OCTETS + njt_http_v2_header_method.len
                      + NJT_HTTP_V2_INT_OCTETS + r->method_name.len;
            }
        }
        if (n > v2c->max_tmp_len) {
            v2c->max_tmp_len = n;
        }
        v2c->n += n;
        v2c->method = method;

        return NJT_OK;
    }

    method = v2c->method;

    if (method.len) {
        *b->last++ = 0;
        b->last = njt_http_v2_write_name(b->last,njt_http_v2_header_method.data,
                                            njt_http_v2_header_method.len,v2c->tmp);
        b->last = njt_http_v2_write_value(b->last,method.data,method.len,v2c->tmp);
    } else {

        v3method = njt_http_v2_map_method(r->method);

        if (v3method) {
            *b->last++ = njt_http_v2_indexed(v3method);
        } else {
            *b->last++ = 0;
            b->last = njt_http_v2_write_name(b->last,njt_http_v2_header_method.data,
                                            njt_http_v2_header_method.len,v2c->tmp);
            b->last = njt_http_v2_write_value(b->last,r->method_name.data,r->method_name.len,v2c->tmp);
        }
    }

    return NJT_OK;
}

static njt_inline njt_uint_t
njt_http_v2_map_method(njt_uint_t method)
{
    switch (method) {
    case NJT_HTTP_GET:
        return NJT_HTTP_V2_METHOD_GET_INDEX;   
    case NJT_HTTP_POST:
        return NJT_HTTP_V2_METHOD_POST_INDEX;
    default:
        return 0;
    }
}

static njt_int_t
njt_http_v2_proxy_encode_headers(njt_http_request_t *r,
    njt_http_v2_proxy_ctx_t *v2c, njt_buf_t *b)
{
    u_char                       *p, *start;
    size_t                        key_len, val_len, hlen, max_head, n;
    njt_str_t                     tmp, tmpv;
    njt_uint_t                    i;
    njt_list_part_t              *part;
    njt_table_elt_t              *header;
    njt_http_script_code_pt       code;
    njt_http_proxy_headers_t     *headers;
    njt_http_script_engine_t     *le;
    njt_http_script_engine_t     *e;
    njt_http_proxy_loc_conf_t    *plcf;
    njt_http_script_len_code_pt   lcode;

    plcf = njt_http_get_module_loc_conf(r, njt_http_proxy_module);

    headers = v2c->headers;
    le = &v2c->le;
    e = &v2c->e;

    if (b == NULL) {

        le->ip = headers->lengths->elts;
        le->request = r;
        le->flushed = 1;

        n = 0;
        max_head = 0;

        while (*(uintptr_t *) le->ip) {

            lcode = *(njt_http_script_len_code_pt *) le->ip;
            key_len = lcode(le);

            for (val_len = 0; *(uintptr_t *) le->ip; val_len += lcode(le)) {
                lcode = *(njt_http_script_len_code_pt *) le->ip;
            }
            le->ip += sizeof(uintptr_t);

            if (val_len == 0) {
                continue;
            }

            hlen = key_len + val_len;
            if (hlen > max_head) {
                max_head = hlen;
            }
            if (key_len > v2c->max_tmp_len) {
                v2c->max_tmp_len = key_len;
            }

            if (val_len > v2c->max_tmp_len) {
                v2c->max_tmp_len = val_len;
            }

            n += 1 + NJT_HTTP_V2_INT_OCTETS + key_len
              + NJT_HTTP_V2_INT_OCTETS + val_len;
        }

        if (plcf->upstream.pass_request_headers) {
            part = &r->headers_in.headers.part;
            header = part->elts;

            for (i = 0; /* void */; i++) {

                if (i >= part->nelts) {
                    if (part->next == NULL) {
                        break;
                    }

                    part = part->next;
                    header = part->elts;
                    i = 0;
                }

                if (njt_hash_find(&headers->hash, header[i].hash,
                                  header[i].lowcase_key, header[i].key.len))
                {
                    continue;
                }
                n += 1 + NJT_HTTP_V2_INT_OCTETS + header[i].key.len
                  + NJT_HTTP_V2_INT_OCTETS + header[i].value.len;

                if (header[i].key.len > v2c->max_tmp_len) {
                    v2c->max_tmp_len = header[i].key.len;
                } 
                if (header[i].value.len > v2c->max_tmp_len) {
                    v2c->max_tmp_len = header[i].value.len;
                } 
            }
        }

        v2c->n += n;
        v2c->max_head = max_head;

        return NJT_OK;
    }

    max_head = v2c->max_head;

    p = njt_pnalloc(r->pool, max_head);
    if (p == NULL) {
        return NJT_ERROR;
    }

    start = p;

    njt_memzero(e, sizeof(njt_http_script_engine_t));

    e->ip = headers->values->elts;
    e->pos = p;
    e->request = r;
    e->flushed = 1;

    le->ip = headers->lengths->elts;

    tmp.data = p;
    tmp.len = 0;

    tmpv.data = NULL;
    tmpv.len = 0;

    while (*(uintptr_t *) le->ip) {

        lcode = *(njt_http_script_len_code_pt *) le->ip;
        (void) lcode(le);

        for (val_len = 0; *(uintptr_t *) le->ip; val_len += lcode(le)) {
            lcode = *(njt_http_script_len_code_pt *) le->ip;
        }
        le->ip += sizeof(uintptr_t);

        if (val_len == 0) {
            e->skip = 1;

            while (*(uintptr_t *) e->ip) {
                code = *(njt_http_script_code_pt *) e->ip;
                code((njt_http_script_engine_t *) e);
            }
            e->ip += sizeof(uintptr_t);

            e->skip = 0;

            continue;
        }

        code = *(njt_http_script_code_pt *) e->ip;
        code((njt_http_script_engine_t *) e);

        tmp.len = e->pos - tmp.data;
        tmpv.data = e->pos;

        while (*(uintptr_t *) e->ip) {
            code = *(njt_http_script_code_pt *) e->ip;
            code((njt_http_script_engine_t *) e);
        }
        e->ip += sizeof(uintptr_t);

        tmpv.len = e->pos - tmpv.data;

        *b->last++ = 0;
        b->last = njt_http_v2_write_name(b->last,tmp.data,tmp.len,v2c->tmp);
        b->last = njt_http_v2_write_value(b->last,tmpv.data,tmpv.len,v2c->tmp);

        tmp.data = p;
        tmp.len = 0;

        tmpv.data = NULL;
        tmpv.len = 0;
        e->pos = start;
    }

    if (plcf->upstream.pass_request_headers) {
        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (njt_hash_find(&headers->hash, header[i].hash,
                              header[i].lowcase_key, header[i].key.len))
            {
                continue;
            }

            *b->last++ = 0;
            b->last = njt_http_v2_write_name(b->last,header[i].key.data,header[i].key.len,v2c->tmp);
            b->last = njt_http_v2_write_value(b->last,header[i].value.data,header[i].value.len,v2c->tmp);

            njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header: \"%V: %V\"",
                           &header[i].key, &header[i].value);
        }
    }

    return NJT_OK;
}

static njt_int_t
njt_http_v2_proxy_encode_path(njt_http_request_t *r,
    njt_http_v2_proxy_ctx_t *v2c, njt_buf_t *b)
{
    size_t                      n;
    u_char                     *p;
    size_t                      loc_len;
    size_t                      uri_len;   
    uintptr_t                   escape;
    njt_uint_t                  unparsed_uri;
    njt_http_upstream_t        *u;
    njt_http_proxy_ctx_t       *ctx;
    njt_http_proxy_loc_conf_t  *plcf;

    static njt_str_t njt_http_v2_path = njt_string(":path");

    plcf = njt_http_get_module_loc_conf(r, njt_http_proxy_module);
    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    if (b == NULL) {

        escape = 0;
        uri_len = 0;
        loc_len = 0;
        unparsed_uri = 0;

        if (plcf->proxy_lengths && ctx->vars.uri.len) {
            uri_len = ctx->vars.uri.len;

        } else if (ctx->vars.uri.len == 0 && r->valid_unparsed_uri) {
            unparsed_uri = 1;
            uri_len = r->unparsed_uri.len;

        } else {
            loc_len = (r->valid_location && ctx->vars.uri.len) ?
                                                        plcf->location.len : 0;

            if (r->quoted_uri || r->internal) {
               escape = 2 * njt_escape_uri(NULL, r->uri.data + loc_len,
                                           r->uri.len - loc_len,
                                           NJT_ESCAPE_URI);
            }

            uri_len = ctx->vars.uri.len + r->uri.len - loc_len + escape
                      + sizeof("?") - 1 + r->args.len;
        }

        if (uri_len == 0) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "zero length URI to proxy");
            return NJT_ERROR;
        }

        n = 1 + NJT_HTTP_V2_INT_OCTETS + njt_http_v2_path.len
          + NJT_HTTP_V2_INT_OCTETS + uri_len;

        v2c->n += n;

        if (uri_len > v2c->max_tmp_len) {
            v2c->max_tmp_len = uri_len;
        }

        v2c->escape = escape;
        v2c->uri_len = uri_len;
        v2c->loc_len = loc_len;
        v2c->unparsed_uri = unparsed_uri;

        return NJT_OK;
    }

    u = r->upstream;

    escape = v2c->escape;
    uri_len = v2c->uri_len;
    loc_len = v2c->loc_len;
    unparsed_uri = v2c->unparsed_uri;

    p = njt_palloc(r->pool, uri_len);
    if (p == NULL) {
        return NJT_ERROR;
    }

    u->uri.data = p;

    if (plcf->proxy_lengths && ctx->vars.uri.len) {
        p = njt_copy(p, ctx->vars.uri.data, ctx->vars.uri.len);

    } else if (unparsed_uri) {
        p = njt_copy(p, r->unparsed_uri.data, r->unparsed_uri.len);

    } else {
        if (r->valid_location) {
            p = njt_copy(p, ctx->vars.uri.data, ctx->vars.uri.len);
        }

        if (escape) {
            njt_escape_uri(p, r->uri.data + loc_len,
                           r->uri.len - loc_len, NJT_ESCAPE_URI);
            p += r->uri.len - loc_len + escape;

        } else {
            p = njt_copy(p, r->uri.data + loc_len, r->uri.len - loc_len);
        }

        if (r->args.len > 0) {
            *p++ = '?';
            p = njt_copy(p, r->args.data, r->args.len);
        }
    }

    u->uri.len = p - u->uri.data;
    *b->last++ = 0;
    b->last = njt_http_v2_write_name(b->last,njt_http_v2_path.data,njt_http_v2_path.len,v2c->tmp);
    b->last = njt_http_v2_write_value(b->last,u->uri.data,u->uri.len,v2c->tmp);
    return NJT_OK;
}

static njt_int_t
njt_http_v2_proxy_encode_authority(njt_http_request_t *r,
    njt_http_v2_proxy_ctx_t *v2c, njt_buf_t *b)
{
    size_t                      n;
    njt_http_proxy_ctx_t       *ctx;
    njt_http_proxy_loc_conf_t  *plcf;
    static njt_str_t njt_http_v2_auth = njt_string(":authority");

    plcf = njt_http_get_module_loc_conf(r, njt_http_proxy_module);

    if (plcf->host_set) {
        return NJT_OK;
    }

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    if (b == NULL) {

        n = 1 + NJT_HTTP_V2_INT_OCTETS + njt_http_v2_auth.len
          + NJT_HTTP_V2_INT_OCTETS + ctx->host.len;
        v2c->n += n;
        if ( ctx->host.len > v2c->max_tmp_len) {
            v2c->max_tmp_len =  ctx->host.len;
        }    

        return NJT_OK;
    }
    *b->last++ = 0;
    b->last = njt_http_v2_write_name(b->last,njt_http_v2_auth.data,njt_http_v2_auth.len,v2c->tmp);
    b->last = njt_http_v2_write_value(b->last,ctx->host.data,ctx->host.len,v2c->tmp);

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http2 header: \":authority: %V\"", &ctx->host);

    return NJT_OK;
}

static njt_int_t
njt_http_v2_proxy_body_length(njt_http_request_t *r,
    njt_http_v2_proxy_ctx_t *v2c)
{
    size_t                        body_len;
    njt_http_proxy_ctx_t         *ctx;
    njt_http_script_engine_t     *le;
    njt_http_proxy_loc_conf_t    *plcf;
    njt_http_script_len_code_pt   lcode;

    plcf = njt_http_get_module_loc_conf(r, njt_http_proxy_module);
    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    le = &v2c->le; 

    if (plcf->body_lengths) {
        le->ip = plcf->body_lengths->elts;
        le->request = r;
        le->flushed = 1;
        body_len = 0;

        while (*(uintptr_t *) le->ip) {
            lcode = *(njt_http_script_len_code_pt *) le->ip;
            body_len += lcode(le);
        }

        ctx->internal_body_length = body_len;      

    } else if (r->headers_in.chunked && r->reading_body) {
        ctx->internal_body_length = -1;
        ctx->internal_chunked = 1;

    } else {
        ctx->internal_body_length = r->headers_in.content_length_n;       
    }

    return NJT_OK;
}

static njt_chain_t *
njt_http_v2_proxy_encode_body(njt_http_request_t *r,
    njt_http_v2_proxy_ctx_t *v2c)
{
    njt_buf_t                  *b;
    njt_chain_t                *cl, *body, *prev, *head;
    njt_http_upstream_t        *u;
    njt_http_proxy_ctx_t       *ctx;
    njt_http_script_code_pt     code;
    njt_http_script_engine_t   *e;
    njt_http_proxy_loc_conf_t  *plcf;

    plcf = njt_http_get_module_loc_conf(r, njt_http_proxy_module);
    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);
    /* body set in configuration */
    
    u = r->upstream;

    if (plcf->body_values) {

        e = &v2c->e;

        cl = njt_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NJT_CHAIN_ERROR;
        }

        b = njt_create_temp_buf(r->pool, ctx->internal_body_length);
        if (b == NULL) {
            return NJT_CHAIN_ERROR;
        }

        cl->buf = b;
        cl->next = NULL;

        e->ip = plcf->body_values->elts;
        e->pos = b->last;
        e->skip = 0;

        while (*(uintptr_t *) e->ip) {
            code = *(njt_http_script_code_pt *) e->ip;
            code((njt_http_script_engine_t *) e);
        }

        b->last = e->pos;
        b->last_buf = 1;

        return cl;
    }

     if (!plcf->upstream.pass_request_body) {
        return NULL;
    }

    /* body from client */

    cl = NULL;
    head = NULL;
    prev = NULL;

    body = u->request_bufs;

    while (body) {

        b = njt_alloc_buf(r->pool);
        if (b == NULL) {
            return NJT_CHAIN_ERROR;
        }

        njt_memcpy(b, body->buf, sizeof(njt_buf_t));

        cl = njt_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NJT_CHAIN_ERROR;
        }

        cl->buf = b;

        if (prev) {
            prev->next = cl;

        } else {
            head = cl;
        }

        prev = cl;
        body = body->next;
    }

    if (cl) {
        cl->next = NULL;
    }

    return head;
}

static njt_int_t
njt_http_v2_proxy_process_header(njt_http_request_t *r)
{
    u_char                       *p;
    njt_buf_t                    *b;
    njt_int_t                     rc;
    njt_connection_t             *c, c_stub;
    njt_http_upstream_t          *u;
    njt_http_v2_connection_t     *h2c, h2c_stub;
    njt_http_v2_stream_t         *stream,stream_stub;
    njt_http_v2_state_t           tmp_state;
    njt_http_core_srv_conf_t     *cscf;

    u = r->upstream;
    c = u->peer.connection;    

    njt_log_debug3(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http2 proxy header cache:%p, c:%p, buffer:%d", 
                   r->cache, c, u->buffer.last - u->buffer.pos);

#if (NJT_HTTP_CACHE)
    /*from cache file*/
    if (r->cache && 
        ( !c 
          || u->cache_status == NJT_HTTP_CACHE_STALE 
          || u->cache_status == NJT_HTTP_CACHE_REVALIDATED ))
    {
        njt_memzero(&h2c_stub,sizeof(njt_http_v2_connection_t));
        njt_memzero(&stream_stub,sizeof(njt_http_v2_stream_t));
        njt_memzero(&c_stub,sizeof(njt_connection_t));
        njt_memzero(&tmp_state,sizeof(njt_http_v2_state_t));

        cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);

        h2c = &h2c_stub;
        h2c->fake = 1;
        h2c->client = 1;
        h2c->pool = r->pool;
        h2c->state.pool = r->pool;
        h2c->state.flags |= NJT_HTTP_V2_END_HEADERS_FLAG;
        h2c->state.handler = njt_http_v2_state_header_block;
        h2c->state.length = r->cache->body_start - r->cache->header_start;
        h2c->state.keep_pool = 1;
        h2c->http_connection = r->http_connection;
        h2c->state.header_limit = cscf->large_client_header_buffers.size
                               * cscf->large_client_header_buffers.num;
        c = &c_stub;
        c->log = r->connection->log;
        c->pool = r->pool;
        h2c->connection = c;

        stream = &stream_stub;
        stream->state = &tmp_state;
        stream->request = r;
        h2c->state.stream = stream; 
    } else {
#endif
        stream = c->stream;
        h2c = njt_http_v2_get_connection(c);
#if (NJT_HTTP_CACHE)
    }
#endif
    /*save state*/
    njt_memcpy(&tmp_state, &h2c->state, sizeof(njt_http_v2_state_t));
    njt_memcpy(&h2c->state, stream->state, sizeof(njt_http_v2_state_t));

    b = &u->buffer;
    p = b->pos;

    h2c->state.parse = 1;
    rc = njt_http_v2_parse_headers(h2c, b);
    h2c->state.parse = 0;

    /*restore state*/
    njt_memcpy(stream->state, &h2c->state, sizeof(njt_http_v2_state_t));
    njt_memcpy(&h2c->state, &tmp_state, sizeof(njt_http_v2_state_t));

    njt_log_debug3(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "njt_http_v2_parse_headers rc:%d pos:%p, last:%p", 
                   rc, b->pos, b->last);

    if (rc == NJT_ERROR) {
        return NJT_ERROR;
    }

    if (h2c) {
        h2c->total_bytes += b->pos - p;
    }

    if (rc == NJT_AGAIN) {
        return NJT_AGAIN;
    }

    return NJT_OK;
}

static njt_int_t
njt_http_v2_proxy_reinit_request(njt_http_request_t *r)
{
    njt_http_proxy_ctx_t  *ctx;

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    if (ctx == NULL) {
        return NJT_OK;
    }

    ctx->status.code = 0;
    ctx->status.count = 0;
    ctx->status.start = NULL;
    ctx->status.end = NULL;
    ctx->chunked.state = 0;

    r->upstream->process_header = njt_http_v2_proxy_process_header;
    r->upstream->pipe->input_filter = njt_http_proxy_copy_filter;
    r->upstream->input_filter = njt_http_proxy_non_buffered_copy_filter;
    r->state = 0;

    return NJT_OK;
}

static void
njt_http_v2_proxy_abort_request(njt_http_request_t *r)
{
    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http v2 proxy request");
}


static void
njt_http_v2_proxy_finalize_request(njt_http_request_t *r, njt_int_t rc)
{
    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http v2 proxy request");
}

#endif
#if (NJT_HTTP_V3)

static char *
njt_http_v3_proxy_host_key(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_proxy_loc_conf_t *plcf = conf;

    u_char           *buf;
    size_t            size;
    ssize_t           n;
    njt_str_t        *value;
    njt_file_t        file;
    njt_file_info_t   fi;
    njt_quic_conf_t  *qcf;

    qcf = &plcf->upstream.quic;

    if (qcf->host_key.len) {
        return "is duplicate";
    }

    buf = NULL;
#if (NJT_SUPPRESS_WARN)
    size = 0;
#endif

    value = cf->args->elts;

    if (njt_conf_full_name(cf->cycle, &value[1], 1) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    njt_memzero(&file, sizeof(njt_file_t));
    file.name = value[1];
    file.log = cf->log;

    file.fd = njt_open_file(file.name.data, NJT_FILE_RDONLY, NJT_FILE_OPEN, 0);

    if (file.fd == NJT_INVALID_FILE) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, njt_errno,
                           njt_open_file_n " \"%V\" failed", &file.name);
        return NJT_CONF_ERROR;
    }

    if (njt_fd_info(file.fd, &fi) == NJT_FILE_ERROR) {
        njt_conf_log_error(NJT_LOG_CRIT, cf, njt_errno,
                           njt_fd_info_n " \"%V\" failed", &file.name);
        goto failed;
    }

    size = njt_file_size(&fi);

    if (size == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "\"%V\" zero key size", &file.name);
        goto failed;
    }

    buf = njt_pnalloc(cf->pool, size);
    if (buf == NULL) {
        goto failed;
    }

    n = njt_read_file(&file, buf, size, 0);

    if (n == NJT_ERROR) {
        njt_conf_log_error(NJT_LOG_CRIT, cf, njt_errno,
                           njt_read_file_n " \"%V\" failed", &file.name);
        goto failed;
    }

    if ((size_t) n != size) {
        njt_conf_log_error(NJT_LOG_CRIT, cf, 0,
                           njt_read_file_n " \"%V\" returned only "
                           "%z bytes instead of %uz", &file.name, n, size);
        goto failed;
    }

    qcf->host_key.data = buf;
    qcf->host_key.len = n;

    if (njt_close_file(file.fd) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_ALERT, cf->log, njt_errno,
                      njt_close_file_n " \"%V\" failed", &file.name);
    }

    return NJT_CONF_OK;

failed:

    if (njt_close_file(file.fd) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_ALERT, cf->log, njt_errno,
                      njt_close_file_n " \"%V\" failed", &file.name);
    }

    if (buf) {
        njt_explicit_memzero(buf, size);
    }

    return NJT_CONF_ERROR;
}


static njt_int_t
njt_http_v3_proxy_merge_quic(njt_conf_t *cf, njt_http_proxy_loc_conf_t *conf,
    njt_http_proxy_loc_conf_t *prev)
{
    if ((conf->upstream.upstream || conf->proxy_lengths)
        && (conf->ssl == 0 || conf->upstream.ssl == NULL))
    {
        /* we have proxy_pass, http/3 and no ssl - this isn't going to work */

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "http3 proxy requires ssl configuration "
                           "and https:// scheme");
        return NJT_ERROR;
    }

    njt_conf_merge_value(conf->enable_hq, prev->enable_hq, 0);

    if (conf->enable_hq) {
        conf->upstream.quic.alpn.data = (unsigned char *)
                                        NJT_HTTP_V3_HQ_ALPN_PROTO;

        conf->upstream.quic.alpn.len = sizeof(NJT_HTTP_V3_HQ_ALPN_PROTO) - 1;

    } else {
        conf->upstream.quic.alpn.data = (unsigned char *)
                                        NJT_HTTP_V3_ALPN_PROTO;

        conf->upstream.quic.alpn.len = sizeof(NJT_HTTP_V3_ALPN_PROTO) - 1;
    }

    njt_conf_merge_size_value(conf->upstream.quic.stream_buffer_size,
                              prev->upstream.quic.stream_buffer_size,
                              65536);

    njt_conf_merge_uint_value(conf->upstream.quic.max_concurrent_streams_bidi,
                              prev->upstream.quic.max_concurrent_streams_bidi,
                              128);

    njt_conf_merge_value(conf->upstream.quic.gso_enabled,
                         prev->upstream.quic.gso_enabled,
                         0);

    njt_conf_merge_uint_value(conf->upstream.quic.active_connection_id_limit,
                              prev->upstream.quic.active_connection_id_limit,
                              2);

    conf->upstream.quic.idle_timeout = conf->upstream.read_timeout;
    conf->upstream.quic.handshake_timeout = conf->upstream.connect_timeout;

    if (conf->upstream.quic.host_key.len == 0) {

        conf->upstream.quic.host_key.len = NJT_QUIC_DEFAULT_HOST_KEY_LEN;
        conf->upstream.quic.host_key.data = njt_palloc(cf->pool,
                                             conf->upstream.quic.host_key.len);

        if (conf->upstream.quic.host_key.data == NULL) {
            return NJT_ERROR;
        }

        if (RAND_bytes(conf->upstream.quic.host_key.data,
                       NJT_QUIC_DEFAULT_HOST_KEY_LEN)
            <= 0)
        {
            return NJT_ERROR;
        }
    }

    if (njt_quic_derive_key(cf->log, "av_token_key",
                            &conf->upstream.quic.host_key,
                            &njt_http_v3_proxy_quic_salt,
                            conf->upstream.quic.av_token_key,
                            NJT_QUIC_AV_KEY_LEN)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    if (njt_quic_derive_key(cf->log, "sr_token_key",
                            &conf->upstream.quic.host_key,
                            &njt_http_v3_proxy_quic_salt,
                            conf->upstream.quic.sr_token_key,
                            NJT_QUIC_SR_KEY_LEN)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    conf->upstream.quic.ssl = conf->upstream.ssl;

    return NJT_OK;
}


static njt_int_t
njt_http_v3_proxy_create_request(njt_http_request_t *r)
{
    njt_buf_t                  *b;
    njt_chain_t                *cl, *body, *out;
    njt_http_upstream_t        *u;
    njt_http_proxy_ctx_t       *ctx;
    njt_http_v3_proxy_ctx_t     v3c;
    njt_http_proxy_headers_t   *headers;
    njt_http_proxy_loc_conf_t  *plcf;

    /*
     * HTTP/3 Request:
     *
     * HEADERS FRAME
     *    :method:
     *    :scheme:
     *    :path:
     *    :authority:
     *     proxy headers[]
     *     client headers[]
     *
     * DATA FRAME
     *    body
     *
     * HEADERS FRAME
     *    trailers[]
     */

    u = r->upstream;

    plcf = njt_http_get_module_loc_conf(r, njt_http_proxy_module);

#if (NJT_HTTP_CACHE)
    headers = u->cacheable ? &plcf->headers_cache : &plcf->headers;
#else
    headers = &plcf->headers;
#endif

    njt_memzero(&v3c, sizeof(njt_http_v3_proxy_ctx_t));

    njt_http_script_flush_no_cacheable_variables(r, plcf->body_flushes);
    njt_http_script_flush_no_cacheable_variables(r, headers->flushes);

    v3c.headers = headers;

    v3c.n = njt_http_v3_encode_field_section_prefix(NULL, 0, 0, 0);

    /* calculate lengths */

    njt_http_v3_proxy_encode_method(r, &v3c, NULL);

    v3c.n += njt_http_v3_encode_field_ri(NULL, 0,
                                         NJT_HTTP_V3_HEADER_SCHEME_HTTPS);

    if (njt_http_v3_proxy_encode_path(r, &v3c, NULL) != NJT_OK) {
        return NJT_ERROR;
    }

    if (njt_http_v3_proxy_encode_authority(r, &v3c, NULL) != NJT_OK) {
        return NJT_ERROR;
    }

    if (njt_http_v3_proxy_body_length(r, &v3c) != NJT_OK) {
        return NJT_ERROR;
    }

    if (njt_http_v3_proxy_encode_headers(r, &v3c, NULL) != NJT_OK) {
        return NJT_ERROR;
    }

    /* generate HTTP/3 request of known size */

    b = njt_create_temp_buf(r->pool, v3c.n);
    if (b == NULL) {
        return NJT_ERROR;
    }

    b->last = (u_char *) njt_http_v3_encode_field_section_prefix(b->last,
                                                                 0, 0, 0);

    if (njt_http_v3_proxy_encode_method(r, &v3c, b) != NJT_OK) {
        return NJT_ERROR;
    }

    b->last = (u_char *) njt_http_v3_encode_field_ri(b->last, 0,
                                              NJT_HTTP_V3_HEADER_SCHEME_HTTPS);

    if (njt_http_v3_proxy_encode_path(r, &v3c, b) != NJT_OK) {
        return NJT_ERROR;
    }

    if (njt_http_v3_proxy_encode_authority(r, &v3c, b) != NJT_OK) {
        return NJT_ERROR;
    }

    if (njt_http_v3_proxy_encode_headers(r, &v3c, b) != NJT_OK) {
        return NJT_ERROR;
    }

    out = njt_http_v3_create_headers_frame(r, b);
    if (out == NJT_CHAIN_ERROR) {
        return NJT_ERROR;
    }

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    if (r->request_body_no_buffering || ctx->internal_chunked) {
        u->output.output_filter = njt_http_v3_proxy_body_output_filter;
        u->output.filter_ctx = r;

    } else if (ctx->internal_body_length != -1) {

        body = njt_http_v3_proxy_encode_body(r, &v3c);
        if (body == NJT_CHAIN_ERROR) {
            return NJT_ERROR;
        }

        body = njt_http_v3_create_data_frame(r, body,
                                             ctx->internal_body_length);
        if (body == NJT_CHAIN_ERROR) {
            return NJT_ERROR;
        }

        for (cl = out; cl->next; cl = cl->next) { /* void */ }
        cl->next = body;
    }

    /* TODO: trailers */

    u->request_bufs = out;

    return NJT_OK;
}


static njt_chain_t *
njt_http_v3_create_headers_frame(njt_http_request_t *r, njt_buf_t *hbuf)
{
    njt_buf_t    *b;
    size_t        n, len;
    njt_chain_t  *cl, *head;

    n = hbuf->last - hbuf->pos;

    len = njt_http_v3_encode_varlen_int(NULL, NJT_HTTP_V3_FRAME_HEADERS)
          + njt_http_v3_encode_varlen_int(NULL, n);

    b = njt_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NULL;
    }

    b->last = (u_char *) njt_http_v3_encode_varlen_int(b->last,
                                                    NJT_HTTP_V3_FRAME_HEADERS);
    b->last = (u_char *) njt_http_v3_encode_varlen_int(b->last, n);

    /* mark our header buffers to distinguish them in non-buffered filter */
    b->tag = (njt_buf_tag_t) &njt_http_v3_create_headers_frame;
    hbuf->tag = (njt_buf_tag_t) &njt_http_v3_create_headers_frame;

    cl = njt_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = b;
    head = cl;

    cl = njt_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = hbuf;
    cl->next = NULL;

    head->next = cl;

    return head;
}


static njt_chain_t *
njt_http_v3_create_data_frame(njt_http_request_t *r, njt_chain_t *body,
    size_t size)
{
    size_t        len;
    njt_buf_t    *b;
    njt_chain_t  *cl;

    len = njt_http_v3_encode_varlen_int(NULL, NJT_HTTP_V3_FRAME_DATA)
          + njt_http_v3_encode_varlen_int(NULL, size);

    b = njt_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NJT_CHAIN_ERROR;
    }

    b->last = (u_char *) njt_http_v3_encode_varlen_int(b->last,
                                                       NJT_HTTP_V3_FRAME_DATA);
    b->last = (u_char *) njt_http_v3_encode_varlen_int(b->last, size);

    cl = njt_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NJT_CHAIN_ERROR;
    }

    cl->buf = b;
    cl->next = body;

    return cl;
}


static njt_inline njt_uint_t
njt_http_v3_map_method(njt_uint_t method)
{
    switch (method) {
    case NJT_HTTP_GET:
        return NJT_HTTP_V3_HEADER_METHOD_GET;
    case NJT_HTTP_HEAD:
        return NJT_HTTP_V3_HEADER_METHOD_HEAD;
    case NJT_HTTP_POST:
        return NJT_HTTP_V3_HEADER_METHOD_POST;
    case NJT_HTTP_PUT:
        return NJT_HTTP_V3_HEADER_METHOD_PUT;
    case NJT_HTTP_DELETE:
        return NJT_HTTP_V3_HEADER_METHOD_DELETE;
    case NJT_HTTP_OPTIONS:
        return NJT_HTTP_V3_HEADER_METHOD_OPTIONS;
    default:
        return 0;
    }
}


static njt_int_t
njt_http_v3_proxy_encode_method(njt_http_request_t *r,
    njt_http_v3_proxy_ctx_t *v3c, njt_buf_t *b)
{
    size_t                      n;
    njt_str_t                   method;
    njt_uint_t                  v3method;
    njt_http_upstream_t        *u;
    njt_http_proxy_ctx_t       *ctx;
    njt_http_proxy_loc_conf_t  *plcf;

    static njt_str_t njt_http_v3_header_method = njt_string(":method");

    if (b == NULL) {
        /* calculate length */

        plcf = njt_http_get_module_loc_conf(r, njt_http_proxy_module);
        ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

        method.len = 0;
        n = 0;

        u = r->upstream;

        if (u->method.len) {
            /* HEAD was changed to GET to cache response */
            method = u->method;

        } else if (plcf->method) {
            if (njt_http_complex_value(r, plcf->method, &method) != NJT_OK) {
                return NJT_ERROR;
            }
        } else {
            method = r->method_name;
        }

        if (method.len == 4
            && njt_strncasecmp(method.data, (u_char *) "HEAD", 4) == 0)
        {
            ctx->head = 1;
        }

        if (method.len) {
            n = njt_http_v3_encode_field_l(NULL, &njt_http_v3_header_method,
                                           &method);
        } else {

            v3method = njt_http_v3_map_method(r->method);

            if (v3method) {
                n = njt_http_v3_encode_field_ri(NULL, 0, v3method);

            } else {
                n = njt_http_v3_encode_field_l(NULL,
                                               &njt_http_v3_header_method,
                                               &r->method_name);
            }
        }

        v3c->n += n;
        v3c->method = method;

        return NJT_OK;
    }

    method = v3c->method;

    if (method.len) {
        b->last = (u_char *) njt_http_v3_encode_field_l(b->last,
                                                    &njt_http_v3_header_method,
                                                    &method);
    } else {

        v3method = njt_http_v3_map_method(r->method);

        if (v3method) {
            b->last = (u_char *) njt_http_v3_encode_field_ri(b->last, 0,
                                                             v3method);
        } else {
            b->last = (u_char *) njt_http_v3_encode_field_l(b->last,
                                                    &njt_http_v3_header_method,
                                                    &r->method_name);
        }
    }

    return NJT_OK;
}


static njt_int_t
njt_http_v3_proxy_encode_authority(njt_http_request_t *r,
    njt_http_v3_proxy_ctx_t *v3c, njt_buf_t *b)
{
    size_t                      n;
    njt_http_proxy_ctx_t       *ctx;
    njt_http_proxy_loc_conf_t  *plcf;

    plcf = njt_http_get_module_loc_conf(r, njt_http_proxy_module);

    if (plcf->host_set) {
        return NJT_OK;
    }

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    if (b == NULL) {

        n = njt_http_v3_encode_field_lri(NULL, 0, NJT_HTTP_V3_HEADER_AUTHORITY,
                                         NULL, ctx->host.len);
        v3c->n += n;

        return NJT_OK;
    }

    b->last = (u_char *) njt_http_v3_encode_field_lri(b->last, 0,
                  NJT_HTTP_V3_HEADER_AUTHORITY, ctx->host.data, ctx->host.len);

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http3 header: \":authority: %V\"", &ctx->host);

    return NJT_OK;
}


static njt_int_t
njt_http_v3_proxy_encode_path(njt_http_request_t *r,
    njt_http_v3_proxy_ctx_t *v3c, njt_buf_t *b)
{
    size_t                      n;
    u_char                     *p;
    size_t                      loc_len;
    size_t                      uri_len;
    njt_str_t                   tmp;
    uintptr_t                   escape;
    njt_uint_t                  unparsed_uri;
    njt_http_upstream_t        *u;
    njt_http_proxy_ctx_t       *ctx;
    njt_http_proxy_loc_conf_t  *plcf;

    static njt_str_t njt_http_v3_path = njt_string(":path");

    plcf = njt_http_get_module_loc_conf(r, njt_http_proxy_module);
    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    if (b == NULL) {

        escape = 0;
        uri_len = 0;
        loc_len = 0;
        unparsed_uri = 0;

        if (plcf->proxy_lengths && ctx->vars.uri.len) {
            uri_len = ctx->vars.uri.len;

        } else if (ctx->vars.uri.len == 0 && r->valid_unparsed_uri) {
            unparsed_uri = 1;
            uri_len = r->unparsed_uri.len;

        } else {
            loc_len = (r->valid_location && ctx->vars.uri.len) ?
                                                        plcf->location.len : 0;

            if (r->quoted_uri || r->internal) {
               escape = 2 * njt_escape_uri(NULL, r->uri.data + loc_len,
                                           r->uri.len - loc_len,
                                           NJT_ESCAPE_URI);
            }

            uri_len = ctx->vars.uri.len + r->uri.len - loc_len + escape
                      + sizeof("?") - 1 + r->args.len;
        }

        if (uri_len == 0) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "zero length URI to proxy");
            return NJT_ERROR;
        }

        tmp.data = NULL;
        tmp.len = uri_len;

        n = njt_http_v3_encode_field_l(NULL, &njt_http_v3_path, &tmp);

        v3c->n += n;

        v3c->escape = escape;
        v3c->uri_len = uri_len;
        v3c->loc_len = loc_len;
        v3c->unparsed_uri = unparsed_uri;

        return NJT_OK;
    }

    u = r->upstream;

    escape = v3c->escape;
    uri_len = v3c->uri_len;
    loc_len = v3c->loc_len;
    unparsed_uri = v3c->unparsed_uri;

    p = njt_palloc(r->pool, uri_len);
    if (p == NULL) {
        return NJT_ERROR;
    }

    u->uri.data = p;

    if (plcf->proxy_lengths && ctx->vars.uri.len) {
        p = njt_copy(p, ctx->vars.uri.data, ctx->vars.uri.len);

    } else if (unparsed_uri) {
        p = njt_copy(p, r->unparsed_uri.data, r->unparsed_uri.len);

    } else {
        if (r->valid_location) {
            p = njt_copy(p, ctx->vars.uri.data, ctx->vars.uri.len);
        }

        if (escape) {
            njt_escape_uri(p, r->uri.data + loc_len,
                           r->uri.len - loc_len, NJT_ESCAPE_URI);
            p += r->uri.len - loc_len + escape;

        } else {
            p = njt_copy(p, r->uri.data + loc_len, r->uri.len - loc_len);
        }

        if (r->args.len > 0) {
            *p++ = '?';
            p = njt_copy(p, r->args.data, r->args.len);
        }
    }

    u->uri.len = p - u->uri.data;

    b->last = (u_char *) njt_http_v3_encode_field_l(b->last, &njt_http_v3_path,
                                                    &u->uri);
    return NJT_OK;
}


static njt_int_t
njt_http_v3_proxy_body_length(njt_http_request_t *r,
    njt_http_v3_proxy_ctx_t *v3c)
{
    size_t                        body_len, n;
    njt_http_proxy_ctx_t         *ctx;
    njt_http_script_engine_t     *le;
    njt_http_proxy_loc_conf_t    *plcf;
    njt_http_script_len_code_pt   lcode;

    plcf = njt_http_get_module_loc_conf(r, njt_http_proxy_module);
    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    le = &v3c->le;

    n = 0;

    if (plcf->body_lengths) {
        le->ip = plcf->body_lengths->elts;
        le->request = r;
        le->flushed = 1;
        body_len = 0;

        while (*(uintptr_t *) le->ip) {
            lcode = *(njt_http_script_len_code_pt *) le->ip;
            body_len += lcode(le);
        }

        ctx->internal_body_length = body_len;
        n += body_len;

    } else if (r->headers_in.chunked && r->reading_body) {
        ctx->internal_body_length = -1;
        ctx->internal_chunked = 1;

    } else {
        ctx->internal_body_length = r->headers_in.content_length_n;
        n = r->headers_in.content_length_n;
    }

    v3c->n += n;

    return NJT_OK;
}


static njt_chain_t *
njt_http_v3_proxy_encode_body(njt_http_request_t *r,
    njt_http_v3_proxy_ctx_t *v3c)
{
    njt_buf_t                  *b;
    njt_chain_t                *body, *cl, *prev, *head;
    njt_http_upstream_t        *u;
    njt_http_proxy_ctx_t       *ctx;
    njt_http_script_code_pt     code;
    njt_http_script_engine_t   *e;
    njt_http_proxy_loc_conf_t  *plcf;

    plcf = njt_http_get_module_loc_conf(r, njt_http_proxy_module);
    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    u = r->upstream;

    /* body set in configuration */

    if (plcf->body_values) {

        e = &v3c->e;

        cl = njt_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NJT_CHAIN_ERROR;
        }

        b = njt_create_temp_buf(r->pool, ctx->internal_body_length);
        if (b == NULL) {
            return NJT_CHAIN_ERROR;
        }

        cl->buf = b;
        cl->next = NULL;

        e->ip = plcf->body_values->elts;
        e->pos = b->last;
        e->skip = 0;

        while (*(uintptr_t *) e->ip) {
            code = *(njt_http_script_code_pt *) e->ip;
            code((njt_http_script_engine_t *) e);
        }

        b->last = e->pos;

        return cl;
    }

    if (!plcf->upstream.pass_request_body) {
        return NULL;
    }

    /* body from client */

    cl = NULL;
    head = NULL;
    prev = NULL;

    body = u->request_bufs;

    while (body) {

        b = njt_alloc_buf(r->pool);
        if (b == NULL) {
            return NJT_CHAIN_ERROR;
        }

        njt_memcpy(b, body->buf, sizeof(njt_buf_t));

        cl = njt_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NJT_CHAIN_ERROR;
        }

        cl->buf = b;

        if (prev) {
            prev->next = cl;

        } else {
            head = cl;
        }

        prev = cl;
        body = body->next;
    }

    if (cl) {
        cl->next = NULL;
    }

    return head;
}


static njt_int_t
njt_http_v3_proxy_body_output_filter(void *data, njt_chain_t *in)
{
    njt_http_request_t  *r = data;

    off_t                  size;
    u_char                *chunk;
    size_t                 len;
    njt_buf_t             *b;
    njt_int_t              rc;
    njt_chain_t           *out, *cl, *tl, **ll, **fl;
    njt_http_proxy_ctx_t  *ctx;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "v3 proxy output filter");

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    if (in == NULL) {
        out = in;
        goto out;
    }

    out = NULL;
    ll = &out;

    if (!ctx->header_sent) {

        /* buffers contain v3-encoded headers frame, pass it as is */

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "v3 proxy output header");

        ctx->header_sent = 1;

        for ( ;; ) {

            if (in->buf->tag
                != (njt_buf_tag_t) &njt_http_v3_create_headers_frame)
            {
                break;
            }

            tl = njt_alloc_chain_link(r->pool);
            if (tl == NULL) {
                return NJT_ERROR;
            }

            tl->buf = in->buf;
            *ll = tl;
            ll = &tl->next;

            in = in->next;

            if (in == NULL) {
                tl->next = NULL;
                goto out;
            }
        }
    }

    size = 0;
    fl = ll;

    for (cl = in; cl; cl = cl->next) {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "v3 proxy output chunk: %O", njt_buf_size(cl->buf));

        size += njt_buf_size(cl->buf);

        if (cl->buf->flush
            || cl->buf->sync
            || njt_buf_in_memory(cl->buf)
            || cl->buf->in_file)
        {
            tl = njt_alloc_chain_link(r->pool);
            if (tl == NULL) {
                return NJT_ERROR;
            }

            tl->buf = cl->buf;
            *ll = tl;
            ll = &tl->next;
        }
    }

    if (size) {

        tl = njt_chain_get_free_buf(r->pool, &ctx->free);
        if (tl == NULL) {
            return NJT_ERROR;
        }

        b = tl->buf;
        chunk = b->start;

        if (chunk == NULL) {
            len = njt_http_v3_encode_varlen_int(NULL,
                                                 NJT_HTTP_V3_FRAME_DATA)
                   + 8 /* max varlen int length*/;

            chunk = njt_palloc(r->pool, len);
            if (chunk == NULL) {
                return NJT_ERROR;
            }
            b->start = chunk;
            b->pos = b->start;
            b->end = chunk + len;
        }

        b->tag = (njt_buf_tag_t) &njt_http_v3_proxy_body_output_filter;
        b->memory = 0;
        b->temporary = 1;

        b->last = (u_char *) njt_http_v3_encode_varlen_int(b->start,
                                                       NJT_HTTP_V3_FRAME_DATA);
        b->last = (u_char *) njt_http_v3_encode_varlen_int(b->last, size);

        tl->next = *fl;
        *fl = tl;
    }

    *ll = NULL;

out:

    rc = njt_chain_writer(&r->upstream->writer, out);

    njt_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
                        (njt_buf_tag_t) &njt_http_v3_proxy_body_output_filter);

    return rc;
}


static njt_int_t
njt_http_v3_proxy_encode_headers(njt_http_request_t *r,
    njt_http_v3_proxy_ctx_t *v3c, njt_buf_t *b)
{
    u_char                       *p, *start;
    size_t                        key_len, val_len, hlen, max_head, n;
    njt_str_t                     tmp, tmpv;
    njt_uint_t                    i;
    njt_list_part_t              *part;
    njt_table_elt_t              *header;
    njt_http_script_code_pt       code;
    njt_http_proxy_headers_t     *headers;
    njt_http_script_engine_t     *le;
    njt_http_script_engine_t     *e;
    njt_http_proxy_loc_conf_t    *plcf;
    njt_http_script_len_code_pt   lcode;

    plcf = njt_http_get_module_loc_conf(r, njt_http_proxy_module);

    headers = v3c->headers;
    le = &v3c->le;
    e = &v3c->e;

    if (b == NULL) {

        le->ip = headers->lengths->elts;
        le->request = r;
        le->flushed = 1;

        n = 0;
        max_head = 0;

        while (*(uintptr_t *) le->ip) {

            lcode = *(njt_http_script_len_code_pt *) le->ip;
            key_len = lcode(le);

            for (val_len = 0; *(uintptr_t *) le->ip; val_len += lcode(le)) {
                lcode = *(njt_http_script_len_code_pt *) le->ip;
            }
            le->ip += sizeof(uintptr_t);

            if (val_len == 0) {
                continue;
            }

            tmp.data = NULL;
            tmp.len = key_len;

            tmpv.data = NULL;
            tmpv.len = val_len;

            hlen = key_len + val_len;
            if (hlen > max_head) {
                max_head = hlen;
            }

            n += njt_http_v3_encode_field_l(NULL, &tmp, &tmpv);
        }

        if (plcf->upstream.pass_request_headers) {
            part = &r->headers_in.headers.part;
            header = part->elts;

            for (i = 0; /* void */; i++) {

                if (i >= part->nelts) {
                    if (part->next == NULL) {
                        break;
                    }

                    part = part->next;
                    header = part->elts;
                    i = 0;
                }

                if (njt_hash_find(&headers->hash, header[i].hash,
                                  header[i].lowcase_key, header[i].key.len))
                {
                    continue;
                }

                n += njt_http_v3_encode_field_l(NULL, &header[i].key,
                                                &header[i].value);
            }
        }

        v3c->n += n;
        v3c->max_head = max_head;

        return NJT_OK;
    }

    max_head = v3c->max_head;

    p = njt_pnalloc(r->pool, max_head);
    if (p == NULL) {
        return NJT_ERROR;
    }

    start = p;

    njt_memzero(e, sizeof(njt_http_script_engine_t));

    e->ip = headers->values->elts;
    e->pos = p;
    e->request = r;
    e->flushed = 1;

    le->ip = headers->lengths->elts;

    tmp.data = p;
    tmp.len = 0;

    tmpv.data = NULL;
    tmpv.len = 0;

    while (*(uintptr_t *) le->ip) {

        lcode = *(njt_http_script_len_code_pt *) le->ip;
        (void) lcode(le);

        for (val_len = 0; *(uintptr_t *) le->ip; val_len += lcode(le)) {
            lcode = *(njt_http_script_len_code_pt *) le->ip;
        }
        le->ip += sizeof(uintptr_t);

        if (val_len == 0) {
            e->skip = 1;

            while (*(uintptr_t *) e->ip) {
                code = *(njt_http_script_code_pt *) e->ip;
                code((njt_http_script_engine_t *) e);
            }
            e->ip += sizeof(uintptr_t);

            e->skip = 0;

            continue;
        }

        code = *(njt_http_script_code_pt *) e->ip;
        code((njt_http_script_engine_t *) e);

        tmp.len = e->pos - tmp.data;
        tmpv.data = e->pos;

        while (*(uintptr_t *) e->ip) {
            code = *(njt_http_script_code_pt *) e->ip;
            code((njt_http_script_engine_t *) e);
        }
        e->ip += sizeof(uintptr_t);

        tmpv.len = e->pos - tmpv.data;

        b->last = (u_char *) njt_http_v3_encode_field_l(b->last, &tmp, &tmpv);

        tmp.data = p;
        tmp.len = 0;

        tmpv.data = NULL;
        tmpv.len = 0;
        e->pos = start;
    }

    if (plcf->upstream.pass_request_headers) {
        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (njt_hash_find(&headers->hash, header[i].hash,
                              header[i].lowcase_key, header[i].key.len))
            {
                continue;
            }

            b->last = (u_char *) njt_http_v3_encode_field_l(b->last,
                                                            &header[i].key,
                                                            &header[i].value);

            njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header: \"%V: %V\"",
                           &header[i].key, &header[i].value);
        }
    }

    return NJT_OK;
}


static njt_int_t
njt_http_v3_proxy_reinit_request(njt_http_request_t *r)
{
    njt_http_proxy_ctx_t  *ctx;

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    if (ctx == NULL) {
        return NJT_OK;
    }

    r->upstream->process_header = njt_http_v3_proxy_process_status_line;
    r->upstream->pipe->input_filter = njt_http_v3_proxy_copy_filter;
    r->upstream->input_filter = njt_http_v3_proxy_non_buffered_copy_filter;
    r->state = 0;

    return NJT_OK;
}


static njt_int_t
njt_http_v3_proxy_process_status_line(njt_http_request_t *r)
{
    u_char                       *p;
    njt_buf_t                    *b;
    njt_int_t                     rc;
    njt_connection_t             *c, stub;
    njt_http_upstream_t          *u;
    njt_http_proxy_ctx_t         *ctx;
    njt_http_v3_session_t        *h3c;
    njt_http_v3_parse_headers_t  *st;

    u = r->upstream;
    c = u->peer.connection;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "njt_http_v3_proxy_process_status_line");

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);
    if (ctx == NULL) {
        return NJT_ERROR;
    }

#if (NJT_HTTP_CACHE)
    if (r->cache) {
        /* no connection here */
        h3c = NULL;
        njt_memzero(&stub, sizeof(njt_connection_t));
        c = &stub;

        /* while HTTP/3 parsing, only log and pool are used */
        c->log = r->connection->log;
        c->pool = r->connection->pool;
    } else
#endif

    h3c = njt_http_v3_get_session(c);

    if (njt_list_init(&u->headers_in.headers, r->pool, 20,
                      sizeof(njt_table_elt_t))
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    ctx->v3_parse->header_limit = u->conf->bufs.size * u->conf->bufs.num;

    st = &ctx->v3_parse->headers;
    b = &u->buffer;

    for ( ;; ) {

       p = b->pos;

       rc = njt_http_v3_parse_headers(c, st, b);
       if (rc > 0) {

            if (h3c) {
                njt_quic_reset_stream(c, rc);
            }
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "upstream sent invalid header rc:%i", rc);
            return NJT_HTTP_UPSTREAM_INVALID_HEADER;
        }

        if (rc == NJT_ERROR) {
            return NJT_ERROR;
        }

        if (h3c) {
            h3c->total_bytes += b->pos - p;
        }

        if (rc == NJT_BUSY) {
            /* HTTP/3 blocked */
            return NJT_AGAIN;
        }

        if (rc == NJT_AGAIN) {
            return NJT_AGAIN;
        }

        /* rc == NJT_OK || rc == njt_DONE */

        if (h3c) {
            h3c->payload_bytes += njt_http_v3_encode_field_l(NULL,
                                                   &st->field_rep.field.name,
                                                   &st->field_rep.field.value);
        }

        if (njt_http_v3_proxy_process_header(r, &st->field_rep.field.name,
                                             &st->field_rep.field.value)
            != NJT_OK)
        {
            return NJT_ERROR;
        }

        if (rc == NJT_DONE) {
            return njt_http_v3_proxy_headers_done(r);
        }
    }

    return NJT_OK;
}


static void
njt_http_v3_proxy_abort_request(njt_http_request_t *r)
{
    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http v3 proxy request");
}


static void
njt_http_v3_proxy_finalize_request(njt_http_request_t *r, njt_int_t rc)
{
    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http v3 proxy request");
}


static njt_int_t
njt_http_v3_proxy_process_header(njt_http_request_t *r, njt_str_t *name,
    njt_str_t *value)
{
    size_t                          len;
    njt_table_elt_t                *h;
    njt_http_upstream_t            *u;
    njt_http_proxy_ctx_t           *ctx;
    njt_http_upstream_header_t     *hh;
    njt_http_upstream_main_conf_t  *umcf;

    /* based on njt_http_v3_process_header() */

    umcf = njt_http_get_module_main_conf(r, njt_http_upstream_module);
    u = r->upstream;

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    len = name->len + value->len;

    if (len > ctx->v3_parse->header_limit) {
        njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                      "client sent too large header");
        return NJT_ERROR;
    }

    ctx->v3_parse->header_limit -= len;

    if (name->len && name->data[0] == ':') {
        return njt_http_v3_proxy_process_pseudo_header(r, name, value);
    }

    h = njt_list_push(&u->headers_in.headers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    /*
     * HTTP/3 parsing used peer->connection.pool, which might be destroyed,
     * at the moment when r->headers_out are used;
     * thus allocate from r->pool and copy header name/value
     */
    h->key.len = name->len;
    h->key.data = njt_pnalloc(r->pool, name->len + 1);
    if (h->key.data == NULL) {
        return NJT_ERROR;
    }
    njt_memcpy(h->key.data, name->data, name->len);
    h->key.data[h->key.len] = 0;

    h->value.len = value->len;
    h->value.data = njt_pnalloc(r->pool, value->len + 1);
    if (h->value.data == NULL) {
        return NJT_ERROR;
    }
    njt_memcpy(h->value.data, value->data, value->len);
    h->value.data[h->value.len] = 0;

    h->lowcase_key = h->key.data;
    h->hash = njt_hash_key(h->key.data, h->key.len);

    hh = njt_hash_find(&umcf->headers_in_hash, h->hash,
                       h->lowcase_key, h->key.len);

    if (hh && hh->handler(r, h, hh->offset) != NJT_OK) {
        return NJT_ERROR;
    }

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http3 header: \"%V: %V\"", name, value);

    return NJT_OK;
}


static njt_int_t
njt_http_v3_proxy_headers_done(njt_http_request_t *r)
{
    njt_table_elt_t         *h;
    njt_connection_t        *c;
    njt_http_proxy_ctx_t    *ctx;
    njt_http_upstream_t     *u;

    /*
     * based on NJT_HTTP_PARSE_HEADER_DONE in njt_http_proxy_process_header()
     * and njt_http_v3_process_request_header()
     */

    u = r->upstream;
    c = u->peer.connection;

    /*
     * if no "Server" and "Date" in header line,
     * then add the special empty headers
     */

    if (u->headers_in.server == NULL) {
        h = njt_list_push(&u->headers_in.headers);
        if (h == NULL) {
            return NJT_ERROR;
        }

        h->hash = njt_hash(njt_hash(njt_hash(njt_hash(
                                    njt_hash('s', 'e'), 'r'), 'v'), 'e'), 'r');

        njt_str_set(&h->key, "Server");
        njt_str_null(&h->value);
        h->lowcase_key = (u_char *) "server";
        h->next = NULL;
    }

    if (u->headers_in.date == NULL) {
        h = njt_list_push(&u->headers_in.headers);
        if (h == NULL) {
            return NJT_ERROR;
        }

        h->hash = njt_hash(njt_hash(njt_hash('d', 'a'), 't'), 'e');

        njt_str_set(&h->key, "Date");
        njt_str_null(&h->value);
        h->lowcase_key = (u_char *) "date";
        h->next = NULL;
    }

    if (njt_http_v3_proxy_construct_cookie_header(r) != NJT_OK) {
        return NJT_ERROR;
    }

    if (u->headers_in.content_length) {
        u->headers_in.content_length_n =
                            njt_atoof(u->headers_in.content_length->value.data,
                                      u->headers_in.content_length->value.len);

        if (u->headers_in.content_length_n == NJT_ERROR) {
            njt_log_error(NJT_LOG_INFO, c->log, 0,
                          "client sent invalid \"Content-Length\" header");
            return NJT_ERROR;
        }

    } else {
        u->headers_in.content_length_n = -1;
    }

    /*
     * set u->keepalive if response has no body; this allows to keep
     * connections alive in case of r->header_only or X-Accel-Redirect
     */

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    if (u->headers_in.status_n == NJT_HTTP_NO_CONTENT
        || u->headers_in.status_n == NJT_HTTP_NOT_MODIFIED
        || ctx->head
        || (!u->headers_in.chunked
            && u->headers_in.content_length_n == 0))
    {
        u->keepalive = !u->headers_in.connection_close;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_v3_proxy_process_pseudo_header(njt_http_request_t *r, njt_str_t *name,
    njt_str_t *value)
{
    njt_int_t             status;
    njt_str_t            *status_line;
    njt_http_upstream_t  *u;

    /* based on njt_http_v3_process_pseudo_header() */

    /*
     * RFC 9114, 4.3.2
     *
     * For responses, a single ":status" pseudo-header field
     * is defined that carries the HTTP status code;
     */

    u = r->upstream;

    if (name->len == 7 && njt_strncmp(name->data, ":status", 7) == 0) {

        if (u->state && u->state->status
#if (NJT_HTTP_CACHE)
            && !r->cached
#endif
        ) {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "upstream sent duplicate \":status\" header");
            return NJT_ERROR;
        }

        if (value->len == 0) {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "upstream sent empty \":status\" header");
            return NJT_ERROR;
        }

        if (value->len < 3) {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                          "upstream sent too short \":status\" header");
            return NJT_ERROR;
        }

        status = njt_atoi(value->data, 3);

        if (status == NJT_ERROR) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "upstream sent invalid status \"%V\"", value);
            return NJT_ERROR;
        }

        if (u->state && u->state->status == 0) {
            u->state->status = status;
        }

        u->headers_in.status_n = status;

        status_line = njt_http_status_line(status);
        if (status_line) {
            u->headers_in.status_line = *status_line;
        }

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http v3 proxy status %ui \"%V\"",
                       u->headers_in.status_n, &u->headers_in.status_line);

        return NJT_OK;
    }

    njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                  "upstream sent unexpected pseudo-header \"%V\"", name);

    return NJT_ERROR;
}


static njt_int_t
njt_http_v3_proxy_input_filter_init(void *data)
{
    njt_http_request_t  *r = data;

    njt_http_upstream_t   *u;
    njt_http_proxy_ctx_t  *ctx;

    u = r->upstream;
    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    if (ctx == NULL) {
        return NJT_ERROR;
    }

    njt_log_debug4(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http v3 proxy filter init s:%ui h:%d c:%d l:%O",
                   u->headers_in.status_n, ctx->head, u->headers_in.chunked,
                   u->headers_in.content_length_n);

    /* as per RFC2616, 4.4 Message Length */

    /* HTTP/3 is 'chunked-like' by default, filter is already set */

    if (u->headers_in.status_n == NJT_HTTP_NO_CONTENT
        || u->headers_in.status_n == NJT_HTTP_NOT_MODIFIED
        || ctx->head)
    {
        /* 1xx, 204, and 304 and replies to HEAD requests */
        /* no 1xx since we don't send Expect and Upgrade */

        u->pipe->length = 0;
        u->length = 0;

    } else if (u->headers_in.content_length_n == 0) {
        /* empty body: special case as filter won't be called */

        u->pipe->length = 0;
        u->length = 0;

    } else {
        /* content length or connection close */

        u->pipe->length = u->headers_in.content_length_n;
        u->length = u->headers_in.content_length_n;
    }

    /* TODO: check flag handling in HTTP/3 */
    u->keepalive = 1;

    return NJT_OK;
}


/* reading non-buffered body from V3 upstream */
static njt_int_t
njt_http_v3_proxy_non_buffered_copy_filter(void *data, ssize_t bytes)
{
    njt_http_request_t  *r = data;

    size_t                     size, len;
    njt_int_t                  rc;
    njt_buf_t                 *b, *buf;
    njt_chain_t               *cl, **ll;
    njt_http_upstream_t       *u;
    njt_http_proxy_ctx_t      *ctx;
    njt_http_v3_parse_data_t  *st;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http v3 proxy non buffered copy filter");

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    if (ctx == NULL) {
        return NJT_ERROR;
    }

    u = r->upstream;
    buf = &u->buffer;

    buf->pos = buf->last;
    buf->last += bytes;

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    st = &ctx->v3_parse->body;

    while (buf->pos < buf->last) {

        if (st->length == 0) {

            rc = njt_http_v3_parse_data(r->connection, st, buf);

            njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "njt_http_v3_parse_data rc:%i st->length: %ui",
                           rc, st->length);

            if (rc == NJT_AGAIN) {
                break;
            }

            if (rc == NJT_ERROR || rc > 0) {
                return NJT_ERROR;
            }

            if (rc == NJT_DONE) {
                /* TODO: trailers */
                u->length = 0;
            }

            /* rc == NJT_OK */
            continue;
        }

        /* need to consume ctx->st.length bytes and then parse again */

        cl = njt_chain_get_free_buf(r->pool, &u->free_bufs);
        if (cl == NULL) {
            return NJT_ERROR;
        }

        *ll = cl;
        ll = &cl->next;

        b = cl->buf;

        b->start = buf->pos;
        b->pos = buf->pos;
        b->last = buf->last;
        b->end = buf->end;

        b->tag = u->output.tag;
        b->flush = 1;
        b->temporary = 1;

        size = buf->last - buf->pos;
        len = njt_min(size, st->length);

        buf->pos += len;
        st->length -= len;

        if (u->length != -1) {
            u->length -= len;
        }

        b->last = buf->pos;

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http v3 proxy out buf %p %z",
                       b->pos, b->last - b->pos);
    }

    if (u->length == 0) {
        u->keepalive = !u->headers_in.connection_close;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_v3_proxy_copy_filter(njt_event_pipe_t *p, njt_buf_t *buf)
{
    size_t                     size, len;
    njt_int_t                  rc;
    njt_buf_t                 *b, **prev;
    njt_chain_t               *cl;
    njt_http_upstream_t       *u;
    njt_http_request_t        *r;
    njt_http_proxy_ctx_t      *ctx;
    njt_http_v3_parse_data_t  *st;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, p->log, 0,
                   "http_v3_proxy_copy_filter");

    if (buf->pos == buf->last) {
        return NJT_OK;
    }

    if (p->upstream_done) {
        njt_log_debug0(NJT_LOG_DEBUG_HTTP, p->log, 0,
                       "http v3 proxy data after close");
        return NJT_OK;
    }

    if (p->length == 0) {
        njt_log_error(NJT_LOG_WARN, p->log, 0,
                      "upstream sent more data than specified in "
                      "\"Content-Length\" header");

        r = p->input_ctx;
        r->upstream->keepalive = 0;
        p->upstream_done = 1;

        return NJT_OK;
    }

    r = p->input_ctx;
    u = r->upstream;

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);
    if (ctx == NULL) {
        return NJT_ERROR;
    }

    st = &ctx->v3_parse->body;

    b = NULL;
    prev = &buf->shadow;

    while (buf->pos < buf->last) {

        if (st->length == 0) {
            rc = njt_http_v3_parse_data(r->connection, st, buf);

            njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "njt_http_v3_parse_data rc:%i st->length: %ui",
                           rc, st->length);

            if (rc == NJT_AGAIN) {
                break;
            }

            if (rc == NJT_ERROR || rc > 0) {
                return NJT_ERROR;
            }

            if (rc == NJT_DONE) {
                /* TODO: trailers */
                p->length = 0;
            }

            /* rc == NJT_OK */
            continue;
        }

        /* need to consume ctx->st.length bytes and then parse again */

        cl = njt_chain_get_free_buf(p->pool, &p->free);
        if (cl == NULL) {
            return NJT_ERROR;
        }

        b = cl->buf;

        njt_memcpy(b, buf, sizeof(njt_buf_t));

        b->tag = p->tag;
        b->recycled = 1;
        b->temporary = 1;

        *prev = b;
        prev = &b->shadow;

        if (p->in) {
            *p->last_in = cl;

        } else {
            p->in = cl;
        }

        p->last_in = &cl->next;

        size = buf->last - buf->pos;

        len = njt_min(size, st->length);

        buf->pos += len;
        b->last = buf->pos;

        st->length -= len;
        ctx->data_recvd += len;

        if (p->length != -1) {
            p->length -= len;
        }

        njt_log_debug2(NJT_LOG_DEBUG_EVENT, p->log, 0,
                       "http v3 proxy input buf #%d %p", b->num, b->pos);
    }

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, p->log, 0,
                   "http v3 proxy copy filter st length %ui pipe len:%O",
                   st->length, p->length);

    if (p->length == 0) {
        u->keepalive = !u->headers_in.connection_close;
    }

    if (b) {
        b->shadow = buf;
        b->last_shadow = 1;

        njt_log_debug2(NJT_LOG_DEBUG_EVENT, p->log, 0,
                       "input buf %p %z", b->pos, b->last - b->pos);
        return NJT_OK;
    }

    /* there is no data record in the buf, add it to free chain */

    if (njt_event_pipe_add_free_buf(p, buf) != NJT_OK) {
        return NJT_ERROR;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_v3_proxy_construct_cookie_header(njt_http_request_t *r)
{
    u_char                         *buf, *p, *end;
    size_t                          len;
    njt_str_t                      *vals;
    njt_uint_t                      i;
    njt_array_t                    *cookies;
    njt_table_elt_t                *h;
    njt_http_header_t              *hh;
    njt_http_upstream_t            *u;
    njt_http_proxy_ctx_t           *ctx;
    njt_http_upstream_main_conf_t  *umcf;

    static njt_str_t cookie = njt_string("cookie");

    ctx = njt_http_get_module_ctx(r, njt_http_proxy_module);

    u = r->upstream;
    cookies = ctx->v3_parse->cookies;

    if (cookies == NULL) {
        return NJT_OK;
    }

    vals = cookies->elts;

    i = 0;
    len = 0;

    do {
        len += vals[i].len + 2;
    } while (++i != cookies->nelts);

    len -= 2;

    buf = njt_pnalloc(r->pool, len + 1);
    if (buf == NULL) {
        return NJT_ERROR;
    }

    p = buf;
    end = buf + len;

    for (i = 0; /* void */ ; i++) {

        p = njt_cpymem(p, vals[i].data, vals[i].len);

        if (p == end) {
            *p = '\0';
            break;
        }

        *p++ = ';'; *p++ = ' ';
    }

    h = njt_list_push(&u->headers_in.headers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    h->hash = njt_hash(njt_hash(njt_hash(njt_hash(
                                    njt_hash('c', 'o'), 'o'), 'k'), 'i'), 'e');

    h->key.len = cookie.len;
    h->key.data = cookie.data;

    h->value.len = len;
    h->value.data = buf;

    h->lowcase_key = cookie.data;

    umcf = njt_http_get_module_main_conf(r, njt_http_upstream_module);

    hh = njt_hash_find(&umcf->headers_in_hash, h->hash,
                       h->lowcase_key, h->key.len);

    if (hh == NULL) {
        return NJT_ERROR;
    }

    if (hh->handler(r, h, hh->offset) != NJT_OK) {
        return NJT_ERROR;
    }

    return NJT_OK;
}

#endif
