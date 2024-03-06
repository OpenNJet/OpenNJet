
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


typedef struct {
    njt_array_t               *flushes;
    njt_array_t               *lengths;
    njt_array_t               *values;
    njt_hash_t                 hash;
} njt_http_grpc_headers_t;


typedef struct {
    njt_http_upstream_conf_t   upstream;

    njt_http_grpc_headers_t    headers;
    njt_array_t               *headers_source;

    njt_str_t                  host;
    njt_uint_t                 host_set;

    njt_array_t               *grpc_lengths;
    njt_array_t               *grpc_values;

#if (NJT_HTTP_SSL)
    njt_uint_t                 ssl;
    njt_uint_t                 ssl_protocols;
    njt_str_t                  ssl_ciphers;
    njt_uint_t                 ssl_verify_depth;
    njt_str_t                  ssl_trusted_certificate;
    njt_str_t                  ssl_crl;
    njt_array_t               *ssl_conf_commands;
#endif
} njt_http_grpc_loc_conf_t;


typedef enum {
    njt_http_grpc_st_start = 0,
    njt_http_grpc_st_length_2,
    njt_http_grpc_st_length_3,
    njt_http_grpc_st_type,
    njt_http_grpc_st_flags,
    njt_http_grpc_st_stream_id,
    njt_http_grpc_st_stream_id_2,
    njt_http_grpc_st_stream_id_3,
    njt_http_grpc_st_stream_id_4,
    njt_http_grpc_st_payload,
    njt_http_grpc_st_padding
} njt_http_grpc_state_e;


typedef struct {
    size_t                     init_window;
    size_t                     send_window;
    size_t                     recv_window;
    njt_uint_t                 last_stream_id;
} njt_http_grpc_conn_t;


typedef struct {
    njt_http_grpc_state_e      state;
    njt_uint_t                 frame_state;
    njt_uint_t                 fragment_state;

    njt_chain_t               *in;
    njt_chain_t               *out;
    njt_chain_t               *free;
    njt_chain_t               *busy;

    njt_http_grpc_conn_t      *connection;

    njt_uint_t                 id;

    njt_uint_t                 pings;
    njt_uint_t                 settings;

    off_t                      length;

    ssize_t                    send_window;
    size_t                     recv_window;

    size_t                     rest;
    njt_uint_t                 stream_id;
    u_char                     type;
    u_char                     flags;
    u_char                     padding;

    njt_uint_t                 error;
    njt_uint_t                 window_update;

    njt_uint_t                 setting_id;
    njt_uint_t                 setting_value;

    u_char                     ping_data[8];

    njt_uint_t                 index;
    njt_str_t                  name;
    njt_str_t                  value;

    u_char                    *field_end;
    size_t                     field_length;
    size_t                     field_rest;
    u_char                     field_state;

    unsigned                   literal:1;
    unsigned                   field_huffman:1;

    unsigned                   header_sent:1;
    unsigned                   output_closed:1;
    unsigned                   output_blocked:1;
    unsigned                   parsing_headers:1;
    unsigned                   end_stream:1;
    unsigned                   done:1;
    unsigned                   status:1;
    unsigned                   rst:1;
    unsigned                   goaway:1;

    njt_http_request_t        *request;

    njt_str_t                  host;
} njt_http_grpc_ctx_t;


typedef struct {
    u_char                     length_0;
    u_char                     length_1;
    u_char                     length_2;
    u_char                     type;
    u_char                     flags;
    u_char                     stream_id_0;
    u_char                     stream_id_1;
    u_char                     stream_id_2;
    u_char                     stream_id_3;
} njt_http_grpc_frame_t;


static njt_int_t njt_http_grpc_eval(njt_http_request_t *r,
    njt_http_grpc_ctx_t *ctx, njt_http_grpc_loc_conf_t *glcf);
 njt_int_t njt_http_grpc_create_request(njt_http_request_t *r);
static njt_int_t njt_http_grpc_reinit_request(njt_http_request_t *r);
njt_int_t njt_http_grpc_body_output_filter(void *data, njt_chain_t *in);
static njt_int_t njt_http_grpc_process_header(njt_http_request_t *r);
static njt_int_t njt_http_grpc_filter_init(void *data);
static njt_int_t njt_http_grpc_filter(void *data, ssize_t bytes);

static njt_int_t njt_http_grpc_parse_frame(njt_http_request_t *r,
    njt_http_grpc_ctx_t *ctx, njt_buf_t *b);
static njt_int_t njt_http_grpc_parse_header(njt_http_request_t *r,
    njt_http_grpc_ctx_t *ctx, njt_buf_t *b);
static njt_int_t njt_http_grpc_parse_fragment(njt_http_request_t *r,
    njt_http_grpc_ctx_t *ctx, njt_buf_t *b);
static njt_int_t njt_http_grpc_validate_header_name(njt_http_request_t *r,
    njt_str_t *s);
static njt_int_t njt_http_grpc_validate_header_value(njt_http_request_t *r,
    njt_str_t *s);
static njt_int_t njt_http_grpc_parse_rst_stream(njt_http_request_t *r,
    njt_http_grpc_ctx_t *ctx, njt_buf_t *b);
static njt_int_t njt_http_grpc_parse_goaway(njt_http_request_t *r,
    njt_http_grpc_ctx_t *ctx, njt_buf_t *b);
static njt_int_t njt_http_grpc_parse_window_update(njt_http_request_t *r,
    njt_http_grpc_ctx_t *ctx, njt_buf_t *b);
static njt_int_t njt_http_grpc_parse_settings(njt_http_request_t *r,
    njt_http_grpc_ctx_t *ctx, njt_buf_t *b);
static njt_int_t njt_http_grpc_parse_ping(njt_http_request_t *r,
    njt_http_grpc_ctx_t *ctx, njt_buf_t *b);

static njt_int_t njt_http_grpc_send_settings_ack(njt_http_request_t *r,
    njt_http_grpc_ctx_t *ctx);
static njt_int_t njt_http_grpc_send_ping_ack(njt_http_request_t *r,
    njt_http_grpc_ctx_t *ctx);
static njt_int_t njt_http_grpc_send_window_update(njt_http_request_t *r,
    njt_http_grpc_ctx_t *ctx);

static njt_chain_t *njt_http_grpc_get_buf(njt_http_request_t *r,
    njt_http_grpc_ctx_t *ctx);
static njt_http_grpc_ctx_t *njt_http_grpc_get_ctx(njt_http_request_t *r);
static njt_int_t njt_http_grpc_get_connection_data(njt_http_request_t *r,
    njt_http_grpc_ctx_t *ctx, njt_peer_connection_t *pc);
static void njt_http_grpc_cleanup(void *data);

static void njt_http_grpc_abort_request(njt_http_request_t *r);
static void njt_http_grpc_finalize_request(njt_http_request_t *r,
    njt_int_t rc);

static njt_int_t njt_http_grpc_internal_trailers_variable(
    njt_http_request_t *r, njt_http_variable_value_t *v, uintptr_t data);

static njt_int_t njt_http_grpc_add_variables(njt_conf_t *cf);
static void *njt_http_grpc_create_loc_conf(njt_conf_t *cf);
static char *njt_http_grpc_merge_loc_conf(njt_conf_t *cf,
    void *parent, void *child);
static njt_int_t njt_http_grpc_init_headers(njt_conf_t *cf,
    njt_http_grpc_loc_conf_t *conf, njt_http_grpc_headers_t *headers,
    njt_keyval_t *default_headers);

static char *njt_http_grpc_pass(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);

#if (NJT_HTTP_SSL)
static char *njt_http_grpc_ssl_password_file(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);
static char *njt_http_grpc_ssl_conf_command_check(njt_conf_t *cf, void *post,
    void *data);
static njt_int_t njt_http_grpc_merge_ssl(njt_conf_t *cf,
    njt_http_grpc_loc_conf_t *conf, njt_http_grpc_loc_conf_t *prev);
static njt_int_t njt_http_grpc_set_ssl(njt_conf_t *cf,
    njt_http_grpc_loc_conf_t *glcf);
#endif


static njt_conf_bitmask_t  njt_http_grpc_next_upstream_masks[] = {
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
    { njt_string("off"), NJT_HTTP_UPSTREAM_FT_OFF },
    { njt_null_string, 0 }
};


#if (NJT_HTTP_SSL)

static njt_conf_bitmask_t  njt_http_grpc_ssl_protocols[] = {
    { njt_string("SSLv2"), NJT_SSL_SSLv2 },
    { njt_string("SSLv3"), NJT_SSL_SSLv3 },
    { njt_string("TLSv1"), NJT_SSL_TLSv1 },
    { njt_string("TLSv1.1"), NJT_SSL_TLSv1_1 },
    { njt_string("TLSv1.2"), NJT_SSL_TLSv1_2 },
    { njt_string("TLSv1.3"), NJT_SSL_TLSv1_3 },
    { njt_null_string, 0 }
};

static njt_conf_post_t  njt_http_grpc_ssl_conf_command_post =
    { njt_http_grpc_ssl_conf_command_check };

#endif


static njt_command_t  njt_http_grpc_commands[] = {

    { njt_string("grpc_pass"),
      NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE1,
      njt_http_grpc_pass,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("grpc_bind"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE12,
      njt_http_upstream_bind_set_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_grpc_loc_conf_t, upstream.local),
      NULL },

    { njt_string("grpc_socket_keepalive"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_grpc_loc_conf_t, upstream.socket_keepalive),
      NULL },

    { njt_string("grpc_connect_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_grpc_loc_conf_t, upstream.connect_timeout),
      NULL },

    { njt_string("grpc_send_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_grpc_loc_conf_t, upstream.send_timeout),
      NULL },

    { njt_string("grpc_intercept_errors"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_grpc_loc_conf_t, upstream.intercept_errors),
      NULL },

    { njt_string("grpc_buffer_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_grpc_loc_conf_t, upstream.buffer_size),
      NULL },

    { njt_string("grpc_read_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_grpc_loc_conf_t, upstream.read_timeout),
      NULL },

    { njt_string("grpc_next_upstream"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_grpc_loc_conf_t, upstream.next_upstream),
      &njt_http_grpc_next_upstream_masks },

    { njt_string("grpc_next_upstream_tries"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_grpc_loc_conf_t, upstream.next_upstream_tries),
      NULL },

    { njt_string("grpc_next_upstream_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_grpc_loc_conf_t, upstream.next_upstream_timeout),
      NULL },

    { njt_string("grpc_set_header"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE2,
      njt_conf_set_keyval_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_grpc_loc_conf_t, headers_source),
      NULL },

    { njt_string("grpc_pass_header"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_array_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_grpc_loc_conf_t, upstream.pass_headers),
      NULL },

    { njt_string("grpc_hide_header"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_array_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_grpc_loc_conf_t, upstream.hide_headers),
      NULL },

    { njt_string("grpc_ignore_headers"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_grpc_loc_conf_t, upstream.ignore_headers),
      &njt_http_upstream_ignore_headers_masks },

#if (NJT_HTTP_SSL)

    { njt_string("grpc_ssl_session_reuse"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_grpc_loc_conf_t, upstream.ssl_session_reuse),
      NULL },

    { njt_string("grpc_ssl_protocols"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_grpc_loc_conf_t, ssl_protocols),
      &njt_http_grpc_ssl_protocols },

    { njt_string("grpc_ssl_ciphers"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_grpc_loc_conf_t, ssl_ciphers),
      NULL },

    { njt_string("grpc_ssl_name"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_set_complex_value_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_grpc_loc_conf_t, upstream.ssl_name),
      NULL },

    { njt_string("grpc_ssl_server_name"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_grpc_loc_conf_t, upstream.ssl_server_name),
      NULL },

    { njt_string("grpc_ssl_verify"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_grpc_loc_conf_t, upstream.ssl_verify),
      NULL },

    { njt_string("grpc_ssl_verify_depth"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_grpc_loc_conf_t, ssl_verify_depth),
      NULL },

    { njt_string("grpc_ssl_trusted_certificate"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_grpc_loc_conf_t, ssl_trusted_certificate),
      NULL },

    { njt_string("grpc_ssl_crl"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_grpc_loc_conf_t, ssl_crl),
      NULL },

    { njt_string("grpc_ssl_certificate"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_set_complex_value_zero_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_grpc_loc_conf_t, upstream.ssl_certificate),
      NULL },

    { njt_string("grpc_ssl_certificate_key"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_set_complex_value_zero_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_grpc_loc_conf_t, upstream.ssl_certificate_key),
      NULL },

    { njt_string("grpc_ssl_password_file"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_grpc_ssl_password_file,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("grpc_ssl_conf_command"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE2,
      njt_conf_set_keyval_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_grpc_loc_conf_t, ssl_conf_commands),
      &njt_http_grpc_ssl_conf_command_post },

#endif

      njt_null_command
};


static njt_http_module_t  njt_http_grpc_module_ctx = {
    njt_http_grpc_add_variables,           /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_grpc_create_loc_conf,         /* create location configuration */
    njt_http_grpc_merge_loc_conf           /* merge location configuration */
};


njt_module_t  njt_http_grpc_module = {
    NJT_MODULE_V1,
    &njt_http_grpc_module_ctx,             /* module context */
    njt_http_grpc_commands,                /* module directives */
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


static u_char  njt_http_grpc_connection_start[] =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"         /* connection preface */

    "\x00\x00\x12\x04\x00\x00\x00\x00\x00"     /* settings frame */
    "\x00\x01\x00\x00\x00\x00"                 /* header table size */
    "\x00\x02\x00\x00\x00\x00"                 /* disable push */
    "\x00\x04\x7f\xff\xff\xff"                 /* initial window */

    "\x00\x00\x04\x08\x00\x00\x00\x00\x00"     /* window update frame */
    "\x7f\xff\x00\x00";


static njt_keyval_t  njt_http_grpc_headers[] = {
    { njt_string("Content-Length"), njt_string("$content_length") },
    { njt_string("TE"), njt_string("$grpc_internal_trailers") },
    { njt_string("Host"), njt_string("") },
    { njt_string("Connection"), njt_string("") },
    { njt_string("Transfer-Encoding"), njt_string("") },
    { njt_string("Keep-Alive"), njt_string("") },
    { njt_string("Expect"), njt_string("") },
    { njt_string("Upgrade"), njt_string("") },
    { njt_null_string, njt_null_string }
};


static njt_str_t  njt_http_grpc_hide_headers[] = {
    njt_string("Date"),
    njt_string("Server"),
    njt_string("X-Accel-Expires"),
    njt_string("X-Accel-Redirect"),
    njt_string("X-Accel-Limit-Rate"),
    njt_string("X-Accel-Buffering"),
    njt_string("X-Accel-Charset"),
    njt_null_string
};


static njt_http_variable_t  njt_http_grpc_vars[] = {

    { njt_string("grpc_internal_trailers"), NULL,
      njt_http_grpc_internal_trailers_variable, 0,
      NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_NOHASH, 0, NJT_VAR_INIT_REF_COUNT },

      njt_http_null_variable
};


static njt_int_t
njt_http_grpc_handler(njt_http_request_t *r)
{
    njt_int_t                  rc;
    njt_http_upstream_t       *u;
    njt_http_grpc_ctx_t       *ctx;
    njt_http_grpc_loc_conf_t  *glcf;

    if (njt_http_upstream_create(r) != NJT_OK) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = njt_pcalloc(r->pool, sizeof(njt_http_grpc_ctx_t));
    if (ctx == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->request = r;

    njt_http_set_ctx(r, ctx, njt_http_grpc_module);

    glcf = njt_http_get_module_loc_conf(r, njt_http_grpc_module);

    u = r->upstream;

    if (glcf->grpc_lengths == NULL) {
        ctx->host = glcf->host;

#if (NJT_HTTP_SSL)
        u->ssl = glcf->ssl;

        if (u->ssl) {
            njt_str_set(&u->schema, "grpcs://");

        } else {
            njt_str_set(&u->schema, "grpc://");
        }
#else
        njt_str_set(&u->schema, "grpc://");
#endif

    } else {
        if (njt_http_grpc_eval(r, ctx, glcf) != NJT_OK) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    u->output.tag = (njt_buf_tag_t) &njt_http_grpc_module;

    u->conf = &glcf->upstream;

    u->create_request = njt_http_grpc_create_request;
    u->reinit_request = njt_http_grpc_reinit_request;
    u->process_header = njt_http_grpc_process_header;
    u->abort_request = njt_http_grpc_abort_request;
    u->finalize_request = njt_http_grpc_finalize_request;

    u->input_filter_init = njt_http_grpc_filter_init;
    u->input_filter = njt_http_grpc_filter;
    u->input_filter_ctx = ctx;

    r->request_body_no_buffering = 1;

    rc = njt_http_read_client_request_body(r, njt_http_upstream_init);

    if (rc >= NJT_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NJT_DONE;
}


static njt_int_t
njt_http_grpc_eval(njt_http_request_t *r, njt_http_grpc_ctx_t *ctx,
    njt_http_grpc_loc_conf_t *glcf)
{
    size_t                add;
    njt_url_t             url;
    njt_http_upstream_t  *u;

    njt_memzero(&url, sizeof(njt_url_t));

    if (njt_http_script_run(r, &url.url, glcf->grpc_lengths->elts, 0,
                            glcf->grpc_values->elts)
        == NULL)
    {
        return NJT_ERROR;
    }

    if (url.url.len > 7
        && njt_strncasecmp(url.url.data, (u_char *) "grpc://", 7) == 0)
    {
        add = 7;

    } else if (url.url.len > 8
               && njt_strncasecmp(url.url.data, (u_char *) "grpcs://", 8) == 0)
    {

#if (NJT_HTTP_SSL)
        add = 8;
        r->upstream->ssl = 1;
#else
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "grpcs protocol requires SSL support");
        return NJT_ERROR;
#endif

    } else {
        add = 0;
    }

    u = r->upstream;

    if (add) {
        u->schema.len = add;
        u->schema.data = url.url.data;

        url.url.data += add;
        url.url.len -= add;

    } else {
        njt_str_set(&u->schema, "grpc://");
    }

    url.no_resolve = 1;

    if (njt_parse_url(r->pool, &url) != NJT_OK) {
        if (url.err) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "%s in upstream \"%V\"", url.err, &url.url);
        }

        return NJT_ERROR;
    }

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
    u->resolved->port = url.port;
    u->resolved->no_port = url.no_port;

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

    return NJT_OK;
}


 njt_int_t
njt_http_grpc_create_request(njt_http_request_t *r)
{
    u_char                       *p, *tmp, *key_tmp, *val_tmp, *headers_frame;
    size_t                        len, tmp_len, key_len, val_len, uri_len;
    uintptr_t                     escape;
    njt_buf_t                    *b;
    njt_uint_t                    i, next;
    njt_chain_t                  *cl, *body;
    njt_list_part_t              *part;
    njt_table_elt_t              *header;
    njt_http_grpc_ctx_t          *ctx;
    njt_http_upstream_t          *u;
    njt_http_grpc_frame_t        *f;
    njt_http_script_code_pt       code;
    njt_http_grpc_loc_conf_t     *glcf;
    njt_http_script_engine_t      e, le;
    njt_http_script_len_code_pt   lcode;

    u = r->upstream;

    glcf = njt_http_get_module_loc_conf(r, njt_http_grpc_module);

    ctx = njt_http_get_module_ctx(r, njt_http_grpc_module);

    len = sizeof(njt_http_grpc_connection_start) - 1
          + sizeof(njt_http_grpc_frame_t);             /* headers frame */

    /* :method header */

    if (r->method == NJT_HTTP_GET || r->method == NJT_HTTP_POST) {
        len += 1;
        tmp_len = 0;

    } else {
        len += 1 + NJT_HTTP_V2_INT_OCTETS + r->method_name.len;
        tmp_len = r->method_name.len;
    }

    /* :scheme header */

    len += 1;

    /* :path header */

    if (r->valid_unparsed_uri) {
        escape = 0;
        uri_len = r->unparsed_uri.len;

    } else {
        escape = 2 * njt_escape_uri(NULL, r->uri.data, r->uri.len,
                                    NJT_ESCAPE_URI);
        uri_len = r->uri.len + escape + sizeof("?") - 1 + r->args.len;
    }

    len += 1 + NJT_HTTP_V2_INT_OCTETS + uri_len;

    if (tmp_len < uri_len) {
        tmp_len = uri_len;
    }

    /* :authority header */

    if (!glcf->host_set) {
        len += 1 + NJT_HTTP_V2_INT_OCTETS + ctx->host.len;

        if (tmp_len < ctx->host.len) {
            tmp_len = ctx->host.len;
        }
    }

    /* other headers */

    njt_http_script_flush_no_cacheable_variables(r, glcf->headers.flushes);
    njt_memzero(&le, sizeof(njt_http_script_engine_t));

    le.ip = glcf->headers.lengths->elts;
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

        len += 1 + NJT_HTTP_V2_INT_OCTETS + key_len
                 + NJT_HTTP_V2_INT_OCTETS + val_len;

        if (tmp_len < key_len) {
            tmp_len = key_len;
        }

        if (tmp_len < val_len) {
            tmp_len = val_len;
        }
    }

    if (glcf->upstream.pass_request_headers) {
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

            if (njt_hash_find(&glcf->headers.hash, header[i].hash,
                              header[i].lowcase_key, header[i].key.len))
            {
                continue;
            }

            len += 1 + NJT_HTTP_V2_INT_OCTETS + header[i].key.len
                     + NJT_HTTP_V2_INT_OCTETS + header[i].value.len;

            if (tmp_len < header[i].key.len) {
                tmp_len = header[i].key.len;
            }

            if (tmp_len < header[i].value.len) {
                tmp_len = header[i].value.len;
            }
        }
    }

    /* continuation frames */

    len += sizeof(njt_http_grpc_frame_t)
           * (len / NJT_HTTP_V2_DEFAULT_FRAME_SIZE);


    b = njt_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NJT_ERROR;
    }

    cl = njt_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NJT_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    tmp = njt_palloc(r->pool, tmp_len * 3);
    if (tmp == NULL) {
        return NJT_ERROR;
    }

    key_tmp = tmp + tmp_len;
    val_tmp = tmp + 2 * tmp_len;

    /* connection preface */

    b->last = njt_copy(b->last, njt_http_grpc_connection_start,
                       sizeof(njt_http_grpc_connection_start) - 1);

    /* headers frame */

    headers_frame = b->last;

    f = (njt_http_grpc_frame_t *) b->last;
    b->last += sizeof(njt_http_grpc_frame_t);

    f->length_0 = 0;
    f->length_1 = 0;
    f->length_2 = 0;
    f->type = NJT_HTTP_V2_HEADERS_FRAME;
    f->flags = 0;
    f->stream_id_0 = 0;
    f->stream_id_1 = 0;
    f->stream_id_2 = 0;
    f->stream_id_3 = 1;

    if (r->method == NJT_HTTP_GET) {
        *b->last++ = njt_http_v2_indexed(NJT_HTTP_V2_METHOD_GET_INDEX);

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":method: GET\"");

    } else if (r->method == NJT_HTTP_POST) {
        *b->last++ = njt_http_v2_indexed(NJT_HTTP_V2_METHOD_POST_INDEX);

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":method: POST\"");

    } else {
        *b->last++ = njt_http_v2_inc_indexed(NJT_HTTP_V2_METHOD_INDEX);
        b->last = njt_http_v2_write_value(b->last, r->method_name.data,
                                          r->method_name.len, tmp);

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":method: %V\"", &r->method_name);
    }

#if (NJT_HTTP_SSL)
    if (u->ssl) {
        *b->last++ = njt_http_v2_indexed(NJT_HTTP_V2_SCHEME_HTTPS_INDEX);

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":scheme: https\"");
    } else
#endif
    {
        *b->last++ = njt_http_v2_indexed(NJT_HTTP_V2_SCHEME_HTTP_INDEX);

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":scheme: http\"");
    }

    if (r->valid_unparsed_uri) {

        if (r->unparsed_uri.len == 1 && r->unparsed_uri.data[0] == '/') {
            *b->last++ = njt_http_v2_indexed(NJT_HTTP_V2_PATH_ROOT_INDEX);

        } else {
            *b->last++ = njt_http_v2_inc_indexed(NJT_HTTP_V2_PATH_INDEX);
            b->last = njt_http_v2_write_value(b->last, r->unparsed_uri.data,
                                              r->unparsed_uri.len, tmp);
        }

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":path: %V\"", &r->unparsed_uri);

    } else if (escape || r->args.len > 0) {
        p = val_tmp;

        if (escape) {
            p = (u_char *) njt_escape_uri(p, r->uri.data, r->uri.len,
                                          NJT_ESCAPE_URI);

        } else {
            p = njt_copy(p, r->uri.data, r->uri.len);
        }

        if (r->args.len > 0) {
            *p++ = '?';
            p = njt_copy(p, r->args.data, r->args.len);
        }

        *b->last++ = njt_http_v2_inc_indexed(NJT_HTTP_V2_PATH_INDEX);
        b->last = njt_http_v2_write_value(b->last, val_tmp, p - val_tmp, tmp);

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":path: %*s\"", p - val_tmp, val_tmp);

    } else {
        *b->last++ = njt_http_v2_inc_indexed(NJT_HTTP_V2_PATH_INDEX);
        b->last = njt_http_v2_write_value(b->last, r->uri.data,
                                          r->uri.len, tmp);

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":path: %V\"", &r->uri);
    }

    if (!glcf->host_set) {
        *b->last++ = njt_http_v2_inc_indexed(NJT_HTTP_V2_AUTHORITY_INDEX);
        b->last = njt_http_v2_write_value(b->last, ctx->host.data,
                                          ctx->host.len, tmp);

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header: \":authority: %V\"", &ctx->host);
    }

    njt_memzero(&e, sizeof(njt_http_script_engine_t));

    e.ip = glcf->headers.values->elts;
    e.request = r;
    e.flushed = 1;

    le.ip = glcf->headers.lengths->elts;

    while (*(uintptr_t *) le.ip) {

        lcode = *(njt_http_script_len_code_pt *) le.ip;
        key_len = lcode(&le);

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

        *b->last++ = 0;

        e.pos = key_tmp;

        code = *(njt_http_script_code_pt *) e.ip;
        code((njt_http_script_engine_t *) &e);

        b->last = njt_http_v2_write_name(b->last, key_tmp, key_len, tmp);

        e.pos = val_tmp;

        while (*(uintptr_t *) e.ip) {
            code = *(njt_http_script_code_pt *) e.ip;
            code((njt_http_script_engine_t *) &e);
        }
        e.ip += sizeof(uintptr_t);

        b->last = njt_http_v2_write_value(b->last, val_tmp, val_len, tmp);

#if (NJT_DEBUG)
        if (r->connection->log->log_level & NJT_LOG_DEBUG_HTTP) {
            njt_strlow(key_tmp, key_tmp, key_len);

            njt_log_debug4(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc header: \"%*s: %*s\"",
                           key_len, key_tmp, val_len, val_tmp);
        }
#endif
    }

    if (glcf->upstream.pass_request_headers) {
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

            if (njt_hash_find(&glcf->headers.hash, header[i].hash,
                              header[i].lowcase_key, header[i].key.len))
            {
                continue;
            }

            *b->last++ = 0;

            b->last = njt_http_v2_write_name(b->last, header[i].key.data,
                                             header[i].key.len, tmp);

            b->last = njt_http_v2_write_value(b->last, header[i].value.data,
                                              header[i].value.len, tmp);

#if (NJT_DEBUG)
            if (r->connection->log->log_level & NJT_LOG_DEBUG_HTTP) {
                njt_strlow(tmp, header[i].key.data, header[i].key.len);

                njt_log_debug3(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "grpc header: \"%*s: %V\"",
                               header[i].key.len, tmp, &header[i].value);
            }
#endif
        }
    }

    /* update headers frame length */

    len = b->last - headers_frame - sizeof(njt_http_grpc_frame_t);

    if (len > NJT_HTTP_V2_DEFAULT_FRAME_SIZE) {
        len = NJT_HTTP_V2_DEFAULT_FRAME_SIZE;
        next = 1;

    } else {
        next = 0;
    }

    f = (njt_http_grpc_frame_t *) headers_frame;

    f->length_0 = (u_char) ((len >> 16) & 0xff);
    f->length_1 = (u_char) ((len >> 8) & 0xff);
    f->length_2 = (u_char) (len & 0xff);

    /* create additional continuation frames */

    p = headers_frame;

    while (next) {
        p += sizeof(njt_http_grpc_frame_t) + NJT_HTTP_V2_DEFAULT_FRAME_SIZE;
        len = b->last - p;

        njt_memmove(p + sizeof(njt_http_grpc_frame_t), p, len);
        b->last += sizeof(njt_http_grpc_frame_t);

        if (len > NJT_HTTP_V2_DEFAULT_FRAME_SIZE) {
            len = NJT_HTTP_V2_DEFAULT_FRAME_SIZE;
            next = 1;

        } else {
            next = 0;
        }

        f = (njt_http_grpc_frame_t *) p;

        f->length_0 = (u_char) ((len >> 16) & 0xff);
        f->length_1 = (u_char) ((len >> 8) & 0xff);
        f->length_2 = (u_char) (len & 0xff);
        f->type = NJT_HTTP_V2_CONTINUATION_FRAME;
        f->flags = 0;
        f->stream_id_0 = 0;
        f->stream_id_1 = 0;
        f->stream_id_2 = 0;
        f->stream_id_3 = 1;
    }

    f->flags |= NJT_HTTP_V2_END_HEADERS_FLAG;

    njt_log_debug4(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc header: %*xs%s, len: %uz",
                   (size_t) njt_min(b->last - b->pos, 256), b->pos,
                   b->last - b->pos > 256 ? "..." : "",
                   b->last - b->pos);

    if (r->request_body_no_buffering) {

        u->request_bufs = cl;

    } else {

        body = u->request_bufs;
        u->request_bufs = cl;

        if (body == NULL) {
            f = (njt_http_grpc_frame_t *) headers_frame;
            f->flags |= NJT_HTTP_V2_END_STREAM_FLAG;
        }

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

        b->last_buf = 1;
    }

    u->output.output_filter = njt_http_grpc_body_output_filter;
    u->output.filter_ctx = r;

    b->flush = 1;
    cl->next = NULL;

    return NJT_OK;
}


static njt_int_t
njt_http_grpc_reinit_request(njt_http_request_t *r)
{
    njt_http_grpc_ctx_t  *ctx;

    ctx = njt_http_get_module_ctx(r, njt_http_grpc_module);

    if (ctx == NULL) {
        return NJT_OK;
    }

    ctx->state = 0;
    ctx->header_sent = 0;
    ctx->output_closed = 0;
    ctx->output_blocked = 0;
    ctx->parsing_headers = 0;
    ctx->end_stream = 0;
    ctx->done = 0;
    ctx->status = 0;
    ctx->rst = 0;
    ctx->goaway = 0;
    ctx->connection = NULL;

    return NJT_OK;
}


 njt_int_t
njt_http_grpc_body_output_filter(void *data, njt_chain_t *in)
{
    njt_http_request_t  *r = data;

    off_t                   file_pos;
    u_char                 *p, *pos, *start;
    size_t                  len, limit;
    njt_buf_t              *b;
    njt_int_t               rc;
    njt_uint_t              next, last;
    njt_chain_t            *cl, *out, **ll;
    njt_http_upstream_t    *u;
    njt_http_grpc_ctx_t    *ctx;
    njt_http_grpc_frame_t  *f;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc output filter");

    ctx = njt_http_grpc_get_ctx(r);

    if (ctx == NULL) {
        return NJT_ERROR;
    }

    if (in) {
        if (njt_chain_add_copy(r->pool, &ctx->in, in) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    out = NULL;
    ll = &out;

    if (!ctx->header_sent) {
        /* first buffer contains headers */

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc output header");

        ctx->header_sent = 1;

        if (ctx->id != 1) {
            /*
             * keepalive connection: skip connection preface,
             * update stream identifiers
             */

            b = ctx->in->buf;
            b->pos += sizeof(njt_http_grpc_connection_start) - 1;

            p = b->pos;

            while (p < b->last) {
                f = (njt_http_grpc_frame_t *) p;
                p += sizeof(njt_http_grpc_frame_t);

                f->stream_id_0 = (u_char) ((ctx->id >> 24) & 0xff);
                f->stream_id_1 = (u_char) ((ctx->id >> 16) & 0xff);
                f->stream_id_2 = (u_char) ((ctx->id >> 8) & 0xff);
                f->stream_id_3 = (u_char) (ctx->id & 0xff);

                p += (f->length_0 << 16) + (f->length_1 << 8) + f->length_2;
            }
        }

        if (ctx->in->buf->last_buf) {
            ctx->output_closed = 1;
        }

        *ll = ctx->in;
        ll = &ctx->in->next;

        ctx->in = ctx->in->next;
    }

    if (ctx->out) {
        /* queued control frames */

        *ll = ctx->out;

        for (cl = ctx->out, ll = &cl->next; cl; cl = cl->next) {
            ll = &cl->next;
        }

        ctx->out = NULL;
    }

    f = NULL;
    last = 0;

    limit = njt_max(0, ctx->send_window);

    if (limit > ctx->connection->send_window) {
        limit = ctx->connection->send_window;
    }

    njt_log_debug3(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc output limit: %uz w:%z:%uz",
                   limit, ctx->send_window, ctx->connection->send_window);

#if (NJT_SUPPRESS_WARN)
    file_pos = 0;
    pos = NULL;
    cl = NULL;
#endif

    in = ctx->in;

    while (in && limit > 0) {

        njt_log_debug7(NJT_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "grpc output in  l:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       in->buf->last_buf,
                       in->buf->in_file,
                       in->buf->start, in->buf->pos,
                       in->buf->last - in->buf->pos,
                       in->buf->file_pos,
                       in->buf->file_last - in->buf->file_pos);

        if (njt_buf_special(in->buf)) {
            goto next;
        }

        if (in->buf->in_file) {
            file_pos = in->buf->file_pos;

        } else {
            pos = in->buf->pos;
        }

        next = 0;

        do {

            cl = njt_http_grpc_get_buf(r, ctx);
            if (cl == NULL) {
                return NJT_ERROR;
            }

            b = cl->buf;

            f = (njt_http_grpc_frame_t *) b->last;
            b->last += sizeof(njt_http_grpc_frame_t);

            *ll = cl;
            ll = &cl->next;

            cl = njt_chain_get_free_buf(r->pool, &ctx->free);
            if (cl == NULL) {
                return NJT_ERROR;
            }

            b = cl->buf;
            start = b->start;

            njt_memcpy(b, in->buf, sizeof(njt_buf_t));

            /*
             * restore b->start to preserve memory allocated in the buffer,
             * to reuse it later for headers and control frames
             */

            b->start = start;

            if (in->buf->in_file) {
                b->file_pos = file_pos;
                file_pos += njt_min(NJT_HTTP_V2_DEFAULT_FRAME_SIZE, limit);

                if (file_pos >= in->buf->file_last) {
                    file_pos = in->buf->file_last;
                    next = 1;
                }

                b->file_last = file_pos;
                len = (njt_uint_t) (file_pos - b->file_pos);

            } else {
                b->pos = pos;
                pos += njt_min(NJT_HTTP_V2_DEFAULT_FRAME_SIZE, limit);

                if (pos >= in->buf->last) {
                    pos = in->buf->last;
                    next = 1;
                }

                b->last = pos;
                len = (njt_uint_t) (pos - b->pos);
            }

            b->tag = (njt_buf_tag_t) &njt_http_grpc_body_output_filter;
            b->shadow = in->buf;
            b->last_shadow = next;

            b->last_buf = 0;
            b->last_in_chain = 0;

            *ll = cl;
            ll = &cl->next;

            f->length_0 = (u_char) ((len >> 16) & 0xff);
            f->length_1 = (u_char) ((len >> 8) & 0xff);
            f->length_2 = (u_char) (len & 0xff);
            f->type = NJT_HTTP_V2_DATA_FRAME;
            f->flags = 0;
            f->stream_id_0 = (u_char) ((ctx->id >> 24) & 0xff);
            f->stream_id_1 = (u_char) ((ctx->id >> 16) & 0xff);
            f->stream_id_2 = (u_char) ((ctx->id >> 8) & 0xff);
            f->stream_id_3 = (u_char) (ctx->id & 0xff);

            limit -= len;
            ctx->send_window -= len;
            ctx->connection->send_window -= len;

        } while (!next && limit > 0);

        if (!next) {
            /*
             * if the buffer wasn't fully sent due to flow control limits,
             * preserve position for future use
             */

            if (in->buf->in_file) {
                in->buf->file_pos = file_pos;

            } else {
                in->buf->pos = pos;
            }

            break;
        }

    next:

        if (in->buf->last_buf) {
            last = 1;
        }

        in = in->next;
    }

    ctx->in = in;

    if (last) {

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc output last");

        ctx->output_closed = 1;

        if (f) {
            f->flags |= NJT_HTTP_V2_END_STREAM_FLAG;

        } else {
            cl = njt_http_grpc_get_buf(r, ctx);
            if (cl == NULL) {
                return NJT_ERROR;
            }

            b = cl->buf;

            f = (njt_http_grpc_frame_t *) b->last;
            b->last += sizeof(njt_http_grpc_frame_t);

            f->length_0 = 0;
            f->length_1 = 0;
            f->length_2 = 0;
            f->type = NJT_HTTP_V2_DATA_FRAME;
            f->flags = NJT_HTTP_V2_END_STREAM_FLAG;
            f->stream_id_0 = (u_char) ((ctx->id >> 24) & 0xff);
            f->stream_id_1 = (u_char) ((ctx->id >> 16) & 0xff);
            f->stream_id_2 = (u_char) ((ctx->id >> 8) & 0xff);
            f->stream_id_3 = (u_char) (ctx->id & 0xff);

            *ll = cl;
            ll = &cl->next;
        }

        cl->buf->last_buf = 1;
    }

    *ll = NULL;

#if (NJT_DEBUG)

    for (cl = out; cl; cl = cl->next) {
        njt_log_debug7(NJT_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "grpc output out l:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->last_buf,
                       cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    njt_log_debug3(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc output limit: %uz w:%z:%uz",
                   limit, ctx->send_window, ctx->connection->send_window);

#endif

    rc = njt_chain_writer(&r->upstream->writer, out);

    njt_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
                            (njt_buf_tag_t) &njt_http_grpc_body_output_filter);

    for (cl = ctx->free; cl; cl = cl->next) {

        /* mark original buffers as sent */

        if (cl->buf->shadow) {
            if (cl->buf->last_shadow) {
                b = cl->buf->shadow;
                b->pos = b->last;
            }

            cl->buf->shadow = NULL;
        }
    }

    if (rc == NJT_OK && ctx->in) {
        rc = NJT_AGAIN;
    }

    if (rc == NJT_AGAIN) {
        ctx->output_blocked = 1;

    } else {
        ctx->output_blocked = 0;
    }

    if (ctx->done) {

        /*
         * We have already got the response and were sending some additional
         * control frames.  Even if there is still something unsent, stop
         * here anyway.
         */

        u = r->upstream;
        u->length = 0;

        if (ctx->in == NULL
            && ctx->out == NULL
            && ctx->output_closed
            && !ctx->output_blocked
            && !ctx->goaway
            && ctx->state == njt_http_grpc_st_start)
        {
            u->keepalive = 1;
        }

        njt_post_event(u->peer.connection->read, &njt_posted_events);
    }

    return rc;
}


static njt_int_t
njt_http_grpc_process_header(njt_http_request_t *r)
{
    njt_str_t                      *status_line;
    njt_int_t                       rc, status;
    njt_buf_t                      *b;
    njt_table_elt_t                *h;
    njt_http_upstream_t            *u;
    njt_http_grpc_ctx_t            *ctx;
    njt_http_upstream_header_t     *hh;
    njt_http_upstream_main_conf_t  *umcf;

    u = r->upstream;
    b = &u->buffer;

    njt_log_debug4(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc response: %*xs%s, len: %uz",
                   (size_t) njt_min(b->last - b->pos, 256),
                   b->pos, b->last - b->pos > 256 ? "..." : "",
                   b->last - b->pos);

    ctx = njt_http_grpc_get_ctx(r);

    if (ctx == NULL) {
        return NJT_ERROR;
    }

    umcf = njt_http_get_module_main_conf(r, njt_http_upstream_module);

    for ( ;; ) {

        if (ctx->state < njt_http_grpc_st_payload) {

            rc = njt_http_grpc_parse_frame(r, ctx, b);

            if (rc == NJT_AGAIN) {

                /*
                 * there can be a lot of window update frames,
                 * so we reset buffer if it is empty and we haven't
                 * started parsing headers yet
                 */

                if (!ctx->parsing_headers) {
                    b->pos = b->start;
                    b->last = b->pos;
                }

                return NJT_AGAIN;
            }

            if (rc == NJT_ERROR) {
                return NJT_HTTP_UPSTREAM_INVALID_HEADER;
            }

            /*
             * RFC 7540 says that implementations MUST discard frames
             * that have unknown or unsupported types.  However, extension
             * frames that appear in the middle of a header block are
             * not permitted.  Also, for obvious reasons CONTINUATION frames
             * cannot appear before headers, and DATA frames are not expected
             * to appear before all headers are parsed.
             */

            if (ctx->type == NJT_HTTP_V2_DATA_FRAME
                || (ctx->type == NJT_HTTP_V2_CONTINUATION_FRAME
                    && !ctx->parsing_headers)
                || (ctx->type != NJT_HTTP_V2_CONTINUATION_FRAME
                    && ctx->parsing_headers))
            {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream sent unexpected http2 frame: %d",
                              ctx->type);
                return NJT_HTTP_UPSTREAM_INVALID_HEADER;
            }

            if (ctx->stream_id && ctx->stream_id != ctx->id) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream sent frame for unknown stream %ui",
                              ctx->stream_id);
                return NJT_HTTP_UPSTREAM_INVALID_HEADER;
            }
        }

        /* frame payload */

        if (ctx->type == NJT_HTTP_V2_RST_STREAM_FRAME) {

            rc = njt_http_grpc_parse_rst_stream(r, ctx, b);

            if (rc == NJT_AGAIN) {
                return NJT_AGAIN;
            }

            if (rc == NJT_ERROR) {
                return NJT_HTTP_UPSTREAM_INVALID_HEADER;
            }

            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "upstream rejected request with error %ui",
                          ctx->error);

            return NJT_HTTP_UPSTREAM_INVALID_HEADER;
        }

        if (ctx->type == NJT_HTTP_V2_GOAWAY_FRAME) {

            rc = njt_http_grpc_parse_goaway(r, ctx, b);

            if (rc == NJT_AGAIN) {
                return NJT_AGAIN;
            }

            if (rc == NJT_ERROR) {
                return NJT_HTTP_UPSTREAM_INVALID_HEADER;
            }

            /*
             * If stream_id is lower than one we use, our
             * request won't be processed and needs to be retried.
             * If stream_id is greater or equal to the one we use,
             * we can continue normally (except we can't use this
             * connection for additional requests).  If there is
             * a real error, the connection will be closed.
             */

            if (ctx->stream_id < ctx->id) {

                /* TODO: we can retry non-idempotent requests */

                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream sent goaway with error %ui",
                              ctx->error);

                return NJT_HTTP_UPSTREAM_INVALID_HEADER;
            }

            ctx->goaway = 1;

            continue;
        }

        if (ctx->type == NJT_HTTP_V2_WINDOW_UPDATE_FRAME) {

            rc = njt_http_grpc_parse_window_update(r, ctx, b);

            if (rc == NJT_AGAIN) {
                return NJT_AGAIN;
            }

            if (rc == NJT_ERROR) {
                return NJT_HTTP_UPSTREAM_INVALID_HEADER;
            }

            if (ctx->in) {
                njt_post_event(u->peer.connection->write, &njt_posted_events);
            }

            continue;
        }

        if (ctx->type == NJT_HTTP_V2_SETTINGS_FRAME) {

            rc = njt_http_grpc_parse_settings(r, ctx, b);

            if (rc == NJT_AGAIN) {
                return NJT_AGAIN;
            }

            if (rc == NJT_ERROR) {
                return NJT_HTTP_UPSTREAM_INVALID_HEADER;
            }

            if (ctx->in) {
                njt_post_event(u->peer.connection->write, &njt_posted_events);
            }

            continue;
        }

        if (ctx->type == NJT_HTTP_V2_PING_FRAME) {

            rc = njt_http_grpc_parse_ping(r, ctx, b);

            if (rc == NJT_AGAIN) {
                return NJT_AGAIN;
            }

            if (rc == NJT_ERROR) {
                return NJT_HTTP_UPSTREAM_INVALID_HEADER;
            }

            njt_post_event(u->peer.connection->write, &njt_posted_events);
            continue;
        }

        if (ctx->type == NJT_HTTP_V2_PUSH_PROMISE_FRAME) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "upstream sent unexpected push promise frame");
            return NJT_HTTP_UPSTREAM_INVALID_HEADER;
        }

        if (ctx->type != NJT_HTTP_V2_HEADERS_FRAME
            && ctx->type != NJT_HTTP_V2_CONTINUATION_FRAME)
        {
            /* priority, unknown frames */

            if (b->last - b->pos < (ssize_t) ctx->rest) {
                ctx->rest -= b->last - b->pos;
                b->pos = b->last;
                return NJT_AGAIN;
            }

            b->pos += ctx->rest;
            ctx->rest = 0;
            ctx->state = njt_http_grpc_st_start;

            continue;
        }

        /* headers */

        for ( ;; ) {

            rc = njt_http_grpc_parse_header(r, ctx, b);

            if (rc == NJT_AGAIN) {
                break;
            }

            if (rc == NJT_OK) {

                /* a header line has been parsed successfully */

                njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "grpc header: \"%V: %V\"",
                               &ctx->name, &ctx->value);

                if (ctx->name.len && ctx->name.data[0] == ':') {

                    if (ctx->name.len != sizeof(":status") - 1
                        || njt_strncmp(ctx->name.data, ":status",
                                       sizeof(":status") - 1)
                           != 0)
                    {
                        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                      "upstream sent invalid header \"%V: %V\"",
                                      &ctx->name, &ctx->value);
                        return NJT_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    if (ctx->status) {
                        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                      "upstream sent duplicate :status header");
                        return NJT_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    status_line = &ctx->value;

                    if (status_line->len != 3) {
                        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                      "upstream sent invalid :status \"%V\"",
                                      status_line);
                        return NJT_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    status = njt_atoi(status_line->data, 3);

                    if (status == NJT_ERROR) {
                        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                      "upstream sent invalid :status \"%V\"",
                                      status_line);
                        return NJT_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    if (status < NJT_HTTP_OK) {
                        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                      "upstream sent unexpected :status \"%V\"",
                                      status_line);
                        return NJT_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    u->headers_in.status_n = status;

                    if (u->state && u->state->status == 0) {
                        u->state->status = status;
                    }

                    ctx->status = 1;

                    continue;

                } else if (!ctx->status) {
                    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                  "upstream sent no :status header");
                    return NJT_HTTP_UPSTREAM_INVALID_HEADER;
                }

                h = njt_list_push(&u->headers_in.headers);
                if (h == NULL) {
                    return NJT_ERROR;
                }

                h->key = ctx->name;
                h->value = ctx->value;
                h->lowcase_key = h->key.data;
                h->hash = njt_hash_key(h->key.data, h->key.len);

                hh = njt_hash_find(&umcf->headers_in_hash, h->hash,
                                   h->lowcase_key, h->key.len);

                if (hh) {
                    rc = hh->handler(r, h, hh->offset);

                    if (rc != NJT_OK) {
                        return rc;
                    }
                }

                continue;
            }

            if (rc == NJT_HTTP_PARSE_HEADER_DONE) {

                /* a whole header has been parsed successfully */

                njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "grpc header done");

                if (ctx->end_stream) {
                    u->headers_in.content_length_n = 0;

                    if (ctx->in == NULL
                        && ctx->out == NULL
                        && ctx->output_closed
                        && !ctx->output_blocked
                        && !ctx->goaway
                        && b->last == b->pos)
                    {
                        u->keepalive = 1;
                    }
                }

                return NJT_OK;
            }

            /* there was error while a header line parsing */

            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "upstream sent invalid header");

            return NJT_HTTP_UPSTREAM_INVALID_HEADER;
        }

        /* rc == NJT_AGAIN */

        if (ctx->rest == 0) {
            ctx->state = njt_http_grpc_st_start;
            continue;
        }

        return NJT_AGAIN;
    }
}


static njt_int_t
njt_http_grpc_filter_init(void *data)
{
    njt_http_grpc_ctx_t  *ctx = data;

    njt_http_request_t   *r;
    njt_http_upstream_t  *u;

    r = ctx->request;
    u = r->upstream;

    if (u->headers_in.status_n == NJT_HTTP_NO_CONTENT
        || u->headers_in.status_n == NJT_HTTP_NOT_MODIFIED
        || r->method == NJT_HTTP_HEAD)
    {
        ctx->length = 0;

    } else {
        ctx->length = u->headers_in.content_length_n;
    }

    if (ctx->end_stream) {

        if (ctx->length > 0) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "upstream prematurely closed stream");
            return NJT_ERROR;
        }

        u->length = 0;
        ctx->done = 1;

    } else {
        u->length = 1;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_grpc_filter(void *data, ssize_t bytes)
{
    njt_http_grpc_ctx_t  *ctx = data;

    njt_int_t             rc;
    njt_buf_t            *b, *buf;
    njt_chain_t          *cl, **ll;
    njt_table_elt_t      *h;
    njt_http_request_t   *r;
    njt_http_upstream_t  *u;

    r = ctx->request;
    u = r->upstream;
    b = &u->buffer;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc filter bytes:%z", bytes);

    b->pos = b->last;
    b->last += bytes;

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    for ( ;; ) {

        if (ctx->state < njt_http_grpc_st_payload) {

            rc = njt_http_grpc_parse_frame(r, ctx, b);

            if (rc == NJT_AGAIN) {

                if (ctx->done) {

                    if (ctx->length > 0) {
                        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                      "upstream prematurely closed stream");
                        return NJT_ERROR;
                    }

                    /*
                     * We have finished parsing the response and the
                     * remaining control frames.  If there are unsent
                     * control frames, post a write event to send them.
                     */

                    if (ctx->out) {
                        njt_post_event(u->peer.connection->write,
                                       &njt_posted_events);
                        return NJT_AGAIN;
                    }

                    u->length = 0;

                    if (ctx->in == NULL
                        && ctx->output_closed
                        && !ctx->output_blocked
                        && !ctx->goaway
                        && ctx->state == njt_http_grpc_st_start)
                    {
                        u->keepalive = 1;
                    }

                    break;
                }

                return NJT_AGAIN;
            }

            if (rc == NJT_ERROR) {
                return NJT_ERROR;
            }

            if ((ctx->type == NJT_HTTP_V2_CONTINUATION_FRAME
                 && !ctx->parsing_headers)
                || (ctx->type != NJT_HTTP_V2_CONTINUATION_FRAME
                    && ctx->parsing_headers))
            {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream sent unexpected http2 frame: %d",
                              ctx->type);
                return NJT_ERROR;
            }

            if (ctx->type == NJT_HTTP_V2_DATA_FRAME) {

                if (ctx->stream_id != ctx->id) {
                    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                  "upstream sent data frame "
                                  "for unknown stream %ui",
                                  ctx->stream_id);
                    return NJT_ERROR;
                }

                if (ctx->rest > ctx->recv_window) {
                    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                  "upstream violated stream flow control, "
                                  "received %uz data frame with window %uz",
                                  ctx->rest, ctx->recv_window);
                    return NJT_ERROR;
                }

                if (ctx->rest > ctx->connection->recv_window) {
                    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                  "upstream violated connection flow control, "
                                  "received %uz data frame with window %uz",
                                  ctx->rest, ctx->connection->recv_window);
                    return NJT_ERROR;
                }

                ctx->recv_window -= ctx->rest;
                ctx->connection->recv_window -= ctx->rest;

                if (ctx->connection->recv_window < NJT_HTTP_V2_MAX_WINDOW / 4
                    || ctx->recv_window < NJT_HTTP_V2_MAX_WINDOW / 4)
                {
                    if (njt_http_grpc_send_window_update(r, ctx) != NJT_OK) {
                        return NJT_ERROR;
                    }

                    njt_post_event(u->peer.connection->write,
                                   &njt_posted_events);
                }
            }

            if (ctx->stream_id && ctx->stream_id != ctx->id) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream sent frame for unknown stream %ui",
                              ctx->stream_id);
                return NJT_ERROR;
            }

            if (ctx->stream_id && ctx->done
                && ctx->type != NJT_HTTP_V2_RST_STREAM_FRAME
                && ctx->type != NJT_HTTP_V2_WINDOW_UPDATE_FRAME)
            {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream sent frame for closed stream %ui",
                              ctx->stream_id);
                return NJT_ERROR;
            }

            ctx->padding = 0;
        }

        if (ctx->state == njt_http_grpc_st_padding) {

            if (b->last - b->pos < (ssize_t) ctx->rest) {
                ctx->rest -= b->last - b->pos;
                b->pos = b->last;
                return NJT_AGAIN;
            }

            b->pos += ctx->rest;
            ctx->rest = 0;
            ctx->state = njt_http_grpc_st_start;

            if (ctx->flags & NJT_HTTP_V2_END_STREAM_FLAG) {
                ctx->done = 1;
            }

            continue;
        }

        /* frame payload */

        if (ctx->type == NJT_HTTP_V2_RST_STREAM_FRAME) {

            rc = njt_http_grpc_parse_rst_stream(r, ctx, b);

            if (rc == NJT_AGAIN) {
                return NJT_AGAIN;
            }

            if (rc == NJT_ERROR) {
                return NJT_ERROR;
            }

            if (ctx->error || !ctx->done) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream rejected request with error %ui",
                              ctx->error);
                return NJT_ERROR;
            }

            if (ctx->rst) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream sent frame for closed stream %ui",
                              ctx->stream_id);
                return NJT_ERROR;
            }

            ctx->rst = 1;

            continue;
        }

        if (ctx->type == NJT_HTTP_V2_GOAWAY_FRAME) {

            rc = njt_http_grpc_parse_goaway(r, ctx, b);

            if (rc == NJT_AGAIN) {
                return NJT_AGAIN;
            }

            if (rc == NJT_ERROR) {
                return NJT_ERROR;
            }

            /*
             * If stream_id is lower than one we use, our
             * request won't be processed and needs to be retried.
             * If stream_id is greater or equal to the one we use,
             * we can continue normally (except we can't use this
             * connection for additional requests).  If there is
             * a real error, the connection will be closed.
             */

            if (ctx->stream_id < ctx->id) {

                /* TODO: we can retry non-idempotent requests */

                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream sent goaway with error %ui",
                              ctx->error);

                return NJT_ERROR;
            }

            ctx->goaway = 1;

            continue;
        }

        if (ctx->type == NJT_HTTP_V2_WINDOW_UPDATE_FRAME) {

            rc = njt_http_grpc_parse_window_update(r, ctx, b);

            if (rc == NJT_AGAIN) {
                return NJT_AGAIN;
            }

            if (rc == NJT_ERROR) {
                return NJT_ERROR;
            }

            if (ctx->in) {
                njt_post_event(u->peer.connection->write, &njt_posted_events);
            }

            continue;
        }

        if (ctx->type == NJT_HTTP_V2_SETTINGS_FRAME) {

            rc = njt_http_grpc_parse_settings(r, ctx, b);

            if (rc == NJT_AGAIN) {
                return NJT_AGAIN;
            }

            if (rc == NJT_ERROR) {
                return NJT_ERROR;
            }

            if (ctx->in) {
                njt_post_event(u->peer.connection->write, &njt_posted_events);
            }

            continue;
        }

        if (ctx->type == NJT_HTTP_V2_PING_FRAME) {

            rc = njt_http_grpc_parse_ping(r, ctx, b);

            if (rc == NJT_AGAIN) {
                return NJT_AGAIN;
            }

            if (rc == NJT_ERROR) {
                return NJT_ERROR;
            }

            njt_post_event(u->peer.connection->write, &njt_posted_events);
            continue;
        }

        if (ctx->type == NJT_HTTP_V2_PUSH_PROMISE_FRAME) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "upstream sent unexpected push promise frame");
            return NJT_ERROR;
        }

        if (ctx->type == NJT_HTTP_V2_HEADERS_FRAME
            || ctx->type == NJT_HTTP_V2_CONTINUATION_FRAME)
        {
            for ( ;; ) {

                rc = njt_http_grpc_parse_header(r, ctx, b);

                if (rc == NJT_AGAIN) {
                    break;
                }

                if (rc == NJT_OK) {

                    /* a header line has been parsed successfully */

                    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "grpc trailer: \"%V: %V\"",
                                   &ctx->name, &ctx->value);

                    if (ctx->name.len && ctx->name.data[0] == ':') {
                        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                      "upstream sent invalid "
                                      "trailer \"%V: %V\"",
                                      &ctx->name, &ctx->value);
                        return NJT_ERROR;
                    }

                    h = njt_list_push(&u->headers_in.trailers);
                    if (h == NULL) {
                        return NJT_ERROR;
                    }

                    h->key = ctx->name;
                    h->value = ctx->value;
                    h->lowcase_key = h->key.data;
                    h->hash = njt_hash_key(h->key.data, h->key.len);

                    continue;
                }

                if (rc == NJT_HTTP_PARSE_HEADER_DONE) {

                    /* a whole header has been parsed successfully */

                    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "grpc trailer done");

                    if (ctx->end_stream) {
                        ctx->done = 1;
                        break;
                    }

                    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                  "upstream sent trailer without "
                                  "end stream flag");
                    return NJT_ERROR;
                }

                /* there was error while a header line parsing */

                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid trailer");

                return NJT_ERROR;
            }

            if (rc == NJT_HTTP_PARSE_HEADER_DONE) {
                continue;
            }

            /* rc == NJT_AGAIN */

            if (ctx->rest == 0) {
                ctx->state = njt_http_grpc_st_start;
                continue;
            }

            return NJT_AGAIN;
        }

        if (ctx->type != NJT_HTTP_V2_DATA_FRAME) {

            /* priority, unknown frames */

            if (b->last - b->pos < (ssize_t) ctx->rest) {
                ctx->rest -= b->last - b->pos;
                b->pos = b->last;
                return NJT_AGAIN;
            }

            b->pos += ctx->rest;
            ctx->rest = 0;
            ctx->state = njt_http_grpc_st_start;

            continue;
        }

        /*
         * data frame:
         *
         * +---------------+
         * |Pad Length? (8)|
         * +---------------+-----------------------------------------------+
         * |                            Data (*)                         ...
         * +---------------------------------------------------------------+
         * |                           Padding (*)                       ...
         * +---------------------------------------------------------------+
         */

        if (ctx->flags & NJT_HTTP_V2_PADDED_FLAG) {

            if (ctx->rest == 0) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream sent too short http2 frame");
                return NJT_ERROR;
            }

            if (b->pos == b->last) {
                return NJT_AGAIN;
            }

            ctx->flags &= ~NJT_HTTP_V2_PADDED_FLAG;
            ctx->padding = *b->pos++;
            ctx->rest -= 1;

            if (ctx->padding > ctx->rest) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream sent http2 frame with too long "
                              "padding: %d in frame %uz",
                              ctx->padding, ctx->rest);
                return NJT_ERROR;
            }

            continue;
        }

        if (ctx->rest == ctx->padding) {
            goto done;
        }

        if (b->pos == b->last) {
            return NJT_AGAIN;
        }

        cl = njt_chain_get_free_buf(r->pool, &u->free_bufs);
        if (cl == NULL) {
            return NJT_ERROR;
        }

        *ll = cl;
        ll = &cl->next;

        buf = cl->buf;

        buf->flush = 1;
        buf->memory = 1;

        buf->pos = b->pos;
        buf->tag = u->output.tag;

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc output buf %p", buf->pos);

        if (b->last - b->pos < (ssize_t) ctx->rest - ctx->padding) {

            ctx->rest -= b->last - b->pos;
            b->pos = b->last;
            buf->last = b->pos;

            if (ctx->length != -1) {

                if (buf->last - buf->pos > ctx->length) {
                    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                  "upstream sent response body larger "
                                  "than indicated content length");
                    return NJT_ERROR;
                }

                ctx->length -= buf->last - buf->pos;
            }

            return NJT_AGAIN;
        }

        b->pos += ctx->rest - ctx->padding;
        buf->last = b->pos;
        ctx->rest = ctx->padding;

        if (ctx->length != -1) {

            if (buf->last - buf->pos > ctx->length) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream sent response body larger "
                              "than indicated content length");
                return NJT_ERROR;
            }

            ctx->length -= buf->last - buf->pos;
        }

    done:

        if (ctx->padding) {
            ctx->state = njt_http_grpc_st_padding;
            continue;
        }

        ctx->state = njt_http_grpc_st_start;

        if (ctx->flags & NJT_HTTP_V2_END_STREAM_FLAG) {
            ctx->done = 1;
        }
    }

    return NJT_OK;
}


static njt_int_t
njt_http_grpc_parse_frame(njt_http_request_t *r, njt_http_grpc_ctx_t *ctx,
    njt_buf_t *b)
{
    u_char                 ch, *p;
    njt_http_grpc_state_e  state;

    state = ctx->state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

#if 0
        njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc frame byte: %02Xd, s:%d", ch, state);
#endif

        switch (state) {

        case njt_http_grpc_st_start:
            ctx->rest = ch << 16;
            state = njt_http_grpc_st_length_2;
            break;

        case njt_http_grpc_st_length_2:
            ctx->rest |= ch << 8;
            state = njt_http_grpc_st_length_3;
            break;

        case njt_http_grpc_st_length_3:
            ctx->rest |= ch;

            if (ctx->rest > NJT_HTTP_V2_DEFAULT_FRAME_SIZE) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream sent too large http2 frame: %uz",
                              ctx->rest);
                return NJT_ERROR;
            }

            state = njt_http_grpc_st_type;
            break;

        case njt_http_grpc_st_type:
            ctx->type = ch;
            state = njt_http_grpc_st_flags;
            break;

        case njt_http_grpc_st_flags:
            ctx->flags = ch;
            state = njt_http_grpc_st_stream_id;
            break;

        case njt_http_grpc_st_stream_id:
            ctx->stream_id = (ch & 0x7f) << 24;
            state = njt_http_grpc_st_stream_id_2;
            break;

        case njt_http_grpc_st_stream_id_2:
            ctx->stream_id |= ch << 16;
            state = njt_http_grpc_st_stream_id_3;
            break;

        case njt_http_grpc_st_stream_id_3:
            ctx->stream_id |= ch << 8;
            state = njt_http_grpc_st_stream_id_4;
            break;

        case njt_http_grpc_st_stream_id_4:
            ctx->stream_id |= ch;

            njt_log_debug4(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc frame: %d, len: %uz, f:%d, i:%ui",
                           ctx->type, ctx->rest, ctx->flags, ctx->stream_id);

            b->pos = p + 1;

            ctx->state = njt_http_grpc_st_payload;
            ctx->frame_state = 0;

            return NJT_OK;

        /* suppress warning */
        case njt_http_grpc_st_payload:
        case njt_http_grpc_st_padding:
            break;
        }
    }

    b->pos = p;
    ctx->state = state;

    return NJT_AGAIN;
}


static njt_int_t
njt_http_grpc_parse_header(njt_http_request_t *r, njt_http_grpc_ctx_t *ctx,
    njt_buf_t *b)
{
    u_char     ch, *p, *last;
    size_t     min;
    njt_int_t  rc;
    enum {
        sw_start = 0,
        sw_padding_length,
        sw_dependency,
        sw_dependency_2,
        sw_dependency_3,
        sw_dependency_4,
        sw_weight,
        sw_fragment,
        sw_padding
    } state;

    state = ctx->frame_state;

    if (state == sw_start) {

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc parse header: start");

        if (ctx->type == NJT_HTTP_V2_HEADERS_FRAME) {
            ctx->parsing_headers = 1;
            ctx->fragment_state = 0;

            min = (ctx->flags & NJT_HTTP_V2_PADDED_FLAG ? 1 : 0)
                  + (ctx->flags & NJT_HTTP_V2_PRIORITY_FLAG ? 5 : 0);

            if (ctx->rest < min) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream sent headers frame "
                              "with invalid length: %uz",
                              ctx->rest);
                return NJT_ERROR;
            }

            if (ctx->flags & NJT_HTTP_V2_END_STREAM_FLAG) {
                ctx->end_stream = 1;
            }

            if (ctx->flags & NJT_HTTP_V2_PADDED_FLAG) {
                state = sw_padding_length;

            } else if (ctx->flags & NJT_HTTP_V2_PRIORITY_FLAG) {
                state = sw_dependency;

            } else {
                state = sw_fragment;
            }

        } else if (ctx->type == NJT_HTTP_V2_CONTINUATION_FRAME) {
            state = sw_fragment;
        }

        ctx->padding = 0;
        ctx->frame_state = state;
    }

    if (state < sw_fragment) {

        if (b->last - b->pos < (ssize_t) ctx->rest) {
            last = b->last;

        } else {
            last = b->pos + ctx->rest;
        }

        for (p = b->pos; p < last; p++) {
            ch = *p;

#if 0
            njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc header byte: %02Xd s:%d", ch, state);
#endif

            /*
             * headers frame:
             *
             * +---------------+
             * |Pad Length? (8)|
             * +-+-------------+----------------------------------------------+
             * |E|                 Stream Dependency? (31)                    |
             * +-+-------------+----------------------------------------------+
             * |  Weight? (8)  |
             * +-+-------------+----------------------------------------------+
             * |                   Header Block Fragment (*)                ...
             * +--------------------------------------------------------------+
             * |                           Padding (*)                      ...
             * +--------------------------------------------------------------+
             */

            switch (state) {

            case sw_padding_length:

                ctx->padding = ch;

                if (ctx->flags & NJT_HTTP_V2_PRIORITY_FLAG) {
                    state = sw_dependency;
                    break;
                }

                goto fragment;

            case sw_dependency:
                state = sw_dependency_2;
                break;

            case sw_dependency_2:
                state = sw_dependency_3;
                break;

            case sw_dependency_3:
                state = sw_dependency_4;
                break;

            case sw_dependency_4:
                state = sw_weight;
                break;

            case sw_weight:
                goto fragment;

            /* suppress warning */
            case sw_start:
            case sw_fragment:
            case sw_padding:
                break;
            }
        }

        ctx->rest -= p - b->pos;
        b->pos = p;

        ctx->frame_state = state;
        return NJT_AGAIN;

    fragment:

        p++;
        ctx->rest -= p - b->pos;
        b->pos = p;

        if (ctx->padding > ctx->rest) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "upstream sent http2 frame with too long "
                          "padding: %d in frame %uz",
                          ctx->padding, ctx->rest);
            return NJT_ERROR;
        }

        state = sw_fragment;
        ctx->frame_state = state;
    }

    if (state == sw_fragment) {

        rc = njt_http_grpc_parse_fragment(r, ctx, b);

        if (rc == NJT_AGAIN) {
            return NJT_AGAIN;
        }

        if (rc == NJT_ERROR) {
            return NJT_ERROR;
        }

        if (rc == NJT_OK) {
            return NJT_OK;
        }

        /* rc == NJT_DONE */

        state = sw_padding;
        ctx->frame_state = state;
    }

    if (state == sw_padding) {

        if (b->last - b->pos < (ssize_t) ctx->rest) {

            ctx->rest -= b->last - b->pos;
            b->pos = b->last;

            return NJT_AGAIN;
        }

        b->pos += ctx->rest;
        ctx->rest = 0;

        ctx->state = njt_http_grpc_st_start;

        if (ctx->flags & NJT_HTTP_V2_END_HEADERS_FLAG) {

            if (ctx->fragment_state) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream sent truncated http2 header");
                return NJT_ERROR;
            }

            ctx->parsing_headers = 0;

            return NJT_HTTP_PARSE_HEADER_DONE;
        }

        return NJT_AGAIN;
    }

    /* unreachable */

    return NJT_ERROR;
}


static njt_int_t
njt_http_grpc_parse_fragment(njt_http_request_t *r, njt_http_grpc_ctx_t *ctx,
    njt_buf_t *b)
{
    u_char      ch, *p, *last;
    size_t      size;
    njt_uint_t  index, size_update;
    enum {
        sw_start = 0,
        sw_index,
        sw_name_length,
        sw_name_length_2,
        sw_name_length_3,
        sw_name_length_4,
        sw_name,
        sw_name_bytes,
        sw_value_length,
        sw_value_length_2,
        sw_value_length_3,
        sw_value_length_4,
        sw_value,
        sw_value_bytes
    } state;

    /* header block fragment */

#if 0
    njt_log_debug3(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc header fragment %p:%p rest:%uz",
                   b->pos, b->last, ctx->rest);
#endif

    if (b->last - b->pos < (ssize_t) ctx->rest - ctx->padding) {
        last = b->last;

    } else {
        last = b->pos + ctx->rest - ctx->padding;
    }

    state = ctx->fragment_state;

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc header byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            ctx->index = 0;

            if ((ch & 0x80) == 0x80) {
                /*
                 * indexed header:
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 1 |        Index (7+)         |
                 * +---+---------------------------+
                 */

                index = ch & ~0x80;

                if (index == 0 || index > 61) {
                    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid http2 "
                                  "table index: %ui", index);
                    return NJT_ERROR;
                }

                njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "grpc indexed header: %ui", index);

                ctx->index = index;
                ctx->literal = 0;

                goto done;

            } else if ((ch & 0xc0) == 0x40) {
                /*
                 * literal header with incremental indexing:
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 1 |      Index (6+)       |
                 * +---+---+-----------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 1 |           0           |
                 * +---+---+-----------------------+
                 * | H |     Name Length (7+)      |
                 * +---+---------------------------+
                 * |  Name String (Length octets)  |
                 * +---+---------------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 */

                index = ch & ~0xc0;

                if (index > 61) {
                    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid http2 "
                                  "table index: %ui", index);
                    return NJT_ERROR;
                }

                njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "grpc literal header: %ui", index);

                if (index == 0) {
                    state = sw_name_length;
                    break;
                }

                ctx->index = index;
                ctx->literal = 1;

                state = sw_value_length;
                break;

            } else if ((ch & 0xe0) == 0x20) {
                /*
                 * dynamic table size update:
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 0 | 1 |   Max size (5+)   |
                 * +---+---------------------------+
                 */

                size_update = ch & ~0xe0;

                if (size_update > 0) {
                    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid http2 "
                                  "dynamic table size update: %ui",
                                  size_update);
                    return NJT_ERROR;
                }

                njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "grpc table size update: %ui", size_update);

                break;

            } else if ((ch & 0xf0) == 0x10) {
                /*
                 *  literal header field never indexed:
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 0 | 0 | 1 |  Index (4+)   |
                 * +---+---+-----------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 0 | 0 | 1 |       0       |
                 * +---+---+-----------------------+
                 * | H |     Name Length (7+)      |
                 * +---+---------------------------+
                 * |  Name String (Length octets)  |
                 * +---+---------------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 */

                index = ch & ~0xf0;

                if (index == 0x0f) {
                    ctx->index = index;
                    ctx->literal = 1;
                    state = sw_index;
                    break;
                }

                if (index == 0) {
                    state = sw_name_length;
                    break;
                }

                njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "grpc literal header never indexed: %ui",
                               index);

                ctx->index = index;
                ctx->literal = 1;

                state = sw_value_length;
                break;

            } else if ((ch & 0xf0) == 0x00) {
                /*
                 * literal header field without indexing:
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 0 | 0 | 0 |  Index (4+)   |
                 * +---+---+-----------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 0 | 0 | 0 |       0       |
                 * +---+---+-----------------------+
                 * | H |     Name Length (7+)      |
                 * +---+---------------------------+
                 * |  Name String (Length octets)  |
                 * +---+---------------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 */

                index = ch & ~0xf0;

                if (index == 0x0f) {
                    ctx->index = index;
                    ctx->literal = 1;
                    state = sw_index;
                    break;
                }

                if (index == 0) {
                    state = sw_name_length;
                    break;
                }

                njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "grpc literal header without indexing: %ui",
                               index);

                ctx->index = index;
                ctx->literal = 1;

                state = sw_value_length;
                break;
            }

            /* not reached */

            return NJT_ERROR;

        case sw_index:
            ctx->index = ctx->index + (ch & ~0x80);

            if (ch & 0x80) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream sent http2 table index "
                              "with continuation flag");
                return NJT_ERROR;
            }

            if (ctx->index > 61) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid http2 "
                              "table index: %ui", ctx->index);
                return NJT_ERROR;
            }

            njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc header index: %ui", ctx->index);

            state = sw_value_length;
            break;

        case sw_name_length:
            ctx->field_huffman = ch & 0x80 ? 1 : 0;
            ctx->field_length = ch & ~0x80;

            if (ctx->field_length == 0x7f) {
                state = sw_name_length_2;
                break;
            }

            if (ctx->field_length == 0) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream sent zero http2 "
                              "header name length");
                return NJT_ERROR;
            }

            state = sw_name;
            break;

        case sw_name_length_2:
            ctx->field_length += ch & ~0x80;

            if (ch & 0x80) {
                state = sw_name_length_3;
                break;
            }

            state = sw_name;
            break;

        case sw_name_length_3:
            ctx->field_length += (ch & ~0x80) << 7;

            if (ch & 0x80) {
                state = sw_name_length_4;
                break;
            }

            state = sw_name;
            break;

        case sw_name_length_4:
            ctx->field_length += (ch & ~0x80) << 14;

            if (ch & 0x80) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream sent too large http2 "
                              "header name length");
                return NJT_ERROR;
            }

            state = sw_name;
            break;

        case sw_name:
            ctx->name.len = ctx->field_huffman ?
                            ctx->field_length * 8 / 5 : ctx->field_length;

            ctx->name.data = njt_pnalloc(r->pool, ctx->name.len + 1);
            if (ctx->name.data == NULL) {
                return NJT_ERROR;
            }

            ctx->field_end = ctx->name.data;
            ctx->field_rest = ctx->field_length;
            ctx->field_state = 0;

            state = sw_name_bytes;

            /* fall through */

        case sw_name_bytes:

            njt_log_debug4(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc name: len:%uz h:%d last:%uz, rest:%uz",
                           ctx->field_length,
                           ctx->field_huffman,
                           last - p,
                           ctx->rest - (p - b->pos));

            size = njt_min(last - p, (ssize_t) ctx->field_rest);
            ctx->field_rest -= size;

            if (ctx->field_huffman) {
                if (njt_http_huff_decode(&ctx->field_state, p, size,
                                         &ctx->field_end,
                                         ctx->field_rest == 0,
                                         r->connection->log)
                    != NJT_OK)
                {
                    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid encoded header");
                    return NJT_ERROR;
                }

                ctx->name.len = ctx->field_end - ctx->name.data;
                ctx->name.data[ctx->name.len] = '\0';

            } else {
                ctx->field_end = njt_cpymem(ctx->field_end, p, size);
                ctx->name.data[ctx->name.len] = '\0';
            }

            p += size - 1;

            if (ctx->field_rest == 0) {
                state = sw_value_length;
            }

            break;

        case sw_value_length:
            ctx->field_huffman = ch & 0x80 ? 1 : 0;
            ctx->field_length = ch & ~0x80;

            if (ctx->field_length == 0x7f) {
                state = sw_value_length_2;
                break;
            }

            if (ctx->field_length == 0) {
                njt_str_set(&ctx->value, "");
                goto done;
            }

            state = sw_value;
            break;

        case sw_value_length_2:
            ctx->field_length += ch & ~0x80;

            if (ch & 0x80) {
                state = sw_value_length_3;
                break;
            }

            state = sw_value;
            break;

        case sw_value_length_3:
            ctx->field_length += (ch & ~0x80) << 7;

            if (ch & 0x80) {
                state = sw_value_length_4;
                break;
            }

            state = sw_value;
            break;

        case sw_value_length_4:
            ctx->field_length += (ch & ~0x80) << 14;

            if (ch & 0x80) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream sent too large http2 "
                              "header value length");
                return NJT_ERROR;
            }

            state = sw_value;
            break;

        case sw_value:
            ctx->value.len = ctx->field_huffman ?
                             ctx->field_length * 8 / 5 : ctx->field_length;

            ctx->value.data = njt_pnalloc(r->pool, ctx->value.len + 1);
            if (ctx->value.data == NULL) {
                return NJT_ERROR;
            }

            ctx->field_end = ctx->value.data;
            ctx->field_rest = ctx->field_length;
            ctx->field_state = 0;

            state = sw_value_bytes;

            /* fall through */

        case sw_value_bytes:

            njt_log_debug4(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc value: len:%uz h:%d last:%uz, rest:%uz",
                           ctx->field_length,
                           ctx->field_huffman,
                           last - p,
                           ctx->rest - (p - b->pos));

            size = njt_min(last - p, (ssize_t) ctx->field_rest);
            ctx->field_rest -= size;

            if (ctx->field_huffman) {
                if (njt_http_huff_decode(&ctx->field_state, p, size,
                                         &ctx->field_end,
                                         ctx->field_rest == 0,
                                         r->connection->log)
                    != NJT_OK)
                {
                    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid encoded header");
                    return NJT_ERROR;
                }

                ctx->value.len = ctx->field_end - ctx->value.data;
                ctx->value.data[ctx->value.len] = '\0';

            } else {
                ctx->field_end = njt_cpymem(ctx->field_end, p, size);
                ctx->value.data[ctx->value.len] = '\0';
            }

            p += size - 1;

            if (ctx->field_rest == 0) {
                goto done;
            }

            break;
        }

        continue;

    done:

        p++;
        ctx->rest -= p - b->pos;
        ctx->fragment_state = sw_start;
        b->pos = p;

        if (ctx->index) {
            ctx->name = *njt_http_v2_get_static_name(ctx->index);
        }

        if (ctx->index && !ctx->literal) {
            ctx->value = *njt_http_v2_get_static_value(ctx->index);
        }

        if (!ctx->index) {
            if (njt_http_grpc_validate_header_name(r, &ctx->name) != NJT_OK) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid header: \"%V: %V\"",
                              &ctx->name, &ctx->value);
                return NJT_ERROR;
            }
        }

        if (!ctx->index || ctx->literal) {
            if (njt_http_grpc_validate_header_value(r, &ctx->value) != NJT_OK) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid header: \"%V: %V\"",
                              &ctx->name, &ctx->value);
                return NJT_ERROR;
            }
        }

        return NJT_OK;
    }

    ctx->rest -= p - b->pos;
    ctx->fragment_state = state;
    b->pos = p;

    if (ctx->rest > ctx->padding) {
        return NJT_AGAIN;
    }

    return NJT_DONE;
}


static njt_int_t
njt_http_grpc_validate_header_name(njt_http_request_t *r, njt_str_t *s)
{
    u_char      ch;
    njt_uint_t  i;

    for (i = 0; i < s->len; i++) {
        ch = s->data[i];

        if (ch == ':' && i > 0) {
            return NJT_ERROR;
        }

        if (ch >= 'A' && ch <= 'Z') {
            return NJT_ERROR;
        }

        if (ch <= 0x20 || ch == 0x7f) {
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


static njt_int_t
njt_http_grpc_validate_header_value(njt_http_request_t *r, njt_str_t *s)
{
    u_char      ch;
    njt_uint_t  i;

    for (i = 0; i < s->len; i++) {
        ch = s->data[i];

        if (ch == '\0' || ch == CR || ch == LF) {
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


static njt_int_t
njt_http_grpc_parse_rst_stream(njt_http_request_t *r, njt_http_grpc_ctx_t *ctx,
    njt_buf_t *b)
{
    u_char  ch, *p, *last;
    enum {
        sw_start = 0,
        sw_error_2,
        sw_error_3,
        sw_error_4
    } state;

    if (b->last - b->pos < (ssize_t) ctx->rest) {
        last = b->last;

    } else {
        last = b->pos + ctx->rest;
    }

    state = ctx->frame_state;

    if (state == sw_start) {
        if (ctx->rest != 4) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "upstream sent rst stream frame "
                          "with invalid length: %uz",
                          ctx->rest);
            return NJT_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc rst byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            ctx->error = (njt_uint_t) ch << 24;
            state = sw_error_2;
            break;

        case sw_error_2:
            ctx->error |= ch << 16;
            state = sw_error_3;
            break;

        case sw_error_3:
            ctx->error |= ch << 8;
            state = sw_error_4;
            break;

        case sw_error_4:
            ctx->error |= ch;
            state = sw_start;

            njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc error: %ui", ctx->error);

            break;
        }
    }

    ctx->rest -= p - b->pos;
    ctx->frame_state = state;
    b->pos = p;

    if (ctx->rest > 0) {
        return NJT_AGAIN;
    }

    ctx->state = njt_http_grpc_st_start;

    return NJT_OK;
}


static njt_int_t
njt_http_grpc_parse_goaway(njt_http_request_t *r, njt_http_grpc_ctx_t *ctx,
    njt_buf_t *b)
{
    u_char  ch, *p, *last;
    enum {
        sw_start = 0,
        sw_last_stream_id_2,
        sw_last_stream_id_3,
        sw_last_stream_id_4,
        sw_error,
        sw_error_2,
        sw_error_3,
        sw_error_4,
        sw_debug
    } state;

    if (b->last - b->pos < (ssize_t) ctx->rest) {
        last = b->last;

    } else {
        last = b->pos + ctx->rest;
    }

    state = ctx->frame_state;

    if (state == sw_start) {

        if (ctx->stream_id) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "upstream sent goaway frame "
                          "with non-zero stream id: %ui",
                          ctx->stream_id);
            return NJT_ERROR;
        }

        if (ctx->rest < 8) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "upstream sent goaway frame "
                          "with invalid length: %uz",
                          ctx->rest);
            return NJT_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc goaway byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            ctx->stream_id = (ch & 0x7f) << 24;
            state = sw_last_stream_id_2;
            break;

        case sw_last_stream_id_2:
            ctx->stream_id |= ch << 16;
            state = sw_last_stream_id_3;
            break;

        case sw_last_stream_id_3:
            ctx->stream_id |= ch << 8;
            state = sw_last_stream_id_4;
            break;

        case sw_last_stream_id_4:
            ctx->stream_id |= ch;
            state = sw_error;
            break;

        case sw_error:
            ctx->error = (njt_uint_t) ch << 24;
            state = sw_error_2;
            break;

        case sw_error_2:
            ctx->error |= ch << 16;
            state = sw_error_3;
            break;

        case sw_error_3:
            ctx->error |= ch << 8;
            state = sw_error_4;
            break;

        case sw_error_4:
            ctx->error |= ch;
            state = sw_debug;
            break;

        case sw_debug:
            break;
        }
    }

    ctx->rest -= p - b->pos;
    ctx->frame_state = state;
    b->pos = p;

    if (ctx->rest > 0) {
        return NJT_AGAIN;
    }

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc goaway: %ui, stream %ui",
                   ctx->error, ctx->stream_id);

    ctx->state = njt_http_grpc_st_start;

    return NJT_OK;
}


static njt_int_t
njt_http_grpc_parse_window_update(njt_http_request_t *r,
    njt_http_grpc_ctx_t *ctx, njt_buf_t *b)
{
    u_char  ch, *p, *last;
    enum {
        sw_start = 0,
        sw_size_2,
        sw_size_3,
        sw_size_4
    } state;

    if (b->last - b->pos < (ssize_t) ctx->rest) {
        last = b->last;

    } else {
        last = b->pos + ctx->rest;
    }

    state = ctx->frame_state;

    if (state == sw_start) {
        if (ctx->rest != 4) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "upstream sent window update frame "
                          "with invalid length: %uz",
                          ctx->rest);
            return NJT_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc window update byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            ctx->window_update = (ch & 0x7f) << 24;
            state = sw_size_2;
            break;

        case sw_size_2:
            ctx->window_update |= ch << 16;
            state = sw_size_3;
            break;

        case sw_size_3:
            ctx->window_update |= ch << 8;
            state = sw_size_4;
            break;

        case sw_size_4:
            ctx->window_update |= ch;
            state = sw_start;
            break;
        }
    }

    ctx->rest -= p - b->pos;
    ctx->frame_state = state;
    b->pos = p;

    if (ctx->rest > 0) {
        return NJT_AGAIN;
    }

    ctx->state = njt_http_grpc_st_start;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc window update: %ui", ctx->window_update);

    if (ctx->stream_id) {

        if (ctx->window_update > (size_t) NJT_HTTP_V2_MAX_WINDOW
                                 - ctx->send_window)
        {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "upstream sent too large window update");
            return NJT_ERROR;
        }

        ctx->send_window += ctx->window_update;

    } else {

        if (ctx->window_update > NJT_HTTP_V2_MAX_WINDOW
                                 - ctx->connection->send_window)
        {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "upstream sent too large window update");
            return NJT_ERROR;
        }

        ctx->connection->send_window += ctx->window_update;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_grpc_parse_settings(njt_http_request_t *r, njt_http_grpc_ctx_t *ctx,
    njt_buf_t *b)
{
    u_char   ch, *p, *last;
    ssize_t  window_update;
    enum {
        sw_start = 0,
        sw_id,
        sw_id_2,
        sw_value,
        sw_value_2,
        sw_value_3,
        sw_value_4
    } state;

    if (b->last - b->pos < (ssize_t) ctx->rest) {
        last = b->last;

    } else {
        last = b->pos + ctx->rest;
    }

    state = ctx->frame_state;

    if (state == sw_start) {

        if (ctx->stream_id) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "upstream sent settings frame "
                          "with non-zero stream id: %ui",
                          ctx->stream_id);
            return NJT_ERROR;
        }

        if (ctx->flags & NJT_HTTP_V2_ACK_FLAG) {
            njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc settings ack");

            if (ctx->rest != 0) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream sent settings frame "
                              "with ack flag and non-zero length: %uz",
                              ctx->rest);
                return NJT_ERROR;
            }

            ctx->state = njt_http_grpc_st_start;

            return NJT_OK;
        }

        if (ctx->rest % 6 != 0) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "upstream sent settings frame "
                          "with invalid length: %uz",
                          ctx->rest);
            return NJT_ERROR;
        }

        if (ctx->free == NULL && ctx->settings++ > 1000) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "upstream sent too many settings frames");
            return NJT_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc settings byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
        case sw_id:
            ctx->setting_id = ch << 8;
            state = sw_id_2;
            break;

        case sw_id_2:
            ctx->setting_id |= ch;
            state = sw_value;
            break;

        case sw_value:
            ctx->setting_value = (njt_uint_t) ch << 24;
            state = sw_value_2;
            break;

        case sw_value_2:
            ctx->setting_value |= ch << 16;
            state = sw_value_3;
            break;

        case sw_value_3:
            ctx->setting_value |= ch << 8;
            state = sw_value_4;
            break;

        case sw_value_4:
            ctx->setting_value |= ch;
            state = sw_id;

            njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc setting: %ui %ui",
                           ctx->setting_id, ctx->setting_value);

            /*
             * The following settings are defined by the protocol:
             *
             * SETTINGS_HEADER_TABLE_SIZE, SETTINGS_ENABLE_PUSH,
             * SETTINGS_MAX_CONCURRENT_STREAMS, SETTINGS_INITIAL_WINDOW_SIZE,
             * SETTINGS_MAX_FRAME_SIZE, SETTINGS_MAX_HEADER_LIST_SIZE
             *
             * Only SETTINGS_INITIAL_WINDOW_SIZE seems to be needed in
             * a simple client.
             */

            if (ctx->setting_id == 0x04) {
                /* SETTINGS_INITIAL_WINDOW_SIZE */

                if (ctx->setting_value > NJT_HTTP_V2_MAX_WINDOW) {
                    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                  "upstream sent settings frame "
                                  "with too large initial window size: %ui",
                                  ctx->setting_value);
                    return NJT_ERROR;
                }

                window_update = ctx->setting_value
                                - ctx->connection->init_window;
                ctx->connection->init_window = ctx->setting_value;

                if (ctx->send_window > 0
                    && window_update > (ssize_t) NJT_HTTP_V2_MAX_WINDOW
                                       - ctx->send_window)
                {
                    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                  "upstream sent settings frame "
                                  "with too large initial window size: %ui",
                                  ctx->setting_value);
                    return NJT_ERROR;
                }

                ctx->send_window += window_update;
            }

            break;
        }
    }

    ctx->rest -= p - b->pos;
    ctx->frame_state = state;
    b->pos = p;

    if (ctx->rest > 0) {
        return NJT_AGAIN;
    }

    ctx->state = njt_http_grpc_st_start;

    return njt_http_grpc_send_settings_ack(r, ctx);
}


static njt_int_t
njt_http_grpc_parse_ping(njt_http_request_t *r,
    njt_http_grpc_ctx_t *ctx, njt_buf_t *b)
{
    u_char  ch, *p, *last;
    enum {
        sw_start = 0,
        sw_data_2,
        sw_data_3,
        sw_data_4,
        sw_data_5,
        sw_data_6,
        sw_data_7,
        sw_data_8
    } state;

    if (b->last - b->pos < (ssize_t) ctx->rest) {
        last = b->last;

    } else {
        last = b->pos + ctx->rest;
    }

    state = ctx->frame_state;

    if (state == sw_start) {

        if (ctx->stream_id) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "upstream sent ping frame "
                          "with non-zero stream id: %ui",
                          ctx->stream_id);
            return NJT_ERROR;
        }

        if (ctx->rest != 8) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "upstream sent ping frame "
                          "with invalid length: %uz",
                          ctx->rest);
            return NJT_ERROR;
        }

        if (ctx->flags & NJT_HTTP_V2_ACK_FLAG) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "upstream sent ping frame with ack flag");
            return NJT_ERROR;
        }

        if (ctx->free == NULL && ctx->pings++ > 1000) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "upstream sent too many ping frames");
            return NJT_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "grpc ping byte: %02Xd s:%d", ch, state);
#endif

        if (state < sw_data_8) {
            ctx->ping_data[state] = ch;
            state++;

        } else {
            ctx->ping_data[7] = ch;
            state = sw_start;

            njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "grpc ping");
        }
    }

    ctx->rest -= p - b->pos;
    ctx->frame_state = state;
    b->pos = p;

    if (ctx->rest > 0) {
        return NJT_AGAIN;
    }

    ctx->state = njt_http_grpc_st_start;

    return njt_http_grpc_send_ping_ack(r, ctx);
}


static njt_int_t
njt_http_grpc_send_settings_ack(njt_http_request_t *r, njt_http_grpc_ctx_t *ctx)
{
    njt_chain_t            *cl, **ll;
    njt_http_grpc_frame_t  *f;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc send settings ack");

    for (cl = ctx->out, ll = &ctx->out; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = njt_http_grpc_get_buf(r, ctx);
    if (cl == NULL) {
        return NJT_ERROR;
    }

    f = (njt_http_grpc_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(njt_http_grpc_frame_t);

    f->length_0 = 0;
    f->length_1 = 0;
    f->length_2 = 0;
    f->type = NJT_HTTP_V2_SETTINGS_FRAME;
    f->flags = NJT_HTTP_V2_ACK_FLAG;
    f->stream_id_0 = 0;
    f->stream_id_1 = 0;
    f->stream_id_2 = 0;
    f->stream_id_3 = 0;

    *ll = cl;

    return NJT_OK;
}


static njt_int_t
njt_http_grpc_send_ping_ack(njt_http_request_t *r, njt_http_grpc_ctx_t *ctx)
{
    njt_chain_t            *cl, **ll;
    njt_http_grpc_frame_t  *f;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc send ping ack");

    for (cl = ctx->out, ll = &ctx->out; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = njt_http_grpc_get_buf(r, ctx);
    if (cl == NULL) {
        return NJT_ERROR;
    }

    f = (njt_http_grpc_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(njt_http_grpc_frame_t);

    f->length_0 = 0;
    f->length_1 = 0;
    f->length_2 = 8;
    f->type = NJT_HTTP_V2_PING_FRAME;
    f->flags = NJT_HTTP_V2_ACK_FLAG;
    f->stream_id_0 = 0;
    f->stream_id_1 = 0;
    f->stream_id_2 = 0;
    f->stream_id_3 = 0;

    cl->buf->last = njt_copy(cl->buf->last, ctx->ping_data, 8);

    *ll = cl;

    return NJT_OK;
}


static njt_int_t
njt_http_grpc_send_window_update(njt_http_request_t *r,
    njt_http_grpc_ctx_t *ctx)
{
    size_t                  n;
    njt_chain_t            *cl, **ll;
    njt_http_grpc_frame_t  *f;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "grpc send window update: %uz %uz",
                   ctx->connection->recv_window, ctx->recv_window);

    for (cl = ctx->out, ll = &ctx->out; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = njt_http_grpc_get_buf(r, ctx);
    if (cl == NULL) {
        return NJT_ERROR;
    }

    f = (njt_http_grpc_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(njt_http_grpc_frame_t);

    f->length_0 = 0;
    f->length_1 = 0;
    f->length_2 = 4;
    f->type = NJT_HTTP_V2_WINDOW_UPDATE_FRAME;
    f->flags = 0;
    f->stream_id_0 = 0;
    f->stream_id_1 = 0;
    f->stream_id_2 = 0;
    f->stream_id_3 = 0;

    n = NJT_HTTP_V2_MAX_WINDOW - ctx->connection->recv_window;
    ctx->connection->recv_window = NJT_HTTP_V2_MAX_WINDOW;

    *cl->buf->last++ = (u_char) ((n >> 24) & 0xff);
    *cl->buf->last++ = (u_char) ((n >> 16) & 0xff);
    *cl->buf->last++ = (u_char) ((n >> 8) & 0xff);
    *cl->buf->last++ = (u_char) (n & 0xff);

    f = (njt_http_grpc_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(njt_http_grpc_frame_t);

    f->length_0 = 0;
    f->length_1 = 0;
    f->length_2 = 4;
    f->type = NJT_HTTP_V2_WINDOW_UPDATE_FRAME;
    f->flags = 0;
    f->stream_id_0 = (u_char) ((ctx->id >> 24) & 0xff);
    f->stream_id_1 = (u_char) ((ctx->id >> 16) & 0xff);
    f->stream_id_2 = (u_char) ((ctx->id >> 8) & 0xff);
    f->stream_id_3 = (u_char) (ctx->id & 0xff);

    n = NJT_HTTP_V2_MAX_WINDOW - ctx->recv_window;
    ctx->recv_window = NJT_HTTP_V2_MAX_WINDOW;

    *cl->buf->last++ = (u_char) ((n >> 24) & 0xff);
    *cl->buf->last++ = (u_char) ((n >> 16) & 0xff);
    *cl->buf->last++ = (u_char) ((n >> 8) & 0xff);
    *cl->buf->last++ = (u_char) (n & 0xff);

    *ll = cl;

    return NJT_OK;
}


static njt_chain_t *
njt_http_grpc_get_buf(njt_http_request_t *r, njt_http_grpc_ctx_t *ctx)
{
    u_char       *start;
    njt_buf_t    *b;
    njt_chain_t  *cl;

    cl = njt_chain_get_free_buf(r->pool, &ctx->free);
    if (cl == NULL) {
        return NULL;
    }

    b = cl->buf;
    start = b->start;

    if (start == NULL) {

        /*
         * each buffer is large enough to hold two window update
         * frames in a row
         */

        start = njt_palloc(r->pool, 2 * sizeof(njt_http_grpc_frame_t) + 8);
        if (start == NULL) {
            return NULL;
        }

    }

    njt_memzero(b, sizeof(njt_buf_t));

    b->start = start;
    b->pos = start;
    b->last = start;
    b->end = start + 2 * sizeof(njt_http_grpc_frame_t) + 8;

    b->tag = (njt_buf_tag_t) &njt_http_grpc_body_output_filter;
    b->temporary = 1;
    b->flush = 1;

    return cl;
}


static njt_http_grpc_ctx_t *
njt_http_grpc_get_ctx(njt_http_request_t *r)
{
    njt_http_grpc_ctx_t  *ctx;
    njt_http_upstream_t  *u;

    ctx = njt_http_get_module_ctx(r, njt_http_grpc_module);

    if (ctx->connection == NULL) {
        u = r->upstream;

        if (njt_http_grpc_get_connection_data(r, ctx, &u->peer) != NJT_OK) {
            return NULL;
        }
    }

    return ctx;
}


static njt_int_t
njt_http_grpc_get_connection_data(njt_http_request_t *r,
    njt_http_grpc_ctx_t *ctx, njt_peer_connection_t *pc)
{
    njt_connection_t    *c;
    njt_pool_cleanup_t  *cln;

    c = pc->connection;

    if (pc->cached) {

        /*
         * for cached connections, connection data can be found
         * in the cleanup handler
         */

        for (cln = c->pool->cleanup; cln; cln = cln->next) {
            if (cln->handler == njt_http_grpc_cleanup) {
                ctx->connection = cln->data;
                break;
            }
        }

        if (ctx->connection == NULL) {
            njt_log_error(NJT_LOG_ERR, c->log, 0,
                          "no connection data found for "
                          "keepalive http2 connection");
            return NJT_ERROR;
        }

        ctx->send_window = ctx->connection->init_window;
        ctx->recv_window = NJT_HTTP_V2_MAX_WINDOW;

        ctx->connection->last_stream_id += 2;
        ctx->id = ctx->connection->last_stream_id;

        return NJT_OK;
    }

    cln = njt_pool_cleanup_add(c->pool, sizeof(njt_http_grpc_conn_t));
    if (cln == NULL) {
        return NJT_ERROR;
    }

    cln->handler = njt_http_grpc_cleanup;
    ctx->connection = cln->data;

    ctx->connection->init_window = NJT_HTTP_V2_DEFAULT_WINDOW;
    ctx->connection->send_window = NJT_HTTP_V2_DEFAULT_WINDOW;
    ctx->connection->recv_window = NJT_HTTP_V2_MAX_WINDOW;

    ctx->send_window = NJT_HTTP_V2_DEFAULT_WINDOW;
    ctx->recv_window = NJT_HTTP_V2_MAX_WINDOW;

    ctx->id = 1;
    ctx->connection->last_stream_id = 1;

    return NJT_OK;
}


static void
njt_http_grpc_cleanup(void *data)
{
#if 0
    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "grpc cleanup");
#endif
    return;
}


static void
njt_http_grpc_abort_request(njt_http_request_t *r)
{
    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort grpc request");
    return;
}


static void
njt_http_grpc_finalize_request(njt_http_request_t *r, njt_int_t rc)
{
    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize grpc request");
    return;
}


static njt_int_t
njt_http_grpc_internal_trailers_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_table_elt_t  *te;

    te = r->headers_in.te;

    if (te == NULL) {
        v->not_found = 1;
        return NJT_OK;
    }

    if (njt_strlcasestrn(te->value.data, te->value.data + te->value.len,
                         (u_char *) "trailers", 8 - 1)
        == NULL)
    {
        v->not_found = 1;
        return NJT_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = (u_char *) "trailers";
    v->len = sizeof("trailers") - 1;

    return NJT_OK;
}


static njt_int_t
njt_http_grpc_add_variables(njt_conf_t *cf)
{
    njt_http_variable_t  *var, *v;

    for (v = njt_http_grpc_vars; v->name.len; v++) {
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
njt_http_grpc_create_loc_conf(njt_conf_t *cf)
{
    njt_http_grpc_loc_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_grpc_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->upstream.ignore_headers = 0;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.hide_headers_hash = { NULL, 0 };
     *
     *     conf->headers.lengths = NULL;
     *     conf->headers.values = NULL;
     *     conf->headers.hash = { NULL, 0 };
     *     conf->host = { 0, NULL };
     *     conf->host_set = 0;
     *     conf->ssl = 0;
     *     conf->ssl_protocols = 0;
     *     conf->ssl_ciphers = { 0, NULL };
     *     conf->ssl_trusted_certificate = { 0, NULL };
     *     conf->ssl_crl = { 0, NULL };
     */

    conf->upstream.local = NJT_CONF_UNSET_PTR;
    conf->upstream.socket_keepalive = NJT_CONF_UNSET;
    conf->upstream.next_upstream_tries = NJT_CONF_UNSET_UINT;
    conf->upstream.connect_timeout = NJT_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NJT_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NJT_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_timeout = NJT_CONF_UNSET_MSEC;

    conf->upstream.buffer_size = NJT_CONF_UNSET_SIZE;

    conf->upstream.hide_headers = NJT_CONF_UNSET_PTR;
    conf->upstream.pass_headers = NJT_CONF_UNSET_PTR;

    conf->upstream.intercept_errors = NJT_CONF_UNSET;

#if (NJT_HTTP_SSL)
    conf->upstream.ssl_session_reuse = NJT_CONF_UNSET;
    conf->upstream.ssl_name = NJT_CONF_UNSET_PTR;
    conf->upstream.ssl_server_name = NJT_CONF_UNSET;
    conf->upstream.ssl_verify = NJT_CONF_UNSET;
    conf->ssl_verify_depth = NJT_CONF_UNSET_UINT;
    conf->upstream.ssl_certificate = NJT_CONF_UNSET_PTR;
    conf->upstream.ssl_certificate_key = NJT_CONF_UNSET_PTR;
    conf->upstream.ssl_passwords = NJT_CONF_UNSET_PTR;
    conf->ssl_conf_commands = NJT_CONF_UNSET_PTR;
#endif

    /* the hardcoded values */
    conf->upstream.cyclic_temp_file = 0;
    conf->upstream.buffering = 0;
    conf->upstream.ignore_client_abort = 0;
    conf->upstream.send_lowat = 0;
    conf->upstream.bufs.num = 0;
    conf->upstream.busy_buffers_size = 0;
    conf->upstream.max_temp_file_size = 0;
    conf->upstream.temp_file_write_size = 0;
    conf->upstream.pass_request_headers = 1;
    conf->upstream.pass_request_body = 1;
    conf->upstream.force_ranges = 0;
    conf->upstream.pass_trailers = 1;
    conf->upstream.preserve_output = 1;

    conf->headers_source = NJT_CONF_UNSET_PTR;

    njt_str_set(&conf->upstream.module, "grpc");

    return conf;
}


static char *
njt_http_grpc_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_grpc_loc_conf_t *prev = parent;
    njt_http_grpc_loc_conf_t *conf = child;

    njt_int_t                  rc;
    njt_hash_init_t            hash;
    njt_http_core_loc_conf_t  *clcf;

    njt_conf_merge_ptr_value(conf->upstream.local,
                              prev->upstream.local, NULL);

    njt_conf_merge_value(conf->upstream.socket_keepalive,
                              prev->upstream.socket_keepalive, 0);

    njt_conf_merge_uint_value(conf->upstream.next_upstream_tries,
                              prev->upstream.next_upstream_tries, 0);

    njt_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    njt_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    njt_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    njt_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
                              prev->upstream.next_upstream_timeout, 0);

    njt_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) njt_pagesize);

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

    njt_conf_merge_value(conf->upstream.intercept_errors,
                              prev->upstream.intercept_errors, 0);

#if (NJT_HTTP_SSL)

    if (njt_http_grpc_merge_ssl(cf, conf, prev) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    njt_conf_merge_value(conf->upstream.ssl_session_reuse,
                              prev->upstream.ssl_session_reuse, 1);

    njt_conf_merge_bitmask_value(conf->ssl_protocols, prev->ssl_protocols,
                                 (NJT_CONF_BITMASK_SET
                                  |NJT_SSL_TLSv1|NJT_SSL_TLSv1_1
                                  |NJT_SSL_TLSv1_2|NJT_SSL_TLSv1_3));

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

    njt_conf_merge_ptr_value(conf->upstream.ssl_certificate,
                              prev->upstream.ssl_certificate, NULL);
    njt_conf_merge_ptr_value(conf->upstream.ssl_certificate_key,
                              prev->upstream.ssl_certificate_key, NULL);
    njt_conf_merge_ptr_value(conf->upstream.ssl_passwords,
                              prev->upstream.ssl_passwords, NULL);

    njt_conf_merge_ptr_value(conf->ssl_conf_commands,
                              prev->ssl_conf_commands, NULL);

    if (conf->ssl && njt_http_grpc_set_ssl(cf, conf) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

#endif

    hash.max_size = 512;
    hash.bucket_size = njt_align(64, njt_cacheline_size);
    hash.name = "grpc_headers_hash";

    if (njt_http_upstream_hide_headers_hash(cf, &conf->upstream,
            &prev->upstream, njt_http_grpc_hide_headers, &hash)
        != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);

    if (clcf->noname
        && conf->upstream.upstream == NULL && conf->grpc_lengths == NULL)
    {
        conf->upstream.upstream = prev->upstream.upstream;
        conf->host = prev->host;

        conf->grpc_lengths = prev->grpc_lengths;
        conf->grpc_values = prev->grpc_values;

#if (NJT_HTTP_SSL)
        conf->ssl = prev->ssl;
#endif
    }

    if (clcf->lmt_excpt && clcf->handler == NULL
        && (conf->upstream.upstream || conf->grpc_lengths))
    {
        clcf->handler = njt_http_grpc_handler;
    }

    njt_conf_merge_ptr_value(conf->headers_source, prev->headers_source, NULL);

    if (conf->headers_source == prev->headers_source) {
        conf->headers = prev->headers;
        conf->host_set = prev->host_set;
    }

    rc = njt_http_grpc_init_headers(cf, conf, &conf->headers,
                                    njt_http_grpc_headers);
    if (rc != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    /*
     * special handling to preserve conf->headers in the "http" section
     * to inherit it to all servers
     */

    if (prev->headers.hash.buckets == NULL
        && conf->headers_source == prev->headers_source)
    {
        prev->headers = conf->headers;
        prev->host_set = conf->host_set;
    }

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_grpc_init_headers(njt_conf_t *cf, njt_http_grpc_loc_conf_t *conf,
    njt_http_grpc_headers_t *headers, njt_keyval_t *default_headers)
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

            if (src[i].key.len == 4
                && njt_strncasecmp(src[i].key.data, (u_char *) "Host", 4) == 0)
            {
                conf->host_set = 1;
            }

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
    hash.max_size = 512;
    hash.bucket_size = 64;
    hash.name = "grpc_headers_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    return njt_hash_init(&hash, headers_names.elts, headers_names.nelts);
}


static char *
njt_http_grpc_pass(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_grpc_loc_conf_t *glcf = conf;

    size_t                      add;
    njt_str_t                  *value, *url;
    njt_url_t                   u;
    njt_uint_t                  n;
    njt_http_core_loc_conf_t   *clcf;
    njt_http_script_compile_t   sc;

    if (glcf->upstream.upstream || glcf->grpc_lengths) {
        return "is duplicate";
    }

    clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);

    clcf->handler = njt_http_grpc_handler;

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
        sc.lengths = &glcf->grpc_lengths;
        sc.values = &glcf->grpc_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (njt_http_script_compile(&sc) != NJT_OK) {
            return NJT_CONF_ERROR;
        }

#if (NJT_HTTP_SSL)
        glcf->ssl = 1;
#endif

        return NJT_CONF_OK;
    }

    if (njt_strncasecmp(url->data, (u_char *) "grpc://", 7) == 0) {
        add = 7;

    } else if (njt_strncasecmp(url->data, (u_char *) "grpcs://", 8) == 0) {

#if (NJT_HTTP_SSL)
        glcf->ssl = 1;

        add = 8;
#else
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "grpcs protocol requires SSL support");
        return NJT_CONF_ERROR;
#endif

    } else {
        add = 0;
    }

    njt_memzero(&u, sizeof(njt_url_t));

    u.url.len = url->len - add;
    u.url.data = url->data + add;
    u.no_resolve = 1;

    glcf->upstream.upstream = njt_http_upstream_add(cf, &u, 0);
    if (glcf->upstream.upstream == NULL) {
        return NJT_CONF_ERROR;
    }

    if (u.family != AF_UNIX) {

        if (u.no_port) {
            glcf->host = u.host;

        } else {
            glcf->host.len = u.host.len + 1 + u.port_text.len;
            glcf->host.data = u.host.data;
        }

    } else {
        njt_str_set(&glcf->host, "localhost");
    }

    return NJT_CONF_OK;
}


#if (NJT_HTTP_SSL)

static char *
njt_http_grpc_ssl_password_file(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_grpc_loc_conf_t *glcf = conf;

    njt_str_t  *value;

    if (glcf->upstream.ssl_passwords != NJT_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    glcf->upstream.ssl_passwords = njt_ssl_read_password_file(cf, &value[1]);

    if (glcf->upstream.ssl_passwords == NULL) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static char *
njt_http_grpc_ssl_conf_command_check(njt_conf_t *cf, void *post, void *data)
{
#ifndef SSL_CONF_FLAG_FILE
    return "is not supported on this platform";
#else
    return NJT_CONF_OK;
#endif
}


static njt_int_t
njt_http_grpc_merge_ssl(njt_conf_t *cf, njt_http_grpc_loc_conf_t *conf,
    njt_http_grpc_loc_conf_t *prev)
{
    njt_uint_t  preserve;

    if (conf->ssl_protocols == 0
        && conf->ssl_ciphers.data == NULL
        && conf->upstream.ssl_certificate == NJT_CONF_UNSET_PTR
        && conf->upstream.ssl_certificate_key == NJT_CONF_UNSET_PTR
        && conf->upstream.ssl_passwords == NJT_CONF_UNSET_PTR
        && conf->upstream.ssl_verify == NJT_CONF_UNSET
        && conf->ssl_verify_depth == NJT_CONF_UNSET_UINT
        && conf->ssl_trusted_certificate.data == NULL
        && conf->ssl_crl.data == NULL
        && conf->upstream.ssl_session_reuse == NJT_CONF_UNSET
        && conf->ssl_conf_commands == NJT_CONF_UNSET_PTR)
    {
        if (prev->upstream.ssl) {
            conf->upstream.ssl = prev->upstream.ssl;
            return NJT_OK;
        }

        preserve = 1;

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
    }

    return NJT_OK;
}


static njt_int_t
njt_http_grpc_set_ssl(njt_conf_t *cf, njt_http_grpc_loc_conf_t *glcf)
{
    njt_pool_cleanup_t  *cln;

    if (glcf->upstream.ssl->ctx) {
        return NJT_OK;
    }

    if (njt_ssl_create(glcf->upstream.ssl, glcf->ssl_protocols, NULL)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    cln = njt_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        njt_ssl_cleanup_ctx(glcf->upstream.ssl);
        return NJT_ERROR;
    }

    cln->handler = njt_ssl_cleanup_ctx;
    cln->data = glcf->upstream.ssl;

    if (njt_ssl_ciphers(cf, glcf->upstream.ssl, &glcf->ssl_ciphers, 0)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    if (glcf->upstream.ssl_certificate
        && glcf->upstream.ssl_certificate->value.len)
    {
        if (glcf->upstream.ssl_certificate_key == NULL) {
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "no \"grpc_ssl_certificate_key\" is defined "
                          "for certificate \"%V\"",
                          &glcf->upstream.ssl_certificate->value);
            return NJT_ERROR;
        }

        if (glcf->upstream.ssl_certificate->lengths
            || glcf->upstream.ssl_certificate_key->lengths)
        {
            glcf->upstream.ssl_passwords =
                  njt_ssl_preserve_passwords(cf, glcf->upstream.ssl_passwords);
            if (glcf->upstream.ssl_passwords == NULL) {
                return NJT_ERROR;
            }

        } else {
            if (njt_ssl_certificate(cf, glcf->upstream.ssl,
                                    &glcf->upstream.ssl_certificate->value,
                                    &glcf->upstream.ssl_certificate_key->value,
                                    glcf->upstream.ssl_passwords)
                != NJT_OK)
            {
                return NJT_ERROR;
            }
        }
    }

    if (glcf->upstream.ssl_verify) {
        if (glcf->ssl_trusted_certificate.len == 0) {
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                      "no grpc_ssl_trusted_certificate for grpc_ssl_verify");
            return NJT_ERROR;
        }

        if (njt_ssl_trusted_certificate(cf, glcf->upstream.ssl,
                                        &glcf->ssl_trusted_certificate,
                                        glcf->ssl_verify_depth)
            != NJT_OK)
        {
            return NJT_ERROR;
        }

        if (njt_ssl_crl(cf, glcf->upstream.ssl, &glcf->ssl_crl) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    if (njt_ssl_client_session_cache(cf, glcf->upstream.ssl,
                                     glcf->upstream.ssl_session_reuse)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation

    if (SSL_CTX_set_alpn_protos(glcf->upstream.ssl->ctx,
                                (u_char *) "\x02h2", 3)
        != 0)
    {
        njt_ssl_error(NJT_LOG_EMERG, cf->log, 0,
                      "SSL_CTX_set_alpn_protos() failed");
        return NJT_ERROR;
    }

#endif

    if (njt_ssl_conf_commands(cf, glcf->upstream.ssl, glcf->ssl_conf_commands)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    return NJT_OK;
}
void *njt_http_grpc_hc_get_up_uptream(void *pglcf) {
    return ((njt_http_grpc_loc_conf_t *)pglcf)->upstream.upstream;
}
void *njt_http_grpc_hc_get_uptream(void *pglcf) {
    return &((njt_http_grpc_loc_conf_t *)pglcf)->upstream;
}


njt_array_t *njt_http_grpc_hc_get_lengths(void *pglcf) {
    return ((njt_http_grpc_loc_conf_t *)pglcf)->grpc_lengths;
}


njt_shm_zone_t *njt_http_grpc_hc_get_shm_zone(void *pglcf) {
    return ((njt_http_grpc_loc_conf_t *)pglcf)->upstream.upstream->shm_zone;
}
void *njt_http_grpc_hc_create_grpc_on(njt_pool_t *pool) {
    njt_http_grpc_conn_t                 *grpc_con;

    grpc_con = njt_pcalloc(pool, sizeof(njt_http_grpc_conn_t));
    if (grpc_con == NULL) {
        return NULL;
    };
    grpc_con->init_window = NJT_HTTP_V2_DEFAULT_WINDOW;
    grpc_con->send_window = NJT_HTTP_V2_DEFAULT_WINDOW;
    grpc_con->recv_window = NJT_HTTP_V2_MAX_WINDOW;

    return grpc_con;
}
void *njt_http_grpc_hc_create_in_filter_ctx(njt_pool_t *pool, void *r, void *grpc_con) {
    njt_http_grpc_ctx_t                 *ctx;

    ctx = njt_pcalloc(pool, sizeof(njt_http_grpc_ctx_t));
    if (ctx == NULL) {
        return NULL;
    };
    ctx->connection = (njt_http_grpc_conn_t *)grpc_con;
    ctx->send_window = NJT_HTTP_V2_DEFAULT_WINDOW;
    ctx->recv_window = NJT_HTTP_V2_MAX_WINDOW;
    ctx->id = 1;
    ctx->connection->last_stream_id = 1;
    ctx->request = (njt_http_request_t *)r;
    ctx->in = njt_pcalloc(pool, sizeof(njt_chain_t));
    if (ctx->in == NULL) {
        return NULL;
    };
    ctx->in->buf = njt_pcalloc(pool, sizeof(njt_buf_t));
    if (ctx->in->buf == NULL) {
        return NULL;
    };

    return ctx;
}
void njt_http_grpc_hc_set_upstream(njt_http_upstream_t *u)
{
    u->create_request = njt_http_grpc_create_request;
    u->reinit_request = njt_http_grpc_reinit_request;
    u->process_header = njt_http_grpc_process_header;
    u->abort_request = njt_http_grpc_abort_request;
    u->finalize_request = njt_http_grpc_finalize_request;

    u->input_filter_init = njt_http_grpc_filter_init;
    u->input_filter = njt_http_grpc_filter;
}
#endif
