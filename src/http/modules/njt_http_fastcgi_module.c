
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


typedef struct {
    njt_array_t                    caches;  /* njt_http_file_cache_t * */
} njt_http_fastcgi_main_conf_t;


typedef struct {
    njt_array_t                   *flushes;
    njt_array_t                   *lengths;
    njt_array_t                   *values;
    njt_uint_t                     number;
    njt_hash_t                     hash;
} njt_http_fastcgi_params_t;


typedef struct {
    njt_http_upstream_conf_t       upstream;

    njt_str_t                      index;

    njt_http_fastcgi_params_t      params;
#if (NJT_HTTP_CACHE)
    njt_http_fastcgi_params_t      params_cache;
#endif

    njt_array_t                   *params_source;
    njt_array_t                   *catch_stderr;

    njt_array_t                   *fastcgi_lengths;
    njt_array_t                   *fastcgi_values;

    njt_flag_t                     keep_conn;

#if (NJT_HTTP_CACHE)
    njt_http_complex_value_t       cache_key;
#endif

#if (NJT_PCRE)
    njt_regex_t                   *split_regex;
    njt_str_t                      split_name;
#endif
} njt_http_fastcgi_loc_conf_t;


typedef enum {
    njt_http_fastcgi_st_version = 0,
    njt_http_fastcgi_st_type,
    njt_http_fastcgi_st_request_id_hi,
    njt_http_fastcgi_st_request_id_lo,
    njt_http_fastcgi_st_content_length_hi,
    njt_http_fastcgi_st_content_length_lo,
    njt_http_fastcgi_st_padding_length,
    njt_http_fastcgi_st_reserved,
    njt_http_fastcgi_st_data,
    njt_http_fastcgi_st_padding
} njt_http_fastcgi_state_e;


typedef struct {
    u_char                        *start;
    u_char                        *end;
} njt_http_fastcgi_split_part_t;


typedef struct {
    njt_http_fastcgi_state_e       state;
    u_char                        *pos;
    u_char                        *last;
    njt_uint_t                     type;
    size_t                         length;
    size_t                         padding;

    off_t                          rest;

    njt_chain_t                   *free;
    njt_chain_t                   *busy;

    unsigned                       fastcgi_stdout:1;
    unsigned                       large_stderr:1;
    unsigned                       header_sent:1;
    unsigned                       closed:1;

    njt_array_t                   *split_parts;

    njt_str_t                      script_name;
    njt_str_t                      path_info;
} njt_http_fastcgi_ctx_t;


#define NJT_HTTP_FASTCGI_RESPONDER      1

#define NJT_HTTP_FASTCGI_KEEP_CONN      1

#define NJT_HTTP_FASTCGI_BEGIN_REQUEST  1
#define NJT_HTTP_FASTCGI_ABORT_REQUEST  2
#define NJT_HTTP_FASTCGI_END_REQUEST    3
#define NJT_HTTP_FASTCGI_PARAMS         4
#define NJT_HTTP_FASTCGI_STDIN          5
#define NJT_HTTP_FASTCGI_STDOUT         6
#define NJT_HTTP_FASTCGI_STDERR         7
#define NJT_HTTP_FASTCGI_DATA           8


typedef struct {
    u_char  version;
    u_char  type;
    u_char  request_id_hi;
    u_char  request_id_lo;
    u_char  content_length_hi;
    u_char  content_length_lo;
    u_char  padding_length;
    u_char  reserved;
} njt_http_fastcgi_header_t;


typedef struct {
    u_char  role_hi;
    u_char  role_lo;
    u_char  flags;
    u_char  reserved[5];
} njt_http_fastcgi_begin_request_t;


typedef struct {
    u_char  version;
    u_char  type;
    u_char  request_id_hi;
    u_char  request_id_lo;
} njt_http_fastcgi_header_small_t;


typedef struct {
    njt_http_fastcgi_header_t         h0;
    njt_http_fastcgi_begin_request_t  br;
    njt_http_fastcgi_header_small_t   h1;
} njt_http_fastcgi_request_start_t;


static njt_int_t njt_http_fastcgi_eval(njt_http_request_t *r,
    njt_http_fastcgi_loc_conf_t *flcf);
#if (NJT_HTTP_CACHE)
static njt_int_t njt_http_fastcgi_create_key(njt_http_request_t *r);
#endif
static njt_int_t njt_http_fastcgi_create_request(njt_http_request_t *r);
static njt_int_t njt_http_fastcgi_reinit_request(njt_http_request_t *r);
static njt_int_t njt_http_fastcgi_body_output_filter(void *data,
    njt_chain_t *in);
static njt_int_t njt_http_fastcgi_process_header(njt_http_request_t *r);
static njt_int_t njt_http_fastcgi_input_filter_init(void *data);
static njt_int_t njt_http_fastcgi_input_filter(njt_event_pipe_t *p,
    njt_buf_t *buf);
static njt_int_t njt_http_fastcgi_non_buffered_filter(void *data,
    ssize_t bytes);
static njt_int_t njt_http_fastcgi_process_record(njt_http_request_t *r,
    njt_http_fastcgi_ctx_t *f);
static void njt_http_fastcgi_abort_request(njt_http_request_t *r);
static void njt_http_fastcgi_finalize_request(njt_http_request_t *r,
    njt_int_t rc);

static njt_int_t njt_http_fastcgi_add_variables(njt_conf_t *cf);
static void *njt_http_fastcgi_create_main_conf(njt_conf_t *cf);
static void *njt_http_fastcgi_create_loc_conf(njt_conf_t *cf);
static char *njt_http_fastcgi_merge_loc_conf(njt_conf_t *cf,
    void *parent, void *child);
static njt_int_t njt_http_fastcgi_init_params(njt_conf_t *cf,
    njt_http_fastcgi_loc_conf_t *conf, njt_http_fastcgi_params_t *params,
    njt_keyval_t *default_params);

static njt_int_t njt_http_fastcgi_script_name_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_int_t njt_http_fastcgi_path_info_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data);
static njt_http_fastcgi_ctx_t *njt_http_fastcgi_split(njt_http_request_t *r,
    njt_http_fastcgi_loc_conf_t *flcf);

static char *njt_http_fastcgi_pass(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_fastcgi_split_path_info(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);
static char *njt_http_fastcgi_store(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
#if (NJT_HTTP_CACHE)
static char *njt_http_fastcgi_cache(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_fastcgi_cache_key(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
#endif

static char *njt_http_fastcgi_lowat_check(njt_conf_t *cf, void *post,
    void *data);


static njt_conf_post_t  njt_http_fastcgi_lowat_post =
    { njt_http_fastcgi_lowat_check };


static njt_conf_bitmask_t  njt_http_fastcgi_next_upstream_masks[] = {
    { njt_string("error"), NJT_HTTP_UPSTREAM_FT_ERROR },
    { njt_string("timeout"), NJT_HTTP_UPSTREAM_FT_TIMEOUT },
    { njt_string("invalid_header"), NJT_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { njt_string("non_idempotent"), NJT_HTTP_UPSTREAM_FT_NON_IDEMPOTENT },
    { njt_string("http_500"), NJT_HTTP_UPSTREAM_FT_HTTP_500 },
    { njt_string("http_503"), NJT_HTTP_UPSTREAM_FT_HTTP_503 },
    { njt_string("http_403"), NJT_HTTP_UPSTREAM_FT_HTTP_403 },
    { njt_string("http_404"), NJT_HTTP_UPSTREAM_FT_HTTP_404 },
    { njt_string("http_429"), NJT_HTTP_UPSTREAM_FT_HTTP_429 },
    { njt_string("updating"), NJT_HTTP_UPSTREAM_FT_UPDATING },
    { njt_string("off"), NJT_HTTP_UPSTREAM_FT_OFF },
    { njt_null_string, 0 }
};


njt_module_t  njt_http_fastcgi_module;


static njt_command_t  njt_http_fastcgi_commands[] = {

    { njt_string("fastcgi_pass"),
      NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE1,
      njt_http_fastcgi_pass,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("fastcgi_index"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, index),
      NULL },

    { njt_string("fastcgi_split_path_info"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_fastcgi_split_path_info,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("fastcgi_store"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_fastcgi_store,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("fastcgi_store_access"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE123,
      njt_conf_set_access_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.store_access),
      NULL },

    { njt_string("fastcgi_buffering"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.buffering),
      NULL },

    { njt_string("fastcgi_request_buffering"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.request_buffering),
      NULL },

    { njt_string("fastcgi_ignore_client_abort"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.ignore_client_abort),
      NULL },

    { njt_string("fastcgi_bind"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE12,
      njt_http_upstream_bind_set_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.local),
      NULL },

    { njt_string("fastcgi_socket_keepalive"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.socket_keepalive),
      NULL },

    { njt_string("fastcgi_connect_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.connect_timeout),
      NULL },

    { njt_string("fastcgi_send_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.send_timeout),
      NULL },

    { njt_string("fastcgi_send_lowat"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.send_lowat),
      &njt_http_fastcgi_lowat_post },

    { njt_string("fastcgi_buffer_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.buffer_size),
      NULL },

    { njt_string("fastcgi_pass_request_headers"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.pass_request_headers),
      NULL },

    { njt_string("fastcgi_pass_request_body"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.pass_request_body),
      NULL },

    { njt_string("fastcgi_intercept_errors"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.intercept_errors),
      NULL },

    { njt_string("fastcgi_read_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.read_timeout),
      NULL },

    { njt_string("fastcgi_buffers"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE2,
      njt_conf_set_bufs_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.bufs),
      NULL },

    { njt_string("fastcgi_busy_buffers_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.busy_buffers_size_conf),
      NULL },

    { njt_string("fastcgi_force_ranges"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.force_ranges),
      NULL },

    { njt_string("fastcgi_limit_rate"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.limit_rate),
      NULL },

#if (NJT_HTTP_CACHE)

    { njt_string("fastcgi_cache"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_fastcgi_cache,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("fastcgi_cache_key"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_fastcgi_cache_key,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("fastcgi_cache_path"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_2MORE,
      njt_http_file_cache_set_slot,
      NJT_HTTP_MAIN_CONF_OFFSET,
      offsetof(njt_http_fastcgi_main_conf_t, caches),
      &njt_http_fastcgi_module },

    { njt_string("fastcgi_cache_bypass"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_http_set_predicate_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.cache_bypass),
      NULL },

    { njt_string("fastcgi_no_cache"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_http_set_predicate_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.no_cache),
      NULL },

    { njt_string("fastcgi_cache_valid"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_http_file_cache_valid_set_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.cache_valid),
      NULL },

    { njt_string("fastcgi_cache_min_uses"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.cache_min_uses),
      NULL },

    { njt_string("fastcgi_cache_max_range_offset"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_off_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.cache_max_range_offset),
      NULL },

    { njt_string("fastcgi_cache_use_stale"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.cache_use_stale),
      &njt_http_fastcgi_next_upstream_masks },

    { njt_string("fastcgi_cache_methods"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.cache_methods),
      &njt_http_upstream_cache_method_mask },

    { njt_string("fastcgi_cache_lock"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.cache_lock),
      NULL },

    { njt_string("fastcgi_cache_lock_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.cache_lock_timeout),
      NULL },

    { njt_string("fastcgi_cache_lock_age"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.cache_lock_age),
      NULL },

    { njt_string("fastcgi_cache_revalidate"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.cache_revalidate),
      NULL },

    { njt_string("fastcgi_cache_background_update"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.cache_background_update),
      NULL },

#endif

    { njt_string("fastcgi_temp_path"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1234,
      njt_conf_set_path_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.temp_path),
      NULL },

    { njt_string("fastcgi_max_temp_file_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.max_temp_file_size_conf),
      NULL },

    { njt_string("fastcgi_temp_file_write_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.temp_file_write_size_conf),
      NULL },

    { njt_string("fastcgi_next_upstream"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.next_upstream),
      &njt_http_fastcgi_next_upstream_masks },

    { njt_string("fastcgi_next_upstream_tries"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.next_upstream_tries),
      NULL },

    { njt_string("fastcgi_next_upstream_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.next_upstream_timeout),
      NULL },

    { njt_string("fastcgi_param"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE23,
      njt_http_upstream_param_set_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, params_source),
      NULL },

    { njt_string("fastcgi_pass_header"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_array_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.pass_headers),
      NULL },

    { njt_string("fastcgi_hide_header"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_array_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.hide_headers),
      NULL },

    { njt_string("fastcgi_ignore_headers"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, upstream.ignore_headers),
      &njt_http_upstream_ignore_headers_masks },

    { njt_string("fastcgi_catch_stderr"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_array_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, catch_stderr),
      NULL },

    { njt_string("fastcgi_keep_conn"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_fastcgi_loc_conf_t, keep_conn),
      NULL },

      njt_null_command
};


static njt_http_module_t  njt_http_fastcgi_module_ctx = {
    njt_http_fastcgi_add_variables,        /* preconfiguration */
    NULL,                                  /* postconfiguration */

    njt_http_fastcgi_create_main_conf,     /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_fastcgi_create_loc_conf,      /* create location configuration */
    njt_http_fastcgi_merge_loc_conf        /* merge location configuration */
};


njt_module_t  njt_http_fastcgi_module = {
    NJT_MODULE_V1,
    &njt_http_fastcgi_module_ctx,          /* module context */
    njt_http_fastcgi_commands,             /* module directives */
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


static njt_http_fastcgi_request_start_t  njt_http_fastcgi_request_start = {
    { 1,                                               /* version */
      NJT_HTTP_FASTCGI_BEGIN_REQUEST,                  /* type */
      0,                                               /* request_id_hi */
      1,                                               /* request_id_lo */
      0,                                               /* content_length_hi */
      sizeof(njt_http_fastcgi_begin_request_t),        /* content_length_lo */
      0,                                               /* padding_length */
      0 },                                             /* reserved */

    { 0,                                               /* role_hi */
      NJT_HTTP_FASTCGI_RESPONDER,                      /* role_lo */
      0, /* NJT_HTTP_FASTCGI_KEEP_CONN */              /* flags */
      { 0, 0, 0, 0, 0 } },                             /* reserved[5] */

    { 1,                                               /* version */
      NJT_HTTP_FASTCGI_PARAMS,                         /* type */
      0,                                               /* request_id_hi */
      1 },                                             /* request_id_lo */

};


static njt_http_variable_t  njt_http_fastcgi_vars[] = {

    { njt_string("fastcgi_script_name"), NULL,
      njt_http_fastcgi_script_name_variable, 0,
      NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_NOHASH, 0, NJT_VAR_INIT_REF_COUNT },

    { njt_string("fastcgi_path_info"), NULL,
      njt_http_fastcgi_path_info_variable, 0,
      NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_NOHASH, 0, NJT_VAR_INIT_REF_COUNT },

      njt_http_null_variable
};


static njt_str_t  njt_http_fastcgi_hide_headers[] = {
    njt_string("Status"),
    njt_string("X-Accel-Expires"),
    njt_string("X-Accel-Redirect"),
    njt_string("X-Accel-Limit-Rate"),
    njt_string("X-Accel-Buffering"),
    njt_string("X-Accel-Charset"),
    njt_null_string
};


#if (NJT_HTTP_CACHE)

static njt_keyval_t  njt_http_fastcgi_cache_headers[] = {
    { njt_string("HTTP_IF_MODIFIED_SINCE"),
      njt_string("$upstream_cache_last_modified") },
    { njt_string("HTTP_IF_UNMODIFIED_SINCE"), njt_string("") },
    { njt_string("HTTP_IF_NONE_MATCH"), njt_string("$upstream_cache_etag") },
    { njt_string("HTTP_IF_MATCH"), njt_string("") },
    { njt_string("HTTP_RANGE"), njt_string("") },
    { njt_string("HTTP_IF_RANGE"), njt_string("") },
    { njt_null_string, njt_null_string }
};

#endif


static njt_path_init_t  njt_http_fastcgi_temp_path = {
    njt_string(NJT_HTTP_FASTCGI_TEMP_PATH), { 1, 2, 0 }
};


static njt_int_t
njt_http_fastcgi_handler(njt_http_request_t *r)
{
    njt_int_t                      rc;
    njt_http_upstream_t           *u;
    njt_http_fastcgi_ctx_t        *f;
    njt_http_fastcgi_loc_conf_t   *flcf;
#if (NJT_HTTP_CACHE)
    njt_http_fastcgi_main_conf_t  *fmcf;
#endif

    if (njt_http_upstream_create(r) != NJT_OK) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    f = njt_pcalloc(r->pool, sizeof(njt_http_fastcgi_ctx_t));
    if (f == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    njt_http_set_ctx(r, f, njt_http_fastcgi_module);

    flcf = njt_http_get_module_loc_conf(r, njt_http_fastcgi_module);

    if (flcf->fastcgi_lengths) {
        if (njt_http_fastcgi_eval(r, flcf) != NJT_OK) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    u = r->upstream;

    njt_str_set(&u->schema, "fastcgi://");
    u->output.tag = (njt_buf_tag_t) &njt_http_fastcgi_module;

    u->conf = &flcf->upstream;

#if (NJT_HTTP_CACHE)
    fmcf = njt_http_get_module_main_conf(r, njt_http_fastcgi_module);

    u->caches = &fmcf->caches;
    u->create_key = njt_http_fastcgi_create_key;
#endif

    u->create_request = njt_http_fastcgi_create_request;
    u->reinit_request = njt_http_fastcgi_reinit_request;
    u->process_header = njt_http_fastcgi_process_header;
    u->abort_request = njt_http_fastcgi_abort_request;
    u->finalize_request = njt_http_fastcgi_finalize_request;
    r->state = 0;

    u->buffering = flcf->upstream.buffering;

    u->pipe = njt_pcalloc(r->pool, sizeof(njt_event_pipe_t));
    if (u->pipe == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    u->pipe->input_filter = njt_http_fastcgi_input_filter;
    u->pipe->input_ctx = r;

    u->input_filter_init = njt_http_fastcgi_input_filter_init;
    u->input_filter = njt_http_fastcgi_non_buffered_filter;
    u->input_filter_ctx = r;

    if (!flcf->upstream.request_buffering
        && flcf->upstream.pass_request_body)
    {
        r->request_body_no_buffering = 1;
    }

    rc = njt_http_read_client_request_body(r, njt_http_upstream_init);

    if (rc >= NJT_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NJT_DONE;
}


static njt_int_t
njt_http_fastcgi_eval(njt_http_request_t *r, njt_http_fastcgi_loc_conf_t *flcf)
{
    njt_url_t             url;
    njt_http_upstream_t  *u;

    njt_memzero(&url, sizeof(njt_url_t));

    if (njt_http_script_run(r, &url.url, flcf->fastcgi_lengths->elts, 0,
                            flcf->fastcgi_values->elts)
        == NULL)
    {
        return NJT_ERROR;
    }

    url.no_resolve = 1;

    if (njt_parse_url(r->pool, &url) != NJT_OK) {
        if (url.err) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "%s in upstream \"%V\"", url.err, &url.url);
        }

        return NJT_ERROR;
    }

    u = r->upstream;

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

    return NJT_OK;
}


#if (NJT_HTTP_CACHE)

static njt_int_t
njt_http_fastcgi_create_key(njt_http_request_t *r)
{
    njt_str_t                    *key;
    njt_http_fastcgi_loc_conf_t  *flcf;

    key = njt_array_push(&r->cache->keys);
    if (key == NULL) {
        return NJT_ERROR;
    }

    flcf = njt_http_get_module_loc_conf(r, njt_http_fastcgi_module);

    if (njt_http_complex_value(r, &flcf->cache_key, key) != NJT_OK) {
        return NJT_ERROR;
    }

    return NJT_OK;
}

#endif


static njt_int_t
njt_http_fastcgi_create_request(njt_http_request_t *r)
{
    off_t                         file_pos;
    u_char                        ch, sep, *pos, *lowcase_key;
    size_t                        size, len, key_len, val_len, padding,
                                  allocated;
    njt_uint_t                    i, n, next, hash, skip_empty, header_params;
    njt_buf_t                    *b;
    njt_chain_t                  *cl, *body;
    njt_list_part_t              *part;
    njt_table_elt_t              *header, *hn, **ignored;
    njt_http_upstream_t          *u;
    njt_http_script_code_pt       code;
    njt_http_script_engine_t      e, le;
    njt_http_fastcgi_header_t    *h;
    njt_http_fastcgi_params_t    *params;
    njt_http_fastcgi_loc_conf_t  *flcf;
    njt_http_script_len_code_pt   lcode;

    len = 0;
    header_params = 0;
    ignored = NULL;

    u = r->upstream;

    flcf = njt_http_get_module_loc_conf(r, njt_http_fastcgi_module);

#if (NJT_HTTP_CACHE)
    params = u->cacheable ? &flcf->params_cache : &flcf->params;
#else
    params = &flcf->params;
#endif

    if (params->lengths) {
        njt_memzero(&le, sizeof(njt_http_script_engine_t));

        njt_http_script_flush_no_cacheable_variables(r, params->flushes);
        le.flushed = 1;

        le.ip = params->lengths->elts;
        le.request = r;

        while (*(uintptr_t *) le.ip) {

            lcode = *(njt_http_script_len_code_pt *) le.ip;
            key_len = lcode(&le);

            lcode = *(njt_http_script_len_code_pt *) le.ip;
            skip_empty = lcode(&le);

            for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
                lcode = *(njt_http_script_len_code_pt *) le.ip;
            }
            le.ip += sizeof(uintptr_t);

            if (skip_empty && val_len == 0) {
                continue;
            }

            len += 1 + key_len + ((val_len > 127) ? 4 : 1) + val_len;
        }
    }

    if (flcf->upstream.pass_request_headers) {

        allocated = 0;
        lowcase_key = NULL;

        if (njt_http_link_multi_headers(r) != NJT_OK) {
            return NJT_ERROR;
        }

        if (params->number || r->headers_in.multi) {
            n = 0;
            part = &r->headers_in.headers.part;

            while (part) {
                n += part->nelts;
                part = part->next;
            }

            ignored = njt_palloc(r->pool, n * sizeof(void *));
            if (ignored == NULL) {
                return NJT_ERROR;
            }
        }

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

            for (n = 0; n < header_params; n++) {
                if (ignored != NULL && &header[i] == ignored[n]) {
                    goto next_length;
                } else if(ignored == NULL) {
		   njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
                      "fastcgi request ignored is null");	
		}
            }

            if (params->number) {
                if (allocated < header[i].key.len) {
                    allocated = header[i].key.len + 16;
                    lowcase_key = njt_pnalloc(r->pool, allocated);
                    if (lowcase_key == NULL) {
                        return NJT_ERROR;
                    }
                }

                hash = 0;

                for (n = 0; n < header[i].key.len; n++) {
                    ch = header[i].key.data[n];

                    if (ch >= 'A' && ch <= 'Z') {
                        ch |= 0x20;

                    } else if (ch == '-') {
                        ch = '_';
                    }

                    hash = njt_hash(hash, ch);
                    lowcase_key[n] = ch;
                }
                if (njt_hash_find(&params->hash, hash, lowcase_key, n)) {
		    if(ignored != NULL) {
                    	ignored[header_params++] = &header[i];
		    } else {
			 njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
                      "fastcgi request ignored is null");
		    }
                    continue;
                }
            }

            key_len = sizeof("HTTP_") - 1 + header[i].key.len;

            val_len = header[i].value.len;

            for (hn = header[i].next; hn; hn = hn->next) {
                val_len += hn->value.len + 2;
                ignored[header_params++] = hn;
            }

            len += ((key_len > 127) ? 4 : 1) + key_len
                   + ((val_len > 127) ? 4 : 1) + val_len;

        next_length:

            continue;
        }
    }


    if (len > 65535) {
        njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
                      "fastcgi request record is too big: %uz", len);
        return NJT_ERROR;
    }


    padding = 8 - len % 8;
    padding = (padding == 8) ? 0 : padding;


    size = sizeof(njt_http_fastcgi_header_t)
           + sizeof(njt_http_fastcgi_begin_request_t)

           + sizeof(njt_http_fastcgi_header_t)  /* NJT_HTTP_FASTCGI_PARAMS */
           + len + padding
           + sizeof(njt_http_fastcgi_header_t)  /* NJT_HTTP_FASTCGI_PARAMS */

           + sizeof(njt_http_fastcgi_header_t); /* NJT_HTTP_FASTCGI_STDIN */


    b = njt_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NJT_ERROR;
    }

    cl = njt_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NJT_ERROR;
    }

    cl->buf = b;

    njt_http_fastcgi_request_start.br.flags =
        flcf->keep_conn ? NJT_HTTP_FASTCGI_KEEP_CONN : 0;

    njt_memcpy(b->pos, &njt_http_fastcgi_request_start,
               sizeof(njt_http_fastcgi_request_start_t));

    h = (njt_http_fastcgi_header_t *)
             (b->pos + sizeof(njt_http_fastcgi_header_t)
                     + sizeof(njt_http_fastcgi_begin_request_t));

    h->content_length_hi = (u_char) ((len >> 8) & 0xff);
    h->content_length_lo = (u_char) (len & 0xff);
    h->padding_length = (u_char) padding;
    h->reserved = 0;

    b->last = b->pos + sizeof(njt_http_fastcgi_header_t)
                     + sizeof(njt_http_fastcgi_begin_request_t)
                     + sizeof(njt_http_fastcgi_header_t);


    if (params->lengths) {
        njt_memzero(&e, sizeof(njt_http_script_engine_t));

        e.ip = params->values->elts;
        e.pos = b->last;
        e.request = r;
        e.flushed = 1;

        le.ip = params->lengths->elts;

        while (*(uintptr_t *) le.ip) {

            lcode = *(njt_http_script_len_code_pt *) le.ip;
            key_len = (u_char) lcode(&le);

            lcode = *(njt_http_script_len_code_pt *) le.ip;
            skip_empty = lcode(&le);

            for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
                lcode = *(njt_http_script_len_code_pt *) le.ip;
            }
            le.ip += sizeof(uintptr_t);

            if (skip_empty && val_len == 0) {
                e.skip = 1;

                while (*(uintptr_t *) e.ip) {
                    code = *(njt_http_script_code_pt *) e.ip;
                    code((njt_http_script_engine_t *) &e);
                }
                e.ip += sizeof(uintptr_t);

                e.skip = 0;

                continue;
            }

            *e.pos++ = (u_char) key_len;

            if (val_len > 127) {
                *e.pos++ = (u_char) (((val_len >> 24) & 0x7f) | 0x80);
                *e.pos++ = (u_char) ((val_len >> 16) & 0xff);
                *e.pos++ = (u_char) ((val_len >> 8) & 0xff);
                *e.pos++ = (u_char) (val_len & 0xff);

            } else {
                *e.pos++ = (u_char) val_len;
            }

            while (*(uintptr_t *) e.ip) {
                code = *(njt_http_script_code_pt *) e.ip;
                code((njt_http_script_engine_t *) &e);
            }
            e.ip += sizeof(uintptr_t);

            njt_log_debug4(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "fastcgi param: \"%*s: %*s\"",
                           key_len, e.pos - (key_len + val_len),
                           val_len, e.pos - val_len);
        }

        b->last = e.pos;
    }


    if (flcf->upstream.pass_request_headers) {

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

            for (n = 0; n < header_params; n++) {
                if (&header[i] == ignored[n]) {
                    goto next_value;
                }
            }

            key_len = sizeof("HTTP_") - 1 + header[i].key.len;
            if (key_len > 127) {
                *b->last++ = (u_char) (((key_len >> 24) & 0x7f) | 0x80);
                *b->last++ = (u_char) ((key_len >> 16) & 0xff);
                *b->last++ = (u_char) ((key_len >> 8) & 0xff);
                *b->last++ = (u_char) (key_len & 0xff);

            } else {
                *b->last++ = (u_char) key_len;
            }

            val_len = header[i].value.len;

            for (hn = header[i].next; hn; hn = hn->next) {
                val_len += hn->value.len + 2;
            }

            if (val_len > 127) {
                *b->last++ = (u_char) (((val_len >> 24) & 0x7f) | 0x80);
                *b->last++ = (u_char) ((val_len >> 16) & 0xff);
                *b->last++ = (u_char) ((val_len >> 8) & 0xff);
                *b->last++ = (u_char) (val_len & 0xff);

            } else {
                *b->last++ = (u_char) val_len;
            }

            b->last = njt_cpymem(b->last, "HTTP_", sizeof("HTTP_") - 1);

            for (n = 0; n < header[i].key.len; n++) {
                ch = header[i].key.data[n];

                if (ch >= 'a' && ch <= 'z') {
                    ch &= ~0x20;

                } else if (ch == '-') {
                    ch = '_';
                }

                *b->last++ = ch;
            }

            b->last = njt_copy(b->last, header[i].value.data,
                               header[i].value.len);

            if (header[i].next) {

                if (header[i].key.len == sizeof("Cookie") - 1
                    && njt_strncasecmp(header[i].key.data, (u_char *) "Cookie",
                                       sizeof("Cookie") - 1)
                       == 0)
                {
                    sep = ';';

                } else {
                    sep = ',';
                }

                for (hn = header[i].next; hn; hn = hn->next) {
                    *b->last++ = sep;
                    *b->last++ = ' ';
                    b->last = njt_copy(b->last, hn->value.data, hn->value.len);
                }
            }

            njt_log_debug4(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "fastcgi param: \"%*s: %*s\"",
                           key_len, b->last - (key_len + val_len),
                           val_len, b->last - val_len);
        next_value:

            continue;
        }
    }


    if (padding) {
        njt_memzero(b->last, padding);
        b->last += padding;
    }


    h = (njt_http_fastcgi_header_t *) b->last;
    b->last += sizeof(njt_http_fastcgi_header_t);

    h->version = 1;
    h->type = NJT_HTTP_FASTCGI_PARAMS;
    h->request_id_hi = 0;
    h->request_id_lo = 1;
    h->content_length_hi = 0;
    h->content_length_lo = 0;
    h->padding_length = 0;
    h->reserved = 0;

    if (r->request_body_no_buffering) {

        u->request_bufs = cl;

        u->output.output_filter = njt_http_fastcgi_body_output_filter;
        u->output.filter_ctx = r;

    } else if (flcf->upstream.pass_request_body) {

        body = u->request_bufs;
        u->request_bufs = cl;

#if (NJT_SUPPRESS_WARN)
        file_pos = 0;
        pos = NULL;
#endif

        while (body) {

            if (njt_buf_special(body->buf)) {
                body = body->next;
                continue;
            }

            if (body->buf->in_file) {
                file_pos = body->buf->file_pos;

            } else {
                pos = body->buf->pos;
            }

            next = 0;

            do {
                b = njt_alloc_buf(r->pool);
                if (b == NULL) {
                    return NJT_ERROR;
                }

                njt_memcpy(b, body->buf, sizeof(njt_buf_t));

                if (body->buf->in_file) {
                    b->file_pos = file_pos;
                    file_pos += 32 * 1024;

                    if (file_pos >= body->buf->file_last) {
                        file_pos = body->buf->file_last;
                        next = 1;
                    }

                    b->file_last = file_pos;
                    len = (njt_uint_t) (file_pos - b->file_pos);

                } else {
                    b->pos = pos;
                    b->start = pos;
                    pos += 32 * 1024;

                    if (pos >= body->buf->last) {
                        pos = body->buf->last;
                        next = 1;
                    }

                    b->last = pos;
                    len = (njt_uint_t) (pos - b->pos);
                }

                padding = 8 - len % 8;
                padding = (padding == 8) ? 0 : padding;

                h = (njt_http_fastcgi_header_t *) cl->buf->last;
                cl->buf->last += sizeof(njt_http_fastcgi_header_t);

                h->version = 1;
                h->type = NJT_HTTP_FASTCGI_STDIN;
                h->request_id_hi = 0;
                h->request_id_lo = 1;
                h->content_length_hi = (u_char) ((len >> 8) & 0xff);
                h->content_length_lo = (u_char) (len & 0xff);
                h->padding_length = (u_char) padding;
                h->reserved = 0;

                cl->next = njt_alloc_chain_link(r->pool);
                if (cl->next == NULL) {
                    return NJT_ERROR;
                }

                cl = cl->next;
                cl->buf = b;

                b = njt_create_temp_buf(r->pool,
                                        sizeof(njt_http_fastcgi_header_t)
                                        + padding);
                if (b == NULL) {
                    return NJT_ERROR;
                }

                if (padding) {
                    njt_memzero(b->last, padding);
                    b->last += padding;
                }

                cl->next = njt_alloc_chain_link(r->pool);
                if (cl->next == NULL) {
                    return NJT_ERROR;
                }

                cl = cl->next;
                cl->buf = b;

            } while (!next);

            body = body->next;
        }

    } else {
        u->request_bufs = cl;
    }

    if (!r->request_body_no_buffering) {
        h = (njt_http_fastcgi_header_t *) cl->buf->last;
        cl->buf->last += sizeof(njt_http_fastcgi_header_t);

        h->version = 1;
        h->type = NJT_HTTP_FASTCGI_STDIN;
        h->request_id_hi = 0;
        h->request_id_lo = 1;
        h->content_length_hi = 0;
        h->content_length_lo = 0;
        h->padding_length = 0;
        h->reserved = 0;
    }

    cl->next = NULL;

    return NJT_OK;
}


static njt_int_t
njt_http_fastcgi_reinit_request(njt_http_request_t *r)
{
    njt_http_fastcgi_ctx_t  *f;

    f = njt_http_get_module_ctx(r, njt_http_fastcgi_module);

    if (f == NULL) {
        return NJT_OK;
    }

    f->state = njt_http_fastcgi_st_version;
    f->fastcgi_stdout = 0;
    f->large_stderr = 0;

    if (f->split_parts) {
        f->split_parts->nelts = 0;
    }

    r->state = 0;

    return NJT_OK;
}


static njt_int_t
njt_http_fastcgi_body_output_filter(void *data, njt_chain_t *in)
{
    njt_http_request_t  *r = data;

    off_t                       file_pos;
    u_char                     *pos, *start;
    size_t                      len, padding;
    njt_buf_t                  *b;
    njt_int_t                   rc;
    njt_uint_t                  next, last;
    njt_chain_t                *cl, *tl, *out, **ll;
    njt_http_fastcgi_ctx_t     *f;
    njt_http_fastcgi_header_t  *h;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "fastcgi output filter");

    f = njt_http_get_module_ctx(r, njt_http_fastcgi_module);

    if (in == NULL) {
        out = in;
        goto out;
    }

    out = NULL;
    ll = &out;

    if (!f->header_sent) {
        /* first buffer contains headers, pass it unmodified */

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "fastcgi output header");

        f->header_sent = 1;

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

    cl = njt_chain_get_free_buf(r->pool, &f->free);
    if (cl == NULL) {
        return NJT_ERROR;
    }

    b = cl->buf;

    b->tag = (njt_buf_tag_t) &njt_http_fastcgi_body_output_filter;
    b->temporary = 1;

    if (b->start == NULL) {
        /* reserve space for maximum possible padding, 7 bytes */

        b->start = njt_palloc(r->pool,
                              sizeof(njt_http_fastcgi_header_t) + 7);
        if (b->start == NULL) {
            return NJT_ERROR;
        }

        b->pos = b->start;
        b->last = b->start;

        b->end = b->start + sizeof(njt_http_fastcgi_header_t) + 7;
    }

    *ll = cl;

    last = 0;
    padding = 0;

#if (NJT_SUPPRESS_WARN)
    file_pos = 0;
    pos = NULL;
#endif

    while (in) {

        njt_log_debug7(NJT_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "fastcgi output in  l:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       in->buf->last_buf,
                       in->buf->in_file,
                       in->buf->start, in->buf->pos,
                       in->buf->last - in->buf->pos,
                       in->buf->file_pos,
                       in->buf->file_last - in->buf->file_pos);

        if (in->buf->last_buf) {
            last = 1;
        }

        if (njt_buf_special(in->buf)) {
            in = in->next;
            continue;
        }

        if (in->buf->in_file) {
            file_pos = in->buf->file_pos;

        } else {
            pos = in->buf->pos;
        }

        next = 0;

        do {
            tl = njt_chain_get_free_buf(r->pool, &f->free);
            if (tl == NULL) {
                return NJT_ERROR;
            }

            b = tl->buf;
            start = b->start;

            njt_memcpy(b, in->buf, sizeof(njt_buf_t));

            /*
             * restore b->start to preserve memory allocated in the buffer,
             * to reuse it later for headers and padding
             */

            b->start = start;

            if (in->buf->in_file) {
                b->file_pos = file_pos;
                file_pos += 32 * 1024;

                if (file_pos >= in->buf->file_last) {
                    file_pos = in->buf->file_last;
                    next = 1;
                }

                b->file_last = file_pos;
                len = (njt_uint_t) (file_pos - b->file_pos);

            } else {
                b->pos = pos;
                pos += 32 * 1024;

                if (pos >= in->buf->last) {
                    pos = in->buf->last;
                    next = 1;
                }

                b->last = pos;
                len = (njt_uint_t) (pos - b->pos);
            }

            b->tag = (njt_buf_tag_t) &njt_http_fastcgi_body_output_filter;
            b->shadow = in->buf;
            b->last_shadow = next;

            b->last_buf = 0;
            b->last_in_chain = 0;

            padding = 8 - len % 8;
            padding = (padding == 8) ? 0 : padding;

            h = (njt_http_fastcgi_header_t *) cl->buf->last;
            cl->buf->last += sizeof(njt_http_fastcgi_header_t);

            h->version = 1;
            h->type = NJT_HTTP_FASTCGI_STDIN;
            h->request_id_hi = 0;
            h->request_id_lo = 1;
            h->content_length_hi = (u_char) ((len >> 8) & 0xff);
            h->content_length_lo = (u_char) (len & 0xff);
            h->padding_length = (u_char) padding;
            h->reserved = 0;

            cl->next = tl;
            cl = tl;

            tl = njt_chain_get_free_buf(r->pool, &f->free);
            if (tl == NULL) {
                return NJT_ERROR;
            }

            b = tl->buf;

            b->tag = (njt_buf_tag_t) &njt_http_fastcgi_body_output_filter;
            b->temporary = 1;

            if (b->start == NULL) {
                /* reserve space for maximum possible padding, 7 bytes */

                b->start = njt_palloc(r->pool,
                                      sizeof(njt_http_fastcgi_header_t) + 7);
                if (b->start == NULL) {
                    return NJT_ERROR;
                }

                b->pos = b->start;
                b->last = b->start;

                b->end = b->start + sizeof(njt_http_fastcgi_header_t) + 7;
            }

            if (padding) {
                njt_memzero(b->last, padding);
                b->last += padding;
            }

            cl->next = tl;
            cl = tl;

        } while (!next);

        in = in->next;
    }

    if (last) {
        h = (njt_http_fastcgi_header_t *) cl->buf->last;
        cl->buf->last += sizeof(njt_http_fastcgi_header_t);

        h->version = 1;
        h->type = NJT_HTTP_FASTCGI_STDIN;
        h->request_id_hi = 0;
        h->request_id_lo = 1;
        h->content_length_hi = 0;
        h->content_length_lo = 0;
        h->padding_length = 0;
        h->reserved = 0;

        cl->buf->last_buf = 1;

    } else if (padding == 0) {
        /* TODO: do not allocate buffers instead */
        cl->buf->temporary = 0;
        cl->buf->sync = 1;
    }

    cl->next = NULL;

out:

#if (NJT_DEBUG)

    for (cl = out; cl; cl = cl->next) {
        njt_log_debug7(NJT_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "fastcgi output out l:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->last_buf,
                       cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

#endif

    rc = njt_chain_writer(&r->upstream->writer, out);

    njt_chain_update_chains(r->pool, &f->free, &f->busy, &out,
                         (njt_buf_tag_t) &njt_http_fastcgi_body_output_filter);

    for (cl = f->free; cl; cl = cl->next) {

        /* mark original buffers as sent */

        if (cl->buf->shadow) {
            if (cl->buf->last_shadow) {
                b = cl->buf->shadow;
                b->pos = b->last;
            }

            cl->buf->shadow = NULL;
        }
    }

    return rc;
}


static njt_int_t
njt_http_fastcgi_process_header(njt_http_request_t *r)
{
    u_char                         *p, *msg, *start, *last,
                                   *part_start, *part_end;
    size_t                          size;
    njt_str_t                      *status_line, *pattern;
    njt_int_t                       rc, status;
    njt_buf_t                       buf;
    njt_uint_t                      i;
    njt_table_elt_t                *h;
    njt_http_upstream_t            *u;
    njt_http_fastcgi_ctx_t         *f;
    njt_http_upstream_header_t     *hh;
    njt_http_fastcgi_loc_conf_t    *flcf;
    njt_http_fastcgi_split_part_t  *part;
    njt_http_upstream_main_conf_t  *umcf;

    f = njt_http_get_module_ctx(r, njt_http_fastcgi_module);

    umcf = njt_http_get_module_main_conf(r, njt_http_upstream_module);

    u = r->upstream;

    for ( ;; ) {

        if (f->state < njt_http_fastcgi_st_data) {

            f->pos = u->buffer.pos;
            f->last = u->buffer.last;

            rc = njt_http_fastcgi_process_record(r, f);

            u->buffer.pos = f->pos;
            u->buffer.last = f->last;

            if (rc == NJT_AGAIN) {
                return NJT_AGAIN;
            }

            if (rc == NJT_ERROR) {
                return NJT_HTTP_UPSTREAM_INVALID_HEADER;
            }

            if (f->type != NJT_HTTP_FASTCGI_STDOUT
                && f->type != NJT_HTTP_FASTCGI_STDERR)
            {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream sent unexpected FastCGI record: %ui",
                              f->type);

                return NJT_HTTP_UPSTREAM_INVALID_HEADER;
            }

            if (f->type == NJT_HTTP_FASTCGI_STDOUT && f->length == 0) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream prematurely closed FastCGI stdout");

                return NJT_HTTP_UPSTREAM_INVALID_HEADER;
            }
        }

        if (f->state == njt_http_fastcgi_st_padding) {

            if (u->buffer.pos + f->padding < u->buffer.last) {
                f->state = njt_http_fastcgi_st_version;
                u->buffer.pos += f->padding;

                continue;
            }

            if (u->buffer.pos + f->padding == u->buffer.last) {
                f->state = njt_http_fastcgi_st_version;
                u->buffer.pos = u->buffer.last;

                return NJT_AGAIN;
            }

            f->padding -= u->buffer.last - u->buffer.pos;
            u->buffer.pos = u->buffer.last;

            return NJT_AGAIN;
        }


        /* f->state == njt_http_fastcgi_st_data */

        if (f->type == NJT_HTTP_FASTCGI_STDERR) {

            if (f->length) {
                msg = u->buffer.pos;

                if (u->buffer.pos + f->length <= u->buffer.last) {
                    u->buffer.pos += f->length;
                    f->length = 0;
                    f->state = njt_http_fastcgi_st_padding;

                } else {
                    f->length -= u->buffer.last - u->buffer.pos;
                    u->buffer.pos = u->buffer.last;
                }

                for (p = u->buffer.pos - 1; msg < p; p--) {
                    if (*p != LF && *p != CR && *p != '.' && *p != ' ') {
                        break;
                    }
                }

                p++;

                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "FastCGI sent in stderr: \"%*s\"", p - msg, msg);

                flcf = njt_http_get_module_loc_conf(r, njt_http_fastcgi_module);

                if (flcf->catch_stderr) {
                    pattern = flcf->catch_stderr->elts;

                    for (i = 0; i < flcf->catch_stderr->nelts; i++) {
                        if (njt_strnstr(msg, (char *) pattern[i].data,
                                        p - msg)
                            != NULL)
                        {
                            return NJT_HTTP_UPSTREAM_INVALID_HEADER;
                        }
                    }
                }

                if (u->buffer.pos == u->buffer.last) {

                    if (!f->fastcgi_stdout) {

                        /*
                         * the special handling the large number
                         * of the PHP warnings to not allocate memory
                         */

#if (NJT_HTTP_CACHE)
                        if (r->cache) {
                            u->buffer.pos = u->buffer.start
                                                     + r->cache->header_start;
                        } else {
                            u->buffer.pos = u->buffer.start;
                        }
#else
                        u->buffer.pos = u->buffer.start;
#endif
                        u->buffer.last = u->buffer.pos;
                        f->large_stderr = 1;
                    }

                    return NJT_AGAIN;
                }

            } else {
                f->state = njt_http_fastcgi_st_padding;
            }

            continue;
        }


        /* f->type == NJT_HTTP_FASTCGI_STDOUT */

#if (NJT_HTTP_CACHE)

        if (f->large_stderr && r->cache) {
            ssize_t                     len;
            njt_http_fastcgi_header_t  *fh;

            start = u->buffer.start + r->cache->header_start;

            len = u->buffer.pos - start - 2 * sizeof(njt_http_fastcgi_header_t);

            /*
             * A tail of large stderr output before HTTP header is placed
             * in a cache file without a FastCGI record header.
             * To workaround it we put a dummy FastCGI record header at the
             * start of the stderr output or update r->cache_header_start,
             * if there is no enough place for the record header.
             */

            if (len >= 0) {
                fh = (njt_http_fastcgi_header_t *) start;
                fh->version = 1;
                fh->type = NJT_HTTP_FASTCGI_STDERR;
                fh->request_id_hi = 0;
                fh->request_id_lo = 1;
                fh->content_length_hi = (u_char) ((len >> 8) & 0xff);
                fh->content_length_lo = (u_char) (len & 0xff);
                fh->padding_length = 0;
                fh->reserved = 0;

            } else {
                r->cache->header_start += u->buffer.pos - start
                                          - sizeof(njt_http_fastcgi_header_t);
            }

            f->large_stderr = 0;
        }

#endif

        f->fastcgi_stdout = 1;

        start = u->buffer.pos;

        if (u->buffer.pos + f->length < u->buffer.last) {

            /*
             * set u->buffer.last to the end of the FastCGI record data
             * for njt_http_parse_header_line()
             */

            last = u->buffer.last;
            u->buffer.last = u->buffer.pos + f->length;

        } else {
            last = NULL;
        }

        for ( ;; ) {

            part_start = u->buffer.pos;
            part_end = u->buffer.last;

            rc = njt_http_parse_header_line(r, &u->buffer, 1);

            njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http fastcgi parser: %i", rc);

            if (rc == NJT_AGAIN) {
                break;
            }

            if (rc == NJT_OK) {

                /* a header line has been parsed successfully */

                h = njt_list_push(&u->headers_in.headers);
                if (h == NULL) {
                    return NJT_ERROR;
                }

                if (f->split_parts && f->split_parts->nelts) {

                    part = f->split_parts->elts;
                    size = u->buffer.pos - part_start;

                    for (i = 0; i < f->split_parts->nelts; i++) {
                        size += part[i].end - part[i].start;
                    }

                    p = njt_pnalloc(r->pool, size);
                    if (p == NULL) {
                        h->hash = 0;
                        return NJT_ERROR;
                    }

                    buf.pos = p;

                    for (i = 0; i < f->split_parts->nelts; i++) {
                        p = njt_cpymem(p, part[i].start,
                                       part[i].end - part[i].start);
                    }

                    p = njt_cpymem(p, part_start, u->buffer.pos - part_start);

                    buf.last = p;

                    f->split_parts->nelts = 0;

                    rc = njt_http_parse_header_line(r, &buf, 1);

                    if (rc != NJT_OK) {
                        njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
                                      "invalid header after joining "
                                      "FastCGI records");
                        h->hash = 0;
                        return NJT_ERROR;
                    }

                    h->key.len = r->header_name_end - r->header_name_start;
                    h->key.data = r->header_name_start;
                    h->key.data[h->key.len] = '\0';

                    h->value.len = r->header_end - r->header_start;
                    h->value.data = r->header_start;
                    h->value.data[h->value.len] = '\0';

                    h->lowcase_key = njt_pnalloc(r->pool, h->key.len);
                    if (h->lowcase_key == NULL) {
                        return NJT_ERROR;
                    }

                } else {

                    h->key.len = r->header_name_end - r->header_name_start;
                    h->value.len = r->header_end - r->header_start;

                    h->key.data = njt_pnalloc(r->pool,
                                              h->key.len + 1 + h->value.len + 1
                                              + h->key.len);
                    if (h->key.data == NULL) {
                        h->hash = 0;
                        return NJT_ERROR;
                    }

                    h->value.data = h->key.data + h->key.len + 1;
                    h->lowcase_key = h->key.data + h->key.len + 1
                                     + h->value.len + 1;

                    njt_memcpy(h->key.data, r->header_name_start, h->key.len);
                    h->key.data[h->key.len] = '\0';
                    njt_memcpy(h->value.data, r->header_start, h->value.len);
                    h->value.data[h->value.len] = '\0';
                }

                h->hash = r->header_hash;

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
                               "http fastcgi header: \"%V: %V\"",
                               &h->key, &h->value);

                if (u->buffer.pos < u->buffer.last) {
                    continue;
                }

                /* the end of the FastCGI record */

                break;
            }

            if (rc == NJT_HTTP_PARSE_HEADER_DONE) {

                /* a whole header has been parsed successfully */

                njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http fastcgi header done");

                if (u->headers_in.status) {
                    status_line = &u->headers_in.status->value;

                    status = njt_atoi(status_line->data, 3);

                    if (status == NJT_ERROR) {
                        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                      "upstream sent invalid status \"%V\"",
                                      status_line);
                        return NJT_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    u->headers_in.status_n = status;

                    if (status_line->len > 3) {
                        u->headers_in.status_line = *status_line;
                    }

                } else if (u->headers_in.location) {
                    u->headers_in.status_n = 302;
                    njt_str_set(&u->headers_in.status_line,
                                "302 Moved Temporarily");

                } else {
                    u->headers_in.status_n = 200;
                    njt_str_set(&u->headers_in.status_line, "200 OK");
                }

                if (u->state && u->state->status == 0) {
                    u->state->status = u->headers_in.status_n;
                }

                break;
            }

            /* rc == NJT_HTTP_PARSE_INVALID_HEADER */

            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "upstream sent invalid header: \"%*s\\x%02xd...\"",
                          r->header_end - r->header_name_start,
                          r->header_name_start, *r->header_end);

            return NJT_HTTP_UPSTREAM_INVALID_HEADER;
        }

        if (last) {
            u->buffer.last = last;
        }

        f->length -= u->buffer.pos - start;

        if (f->length == 0) {
            f->state = njt_http_fastcgi_st_padding;
        }

        if (rc == NJT_HTTP_PARSE_HEADER_DONE) {
            return NJT_OK;
        }

        if (rc == NJT_OK) {
            continue;
        }

        /* rc == NJT_AGAIN */

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "upstream split a header line in FastCGI records");

        if (f->split_parts == NULL) {
            f->split_parts = njt_array_create(r->pool, 1,
                                        sizeof(njt_http_fastcgi_split_part_t));
            if (f->split_parts == NULL) {
                return NJT_ERROR;
            }
        }

        part = njt_array_push(f->split_parts);
        if (part == NULL) {
            return NJT_ERROR;
        }

        part->start = part_start;
        part->end = part_end;

        if (u->buffer.pos < u->buffer.last) {
            continue;
        }

        return NJT_AGAIN;
    }
}


static njt_int_t
njt_http_fastcgi_input_filter_init(void *data)
{
    njt_http_request_t  *r = data;

    njt_http_upstream_t          *u;
    njt_http_fastcgi_ctx_t       *f;
    njt_http_fastcgi_loc_conf_t  *flcf;

    u = r->upstream;

    f = njt_http_get_module_ctx(r, njt_http_fastcgi_module);
    flcf = njt_http_get_module_loc_conf(r, njt_http_fastcgi_module);

    u->pipe->length = flcf->keep_conn ?
                      (off_t) sizeof(njt_http_fastcgi_header_t) : -1;

    if (u->headers_in.status_n == NJT_HTTP_NO_CONTENT
        || u->headers_in.status_n == NJT_HTTP_NOT_MODIFIED)
    {
        f->rest = 0;

    } else if (r->method == NJT_HTTP_HEAD) {
        f->rest = -2;

    } else {
        f->rest = u->headers_in.content_length_n;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_fastcgi_input_filter(njt_event_pipe_t *p, njt_buf_t *buf)
{
    u_char                       *m, *msg;
    njt_int_t                     rc;
    njt_buf_t                    *b, **prev;
    njt_chain_t                  *cl;
    njt_http_request_t           *r;
    njt_http_fastcgi_ctx_t       *f;
    njt_http_fastcgi_loc_conf_t  *flcf;

    if (buf->pos == buf->last) {
        return NJT_OK;
    }

    r = p->input_ctx;
    f = njt_http_get_module_ctx(r, njt_http_fastcgi_module);
    flcf = njt_http_get_module_loc_conf(r, njt_http_fastcgi_module);

    if (p->upstream_done || f->closed) {
        r->upstream->keepalive = 0;

        njt_log_debug0(NJT_LOG_DEBUG_HTTP, p->log, 0,
                       "http fastcgi data after close");

        return NJT_OK;
    }

    b = NULL;
    prev = &buf->shadow;

    f->pos = buf->pos;
    f->last = buf->last;

    for ( ;; ) {
        if (f->state < njt_http_fastcgi_st_data) {

            rc = njt_http_fastcgi_process_record(r, f);

            if (rc == NJT_AGAIN) {
                break;
            }

            if (rc == NJT_ERROR) {
                return NJT_ERROR;
            }

            if (f->type == NJT_HTTP_FASTCGI_STDOUT && f->length == 0) {
                f->state = njt_http_fastcgi_st_padding;

                njt_log_debug0(NJT_LOG_DEBUG_HTTP, p->log, 0,
                               "http fastcgi closed stdout");

                if (f->rest > 0) {
                    njt_log_error(NJT_LOG_ERR, p->log, 0,
                                  "upstream prematurely closed "
                                  "FastCGI stdout");

                    p->upstream_error = 1;
                    p->upstream_eof = 0;
                    f->closed = 1;

                    break;
                }

                if (!flcf->keep_conn) {
                    p->upstream_done = 1;
                }

                continue;
            }

            if (f->type == NJT_HTTP_FASTCGI_END_REQUEST) {

                njt_log_debug0(NJT_LOG_DEBUG_HTTP, p->log, 0,
                               "http fastcgi sent end request");

                if (f->rest > 0) {
                    njt_log_error(NJT_LOG_ERR, p->log, 0,
                                  "upstream prematurely closed "
                                  "FastCGI request");

                    p->upstream_error = 1;
                    p->upstream_eof = 0;
                    f->closed = 1;

                    break;
                }

                if (!flcf->keep_conn) {
                    p->upstream_done = 1;
                    break;
                }

                continue;
            }
        }


        if (f->state == njt_http_fastcgi_st_padding) {

            if (f->type == NJT_HTTP_FASTCGI_END_REQUEST) {

                if (f->pos + f->padding < f->last) {
                    p->upstream_done = 1;
                    break;
                }

                if (f->pos + f->padding == f->last) {
                    p->upstream_done = 1;
                    r->upstream->keepalive = 1;
                    break;
                }

                f->padding -= f->last - f->pos;

                break;
            }

            if (f->pos + f->padding < f->last) {
                f->state = njt_http_fastcgi_st_version;
                f->pos += f->padding;

                continue;
            }

            if (f->pos + f->padding == f->last) {
                f->state = njt_http_fastcgi_st_version;

                break;
            }

            f->padding -= f->last - f->pos;

            break;
        }


        /* f->state == njt_http_fastcgi_st_data */

        if (f->type == NJT_HTTP_FASTCGI_STDERR) {

            if (f->length) {

                if (f->pos == f->last) {
                    break;
                }

                msg = f->pos;

                if (f->pos + f->length <= f->last) {
                    f->pos += f->length;
                    f->length = 0;
                    f->state = njt_http_fastcgi_st_padding;

                } else {
                    f->length -= f->last - f->pos;
                    f->pos = f->last;
                }

                for (m = f->pos - 1; msg < m; m--) {
                    if (*m != LF && *m != CR && *m != '.' && *m != ' ') {
                        break;
                    }
                }

                njt_log_error(NJT_LOG_ERR, p->log, 0,
                              "FastCGI sent in stderr: \"%*s\"",
                              m + 1 - msg, msg);

            } else {
                f->state = njt_http_fastcgi_st_padding;
            }

            continue;
        }

        if (f->type == NJT_HTTP_FASTCGI_END_REQUEST) {

            if (f->pos + f->length <= f->last) {
                f->state = njt_http_fastcgi_st_padding;
                f->pos += f->length;

                continue;
            }

            f->length -= f->last - f->pos;

            break;
        }


        /* f->type == NJT_HTTP_FASTCGI_STDOUT */

        if (f->pos == f->last) {
            break;
        }

        if (f->rest == -2) {
            f->rest = r->upstream->headers_in.content_length_n;
        }

        if (f->rest == 0) {
            njt_log_error(NJT_LOG_WARN, p->log, 0,
                          "upstream sent more data than specified in "
                          "\"Content-Length\" header");
            p->upstream_done = 1;
            break;
        }

        cl = njt_chain_get_free_buf(p->pool, &p->free);
        if (cl == NULL) {
            return NJT_ERROR;
        }

        b = cl->buf;

        njt_memzero(b, sizeof(njt_buf_t));

        b->pos = f->pos;
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

        if (f->pos + f->length <= f->last) {
            f->state = njt_http_fastcgi_st_padding;
            f->pos += f->length;
            b->last = f->pos;

        } else {
            f->length -= f->last - f->pos;
            f->pos = f->last;
            b->last = f->last;
        }

        if (f->rest > 0) {

            if (b->last - b->pos > f->rest) {
                njt_log_error(NJT_LOG_WARN, p->log, 0,
                              "upstream sent more data than specified in "
                              "\"Content-Length\" header");

                b->last = b->pos + f->rest;
                p->upstream_done = 1;

                break;
            }

            f->rest -= b->last - b->pos;
        }
    }

    if (flcf->keep_conn) {

        /* set p->length, minimal amount of data we want to see */

        if (f->state < njt_http_fastcgi_st_data) {
            p->length = 1;

        } else if (f->state == njt_http_fastcgi_st_padding) {
            p->length = f->padding;

        } else {
            /* njt_http_fastcgi_st_data */

            p->length = f->length;
        }
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
njt_http_fastcgi_non_buffered_filter(void *data, ssize_t bytes)
{
    u_char                  *m, *msg;
    njt_int_t                rc;
    njt_buf_t               *b, *buf;
    njt_chain_t             *cl, **ll;
    njt_http_request_t      *r;
    njt_http_upstream_t     *u;
    njt_http_fastcgi_ctx_t  *f;

    r = data;
    f = njt_http_get_module_ctx(r, njt_http_fastcgi_module);

    u = r->upstream;
    buf = &u->buffer;

    buf->pos = buf->last;
    buf->last += bytes;

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    f->pos = buf->pos;
    f->last = buf->last;

    for ( ;; ) {
        if (f->state < njt_http_fastcgi_st_data) {

            rc = njt_http_fastcgi_process_record(r, f);

            if (rc == NJT_AGAIN) {
                break;
            }

            if (rc == NJT_ERROR) {
                return NJT_ERROR;
            }

            if (f->type == NJT_HTTP_FASTCGI_STDOUT && f->length == 0) {
                f->state = njt_http_fastcgi_st_padding;

                njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http fastcgi closed stdout");

                continue;
            }
        }

        if (f->state == njt_http_fastcgi_st_padding) {

            if (f->type == NJT_HTTP_FASTCGI_END_REQUEST) {

                if (f->rest > 0) {
                    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                                  "upstream prematurely closed "
                                  "FastCGI request");
                    u->error = 1;
                    break;
                }

                if (f->pos + f->padding < f->last) {
                    u->length = 0;
                    break;
                }

                if (f->pos + f->padding == f->last) {
                    u->length = 0;
                    u->keepalive = 1;
                    break;
                }

                f->padding -= f->last - f->pos;

                break;
            }

            if (f->pos + f->padding < f->last) {
                f->state = njt_http_fastcgi_st_version;
                f->pos += f->padding;

                continue;
            }

            if (f->pos + f->padding == f->last) {
                f->state = njt_http_fastcgi_st_version;

                break;
            }

            f->padding -= f->last - f->pos;

            break;
        }


        /* f->state == njt_http_fastcgi_st_data */

        if (f->type == NJT_HTTP_FASTCGI_STDERR) {

            if (f->length) {

                if (f->pos == f->last) {
                    break;
                }

                msg = f->pos;

                if (f->pos + f->length <= f->last) {
                    f->pos += f->length;
                    f->length = 0;
                    f->state = njt_http_fastcgi_st_padding;

                } else {
                    f->length -= f->last - f->pos;
                    f->pos = f->last;
                }

                for (m = f->pos - 1; msg < m; m--) {
                    if (*m != LF && *m != CR && *m != '.' && *m != ' ') {
                        break;
                    }
                }

                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "FastCGI sent in stderr: \"%*s\"",
                              m + 1 - msg, msg);

            } else {
                f->state = njt_http_fastcgi_st_padding;
            }

            continue;
        }

        if (f->type == NJT_HTTP_FASTCGI_END_REQUEST) {

            if (f->pos + f->length <= f->last) {
                f->state = njt_http_fastcgi_st_padding;
                f->pos += f->length;

                continue;
            }

            f->length -= f->last - f->pos;

            break;
        }


        /* f->type == NJT_HTTP_FASTCGI_STDOUT */

        if (f->pos == f->last) {
            break;
        }

        if (f->rest == 0) {
            njt_log_error(NJT_LOG_WARN, r->connection->log, 0,
                          "upstream sent more data than specified in "
                          "\"Content-Length\" header");
            u->length = 0;
            break;
        }

        cl = njt_chain_get_free_buf(r->pool, &u->free_bufs);
        if (cl == NULL) {
            return NJT_ERROR;
        }

        *ll = cl;
        ll = &cl->next;

        b = cl->buf;

        b->flush = 1;
        b->memory = 1;

        b->pos = f->pos;
        b->tag = u->output.tag;

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http fastcgi output buf %p", b->pos);

        if (f->pos + f->length <= f->last) {
            f->state = njt_http_fastcgi_st_padding;
            f->pos += f->length;
            b->last = f->pos;

        } else {
            f->length -= f->last - f->pos;
            f->pos = f->last;
            b->last = f->last;
        }

        if (f->rest > 0) {

            if (b->last - b->pos > f->rest) {
                njt_log_error(NJT_LOG_WARN, r->connection->log, 0,
                              "upstream sent more data than specified in "
                              "\"Content-Length\" header");

                b->last = b->pos + f->rest;
                u->length = 0;

                break;
            }

            f->rest -= b->last - b->pos;
        }
    }

    return NJT_OK;
}


static njt_int_t
njt_http_fastcgi_process_record(njt_http_request_t *r,
    njt_http_fastcgi_ctx_t *f)
{
    u_char                     ch, *p;
    njt_http_fastcgi_state_e   state;

    state = f->state;

    for (p = f->pos; p < f->last; p++) {

        ch = *p;

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http fastcgi record byte: %02Xd", ch);

        switch (state) {

        case njt_http_fastcgi_st_version:
            if (ch != 1) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream sent unsupported FastCGI "
                              "protocol version: %d", ch);
                return NJT_ERROR;
            }
            state = njt_http_fastcgi_st_type;
            break;

        case njt_http_fastcgi_st_type:
            switch (ch) {
            case NJT_HTTP_FASTCGI_STDOUT:
            case NJT_HTTP_FASTCGI_STDERR:
            case NJT_HTTP_FASTCGI_END_REQUEST:
                f->type = (njt_uint_t) ch;
                break;
            default:
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid FastCGI "
                              "record type: %d", ch);
                return NJT_ERROR;

            }
            state = njt_http_fastcgi_st_request_id_hi;
            break;

        /* we support the single request per connection */

        case njt_http_fastcgi_st_request_id_hi:
            if (ch != 0) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream sent unexpected FastCGI "
                              "request id high byte: %d", ch);
                return NJT_ERROR;
            }
            state = njt_http_fastcgi_st_request_id_lo;
            break;

        case njt_http_fastcgi_st_request_id_lo:
            if (ch != 1) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                              "upstream sent unexpected FastCGI "
                              "request id low byte: %d", ch);
                return NJT_ERROR;
            }
            state = njt_http_fastcgi_st_content_length_hi;
            break;

        case njt_http_fastcgi_st_content_length_hi:
            f->length = ch << 8;
            state = njt_http_fastcgi_st_content_length_lo;
            break;

        case njt_http_fastcgi_st_content_length_lo:
            f->length |= (size_t) ch;
            state = njt_http_fastcgi_st_padding_length;
            break;

        case njt_http_fastcgi_st_padding_length:
            f->padding = (size_t) ch;
            state = njt_http_fastcgi_st_reserved;
            break;

        case njt_http_fastcgi_st_reserved:
            state = njt_http_fastcgi_st_data;

            njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http fastcgi record length: %z", f->length);

            f->pos = p + 1;
            f->state = state;

            return NJT_OK;

        /* suppress warning */
        case njt_http_fastcgi_st_data:
        case njt_http_fastcgi_st_padding:
            break;
        }
    }

    f->pos = p;
    f->state = state;

    return NJT_AGAIN;
}


static void
njt_http_fastcgi_abort_request(njt_http_request_t *r)
{
    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http fastcgi request");

    return;
}


static void
njt_http_fastcgi_finalize_request(njt_http_request_t *r, njt_int_t rc)
{
    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http fastcgi request");

    return;
}


static njt_int_t
njt_http_fastcgi_add_variables(njt_conf_t *cf)
{
    njt_http_variable_t  *var, *v;

    for (v = njt_http_fastcgi_vars; v->name.len; v++) {
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
njt_http_fastcgi_create_main_conf(njt_conf_t *cf)
{
    njt_http_fastcgi_main_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_fastcgi_main_conf_t));
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
njt_http_fastcgi_create_loc_conf(njt_conf_t *cf)
{
    njt_http_fastcgi_loc_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_fastcgi_loc_conf_t));
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
     *     conf->index.len = { 0, NULL };
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
    conf->upstream.limit_rate = NJT_CONF_UNSET_SIZE;

    conf->upstream.busy_buffers_size_conf = NJT_CONF_UNSET_SIZE;
    conf->upstream.max_temp_file_size_conf = NJT_CONF_UNSET_SIZE;
    conf->upstream.temp_file_write_size_conf = NJT_CONF_UNSET_SIZE;

    conf->upstream.pass_request_headers = NJT_CONF_UNSET;
    conf->upstream.pass_request_body = NJT_CONF_UNSET;

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
    conf->upstream.cache_background_update = NJT_CONF_UNSET;
#endif

    conf->upstream.hide_headers = NJT_CONF_UNSET_PTR;
    conf->upstream.pass_headers = NJT_CONF_UNSET_PTR;

    conf->upstream.intercept_errors = NJT_CONF_UNSET;

    /* "fastcgi_cyclic_temp_file" is disabled */
    conf->upstream.cyclic_temp_file = 0;

    conf->upstream.change_buffering = 1;

    conf->catch_stderr = NJT_CONF_UNSET_PTR;

    conf->keep_conn = NJT_CONF_UNSET;

    njt_str_set(&conf->upstream.module, "fastcgi");

    return conf;
}


static char *
njt_http_fastcgi_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_fastcgi_loc_conf_t *prev = parent;
    njt_http_fastcgi_loc_conf_t *conf = child;

    size_t                        size;
    njt_int_t                     rc;
    njt_hash_init_t               hash;
    njt_http_core_loc_conf_t     *clcf;

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

    njt_conf_merge_size_value(conf->upstream.limit_rate,
                              prev->upstream.limit_rate, 0);


    njt_conf_merge_bufs_value(conf->upstream.bufs, prev->upstream.bufs,
                              8, njt_pagesize);

    if (conf->upstream.bufs.num < 2) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "there must be at least 2 \"fastcgi_buffers\"");
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
             "\"fastcgi_busy_buffers_size\" must be equal to or greater than "
             "the maximum of the value of \"fastcgi_buffer_size\" and "
             "one of the \"fastcgi_buffers\"");

        return NJT_CONF_ERROR;
    }

    if (conf->upstream.busy_buffers_size
        > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size)
    {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
             "\"fastcgi_busy_buffers_size\" must be less than "
             "the size of all \"fastcgi_buffers\" minus one buffer");

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
             "\"fastcgi_temp_file_write_size\" must be equal to or greater "
             "than the maximum of the value of \"fastcgi_buffer_size\" and "
             "one of the \"fastcgi_buffers\"");

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
             "\"fastcgi_max_temp_file_size\" must be equal to zero to disable "
             "temporary files usage or must be equal to or greater than "
             "the maximum of the value of \"fastcgi_buffer_size\" and "
             "one of the \"fastcgi_buffers\"");

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
                              &njt_http_fastcgi_temp_path)
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
                           "\"fastcgi_cache\" zone \"%V\" is unknown",
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

    if (conf->upstream.cache && conf->cache_key.value.data == NULL) {
        njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                           "no \"fastcgi_cache_key\" for \"fastcgi_cache\"");
    }

    njt_conf_merge_value(conf->upstream.cache_lock,
                              prev->upstream.cache_lock, 0);

    njt_conf_merge_msec_value(conf->upstream.cache_lock_timeout,
                              prev->upstream.cache_lock_timeout, 5000);

    njt_conf_merge_msec_value(conf->upstream.cache_lock_age,
                              prev->upstream.cache_lock_age, 5000);

    njt_conf_merge_value(conf->upstream.cache_revalidate,
                              prev->upstream.cache_revalidate, 0);

    njt_conf_merge_value(conf->upstream.cache_background_update,
                              prev->upstream.cache_background_update, 0);

#endif

    njt_conf_merge_value(conf->upstream.pass_request_headers,
                              prev->upstream.pass_request_headers, 1);
    njt_conf_merge_value(conf->upstream.pass_request_body,
                              prev->upstream.pass_request_body, 1);

    njt_conf_merge_value(conf->upstream.intercept_errors,
                              prev->upstream.intercept_errors, 0);

    njt_conf_merge_ptr_value(conf->catch_stderr, prev->catch_stderr, NULL);

    njt_conf_merge_value(conf->keep_conn, prev->keep_conn, 0);


    njt_conf_merge_str_value(conf->index, prev->index, "");

    hash.max_size = 512;
    hash.bucket_size = njt_align(64, njt_cacheline_size);
    hash.name = "fastcgi_hide_headers_hash";

    if (njt_http_upstream_hide_headers_hash(cf, &conf->upstream,
             &prev->upstream, njt_http_fastcgi_hide_headers, &hash)
        != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);

    if (clcf->noname
        && conf->upstream.upstream == NULL && conf->fastcgi_lengths == NULL)
    {
        conf->upstream.upstream = prev->upstream.upstream;
        conf->fastcgi_lengths = prev->fastcgi_lengths;
        conf->fastcgi_values = prev->fastcgi_values;
    }

    if (clcf->lmt_excpt && clcf->handler == NULL
        && (conf->upstream.upstream || conf->fastcgi_lengths))
    {
        clcf->handler = njt_http_fastcgi_handler;
    }

#if (NJT_PCRE)
    if (conf->split_regex == NULL) {
        conf->split_regex = prev->split_regex;
        conf->split_name = prev->split_name;
    }
#endif

    if (conf->params_source == NULL) {
        conf->params = prev->params;
#if (NJT_HTTP_CACHE)
        conf->params_cache = prev->params_cache;
#endif
        conf->params_source = prev->params_source;
    }

    rc = njt_http_fastcgi_init_params(cf, conf, &conf->params, NULL);
    if (rc != NJT_OK) {
        return NJT_CONF_ERROR;
    }

#if (NJT_HTTP_CACHE)

    if (conf->upstream.cache) {
        rc = njt_http_fastcgi_init_params(cf, conf, &conf->params_cache,
                                          njt_http_fastcgi_cache_headers);
        if (rc != NJT_OK) {
            return NJT_CONF_ERROR;
        }
    }

#endif

    /*
     * special handling to preserve conf->params in the "http" section
     * to inherit it to all servers
     */

    if (prev->params.hash.buckets == NULL
        && conf->params_source == prev->params_source)
    {
        prev->params = conf->params;
#if (NJT_HTTP_CACHE)
        prev->params_cache = conf->params_cache;
#endif
    }

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_fastcgi_init_params(njt_conf_t *cf, njt_http_fastcgi_loc_conf_t *conf,
    njt_http_fastcgi_params_t *params, njt_keyval_t *default_params)
{
    u_char                       *p;
    size_t                        size;
    uintptr_t                    *code;
    njt_uint_t                    i, nsrc;
    njt_array_t                   headers_names, params_merged;
    njt_keyval_t                 *h;
    njt_hash_key_t               *hk;
    njt_hash_init_t               hash;
    njt_http_upstream_param_t    *src, *s;
    njt_http_script_compile_t     sc;
    njt_http_script_copy_code_t  *copy;

    if (params->hash.buckets) {
        return NJT_OK;
    }

    if (conf->params_source == NULL && default_params == NULL) {
        params->hash.buckets = (void *) 1;
        return NJT_OK;
    }

    params->lengths = njt_array_create(cf->pool, 64, 1);
    if (params->lengths == NULL) {
        return NJT_ERROR;
    }

    params->values = njt_array_create(cf->pool, 512, 1);
    if (params->values == NULL) {
        return NJT_ERROR;
    }

    if (njt_array_init(&headers_names, cf->temp_pool, 4, sizeof(njt_hash_key_t))
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    if (conf->params_source) {
        src = conf->params_source->elts;
        nsrc = conf->params_source->nelts;

    } else {
        src = NULL;
        nsrc = 0;
    }

    if (default_params) {
        if (njt_array_init(&params_merged, cf->temp_pool, 4,
                           sizeof(njt_http_upstream_param_t))
            != NJT_OK)
        {
            return NJT_ERROR;
        }

        for (i = 0; i < nsrc; i++) {

            s = njt_array_push(&params_merged);
            if (s == NULL) {
                return NJT_ERROR;
            }

            *s = src[i];
        }

        h = default_params;

        while (h->key.len) {

            src = params_merged.elts;
            nsrc = params_merged.nelts;

            for (i = 0; i < nsrc; i++) {
                if (njt_strcasecmp(h->key.data, src[i].key.data) == 0) {
                    goto next;
                }
            }

            s = njt_array_push(&params_merged);
            if (s == NULL) {
                return NJT_ERROR;
            }

            s->key = h->key;
            s->value = h->value;
            s->skip_empty = 1;

        next:

            h++;
        }

        src = params_merged.elts;
        nsrc = params_merged.nelts;
    }

    for (i = 0; i < nsrc; i++) {

        if (src[i].key.len > sizeof("HTTP_") - 1
            && njt_strncmp(src[i].key.data, "HTTP_", sizeof("HTTP_") - 1) == 0)
        {
            hk = njt_array_push(&headers_names);
            if (hk == NULL) {
                return NJT_ERROR;
            }

            hk->key.len = src[i].key.len - 5;
            hk->key.data = src[i].key.data + 5;
            hk->key_hash = njt_hash_key_lc(hk->key.data, hk->key.len);
            hk->value = (void *) 1;

            if (src[i].value.len == 0) {
                continue;
            }
        }

        copy = njt_array_push_n(params->lengths,
                                sizeof(njt_http_script_copy_code_t));
        if (copy == NULL) {
            return NJT_ERROR;
        }

        copy->code = (njt_http_script_code_pt) (void *)
                                                 njt_http_script_copy_len_code;
        copy->len = src[i].key.len;

        copy = njt_array_push_n(params->lengths,
                                sizeof(njt_http_script_copy_code_t));
        if (copy == NULL) {
            return NJT_ERROR;
        }

        copy->code = (njt_http_script_code_pt) (void *)
                                                 njt_http_script_copy_len_code;
        copy->len = src[i].skip_empty;


        size = (sizeof(njt_http_script_copy_code_t)
                + src[i].key.len + sizeof(uintptr_t) - 1)
               & ~(sizeof(uintptr_t) - 1);

        copy = njt_array_push_n(params->values, size);
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
        sc.flushes = &params->flushes;
        sc.lengths = &params->lengths;
        sc.values = &params->values;

        if (njt_http_script_compile(&sc) != NJT_OK) {
            return NJT_ERROR;
        }

        code = njt_array_push_n(params->lengths, sizeof(uintptr_t));
        if (code == NULL) {
            return NJT_ERROR;
        }

        *code = (uintptr_t) NULL;


        code = njt_array_push_n(params->values, sizeof(uintptr_t));
        if (code == NULL) {
            return NJT_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    code = njt_array_push_n(params->lengths, sizeof(uintptr_t));
    if (code == NULL) {
        return NJT_ERROR;
    }

    *code = (uintptr_t) NULL;

    params->number = headers_names.nelts;

    hash.hash = &params->hash;
    hash.key = njt_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = 64;
    hash.name = "fastcgi_params_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    return njt_hash_init(&hash, headers_names.elts, headers_names.nelts);
}


static njt_int_t
njt_http_fastcgi_script_name_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    u_char                       *p;
    njt_http_fastcgi_ctx_t       *f;
    njt_http_fastcgi_loc_conf_t  *flcf;

    flcf = njt_http_get_module_loc_conf(r, njt_http_fastcgi_module);

    f = njt_http_fastcgi_split(r, flcf);

    if (f == NULL) {
        return NJT_ERROR;
    }

    if (f->script_name.len == 0
        || f->script_name.data[f->script_name.len - 1] != '/')
    {
        v->len = f->script_name.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = f->script_name.data;

        return NJT_OK;
    }

    v->len = f->script_name.len + flcf->index.len;

    v->data = njt_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        return NJT_ERROR;
    }

    p = njt_copy(v->data, f->script_name.data, f->script_name.len);
    njt_memcpy(p, flcf->index.data, flcf->index.len);

    return NJT_OK;
}


static njt_int_t
njt_http_fastcgi_path_info_variable(njt_http_request_t *r,
    njt_http_variable_value_t *v, uintptr_t data)
{
    njt_http_fastcgi_ctx_t       *f;
    njt_http_fastcgi_loc_conf_t  *flcf;

    flcf = njt_http_get_module_loc_conf(r, njt_http_fastcgi_module);

    f = njt_http_fastcgi_split(r, flcf);

    if (f == NULL) {
        return NJT_ERROR;
    }

    v->len = f->path_info.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = f->path_info.data;

    return NJT_OK;
}


static njt_http_fastcgi_ctx_t *
njt_http_fastcgi_split(njt_http_request_t *r, njt_http_fastcgi_loc_conf_t *flcf)
{
    njt_http_fastcgi_ctx_t       *f;
#if (NJT_PCRE)
    njt_int_t                     n;
    int                           captures[(1 + 2) * 3];

    f = njt_http_get_module_ctx(r, njt_http_fastcgi_module);

    if (f == NULL) {
        f = njt_pcalloc(r->pool, sizeof(njt_http_fastcgi_ctx_t));
        if (f == NULL) {
            return NULL;
        }

        njt_http_set_ctx(r, f, njt_http_fastcgi_module);
    }

    if (f->script_name.len) {
        return f;
    }

    if (flcf->split_regex == NULL) {
        f->script_name = r->uri;
        return f;
    }

    n = njt_regex_exec(flcf->split_regex, &r->uri, captures, (1 + 2) * 3);

    if (n >= 0) { /* match */
        f->script_name.len = captures[3] - captures[2];
        f->script_name.data = r->uri.data + captures[2];

        f->path_info.len = captures[5] - captures[4];
        f->path_info.data = r->uri.data + captures[4];

        return f;
    }

    if (n == NJT_REGEX_NO_MATCHED) {
        f->script_name = r->uri;
        return f;
    }

    njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
                  njt_regex_exec_n " failed: %i on \"%V\" using \"%V\"",
                  n, &r->uri, &flcf->split_name);
    return NULL;

#else

    f = njt_http_get_module_ctx(r, njt_http_fastcgi_module);

    if (f == NULL) {
        f = njt_pcalloc(r->pool, sizeof(njt_http_fastcgi_ctx_t));
        if (f == NULL) {
            return NULL;
        }

        njt_http_set_ctx(r, f, njt_http_fastcgi_module);
    }

    f->script_name = r->uri;

    return f;

#endif
}


static char *
njt_http_fastcgi_pass(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_fastcgi_loc_conf_t *flcf = conf;

    njt_url_t                   u;
    njt_str_t                  *value, *url;
    njt_uint_t                  n;
    njt_http_core_loc_conf_t   *clcf;
    njt_http_script_compile_t   sc;

    if (flcf->upstream.upstream || flcf->fastcgi_lengths) {
        return "is duplicate";
    }

    clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);

    clcf->handler = njt_http_fastcgi_handler;

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
        sc.lengths = &flcf->fastcgi_lengths;
        sc.values = &flcf->fastcgi_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (njt_http_script_compile(&sc) != NJT_OK) {
            return NJT_CONF_ERROR;
        }

        return NJT_CONF_OK;
    }

    njt_memzero(&u, sizeof(njt_url_t));

    u.url = value[1];
    u.no_resolve = 1;

    flcf->upstream.upstream = njt_http_upstream_add(cf, &u, 0);
    if (flcf->upstream.upstream == NULL) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static char *
njt_http_fastcgi_split_path_info(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
#if (NJT_PCRE)
    njt_http_fastcgi_loc_conf_t *flcf = conf;

    njt_str_t            *value;
    njt_regex_compile_t   rc;
    u_char                errstr[NJT_MAX_CONF_ERRSTR];

    value = cf->args->elts;

    flcf->split_name = value[1];

    njt_memzero(&rc, sizeof(njt_regex_compile_t));

    rc.pattern = value[1];
    rc.pool = cf->pool;
    rc.err.len = NJT_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    if (njt_regex_compile(&rc) != NJT_OK) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "%V", &rc.err);
        return NJT_CONF_ERROR;
    }

    if (rc.captures != 2) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "pattern \"%V\" must have 2 captures", &value[1]);
        return NJT_CONF_ERROR;
    }

    flcf->split_regex = rc.regex;

    return NJT_CONF_OK;

#else

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "\"%V\" requires PCRE library", &cmd->name);
    return NJT_CONF_ERROR;

#endif
}


static char *
njt_http_fastcgi_store(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_fastcgi_loc_conf_t *flcf = conf;

    njt_str_t                  *value;
    njt_http_script_compile_t   sc;

    if (flcf->upstream.store != NJT_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (njt_strcmp(value[1].data, "off") == 0) {
        flcf->upstream.store = 0;
        return NJT_CONF_OK;
    }

#if (NJT_HTTP_CACHE)
    if (flcf->upstream.cache > 0) {
        return "is incompatible with \"fastcgi_cache\"";
    }
#endif

    flcf->upstream.store = 1;

    if (njt_strcmp(value[1].data, "on") == 0) {
        return NJT_CONF_OK;
    }

    /* include the terminating '\0' into script */
    value[1].len++;

    njt_memzero(&sc, sizeof(njt_http_script_compile_t));

    sc.cf = cf;
    sc.source = &value[1];
    sc.lengths = &flcf->upstream.store_lengths;
    sc.values = &flcf->upstream.store_values;
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
njt_http_fastcgi_cache(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_fastcgi_loc_conf_t *flcf = conf;

    njt_str_t                         *value;
    njt_http_complex_value_t           cv;
    njt_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (flcf->upstream.cache != NJT_CONF_UNSET) {
        return "is duplicate";
    }

    if (njt_strcmp(value[1].data, "off") == 0) {
        flcf->upstream.cache = 0;
        return NJT_CONF_OK;
    }

    if (flcf->upstream.store > 0) {
        return "is incompatible with \"fastcgi_store\"";
    }

    flcf->upstream.cache = 1;

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    if (cv.lengths != NULL) {

        flcf->upstream.cache_value = njt_palloc(cf->pool,
                                             sizeof(njt_http_complex_value_t));
        if (flcf->upstream.cache_value == NULL) {
            return NJT_CONF_ERROR;
        }

        *flcf->upstream.cache_value = cv;

        return NJT_CONF_OK;
    }

    flcf->upstream.cache_zone = njt_shared_memory_add(cf, &value[1], 0,
                                                      &njt_http_fastcgi_module);
    if (flcf->upstream.cache_zone == NULL) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static char *
njt_http_fastcgi_cache_key(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_fastcgi_loc_conf_t *flcf = conf;

    njt_str_t                         *value;
    njt_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (flcf->cache_key.value.data) {
        return "is duplicate";
    }

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &flcf->cache_key;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}

#endif


static char *
njt_http_fastcgi_lowat_check(njt_conf_t *cf, void *post, void *data)
{
#if (NJT_FREEBSD)
    ssize_t *np = data;

    if ((u_long) *np >= njt_freebsd_net_inet_tcp_sendspace) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "\"fastcgi_send_lowat\" must be less than %d "
                           "(sysctl net.inet.tcp.sendspace)",
                           njt_freebsd_net_inet_tcp_sendspace);

        return NJT_CONF_ERROR;
    }

#elif !(NJT_HAVE_SO_SNDLOWAT)
    ssize_t *np = data;

    njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                       "\"fastcgi_send_lowat\" is not supported, ignored");

    *np = 0;

#endif

    return NJT_CONF_OK;
}
