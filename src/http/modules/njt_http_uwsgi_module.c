
/*
 * Copyright (C) Unbit S.a.s. 2009-2010
 * Copyright (C) 2008 Manlio Perillo (manlio.perillo@gmail.com)
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


typedef struct {
    njt_array_t                caches;  /* njt_http_file_cache_t * */
} njt_http_uwsgi_main_conf_t;


typedef struct {
    njt_array_t               *flushes;
    njt_array_t               *lengths;
    njt_array_t               *values;
    njt_uint_t                 number;
    njt_hash_t                 hash;
} njt_http_uwsgi_params_t;


typedef struct {
    njt_http_upstream_conf_t   upstream;

    njt_http_uwsgi_params_t    params;
#if (NJT_HTTP_CACHE)
    njt_http_uwsgi_params_t    params_cache;
#endif
    njt_array_t               *params_source;

    njt_array_t               *uwsgi_lengths;
    njt_array_t               *uwsgi_values;

#if (NJT_HTTP_CACHE)
    njt_http_complex_value_t   cache_key;
#endif

    njt_str_t                  uwsgi_string;

    njt_uint_t                 modifier1;
    njt_uint_t                 modifier2;

#if (NJT_HTTP_SSL)
    njt_uint_t                 ssl;
    njt_uint_t                 ssl_protocols;
    njt_str_t                  ssl_ciphers;
    njt_uint_t                 ssl_verify_depth;
    njt_str_t                  ssl_trusted_certificate;
    njt_str_t                  ssl_crl;
    njt_array_t               *ssl_conf_commands;
#endif
} njt_http_uwsgi_loc_conf_t;


static njt_int_t njt_http_uwsgi_eval(njt_http_request_t *r,
    njt_http_uwsgi_loc_conf_t *uwcf);
static njt_int_t njt_http_uwsgi_create_request(njt_http_request_t *r);
static njt_int_t njt_http_uwsgi_reinit_request(njt_http_request_t *r);
static njt_int_t njt_http_uwsgi_process_status_line(njt_http_request_t *r);
static njt_int_t njt_http_uwsgi_process_header(njt_http_request_t *r);
static njt_int_t njt_http_uwsgi_input_filter_init(void *data);
static void njt_http_uwsgi_abort_request(njt_http_request_t *r);
static void njt_http_uwsgi_finalize_request(njt_http_request_t *r,
    njt_int_t rc);

static void *njt_http_uwsgi_create_main_conf(njt_conf_t *cf);
static void *njt_http_uwsgi_create_loc_conf(njt_conf_t *cf);
static char *njt_http_uwsgi_merge_loc_conf(njt_conf_t *cf, void *parent,
    void *child);
static njt_int_t njt_http_uwsgi_init_params(njt_conf_t *cf,
    njt_http_uwsgi_loc_conf_t *conf, njt_http_uwsgi_params_t *params,
    njt_keyval_t *default_params);

static char *njt_http_uwsgi_pass(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_uwsgi_store(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);

#if (NJT_HTTP_CACHE)
static njt_int_t njt_http_uwsgi_create_key(njt_http_request_t *r);
static char *njt_http_uwsgi_cache(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_uwsgi_cache_key(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
#endif

#if (NJT_HTTP_SSL)
static char *njt_http_uwsgi_ssl_password_file(njt_conf_t *cf,
    njt_command_t *cmd, void *conf);
static char *njt_http_uwsgi_ssl_conf_command_check(njt_conf_t *cf, void *post,
    void *data);
static njt_int_t njt_http_uwsgi_merge_ssl(njt_conf_t *cf,
    njt_http_uwsgi_loc_conf_t *conf, njt_http_uwsgi_loc_conf_t *prev);
static njt_int_t njt_http_uwsgi_set_ssl(njt_conf_t *cf,
    njt_http_uwsgi_loc_conf_t *uwcf);
#endif


static njt_conf_num_bounds_t  njt_http_uwsgi_modifier_bounds = {
    njt_conf_check_num_bounds, 0, 255
};


static njt_conf_bitmask_t njt_http_uwsgi_next_upstream_masks[] = {
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


#if (NJT_HTTP_SSL)

static njt_conf_bitmask_t  njt_http_uwsgi_ssl_protocols[] = {
    { njt_string("SSLv2"), NJT_SSL_SSLv2 },
    { njt_string("SSLv3"), NJT_SSL_SSLv3 },
    { njt_string("TLSv1"), NJT_SSL_TLSv1 },
    { njt_string("TLSv1.1"), NJT_SSL_TLSv1_1 },
    { njt_string("TLSv1.2"), NJT_SSL_TLSv1_2 },
    { njt_string("TLSv1.3"), NJT_SSL_TLSv1_3 },
    { njt_null_string, 0 }
};

static njt_conf_post_t  njt_http_uwsgi_ssl_conf_command_post =
    { njt_http_uwsgi_ssl_conf_command_check };

#endif


njt_module_t  njt_http_uwsgi_module;


static njt_command_t njt_http_uwsgi_commands[] = {

    { njt_string("uwsgi_pass"),
      NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE1,
      njt_http_uwsgi_pass,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("uwsgi_modifier1"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, modifier1),
      &njt_http_uwsgi_modifier_bounds },

    { njt_string("uwsgi_modifier2"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, modifier2),
      &njt_http_uwsgi_modifier_bounds },

    { njt_string("uwsgi_store"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_uwsgi_store,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("uwsgi_store_access"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE123,
      njt_conf_set_access_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.store_access),
      NULL },

    { njt_string("uwsgi_buffering"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.buffering),
      NULL },

    { njt_string("uwsgi_request_buffering"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.request_buffering),
      NULL },

    { njt_string("uwsgi_ignore_client_abort"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.ignore_client_abort),
      NULL },

    { njt_string("uwsgi_bind"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE12,
      njt_http_upstream_bind_set_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.local),
      NULL },

    { njt_string("uwsgi_socket_keepalive"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.socket_keepalive),
      NULL },

    { njt_string("uwsgi_connect_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.connect_timeout),
      NULL },

    { njt_string("uwsgi_send_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.send_timeout),
      NULL },

    { njt_string("uwsgi_buffer_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.buffer_size),
      NULL },

    { njt_string("uwsgi_pass_request_headers"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.pass_request_headers),
      NULL },

    { njt_string("uwsgi_pass_request_body"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.pass_request_body),
      NULL },

    { njt_string("uwsgi_intercept_errors"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.intercept_errors),
      NULL },

    { njt_string("uwsgi_read_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.read_timeout),
      NULL },

    { njt_string("uwsgi_buffers"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE2,
      njt_conf_set_bufs_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.bufs),
      NULL },

    { njt_string("uwsgi_busy_buffers_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.busy_buffers_size_conf),
      NULL },

    { njt_string("uwsgi_force_ranges"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.force_ranges),
      NULL },

    { njt_string("uwsgi_limit_rate"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.limit_rate),
      NULL },

#if (NJT_HTTP_CACHE)

    { njt_string("uwsgi_cache"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_uwsgi_cache,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("uwsgi_cache_key"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_uwsgi_cache_key,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("uwsgi_cache_path"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_2MORE,
      njt_http_file_cache_set_slot,
      NJT_HTTP_MAIN_CONF_OFFSET,
      offsetof(njt_http_uwsgi_main_conf_t, caches),
      &njt_http_uwsgi_module },

    { njt_string("uwsgi_cache_bypass"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_http_set_predicate_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.cache_bypass),
      NULL },

    { njt_string("uwsgi_no_cache"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_http_set_predicate_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.no_cache),
      NULL },

    { njt_string("uwsgi_cache_valid"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_http_file_cache_valid_set_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.cache_valid),
      NULL },

    { njt_string("uwsgi_cache_min_uses"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.cache_min_uses),
      NULL },

    { njt_string("uwsgi_cache_max_range_offset"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_off_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.cache_max_range_offset),
      NULL },

    { njt_string("uwsgi_cache_use_stale"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.cache_use_stale),
      &njt_http_uwsgi_next_upstream_masks },

    { njt_string("uwsgi_cache_methods"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.cache_methods),
      &njt_http_upstream_cache_method_mask },

    { njt_string("uwsgi_cache_lock"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.cache_lock),
      NULL },

    { njt_string("uwsgi_cache_lock_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.cache_lock_timeout),
      NULL },

    { njt_string("uwsgi_cache_lock_age"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.cache_lock_age),
      NULL },

    { njt_string("uwsgi_cache_revalidate"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.cache_revalidate),
      NULL },

    { njt_string("uwsgi_cache_background_update"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.cache_background_update),
      NULL },

#endif

    { njt_string("uwsgi_temp_path"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1234,
      njt_conf_set_path_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.temp_path),
      NULL },

    { njt_string("uwsgi_max_temp_file_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.max_temp_file_size_conf),
      NULL },

    { njt_string("uwsgi_temp_file_write_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.temp_file_write_size_conf),
      NULL },

    { njt_string("uwsgi_next_upstream"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.next_upstream),
      &njt_http_uwsgi_next_upstream_masks },

    { njt_string("uwsgi_next_upstream_tries"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.next_upstream_tries),
      NULL },

    { njt_string("uwsgi_next_upstream_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.next_upstream_timeout),
      NULL },

    { njt_string("uwsgi_param"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE23,
      njt_http_upstream_param_set_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, params_source),
      NULL },

    { njt_string("uwsgi_string"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, uwsgi_string),
      NULL },

    { njt_string("uwsgi_pass_header"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_array_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.pass_headers),
      NULL },

    { njt_string("uwsgi_hide_header"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_array_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.hide_headers),
      NULL },

    { njt_string("uwsgi_ignore_headers"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.ignore_headers),
      &njt_http_upstream_ignore_headers_masks },

#if (NJT_HTTP_SSL)

    { njt_string("uwsgi_ssl_session_reuse"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.ssl_session_reuse),
      NULL },

    { njt_string("uwsgi_ssl_protocols"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, ssl_protocols),
      &njt_http_uwsgi_ssl_protocols },

    { njt_string("uwsgi_ssl_ciphers"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, ssl_ciphers),
      NULL },

    { njt_string("uwsgi_ssl_name"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_set_complex_value_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.ssl_name),
      NULL },

    { njt_string("uwsgi_ssl_server_name"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.ssl_server_name),
      NULL },

    { njt_string("uwsgi_ssl_verify"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.ssl_verify),
      NULL },

    { njt_string("uwsgi_ssl_verify_depth"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, ssl_verify_depth),
      NULL },

    { njt_string("uwsgi_ssl_trusted_certificate"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, ssl_trusted_certificate),
      NULL },

    { njt_string("uwsgi_ssl_crl"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, ssl_crl),
      NULL },

    { njt_string("uwsgi_ssl_certificate"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_set_complex_value_zero_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.ssl_certificate),
      NULL },

    { njt_string("uwsgi_ssl_certificate_key"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_set_complex_value_zero_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, upstream.ssl_certificate_key),
      NULL },

    { njt_string("uwsgi_ssl_password_file"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_uwsgi_ssl_password_file,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("uwsgi_ssl_conf_command"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE2,
      njt_conf_set_keyval_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_uwsgi_loc_conf_t, ssl_conf_commands),
      &njt_http_uwsgi_ssl_conf_command_post },

#endif

      njt_null_command
};


static njt_http_module_t njt_http_uwsgi_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    njt_http_uwsgi_create_main_conf,       /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_uwsgi_create_loc_conf,        /* create location configuration */
    njt_http_uwsgi_merge_loc_conf          /* merge location configuration */
};


njt_module_t njt_http_uwsgi_module = {
    NJT_MODULE_V1,
    &njt_http_uwsgi_module_ctx,            /* module context */
    njt_http_uwsgi_commands,               /* module directives */
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


static njt_str_t njt_http_uwsgi_hide_headers[] = {
    njt_string("X-Accel-Expires"),
    njt_string("X-Accel-Redirect"),
    njt_string("X-Accel-Limit-Rate"),
    njt_string("X-Accel-Buffering"),
    njt_string("X-Accel-Charset"),
    njt_null_string
};


#if (NJT_HTTP_CACHE)

static njt_keyval_t  njt_http_uwsgi_cache_headers[] = {
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


static njt_path_init_t njt_http_uwsgi_temp_path = {
    njt_string(NJT_HTTP_UWSGI_TEMP_PATH), { 1, 2, 0 }
};


static njt_int_t
njt_http_uwsgi_handler(njt_http_request_t *r)
{
    njt_int_t                    rc;
    njt_http_status_t           *status;
    njt_http_upstream_t         *u;
    njt_http_uwsgi_loc_conf_t   *uwcf;
#if (NJT_HTTP_CACHE)
    njt_http_uwsgi_main_conf_t  *uwmcf;
#endif

    if (njt_http_upstream_create(r) != NJT_OK) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    status = njt_pcalloc(r->pool, sizeof(njt_http_status_t));
    if (status == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    njt_http_set_ctx(r, status, njt_http_uwsgi_module);

    uwcf = njt_http_get_module_loc_conf(r, njt_http_uwsgi_module);

    u = r->upstream;

    if (uwcf->uwsgi_lengths == NULL) {

#if (NJT_HTTP_SSL)
        u->ssl = uwcf->ssl;

        if (u->ssl) {
            njt_str_set(&u->schema, "suwsgi://");

        } else {
            njt_str_set(&u->schema, "uwsgi://");
        }
#else
        njt_str_set(&u->schema, "uwsgi://");
#endif

    } else {
        if (njt_http_uwsgi_eval(r, uwcf) != NJT_OK) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    u->output.tag = (njt_buf_tag_t) &njt_http_uwsgi_module;

    u->conf = &uwcf->upstream;

#if (NJT_HTTP_CACHE)
    uwmcf = njt_http_get_module_main_conf(r, njt_http_uwsgi_module);

    u->caches = &uwmcf->caches;
    u->create_key = njt_http_uwsgi_create_key;
#endif

    u->create_request = njt_http_uwsgi_create_request;
    u->reinit_request = njt_http_uwsgi_reinit_request;
    u->process_header = njt_http_uwsgi_process_status_line;
    u->abort_request = njt_http_uwsgi_abort_request;
    u->finalize_request = njt_http_uwsgi_finalize_request;
    r->state = 0;

    u->buffering = uwcf->upstream.buffering;

    u->pipe = njt_pcalloc(r->pool, sizeof(njt_event_pipe_t));
    if (u->pipe == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    u->pipe->input_filter = njt_event_pipe_copy_input_filter;
    u->pipe->input_ctx = r;

    u->input_filter_init = njt_http_uwsgi_input_filter_init;
    u->input_filter = njt_http_upstream_non_buffered_filter;
    u->input_filter_ctx = r;

    if (!uwcf->upstream.request_buffering
        && uwcf->upstream.pass_request_body
        && !r->headers_in.chunked)
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
njt_http_uwsgi_eval(njt_http_request_t *r, njt_http_uwsgi_loc_conf_t * uwcf)
{
    size_t                add;
    njt_url_t             url;
    njt_http_upstream_t  *u;

    njt_memzero(&url, sizeof(njt_url_t));

    if (njt_http_script_run(r, &url.url, uwcf->uwsgi_lengths->elts, 0,
                            uwcf->uwsgi_values->elts)
        == NULL)
    {
        return NJT_ERROR;
    }

    if (url.url.len > 8
        && njt_strncasecmp(url.url.data, (u_char *) "uwsgi://", 8) == 0)
    {
        add = 8;

    } else if (url.url.len > 9
               && njt_strncasecmp(url.url.data, (u_char *) "suwsgi://", 9) == 0)
    {

#if (NJT_HTTP_SSL)
        add = 9;
        r->upstream->ssl = 1;
#else
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "suwsgi protocol requires SSL support");
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
        njt_str_set(&u->schema, "uwsgi://");
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

    return NJT_OK;
}


#if (NJT_HTTP_CACHE)

static njt_int_t
njt_http_uwsgi_create_key(njt_http_request_t *r)
{
    njt_str_t                  *key;
    njt_http_uwsgi_loc_conf_t  *uwcf;

    key = njt_array_push(&r->cache->keys);
    if (key == NULL) {
        return NJT_ERROR;
    }

    uwcf = njt_http_get_module_loc_conf(r, njt_http_uwsgi_module);

    if (njt_http_complex_value(r, &uwcf->cache_key, key) != NJT_OK) {
        return NJT_ERROR;
    }

    return NJT_OK;
}

#endif


static njt_int_t
njt_http_uwsgi_create_request(njt_http_request_t *r)
{
    u_char                        ch, sep, *lowcase_key;
    size_t                        key_len, val_len, len, allocated;
    njt_uint_t                    i, n, hash, skip_empty, header_params;
    njt_buf_t                    *b;
    njt_chain_t                  *cl, *body;
    njt_list_part_t              *part;
    njt_table_elt_t              *header, *hn, **ignored;
    njt_http_uwsgi_params_t      *params;
    njt_http_script_code_pt       code;
    njt_http_script_engine_t      e, le;
    njt_http_uwsgi_loc_conf_t    *uwcf;
    njt_http_script_len_code_pt   lcode;

    len = 0;
    header_params = 0;
    ignored = NULL;

    uwcf = njt_http_get_module_loc_conf(r, njt_http_uwsgi_module);

#if (NJT_HTTP_CACHE)
    params = r->upstream->cacheable ? &uwcf->params_cache : &uwcf->params;
#else
    params = &uwcf->params;
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

            len += 2 + key_len + 2 + val_len;
        }
    }

    if (uwcf->upstream.pass_request_headers) {

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

        for (i = 0; /* void */ ; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            for (n = 0; n < header_params; n++) {
                if (ignored != NULL &&  &header[i] == ignored[n]) {
                    goto next_length;
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

                if (njt_hash_find(&params->hash, hash, lowcase_key, n) && ignored != NULL) {
                    ignored[header_params++] = &header[i];
                    continue;
                }
            }

            len += 2 + sizeof("HTTP_") - 1 + header[i].key.len
                 + 2 + header[i].value.len;

            for (hn = header[i].next; hn; hn = hn->next) {
                len += hn->value.len + 2;
		if(ignored != NULL) {
                	ignored[header_params++] = hn;
		}
            }

        next_length:

            continue;
        }
    }

    len += uwcf->uwsgi_string.len;

#if 0
    /* allow custom uwsgi packet */
    if (len > 0 && len < 2) {
        njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
                      "uwsgi request is too little: %uz", len);
        return NJT_ERROR;
    }
#endif

    if (len > 65535) {
        njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
                      "uwsgi request is too big: %uz", len);
        return NJT_ERROR;
    }

    b = njt_create_temp_buf(r->pool, len + 4);
    if (b == NULL) {
        return NJT_ERROR;
    }

    cl = njt_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NJT_ERROR;
    }

    cl->buf = b;

    *b->last++ = (u_char) uwcf->modifier1;
    *b->last++ = (u_char) (len & 0xff);
    *b->last++ = (u_char) ((len >> 8) & 0xff);
    *b->last++ = (u_char) uwcf->modifier2;

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

            *e.pos++ = (u_char) (key_len & 0xff);
            *e.pos++ = (u_char) ((key_len >> 8) & 0xff);

            code = *(njt_http_script_code_pt *) e.ip;
            code((njt_http_script_engine_t *) &e);

            *e.pos++ = (u_char) (val_len & 0xff);
            *e.pos++ = (u_char) ((val_len >> 8) & 0xff);

            while (*(uintptr_t *) e.ip) {
                code = *(njt_http_script_code_pt *) e.ip;
                code((njt_http_script_engine_t *) &e);
            }

            e.ip += sizeof(uintptr_t);

            njt_log_debug4(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "uwsgi param: \"%*s: %*s\"",
                           key_len, e.pos - (key_len + 2 + val_len),
                           val_len, e.pos - val_len);
        }

        b->last = e.pos;
    }

    if (uwcf->upstream.pass_request_headers) {

        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0; /* void */ ; i++) {

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
            *b->last++ = (u_char) (key_len & 0xff);
            *b->last++ = (u_char) ((key_len >> 8) & 0xff);

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

            val_len = header[i].value.len;

            for (hn = header[i].next; hn; hn = hn->next) {
                val_len += hn->value.len + 2;
            }

            *b->last++ = (u_char) (val_len & 0xff);
            *b->last++ = (u_char) ((val_len >> 8) & 0xff);
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
                           "uwsgi param: \"%*s: %*s\"",
                           key_len, b->last - (key_len + 2 + val_len),
                           val_len, b->last - val_len);
        next_value:

            continue;
        }
    }

    b->last = njt_copy(b->last, uwcf->uwsgi_string.data,
                       uwcf->uwsgi_string.len);

    if (r->request_body_no_buffering) {
        r->upstream->request_bufs = cl;

    } else if (uwcf->upstream.pass_request_body) {
        body = r->upstream->request_bufs;
        r->upstream->request_bufs = cl;

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
        r->upstream->request_bufs = cl;
    }

    b->flush = 1;
    cl->next = NULL;

    return NJT_OK;
}


static njt_int_t
njt_http_uwsgi_reinit_request(njt_http_request_t *r)
{
    njt_http_status_t  *status;

    status = njt_http_get_module_ctx(r, njt_http_uwsgi_module);

    if (status == NULL) {
        return NJT_OK;
    }

    status->code = 0;
    status->count = 0;
    status->start = NULL;
    status->end = NULL;

    r->upstream->process_header = njt_http_uwsgi_process_status_line;
    r->state = 0;

    return NJT_OK;
}


static njt_int_t
njt_http_uwsgi_process_status_line(njt_http_request_t *r)
{
    size_t                 len;
    njt_int_t              rc;
    njt_http_status_t     *status;
    njt_http_upstream_t   *u;

    status = njt_http_get_module_ctx(r, njt_http_uwsgi_module);

    if (status == NULL) {
        return NJT_ERROR;
    }

    u = r->upstream;

    rc = njt_http_parse_status_line(r, &u->buffer, status);

    if (rc == NJT_AGAIN) {
        return rc;
    }

    if (rc == NJT_ERROR) {
        u->process_header = njt_http_uwsgi_process_header;
        return njt_http_uwsgi_process_header(r);
    }

    if (u->state && u->state->status == 0) {
        u->state->status = status->code;
    }

    u->headers_in.status_n = status->code;

    len = status->end - status->start;
    u->headers_in.status_line.len = len;

    u->headers_in.status_line.data = njt_pnalloc(r->pool, len);
    if (u->headers_in.status_line.data == NULL) {
        return NJT_ERROR;
    }

    njt_memcpy(u->headers_in.status_line.data, status->start, len);

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http uwsgi status %ui \"%V\"",
                   u->headers_in.status_n, &u->headers_in.status_line);

    u->process_header = njt_http_uwsgi_process_header;

    return njt_http_uwsgi_process_header(r);
}


static njt_int_t
njt_http_uwsgi_process_header(njt_http_request_t *r)
{
    njt_str_t                      *status_line;
    njt_int_t                       rc, status;
    njt_table_elt_t                *h;
    njt_http_upstream_t            *u;
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
                                      h->key.len + 1 + h->value.len + 1
                                      + h->key.len);
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
                           "http uwsgi header: \"%V: %V\"", &h->key, &h->value);

            continue;
        }

        if (rc == NJT_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http uwsgi header done");

            u = r->upstream;

            if (u->headers_in.status_n) {
                goto done;
            }

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

        done:

            if (u->headers_in.status_n == NJT_HTTP_SWITCHING_PROTOCOLS
                && r->headers_in.upgrade)
            {
                u->upgrade = 1;
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
njt_http_uwsgi_input_filter_init(void *data)
{
    njt_http_request_t   *r = data;
    njt_http_upstream_t  *u;

    u = r->upstream;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http uwsgi filter init s:%ui l:%O",
                   u->headers_in.status_n, u->headers_in.content_length_n);

    if (u->headers_in.status_n == NJT_HTTP_NO_CONTENT
        || u->headers_in.status_n == NJT_HTTP_NOT_MODIFIED)
    {
        u->pipe->length = 0;
        u->length = 0;

    } else if (r->method == NJT_HTTP_HEAD) {
        u->pipe->length = -1;
        u->length = -1;

    } else {
        u->pipe->length = u->headers_in.content_length_n;
        u->length = u->headers_in.content_length_n;
    }

    return NJT_OK;
}


static void
njt_http_uwsgi_abort_request(njt_http_request_t *r)
{
    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http uwsgi request");

    return;
}


static void
njt_http_uwsgi_finalize_request(njt_http_request_t *r, njt_int_t rc)
{
    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http uwsgi request");

    return;
}


static void *
njt_http_uwsgi_create_main_conf(njt_conf_t *cf)
{
    njt_http_uwsgi_main_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_uwsgi_main_conf_t));
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
njt_http_uwsgi_create_loc_conf(njt_conf_t *cf)
{
    njt_http_uwsgi_loc_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_uwsgi_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->modifier1 = NJT_CONF_UNSET_UINT;
    conf->modifier2 = NJT_CONF_UNSET_UINT;

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

    /* "uwsgi_cyclic_temp_file" is disabled */
    conf->upstream.cyclic_temp_file = 0;

    conf->upstream.change_buffering = 1;

    njt_str_set(&conf->upstream.module, "uwsgi");

    return conf;
}


static char *
njt_http_uwsgi_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_uwsgi_loc_conf_t *prev = parent;
    njt_http_uwsgi_loc_conf_t *conf = child;

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
        njt_conf_merge_value(conf->upstream.store, prev->upstream.store, 0);

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
                           "there must be at least 2 \"uwsgi_buffers\"");
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
            "\"uwsgi_busy_buffers_size\" must be equal to or greater "
            "than the maximum of the value of \"uwsgi_buffer_size\" and "
            "one of the \"uwsgi_buffers\"");

        return NJT_CONF_ERROR;
    }

    if (conf->upstream.busy_buffers_size
        > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size)
    {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
            "\"uwsgi_busy_buffers_size\" must be less than "
            "the size of all \"uwsgi_buffers\" minus one buffer");

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
            "\"uwsgi_temp_file_write_size\" must be equal to or greater than "
            "the maximum of the value of \"uwsgi_buffer_size\" and "
            "one of the \"uwsgi_buffers\"");

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
            "\"uwsgi_max_temp_file_size\" must be equal to zero to disable "
            "temporary files usage or must be equal to or greater than "
            "the maximum of the value of \"uwsgi_buffer_size\" and "
            "one of the \"uwsgi_buffers\"");

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
                                  &njt_http_uwsgi_temp_path)
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
                           "\"uwsgi_cache\" zone \"%V\" is unknown",
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
                           "no \"uwsgi_cache_key\" for \"uwsgi_cache\"");
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

#if (NJT_HTTP_SSL)

    if (njt_http_uwsgi_merge_ssl(cf, conf, prev) != NJT_OK) {
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

    if (conf->ssl && njt_http_uwsgi_set_ssl(cf, conf) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

#endif

    njt_conf_merge_str_value(conf->uwsgi_string, prev->uwsgi_string, "");

    hash.max_size = 512;
    hash.bucket_size = njt_align(64, njt_cacheline_size);
    hash.name = "uwsgi_hide_headers_hash";

    if (njt_http_upstream_hide_headers_hash(cf, &conf->upstream,
            &prev->upstream, njt_http_uwsgi_hide_headers, &hash)
        != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);

    if (clcf->noname
        && conf->upstream.upstream == NULL && conf->uwsgi_lengths == NULL)
    {
        conf->upstream.upstream = prev->upstream.upstream;

        conf->uwsgi_lengths = prev->uwsgi_lengths;
        conf->uwsgi_values = prev->uwsgi_values;

#if (NJT_HTTP_SSL)
        conf->ssl = prev->ssl;
#endif
    }

    if (clcf->lmt_excpt && clcf->handler == NULL
        && (conf->upstream.upstream || conf->uwsgi_lengths))
    {
        clcf->handler = njt_http_uwsgi_handler;
    }

    njt_conf_merge_uint_value(conf->modifier1, prev->modifier1, 0);
    njt_conf_merge_uint_value(conf->modifier2, prev->modifier2, 0);

    if (conf->params_source == NULL) {
        conf->params = prev->params;
#if (NJT_HTTP_CACHE)
        conf->params_cache = prev->params_cache;
#endif
        conf->params_source = prev->params_source;
    }

    rc = njt_http_uwsgi_init_params(cf, conf, &conf->params, NULL);
    if (rc != NJT_OK) {
        return NJT_CONF_ERROR;
    }

#if (NJT_HTTP_CACHE)

    if (conf->upstream.cache) {
        rc = njt_http_uwsgi_init_params(cf, conf, &conf->params_cache,
                                        njt_http_uwsgi_cache_headers);
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
njt_http_uwsgi_init_params(njt_conf_t *cf, njt_http_uwsgi_loc_conf_t *conf,
    njt_http_uwsgi_params_t *params, njt_keyval_t *default_params)
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
    hash.name = "uwsgi_params_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    return njt_hash_init(&hash, headers_names.elts, headers_names.nelts);
}


static char *
njt_http_uwsgi_pass(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_uwsgi_loc_conf_t *uwcf = conf;

    size_t                      add;
    njt_url_t                   u;
    njt_str_t                  *value, *url;
    njt_uint_t                  n;
    njt_http_core_loc_conf_t   *clcf;
    njt_http_script_compile_t   sc;

    if (uwcf->upstream.upstream || uwcf->uwsgi_lengths) {
        return "is duplicate";
    }

    clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);
    clcf->handler = njt_http_uwsgi_handler;

    value = cf->args->elts;

    url = &value[1];

    n = njt_http_script_variables_count(url);

    if (n) {

        njt_memzero(&sc, sizeof(njt_http_script_compile_t));

        sc.cf = cf;
        sc.source = url;
        sc.lengths = &uwcf->uwsgi_lengths;
        sc.values = &uwcf->uwsgi_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (njt_http_script_compile(&sc) != NJT_OK) {
            return NJT_CONF_ERROR;
        }

#if (NJT_HTTP_SSL)
        uwcf->ssl = 1;
#endif

        return NJT_CONF_OK;
    }

    if (njt_strncasecmp(url->data, (u_char *) "uwsgi://", 8) == 0) {
        add = 8;

    } else if (njt_strncasecmp(url->data, (u_char *) "suwsgi://", 9) == 0) {

#if (NJT_HTTP_SSL)
        add = 9;
        uwcf->ssl = 1;
#else
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "suwsgi protocol requires SSL support");
        return NJT_CONF_ERROR;
#endif

    } else {
        add = 0;
    }

    njt_memzero(&u, sizeof(njt_url_t));

    u.url.len = url->len - add;
    u.url.data = url->data + add;
    u.no_resolve = 1;

    uwcf->upstream.upstream = njt_http_upstream_add(cf, &u, 0);
    if (uwcf->upstream.upstream == NULL) {
        return NJT_CONF_ERROR;
    }

    if (clcf->name.len && clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    return NJT_CONF_OK;
}


static char *
njt_http_uwsgi_store(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_uwsgi_loc_conf_t *uwcf = conf;

    njt_str_t                  *value;
    njt_http_script_compile_t   sc;

    if (uwcf->upstream.store != NJT_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (njt_strcmp(value[1].data, "off") == 0) {
        uwcf->upstream.store = 0;
        return NJT_CONF_OK;
    }

#if (NJT_HTTP_CACHE)

    if (uwcf->upstream.cache > 0) {
        return "is incompatible with \"uwsgi_cache\"";
    }

#endif

    uwcf->upstream.store = 1;

    if (njt_strcmp(value[1].data, "on") == 0) {
        return NJT_CONF_OK;
    }

    /* include the terminating '\0' into script */
    value[1].len++;

    njt_memzero(&sc, sizeof(njt_http_script_compile_t));

    sc.cf = cf;
    sc.source = &value[1];
    sc.lengths = &uwcf->upstream.store_lengths;
    sc.values = &uwcf->upstream.store_values;
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
njt_http_uwsgi_cache(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_uwsgi_loc_conf_t *uwcf = conf;

    njt_str_t                         *value;
    njt_http_complex_value_t           cv;
    njt_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (uwcf->upstream.cache != NJT_CONF_UNSET) {
        return "is duplicate";
    }

    if (njt_strcmp(value[1].data, "off") == 0) {
        uwcf->upstream.cache = 0;
        return NJT_CONF_OK;
    }

    if (uwcf->upstream.store > 0) {
        return "is incompatible with \"uwsgi_store\"";
    }

    uwcf->upstream.cache = 1;

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    if (cv.lengths != NULL) {

        uwcf->upstream.cache_value = njt_palloc(cf->pool,
                                             sizeof(njt_http_complex_value_t));
        if (uwcf->upstream.cache_value == NULL) {
            return NJT_CONF_ERROR;
        }

        *uwcf->upstream.cache_value = cv;

        return NJT_CONF_OK;
    }

    uwcf->upstream.cache_zone = njt_shared_memory_add(cf, &value[1], 0,
                                                      &njt_http_uwsgi_module);
    if (uwcf->upstream.cache_zone == NULL) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static char *
njt_http_uwsgi_cache_key(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_uwsgi_loc_conf_t *uwcf = conf;

    njt_str_t                         *value;
    njt_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (uwcf->cache_key.value.data) {
        return "is duplicate";
    }

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &uwcf->cache_key;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}

#endif


#if (NJT_HTTP_SSL)

static char *
njt_http_uwsgi_ssl_password_file(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_uwsgi_loc_conf_t *uwcf = conf;

    njt_str_t  *value;

    if (uwcf->upstream.ssl_passwords != NJT_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    uwcf->upstream.ssl_passwords = njt_ssl_read_password_file(cf, &value[1]);

    if (uwcf->upstream.ssl_passwords == NULL) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


static char *
njt_http_uwsgi_ssl_conf_command_check(njt_conf_t *cf, void *post, void *data)
{
#ifndef SSL_CONF_FLAG_FILE
    return "is not supported on this platform";
#else
    return NJT_CONF_OK;
#endif
}


static njt_int_t
njt_http_uwsgi_merge_ssl(njt_conf_t *cf, njt_http_uwsgi_loc_conf_t *conf,
    njt_http_uwsgi_loc_conf_t *prev)
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
njt_http_uwsgi_set_ssl(njt_conf_t *cf, njt_http_uwsgi_loc_conf_t *uwcf)
{
    njt_pool_cleanup_t  *cln;

    if (uwcf->upstream.ssl->ctx) {
        return NJT_OK;
    }

    if (njt_ssl_create(uwcf->upstream.ssl, uwcf->ssl_protocols, NULL)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    cln = njt_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        njt_ssl_cleanup_ctx(uwcf->upstream.ssl);
        return NJT_ERROR;
    }

    cln->handler = njt_ssl_cleanup_ctx;
    cln->data = uwcf->upstream.ssl;

    if (njt_ssl_ciphers(cf, uwcf->upstream.ssl, &uwcf->ssl_ciphers, 0)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    if (uwcf->upstream.ssl_certificate
        && uwcf->upstream.ssl_certificate->value.len)
    {
        if (uwcf->upstream.ssl_certificate_key == NULL) {
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "no \"uwsgi_ssl_certificate_key\" is defined "
                          "for certificate \"%V\"",
                          &uwcf->upstream.ssl_certificate->value);
            return NJT_ERROR;
        }

        if (uwcf->upstream.ssl_certificate->lengths
            || uwcf->upstream.ssl_certificate_key->lengths)
        {
            uwcf->upstream.ssl_passwords =
                  njt_ssl_preserve_passwords(cf, uwcf->upstream.ssl_passwords);
            if (uwcf->upstream.ssl_passwords == NULL) {
                return NJT_ERROR;
            }

        } else {
            if (njt_ssl_certificate(cf, uwcf->upstream.ssl,
                                    &uwcf->upstream.ssl_certificate->value,
                                    &uwcf->upstream.ssl_certificate_key->value,
                                    uwcf->upstream.ssl_passwords)
                != NJT_OK)
            {
                return NJT_ERROR;
            }
        }
    }

    if (uwcf->upstream.ssl_verify) {
        if (uwcf->ssl_trusted_certificate.len == 0) {
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                      "no uwsgi_ssl_trusted_certificate for uwsgi_ssl_verify");
            return NJT_ERROR;
        }

        if (njt_ssl_trusted_certificate(cf, uwcf->upstream.ssl,
                                        &uwcf->ssl_trusted_certificate,
                                        uwcf->ssl_verify_depth)
            != NJT_OK)
        {
            return NJT_ERROR;
        }

        if (njt_ssl_crl(cf, uwcf->upstream.ssl, &uwcf->ssl_crl) != NJT_OK) {
            return NJT_ERROR;
        }
    }

    if (njt_ssl_client_session_cache(cf, uwcf->upstream.ssl,
                                     uwcf->upstream.ssl_session_reuse)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    if (njt_ssl_conf_commands(cf, uwcf->upstream.ssl, uwcf->ssl_conf_commands)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    return NJT_OK;
}

#endif
