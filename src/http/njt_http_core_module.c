
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_http_util.h>
#include "njt_str_util.h"
#include <njt_http_if_location_api.h>
#include <njt_http_if_location_parse.h>
#include <njt_http_if_location_lex.h>

typedef struct {
    u_char    *name;
    uint32_t   method;
} njt_http_method_name_t;

typedef struct {
    njt_http_request_t               *r;
    njt_http_core_loc_conf_t         *clcf;
    njt_http_script_engine_t     *e;
    njt_uint_t stack_size;
}njt_http_if_location_request;

#define NJT_HTTP_REQUEST_BODY_FILE_OFF    0
#define NJT_HTTP_REQUEST_BODY_FILE_ON     1
#define NJT_HTTP_REQUEST_BODY_FILE_CLEAN  2
#define  LEFT   -1
#define  RIGHT   1


static njt_int_t njt_http_core_auth_delay(njt_http_request_t *r);
static void njt_http_core_auth_delay_handler(njt_http_request_t *r);

static njt_int_t njt_http_core_find_location(njt_http_request_t *r);
static njt_int_t njt_http_core_find_static_location(njt_http_request_t *r,
    njt_http_location_tree_node_t *node);

static njt_int_t njt_http_core_preconfiguration(njt_conf_t *cf);
static njt_int_t njt_http_core_postconfiguration(njt_conf_t *cf);
static void *njt_http_core_create_main_conf(njt_conf_t *cf);
static char *njt_http_core_init_main_conf(njt_conf_t *cf, void *conf);
static void *njt_http_core_create_srv_conf(njt_conf_t *cf);
static char *njt_http_core_merge_srv_conf(njt_conf_t *cf,
    void *parent, void *child);
static void *njt_http_core_create_loc_conf(njt_conf_t *cf);
static char *njt_http_core_merge_loc_conf(njt_conf_t *cf,
    void *parent, void *child);

static char *njt_http_core_server(njt_conf_t *cf, njt_command_t *cmd,
    void *dummy);
static char *njt_http_core_location(njt_conf_t *cf, njt_command_t *cmd,
    void *dummy);
static njt_int_t njt_http_core_regex_location(njt_conf_t *cf,
    njt_http_core_loc_conf_t *clcf, njt_str_t *regex, njt_uint_t caseless);

static char *njt_http_core_types(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_core_type(njt_conf_t *cf, njt_command_t *dummy,
    void *conf);

static char *njt_http_core_listen(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_core_server_name(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_core_root(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static char *njt_http_core_limit_except(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
//add by clb, used for ctrl api module
static char *
njt_http_core_api_limit_except(njt_conf_t *cf, njt_command_t *cmd, void *conf);
//end add by clb
static char *njt_http_core_set_aio(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_core_directio(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_core_error_page(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_core_open_file_cache(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_core_error_log(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_core_keepalive(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_core_internal(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
static char *njt_http_core_resolver(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
#if (NJT_HTTP_GZIP)
static njt_int_t njt_http_gzip_accept_encoding(njt_str_t *ae);
static njt_uint_t njt_http_gzip_quantity(u_char *p, u_char *last);
static char *njt_http_gzip_disable(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
#endif
static njt_int_t njt_http_get_forwarded_addr_internal(njt_http_request_t *r,
    njt_addr_t *addr, u_char *xff, size_t xfflen, njt_array_t *proxies,
    int recursive);
#if (NJT_HAVE_OPENAT)
static char *njt_http_disable_symlinks(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
#endif

static char *njt_http_core_lowat_check(njt_conf_t *cf, void *post, void *data);
static char *njt_http_core_pool_size(njt_conf_t *cf, void *post, void *data);

static char *
njt_http_core_if_location_array_new(njt_conf_t *cf, loc_parse_ctx_t * parse_ctx,njt_http_core_loc_conf_t  *pclcf);

static char *
njt_http_core_if_location_parse(njt_conf_t *cf,njt_http_core_loc_conf_t  *pclcf);

static njt_int_t
njt_http_core_run_location(njt_http_request_t *r,njt_http_core_loc_conf_t  *clcf);

 int
njt_http_core_run_location_callback(void *ctx,void *pdata);

njt_int_t njt_http_core_cp_loc_parse_tree(loc_parse_node_t * root, njt_pool_t   *pool,loc_parse_node_t ** new_root);
loc_parse_ctx_t*
njt_http_core_loc_parse_tree_ctx(loc_parse_node_t *root,njt_pool_t   *pool);


extern njt_module_t  njt_http_rewrite_module;

static njt_conf_post_t  njt_http_core_lowat_post =
    { njt_http_core_lowat_check };

static njt_conf_post_handler_pt  njt_http_core_pool_size_p =
    njt_http_core_pool_size;


static njt_conf_enum_t  njt_http_core_request_body_in_file[] = {
    { njt_string("off"), NJT_HTTP_REQUEST_BODY_FILE_OFF },
    { njt_string("on"), NJT_HTTP_REQUEST_BODY_FILE_ON },
    { njt_string("clean"), NJT_HTTP_REQUEST_BODY_FILE_CLEAN },
    { njt_null_string, 0 }
};


static njt_conf_enum_t  njt_http_core_satisfy[] = {
    { njt_string("all"), NJT_HTTP_SATISFY_ALL },
    { njt_string("any"), NJT_HTTP_SATISFY_ANY },
    { njt_null_string, 0 }
};


static njt_conf_enum_t  njt_http_core_lingering_close[] = {
    { njt_string("off"), NJT_HTTP_LINGERING_OFF },
    { njt_string("on"), NJT_HTTP_LINGERING_ON },
    { njt_string("always"), NJT_HTTP_LINGERING_ALWAYS },
    { njt_null_string, 0 }
};


static njt_conf_enum_t  njt_http_core_server_tokens[] = {
    { njt_string("off"), NJT_HTTP_SERVER_TOKENS_OFF },
    { njt_string("on"), NJT_HTTP_SERVER_TOKENS_ON },
    { njt_string("build"), NJT_HTTP_SERVER_TOKENS_BUILD },
    { njt_null_string, 0 }
};


static njt_conf_enum_t  njt_http_core_if_modified_since[] = {
    { njt_string("off"), NJT_HTTP_IMS_OFF },
    { njt_string("exact"), NJT_HTTP_IMS_EXACT },
    { njt_string("before"), NJT_HTTP_IMS_BEFORE },
    { njt_null_string, 0 }
};


static njt_conf_bitmask_t  njt_http_core_keepalive_disable[] = {
    { njt_string("none"), NJT_HTTP_KEEPALIVE_DISABLE_NONE },
    { njt_string("msie6"), NJT_HTTP_KEEPALIVE_DISABLE_MSIE6 },
    { njt_string("safari"), NJT_HTTP_KEEPALIVE_DISABLE_SAFARI },
    { njt_null_string, 0 }
};


static njt_path_init_t  njt_http_client_temp_path = {
    njt_string(NJT_HTTP_CLIENT_TEMP_PATH), { 0, 0, 0 }
};


#if (NJT_HTTP_GZIP)

static njt_conf_enum_t  njt_http_gzip_http_version[] = {
    { njt_string("1.0"), NJT_HTTP_VERSION_10 },
    { njt_string("1.1"), NJT_HTTP_VERSION_11 },
    { njt_null_string, 0 }
};


static njt_conf_bitmask_t  njt_http_gzip_proxied_mask[] = {
    { njt_string("off"), NJT_HTTP_GZIP_PROXIED_OFF },
    { njt_string("expired"), NJT_HTTP_GZIP_PROXIED_EXPIRED },
    { njt_string("no-cache"), NJT_HTTP_GZIP_PROXIED_NO_CACHE },
    { njt_string("no-store"), NJT_HTTP_GZIP_PROXIED_NO_STORE },
    { njt_string("private"), NJT_HTTP_GZIP_PROXIED_PRIVATE },
    { njt_string("no_last_modified"), NJT_HTTP_GZIP_PROXIED_NO_LM },
    { njt_string("no_etag"), NJT_HTTP_GZIP_PROXIED_NO_ETAG },
    { njt_string("auth"), NJT_HTTP_GZIP_PROXIED_AUTH },
    { njt_string("any"), NJT_HTTP_GZIP_PROXIED_ANY },
    { njt_null_string, 0 }
};


static njt_str_t  njt_http_gzip_no_cache = njt_string("no-cache");
static njt_str_t  njt_http_gzip_no_store = njt_string("no-store");
static njt_str_t  njt_http_gzip_private = njt_string("private");

#endif


static njt_command_t  njt_http_core_commands[] = {

    { njt_string("variables_hash_max_size"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_MAIN_CONF_OFFSET,
      offsetof(njt_http_core_main_conf_t, variables_hash_max_size),
      NULL },

    { njt_string("variables_hash_bucket_size"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_MAIN_CONF_OFFSET,
      offsetof(njt_http_core_main_conf_t, variables_hash_bucket_size),
      NULL },

    { njt_string("server_names_hash_max_size"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_MAIN_CONF_OFFSET,
      offsetof(njt_http_core_main_conf_t, server_names_hash_max_size),
      NULL },

    { njt_string("server_names_hash_bucket_size"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_MAIN_CONF_OFFSET,
      offsetof(njt_http_core_main_conf_t, server_names_hash_bucket_size),
      NULL },

    { njt_string("server"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_BLOCK|NJT_CONF_NOARGS,
      njt_http_core_server,
      0,
      0,
      NULL },

    { njt_string("connection_pool_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_core_srv_conf_t, connection_pool_size),
      &njt_http_core_pool_size_p },

    { njt_string("request_pool_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_core_srv_conf_t, request_pool_size),
      &njt_http_core_pool_size_p },

    { njt_string("client_header_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_core_srv_conf_t, client_header_timeout),
      NULL },

    { njt_string("client_header_buffer_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_core_srv_conf_t, client_header_buffer_size),
      NULL },

    { njt_string("large_client_header_buffers"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE2,
      njt_conf_set_bufs_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_core_srv_conf_t, large_client_header_buffers),
      NULL },

    { njt_string("ignore_invalid_headers"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_core_srv_conf_t, ignore_invalid_headers),
      NULL },

    { njt_string("merge_slashes"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_core_srv_conf_t, merge_slashes),
      NULL },

    { njt_string("underscores_in_headers"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_SRV_CONF_OFFSET,
      offsetof(njt_http_core_srv_conf_t, underscores_in_headers),
      NULL },

    { njt_string("location"),
      NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_BLOCK|NJT_CONF_1MORE,
      njt_http_core_location,
      NJT_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("listen"),
      NJT_HTTP_SRV_CONF|NJT_CONF_1MORE,
      njt_http_core_listen,
      NJT_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("server_name"),
      NJT_HTTP_SRV_CONF|NJT_CONF_1MORE,
      njt_http_core_server_name,
      NJT_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { njt_string("types_hash_max_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, types_hash_max_size),
      NULL },

    { njt_string("types_hash_bucket_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, types_hash_bucket_size),
      NULL },

    { njt_string("types"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF
                                          |NJT_CONF_BLOCK|NJT_CONF_NOARGS,
      njt_http_core_types,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("default_type"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, default_type),
      NULL },

    { njt_string("root"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_TAKE1,
      njt_http_core_root,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("alias"),
      NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_core_root,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("limit_except"),
      NJT_HTTP_LOC_CONF|NJT_CONF_BLOCK|NJT_CONF_1MORE,
      njt_http_core_limit_except,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    //add by clb, used for ctrl api module
    { njt_string("api_limit_except"),
      NJT_HTTP_LOC_CONF|NJT_CONF_BLOCK|NJT_CONF_2MORE,
      njt_http_core_api_limit_except,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
    //end add by clb

    { njt_string("client_max_body_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_off_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, client_max_body_size),
      NULL },

    { njt_string("client_body_buffer_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, client_body_buffer_size),
      NULL },

    { njt_string("client_body_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, client_body_timeout),
      NULL },

    { njt_string("client_body_temp_path"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1234,
      njt_conf_set_path_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, client_body_temp_path),
      NULL },

    { njt_string("client_body_in_file_only"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_enum_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, client_body_in_file_only),
      &njt_http_core_request_body_in_file },

    { njt_string("client_body_in_single_buffer"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, client_body_in_single_buffer),
      NULL },

    { njt_string("sendfile"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, sendfile),
      NULL },

    { njt_string("sendfile_max_chunk"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, sendfile_max_chunk),
      NULL },

    { njt_string("subrequest_output_buffer_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, subrequest_output_buffer_size),
      NULL },

    { njt_string("aio"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_core_set_aio,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("aio_write"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, aio_write),
      NULL },

    { njt_string("read_ahead"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, read_ahead),
      NULL },

    { njt_string("directio"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_http_core_directio,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("directio_alignment"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_off_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, directio_alignment),
      NULL },

    { njt_string("tcp_nopush"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, tcp_nopush),
      NULL },

    { njt_string("tcp_nodelay"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, tcp_nodelay),
      NULL },

    { njt_string("send_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, send_timeout),
      NULL },

    { njt_string("send_lowat"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, send_lowat),
      &njt_http_core_lowat_post },

    { njt_string("postpone_output"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, postpone_output),
      NULL },

    { njt_string("limit_rate"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_TAKE1,
      njt_http_set_complex_value_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, limit_rate),
      NULL },

    { njt_string("limit_rate_after"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_TAKE1,
      njt_http_set_complex_value_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, limit_rate_after),
      NULL },

    { njt_string("keepalive_time"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, keepalive_time),
      NULL },

    { njt_string("keepalive_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE12,
      njt_http_core_keepalive,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("keepalive_requests"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, keepalive_requests),
      NULL },

    { njt_string("keepalive_disable"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE12,
      njt_conf_set_bitmask_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, keepalive_disable),
      &njt_http_core_keepalive_disable },

    { njt_string("satisfy"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_enum_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, satisfy),
      &njt_http_core_satisfy },

    { njt_string("auth_delay"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, auth_delay),
      NULL },

    { njt_string("internal"),
      NJT_HTTP_LOC_CONF|NJT_CONF_NOARGS,
      njt_http_core_internal,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("lingering_close"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_enum_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, lingering_close),
      &njt_http_core_lingering_close },

    { njt_string("lingering_time"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, lingering_time),
      NULL },

    { njt_string("lingering_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, lingering_timeout),
      NULL },

    { njt_string("reset_timedout_connection"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, reset_timedout_connection),
      NULL },

    { njt_string("absolute_redirect"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, absolute_redirect),
      NULL },

    { njt_string("server_name_in_redirect"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, server_name_in_redirect),
      NULL },

    { njt_string("port_in_redirect"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, port_in_redirect),
      NULL },

    { njt_string("msie_padding"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, msie_padding),
      NULL },

    { njt_string("msie_refresh"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, msie_refresh),
      NULL },

    { njt_string("log_not_found"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, log_not_found),
      NULL },

    { njt_string("log_subrequest"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, log_subrequest),
      NULL },

    { njt_string("recursive_error_pages"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, recursive_error_pages),
      NULL },

    { njt_string("server_tokens"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_enum_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, server_tokens),
      &njt_http_core_server_tokens },

    { njt_string("if_modified_since"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_enum_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, if_modified_since),
      &njt_http_core_if_modified_since },

    { njt_string("max_ranges"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, max_ranges),
      NULL },

    { njt_string("chunked_transfer_encoding"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, chunked_transfer_encoding),
      NULL },

    { njt_string("etag"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, etag),
      NULL },

    { njt_string("error_page"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_2MORE,
      njt_http_core_error_page,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("post_action"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, post_action),
      NULL },

    { njt_string("error_log"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_http_core_error_log,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("open_file_cache"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE12,
      njt_http_core_open_file_cache,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, open_file_cache),
      NULL },

    { njt_string("open_file_cache_valid"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_sec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, open_file_cache_valid),
      NULL },

    { njt_string("open_file_cache_min_uses"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, open_file_cache_min_uses),
      NULL },

    { njt_string("open_file_cache_errors"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, open_file_cache_errors),
      NULL },

    { njt_string("open_file_cache_events"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, open_file_cache_events),
      NULL },

    { njt_string("resolver"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_http_core_resolver,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { njt_string("resolver_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, resolver_timeout),
      NULL },

#if (NJT_HTTP_GZIP)

    { njt_string("gzip_vary"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, gzip_vary),
      NULL },

    { njt_string("gzip_http_version"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_enum_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, gzip_http_version),
      &njt_http_gzip_http_version },

    { njt_string("gzip_proxied"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_core_loc_conf_t, gzip_proxied),
      &njt_http_gzip_proxied_mask },

    { njt_string("gzip_disable"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_http_gzip_disable,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

#endif

#if (NJT_HAVE_OPENAT)

    { njt_string("disable_symlinks"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE12,
      njt_http_disable_symlinks,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

#endif

      njt_null_command
};


static njt_http_module_t  njt_http_core_module_ctx = {
    njt_http_core_preconfiguration,        /* preconfiguration */
    njt_http_core_postconfiguration,       /* postconfiguration */

    njt_http_core_create_main_conf,        /* create main configuration */
    njt_http_core_init_main_conf,          /* init main configuration */

    njt_http_core_create_srv_conf,         /* create server configuration */
    njt_http_core_merge_srv_conf,          /* merge server configuration */

    njt_http_core_create_loc_conf,         /* create location configuration */
    njt_http_core_merge_loc_conf           /* merge location configuration */
};


njt_module_t  njt_http_core_module = {
    NJT_MODULE_V1,
    &njt_http_core_module_ctx,             /* module context */
    njt_http_core_commands,                /* module directives */
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


njt_str_t  njt_http_core_get_method = { 3, (u_char *) "GET" };


void
njt_http_handler(njt_http_request_t *r)
{
    njt_http_core_main_conf_t  *cmcf;

    r->connection->log->action = NULL;

    if (!r->internal) {
        switch (r->headers_in.connection_type) {
        case 0:
            r->keepalive = (r->http_version > NJT_HTTP_VERSION_10);
            break;

        case NJT_HTTP_CONNECTION_CLOSE:
            r->keepalive = 0;
            break;

        case NJT_HTTP_CONNECTION_KEEP_ALIVE:
            r->keepalive = 1;
            break;
        }

        r->lingering_close = (r->headers_in.content_length_n > 0
                              || r->headers_in.chunked);
        r->phase_handler = 0;

    } else {
        cmcf = njt_http_get_module_main_conf(r, njt_http_core_module);
        r->phase_handler = cmcf->phase_engine.server_rewrite_index;
    }

    r->valid_location = 1;
#if (NJT_HTTP_GZIP)
    r->gzip_tested = 0;
    r->gzip_ok = 0;
    r->gzip_vary = 0;
#endif

    r->write_event_handler = njt_http_core_run_phases;
    njt_http_core_run_phases(r);
}


void
njt_http_core_run_phases(njt_http_request_t *r)
{
    njt_int_t                   rc;
    njt_http_phase_handler_t   *ph;
    njt_http_core_main_conf_t  *cmcf;

    cmcf = njt_http_get_module_main_conf(r, njt_http_core_module);

    ph = cmcf->phase_engine.handlers;

    while (ph[r->phase_handler].checker) {

        rc = ph[r->phase_handler].checker(r, &ph[r->phase_handler]);

        if (rc == NJT_OK) {
            return;
        }
    }
}


njt_int_t
njt_http_core_generic_phase(njt_http_request_t *r, njt_http_phase_handler_t *ph)
{
    njt_int_t  rc;

    /*
     * generic phase checker,
     * used by the post read and pre-access phases
     */

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "generic phase: %ui", r->phase_handler);

    rc = ph->handler(r);

    if (rc == NJT_OK) {
        r->phase_handler = ph->next;
        return NJT_AGAIN;
    }

    if (rc == NJT_DECLINED) {
        r->phase_handler++;
        return NJT_AGAIN;
    }

    if (rc == NJT_AGAIN || rc == NJT_DONE) {
        return NJT_OK;
    }

    /* rc == NJT_ERROR || rc == NJT_HTTP_...  */

    njt_http_finalize_request(r, rc);

    return NJT_OK;
}


njt_int_t
njt_http_core_rewrite_phase(njt_http_request_t *r, njt_http_phase_handler_t *ph)
{
    njt_int_t  rc;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "rewrite phase: %ui", r->phase_handler);

    rc = ph->handler(r);

    if (rc == NJT_DECLINED) {
        r->phase_handler++;
        return NJT_AGAIN;
    }

    if (rc == NJT_DONE) {
        return NJT_OK;
    }

    /* NJT_OK, NJT_AGAIN, NJT_ERROR, NJT_HTTP_...  */

    njt_http_finalize_request(r, rc);

    return NJT_OK;
}
// by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
static void njt_http_core_free_location(void* data){
    njt_http_core_loc_conf_t  *clcf = data;
    if(clcf != NULL && clcf->disable == 1 && clcf->ref_count == 0) {
        njt_http_location_delete_dyn_var(clcf);
        njt_http_location_destroy(clcf); 
       
    }
}
static void njt_http_core_free_ctx(void* data){
    njt_http_core_loc_conf_t  *clcf;
    njt_http_request_t *r;
    njt_pool_cleanup_t   *cln;
    u_char *p = data;
    njt_memcpy(&clcf,p,sizeof(njt_http_core_loc_conf_t  *));
    njt_memcpy(&r,p + sizeof(njt_http_core_loc_conf_t  *),sizeof(njt_http_request_t  *));

     //njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "ref_count clcf=%V,ref_count=%i",&clcf->name,clcf->ref_count);

    --clcf->ref_count;

    if(clcf->disable == 1 && clcf->ref_count == 0) {
        
        cln = njt_pool_cleanup_add(r->connection->pool,0);
        if (cln != NULL) {
             cln->data = clcf;
             cln->handler = njt_http_core_free_location;
        }

    } 
   
}
#endif
//end

// by zyg
#if (NJT_HTTP_DYNAMIC_SERVER)
static void njt_http_core_free_srv(void* data){
    njt_http_core_loc_conf_t *clcf;
    njt_http_core_srv_conf_t  *cscf = data;
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "njt_http_core_free_srv server %V,ref_count=%d,disable=%d!",&cscf->server_name,cscf->ref_count,cscf->disable);
     if(cscf != NULL && cscf->disable == 1 && cscf->ref_count == 0) {
        clcf = cscf->ctx->loc_conf[njt_http_core_module.ctx_index];
        njt_http_location_delete_dyn_var(clcf);
        njt_http_location_destroy(clcf);
        njt_http_server_delete_dyn_var(cscf);  
        njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "njt_http_core_free_srv server %V,ref_count=%d!",&cscf->server_name,cscf->ref_count);
       njt_destroy_pool(cscf->pool);
    }

    
}

void njt_http_core_free_srv_ctx(void* data) {
   
    njt_http_core_srv_conf_t  *cscf;
    njt_http_request_t *r;
    njt_pool_cleanup_t   *cln;
    u_char *p = data;
    njt_memcpy(&cscf,p,sizeof(njt_http_core_srv_conf_t  *));
    njt_memcpy(&r,p + sizeof(njt_http_core_srv_conf_t  *),sizeof(njt_http_request_t  *));

    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "njt_http_core_free_srv_ctx server %V,ref_count=%d,disable=%d!",&cscf->server_name,cscf->ref_count,cscf->disable);

    --cscf->ref_count;

    if(cscf->disable == 1 && cscf->ref_count == 0) {
        
        cln = njt_pool_cleanup_add_tail(r->connection->pool,0);
        if (cln != NULL) {
             cln->data = cscf;
             cln->handler = njt_http_core_free_srv;
        }
    } 
}

#endif
//end



njt_int_t
njt_http_core_find_config_phase(njt_http_request_t *r,
    njt_http_phase_handler_t *ph)
{
    u_char                    *p;
    size_t                     len;
    njt_int_t                  rc;
    njt_http_core_loc_conf_t  *clcf;

    r->content_handler = NULL;
    r->uri_changed = 0;

//add by clb
#if (NJT_HTTP_PROXY_CONNECT)
    if (r->method == NJT_HTTP_CONNECT) {
        njt_http_update_location_config(r);
        r->phase_handler++;
        return NJT_AGAIN;
    }
#endif

    rc = njt_http_core_find_location(r);

    if (rc == NJT_ERROR) {
        njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return NJT_OK;
    }

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    if (!r->internal && clcf->internal) {
        njt_http_finalize_request(r, NJT_HTTP_NOT_FOUND);
        return NJT_OK;
    }

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "using configuration \"%s%V\"",
                   (clcf->noname ? "*" : (clcf->exact_match ? "=" : "")),
                   &clcf->name);

    njt_http_update_location_config(r);
    // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
    njt_http_core_loc_conf_t  *temp;
    njt_pool_cleanup_t   *cln;
    u_char *pt;
//    njt_pool_cleanup_t  **cln,*end;
	//njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "ref_count used_ref=%i",r->used_ref);
        temp = njt_http_get_module_loc_conf(r,njt_http_core_module);
        ++temp->ref_count;

	njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "ref_count clcf=%V,ref_count=%i",&temp->name,temp->ref_count);
        cln = njt_pool_cleanup_add(r->main->pool,sizeof(njt_http_core_loc_conf_t *) + sizeof(njt_http_request_t *));
        if (cln == NULL) {
             njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
             return NJT_OK;
        }
        cln->handler = njt_http_core_free_ctx;
        pt = cln->data;
        njt_memcpy(pt,&temp,sizeof(njt_http_core_loc_conf_t *));
        njt_memcpy(pt+sizeof(njt_http_core_loc_conf_t *),&r->main,sizeof(njt_http_request_t *));
        
#endif
    //end
    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http cl:%O max:%O",
                   r->headers_in.content_length_n, clcf->client_max_body_size);

    if (r->headers_in.content_length_n != -1
        && !r->discard_body
        && clcf->client_max_body_size
        && clcf->client_max_body_size < r->headers_in.content_length_n)
    {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "client intended to send too large body: %O bytes",
                      r->headers_in.content_length_n);

        r->expect_tested = 1;
        (void) njt_http_discard_request_body(r);
        njt_http_finalize_request(r, NJT_HTTP_REQUEST_ENTITY_TOO_LARGE);
        return NJT_OK;
    }

    if (rc == NJT_DONE) {
        njt_http_clear_location(r);

        r->headers_out.location = njt_list_push(&r->headers_out.headers);
        if (r->headers_out.location == NULL) {
            njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
            return NJT_OK;
        }

        r->headers_out.location->hash = 1;
        r->headers_out.location->next = NULL;
        njt_str_set(&r->headers_out.location->key, "Location");

        if (r->args.len == 0) {
            r->headers_out.location->value = clcf->escaped_name;

        } else {
            len = clcf->escaped_name.len + 1 + r->args.len;
            p = njt_pnalloc(r->pool, len);

            if (p == NULL) {
                njt_http_clear_location(r);
                njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
                return NJT_OK;
            }

            r->headers_out.location->value.len = len;
            r->headers_out.location->value.data = p;

            p = njt_cpymem(p, clcf->escaped_name.data, clcf->escaped_name.len);
            *p++ = '?';
            njt_memcpy(p, r->args.data, r->args.len);
        }

        njt_http_finalize_request(r, NJT_HTTP_MOVED_PERMANENTLY);
        return NJT_OK;
    }

    r->phase_handler++;
    return NJT_AGAIN;
}


njt_int_t
njt_http_core_post_rewrite_phase(njt_http_request_t *r,
    njt_http_phase_handler_t *ph)
{
    njt_http_core_srv_conf_t  *cscf;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "post rewrite phase: %ui", r->phase_handler);

    if (!r->uri_changed) {
        r->phase_handler++;
        return NJT_AGAIN;
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "uri changes: %d", r->uri_changes);

    /*
     * gcc before 3.3 compiles the broken code for
     *     if (r->uri_changes-- == 0)
     * if the r->uri_changes is defined as
     *     unsigned  uri_changes:4
     */

    r->uri_changes--;

    if (r->uri_changes == 0) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "rewrite or internal redirection cycle "
                      "while processing \"%V\"", &r->uri);

        njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return NJT_OK;
    }

    r->phase_handler = ph->next;

    cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);
    r->loc_conf = cscf->ctx->loc_conf;

    return NJT_AGAIN;
}


njt_int_t
njt_http_core_access_phase(njt_http_request_t *r, njt_http_phase_handler_t *ph)
{
    njt_int_t                  rc;
    njt_table_elt_t           *h;
    njt_http_core_loc_conf_t  *clcf;

    if (r != r->main) {
        r->phase_handler = ph->next;
        return NJT_AGAIN;
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "access phase: %ui", r->phase_handler);

    rc = ph->handler(r);

    if (rc == NJT_DECLINED) {
        r->phase_handler++;
        return NJT_AGAIN;
    }

    if (rc == NJT_AGAIN || rc == NJT_DONE) {
        return NJT_OK;
    }

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    if (clcf->satisfy == NJT_HTTP_SATISFY_ALL) {

        if (rc == NJT_OK) {
            r->phase_handler++;
            return NJT_AGAIN;
        }

    } else {
        if (rc == NJT_OK) {
            r->access_code = 0;

            for (h = r->headers_out.www_authenticate; h; h = h->next) {
                h->hash = 0;
            }

            r->phase_handler = ph->next;
            return NJT_AGAIN;
        }

        if (rc == NJT_HTTP_FORBIDDEN || rc == NJT_HTTP_UNAUTHORIZED) {
            if (r->access_code != NJT_HTTP_UNAUTHORIZED) {
                r->access_code = rc;
            }

            r->phase_handler++;
            return NJT_AGAIN;
        }
    }

    /* rc == NJT_ERROR || rc == NJT_HTTP_...  */

    if (rc == NJT_HTTP_UNAUTHORIZED) {
        return njt_http_core_auth_delay(r);
    }

    njt_http_finalize_request(r, rc);
    return NJT_OK;
}


njt_int_t
njt_http_core_post_access_phase(njt_http_request_t *r,
    njt_http_phase_handler_t *ph)
{
    njt_int_t  access_code;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "post access phase: %ui", r->phase_handler);

    access_code = r->access_code;

    if (access_code) {
        r->access_code = 0;

        if (access_code == NJT_HTTP_FORBIDDEN) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "access forbidden by rule");
        }

        if (access_code == NJT_HTTP_UNAUTHORIZED) {
            return njt_http_core_auth_delay(r);
        }

        njt_http_finalize_request(r, access_code);
        return NJT_OK;
    }

    r->phase_handler++;
    return NJT_AGAIN;
}


static njt_int_t
njt_http_core_auth_delay(njt_http_request_t *r)
{
    njt_http_core_loc_conf_t  *clcf;

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    if (clcf->auth_delay == 0) {
        njt_http_finalize_request(r, NJT_HTTP_UNAUTHORIZED);
        return NJT_OK;
    }

    njt_log_error(NJT_LOG_INFO, r->connection->log, 0,
                  "delaying unauthorized request");

    if (r->connection->read->ready) {
        njt_post_event(r->connection->read, &njt_posted_events);

    } else {
        if (njt_handle_read_event(r->connection->read, 0) != NJT_OK) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    r->read_event_handler = njt_http_test_reading;
    r->write_event_handler = njt_http_core_auth_delay_handler;

    r->connection->write->delayed = 1;
    njt_add_timer(r->connection->write, clcf->auth_delay);

    /*
     * trigger an additional event loop iteration
     * to ensure constant-time processing
     */

    njt_post_event(r->connection->write, &njt_posted_next_events);

    return NJT_OK;
}


static void
njt_http_core_auth_delay_handler(njt_http_request_t *r)
{
    njt_event_t  *wev;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth delay handler");

    wev = r->connection->write;

    if (wev->delayed) {

        if (njt_handle_write_event(wev, 0) != NJT_OK) {
            njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        }

        return;
    }

    njt_http_finalize_request(r, NJT_HTTP_UNAUTHORIZED);
}


njt_int_t
njt_http_core_content_phase(njt_http_request_t *r,
    njt_http_phase_handler_t *ph)
{
    size_t     root;
    njt_int_t  rc;
    njt_str_t  path;

    if (r->content_handler) {
        r->write_event_handler = njt_http_request_empty_handler;
        njt_http_finalize_request(r, r->content_handler(r));
        return NJT_OK;
    }

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "content phase: %ui", r->phase_handler);

    rc = ph->handler(r);

    if (rc != NJT_DECLINED) {
        njt_http_finalize_request(r, rc);
        return NJT_OK;
    }

    /* rc == NJT_DECLINED */

    ph++;

    if (ph->checker) {
        r->phase_handler++;
        return NJT_AGAIN;
    }

    /* no content handler was found */

    if (r->uri.data[r->uri.len - 1] == '/') {

        if (njt_http_map_uri_to_path(r, &path, &root, 0) != NULL) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "directory index of \"%s\" is forbidden", path.data);
        }

        njt_http_finalize_request(r, NJT_HTTP_FORBIDDEN);
        return NJT_OK;
    }

    njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "no handler found");

    njt_http_finalize_request(r, NJT_HTTP_NOT_FOUND);
    return NJT_OK;
}


void
njt_http_update_location_config(njt_http_request_t *r)
{
    njt_http_core_loc_conf_t  *clcf;
    //add by clb, used for ctrl api module
    njt_uint_t                 i;
    size_t                     len;
    njt_http_api_limit_except_t *api_limit_except, *tmp_limit_except;
    //end add by clb

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    if (r->method & clcf->limit_except) {
        r->loc_conf = clcf->limit_except_loc_conf;
        clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);
    }
    //add by clb, used for ctrl api module
    else if(clcf->api_limit_excepts != NJT_CONF_UNSET_PTR){
        //filter module_key
        api_limit_except  = clcf->api_limit_excepts->elts;
        len = r->uri.len - clcf->name.len;
	    for(i = 0; i < clcf->api_limit_excepts->nelts; i++) {
            tmp_limit_except = &api_limit_except[i];
            if(r->method & tmp_limit_except->api_limit_except
            && len >= tmp_limit_except->module_key.len
            && 0 == njt_strncmp((r->uri.data+clcf->name.len), tmp_limit_except->module_key.data, tmp_limit_except->module_key.len)){
                if(len == tmp_limit_except->module_key.len
                ||(r->uri.data[clcf->name.len+tmp_limit_except->module_key.len] == '/')){
                    r->loc_conf = tmp_limit_except->limit_except_loc_conf;
                    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);
                    break;
                }
            }
        }
    }
    //end add by clb

    if (r == r->main) {
        njt_set_connection_log(r->connection, clcf->error_log);
    }

    if ((njt_io.flags & NJT_IO_SENDFILE) && clcf->sendfile) {
        r->connection->sendfile = 1;

    } else {
        r->connection->sendfile = 0;
    }

    if (clcf->client_body_in_file_only) {
        r->request_body_in_file_only = 1;
        r->request_body_in_persistent_file = 1;
        r->request_body_in_clean_file =
            clcf->client_body_in_file_only == NJT_HTTP_REQUEST_BODY_FILE_CLEAN;
        r->request_body_file_log_level = NJT_LOG_NOTICE;

    } else {
        r->request_body_file_log_level = NJT_LOG_WARN;
    }

    r->request_body_in_single_buf = clcf->client_body_in_single_buffer;

    if (r->keepalive) {
        if (clcf->keepalive_timeout == 0) {
            r->keepalive = 0;

        } else if (r->connection->requests >= clcf->keepalive_requests) {
            r->keepalive = 0;

        } else if (njt_current_msec - r->connection->start_time
                   > clcf->keepalive_time)
        {
            r->keepalive = 0;

        } else if (r->headers_in.msie6
                   && r->method == NJT_HTTP_POST
                   && (clcf->keepalive_disable
                       & NJT_HTTP_KEEPALIVE_DISABLE_MSIE6))
        {
            /*
             * MSIE may wait for some time if an response for
             * a POST request was sent over a keepalive connection
             */
            r->keepalive = 0;

        } else if (r->headers_in.safari
                   && (clcf->keepalive_disable
                       & NJT_HTTP_KEEPALIVE_DISABLE_SAFARI))
        {
            /*
             * Safari may send a POST request to a closed keepalive
             * connection and may stall for some time, see
             *     https://bugs.webkit.org/show_bug.cgi?id=5760
             */
            r->keepalive = 0;
        }
    }

    if (!clcf->tcp_nopush) {
        /* disable TCP_NOPUSH/TCP_CORK use */
        r->connection->tcp_nopush = NJT_TCP_NOPUSH_DISABLED;
    }

    if (clcf->handler) {
        r->content_handler = clcf->handler;
    }
}


/*
 * NJT_OK       - exact or regex match
 * NJT_DONE     - auto redirect
 * NJT_AGAIN    - inclusive match
 * NJT_ERROR    - regex error
 * NJT_DECLINED - no match
 */

static njt_int_t
njt_http_core_find_location(njt_http_request_t *r)
{
    njt_int_t                  rc;
    njt_http_core_loc_conf_t  *pclcf;
    njt_http_location_queue_t *lq;
     njt_queue_t *q;
#if (NJT_PCRE)
    njt_int_t                  n;
    njt_uint_t                 noregex;
    njt_http_core_loc_conf_t  *clcf, **clcfp;

    noregex = 0;
#endif

    pclcf = njt_http_get_module_loc_conf(r, njt_http_core_module);


    if (pclcf->if_locations != NULL && njt_queue_empty(pclcf->if_locations) == 0) {
    
    for (q = njt_queue_head(pclcf->if_locations);
         q != njt_queue_sentinel(pclcf->if_locations);
         q = njt_queue_next(q)) {
        lq = (njt_http_location_queue_t *) q;

        clcf = lq->exact ? lq->exact : lq->inclusive;
	clcf->error_log = njt_cycle->log;
	if(njt_http_core_run_location(r,clcf) == NJT_OK){
	  r->loc_conf = clcf->loc_conf;
	  return NJT_OK;
	 }
    }
    }

    rc = njt_http_core_find_static_location(r, pclcf->static_locations);

    if (rc == NJT_AGAIN) {

#if (NJT_PCRE)
        clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);
	if(clcf == NULL) {
	   return NJT_DECLINED;
	}
        noregex = clcf->noregex;
#endif

        /* look up nested locations */

        rc = njt_http_core_find_location(r);
    }

    if (rc == NJT_OK || rc == NJT_DONE) {
        return rc;
    }

    /* rc == NJT_DECLINED or rc == NJT_AGAIN in nested location */

#if (NJT_PCRE)

    if (noregex == 0 && pclcf->regex_locations) {

        for (clcfp = pclcf->regex_locations; *clcfp; clcfp++) {

            njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "test location: ~ \"%V\"", &(*clcfp)->name);

            n = njt_http_regex_exec(r, (*clcfp)->regex, &r->uri);

            if (n == NJT_OK) {
                r->loc_conf = (*clcfp)->loc_conf;

                /* look up nested locations */

                rc = njt_http_core_find_location(r);

                return (rc == NJT_ERROR) ? rc : NJT_OK;
            }

            if (n == NJT_DECLINED) {
                continue;
            }

            return NJT_ERROR;
        }
    }
#endif

    return rc;
}


/*
 * NJT_OK       - exact match
 * NJT_DONE     - auto redirect
 * NJT_AGAIN    - inclusive match
 * NJT_DECLINED - no match
 */

static njt_int_t
njt_http_core_find_static_location(njt_http_request_t *r,
    njt_http_location_tree_node_t *node)
{
    u_char     *uri;
    size_t      len, n;
    njt_int_t   rc, rv;
    len = r->uri.len;
    uri = r->uri.data;
    if(r->uri_key.len != 0 && r->uri_key.data != NULL){
    	len = r->uri_key.len;
    	uri = r->uri_key.data;
    }

    rv = NJT_DECLINED;

    for ( ;; ) {

        if (node == NULL) {
            return rv;
        }

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "test location: \"%*s\"",
                       (size_t) node->len, node->name);

        n = (len <= (size_t) node->len) ? len : node->len;

        rc = njt_filename_cmp(uri, node->name, n);

        if (rc != 0) {
            node = (rc < 0) ? node->left : node->right;

            continue;
        }

        if (len > (size_t) node->len) {

            if (node->inclusive) {

                r->loc_conf = node->inclusive->loc_conf;
                rv = NJT_AGAIN;

                node = node->tree;
                uri += n;
                len -= n;

                continue;
            }

            /* exact only */

            node = node->right;

            continue;
        }

        if (len == (size_t) node->len) {

            if (node->exact) {
                r->loc_conf = node->exact->loc_conf;
                return NJT_OK;

            } else {
                r->loc_conf = node->inclusive->loc_conf;
                return NJT_AGAIN;
            }
        }

        /* len < node->len */

        if (len + 1 == (size_t) node->len && node->auto_redirect) {

            r->loc_conf = (node->exact) ? node->exact->loc_conf:
                                          node->inclusive->loc_conf;
            rv = NJT_DONE;
        }

        node = node->left;
    }
}


void *
njt_http_test_content_type(njt_http_request_t *r, njt_hash_t *types_hash)
{
    u_char      c, *lowcase;
    size_t      len;
    njt_uint_t  i, hash;

    if (types_hash->size == 0) {
        return (void *) 4;
    }

    if (r->headers_out.content_type.len == 0) {
        return NULL;
    }

    len = r->headers_out.content_type_len;

    if (r->headers_out.content_type_lowcase == NULL) {

        lowcase = njt_pnalloc(r->pool, len);
        if (lowcase == NULL) {
            return NULL;
        }

        r->headers_out.content_type_lowcase = lowcase;

        hash = 0;

        for (i = 0; i < len; i++) {
            c = njt_tolower(r->headers_out.content_type.data[i]);
            hash = njt_hash(hash, c);
            lowcase[i] = c;
        }

        r->headers_out.content_type_hash = hash;
    }

    return njt_hash_find(types_hash, r->headers_out.content_type_hash,
                         r->headers_out.content_type_lowcase, len);
}


njt_int_t
njt_http_set_content_type(njt_http_request_t *r)
{
    u_char                     c, *exten;
    njt_str_t                 *type;
    njt_uint_t                 i, hash;
    njt_http_core_loc_conf_t  *clcf;

    if (r->headers_out.content_type.len) {
        return NJT_OK;
    }

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    if (r->exten.len) {

        hash = 0;

        for (i = 0; i < r->exten.len; i++) {
            c = r->exten.data[i];

            if (c >= 'A' && c <= 'Z') {

                exten = njt_pnalloc(r->pool, r->exten.len);
                if (exten == NULL) {
                    return NJT_ERROR;
                }

                hash = njt_hash_strlow(exten, r->exten.data, r->exten.len);

                r->exten.data = exten;

                break;
            }

            hash = njt_hash(hash, c);
        }

        type = njt_hash_find(&clcf->types_hash, hash,
                             r->exten.data, r->exten.len);

        if (type) {
            r->headers_out.content_type_len = type->len;
            r->headers_out.content_type = *type;

            return NJT_OK;
        }
    }

    r->headers_out.content_type_len = clcf->default_type.len;
    r->headers_out.content_type = clcf->default_type;

    return NJT_OK;
}


void
njt_http_set_exten(njt_http_request_t *r)
{
    njt_int_t  i;

    njt_str_null(&r->exten);

    for (i = r->uri.len - 1; i > 1; i--) {
        if (r->uri.data[i] == '.' && r->uri.data[i - 1] != '/') {

            r->exten.len = r->uri.len - i - 1;
            r->exten.data = &r->uri.data[i + 1];

            return;

        } else if (r->uri.data[i] == '/') {
            return;
        }
    }

    return;
}


njt_int_t
njt_http_set_etag(njt_http_request_t *r)
{
    njt_table_elt_t           *etag;
    njt_http_core_loc_conf_t  *clcf;

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    if (!clcf->etag) {
        return NJT_OK;
    }

    etag = njt_list_push(&r->headers_out.headers);
    if (etag == NULL) {
        return NJT_ERROR;
    }

    etag->hash = 1;
    etag->next = NULL;
    njt_str_set(&etag->key, "ETag");

    etag->value.data = njt_pnalloc(r->pool, NJT_OFF_T_LEN + NJT_TIME_T_LEN + 3);
    if (etag->value.data == NULL) {
        etag->hash = 0;
        return NJT_ERROR;
    }

    etag->value.len = njt_sprintf(etag->value.data, "\"%xT-%xO\"",
                                  r->headers_out.last_modified_time,
                                  r->headers_out.content_length_n)
                      - etag->value.data;

    r->headers_out.etag = etag;

    return NJT_OK;
}


void
njt_http_weak_etag(njt_http_request_t *r)
{
    size_t            len;
    u_char           *p;
    njt_table_elt_t  *etag;

    etag = r->headers_out.etag;

    if (etag == NULL) {
        return;
    }

    if (etag->value.len > 2
        && etag->value.data[0] == 'W'
        && etag->value.data[1] == '/')
    {
        return;
    }

    if (etag->value.len < 1 || etag->value.data[0] != '"') {
        r->headers_out.etag->hash = 0;
        r->headers_out.etag = NULL;
        return;
    }

    p = njt_pnalloc(r->pool, etag->value.len + 2);
    if (p == NULL) {
        r->headers_out.etag->hash = 0;
        r->headers_out.etag = NULL;
        return;
    }

    len = njt_sprintf(p, "W/%V", &etag->value) - p;

    etag->value.data = p;
    etag->value.len = len;
}


njt_int_t
njt_http_send_response(njt_http_request_t *r, njt_uint_t status,
    njt_str_t *ct, njt_http_complex_value_t *cv)
{
    njt_int_t     rc;
    njt_str_t     val;
    njt_buf_t    *b;
    njt_chain_t   out;

    rc = njt_http_discard_request_body(r);

    if (rc != NJT_OK) {
        return rc;
    }

    r->headers_out.status = status;

    if (njt_http_complex_value(r, cv, &val) != NJT_OK) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (status == NJT_HTTP_MOVED_PERMANENTLY
        || status == NJT_HTTP_MOVED_TEMPORARILY
        || status == NJT_HTTP_SEE_OTHER
        || status == NJT_HTTP_TEMPORARY_REDIRECT
        || status == NJT_HTTP_PERMANENT_REDIRECT)
    {
        njt_http_clear_location(r);

        r->headers_out.location = njt_list_push(&r->headers_out.headers);
        if (r->headers_out.location == NULL) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        r->headers_out.location->hash = 1;
        r->headers_out.location->next = NULL;
        njt_str_set(&r->headers_out.location->key, "Location");
        r->headers_out.location->value = val;

        return status;
    }

    r->headers_out.content_length_n = val.len;

    if (ct) {
        r->headers_out.content_type_len = ct->len;
        r->headers_out.content_type = *ct;

    } else {
        if (njt_http_set_content_type(r) != NJT_OK) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    b = njt_calloc_buf(r->pool);
    if (b == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->pos = val.data;
    b->last = val.data + val.len;
    b->memory = val.len ? 1 : 0;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;
    b->sync = (b->last_buf || b->memory) ? 0 : 1;

    out.buf = b;
    out.next = NULL;

    rc = njt_http_send_header(r);

    if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) {
        return rc;
    }

    return njt_http_output_filter(r, &out);
}


njt_int_t
njt_http_send_header(njt_http_request_t *r)
{
    if (r->post_action) {
        return NJT_OK;
    }

    if (r->header_sent) {
        njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
                      "header already sent");
        return NJT_ERROR;
    }

    if (r->err_status) {
        r->headers_out.status = r->err_status;
        r->headers_out.status_line.len = 0;
    }

    return njt_http_top_header_filter(r);
}


njt_int_t
njt_http_output_filter(njt_http_request_t *r, njt_chain_t *in)
{
    njt_int_t          rc;
    njt_connection_t  *c;

    c = r->connection;

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http output filter \"%V?%V\"", &r->uri, &r->args);

    rc = njt_http_top_body_filter(r, in);

    if (rc == NJT_ERROR) {
        /* NJT_ERROR may be returned by any filter */
        c->error = 1;
    }

    return rc;
}


u_char *
njt_http_map_uri_to_path(njt_http_request_t *r, njt_str_t *path,
    size_t *root_length, size_t reserved)
{
    u_char                    *last;
    size_t                     alias;
    njt_http_core_loc_conf_t  *clcf;

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    alias = clcf->alias;

    if (alias && !r->valid_location) {
        njt_log_error(NJT_LOG_ALERT, r->connection->log, 0,
                      "\"alias\" cannot be used in location \"%V\" "
                      "where URI was rewritten", &clcf->name);
        return NULL;
    }

    if (clcf->root_lengths == NULL) {

        *root_length = clcf->root.len;

        path->len = clcf->root.len + reserved + r->uri.len - alias + 1;

        path->data = njt_pnalloc(r->pool, path->len);
        if (path->data == NULL) {
            return NULL;
        }

        last = njt_copy(path->data, clcf->root.data, clcf->root.len);

    } else {

        if (alias == NJT_MAX_SIZE_T_VALUE) {
            reserved += r->add_uri_to_alias ? r->uri.len + 1 : 1;

        } else {
            reserved += r->uri.len - alias + 1;
        }

        if (njt_http_script_run(r, path, clcf->root_lengths->elts, reserved,
                                clcf->root_values->elts)
            == NULL)
        {
            return NULL;
        }

        if (njt_get_full_name(r->pool, (njt_str_t *) &njt_cycle->prefix, path)
            != NJT_OK)
        {
            return NULL;
        }

        *root_length = path->len - reserved;
        last = path->data + *root_length;

        if (alias == NJT_MAX_SIZE_T_VALUE) {
            if (!r->add_uri_to_alias) {
                *last = '\0';
                return last;
            }

            alias = 0;
        }
    }

    last = njt_copy(last, r->uri.data + alias, r->uri.len - alias);
    *last = '\0';

    return last;
}


njt_int_t
njt_http_auth_basic_user(njt_http_request_t *r)
{
    njt_str_t   auth, encoded;
    njt_uint_t  len;

    if (r->headers_in.user.len == 0 && r->headers_in.user.data != NULL) {
        return NJT_DECLINED;
    }

    if (r->headers_in.authorization == NULL) {
        r->headers_in.user.data = (u_char *) "";
        return NJT_DECLINED;
    }

    encoded = r->headers_in.authorization->value;

    if (encoded.len < sizeof("Basic ") - 1
        || njt_strncasecmp(encoded.data, (u_char *) "Basic ",
                           sizeof("Basic ") - 1)
           != 0)
    {
        r->headers_in.user.data = (u_char *) "";
        return NJT_DECLINED;
    }

    encoded.len -= sizeof("Basic ") - 1;
    encoded.data += sizeof("Basic ") - 1;

    while (encoded.len && encoded.data[0] == ' ') {
        encoded.len--;
        encoded.data++;
    }

    if (encoded.len == 0) {
        r->headers_in.user.data = (u_char *) "";
        return NJT_DECLINED;
    }

    auth.len = njt_base64_decoded_length(encoded.len);
    auth.data = njt_pnalloc(r->pool, auth.len + 1);
    if (auth.data == NULL) {
        return NJT_ERROR;
    }

    if (njt_decode_base64(&auth, &encoded) != NJT_OK) {
        r->headers_in.user.data = (u_char *) "";
        return NJT_DECLINED;
    }

    auth.data[auth.len] = '\0';

    for (len = 0; len < auth.len; len++) {
        if (auth.data[len] == ':') {
            break;
        }
    }

    if (len == 0 || len == auth.len) {
        r->headers_in.user.data = (u_char *) "";
        return NJT_DECLINED;
    }

    r->headers_in.user.len = len;
    r->headers_in.user.data = auth.data;
    r->headers_in.passwd.len = auth.len - len - 1;
    r->headers_in.passwd.data = &auth.data[len + 1];

    return NJT_OK;
}


#if (NJT_HTTP_GZIP)

njt_int_t
njt_http_gzip_ok(njt_http_request_t *r)
{
    time_t                     date, expires;
    njt_uint_t                 p;
    njt_table_elt_t           *e, *d, *ae, *cc;
    njt_http_core_loc_conf_t  *clcf;

    r->gzip_tested = 1;

    if (r != r->main) {
        return NJT_DECLINED;
    }

    ae = r->headers_in.accept_encoding;
    if (ae == NULL) {
        return NJT_DECLINED;
    }

    if (ae->value.len < sizeof("gzip") - 1) {
        return NJT_DECLINED;
    }

    /*
     * test first for the most common case "gzip,...":
     *   MSIE:    "gzip, deflate"
     *   Firefox: "gzip,deflate"
     *   Chrome:  "gzip,deflate,sdch"
     *   Safari:  "gzip, deflate"
     *   Opera:   "gzip, deflate"
     */

    if (njt_memcmp(ae->value.data, "gzip,", 5) != 0
        && njt_http_gzip_accept_encoding(&ae->value) != NJT_OK)
    {
        return NJT_DECLINED;
    }

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    if (r->headers_in.msie6 && clcf->gzip_disable_msie6) {
        return NJT_DECLINED;
    }

    if (r->http_version < clcf->gzip_http_version) {
        return NJT_DECLINED;
    }

    if (r->headers_in.via == NULL) {
        goto ok;
    }

    p = clcf->gzip_proxied;

    if (p & NJT_HTTP_GZIP_PROXIED_OFF) {
        return NJT_DECLINED;
    }

    if (p & NJT_HTTP_GZIP_PROXIED_ANY) {
        goto ok;
    }

    if (r->headers_in.authorization && (p & NJT_HTTP_GZIP_PROXIED_AUTH)) {
        goto ok;
    }

    e = r->headers_out.expires;

    if (e) {

        if (!(p & NJT_HTTP_GZIP_PROXIED_EXPIRED)) {
            return NJT_DECLINED;
        }

        expires = njt_parse_http_time(e->value.data, e->value.len);
        if (expires == NJT_ERROR) {
            return NJT_DECLINED;
        }

        d = r->headers_out.date;

        if (d) {
            date = njt_parse_http_time(d->value.data, d->value.len);
            if (date == NJT_ERROR) {
                return NJT_DECLINED;
            }

        } else {
            date = njt_time();
        }

        if (expires < date) {
            goto ok;
        }

        return NJT_DECLINED;
    }

    cc = r->headers_out.cache_control;

    if (cc) {

        if ((p & NJT_HTTP_GZIP_PROXIED_NO_CACHE)
            && njt_http_parse_multi_header_lines(r, cc, &njt_http_gzip_no_cache,
                                                 NULL)
               != NULL)
        {
            goto ok;
        }

        if ((p & NJT_HTTP_GZIP_PROXIED_NO_STORE)
            && njt_http_parse_multi_header_lines(r, cc, &njt_http_gzip_no_store,
                                                 NULL)
               != NULL)
        {
            goto ok;
        }

        if ((p & NJT_HTTP_GZIP_PROXIED_PRIVATE)
            && njt_http_parse_multi_header_lines(r, cc, &njt_http_gzip_private,
                                                 NULL)
               != NULL)
        {
            goto ok;
        }

        return NJT_DECLINED;
    }

    if ((p & NJT_HTTP_GZIP_PROXIED_NO_LM) && r->headers_out.last_modified) {
        return NJT_DECLINED;
    }

    if ((p & NJT_HTTP_GZIP_PROXIED_NO_ETAG) && r->headers_out.etag) {
        return NJT_DECLINED;
    }

ok:

#if (NJT_PCRE)

    if (clcf->gzip_disable && r->headers_in.user_agent) {

        if (njt_regex_exec_array(clcf->gzip_disable,
                                 &r->headers_in.user_agent->value,
                                 r->connection->log)
            != NJT_DECLINED)
        {
            return NJT_DECLINED;
        }
    }

#endif

    r->gzip_ok = 1;

    return NJT_OK;
}


/*
 * gzip is enabled for the following quantities:
 *     "gzip; q=0.001" ... "gzip; q=1.000"
 * gzip is disabled for the following quantities:
 *     "gzip; q=0" ... "gzip; q=0.000", and for any invalid cases
 */

static njt_int_t
njt_http_gzip_accept_encoding(njt_str_t *ae)
{
    u_char  *p, *start, *last;

    start = ae->data;
    last = start + ae->len;

    for ( ;; ) {
        p = njt_strcasestrn(start, "gzip", 4 - 1);
        if (p == NULL) {
            return NJT_DECLINED;
        }

        if (p == start || (*(p - 1) == ',' || *(p - 1) == ' ')) {
            break;
        }

        start = p + 4;
    }

    p += 4;

    while (p < last) {
        switch (*p++) {
        case ',':
            return NJT_OK;
        case ';':
            goto quantity;
        case ' ':
            continue;
        default:
            return NJT_DECLINED;
        }
    }

    return NJT_OK;

quantity:

    while (p < last) {
        switch (*p++) {
        case 'q':
        case 'Q':
            goto equal;
        case ' ':
            continue;
        default:
            return NJT_DECLINED;
        }
    }

    return NJT_OK;

equal:

    if (p + 2 > last || *p++ != '=') {
        return NJT_DECLINED;
    }

    if (njt_http_gzip_quantity(p, last) == 0) {
        return NJT_DECLINED;
    }

    return NJT_OK;
}


static njt_uint_t
njt_http_gzip_quantity(u_char *p, u_char *last)
{
    u_char      c;
    njt_uint_t  n, q;

    c = *p++;

    if (c != '0' && c != '1') {
        return 0;
    }

    q = (c - '0') * 100;

    if (p == last) {
        return q;
    }

    c = *p++;

    if (c == ',' || c == ' ') {
        return q;
    }

    if (c != '.') {
        return 0;
    }

    n = 0;

    while (p < last) {
        c = *p++;

        if (c == ',' || c == ' ') {
            break;
        }

        if (c >= '0' && c <= '9') {
            q += c - '0';
            n++;
            continue;
        }

        return 0;
    }

    if (q > 100 || n > 3) {
        return 0;
    }

    return q;
}

#endif


njt_int_t
njt_http_subrequest(njt_http_request_t *r,
    njt_str_t *uri, njt_str_t *args, njt_http_request_t **psr,
    njt_http_post_subrequest_t *ps, njt_uint_t flags)
{
    njt_time_t                    *tp;
    njt_connection_t              *c;
    njt_http_request_t            *sr;
    njt_http_core_srv_conf_t      *cscf;
    njt_http_postponed_request_t  *pr, *p;

    if (r->subrequests == 0) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "subrequests cycle while processing \"%V\"", uri);
        return NJT_ERROR;
    }

    /*
     * 1000 is reserved for other purposes.
     */
    if (r->main->count >= 65535 - 1000) {
        njt_log_error(NJT_LOG_CRIT, r->connection->log, 0,
                      "request reference counter overflow "
                      "while processing \"%V\"", uri);
        return NJT_ERROR;
    }

    if (r->subrequest_in_memory) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "nested in-memory subrequest \"%V\"", uri);
        return NJT_ERROR;
    }

    sr = njt_pcalloc(r->pool, sizeof(njt_http_request_t));
    if (sr == NULL) {
        return NJT_ERROR;
    }

    sr->signature = NJT_HTTP_MODULE;

    c = r->connection;
    sr->connection = c;

    sr->ctx = njt_pcalloc(r->pool, sizeof(void *) * njt_http_max_module);
    if (sr->ctx == NULL) {
        return NJT_ERROR;
    }

    if (njt_list_init(&sr->headers_out.headers, r->pool, 20,
                      sizeof(njt_table_elt_t))
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    if (njt_list_init(&sr->headers_out.trailers, r->pool, 4,
                      sizeof(njt_table_elt_t))
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);
    sr->main_conf = cscf->ctx->main_conf;
    sr->srv_conf = cscf->ctx->srv_conf;
    sr->loc_conf = cscf->ctx->loc_conf;

    sr->pool = r->pool;

    sr->headers_in = r->headers_in;

    njt_http_clear_content_length(sr);
    njt_http_clear_accept_ranges(sr);
    njt_http_clear_last_modified(sr);

    sr->request_body = r->request_body;

#if (NJT_HTTP_V2)
    sr->stream = r->stream;
#endif

    sr->method = NJT_HTTP_GET;
    sr->http_version = r->http_version;

    sr->request_line = r->request_line;
    sr->uri = *uri;

    if (args) {
        sr->args = *args;
    }

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http subrequest \"%V?%V\"", uri, &sr->args);

    sr->subrequest_in_memory = (flags & NJT_HTTP_SUBREQUEST_IN_MEMORY) != 0;
    sr->waited = (flags & NJT_HTTP_SUBREQUEST_WAITED) != 0;
    sr->background = (flags & NJT_HTTP_SUBREQUEST_BACKGROUND) != 0;

    sr->unparsed_uri = r->unparsed_uri;
    sr->method_name = njt_http_core_get_method;
    sr->http_protocol = r->http_protocol;
    sr->schema = r->schema;

    njt_http_set_exten(sr);

    sr->main = r->main;
    sr->parent = r;
    sr->post_subrequest = ps;
    sr->read_event_handler = njt_http_request_empty_handler;
    sr->write_event_handler = njt_http_handler;

    sr->variables = r->variables;

    sr->log_handler = r->log_handler;

    if (sr->subrequest_in_memory) {
        sr->filter_need_in_memory = 1;
    }

    if (!sr->background) {
        if (c->data == r && r->postponed == NULL) {
            c->data = sr;
        }

        pr = njt_palloc(r->pool, sizeof(njt_http_postponed_request_t));
        if (pr == NULL) {
            return NJT_ERROR;
        }

        pr->request = sr;
        pr->out = NULL;
        pr->next = NULL;

        if (r->postponed) {
            for (p = r->postponed; p->next; p = p->next) { /* void */ }
            p->next = pr;

        } else {
            r->postponed = pr;
        }
    }

    sr->internal = 1;

    sr->discard_body = r->discard_body;
    sr->expect_tested = 1;
    sr->main_filter_need_in_memory = r->main_filter_need_in_memory;

    sr->uri_changes = NJT_HTTP_MAX_URI_CHANGES + 1;
    sr->subrequests = r->subrequests - 1;

    tp = njt_timeofday();
    sr->start_sec = tp->sec;
    sr->start_msec = tp->msec;

    r->main->count++;

    *psr = sr;

    if (flags & NJT_HTTP_SUBREQUEST_CLONE) {
        sr->method = r->method;
        sr->method_name = r->method_name;
        sr->loc_conf = r->loc_conf;
        sr->valid_location = r->valid_location;
        sr->valid_unparsed_uri = r->valid_unparsed_uri;
        sr->content_handler = r->content_handler;
        sr->phase_handler = r->phase_handler;
        sr->write_event_handler = njt_http_core_run_phases;

#if (NJT_PCRE)
        sr->ncaptures = r->ncaptures;
        sr->captures = r->captures;
        sr->captures_data = r->captures_data;
        sr->realloc_captures = 1;
        r->realloc_captures = 1;
#endif

        njt_http_update_location_config(sr);
    }

    return njt_http_post_request(sr, NULL);
}


njt_int_t
njt_http_internal_redirect(njt_http_request_t *r,
    njt_str_t *uri, njt_str_t *args)
{
    njt_http_core_srv_conf_t  *cscf;

    r->uri_changes--;

    if (r->uri_changes == 0) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "rewrite or internal redirection cycle "
                      "while internally redirecting to \"%V\"", uri);

        r->main->count++;
        njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return NJT_DONE;
    }

    r->uri = *uri;

    if (args) {
        r->args = *args;

    } else {
        njt_str_null(&r->args);
    }

    njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "internal redirect: \"%V?%V\"", uri, &r->args);

    njt_http_set_exten(r);

    /* clear the modules contexts */
    njt_memzero(r->ctx, sizeof(void *) * njt_http_max_module);

    cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);
    r->loc_conf = cscf->ctx->loc_conf;

    njt_http_update_location_config(r);

#if (NJT_HTTP_CACHE)
    r->cache = NULL;
#endif

    r->internal = 1;
    r->valid_unparsed_uri = 0;
    r->add_uri_to_alias = 0;
    r->main->count++;

    njt_http_handler(r);

    return NJT_DONE;
}


njt_int_t
njt_http_named_location(njt_http_request_t *r, njt_str_t *name)
{
    njt_http_core_srv_conf_t    *cscf;
    njt_http_core_loc_conf_t   **clcfp;
    njt_http_core_main_conf_t   *cmcf;

    r->main->count++;
    r->uri_changes--;

    if (r->uri_changes == 0) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "rewrite or internal redirection cycle "
                      "while redirect to named location \"%V\"", name);

        njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return NJT_DONE;
    }

    if (r->uri.len == 0) {
        njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                      "empty URI in redirect to named location \"%V\"", name);

        njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return NJT_DONE;
    }

    cscf = njt_http_get_module_srv_conf(r, njt_http_core_module);

    if (cscf->named_locations) {

        for (clcfp = cscf->named_locations; *clcfp; clcfp++) {

            njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "test location: \"%V\"", &(*clcfp)->name);

            if (name->len != (*clcfp)->name.len
                || njt_strncmp(name->data, (*clcfp)->name.data, name->len) != 0)
            {
                continue;
            }

            njt_log_debug3(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "using location: %V \"%V?%V\"",
                           name, &r->uri, &r->args);

            r->internal = 1;
            r->content_handler = NULL;
            r->uri_changed = 0;
            r->loc_conf = (*clcfp)->loc_conf;

            /* clear the modules contexts */
            njt_memzero(r->ctx, sizeof(void *) * njt_http_max_module);

            njt_http_update_location_config(r);

            cmcf = njt_http_get_module_main_conf(r, njt_http_core_module);

            r->phase_handler = cmcf->phase_engine.location_rewrite_index;

            r->write_event_handler = njt_http_core_run_phases;
            njt_http_core_run_phases(r);

            return NJT_DONE;
        }
    }

    njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                  "could not find named location \"%V\"", name);

    njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);

    return NJT_DONE;
}

//by chengxu
#if (NJT_HTTP_DYNAMIC_LOC)
void njt_http_location_cleanup(njt_http_core_loc_conf_t *clcf){
    njt_http_location_destroy_t *ld;
    if(clcf->clean_end ){
        return;
    }
    while (clcf->destroy_locs != NULL) {
        clcf->destroy_locs->destroy_loc(clcf, clcf->destroy_locs->data);
        ld = clcf->destroy_locs;
        clcf->destroy_locs = clcf->destroy_locs->next;
        ld->destroy_loc = NULL;
    }
    clcf->clean_end = 1;
}

static njt_inline void njt_http_location_cleanup_handler(void * data){
    njt_http_location_cleanup((njt_http_core_loc_conf_t*) data);
}

njt_int_t
njt_http_location_cleanup_add(njt_http_core_loc_conf_t *clcf, void(*handler)(njt_http_core_loc_conf_t *hclcf,void* data) ,void* data){
    njt_http_location_destroy_t *ld;
    njt_pool_cleanup_t *pc;

    ld = njt_pcalloc(clcf->pool,sizeof (njt_http_location_destroy_t));
    if ( ld == NULL ){
        return NJT_ERROR;
    }
    ld->data = data;
    ld->destroy_loc = handler;
    ld->next = clcf->destroy_locs;
    clcf->destroy_locs = ld;
    if(!clcf->clean_set){
        clcf->clean_set = 1;
        pc = njt_pool_cleanup_add(clcf->pool,0);
        pc->handler = njt_http_location_cleanup_handler;
        pc->data = clcf;
    }
    return NJT_OK;
}

static void
njt_http_set_del_variable_flag(njt_http_variable_t *fv)
{
    njt_uint_t                  i;
    njt_http_variable_t        *v;
    njt_http_core_main_conf_t  *cmcf;
  
    cmcf = njt_http_cycle_get_module_main_conf(njt_cycle, njt_http_core_module); //variables  动态pool 上申请，格位重复使用。 内存释放
	if(cmcf == NULL) {
		return;
	}

    v = cmcf->variables.elts;

    if (v == NULL) {
        return;
    } else {
        if(cmcf->variables.nelts > fv->index && fv->name.len == v[fv->index].name.len && njt_strncasecmp(fv->name.data, v[fv->index].name.data, fv->name.len) == 0) {
                njt_pfree(cmcf->variables.pool,v[fv->index].name.data);
                v[fv->index].name.data = NULL;
                v[fv->index].name.len =  0;
                v[fv->index].get_handler = NULL;

        } else {  //zyg 正常不会走到这里。走到这里表示，变量被提前删除了，或名字变了。
            njt_log_error(NJT_LOG_WARN, njt_cycle->pool->log, 0, "njt_http_set_del_variable_flag can't find variable %V by index!",&fv->name);
            for (i = 0; i < cmcf->variables.nelts; i++) {
                if (fv->name.len != v[i].name.len
                    || njt_strncasecmp(fv->name.data, v[i].name.data, fv->name.len) != 0)
                {
                    continue;
                }
                njt_pfree(cmcf->variables.pool,v[i].name.data);
                v[i].name.data = NULL;
                v[i].name.len =  0;
                v[i].get_handler = NULL;
                break;
            }
        }
       
    }
 
}

static void
njt_http_set_del_variables_keys_flag(njt_http_variable_t *fv)
{
    njt_uint_t                  i;
    njt_http_variable_t        *v;
    njt_http_core_main_conf_t  *cmcf;
	njt_hash_key_t             *key;
    //njt_str_t *name = &fv->name;

  

   cmcf = njt_http_cycle_get_module_main_conf(njt_cycle, njt_http_core_module);
   if(cmcf == NULL) {
		return;
	}

   key = cmcf->variables_keys->keys.elts;

    if ( key == NULL) {
        return;
    } else {
       for (i = 0; i < cmcf->variables_keys->keys.nelts; i++) {
        v = key[i].value;
        if(fv != v) {
            continue;
        }
         if(v != NULL && v->name.data != NULL) {
            njt_pfree(cmcf->dyn_var_pool,v->name.data);
            v->name.data = NULL;
            v->name.len = 0;
            v->index = 0;
            v->get_handler = NULL;
        }
         return;
        
       }
       if (i == cmcf->variables_keys->keys.nelts) {
            njt_log_error(NJT_LOG_WARN, njt_cycle->pool->log, 0, "njt_http_set_del_variables_keys_flag can't find variable %V by index!",&fv->name);
       }
    }
}


 void njt_http_refresh_variables_keys(){
	
    njt_uint_t                  i,count;
    njt_http_variable_t        *v,*newv;
    njt_http_core_main_conf_t  *cmcf;
	njt_hash_key_t             *key;
	njt_pool_t *old_pool;
	u_char *pdata;
	njt_int_t rc;
	njt_hash_keys_arrays_t    *old_variables_keys;
    static njt_uint_t  use_clone_mem = 1;


   cmcf = njt_http_cycle_get_module_main_conf(njt_cycle, njt_http_core_module);
   if(cmcf == NULL) {
		return;
	}

   key = cmcf->variables_keys->keys.elts;
   count = cmcf->variables_keys->keys.nelts;
	  old_pool = cmcf->variables_keys->pool;
	  old_variables_keys = cmcf->variables_keys;

	  njt_pool_t *new_pool = njt_create_dynamic_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
	   if(new_pool == NULL) {
		   njt_log_error(NJT_LOG_ERR, njt_cycle->pool->log, 0, "njt_http_refresh_variables_keys create pool error!");
		   return ;
	   }
	   rc = njt_sub_pool(njt_cycle->pool,new_pool);
           if (rc != NJT_OK) {
                   cmcf->variables_keys = old_variables_keys;
                   njt_destroy_pool(new_pool);
                   return;
           }

	   cmcf->variables_keys = njt_pcalloc(new_pool,
                                       sizeof(njt_hash_keys_arrays_t));
		if (cmcf->variables_keys == NULL) {
			cmcf->variables_keys = old_variables_keys;//失败时，继续使用旧的。
			njt_destroy_pool(new_pool);
			njt_log_error(NJT_LOG_ERR, njt_cycle->pool->log, 0, "njt_http_refresh_variables_keys create variables_keys error!");
			return ;
		}

		cmcf->variables_keys->pool = new_pool;
		cmcf->variables_keys->temp_pool = new_pool;

		


		if (njt_hash_keys_array_init(cmcf->variables_keys, NJT_HASH_SMALL) != NJT_OK)
		{
			cmcf->variables_keys = old_variables_keys; //失败时，继续使用旧的。
			njt_destroy_pool(new_pool);
			njt_log_error(NJT_LOG_ERR, njt_cycle->pool->log, 0, "njt_http_refresh_variables_keys njt_hash_keys_array_init  error!");
			return;
		}
 
       for (i = 0; i < count; i++) {
		    v = key[i].value;
			if (v->name.data == NULL || v->name.len == 0)
			{
				njt_pfree(cmcf->dyn_var_pool,v);
				continue;
			}
			
			pdata = v->name.data;
			newv = v;
            if(use_clone_mem == 1) {  //zyg 第一次有静态名，需要copy
                newv->name.data = njt_pnalloc(cmcf->dyn_var_pool, v->name.len);
                //num++;
                if (newv->name.data == NULL) {
                    cmcf->variables_keys = old_variables_keys; //失败时，继续使用旧的。
                    njt_destroy_pool(new_pool);
                    njt_log_error(NJT_LOG_ERR, njt_cycle->pool->log, 0, "njt_http_refresh_variables_keys name alloc  error!");
                    return;
                }
                njt_strlow(newv->name.data, pdata, v->name.len);
            }
			njt_hash_add_key(cmcf->variables_keys, &newv->name, newv, 0);
            if(use_clone_mem == 1) {
			    njt_pfree(cmcf->dyn_var_pool,pdata);
            }
			

		}
        use_clone_mem = 0;

		if(old_pool){
		   njt_destroy_pool(old_pool);
		}
		 //njt_log_error(NJT_LOG_DEBUG, njt_cycle->pool->log, 0, "zyg all:%d, remain:%d",count,num);
		
}


static njt_int_t njt_http_rewrite_delete_dyn_var(njt_http_rewrite_loc_conf_t *rlcf) {
	njt_http_variable_t                     **ip;
	njt_uint_t	               i;
	njt_uint_t                 rf = 0;

	ip = rlcf->var_names.elts;

	for(i=0; i < rlcf->var_names.nelts; i++) {   //var_names，location 上内存不需要释放。
        if (njt_http_del_variable(ip[i]) == NJT_OK) {
            rf = 1;
        }
	}
	return rf;

}


static void njt_http_location_delete_dyn_var_run(njt_http_core_loc_conf_t *clcf,njt_uint_t *have) {
     njt_queue_t *locations;
    njt_queue_t *q;
    njt_http_rewrite_loc_conf_t  *rlcf;
    njt_uint_t                 rf = 0;
    njt_http_location_queue_t *lq;
    njt_http_core_loc_conf_t *new_clcf;
    locations = clcf->old_locations;
    if (locations != NULL) {
        for (q = njt_queue_head(locations);
             q != njt_queue_sentinel(locations);
             q = njt_queue_next(q)) {
            lq = (njt_http_location_queue_t *) q;
            if (lq->exact != NULL) {
                new_clcf = lq->exact;
                njt_http_location_delete_dyn_var_run(new_clcf,have);
            } else if (lq->inclusive != NULL) {
                new_clcf = lq->inclusive;
                njt_http_location_delete_dyn_var_run(new_clcf,have); //zyg
            }
			
        }
    } 
    if(clcf->loc_conf != NULL && clcf->ref_count == 0 && clcf->dynamic_status != 0) {
        rlcf = clcf->loc_conf[njt_http_rewrite_module.ctx_index]; 
        rf = njt_http_rewrite_delete_dyn_var(rlcf);
        if(rf == 1) {
            *have = rf;
        }
    }
}
void  njt_http_location_delete_dyn_var(njt_http_core_loc_conf_t *clcf) {
      njt_uint_t                 rf = 0;
      njt_http_location_delete_dyn_var_run(clcf,&rf);
      if(rf == 1) {
		njt_http_refresh_variables_keys();
	  }
}

#endif
//end

njt_http_cleanup_t *
njt_http_cleanup_add(njt_http_request_t *r, size_t size)
{
    njt_http_cleanup_t  *cln;

    r = r->main;

    cln = njt_palloc(r->pool, sizeof(njt_http_cleanup_t));
    if (cln == NULL) {
        return NULL;
    }

    if (size) {
        cln->data = njt_palloc(r->pool, size);
        if (cln->data == NULL) {
            return NULL;
        }

    } else {
        cln->data = NULL;
    }

    cln->handler = NULL;
    cln->next = r->cleanup;

    r->cleanup = cln;

    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http cleanup add: %p", cln);

    return cln;
}


njt_int_t
njt_http_set_disable_symlinks(njt_http_request_t *r,
    njt_http_core_loc_conf_t *clcf, njt_str_t *path, njt_open_file_info_t *of)
{
#if (NJT_HAVE_OPENAT)
    u_char     *p;
    njt_str_t   from;

    of->disable_symlinks = clcf->disable_symlinks;

    if (clcf->disable_symlinks_from == NULL) {
        return NJT_OK;
    }

    if (njt_http_complex_value(r, clcf->disable_symlinks_from, &from)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    if (from.len == 0
        || from.len > path->len
        || njt_memcmp(path->data, from.data, from.len) != 0)
    {
        return NJT_OK;
    }

    if (from.len == path->len) {
        of->disable_symlinks = NJT_DISABLE_SYMLINKS_OFF;
        return NJT_OK;
    }

    p = path->data + from.len;

    if (*p == '/') {
        of->disable_symlinks_from = from.len;
        return NJT_OK;
    }

    p--;

    if (*p == '/') {
        of->disable_symlinks_from = from.len - 1;
    }
#endif

    return NJT_OK;
}


njt_int_t
njt_http_get_forwarded_addr(njt_http_request_t *r, njt_addr_t *addr,
    njt_table_elt_t *headers, njt_str_t *value, njt_array_t *proxies,
    int recursive)
{
    njt_int_t         rc;
    njt_uint_t        found;
    njt_table_elt_t  *h, *next;

    if (headers == NULL) {
        return njt_http_get_forwarded_addr_internal(r, addr, value->data,
                                                    value->len, proxies,
                                                    recursive);
    }

    /* revert headers order */

    for (h = headers, headers = NULL; h; h = next) {
        next = h->next;
        h->next = headers;
        headers = h;
    }

    /* iterate over all headers in reverse order */

    rc = NJT_DECLINED;

    found = 0;

    for (h = headers; h; h = h->next) {
        rc = njt_http_get_forwarded_addr_internal(r, addr, h->value.data,
                                                  h->value.len, proxies,
                                                  recursive);

        if (!recursive) {
            break;
        }

        if (rc == NJT_DECLINED && found) {
            rc = NJT_DONE;
            break;
        }

        if (rc != NJT_OK) {
            break;
        }

        found = 1;
    }

    /* restore headers order */

    for (h = headers, headers = NULL; h; h = next) {
        next = h->next;
        h->next = headers;
        headers = h;
    }

    return rc;
}


static njt_int_t
njt_http_get_forwarded_addr_internal(njt_http_request_t *r, njt_addr_t *addr,
    u_char *xff, size_t xfflen, njt_array_t *proxies, int recursive)
{
    u_char      *p;
    njt_addr_t   paddr;
    njt_uint_t   found;

    found = 0;

    do {

        if (njt_cidr_match(addr->sockaddr, proxies) != NJT_OK) {
            return found ? NJT_DONE : NJT_DECLINED;
        }

        for (p = xff + xfflen - 1; p > xff; p--, xfflen--) {
            if (*p != ' ' && *p != ',') {
                break;
            }
        }

        for ( /* void */ ; p > xff; p--) {
            if (*p == ' ' || *p == ',') {
                p++;
                break;
            }
        }

        if (njt_parse_addr_port(r->pool, &paddr, p, xfflen - (p - xff))
            != NJT_OK)
        {
            return found ? NJT_DONE : NJT_DECLINED;
        }

        *addr = paddr;
        found = 1;
        xfflen = p - 1 - xff;

    } while (recursive && p > xff);

    return NJT_OK;
}


njt_int_t
njt_http_link_multi_headers(njt_http_request_t *r)
{
    njt_uint_t        i, j;
    njt_list_part_t  *part, *ppart;
    njt_table_elt_t  *header, *pheader, **ph;

    if (r->headers_in.multi_linked) {
        return NJT_OK;
    }

    r->headers_in.multi_linked = 1;

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

        header[i].next = NULL;

        /*
         * search for previous headers with the same name;
         * if there are any, link to them
         */

        ppart = &r->headers_in.headers.part;
        pheader = ppart->elts;

        for (j = 0; /* void */; j++) {

            if (j >= ppart->nelts) {
                if (ppart->next == NULL) {
                    break;
                }

                ppart = ppart->next;
                pheader = ppart->elts;
                j = 0;
            }

            if (part == ppart && i == j) {
                break;
            }

            if (header[i].key.len == pheader[j].key.len
                && njt_strncasecmp(header[i].key.data, pheader[j].key.data,
                                   header[i].key.len)
                   == 0)
            {
                ph = &pheader[j].next;
                while (*ph) { ph = &(*ph)->next; }
                *ph = &header[i];

                r->headers_in.multi = 1;

                break;
            }
        }
    }

    return NJT_OK;
}


static char *
njt_http_core_server(njt_conf_t *cf, njt_command_t *cmd, void *dummy)
{
    char                        *rv;
    void                        *mconf;
    size_t                       len;
    u_char                      *p;
    njt_uint_t                   i;
    njt_conf_t                   pcf;
    njt_http_module_t           *module;
    struct sockaddr_in          *sin;
    njt_http_conf_ctx_t         *ctx, *http_ctx;
    njt_http_listen_opt_t        lsopt;
    njt_http_core_srv_conf_t    *cscf, **cscfp;
    njt_http_core_main_conf_t   *cmcf;
	njt_int_t rc;

#if (NJT_HTTP_DYNAMIC_SERVER)
    njt_pool_t *old_server_pool,*new_server_pool,*old_server_temp_pool;
    

    old_server_pool = cf->pool;
    old_server_temp_pool = cf->temp_pool;
    new_server_pool = njt_create_dynamic_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
    if (new_server_pool == NULL) {
        return NJT_CONF_ERROR;
    }
    rc = njt_sub_pool(cf->cycle->pool,new_server_pool);
    if (rc != NJT_OK) {
        return NJT_CONF_ERROR;
    }
    cf->pool = new_server_pool;
    cf->temp_pool = new_server_pool;

     njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                          "create server=%p",cf->pool);
#endif

    ctx = njt_pcalloc(cf->pool, sizeof(njt_http_conf_ctx_t));
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }
    // ctx->type = 2;
    http_ctx = cf->ctx;
    ctx->main_conf = http_ctx->main_conf;

    /* the server{}'s srv_conf */

    ctx->srv_conf = njt_pcalloc(cf->pool, sizeof(void *) * njt_http_max_module);
    if (ctx->srv_conf == NULL) {
        return NJT_CONF_ERROR;
    }

    /* the server{}'s loc_conf */

    ctx->loc_conf = njt_pcalloc(cf->pool, sizeof(void *) * njt_http_max_module);
    if (ctx->loc_conf == NULL) {
        return NJT_CONF_ERROR;
    }
    // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
    njt_pool_t *old_pool,*new_pool,*old_temp_pool;


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
    for (i = 0; cf->cycle->modules[i]; i++) {
        if (cf->cycle->modules[i]->type != NJT_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[i]->ctx;

        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return NJT_CONF_ERROR;
            }

            ctx->srv_conf[cf->cycle->modules[i]->ctx_index] = mconf;
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

            ctx->loc_conf[cf->cycle->modules[i]->ctx_index] = mconf;
        }
        // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
        cf->pool = old_pool;
        cf->temp_pool = old_temp_pool;
#endif
        //end
    }


    /* the server configuration context */

    cscf = ctx->srv_conf[njt_http_core_module.ctx_index];
    cscf->ctx = ctx;


    cmcf = ctx->main_conf[njt_http_core_module.ctx_index];

    cscfp = njt_array_push(&cmcf->servers);
    if (cscfp == NULL) {
        return NJT_CONF_ERROR;
    }

    *cscfp = cscf;


    /* parse inside server{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NJT_HTTP_SRV_CONF;

    rv = njt_conf_parse(cf, NULL);
    *cf = pcf;
#if (NJT_HTTP_DYNAMIC_SERVER)
    cscf->pool = new_server_pool;
    cf->pool = old_server_pool;
    cf->temp_pool = old_server_temp_pool;
    cscf->dynamic = cf->dynamic;
    cscf->dynamic_status = cf->dynamic;  // 1 
#endif


    if (rv == NJT_CONF_OK && !cscf->listen && cf->dynamic == 0) {
        njt_memzero(&lsopt, sizeof(njt_http_listen_opt_t));

        p = njt_pcalloc(cf->pool, sizeof(struct sockaddr_in));
        if (p == NULL) {
            return NJT_CONF_ERROR;
        }

        lsopt.sockaddr = (struct sockaddr *) p;

        sin = (struct sockaddr_in *) p;

        sin->sin_family = AF_INET;
#if (NJT_WIN32)
        sin->sin_port = htons(80);
#else
        sin->sin_port = htons((getuid() == 0) ? 80 : 8000);
#endif
        sin->sin_addr.s_addr = INADDR_ANY;

        lsopt.socklen = sizeof(struct sockaddr_in);

        lsopt.backlog = NJT_LISTEN_BACKLOG;
	lsopt.type = SOCK_STREAM;
        lsopt.rcvbuf = -1;
        lsopt.sndbuf = -1;
#if (NJT_HAVE_SETFIB)
        lsopt.setfib = -1;
#endif
#if (NJT_HAVE_TCP_FASTOPEN)
        lsopt.fastopen = -1;
#endif
        lsopt.wildcard = 1;

        len = NJT_INET_ADDRSTRLEN + sizeof(":65535") - 1;

        p = njt_pnalloc(cf->pool, len);
        if (p == NULL) {
            return NJT_CONF_ERROR;
        }

        lsopt.addr_text.data = p;
        lsopt.addr_text.len = njt_sock_ntop(lsopt.sockaddr, lsopt.socklen, p,
                                            len, 1);

        if (njt_http_add_listen(cf, cscf, &lsopt) != NJT_OK) {
            return NJT_CONF_ERROR;
        }
    }

    return rv;
}


static char *
njt_http_core_location(njt_conf_t *cf, njt_command_t *cmd, void *dummy)
{
    char                      *rv;
    u_char                    *mod;
    size_t                     len;
    njt_str_t                 *value, *ori_value,*name;
    njt_uint_t                 i;
    njt_conf_t                 save;
    njt_http_module_t         *module;
    njt_http_conf_ctx_t       *ctx, *pctx;
    njt_http_core_loc_conf_t  *clcf, *pclcf;
    njt_http_location_queue_t *lq;
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
        njt_destroy_pool(new_pool);
        return NJT_CONF_ERROR;
    }
   
    cf->pool = new_pool;
    cf->temp_pool = new_pool;
#endif
    //end
    ctx = njt_pcalloc(cf->pool, sizeof(njt_http_conf_ctx_t));
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }
    // ctx->type = 3;
    pctx = cf->ctx;
    ctx->main_conf = pctx->main_conf;
    ctx->srv_conf = pctx->srv_conf;
    pclcf = pctx->loc_conf[njt_http_core_module.ctx_index];

    

    ctx->loc_conf = njt_pcalloc(cf->pool, sizeof(void *) * njt_http_max_module);
    if (ctx->loc_conf == NULL) {
        return NJT_CONF_ERROR;
    }

    for (i = 0; cf->cycle->modules[i]; i++) {
        if (cf->cycle->modules[i]->type != NJT_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[i]->ctx;

        if (module->create_loc_conf) {
            ctx->loc_conf[cf->cycle->modules[i]->ctx_index] =
                                                   module->create_loc_conf(cf);
            if (ctx->loc_conf[cf->cycle->modules[i]->ctx_index] == NULL) {
                return NJT_CONF_ERROR;
            }
        }

    }
    // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
    //cf->pool = old_pool;  //zyg
    //cf->temp_pool = old_temp_pool;
#endif
    //end
    clcf = ctx->loc_conf[njt_http_core_module.ctx_index];
    clcf->loc_conf = ctx->loc_conf;

    value = cf->args->elts;
    // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
    u_char* index;
    len =0;
    ori_value = cf->ori_args->elts;
    for(i = 1; i < cf->ori_args->nelts; i++){
        //len += value[i].len+1;
        len += ori_value[i].len + 1;
    }
    index = njt_pcalloc(clcf->pool,len+1);
    if (index == NULL){
        return NJT_CONF_ERROR;
    }
    clcf->full_name.data = index;
    for(i = 1; i < cf->ori_args->nelts; i++){
        njt_memcpy(index,ori_value[i].data,ori_value[i].len);
        index += ori_value[i].len;
        *index = (u_char)' ';
        ++index;
    }
    clcf->full_name.len = len;
    if(clcf->full_name.len > 0) {
        clcf->full_name.len --;
    }
#endif
    //end
    if (cf->args->nelts == 3) {

        len = value[1].len;
        mod = value[1].data;
        // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
        njt_str_t location_name;
        location_name.data = njt_pcalloc(clcf->pool,value[2].len+1);
        if (location_name.data == NULL){
            return NJT_CONF_ERROR;
        }
        location_name.len = value[2].len;
        njt_memcpy(location_name.data,value[2].data,value[2].len+1);
        name = & location_name;
#else
        name = &value[2];
#endif
        //end

        if (len == 1 && mod[0] == '=') {

            clcf->name = *name;
            clcf->exact_match = 1;

        } else if (len == 2 && mod[0] == '^' && mod[1] == '~') {

            clcf->name = *name;
            clcf->noregex = 1;

        } else if (len == 1 && mod[0] == '~') {

            if (njt_http_core_regex_location(cf, clcf, name, 0) != NJT_OK) {
                return NJT_CONF_ERROR;
            }

        } else if (len == 2 && mod[0] == '~' && mod[1] == '*') {

            if (njt_http_core_regex_location(cf, clcf, name, 1) != NJT_OK) {
                return NJT_CONF_ERROR;
            }

        } else if (mod[0] == '(') {
		if (njt_http_core_if_location_parse(cf,clcf) != NJT_CONF_OK){
			njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
					"invalid location modifier \"%V\"", &value[1]);
			return NJT_CONF_ERROR;
		}
		lq = njt_http_find_location(clcf->full_name,pclcf->if_locations);
		if(lq != NULL && clcf->full_name.data != NULL){
			njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
					"duplicate location \"%V\"", &clcf->full_name);
			return NJT_CONF_ERROR;
		}
		clcf->if_loc = 1;
		clcf->exact_match = 1;
		clcf->name = clcf->full_name;
        } else {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid location modifier \"%V\"", &value[1]);
            return NJT_CONF_ERROR;
        }

    } else {
        // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
        njt_str_t location_name;
        location_name.data = njt_pcalloc(clcf->pool,value[1].len+1);
        if (location_name.data == NULL){
            return NJT_CONF_ERROR;
        }
        location_name.len = value[1].len;
        njt_memcpy(location_name.data,value[1].data,value[1].len+1);
        name = &location_name;
#else
        name = &value[1];
#endif
        //end
	if (name->data[0] == '(') {
		if (njt_http_core_if_location_parse(cf,clcf) != NJT_CONF_OK){
			njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
					"invalid location modifier \"%V\"", &value[1]);
			return NJT_CONF_ERROR;
		}
		lq = njt_http_find_location(clcf->full_name,pclcf->if_locations);
		if(lq != NULL && clcf->full_name.data != NULL){
			njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
					"duplicate location \"%V\"", &clcf->full_name);
			return NJT_CONF_ERROR;
		}
		clcf->if_loc = 1;
		clcf->exact_match = 1;
		clcf->name = clcf->full_name;
        } else {
			if (cf->args->nelts != 2) {
				 njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
						   "invalid location modifier \"%V\"", &value[1]);
				return NJT_CONF_ERROR;
			}
			if (name->data[0] == '=') {

				clcf->name.len = name->len - 1;
				clcf->name.data = name->data + 1;
				clcf->exact_match = 1;

			} else if (name->data[0] == '^' && name->data[1] == '~') {

				clcf->name.len = name->len - 2;
				clcf->name.data = name->data + 2;
				clcf->noregex = 1;

			} else if (name->data[0] == '~') {

				name->len--;
				name->data++;

				if (name->data[0] == '*') {

					name->len--;
					name->data++;

					if (njt_http_core_regex_location(cf, clcf, name, 1) != NJT_OK) {
						return NJT_CONF_ERROR;
					}

				} else {
					if (njt_http_core_regex_location(cf, clcf, name, 0) != NJT_OK) {
						return NJT_CONF_ERROR;
					}
				}

			} else {
				clcf->name = *name;

				if (name->data[0] == '@') {
					clcf->named = 1;
				}
			}
		}
    }


    if (cf->cmd_type == NJT_HTTP_LOC_CONF) {

        /* nested location */
	//if (clcf->if_loc == 1 ){
	///  clcf->name = clcf->full_name;
	//}

#if 0
        clcf->prev_location = pclcf;
#endif

        if (pclcf->exact_match) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "location \"%V\" cannot be inside "
                               "the exact location \"%V\"",
                               &clcf->name, &pclcf->name);
            return NJT_CONF_ERROR;
        }

        if (pclcf->named) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "location \"%V\" cannot be inside "
                               "the named location \"%V\"",
                               &clcf->name, &pclcf->name);
            return NJT_CONF_ERROR;
        }

        if (clcf->named) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "named location \"%V\" can be "
                               "on the server level only",
                               &clcf->name);
            return NJT_CONF_ERROR;
        }

        len = pclcf->name.len;

#if (NJT_PCRE)
        if (clcf->regex == NULL
            && njt_filename_cmp(clcf->name.data, pclcf->name.data, len) != 0 && clcf->if_loc != 1)
#else
        if (njt_filename_cmp(clcf->name.data, pclcf->name.data, len) != 0 && clcf->if_loc != 1)
#endif
        {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "location \"%V\" is outside location \"%V\"",
                               &clcf->name, &pclcf->name);
            return NJT_CONF_ERROR;
        }
    }
	    if(cf->dynamic != 1){
		if (njt_http_add_location_pre_process(cf,&pclcf->locations,pclcf->pool) != NJT_OK || njt_http_add_location(cf, &pclcf->locations, clcf) != NJT_OK) {
		    return NJT_CONF_ERROR;
		}
	    } else {
			 clcf->dynamic_status = 1;  // 1 
		}
    if (clcf->if_loc == 1 ) {
	     if (njt_http_add_location_pre_process(cf,&pclcf->if_locations,pclcf->pool) != NJT_OK || njt_http_add_location(cf, &pclcf->if_locations, clcf) != NJT_OK) {
		    return NJT_CONF_ERROR;
	      }
     } 
	    if (njt_http_add_location_pre_process(cf,&pclcf->old_locations,pclcf->pool) != NJT_OK || njt_http_add_location(cf, &pclcf->old_locations, clcf) != NJT_OK) {
		    return NJT_CONF_ERROR;
	    }

    save = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NJT_HTTP_LOC_CONF;

    // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
    cf->pool = new_pool;
    cf->temp_pool = new_pool;
#endif
    //end
    rv = njt_conf_parse(cf, NULL);
    // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
    cf->pool = old_pool;
    cf->temp_pool = old_temp_pool;
#endif
    //end



    *cf = save;

    return rv;
}


static njt_int_t
njt_http_core_regex_location(njt_conf_t *cf, njt_http_core_loc_conf_t *clcf,
    njt_str_t *regex, njt_uint_t caseless)
{
#if (NJT_PCRE)
    njt_regex_compile_t  rc;
    u_char               errstr[NJT_MAX_CONF_ERRSTR];

    njt_memzero(&rc, sizeof(njt_regex_compile_t));

    rc.pattern = *regex;
    rc.err.len = NJT_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

#if (NJT_HAVE_CASELESS_FILESYSTEM)
    rc.options = NJT_REGEX_CASELESS;
#else
    rc.options = caseless ? NJT_REGEX_CASELESS : 0;
#endif

    clcf->regex = njt_http_regex_compile(cf, &rc);
    if (clcf->regex == NULL) {
        return NJT_ERROR;
    }

    clcf->name = *regex;

    return NJT_OK;

#else

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "using regex \"%V\" requires PCRE library",
                       regex);
    return NJT_ERROR;

#endif
}


static char *
njt_http_core_types(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_core_loc_conf_t *clcf = conf;

    char        *rv;
    njt_conf_t   save;

    if (clcf->types == NULL) {
        clcf->types = njt_array_create(cf->pool, 64, sizeof(njt_hash_key_t));
        if (clcf->types == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    save = *cf;
    cf->handler = njt_http_core_type;
    cf->handler_conf = conf;

    rv = njt_conf_parse(cf, NULL);

    *cf = save;

    return rv;
}


static char *
njt_http_core_type(njt_conf_t *cf, njt_command_t *dummy, void *conf)
{
    njt_http_core_loc_conf_t *clcf = conf;

    njt_str_t       *value, *content_type, *old;
    njt_uint_t       i, n, hash;
    njt_hash_key_t  *type;

    value = cf->args->elts;

    if (njt_strcmp(value[0].data, "include") == 0) {
        if (cf->args->nelts != 2) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid number of arguments"
                               " in \"include\" directive");
            return NJT_CONF_ERROR;
        }

        return njt_conf_include(cf, dummy, conf);
    }

    content_type = njt_palloc(cf->pool, sizeof(njt_str_t));
    if (content_type == NULL) {
        return NJT_CONF_ERROR;
    }

    *content_type = value[0];

    for (i = 1; i < cf->args->nelts; i++) {

        hash = njt_hash_strlow(value[i].data, value[i].data, value[i].len);

        type = clcf->types->elts;
        for (n = 0; n < clcf->types->nelts; n++) {
            if (njt_strcmp(value[i].data, type[n].key.data) == 0) {
                old = type[n].value;
                type[n].value = content_type;

                njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                                   "duplicate extension \"%V\", "
                                   "content type: \"%V\", "
                                   "previous content type: \"%V\"",
                                   &value[i], content_type, old);
                goto next;
            }
        }


        type = njt_array_push(clcf->types);
        if (type == NULL) {
            return NJT_CONF_ERROR;
        }

        type->key = value[i];
        type->key_hash = hash;
        type->value = content_type;

    next:
        continue;
    }

    return NJT_CONF_OK;
}


static njt_int_t
njt_http_core_preconfiguration(njt_conf_t *cf)
{
    return njt_http_variables_add_core_vars(cf);
}


static njt_int_t
njt_http_core_postconfiguration(njt_conf_t *cf)
{
    njt_http_top_request_body_filter = njt_http_request_body_save_filter;

    return NJT_OK;
}


static void *
njt_http_core_create_main_conf(njt_conf_t *cf)
{
    njt_http_core_main_conf_t  *cmcf;

    cmcf = njt_pcalloc(cf->pool, sizeof(njt_http_core_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }

    if (njt_array_init(&cmcf->servers, cf->pool, 4,
                       sizeof(njt_http_core_srv_conf_t *))
        != NJT_OK)
    {
        return NULL;
    }

    cmcf->server_names_hash_max_size = NJT_CONF_UNSET_UINT;
    cmcf->server_names_hash_bucket_size = NJT_CONF_UNSET_UINT;

    cmcf->variables_hash_max_size = NJT_CONF_UNSET_UINT;
    cmcf->variables_hash_bucket_size = NJT_CONF_UNSET_UINT;

    return cmcf;
}


static char *
njt_http_core_init_main_conf(njt_conf_t *cf, void *conf)
{
    njt_http_core_main_conf_t *cmcf = conf;

    njt_conf_init_uint_value(cmcf->server_names_hash_max_size, 512);
    njt_conf_init_uint_value(cmcf->server_names_hash_bucket_size,
                             njt_cacheline_size);

    cmcf->server_names_hash_bucket_size =
            njt_align(cmcf->server_names_hash_bucket_size, njt_cacheline_size);


    njt_conf_init_uint_value(cmcf->variables_hash_max_size, 1024);
    njt_conf_init_uint_value(cmcf->variables_hash_bucket_size, 64);

    cmcf->variables_hash_bucket_size =
               njt_align(cmcf->variables_hash_bucket_size, njt_cacheline_size);

    if (cmcf->ncaptures) {
        cmcf->ncaptures = (cmcf->ncaptures + 1) * 3;
    }

    return NJT_CONF_OK;
}


static void *
njt_http_core_create_srv_conf(njt_conf_t *cf)
{
    njt_http_core_srv_conf_t  *cscf;

    cscf = njt_pcalloc(cf->pool, sizeof(njt_http_core_srv_conf_t));
    if (cscf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     conf->client_large_buffers.num = 0;
     */

    if (njt_array_init(&cscf->server_names, cf->temp_pool, 4,
                       sizeof(njt_http_server_name_t))
        != NJT_OK)
    {
        return NULL;
    }

    cscf->connection_pool_size = NJT_CONF_UNSET_SIZE;
    cscf->request_pool_size = NJT_CONF_UNSET_SIZE;
    cscf->client_header_timeout = NJT_CONF_UNSET_MSEC;
    cscf->client_header_buffer_size = NJT_CONF_UNSET_SIZE;
    cscf->ignore_invalid_headers = NJT_CONF_UNSET;
    cscf->merge_slashes = NJT_CONF_UNSET;
    cscf->underscores_in_headers = NJT_CONF_UNSET;

    cscf->file_name = cf->conf_file->file.name.data;
    cscf->line = cf->conf_file->line;
#if (NJT_HTTP_DYNAMIC_SERVER)
    cscf->pool=cf->pool;  // cx 澶勭悊鍐呭瓨閲婃斁
#endif
    return cscf;
}


static char *
njt_http_core_merge_srv_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_core_srv_conf_t *prev = parent;
    njt_http_core_srv_conf_t *conf = child;

    njt_str_t                name;
    njt_http_server_name_t  *sn;

    /* TODO: it does not merge, it inits only */

    njt_conf_merge_size_value(conf->connection_pool_size,
                              prev->connection_pool_size, 64 * sizeof(void *));
    njt_conf_merge_size_value(conf->request_pool_size,
                              prev->request_pool_size, 4096);
    njt_conf_merge_msec_value(conf->client_header_timeout,
                              prev->client_header_timeout, 60000);
    njt_conf_merge_size_value(conf->client_header_buffer_size,
                              prev->client_header_buffer_size, 1024);
    njt_conf_merge_bufs_value(conf->large_client_header_buffers,
                              prev->large_client_header_buffers,
                              4, 8192);

    if (conf->large_client_header_buffers.size < conf->connection_pool_size) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "the \"large_client_header_buffers\" size must be "
                           "equal to or greater than \"connection_pool_size\"");
        return NJT_CONF_ERROR;
    }

    njt_conf_merge_value(conf->ignore_invalid_headers,
                              prev->ignore_invalid_headers, 1);

    njt_conf_merge_value(conf->merge_slashes, prev->merge_slashes, 1);

    njt_conf_merge_value(conf->underscores_in_headers,
                              prev->underscores_in_headers, 0);

    if (conf->server_names.nelts == 0) {
        /* the array has 4 empty preallocated elements, so push cannot fail */
        sn = njt_array_push(&conf->server_names);
#if (NJT_PCRE)
        sn->regex = NULL;
#endif
        sn->server = conf;
        njt_str_set(&sn->name, "");
         njt_str_set(&sn->full_name, "");
    }

    sn = conf->server_names.elts;
    name = sn[0].name;

#if (NJT_PCRE)
    if (sn->regex) {
        name.len++;
        name.data--;
    } else
#endif

    if (name.data[0] == '.') {
        name.len--;
        name.data++;
    }

    conf->server_name.len = name.len;
    conf->server_name.data = njt_pstrdup(cf->pool, &name);
    if (conf->server_name.data == NULL) {
        return NJT_CONF_ERROR;
    }
    return NJT_CONF_OK;
}


static void *
njt_http_core_create_loc_conf(njt_conf_t *cf)
{
    njt_http_core_loc_conf_t  *clcf;

    clcf = njt_pcalloc(cf->pool, sizeof(njt_http_core_loc_conf_t));
    if (clcf == NULL) {
        return NULL;
    }

    /*
     * set by njt_pcalloc():
     *
     *     clcf->escaped_name = { 0, NULL };
     *     clcf->root = { 0, NULL };
     *     clcf->limit_except = 0;
     *     clcf->post_action = { 0, NULL };
     *     clcf->types = NULL;
     *     clcf->default_type = { 0, NULL };
     *     clcf->error_log = NULL;
     *     clcf->error_pages = NULL;
     *     clcf->client_body_path = NULL;
     *     clcf->regex = NULL;
     *     clcf->exact_match = 0;
     *     clcf->auto_redirect = 0;
     *     clcf->alias = 0;
     *     clcf->gzip_proxied = 0;
     *     clcf->keepalive_disable = 0;
     */
    // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
    clcf->pool=cf->pool;  // cx 处理内存释放
    clcf->destroy_locs = NULL; // cx 处理资源释放
    clcf->ref_count = 0;
    clcf->clean_set = 0;
    clcf->clean_end = 0;
#endif
    //end
    clcf->client_max_body_size = NJT_CONF_UNSET;
    clcf->client_body_buffer_size = NJT_CONF_UNSET_SIZE;
    clcf->client_body_timeout = NJT_CONF_UNSET_MSEC;
    clcf->satisfy = NJT_CONF_UNSET_UINT;
    clcf->auth_delay = NJT_CONF_UNSET_MSEC;
    clcf->if_modified_since = NJT_CONF_UNSET_UINT;
    clcf->max_ranges = NJT_CONF_UNSET_UINT;
    clcf->client_body_in_file_only = NJT_CONF_UNSET_UINT;
    clcf->client_body_in_single_buffer = NJT_CONF_UNSET;
    clcf->internal = NJT_CONF_UNSET;
    clcf->sendfile = NJT_CONF_UNSET;
    clcf->sendfile_max_chunk = NJT_CONF_UNSET_SIZE;
    clcf->subrequest_output_buffer_size = NJT_CONF_UNSET_SIZE;
    clcf->aio = NJT_CONF_UNSET;
    clcf->aio_write = NJT_CONF_UNSET;
#if (NJT_THREADS)
    clcf->thread_pool = NJT_CONF_UNSET_PTR;
    clcf->thread_pool_value = NJT_CONF_UNSET_PTR;
#endif
    clcf->read_ahead = NJT_CONF_UNSET_SIZE;
    clcf->directio = NJT_CONF_UNSET;
    clcf->directio_alignment = NJT_CONF_UNSET;
    clcf->tcp_nopush = NJT_CONF_UNSET;
    clcf->tcp_nodelay = NJT_CONF_UNSET;
    clcf->send_timeout = NJT_CONF_UNSET_MSEC;
    clcf->send_lowat = NJT_CONF_UNSET_SIZE;
    clcf->postpone_output = NJT_CONF_UNSET_SIZE;
    clcf->limit_rate = NJT_CONF_UNSET_PTR;
    clcf->limit_rate_after = NJT_CONF_UNSET_PTR;
    clcf->keepalive_time = NJT_CONF_UNSET_MSEC;
    clcf->keepalive_timeout = NJT_CONF_UNSET_MSEC;
    clcf->keepalive_header = NJT_CONF_UNSET;
    clcf->keepalive_requests = NJT_CONF_UNSET_UINT;
    clcf->lingering_close = NJT_CONF_UNSET_UINT;
    clcf->lingering_time = NJT_CONF_UNSET_MSEC;
    clcf->lingering_timeout = NJT_CONF_UNSET_MSEC;
    clcf->resolver_timeout = NJT_CONF_UNSET_MSEC;
    clcf->reset_timedout_connection = NJT_CONF_UNSET;
    clcf->absolute_redirect = NJT_CONF_UNSET;
    clcf->server_name_in_redirect = NJT_CONF_UNSET;
    clcf->port_in_redirect = NJT_CONF_UNSET;
    clcf->msie_padding = NJT_CONF_UNSET;
    clcf->msie_refresh = NJT_CONF_UNSET;
    clcf->log_not_found = NJT_CONF_UNSET;
    clcf->log_subrequest = NJT_CONF_UNSET;
    clcf->recursive_error_pages = NJT_CONF_UNSET;
    clcf->chunked_transfer_encoding = NJT_CONF_UNSET;
    clcf->etag = NJT_CONF_UNSET;
    clcf->server_tokens = NJT_CONF_UNSET_UINT;
    clcf->types_hash_max_size = NJT_CONF_UNSET_UINT;
    clcf->types_hash_bucket_size = NJT_CONF_UNSET_UINT;

    clcf->open_file_cache = NJT_CONF_UNSET_PTR;
    clcf->open_file_cache_valid = NJT_CONF_UNSET;
    clcf->open_file_cache_min_uses = NJT_CONF_UNSET_UINT;
    clcf->open_file_cache_errors = NJT_CONF_UNSET;
    clcf->open_file_cache_events = NJT_CONF_UNSET;

//add by clb, used for ctrl api module
    clcf->api_limit_excepts = NJT_CONF_UNSET_PTR;
//end add by clb
#if (NJT_HTTP_GZIP)
    clcf->gzip_vary = NJT_CONF_UNSET;
    clcf->gzip_http_version = NJT_CONF_UNSET_UINT;
#if (NJT_PCRE)
    clcf->gzip_disable = NJT_CONF_UNSET_PTR;
#endif
    clcf->gzip_disable_msie6 = 3;
#if (NJT_HTTP_DEGRADATION)
    clcf->gzip_disable_degradation = 3;
#endif
#endif

#if (NJT_HAVE_OPENAT)
    clcf->disable_symlinks = NJT_CONF_UNSET_UINT;
    clcf->disable_symlinks_from = NJT_CONF_UNSET_PTR;
#endif

    return clcf;
}


static njt_str_t  njt_http_core_text_html_type = njt_string("text/html");
static njt_str_t  njt_http_core_image_gif_type = njt_string("image/gif");
static njt_str_t  njt_http_core_image_jpeg_type = njt_string("image/jpeg");

static njt_hash_key_t  njt_http_core_default_types[] = {
    { njt_string("html"), 0, &njt_http_core_text_html_type },
    { njt_string("gif"), 0, &njt_http_core_image_gif_type },
    { njt_string("jpg"), 0, &njt_http_core_image_jpeg_type },
    { njt_null_string, 0, NULL }
};


static char *
njt_http_core_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_core_loc_conf_t *prev = parent;
    njt_http_core_loc_conf_t *conf = child;

    njt_uint_t        i;
    njt_hash_key_t   *type;
    njt_hash_init_t   types_hash;

    if (conf->root.data == NULL) {

        conf->alias = prev->alias;
        conf->root = prev->root;
        conf->root_lengths = prev->root_lengths;
        conf->root_values = prev->root_values;

        if (prev->root.data == NULL) {
            njt_str_set(&conf->root, "html");

            if (njt_conf_full_name(cf->cycle, &conf->root, 0) != NJT_OK) {
                return NJT_CONF_ERROR;
            }
        }
    }

    if (conf->post_action.data == NULL) {
        conf->post_action = prev->post_action;
    }

    njt_conf_merge_uint_value(conf->types_hash_max_size,
                              prev->types_hash_max_size, 1024);

    njt_conf_merge_uint_value(conf->types_hash_bucket_size,
                              prev->types_hash_bucket_size, 64);

    conf->types_hash_bucket_size = njt_align(conf->types_hash_bucket_size,
                                             njt_cacheline_size);

    /*
     * the special handling of the "types" directive in the "http" section
     * to inherit the http's conf->types_hash to all servers
     */

    if (prev->types && prev->types_hash.buckets == NULL) {

        types_hash.hash = &prev->types_hash;
        types_hash.key = njt_hash_key_lc;
        types_hash.max_size = conf->types_hash_max_size;
        types_hash.bucket_size = conf->types_hash_bucket_size;
        types_hash.name = "types_hash";
        types_hash.pool = cf->pool;
        types_hash.temp_pool = NULL;

        if (njt_hash_init(&types_hash, prev->types->elts, prev->types->nelts)
            != NJT_OK)
        {
            return NJT_CONF_ERROR;
        }
    }

    if (conf->types == NULL) {
        conf->types = prev->types;
        conf->types_hash = prev->types_hash;
    }

    if (conf->types == NULL) {
        conf->types = njt_array_create(cf->pool, 3, sizeof(njt_hash_key_t));
        if (conf->types == NULL) {
            return NJT_CONF_ERROR;
        }

        for (i = 0; njt_http_core_default_types[i].key.len; i++) {
            type = njt_array_push(conf->types);
            if (type == NULL) {
                return NJT_CONF_ERROR;
            }

            type->key = njt_http_core_default_types[i].key;
            type->key_hash =
                       njt_hash_key_lc(njt_http_core_default_types[i].key.data,
                                       njt_http_core_default_types[i].key.len);
            type->value = njt_http_core_default_types[i].value;
        }
    }

    if (conf->types_hash.buckets == NULL) {

        types_hash.hash = &conf->types_hash;
        types_hash.key = njt_hash_key_lc;
        types_hash.max_size = conf->types_hash_max_size;
        types_hash.bucket_size = conf->types_hash_bucket_size;
        types_hash.name = "types_hash";
        types_hash.pool = cf->pool;
        types_hash.temp_pool = NULL;

        if (njt_hash_init(&types_hash, conf->types->elts, conf->types->nelts)
            != NJT_OK)
        {
            return NJT_CONF_ERROR;
        }
    }

    if (conf->error_log == NULL) {
        if (prev->error_log) {
            conf->error_log = prev->error_log;
        } else {
            conf->error_log = &cf->cycle->new_log;
        }
    }

    if (conf->error_pages == NULL && prev->error_pages) {
        conf->error_pages = prev->error_pages;
    }

    njt_conf_merge_str_value(conf->default_type,
                              prev->default_type, "text/plain");

    njt_conf_merge_off_value(conf->client_max_body_size,
                              prev->client_max_body_size, 1 * 1024 * 1024);
    njt_conf_merge_size_value(conf->client_body_buffer_size,
                              prev->client_body_buffer_size,
                              (size_t) 2 * njt_pagesize);
    njt_conf_merge_msec_value(conf->client_body_timeout,
                              prev->client_body_timeout, 60000);

    njt_conf_merge_bitmask_value(conf->keepalive_disable,
                              prev->keepalive_disable,
                              (NJT_CONF_BITMASK_SET
                               |NJT_HTTP_KEEPALIVE_DISABLE_MSIE6));
    njt_conf_merge_uint_value(conf->satisfy, prev->satisfy,
                              NJT_HTTP_SATISFY_ALL);
    njt_conf_merge_msec_value(conf->auth_delay, prev->auth_delay, 0);
    njt_conf_merge_uint_value(conf->if_modified_since, prev->if_modified_since,
                              NJT_HTTP_IMS_EXACT);
    njt_conf_merge_uint_value(conf->max_ranges, prev->max_ranges,
                              NJT_MAX_INT32_VALUE);
    njt_conf_merge_uint_value(conf->client_body_in_file_only,
                              prev->client_body_in_file_only,
                              NJT_HTTP_REQUEST_BODY_FILE_OFF);
    njt_conf_merge_value(conf->client_body_in_single_buffer,
                              prev->client_body_in_single_buffer, 0);
    njt_conf_merge_value(conf->internal, prev->internal, 0);
    njt_conf_merge_value(conf->sendfile, prev->sendfile, 0);
    njt_conf_merge_size_value(conf->sendfile_max_chunk,
                              prev->sendfile_max_chunk, 2 * 1024 * 1024);
    njt_conf_merge_size_value(conf->subrequest_output_buffer_size,
                              prev->subrequest_output_buffer_size,
                              (size_t) njt_pagesize);
    njt_conf_merge_value(conf->aio, prev->aio, NJT_HTTP_AIO_OFF);
    njt_conf_merge_value(conf->aio_write, prev->aio_write, 0);
#if (NJT_THREADS)
    njt_conf_merge_ptr_value(conf->thread_pool, prev->thread_pool, NULL);
    njt_conf_merge_ptr_value(conf->thread_pool_value, prev->thread_pool_value,
                             NULL);
#endif
    njt_conf_merge_size_value(conf->read_ahead, prev->read_ahead, 0);
    njt_conf_merge_off_value(conf->directio, prev->directio,
                              NJT_OPEN_FILE_DIRECTIO_OFF);
    njt_conf_merge_off_value(conf->directio_alignment, prev->directio_alignment,
                              512);
    njt_conf_merge_value(conf->tcp_nopush, prev->tcp_nopush, 0);
    njt_conf_merge_value(conf->tcp_nodelay, prev->tcp_nodelay, 1);

    njt_conf_merge_msec_value(conf->send_timeout, prev->send_timeout, 60000);
    njt_conf_merge_size_value(conf->send_lowat, prev->send_lowat, 0);
    njt_conf_merge_size_value(conf->postpone_output, prev->postpone_output,
                              1460);

    njt_conf_merge_ptr_value(conf->limit_rate, prev->limit_rate, NULL);
    njt_conf_merge_ptr_value(conf->limit_rate_after,
                              prev->limit_rate_after, NULL);

    njt_conf_merge_msec_value(conf->keepalive_time,
                              prev->keepalive_time, 3600000);
    njt_conf_merge_msec_value(conf->keepalive_timeout,
                              prev->keepalive_timeout, 75000);
    njt_conf_merge_sec_value(conf->keepalive_header,
                              prev->keepalive_header, 0);
    njt_conf_merge_uint_value(conf->keepalive_requests,
                              prev->keepalive_requests, 1000);
    njt_conf_merge_uint_value(conf->lingering_close,
                              prev->lingering_close, NJT_HTTP_LINGERING_ON);
    njt_conf_merge_msec_value(conf->lingering_time,
                              prev->lingering_time, 30000);
    njt_conf_merge_msec_value(conf->lingering_timeout,
                              prev->lingering_timeout, 5000);
    njt_conf_merge_msec_value(conf->resolver_timeout,
                              prev->resolver_timeout, 30000);

    if (conf->resolver == NULL) {

        if (prev->resolver == NULL) {

            /*
             * create dummy resolver in http {} context
             * to inherit it in all servers
             */

            prev->resolver = njt_resolver_create(cf, NULL, 0);
            if (prev->resolver == NULL) {
                return NJT_CONF_ERROR;
            }
        }

        conf->resolver = prev->resolver;
    }

    if (njt_conf_merge_path_value(cf, &conf->client_body_temp_path,
                              prev->client_body_temp_path,
                              &njt_http_client_temp_path)
        != NJT_OK)
    {
        return NJT_CONF_ERROR;
    }

    njt_conf_merge_value(conf->reset_timedout_connection,
                              prev->reset_timedout_connection, 0);
    njt_conf_merge_value(conf->absolute_redirect,
                              prev->absolute_redirect, 1);
    njt_conf_merge_value(conf->server_name_in_redirect,
                              prev->server_name_in_redirect, 0);
    njt_conf_merge_value(conf->port_in_redirect, prev->port_in_redirect, 1);
    njt_conf_merge_value(conf->msie_padding, prev->msie_padding, 1);
    njt_conf_merge_value(conf->msie_refresh, prev->msie_refresh, 0);
    njt_conf_merge_value(conf->log_not_found, prev->log_not_found, 1);
    njt_conf_merge_value(conf->log_subrequest, prev->log_subrequest, 0);
    njt_conf_merge_value(conf->recursive_error_pages,
                              prev->recursive_error_pages, 0);
    njt_conf_merge_value(conf->chunked_transfer_encoding,
                              prev->chunked_transfer_encoding, 1);
    njt_conf_merge_value(conf->etag, prev->etag, 1);

    njt_conf_merge_uint_value(conf->server_tokens, prev->server_tokens,
                              NJT_HTTP_SERVER_TOKENS_ON);

    njt_conf_merge_ptr_value(conf->open_file_cache,
                              prev->open_file_cache, NULL);

    njt_conf_merge_sec_value(conf->open_file_cache_valid,
                              prev->open_file_cache_valid, 60);

    njt_conf_merge_uint_value(conf->open_file_cache_min_uses,
                              prev->open_file_cache_min_uses, 1);

    njt_conf_merge_sec_value(conf->open_file_cache_errors,
                              prev->open_file_cache_errors, 0);

    njt_conf_merge_sec_value(conf->open_file_cache_events,
                              prev->open_file_cache_events, 0);
#if (NJT_HTTP_GZIP)

    njt_conf_merge_value(conf->gzip_vary, prev->gzip_vary, 0);
    njt_conf_merge_uint_value(conf->gzip_http_version, prev->gzip_http_version,
                              NJT_HTTP_VERSION_11);
    njt_conf_merge_bitmask_value(conf->gzip_proxied, prev->gzip_proxied,
                              (NJT_CONF_BITMASK_SET|NJT_HTTP_GZIP_PROXIED_OFF));

#if (NJT_PCRE)
    njt_conf_merge_ptr_value(conf->gzip_disable, prev->gzip_disable, NULL);
#endif

    if (conf->gzip_disable_msie6 == 3) {
        conf->gzip_disable_msie6 =
            (prev->gzip_disable_msie6 == 3) ? 0 : prev->gzip_disable_msie6;
    }

#if (NJT_HTTP_DEGRADATION)

    if (conf->gzip_disable_degradation == 3) {
        conf->gzip_disable_degradation =
            (prev->gzip_disable_degradation == 3) ?
                 0 : prev->gzip_disable_degradation;
    }

#endif
#endif

#if (NJT_HAVE_OPENAT)
    njt_conf_merge_uint_value(conf->disable_symlinks, prev->disable_symlinks,
                              NJT_DISABLE_SYMLINKS_OFF);
    njt_conf_merge_ptr_value(conf->disable_symlinks_from,
                             prev->disable_symlinks_from, NULL);
#endif

    return NJT_CONF_OK;
}


static char *
njt_http_core_listen(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_core_srv_conf_t *cscf = conf;

    njt_str_t              *value, size;
    njt_url_t               u;
    njt_uint_t              n, i;
    njt_http_listen_opt_t   lsopt;

    cscf->listen = 1;
    value = cf->args->elts;

    njt_memzero(&u, sizeof(njt_url_t));

    u.url = value[1];
    u.listen = 1;
    u.default_port = 80;

    if (njt_parse_url(cf->pool, &u) != NJT_OK) {
        if (u.err) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "%s in \"%V\" of the \"listen\" directive",
                               u.err, &u.url);
        }

        return NJT_CONF_ERROR;
    }

    njt_memzero(&lsopt, sizeof(njt_http_listen_opt_t));

    lsopt.backlog = NJT_LISTEN_BACKLOG;
    lsopt.type = SOCK_STREAM;
    lsopt.rcvbuf = -1;
    lsopt.sndbuf = -1;
#if (NJT_HAVE_SETFIB)
    lsopt.setfib = -1;
#endif
#if (NJT_HAVE_TCP_FASTOPEN)
    lsopt.fastopen = -1;
#endif
#if (NJT_HAVE_INET6)
    lsopt.ipv6only = 1;
#endif

    for (n = 2; n < cf->args->nelts; n++) {

        if (njt_strcmp(value[n].data, "default_server") == 0
            || njt_strcmp(value[n].data, "default") == 0)
        {
            lsopt.default_server = 1;
            continue;
        }

        if (njt_strcmp(value[n].data, "bind") == 0) {
            lsopt.set = 1;
            lsopt.bind = 1;
            continue;
        }

#if (NJT_HAVE_SETFIB)
        if (njt_strncmp(value[n].data, "setfib=", 7) == 0) {
            lsopt.setfib = njt_atoi(value[n].data + 7, value[n].len - 7);
            lsopt.set = 1;
            lsopt.bind = 1;

            if (lsopt.setfib == NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid setfib \"%V\"", &value[n]);
                return NJT_CONF_ERROR;
            }

            continue;
        }
#endif

#if (NJT_HAVE_TCP_FASTOPEN)
        if (njt_strncmp(value[n].data, "fastopen=", 9) == 0) {
            lsopt.fastopen = njt_atoi(value[n].data + 9, value[n].len - 9);
            lsopt.set = 1;
            lsopt.bind = 1;

            if (lsopt.fastopen == NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid fastopen \"%V\"", &value[n]);
                return NJT_CONF_ERROR;
            }

            continue;
        }
#endif

        if (njt_strncmp(value[n].data, "backlog=", 8) == 0) {
            lsopt.backlog = njt_atoi(value[n].data + 8, value[n].len - 8);
            lsopt.set = 1;
            lsopt.bind = 1;

            if (lsopt.backlog == NJT_ERROR || lsopt.backlog == 0) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid backlog \"%V\"", &value[n]);
                return NJT_CONF_ERROR;
            }

            continue;
        }

        if (njt_strncmp(value[n].data, "rcvbuf=", 7) == 0) {
            size.len = value[n].len - 7;
            size.data = value[n].data + 7;

            lsopt.rcvbuf = njt_parse_size(&size);
            lsopt.set = 1;
            lsopt.bind = 1;

            if (lsopt.rcvbuf == NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid rcvbuf \"%V\"", &value[n]);
                return NJT_CONF_ERROR;
            }

            continue;
        }

        if (njt_strncmp(value[n].data, "sndbuf=", 7) == 0) {
            size.len = value[n].len - 7;
            size.data = value[n].data + 7;

            lsopt.sndbuf = njt_parse_size(&size);
            lsopt.set = 1;
            lsopt.bind = 1;

            if (lsopt.sndbuf == NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid sndbuf \"%V\"", &value[n]);
                return NJT_CONF_ERROR;
            }

            continue;
        }

        if (njt_strncmp(value[n].data, "accept_filter=", 14) == 0) {
#if (NJT_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
            lsopt.accept_filter = (char *) &value[n].data[14];
            lsopt.set = 1;
            lsopt.bind = 1;
#else
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "accept filters \"%V\" are not supported "
                               "on this platform, ignored",
                               &value[n]);
#endif
            continue;
        }

        if (njt_strcmp(value[n].data, "deferred") == 0) {
#if (NJT_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
            lsopt.deferred_accept = 1;
            lsopt.set = 1;
            lsopt.bind = 1;
#else
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "the deferred accept is not supported "
                               "on this platform, ignored");
#endif
            continue;
        }

        if (njt_strncmp(value[n].data, "ipv6only=o", 10) == 0) {
#if (NJT_HAVE_INET6 && defined IPV6_V6ONLY)
            if (njt_strcmp(&value[n].data[10], "n") == 0) {
                lsopt.ipv6only = 1;

            } else if (njt_strcmp(&value[n].data[10], "ff") == 0) {
                lsopt.ipv6only = 0;

            } else {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid ipv6only flags \"%s\"",
                                   &value[n].data[9]);
                return NJT_CONF_ERROR;
            }

            lsopt.set = 1;
            lsopt.bind = 1;

            continue;
#else
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "ipv6only is not supported "
                               "on this platform");
            return NJT_CONF_ERROR;
#endif
        }

        if (njt_strcmp(value[n].data, "reuseport") == 0) {
#if (NJT_HAVE_REUSEPORT)
            lsopt.reuseport = 1;
            lsopt.set = 1;
            lsopt.bind = 1;
#else
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "reuseport is not supported "
                               "on this platform, ignored");
#endif
            continue;
        }

        if (njt_strcmp(value[n].data, "ssl") == 0) {
#if (NJT_HTTP_SSL)
            lsopt.ssl = 1;
            continue;
#else
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "the \"ssl\" parameter requires "
                               "njt_http_ssl_module");
            return NJT_CONF_ERROR;
#endif
        }

        if (njt_strcmp(value[n].data, "http2") == 0) {
#if (NJT_HTTP_V2)
            njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                               "the \"listen ... http2\" directive "
                               "is deprecated, use "
                               "the \"http2\" directive instead");

            lsopt.http2 = 1;
            continue;
#else
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "the \"http2\" parameter requires "
                               "njt_http_v2_module");
            return NJT_CONF_ERROR;
#endif
        }

 
        if (njt_strcmp(value[n].data, "http3") == 0) {
#if (NJT_HTTP_V3)
            njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                               "the \"http3\" parameter is deprecated, "
                               "use \"quic\" parameter instead");
            lsopt.quic = 1;
            lsopt.http3 = 1;
            lsopt.type = SOCK_DGRAM;
            continue;
#else
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "the \"http3\" parameter requires "
                               "njt_http_v3_module");
            return NJT_CONF_ERROR;
#endif
        }

        if (njt_strcmp(value[n].data, "quic") == 0) {
#if (NJT_HTTP_V3)
            lsopt.quic = 1;
            lsopt.type = SOCK_DGRAM;
            continue;
#else
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "the \"quic\" parameter requires "
                               "njt_http_v3_module");
            return NJT_CONF_ERROR;
#endif
        }
        if (njt_strncmp(value[n].data, "so_keepalive=", 13) == 0) {

            if (njt_strcmp(&value[n].data[13], "on") == 0) {
                lsopt.so_keepalive = 1;

            } else if (njt_strcmp(&value[n].data[13], "off") == 0) {
                lsopt.so_keepalive = 2;

            } else {

#if (NJT_HAVE_KEEPALIVE_TUNABLE)
                u_char     *p, *end;
                njt_str_t   s;

                end = value[n].data + value[n].len;
                s.data = value[n].data + 13;

                p = njt_strlchr(s.data, end, ':');
                if (p == NULL) {
                    p = end;
                }

                if (p > s.data) {
                    s.len = p - s.data;

                    lsopt.tcp_keepidle = njt_parse_time(&s, 1);
                    if (lsopt.tcp_keepidle == (time_t) NJT_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                p = njt_strlchr(s.data, end, ':');
                if (p == NULL) {
                    p = end;
                }

                if (p > s.data) {
                    s.len = p - s.data;

                    lsopt.tcp_keepintvl = njt_parse_time(&s, 1);
                    if (lsopt.tcp_keepintvl == (time_t) NJT_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                if (s.data < end) {
                    s.len = end - s.data;

                    lsopt.tcp_keepcnt = njt_atoi(s.data, s.len);
                    if (lsopt.tcp_keepcnt == NJT_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                if (lsopt.tcp_keepidle == 0 && lsopt.tcp_keepintvl == 0
                    && lsopt.tcp_keepcnt == 0)
                {
                    goto invalid_so_keepalive;
                }

                lsopt.so_keepalive = 1;

#else

                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "the \"so_keepalive\" parameter accepts "
                                   "only \"on\" or \"off\" on this platform");
                return NJT_CONF_ERROR;

#endif
            }

            lsopt.set = 1;
            lsopt.bind = 1;

            continue;

#if (NJT_HAVE_KEEPALIVE_TUNABLE)
        invalid_so_keepalive:

            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid so_keepalive value: \"%s\"",
                               &value[n].data[13]);
            return NJT_CONF_ERROR;
#endif
        }

        if (njt_strcmp(value[n].data, "proxy_protocol") == 0) {
            lsopt.proxy_protocol = 1;
            continue;
        }

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[n]);
        return NJT_CONF_ERROR;
    }

#if (NJT_HTTP_V3)

    if (lsopt.quic) {
#if (NJT_HTTP_SSL)
        if (lsopt.ssl) {
            return "\"ssl\" parameter is incompatible with \"quic\"";
        }
#endif

#if (NJT_HTTP_V2)
        if (lsopt.http2) {
            return "\"http2\" parameter is incompatible with \"quic\"";
        }
#endif

        if (lsopt.proxy_protocol) {
            return "\"proxy_protocol\" parameter is incompatible with \"quic\"";
        }
    }

#endif

    for (n = 0; n < u.naddrs; n++) {

        for (i = 0; i < n; i++) {
            if (njt_cmp_sockaddr(u.addrs[n].sockaddr, u.addrs[n].socklen,
                                 u.addrs[i].sockaddr, u.addrs[i].socklen, 1)
                == NJT_OK)
            {
                goto next;
            }
        }

        lsopt.sockaddr = u.addrs[n].sockaddr;
        lsopt.socklen = u.addrs[n].socklen;
        lsopt.addr_text = u.addrs[n].name;
        lsopt.wildcard = njt_inet_wildcard(lsopt.sockaddr);

        if (njt_http_add_listen(cf, cscf, &lsopt) != NJT_OK) {
            return NJT_CONF_ERROR;
        }

    next: 
        continue;
    }

    return NJT_CONF_OK;
}


static char *
njt_http_core_server_name(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_core_srv_conf_t *cscf = conf;

    u_char                   ch;
    njt_str_t               *value,*ori_value;
    njt_uint_t               i;
    njt_http_server_name_t  *sn;

    value = cf->args->elts;
    ori_value = cf->ori_args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        ch = value[i].data[0];

        if ((ch == '*' && (value[i].len < 3 || value[i].data[1] != '.'))
            || (ch == '.' && value[i].len < 2))
        {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "server name \"%V\" is invalid", &value[i]);
            return NJT_CONF_ERROR;
        }

        if (njt_strchr(value[i].data, '/')) {
            njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                               "server name \"%V\" has suspicious symbols",
                               &value[i]);
        }
#if (NJT_HTTP_DYNAMIC_LOC) 
         if(cf->dynamic == 1  && cscf->server_names.nelts >= 1) {
             njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "dynamic server only support one name!");
            return NJT_CONF_ERROR;
        }
#endif

        sn = njt_array_push(&cscf->server_names);
        if (sn == NULL) {
            return NJT_CONF_ERROR;
        }

#if (NJT_PCRE)
        sn->regex = NULL;
#endif
        sn->server = cscf;

        if (njt_strcasecmp(value[i].data, (u_char *) "$hostname") == 0) {
            sn->name = cf->cycle->hostname;
#if (NJT_HTTP_DYNAMIC_LOC) 
        sn->full_name = sn->name;
#endif
        } else {
            sn->name = value[i];
#if (NJT_HTTP_DYNAMIC_LOC) 
        sn->full_name = ori_value[i];
#endif
        }

        if (value[i].data[0] != '~') {
            njt_strlow(sn->name.data, sn->name.data, sn->name.len);
            continue;
        }

#if (NJT_PCRE)
        {
        u_char               *p;
        njt_regex_compile_t   rc;
        u_char                errstr[NJT_MAX_CONF_ERRSTR];

        if (value[i].len == 1) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "empty regex in server name \"%V\"", &value[i]);
            return NJT_CONF_ERROR;
        }
#if (NJT_HTTP_DYNAMIC_LOC) 
        sn->full_name = ori_value[i];
#endif
        value[i].len--;
        value[i].data++;

        njt_memzero(&rc, sizeof(njt_regex_compile_t));

        rc.pattern = value[i];
        rc.err.len = NJT_MAX_CONF_ERRSTR;
        rc.err.data = errstr;

        for (p = value[i].data; p < value[i].data + value[i].len; p++) {
            if (*p >= 'A' && *p <= 'Z') {
                rc.options = NJT_REGEX_CASELESS;
                break;
            }
        }

        sn->regex = njt_http_regex_compile(cf, &rc);
        if (sn->regex == NULL) {
            return NJT_CONF_ERROR;
        }

        sn->name = value[i];
        cscf->captures = (rc.captures > 0);
        }
#else
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "using regex \"%V\" "
                           "requires PCRE library", &value[i]);

        return NJT_CONF_ERROR;
#endif
    }

    return NJT_CONF_OK;
}


static char *
njt_http_core_root(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_core_loc_conf_t *clcf = conf;

    njt_str_t                  *value;
    njt_int_t                   alias;
    njt_uint_t                  n;
    njt_http_script_compile_t   sc;

    alias = (cmd->name.len == sizeof("alias") - 1) ? 1 : 0;

    if (clcf->root.data) {

        if ((clcf->alias != 0) == alias) {
            return "is duplicate";
        }

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "\"%V\" directive is duplicate, "
                           "\"%s\" directive was specified earlier",
                           &cmd->name, clcf->alias ? "alias" : "root");

        return NJT_CONF_ERROR;
    }

    if (clcf->named && alias) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "the \"alias\" directive cannot be used "
                           "inside the named location");

        return NJT_CONF_ERROR;
    }

    value = cf->args->elts;

    if (njt_strstr(value[1].data, "$document_root")
        || njt_strstr(value[1].data, "${document_root}"))
    {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "the $document_root variable cannot be used "
                           "in the \"%V\" directive",
                           &cmd->name);

        return NJT_CONF_ERROR;
    }

    if (njt_strstr(value[1].data, "$realpath_root")
        || njt_strstr(value[1].data, "${realpath_root}"))
    {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "the $realpath_root variable cannot be used "
                           "in the \"%V\" directive",
                           &cmd->name);

        return NJT_CONF_ERROR;
    }

    clcf->alias = alias ? clcf->name.len : 0;
    clcf->root = value[1];

    if (!alias && clcf->root.len > 0
        && clcf->root.data[clcf->root.len - 1] == '/')
    {
        clcf->root.len--;
    }

    if (clcf->root.data[0] != '$') {
        if (njt_conf_full_name(cf->cycle, &clcf->root, 0) != NJT_OK) {
            return NJT_CONF_ERROR;
        }
    }

    n = njt_http_script_variables_count(&clcf->root);

    njt_memzero(&sc, sizeof(njt_http_script_compile_t));
    sc.variables = n;

#if (NJT_PCRE)
    if (alias && clcf->regex) {
        clcf->alias = NJT_MAX_SIZE_T_VALUE;
        n = 1;
    }
#endif

    if (n) {
        sc.cf = cf;
        sc.source = &clcf->root;
        sc.lengths = &clcf->root_lengths;
        sc.values = &clcf->root_values;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (njt_http_script_compile(&sc) != NJT_OK) {
            return NJT_CONF_ERROR;
        }
    }

    return NJT_CONF_OK;
}


static njt_http_method_name_t  njt_methods_names[] = {
    { (u_char *) "GET",       (uint32_t) ~NJT_HTTP_GET },
    { (u_char *) "HEAD",      (uint32_t) ~NJT_HTTP_HEAD },
    { (u_char *) "POST",      (uint32_t) ~NJT_HTTP_POST },
    { (u_char *) "PUT",       (uint32_t) ~NJT_HTTP_PUT },
    { (u_char *) "DELETE",    (uint32_t) ~NJT_HTTP_DELETE },
    { (u_char *) "MKCOL",     (uint32_t) ~NJT_HTTP_MKCOL },
    { (u_char *) "COPY",      (uint32_t) ~NJT_HTTP_COPY },
    { (u_char *) "MOVE",      (uint32_t) ~NJT_HTTP_MOVE },
    { (u_char *) "OPTIONS",   (uint32_t) ~NJT_HTTP_OPTIONS },
    { (u_char *) "PROPFIND",  (uint32_t) ~NJT_HTTP_PROPFIND },
    { (u_char *) "PROPPATCH", (uint32_t) ~NJT_HTTP_PROPPATCH },
    { (u_char *) "LOCK",      (uint32_t) ~NJT_HTTP_LOCK },
    { (u_char *) "UNLOCK",    (uint32_t) ~NJT_HTTP_UNLOCK },
    { (u_char *) "PATCH",     (uint32_t) ~NJT_HTTP_PATCH },
    { NULL, 0 }
};


static char *
njt_http_core_limit_except(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_core_loc_conf_t *pclcf = conf;

    char                      *rv;
    void                      *mconf;
    njt_str_t                 *value;
    njt_uint_t                 i;
    njt_conf_t                 save;
    njt_http_module_t         *module;
    njt_http_conf_ctx_t       *ctx, *pctx;
    njt_http_method_name_t    *name;
    njt_http_core_loc_conf_t  *clcf;

    if (pclcf->limit_except) {
        return "is duplicate";
    }

    pclcf->limit_except = 0xffffffff;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        for (name = njt_methods_names; name->name; name++) {

            if (njt_strcasecmp(value[i].data, name->name) == 0) {
                pclcf->limit_except &= name->method;
                goto next;
            }
        }

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid method \"%V\"", &value[i]);
        return NJT_CONF_ERROR;

    next:
        continue;
    }

    if (!(pclcf->limit_except & NJT_HTTP_GET)) {
        pclcf->limit_except &= (uint32_t) ~NJT_HTTP_HEAD;
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
        njt_destroy_pool(new_pool);
        return NJT_CONF_ERROR;
    }
    cf->pool = new_pool;
    cf->temp_pool = new_pool;
#endif
    //end
    ctx = njt_pcalloc(cf->pool, sizeof(njt_http_conf_ctx_t));
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }
    // ctx->type = 4;
    pctx = cf->ctx;
    ctx->main_conf = pctx->main_conf;
    ctx->srv_conf = pctx->srv_conf;

    ctx->loc_conf = njt_pcalloc(cf->pool, sizeof(void *) * njt_http_max_module);
    if (ctx->loc_conf == NULL) {
        return NJT_CONF_ERROR;
    }

    for (i = 0; cf->cycle->modules[i]; i++) {
        if (cf->cycle->modules[i]->type != NJT_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[i]->ctx;

        if (module->create_loc_conf) {

            mconf = module->create_loc_conf(cf);
            if (mconf == NULL) {
                return NJT_CONF_ERROR;
            }

            ctx->loc_conf[cf->cycle->modules[i]->ctx_index] = mconf;
        }

    }


    clcf = ctx->loc_conf[njt_http_core_module.ctx_index];
    pclcf->limit_except_loc_conf = ctx->loc_conf;
    clcf->loc_conf = ctx->loc_conf;
    clcf->name = pclcf->name;
    clcf->noname = 1;
    clcf->lmt_excpt = 1;

    if(cf->dynamic != 1){
		if (njt_http_add_location_pre_process(cf,&pclcf->locations,pclcf->pool) != NJT_OK || njt_http_add_location(cf, &pclcf->locations, clcf) != NJT_OK) {
		    return NJT_CONF_ERROR;
	    } 
    } else {
			 clcf->dynamic_status = 1;  // 1 
	}
    if (njt_http_add_location_pre_process(cf,&pclcf->old_locations,pclcf->pool) != NJT_OK || njt_http_add_location(cf, &pclcf->old_locations, clcf) != NJT_OK) {
		    return NJT_CONF_ERROR;
	}

    save = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NJT_HTTP_LMT_CONF;
    // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
    cf->pool = new_pool;
    cf->temp_pool = new_pool;
#endif
    //end
    rv = njt_conf_parse(cf, NULL);
    // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
    cf->pool = old_pool;
    cf->temp_pool = old_temp_pool;
#endif
    //end


    *cf = save;

    return rv;
}

//add by clb, used for ctrl api module
static char *
njt_http_core_api_limit_except(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_core_loc_conf_t *pclcf = conf;

    char                      *rv;
    void                      *mconf;
    njt_str_t                 *value;
    njt_uint_t                 i;
    njt_conf_t                 save;
    njt_http_module_t         *module;
    njt_http_conf_ctx_t       *ctx, *pctx;
    njt_http_method_name_t    *name;
    njt_http_core_loc_conf_t  *clcf;
    njt_http_api_limit_except_t *limit_except;

    if (pclcf->api_limit_excepts == NJT_CONF_UNSET_PTR) {
        pclcf->api_limit_excepts = njt_array_create(cf->pool, 2,
                                              sizeof(njt_http_api_limit_except_t));
        if (pclcf->api_limit_excepts == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    //push item
    limit_except = njt_array_push(pclcf->api_limit_excepts);
    if (limit_except == NULL) {
        return NJT_CONF_ERROR;
    }

    limit_except->api_limit_except = 0xffffffff;

    value = cf->args->elts;
    limit_except->module_key = value[1];

    for (i = 2; i < cf->args->nelts; i++) {
        for (name = njt_methods_names; name->name; name++) {

            if (njt_strcasecmp(value[i].data, name->name) == 0) {
                limit_except->api_limit_except &= name->method;
                goto next;
            }
        }

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid method \"%V\"", &value[i]);
        return NJT_CONF_ERROR;

    next:
        continue;
    }

    if (!(limit_except->api_limit_except & NJT_HTTP_GET)) {
        limit_except->api_limit_except &= (uint32_t) ~NJT_HTTP_HEAD;
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
        njt_destroy_pool(new_pool);
        return NJT_CONF_ERROR;
    }
    cf->pool = new_pool;
    cf->temp_pool = new_pool;
#endif
    //end
    ctx = njt_pcalloc(cf->pool, sizeof(njt_http_conf_ctx_t));
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }
    // ctx->type = 4;
    pctx = cf->ctx;
    ctx->main_conf = pctx->main_conf;
    ctx->srv_conf = pctx->srv_conf;

    ctx->loc_conf = njt_pcalloc(cf->pool, sizeof(void *) * njt_http_max_module);
    if (ctx->loc_conf == NULL) {
        return NJT_CONF_ERROR;
    }

    for (i = 0; cf->cycle->modules[i]; i++) {
        if (cf->cycle->modules[i]->type != NJT_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[i]->ctx;

        if (module->create_loc_conf) {

            mconf = module->create_loc_conf(cf);
            if (mconf == NULL) {
                return NJT_CONF_ERROR;
            }

            ctx->loc_conf[cf->cycle->modules[i]->ctx_index] = mconf;
        }

    }

    clcf = ctx->loc_conf[njt_http_core_module.ctx_index];
    limit_except->limit_except_loc_conf = ctx->loc_conf;
    clcf->loc_conf = ctx->loc_conf;
    clcf->name = pclcf->name;
    clcf->noname = 1;
    clcf->lmt_excpt = 1;

    if(cf->dynamic != 1){
		if (njt_http_add_location_pre_process(cf,&pclcf->locations,pclcf->pool) != NJT_OK || njt_http_add_location(cf, &pclcf->locations, clcf) != NJT_OK) {
		    return NJT_CONF_ERROR;
	    } 
    } else {
			 clcf->dynamic_status = 1;  // 1 
	}
    if (njt_http_add_location_pre_process(cf,&pclcf->old_locations,pclcf->pool) != NJT_OK || njt_http_add_location(cf, &pclcf->old_locations, clcf) != NJT_OK) {
		    return NJT_CONF_ERROR;
	}

    save = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NJT_HTTP_LMT_CONF;
    // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
    cf->pool = new_pool;
    cf->temp_pool = new_pool;
#endif
    //end
    rv = njt_conf_parse(cf, NULL);
    // by ChengXu
#if (NJT_HTTP_DYNAMIC_LOC)
    cf->pool = old_pool;
    cf->temp_pool = old_temp_pool;
#endif
    //end


    *cf = save;

    return rv;
}
//end add by clb

static char *
njt_http_core_set_aio(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_core_loc_conf_t *clcf = conf;

    njt_str_t  *value;

    if (clcf->aio != NJT_CONF_UNSET) {
        return "is duplicate";
    }

#if (NJT_THREADS)
    clcf->thread_pool = NULL;
    clcf->thread_pool_value = NULL;
#endif

    value = cf->args->elts;

    if (njt_strcmp(value[1].data, "off") == 0) {
        clcf->aio = NJT_HTTP_AIO_OFF;
        return NJT_CONF_OK;
    }

    if (njt_strcmp(value[1].data, "on") == 0) {
#if (NJT_HAVE_FILE_AIO)
        clcf->aio = NJT_HTTP_AIO_ON;
        return NJT_CONF_OK;
#else
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "\"aio on\" "
                           "is unsupported on this platform");
        return NJT_CONF_ERROR;
#endif
    }

    if (njt_strncmp(value[1].data, "threads", 7) == 0
        && (value[1].len == 7 || value[1].data[7] == '='))
    {
#if (NJT_THREADS)
        njt_str_t                          name;
        njt_thread_pool_t                 *tp;
        njt_http_complex_value_t           cv;
        njt_http_compile_complex_value_t   ccv;

        clcf->aio = NJT_HTTP_AIO_THREADS;

        if (value[1].len >= 8) {
            name.len = value[1].len - 8;
            name.data = value[1].data + 8;

            njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &name;
            ccv.complex_value = &cv;

            if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
                return NJT_CONF_ERROR;
            }

            if (cv.lengths != NULL) {
                clcf->thread_pool_value = njt_palloc(cf->pool,
                                    sizeof(njt_http_complex_value_t));
                if (clcf->thread_pool_value == NULL) {
                    return NJT_CONF_ERROR;
                }

                *clcf->thread_pool_value = cv;

                return NJT_CONF_OK;
            }

            tp = njt_thread_pool_add(cf, &name);

        } else {
            tp = njt_thread_pool_add(cf, NULL);
        }

        if (tp == NULL) {
            return NJT_CONF_ERROR;
        }

        clcf->thread_pool = tp;

        return NJT_CONF_OK;
#else
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "\"aio threads\" "
                           "is unsupported on this platform");
        return NJT_CONF_ERROR;
#endif
    }

    return "invalid value";
}


static char *
njt_http_core_directio(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_core_loc_conf_t *clcf = conf;

    njt_str_t  *value;

    if (clcf->directio != NJT_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (njt_strcmp(value[1].data, "off") == 0) {
        clcf->directio = NJT_OPEN_FILE_DIRECTIO_OFF;
        return NJT_CONF_OK;
    }

    clcf->directio = njt_parse_offset(&value[1]);
    if (clcf->directio == (off_t) NJT_ERROR) {
        return "invalid value";
    }

    return NJT_CONF_OK;
}


static char *
njt_http_core_error_page(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_core_loc_conf_t *clcf = conf;

    u_char                            *p;
    njt_int_t                          overwrite;
    njt_str_t                         *value, uri, args;
    njt_uint_t                         i, n;
    njt_http_err_page_t               *err;
    njt_http_complex_value_t           cv;
    njt_http_compile_complex_value_t   ccv;

    if (clcf->error_pages == NULL) {
        clcf->error_pages = njt_array_create(cf->pool, 4,
                                             sizeof(njt_http_err_page_t));
        if (clcf->error_pages == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    i = cf->args->nelts - 2;

    if (value[i].data[0] == '=') {
        if (i == 1) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[i]);
            return NJT_CONF_ERROR;
        }

        if (value[i].len > 1) {
            overwrite = njt_atoi(&value[i].data[1], value[i].len - 1);

            if (overwrite == NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid value \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

        } else {
            overwrite = 0;
        }

        n = 2;

    } else {
        overwrite = -1;
        n = 1;
    }

    uri = value[cf->args->nelts - 1];

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &uri;
    ccv.complex_value = &cv;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    njt_str_null(&args);

    if (cv.lengths == NULL && uri.len && uri.data[0] == '/') {
        p = (u_char *) njt_strchr(uri.data, '?');

        if (p) {
            cv.value.len = p - uri.data;
            cv.value.data = uri.data;
            p++;
            args.len = (uri.data + uri.len) - p;
            args.data = p;
        }
    }

    for (i = 1; i < cf->args->nelts - n; i++) {
        err = njt_array_push(clcf->error_pages);
        if (err == NULL) {
            return NJT_CONF_ERROR;
        }

        err->status = njt_atoi(value[i].data, value[i].len);

        if (err->status == NJT_ERROR || err->status == 499) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[i]);
            return NJT_CONF_ERROR;
        }

        if (err->status < 300 || err->status > 599) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "value \"%V\" must be between 300 and 599",
                               &value[i]);
            return NJT_CONF_ERROR;
        }

        err->overwrite = overwrite;

        if (overwrite == -1) {
            switch (err->status) {
                case NJT_HTTP_TO_HTTPS:
                case NJT_HTTPS_CERT_ERROR:
                case NJT_HTTPS_NO_CERT:
                case NJT_HTTP_REQUEST_HEADER_TOO_LARGE:
                    err->overwrite = NJT_HTTP_BAD_REQUEST;
            }
        }

        err->value = cv;
        err->args = args;
    }

    return NJT_CONF_OK;
}


static char *
njt_http_core_open_file_cache(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_core_loc_conf_t *clcf = conf;

    time_t       inactive;
    njt_str_t   *value, s;
    njt_int_t    max;
    njt_uint_t   i;

    if (clcf->open_file_cache != NJT_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    max = 0;
    inactive = 60;

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

        if (njt_strcmp(value[i].data, "off") == 0) {

            clcf->open_file_cache = NULL;

            continue;
        }

    failed:

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid \"open_file_cache\" parameter \"%V\"",
                           &value[i]);
        return NJT_CONF_ERROR;
    }

    if (clcf->open_file_cache == NULL) {
        return NJT_CONF_OK;
    }

    if (max == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                        "\"open_file_cache\" must have the \"max\" parameter");
        return NJT_CONF_ERROR;
    }

    clcf->open_file_cache = njt_open_file_cache_init(cf->pool, max, inactive);
    if (clcf->open_file_cache) {
        return NJT_CONF_OK;
    }

    return NJT_CONF_ERROR;
}


static char *
njt_http_core_error_log(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_core_loc_conf_t *clcf = conf;

    return njt_log_set_log(cf, &clcf->error_log);
}


static char *
njt_http_core_keepalive(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_core_loc_conf_t *clcf = conf;

    njt_str_t  *value;

    if (clcf->keepalive_timeout != NJT_CONF_UNSET_MSEC) {
        return "is duplicate";
    }

    value = cf->args->elts;

    clcf->keepalive_timeout = njt_parse_time(&value[1], 0);

    if (clcf->keepalive_timeout == (njt_msec_t) NJT_ERROR) {
        return "invalid value";
    }

    if (cf->args->nelts == 2) {
        return NJT_CONF_OK;
    }

    clcf->keepalive_header = njt_parse_time(&value[2], 1);

    if (clcf->keepalive_header == (time_t) NJT_ERROR) {
        return "invalid value";
    }

    return NJT_CONF_OK;
}


static char *
njt_http_core_internal(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_core_loc_conf_t *clcf = conf;

    if (clcf->internal != NJT_CONF_UNSET) {
        return "is duplicate";
    }

    clcf->internal = 1;

    return NJT_CONF_OK;
}


static char *
njt_http_core_resolver(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_core_loc_conf_t  *clcf = conf;

    njt_str_t  *value;

    if (clcf->resolver) {
        return "is duplicate";
    }

    value = cf->args->elts;

    clcf->resolver = njt_resolver_create(cf, &value[1], cf->args->nelts - 1);
    if (clcf->resolver == NULL) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


#if (NJT_HTTP_GZIP)

static char *
njt_http_gzip_disable(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_core_loc_conf_t  *clcf = conf;

#if (NJT_PCRE)

    njt_str_t            *value;
    njt_uint_t            i;
    njt_regex_elt_t      *re;
    njt_regex_compile_t   rc;
    u_char                errstr[NJT_MAX_CONF_ERRSTR];

    if (clcf->gzip_disable == NJT_CONF_UNSET_PTR) {
        clcf->gzip_disable = njt_array_create(cf->pool, 2,
                                              sizeof(njt_regex_elt_t));
        if (clcf->gzip_disable == NULL) {
            return NJT_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    njt_memzero(&rc, sizeof(njt_regex_compile_t));

    rc.pool = cf->pool;
    rc.err.len = NJT_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    for (i = 1; i < cf->args->nelts; i++) {

        if (njt_strcmp(value[i].data, "msie6") == 0) {
            clcf->gzip_disable_msie6 = 1;
            continue;
        }

#if (NJT_HTTP_DEGRADATION)

        if (njt_strcmp(value[i].data, "degradation") == 0) {
            clcf->gzip_disable_degradation = 1;
            continue;
        }

#endif

        re = njt_array_push(clcf->gzip_disable);
        if (re == NULL) {
            return NJT_CONF_ERROR;
        }

        rc.pattern = value[i];
        rc.options = NJT_REGEX_CASELESS;

        if (njt_regex_compile(&rc) != NJT_OK) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "%V", &rc.err);
            return NJT_CONF_ERROR;
        }

        re->regex = rc.regex;
        re->name = value[i].data;
    }

    return NJT_CONF_OK;

#else
    njt_str_t   *value;
    njt_uint_t   i;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (njt_strcmp(value[i].data, "msie6") == 0) {
            clcf->gzip_disable_msie6 = 1;
            continue;
        }

#if (NJT_HTTP_DEGRADATION)

        if (njt_strcmp(value[i].data, "degradation") == 0) {
            clcf->gzip_disable_degradation = 1;
            continue;
        }

#endif

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "without PCRE library \"gzip_disable\" supports "
                           "builtin \"msie6\" and \"degradation\" mask only");

        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;

#endif
}

#endif


#if (NJT_HAVE_OPENAT)

static char *
njt_http_disable_symlinks(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_http_core_loc_conf_t *clcf = conf;

    njt_str_t                         *value;
    njt_uint_t                         i;
    njt_http_compile_complex_value_t   ccv;

    if (clcf->disable_symlinks != NJT_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (njt_strcmp(value[i].data, "off") == 0) {
            clcf->disable_symlinks = NJT_DISABLE_SYMLINKS_OFF;
            continue;
        }

        if (njt_strcmp(value[i].data, "if_not_owner") == 0) {
            clcf->disable_symlinks = NJT_DISABLE_SYMLINKS_NOTOWNER;
            continue;
        }

        if (njt_strcmp(value[i].data, "on") == 0) {
            clcf->disable_symlinks = NJT_DISABLE_SYMLINKS_ON;
            continue;
        }

        if (njt_strncmp(value[i].data, "from=", 5) == 0) {
            value[i].len -= 5;
            value[i].data += 5;

            njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &value[i];
            ccv.complex_value = njt_palloc(cf->pool,
                                           sizeof(njt_http_complex_value_t));
            if (ccv.complex_value == NULL) {
                return NJT_CONF_ERROR;
            }

            if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
                return NJT_CONF_ERROR;
            }

            clcf->disable_symlinks_from = ccv.complex_value;

            continue;
        }

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NJT_CONF_ERROR;
    }

    if (clcf->disable_symlinks == NJT_CONF_UNSET_UINT) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"off\", \"on\" "
                           "or \"if_not_owner\" parameter",
                           &cmd->name);
        return NJT_CONF_ERROR;
    }

    if (cf->args->nelts == 2) {
        clcf->disable_symlinks_from = NULL;
        return NJT_CONF_OK;
    }

    if (clcf->disable_symlinks_from == NJT_CONF_UNSET_PTR) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "duplicate parameters \"%V %V\"",
                           &value[1], &value[2]);
        return NJT_CONF_ERROR;
    }

    if (clcf->disable_symlinks == NJT_DISABLE_SYMLINKS_OFF) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "\"from=\" cannot be used with \"off\" parameter");
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}

#endif


static char *
njt_http_core_lowat_check(njt_conf_t *cf, void *post, void *data)
{
#if (NJT_FREEBSD)
    ssize_t *np = data;

    if ((u_long) *np >= njt_freebsd_net_inet_tcp_sendspace) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "\"send_lowat\" must be less than %d "
                           "(sysctl net.inet.tcp.sendspace)",
                           njt_freebsd_net_inet_tcp_sendspace);

        return NJT_CONF_ERROR;
    }

#elif !(NJT_HAVE_SO_SNDLOWAT)
    ssize_t *np = data;

    njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                       "\"send_lowat\" is not supported, ignored");

    *np = 0;

#endif

    return NJT_CONF_OK;
}


static char *
njt_http_core_pool_size(njt_conf_t *cf, void *post, void *data)
{
    size_t *sp = data;

    if (*sp < NJT_MIN_POOL_SIZE) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "the pool size must be no less than %uz",
                           NJT_MIN_POOL_SIZE);
        return NJT_CONF_ERROR;
    }

    if (*sp % NJT_POOL_ALIGNMENT) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "the pool size must be a multiple of %uz",
                           NJT_POOL_ALIGNMENT);
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}

//(  ((a=1 && b=1)|| c=1) && (d=1 || c=1) || d=1 )
//(  ((a=1 && b=1)|| c=1) || d=1)
//( a=b && (c=d))


//a=b && (c=d)

njt_int_t njt_http_core_if_location(njt_conf_t *cf,njt_http_core_loc_conf_t  *pclcf){


	njt_http_script_if_code_t    *if_code,*if_end_code;
	 njt_http_rewrite_loc_conf_t  *nlcf, **rlcf;
	
	// u_char                       *elts;
	njt_http_rewrite_loc_conf_t  *lcf  = njt_pcalloc(cf->pool, sizeof(njt_http_rewrite_loc_conf_t));
    if (lcf == NULL) {
        return NJT_ERROR;
    }

    lcf->stack_size = 10;
    lcf->log = NJT_CONF_UNSET;
    lcf->uninitialized_variable_warn = 1;

	


    if (njt_http_rewrite_if_condition(cf, lcf) != NJT_CONF_OK) {
        return NJT_ERROR;
    }

    if_code = njt_array_push_n(lcf->codes, sizeof(njt_http_script_if_code_t)*2); //by zyg,add end code
    if (if_code == NULL) {
        return NJT_ERROR;
    }

    if_code->code = njt_http_script_if_code;
    if_code->next = sizeof(njt_http_script_if_code_t);
    if_end_code = if_code + 1;
    njt_memzero(if_end_code,sizeof(njt_http_script_if_code_t));

    if_code->loc_conf = NULL; 


    /* the inner directives must be compiled to the same code array */

    nlcf = pclcf->loc_conf[njt_http_rewrite_module.ctx_index]; //存放到loc 上。
	if(nlcf->mul_codes == NULL) {
	   nlcf->mul_codes = njt_array_create(cf->pool,1, sizeof(njt_http_rewrite_loc_conf_t  *));
	   if(nlcf->mul_codes == NULL){
		return NJT_ERROR;
	   }
	} 
	rlcf = njt_array_push(nlcf->mul_codes);
	*rlcf = lcf;
	return NJT_OK;
}

static njt_int_t njt_http_core_split_if(njt_conf_t *cf,njt_str_t src){
    
    //njt_snprintf(new_src.data,new_src.len,"if (%V %V \"%V\") {",&name,&oper,&value);
   njt_conf_read_memory_token(cf,src);	
   return NJT_OK;
}


static char *
njt_http_core_if_location_parse(njt_conf_t *cf,njt_http_core_loc_conf_t  *pclcf){
#if (NJT_HTTP_DYNAMIC_LOC)
    //u_char* index;
    //njt_uint_t len =0,i;
    njt_str_t  command; //*value;
    loc_parse_ctx_t* ctx;
    loc_parse_node_t *loc_exp_dyn_parse_tree, *root;
    njt_int_t rc;
    njt_int_t   r;

    command.len  = pclcf->full_name.len + 1;
    command.data = njt_pcalloc(pclcf->pool,command.len);
    if (command.data == NULL){
        return NJT_CONF_ERROR;
    }
    njt_memcpy(command.data,pclcf->full_name.data,pclcf->full_name.len);
    /*
    value = cf->ori_args->elts;
    for(i = 1; i < cf->ori_args->nelts; i++){
        len += value[i].len+1;
    }
    index = njt_pcalloc(pclcf->pool,len+1);
    if (index == NULL){
        return NJT_CONF_ERROR;
    }
    command.data = index;
    for(i = 1; i < cf->ori_args->nelts; i++){
        njt_memcpy(index,value[i].data,value[i].len);
        index += value[i].len;

        *index = (u_char)' ';
        ++index;
        
    }
    command.len = len + 1;
    */
    yylex_destroy();
    yy_scan_string((char *)command.data);
    root = NULL;
    r = yyparse(&root);
    if(r != NJT_OK || root == NULL) {
    	free_bison_tree(root);
	return NJT_CONF_ERROR;
    }
    rc = njt_http_core_cp_loc_parse_tree(root,pclcf->pool,&loc_exp_dyn_parse_tree);  
    if(rc != NJT_OK || loc_exp_dyn_parse_tree == NULL) {
    	free_bison_tree(root);
	return NJT_CONF_ERROR;
    }
    free_bison_tree(root);
    ctx = njt_http_core_loc_parse_tree_ctx(loc_exp_dyn_parse_tree,pclcf->pool);
    if(ctx == NULL){
	return NJT_CONF_ERROR;
    }
    pclcf->if_location_root = ctx;
    return njt_http_core_if_location_array_new(cf,ctx,pclcf);
    //return njt_http_core_if_location_array(cf,&command,pclcf,step,oper,dir);
#endif
}
/*
static njt_int_t 
njt_http_core_if_location_get_args(njt_str_t old,njt_str_t *name,njt_str_t *oper,njt_str_t *value) {
  njt_uint_t  i;
  njt_int_t  space_num;
 
  space_num = 0;
  name->data = old.data;
  name->len  = old.len;
  for(i=0; i < old.len; i++){
    if(old.data[i] == ' ') {
	space_num++;
    }
    if(space_num == 1 && oper->data == NULL) {
	name->len = i;
	oper->data = old.data + i + 1;
    } else if (space_num == 2) {
	oper->len = old.data + i - oper->data;
	value->data = old.data + i + 1;
	value->len = old.len - i -1;
	break;
    }
  }
  if(space_num == 1) {
        oper->len = old.data + old.len - oper->data;
        if(oper->len != 0) {
                space_num++;
        }
  }
  return space_num;
}*/

static char *
njt_http_core_if_location_array_new(njt_conf_t *cf, loc_parse_ctx_t * parse_ctx,njt_http_core_loc_conf_t  *pclcf){  // -1, 0 与，1 或
  


  njt_int_t  i;
  //njt_http_core_loc_conf_t **ploc;
  njt_str_t  new_src,old,name,oper,value;
  njt_int_t rc;
  u_char *pdata, *p;

   for(i=0; i < parse_ctx->count; i++) {
   	njt_str_null(&name);
   	njt_str_null(&oper);
   	njt_str_null(&value);

	pdata = (u_char *)parse_ctx->exps[i];
	old.len = njt_strlen(pdata);
	old.data = pdata;

	new_src.len = old.len + 10;
	new_src.data = njt_pcalloc(cf->pool,new_src.len);
	
	
    p = njt_snprintf(new_src.data,new_src.len,"if (%V){ ",&old);
    new_src.len = p - new_src.data;
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "njt_http_core_run_location idx=%d, %V",i,&new_src);
	//njt_http_core_if_location_get_args(old,&name,&oper,&value);
    /*
	if(num <= 1) {
		njt_snprintf(new_src.data,new_src.len,"if (%V){",&name);
	} else if(num == 2) {
		if(value.len > 0 && value.data != NULL) {
                        njt_snprintf(new_src.data,new_src.len,"if (%V %V \"%V\"){",&name,&oper,&value);
                } else {
                        njt_snprintf(new_src.data,new_src.len,"if (%V \"%V\"){",&name,&oper);
                }
	}*/

	njt_http_core_split_if(cf,new_src);
	rc = njt_http_core_if_location(cf,pclcf);
	if (rc  != NJT_OK) {
		return NJT_CONF_ERROR;
	}
   }
   return NJT_CONF_OK;

}


static njt_int_t
njt_http_core_run_location(njt_http_request_t *r,njt_http_core_loc_conf_t     *clcf){

  njt_int_t ret;
  njt_http_if_location_request req;
  njt_uint_t stack_size = 10;
  loc_parse_ctx_t* ctx = clcf->if_location_root;
  req.r = r;
  req.stack_size = stack_size;
  req.clcf = clcf;


    req.e = njt_pcalloc(r->pool, sizeof(njt_http_script_engine_t));
    if (req.e == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    req.e->sp = njt_pcalloc(r->pool,
                        stack_size * sizeof(njt_http_variable_value_t));
    if (req.e->sp == NULL) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

  ret = eval_loc_parse_tree((loc_parse_node_t *)ctx->root,njt_http_core_run_location_callback,&req);
  return (ret == 1?NJT_OK:NJT_ERROR);
}
 int
njt_http_core_run_location_callback(void *ctx,void *pdata)
{
    njt_uint_t                    i;
    njt_http_script_code_pt       code;
    njt_http_rewrite_loc_conf_t  *plcf,*lcf;
    njt_http_rewrite_loc_conf_t  **new_lcf;
    //njt_uint_t                     ret;
    njt_http_variable_value_t     *pbuf;
    loc_exp_t *exp  = ctx;
    //u_char *o_ip;

    njt_http_if_location_request  *request = pdata;
    njt_http_request_t *r = request->r;
    njt_http_core_loc_conf_t     *clcf =  request->clcf;
    
    i = exp->idx;


    plcf = clcf->loc_conf[njt_http_rewrite_module.ctx_index];
    plcf->uninitialized_variable_warn = 1;
    plcf->log = NJT_CONF_UNSET;   
    if (plcf->mul_codes == NULL) {
        return NJT_DECLINED;
    }
     //zyg todo
    //ret = 0;
    pbuf = request->e->sp;
    new_lcf = plcf->mul_codes->elts;
    if(plcf->mul_codes->nelts > i){
	    lcf = new_lcf[i];
	    njt_memzero(request->e,sizeof(njt_http_script_engine_t));
	    njt_memzero(pbuf,request->stack_size * sizeof(njt_http_variable_value_t));
	    request->e->sp = pbuf;
	    request->e->ip = lcf->codes->elts;
	    request->e->request = r;
	    request->e->quote = 1;
	    request->e->log = plcf->log;
	    request->e->status = NJT_DECLINED;
	    request->e->ret = 1;
	    //o_ip = NULL;
	    //while (*(uintptr_t *) request->e->ip && o_ip != request->e->ip) {
	    while (*(uintptr_t *) request->e->ip) {
	//	o_ip = request->e->ip;
		code = *(njt_http_script_code_pt *) request->e->ip;
		code(request->e);
	    }
	    lcf->ret = request->e->ret;
	    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "njt_http_core_run_location_callback idx=%d, %s,ret=%d",exp->idx,exp->exp,lcf->ret);
	    return lcf->ret;
    }
    return NJT_DECLINED;
}

njt_int_t njt_http_core_cp_loc_parse_tree(loc_parse_node_t * root, njt_pool_t   *pool,loc_parse_node_t ** new_root)
{
   loc_parse_node_t *new_node;
   loc_exp_t               *loc_exp;
   njt_int_t  rc;
   if(root == NULL) {
	*new_root = NULL;
	return NJT_OK;
    }
    new_node = njt_pcalloc(pool, sizeof(loc_parse_node_t));
    if(new_node == NULL) {
	return NJT_ERROR;
    }
    new_node->node_type = root->node_type;
    *new_root = new_node;
    switch (root->node_type)
    {
    case LOC_EXPRESSION:
         loc_exp = njt_pcalloc(pool, sizeof(loc_exp_t));
	 if(loc_exp == NULL) {
        	return NJT_ERROR;
    	 }
	 loc_exp->idx = root->loc_exp->idx;
	 loc_exp->exp = njt_pcalloc(pool,njt_strlen(root->loc_exp->exp) + 1);
	 if(loc_exp->exp == NULL) {
		return NJT_ERROR;
	 }
	 njt_memcpy(loc_exp->exp,root->loc_exp->exp,njt_strlen(root->loc_exp->exp));
	 new_node->loc_exp = loc_exp;
         return NJT_OK;
    case BOOL_OP_OR:
    case BOOL_OP_AND:
          rc = njt_http_core_cp_loc_parse_tree(root->left,pool,&new_node->left);
	  if(rc != NJT_OK) {
		return rc;
	  }
          rc = njt_http_core_cp_loc_parse_tree(root->right,pool,&new_node->right);
	  if(rc != NJT_OK) {
                return rc;
          }
	  return NJT_OK;
        break;
    default:
        break;
    }
    return NJT_ERROR;
}
loc_parse_ctx_t*
njt_http_core_loc_parse_tree_ctx(loc_parse_node_t *root,njt_pool_t   *pool){
    char** exps;
    loc_parse_ctx_t* ctx;
    int idx = 0;
    int count = 0;
    loc_parse_node_t** stack;

    // get exp count in ast tree;
    count = get_exp_counts(root);
    exps = njt_pcalloc(pool,sizeof(char *)*count);
    if (!exps) {
        return NULL;
    }
    ctx = njt_pcalloc(pool,sizeof(loc_parse_ctx_t));
    if (!ctx) {
        return NULL;
    }
    stack = njt_alloc(sizeof(loc_parse_node_t*)*count,njt_cycle->log); //malloc(sizeof(loc_parse_node_t*)*count);
    if (!stack) {
        return NULL;
    }

    loc_parse_node_t* current = root;
    int stack_size = 0;

    // printf("start traverse tree \n");
    while (current != NULL || stack_size != 0) {
        if (current != NULL) {
            stack[stack_size] = current;
            stack_size++;
            // printf("stack_size: %d\n", stack_size);
            current = current->left;
        } else {
            current = stack[stack_size-1];
            stack_size--;
            // printf("stack_size: %d\n", stack_size);
            // printf("type: %d\n", current->node_type);
            if (current->node_type == LOC_EXPRESSION) {
                if(idx != current->loc_exp->idx) {
                    printf("idx: %d,  idx_exp: %d \n", idx, current->loc_exp->idx);
                }
		 njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "njt_http_core_loc_parse_tree_ctx run idx=%d, %s",current->loc_exp->idx,current->loc_exp->exp);
                // printf("correct: idx: %d,  idx_exp: %d \n", idx, current->loc_exp->idx);
                exps[idx] = current->loc_exp->exp;
                idx++;
            }
            current = current->right;
        }
    }

    free(stack);

    ctx->root = root;
    ctx->exps = exps;
    ctx->count = count;

    return ctx;
}
njt_http_location_queue_t *njt_http_find_location(njt_str_t name, njt_queue_t *locations) {
    njt_queue_t *x;
    njt_http_location_queue_t *lq;
    njt_http_core_loc_conf_t *clcf;
    if(locations != NULL) {
	    for (x = njt_queue_head(locations);
		 x != njt_queue_sentinel(locations);
		 x = njt_queue_next(x)) {
		lq = (njt_http_location_queue_t *) x;
		clcf = lq->exact ? lq->exact : lq->inclusive;
        if (njt_http_location_full_name_cmp(clcf->full_name,name) == 0) {
        return lq;
        }
		
	    }
    }
    return NULL;
}
 njt_int_t njt_http_add_location_pre_process(njt_conf_t *cf,njt_queue_t **locations,njt_pool_t *pool){
 
    njt_http_location_queue_t *tmp_queue;
    if (*locations != NULL) {
	return NJT_OK;
    }
	if(pool == NULL) {
	   pool = cf->cycle->pool;
	}
        *locations = njt_palloc(pool,                        //cf->temp_pool  by zyg 
                                sizeof(njt_http_location_queue_t));
        if (*locations == NULL) {
            return NJT_ERROR;
        }

        //add by clb
#if (NJT_HTTP_DYNAMIC_LOC)
        tmp_queue = (njt_http_location_queue_t *)*locations;
        tmp_queue->parent_pool = pool;
#endif
        //end
        njt_queue_init(*locations);
	return NJT_OK;
}
void njt_http_server_delete_dyn_var(njt_http_core_srv_conf_t *cscf) {

	njt_uint_t                 rf = 0,rf2 = 0;
    njt_http_core_loc_conf_t *clcf = cscf->ctx->loc_conf[njt_http_core_module.ctx_index];
    njt_http_location_delete_dyn_var_run(clcf,&rf);

	njt_http_rewrite_loc_conf_t  *rlcf = cscf->ctx->loc_conf[njt_http_rewrite_module.ctx_index];  //njt_http_conf_get_module_loc_conf(clcf,njt_http_rewrite_module); //clcf->loc_conf[njt_http_core_module.ctx_index])
	rf2 = njt_http_rewrite_delete_dyn_var(rlcf);
	if(rf == 1 || rf2 == 1) {
		njt_http_refresh_variables_keys();
	}
}


njt_int_t njt_http_del_variable(njt_http_variable_t *fv) {
        if(fv == NULL) {
            return NJT_ERROR;
        }
        fv->ref_count--;
		if( (fv->ref_count == 0 && fv->flags &  NJT_HTTP_DYN_VAR) ){
			njt_http_set_del_variable_flag(fv);
			njt_http_set_del_variables_keys_flag(fv);
			return NJT_OK;
		}
        return NJT_ERROR;
}
