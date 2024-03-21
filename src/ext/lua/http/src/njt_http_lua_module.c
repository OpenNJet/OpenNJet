
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_http_lua_directive.h"
#include "njt_http_lua_capturefilter.h"
#include "njt_http_lua_contentby.h"
#include "njt_http_lua_server_rewriteby.h"
#include "njt_http_lua_rewriteby.h"
#include "njt_http_lua_accessby.h"
#include "njt_http_lua_logby.h"
#include "njt_http_lua_util.h"
#include "njt_http_lua_headerfilterby.h"
#include "njt_http_lua_bodyfilterby.h"
#include "njt_http_lua_initby.h"
#include "njt_http_lua_initworkerby.h"
#include "njt_http_lua_exitworkerby.h"
#include "njt_http_lua_probe.h"
#include "njt_http_lua_semaphore.h"
#include "njt_http_lua_balancer.h"
#include "njt_http_lua_ssl_client_helloby.h"
#include "njt_http_lua_ssl_certby.h"
#include "njt_http_lua_ssl_session_storeby.h"
#include "njt_http_lua_ssl_session_fetchby.h"
#include "njt_http_lua_headers.h"
#include "njt_http_lua_headers_out.h"
#include "njt_http_lua_pipe.h"


static void *njt_http_lua_create_main_conf(njt_conf_t *cf);
static char *njt_http_lua_init_main_conf(njt_conf_t *cf, void *conf);
static void *njt_http_lua_create_srv_conf(njt_conf_t *cf);
static char *njt_http_lua_merge_srv_conf(njt_conf_t *cf, void *parent,
    void *child);
static void *njt_http_lua_create_loc_conf(njt_conf_t *cf);

static char *njt_http_lua_merge_loc_conf(njt_conf_t *cf, void *parent,
    void *child);
static njt_int_t njt_http_lua_init(njt_conf_t *cf);
static char *njt_http_lua_lowat_check(njt_conf_t *cf, void *post, void *data);
#if (NJT_HTTP_SSL)
static njt_int_t njt_http_lua_merge_ssl(njt_conf_t *cf,
    njt_http_lua_loc_conf_t *conf, njt_http_lua_loc_conf_t *prev);
static njt_int_t njt_http_lua_set_ssl(njt_conf_t *cf,
    njt_http_lua_loc_conf_t *llcf);
#if (njet_version >= 1019004)
static char *njt_http_lua_ssl_conf_command_check(njt_conf_t *cf, void *post,
    void *data);
#endif
#endif
static char *njt_http_lua_malloc_trim(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
#if (NJT_PCRE2)
extern void njt_http_lua_regex_cleanup(void *data);
#endif


static njt_conf_post_t  njt_http_lua_lowat_post =
    { njt_http_lua_lowat_check };


static volatile njt_cycle_t  *njt_http_lua_prev_cycle = NULL;


#if (NJT_HTTP_SSL)

static njt_conf_bitmask_t  njt_http_lua_ssl_protocols[] = {
    { njt_string("SSLv2"), NJT_SSL_SSLv2 },
    { njt_string("SSLv3"), NJT_SSL_SSLv3 },
    { njt_string("TLSv1"), NJT_SSL_TLSv1 },
    { njt_string("TLSv1.1"), NJT_SSL_TLSv1_1 },
    { njt_string("TLSv1.2"), NJT_SSL_TLSv1_2 },
#ifdef NJT_SSL_TLSv1_3
    { njt_string("TLSv1.3"), NJT_SSL_TLSv1_3 },
#endif
    { njt_null_string, 0 }
};

#if (njet_version >= 1019004)
static njt_conf_post_t  njt_http_lua_ssl_conf_command_post =
    { njt_http_lua_ssl_conf_command_check };
#endif

#endif


static njt_command_t njt_http_lua_cmds[] = {

    { njt_string("lua_load_resty_core"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_FLAG,
      njt_http_lua_load_resty_core,
      NJT_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { njt_string("lua_thread_cache_max_entries"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_MAIN_CONF_OFFSET,
      offsetof(njt_http_lua_main_conf_t, lua_thread_cache_max_entries),
      NULL },

    { njt_string("lua_max_running_timers"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_MAIN_CONF_OFFSET,
      offsetof(njt_http_lua_main_conf_t, max_running_timers),
      NULL },

    { njt_string("lua_max_pending_timers"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_MAIN_CONF_OFFSET,
      offsetof(njt_http_lua_main_conf_t, max_pending_timers),
      NULL },

    { njt_string("lua_shared_dict"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE2,
      njt_http_lua_shared_dict,
      0,
      0,
      NULL },

    { njt_string("lua_capture_error_log"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE1,
      njt_http_lua_capture_error_log,
      0,
      0,
      NULL },

    { njt_string("lua_sa_restart"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_MAIN_CONF_OFFSET,
      offsetof(njt_http_lua_main_conf_t, set_sa_restart),
      NULL },

    { njt_string("lua_regex_cache_max_entries"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE1,
      njt_http_lua_regex_cache_max_entries,
      NJT_HTTP_MAIN_CONF_OFFSET,
#if (NJT_PCRE)
      offsetof(njt_http_lua_main_conf_t, regex_cache_max_entries),
#else
      0,
#endif
      NULL },

    { njt_string("lua_regex_match_limit"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE1,
      njt_http_lua_regex_match_limit,
      NJT_HTTP_MAIN_CONF_OFFSET,
#if (NJT_PCRE)
      offsetof(njt_http_lua_main_conf_t, regex_match_limit),
#else
      0,
#endif
      NULL },

    { njt_string("lua_package_cpath"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE1,
      njt_http_lua_package_cpath,
      NJT_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { njt_string("lua_package_path"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE1,
      njt_http_lua_package_path,
      NJT_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { njt_string("lua_code_cache"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_FLAG,
      njt_http_lua_code_cache,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_lua_loc_conf_t, enable_code_cache),
      NULL },

    { njt_string("lua_need_request_body"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_lua_loc_conf_t, force_read_body),
      NULL },

    { njt_string("lua_transform_underscores_in_response_headers"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_lua_loc_conf_t, transform_underscores_in_resp_headers),
      NULL },

     { njt_string("lua_socket_log_errors"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_lua_loc_conf_t, log_socket_errors),
      NULL },

    { njt_string("init_by_lua_block"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_BLOCK|NJT_CONF_NOARGS,
      njt_http_lua_init_by_lua_block,
      NJT_HTTP_MAIN_CONF_OFFSET,
      0,
      (void *) njt_http_lua_init_by_inline },

    { njt_string("init_by_lua"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE1,
      njt_http_lua_init_by_lua,
      NJT_HTTP_MAIN_CONF_OFFSET,
      0,
      (void *) njt_http_lua_init_by_inline },

    { njt_string("init_by_lua_file"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE1,
      njt_http_lua_init_by_lua,
      NJT_HTTP_MAIN_CONF_OFFSET,
      0,
      (void *) njt_http_lua_init_by_file },

    { njt_string("init_worker_by_lua_block"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_BLOCK|NJT_CONF_NOARGS,
      njt_http_lua_init_worker_by_lua_block,
      NJT_HTTP_MAIN_CONF_OFFSET,
      0,
      (void *) njt_http_lua_init_worker_by_inline },

    { njt_string("init_worker_by_lua"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE1,
      njt_http_lua_init_worker_by_lua,
      NJT_HTTP_MAIN_CONF_OFFSET,
      0,
      (void *) njt_http_lua_init_worker_by_inline },

    { njt_string("init_worker_by_lua_file"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE1,
      njt_http_lua_init_worker_by_lua,
      NJT_HTTP_MAIN_CONF_OFFSET,
      0,
      (void *) njt_http_lua_init_worker_by_file },

    { njt_string("exit_worker_by_lua_block"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_BLOCK|NJT_CONF_NOARGS,
      njt_http_lua_exit_worker_by_lua_block,
      NJT_HTTP_MAIN_CONF_OFFSET,
      0,
      (void *) njt_http_lua_exit_worker_by_inline },

    { njt_string("exit_worker_by_lua_file"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE1,
      njt_http_lua_exit_worker_by_lua,
      NJT_HTTP_MAIN_CONF_OFFSET,
      0,
      (void *) njt_http_lua_exit_worker_by_file },

#if defined(NDK) && NDK
    /* set_by_lua_block $res { inline Lua code } */
    { njt_string("set_by_lua_block"),
      NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                       |NJT_CONF_TAKE1|NJT_CONF_BLOCK,
      njt_http_lua_set_by_lua_block,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) njt_http_lua_filter_set_by_lua_inline },

    /* set_by_lua $res <inline script> [$arg1 [$arg2 [...]]] */
    { njt_string("set_by_lua"),
      NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                       |NJT_CONF_2MORE,
      njt_http_lua_set_by_lua,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) njt_http_lua_filter_set_by_lua_inline },

    /* set_by_lua_file $res rel/or/abs/path/to/script [$arg1 [$arg2 [..]]] */
    { njt_string("set_by_lua_file"),
      NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                       |NJT_CONF_2MORE,
      njt_http_lua_set_by_lua_file,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) njt_http_lua_filter_set_by_lua_file },
#endif

    /* server_rewrite_by_lua_block { <inline script> } */
    { njt_string("server_rewrite_by_lua_block"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_BLOCK|NJT_CONF_NOARGS,
        njt_http_lua_server_rewrite_by_lua_block,
        NJT_HTTP_SRV_CONF_OFFSET,
        0,
        (void *) njt_http_lua_server_rewrite_handler_inline },

    /* server_rewrite_by_lua_file filename; */
    { njt_string("server_rewrite_by_lua_file"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
        njt_http_lua_server_rewrite_by_lua,
        NJT_HTTP_SRV_CONF_OFFSET,
        0,
        (void *) njt_http_lua_server_rewrite_handler_file },

    /* rewrite_by_lua "<inline script>" */
    { njt_string("rewrite_by_lua"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_TAKE1,
      njt_http_lua_rewrite_by_lua,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) njt_http_lua_rewrite_handler_inline },

    /* rewrite_by_lua_block { <inline script> } */
    { njt_string("rewrite_by_lua_block"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_BLOCK|NJT_CONF_NOARGS,
      njt_http_lua_rewrite_by_lua_block,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) njt_http_lua_rewrite_handler_inline },

    /* access_by_lua "<inline script>" */
    { njt_string("access_by_lua"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_TAKE1,
      njt_http_lua_access_by_lua,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) njt_http_lua_access_handler_inline },

    /* access_by_lua_block { <inline script> } */
    { njt_string("access_by_lua_block"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_BLOCK|NJT_CONF_NOARGS,
      njt_http_lua_access_by_lua_block,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) njt_http_lua_access_handler_inline },

    /* content_by_lua "<inline script>" */
    { njt_string("content_by_lua"),
      NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE1,
      njt_http_lua_content_by_lua,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) njt_http_lua_content_handler_inline },

    /* content_by_lua_block { <inline script> } */
    { njt_string("content_by_lua_block"),
      NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_BLOCK|NJT_CONF_NOARGS,
      njt_http_lua_content_by_lua_block,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) njt_http_lua_content_handler_inline },

    /* log_by_lua <inline script> */
    { njt_string("log_by_lua"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_TAKE1,
      njt_http_lua_log_by_lua,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) njt_http_lua_log_handler_inline },

    /* log_by_lua_block { <inline script> } */
    { njt_string("log_by_lua_block"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_BLOCK|NJT_CONF_NOARGS,
      njt_http_lua_log_by_lua_block,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) njt_http_lua_log_handler_inline },

    { njt_string("rewrite_by_lua_file"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_TAKE1,
      njt_http_lua_rewrite_by_lua,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) njt_http_lua_rewrite_handler_file },

    { njt_string("rewrite_by_lua_no_postpone"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_MAIN_CONF_OFFSET,
      offsetof(njt_http_lua_main_conf_t, postponed_to_rewrite_phase_end),
      NULL },

    { njt_string("access_by_lua_file"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_TAKE1,
      njt_http_lua_access_by_lua,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) njt_http_lua_access_handler_file },

    { njt_string("access_by_lua_no_postpone"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_MAIN_CONF_OFFSET,
      offsetof(njt_http_lua_main_conf_t, postponed_to_access_phase_end),
      NULL },

    /* content_by_lua_file rel/or/abs/path/to/script */
    { njt_string("content_by_lua_file"),
      NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE1,
      njt_http_lua_content_by_lua,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) njt_http_lua_content_handler_file },

    { njt_string("log_by_lua_file"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_TAKE1,
      njt_http_lua_log_by_lua,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) njt_http_lua_log_handler_file },

    /* header_filter_by_lua <inline script> */
    { njt_string("header_filter_by_lua"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_TAKE1,
      njt_http_lua_header_filter_by_lua,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) njt_http_lua_header_filter_inline },

    /* header_filter_by_lua_block { <inline script> } */
    { njt_string("header_filter_by_lua_block"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_BLOCK|NJT_CONF_NOARGS,
      njt_http_lua_header_filter_by_lua_block,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) njt_http_lua_header_filter_inline },

    { njt_string("header_filter_by_lua_file"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_TAKE1,
      njt_http_lua_header_filter_by_lua,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) njt_http_lua_header_filter_file },

    { njt_string("body_filter_by_lua"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_TAKE1,
      njt_http_lua_body_filter_by_lua,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) njt_http_lua_body_filter_inline },

    /* body_filter_by_lua_block { <inline script> } */
    { njt_string("body_filter_by_lua_block"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_BLOCK|NJT_CONF_NOARGS,
      njt_http_lua_body_filter_by_lua_block,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) njt_http_lua_body_filter_inline },

    { njt_string("body_filter_by_lua_file"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_TAKE1,
      njt_http_lua_body_filter_by_lua,
      NJT_HTTP_LOC_CONF_OFFSET,
      0,
      (void *) njt_http_lua_body_filter_file },

    { njt_string("balancer_by_lua_block"),
      NJT_HTTP_UPS_CONF|NJT_CONF_BLOCK|NJT_CONF_NOARGS,
      njt_http_lua_balancer_by_lua_block,
      NJT_HTTP_SRV_CONF_OFFSET,
      0,
      (void *) njt_http_lua_balancer_handler_inline },

    { njt_string("balancer_by_lua_file"),
      NJT_HTTP_UPS_CONF|NJT_CONF_TAKE1,
      njt_http_lua_balancer_by_lua,
      NJT_HTTP_SRV_CONF_OFFSET,
      0,
      (void *) njt_http_lua_balancer_handler_file },

    { njt_string("lua_socket_keepalive_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF
          |NJT_HTTP_LIF_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_lua_loc_conf_t, keepalive_timeout),
      NULL },

    { njt_string("lua_socket_connect_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF
          |NJT_HTTP_LIF_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_lua_loc_conf_t, connect_timeout),
      NULL },

    { njt_string("lua_socket_send_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF
          |NJT_HTTP_LIF_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_lua_loc_conf_t, send_timeout),
      NULL },

    { njt_string("lua_socket_send_lowat"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF
          |NJT_HTTP_LIF_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_lua_loc_conf_t, send_lowat),
      &njt_http_lua_lowat_post },

    { njt_string("lua_socket_buffer_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF
          |NJT_HTTP_LIF_CONF|NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_lua_loc_conf_t, buffer_size),
      NULL },

    { njt_string("lua_socket_pool_size"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF
                        |NJT_HTTP_LIF_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_lua_loc_conf_t, pool_size),
      NULL },

    { njt_string("lua_socket_read_timeout"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF
          |NJT_HTTP_LIF_CONF|NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_lua_loc_conf_t, read_timeout),
      NULL },

    { njt_string("lua_http10_buffering"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_lua_loc_conf_t, http10_buffering),
      NULL },

    { njt_string("lua_check_client_abort"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_lua_loc_conf_t, check_client_abort),
      NULL },

    { njt_string("lua_use_default_type"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
                        |NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_lua_loc_conf_t, use_default_type),
      NULL },

#if (NJT_HTTP_SSL)

    { njt_string("lua_ssl_protocols"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_lua_loc_conf_t, ssl_protocols),
      &njt_http_lua_ssl_protocols },

    { njt_string("lua_ssl_ciphers"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_lua_loc_conf_t, ssl_ciphers),
      NULL },

    { njt_string("ssl_client_hello_by_lua_block"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_BLOCK|NJT_CONF_NOARGS,
      njt_http_lua_ssl_client_hello_by_lua_block,
      NJT_HTTP_SRV_CONF_OFFSET,
      0,
      (void *) njt_http_lua_ssl_client_hello_handler_inline },

    { njt_string("ssl_client_hello_by_lua_file"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_http_lua_ssl_client_hello_by_lua,
      NJT_HTTP_SRV_CONF_OFFSET,
      0,
      (void *) njt_http_lua_ssl_client_hello_handler_file },

    { njt_string("ssl_certificate_by_lua_block"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_BLOCK|NJT_CONF_NOARGS,
      njt_http_lua_ssl_cert_by_lua_block,
      NJT_HTTP_SRV_CONF_OFFSET,
      0,
      (void *) njt_http_lua_ssl_cert_handler_inline },

    { njt_string("ssl_certificate_by_lua_file"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_TAKE1,
      njt_http_lua_ssl_cert_by_lua,
      NJT_HTTP_SRV_CONF_OFFSET,
      0,
      (void *) njt_http_lua_ssl_cert_handler_file },

    { njt_string("ssl_session_store_by_lua_block"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_BLOCK|NJT_CONF_NOARGS,
      njt_http_lua_ssl_sess_store_by_lua_block,
      NJT_HTTP_SRV_CONF_OFFSET,
      0,
      (void *) njt_http_lua_ssl_sess_store_handler_inline },

    { njt_string("ssl_session_store_by_lua_file"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE1,
      njt_http_lua_ssl_sess_store_by_lua,
      NJT_HTTP_SRV_CONF_OFFSET,
      0,
      (void *) njt_http_lua_ssl_sess_store_handler_file },

    { njt_string("ssl_session_fetch_by_lua_block"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_BLOCK|NJT_CONF_NOARGS,
      njt_http_lua_ssl_sess_fetch_by_lua_block,
      NJT_HTTP_SRV_CONF_OFFSET,
      0,
      (void *) njt_http_lua_ssl_sess_fetch_handler_inline },

    { njt_string("ssl_session_fetch_by_lua_file"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE1,
      njt_http_lua_ssl_sess_fetch_by_lua,
      NJT_HTTP_SRV_CONF_OFFSET,
      0,
      (void *) njt_http_lua_ssl_sess_fetch_handler_file },

    { njt_string("lua_ssl_verify_depth"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_lua_loc_conf_t, ssl_verify_depth),
      NULL },

    { njt_string("lua_ssl_certificate"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_array_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_lua_loc_conf_t, ssl_certificates),
      NULL },

    { njt_string("lua_ssl_certificate_key"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_array_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_lua_loc_conf_t, ssl_certificate_keys),
      NULL },

    { njt_string("lua_ssl_trusted_certificate"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_lua_loc_conf_t, ssl_trusted_certificate),
      NULL },

    { njt_string("lua_ssl_crl"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_lua_loc_conf_t, ssl_crl),
      NULL },

#if (njet_version >= 1019004)
    { njt_string("lua_ssl_conf_command"),
      NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE2,
      njt_conf_set_keyval_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_lua_loc_conf_t, ssl_conf_commands),
      &njt_http_lua_ssl_conf_command_post },
#endif
#endif  /* NJT_HTTP_SSL */

     { njt_string("lua_malloc_trim"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE1,
      njt_http_lua_malloc_trim,
      NJT_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { njt_string("lua_worker_thread_vm_pool_size"),
      NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_HTTP_MAIN_CONF_OFFSET,
      offsetof(njt_http_lua_main_conf_t, worker_thread_vm_pool_size),
      NULL },

    njt_null_command
};


static njt_http_module_t njt_http_lua_module_ctx = {
    NULL,                             /*  preconfiguration */
    njt_http_lua_init,                /*  postconfiguration */

    njt_http_lua_create_main_conf,    /*  create main configuration */
    njt_http_lua_init_main_conf,      /*  init main configuration */

    njt_http_lua_create_srv_conf,     /*  create server configuration */
    njt_http_lua_merge_srv_conf,      /*  merge server configuration */

    njt_http_lua_create_loc_conf,     /*  create location configuration */
    njt_http_lua_merge_loc_conf       /*  merge location configuration */
};


njt_module_t njt_http_lua_module = {
    NJT_MODULE_V1,
    &njt_http_lua_module_ctx,   /*  module context */
    njt_http_lua_cmds,          /*  module directives */
    NJT_HTTP_MODULE,            /*  module type */
    NULL,                       /*  init master */
    NULL,                       /*  init module */
    njt_http_lua_init_worker,   /*  init process */
    NULL,                       /*  init thread */
    NULL,                       /*  exit thread */
    njt_http_lua_exit_worker,   /*  exit process */
    NULL,                       /*  exit master */
    NJT_MODULE_V1_PADDING
};


static njt_int_t
njt_http_lua_init(njt_conf_t *cf)
{
    int                         multi_http_blocks;
    njt_int_t                   rc;
    njt_array_t                *arr;
    njt_http_handler_pt        *h;
    volatile njt_cycle_t       *saved_cycle;
    njt_http_core_main_conf_t  *cmcf;
    njt_http_lua_main_conf_t   *lmcf;
    njt_pool_cleanup_t         *cln;
    njt_str_t                   name = njt_string("host");

    if (njt_process == NJT_PROCESS_SIGNALLER || njt_test_config) {
        return NJT_OK;
    }

    lmcf = njt_http_conf_get_module_main_conf(cf, njt_http_lua_module);

    lmcf->host_var_index = njt_http_get_variable_index(cf, &name);
    if (lmcf->host_var_index == NJT_ERROR) {
        return NJT_ERROR;
    }

    if (njt_http_lua_prev_cycle != njt_cycle) {
        njt_http_lua_prev_cycle = njt_cycle;
        multi_http_blocks = 0;

    } else {
        multi_http_blocks = 1;
    }

    if (multi_http_blocks || lmcf->requires_capture_filter) {
        rc = njt_http_lua_capture_filter_init(cf);
        if (rc != NJT_OK) {
            return rc;
        }
    }

    if (lmcf->postponed_to_rewrite_phase_end == NJT_CONF_UNSET) {
        lmcf->postponed_to_rewrite_phase_end = 0;
    }

    if (lmcf->postponed_to_access_phase_end == NJT_CONF_UNSET) {
        lmcf->postponed_to_access_phase_end = 0;
    }

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);

    if (lmcf->requires_server_rewrite) {
        h = njt_array_push(
          &cmcf->phases[NJT_HTTP_SERVER_REWRITE_PHASE].handlers);
        if (h == NULL) {
            return NJT_ERROR;
        }

        *h = njt_http_lua_server_rewrite_handler;
    }

    if (lmcf->requires_rewrite) {
        h = njt_array_push(&cmcf->phases[NJT_HTTP_REWRITE_PHASE].handlers);
        if (h == NULL) {
            return NJT_ERROR;
        }

        *h = njt_http_lua_rewrite_handler;
    }

    if (lmcf->requires_access) {
        h = njt_array_push(&cmcf->phases[NJT_HTTP_ACCESS_PHASE].handlers);
        if (h == NULL) {
            return NJT_ERROR;
        }

        *h = njt_http_lua_access_handler;
    }

    dd("requires log: %d", (int) lmcf->requires_log);

    if (lmcf->requires_log) {
        arr = &cmcf->phases[NJT_HTTP_LOG_PHASE].handlers;
        h = njt_array_push(arr);
        if (h == NULL) {
            return NJT_ERROR;
        }

        if (arr->nelts > 1) {
            h = arr->elts;
            njt_memmove(&h[1], h,
                        (arr->nelts - 1) * sizeof(njt_http_handler_pt));
        }

        *h = njt_http_lua_log_handler;
    }

    if (multi_http_blocks || lmcf->requires_header_filter) {
        rc = njt_http_lua_header_filter_init();
        if (rc != NJT_OK) {
            return rc;
        }
    }

    if (multi_http_blocks || lmcf->requires_body_filter) {
        rc = njt_http_lua_body_filter_init();
        if (rc != NJT_OK) {
            return rc;
        }
    }

    /* add the cleanup of semaphores after the lua_close */
    cln = njt_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NJT_ERROR;
    }

    cln->data = lmcf;
    cln->handler = njt_http_lua_sema_mm_cleanup;

#if (NJT_PCRE2)
    /* add the cleanup of pcre2 regex */
    cln = njt_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NJT_ERROR;
    }

    cln->data = lmcf;
    cln->handler = njt_http_lua_regex_cleanup;
#endif

#ifdef HAVE_NJT_LUA_PIPE
    njt_http_lua_pipe_init();
#endif

#if (njet_version >= 1011011)
    cln = njt_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NJT_ERROR;
    }

    cln->data = lmcf;
    cln->handler = njt_http_lua_njt_raw_header_cleanup;
#endif

    if (lmcf->lua == NULL) {
        dd("initializing lua vm");

#ifndef OPENRESTY_LUAJIT
        if (njt_process != NJT_PROCESS_SIGNALLER && !njt_test_config) {
            njt_log_error(NJT_LOG_ALERT, cf->log, 0,
                          "detected a LuaJIT version which is not OpenResty's"
                          "; many optimizations will be disabled and "
                          "performance will be compromised (see "
                          "https://github.com/openresty/luajit2 for "
                          "OpenResty's LuaJIT or, even better, consider using "
                          "the OpenResty releases from https://openresty.org/"
                          "en/download.html)");
        }
#else
#   if !defined(HAVE_LUA_RESETTHREAD)
        njt_log_error(NJT_LOG_ALERT, cf->log, 0,
                      "detected an old version of OpenResty's LuaJIT missing "
                      "the lua_resetthread API and thus the "
                      "performance will be compromised; please upgrade to the "
                      "latest version of OpenResty's LuaJIT: "
                      "https://github.com/openresty/luajit2");
#   endif
#   if !defined(HAVE_LUA_EXDATA2)
        njt_log_error(NJT_LOG_ALERT, cf->log, 0,
                      "detected an old version of OpenResty's LuaJIT missing "
                      "the exdata2 API and thus the "
                      "performance will be compromised; please upgrade to the "
                      "latest version of OpenResty's LuaJIT: "
                      "https://github.com/openresty/luajit2");
#   endif
#endif

        njt_http_lua_content_length_hash =
                                  njt_http_lua_hash_literal("content-length");
        njt_http_lua_location_hash = njt_http_lua_hash_literal("location");

        rc = njt_http_lua_init_vm(&lmcf->lua, NULL, cf->cycle, cf->pool,
                                  lmcf, cf->log, NULL);
        if (rc != NJT_OK) {
            if (rc == NJT_DECLINED) {
                njt_http_lua_assert(lmcf->lua != NULL);

                njt_conf_log_error(NJT_LOG_ALERT, cf, 0,
                                   "failed to load the 'resty.core' module "
                                   "(https://github.com/openresty/lua-resty"
                                   "-core); ensure you are using an OpenResty "
                                   "release from https://openresty.org/en/"
                                   "download.html (reason: %s)",
                                   lua_tostring(lmcf->lua, -1));

            } else {
                /* rc == NJT_ERROR */
                njt_conf_log_error(NJT_LOG_ALERT, cf, 0,
                                   "failed to initialize Lua VM");
            }

            return NJT_ERROR;
        }

        /* rc == NJT_OK */

        njt_http_lua_assert(lmcf->lua != NULL);

        if (!lmcf->requires_shm && lmcf->init_handler) {
            saved_cycle = njt_cycle;
            njt_cycle = cf->cycle;

            rc = lmcf->init_handler(cf->log, lmcf, lmcf->lua);

            njt_cycle = saved_cycle;

            if (rc != NJT_OK) {
                /* an error happened */
                return NJT_ERROR;
            }
        }

        dd("Lua VM initialized!");
    }

    return NJT_OK;
}


static char *
njt_http_lua_lowat_check(njt_conf_t *cf, void *post, void *data)
{
#if (NJT_FREEBSD)
    ssize_t *np = data;

    if ((u_long) *np >= njt_freebsd_net_inet_tcp_sendspace) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "\"lua_send_lowat\" must be less than %d "
                           "(sysctl net.inet.tcp.sendspace)",
                           njt_freebsd_net_inet_tcp_sendspace);

        return NJT_CONF_ERROR;
    }

#elif !(NJT_HAVE_SO_SNDLOWAT)
    ssize_t *np = data;

    njt_conf_log_error(NJT_LOG_WARN, cf, 0,
                       "\"lua_send_lowat\" is not supported, ignored");

    *np = 0;

#endif

    return NJT_CONF_OK;
}


static void *
njt_http_lua_create_main_conf(njt_conf_t *cf)
{
    njt_int_t       rc;

    njt_http_lua_main_conf_t    *lmcf;

    lmcf = njt_pcalloc(cf->pool, sizeof(njt_http_lua_main_conf_t));
    if (lmcf == NULL) {
        return NULL;
    }

    /* set by njt_pcalloc:
     *      lmcf->lua = NULL;
     *      lmcf->lua_path = { 0, NULL };
     *      lmcf->lua_cpath = { 0, NULL };
     *      lmcf->pending_timers = 0;
     *      lmcf->running_timers = 0;
     *      lmcf->watcher = NULL;
     *      lmcf->regex_cache_entries = 0;
     *      lmcf->jit_stack = NULL;
     *      lmcf->shm_zones = NULL;
     *      lmcf->init_handler = NULL;
     *      lmcf->init_src = { 0, NULL };
     *      lmcf->shm_zones_inited = 0;
     *      lmcf->shdict_zones = NULL;
     *      lmcf->preload_hooks = NULL;
     *      lmcf->requires_header_filter = 0;
     *      lmcf->requires_body_filter = 0;
     *      lmcf->requires_capture_filter = 0;
     *      lmcf->requires_rewrite = 0;
     *      lmcf->requires_access = 0;
     *      lmcf->requires_log = 0;
     *      lmcf->requires_shm = 0;
     */

    lmcf->pool = cf->pool;
    lmcf->max_pending_timers = NJT_CONF_UNSET;
    lmcf->max_running_timers = NJT_CONF_UNSET;
    lmcf->lua_thread_cache_max_entries = NJT_CONF_UNSET;
#if (NJT_PCRE)
    lmcf->regex_cache_max_entries = NJT_CONF_UNSET;
    lmcf->regex_match_limit = NJT_CONF_UNSET;
#endif
    lmcf->postponed_to_rewrite_phase_end = NJT_CONF_UNSET;
    lmcf->postponed_to_access_phase_end = NJT_CONF_UNSET;

    lmcf->set_sa_restart = NJT_CONF_UNSET;

#if (NJT_HTTP_LUA_HAVE_MALLOC_TRIM)
    lmcf->malloc_trim_cycle = NJT_CONF_UNSET_UINT;
#endif

    rc = njt_http_lua_sema_mm_init(cf, lmcf);
    if (rc != NJT_OK) {
        return NULL;
    }

    lmcf->worker_thread_vm_pool_size = NJT_CONF_UNSET;

    dd("njet Lua module main config structure initialized!");

    return lmcf;
}


static char *
njt_http_lua_init_main_conf(njt_conf_t *cf, void *conf)
{
#ifdef HAVE_LUA_RESETTHREAD
    njt_int_t                    i, n;
    njt_http_lua_thread_ref_t   *trefs;
#endif

    njt_http_lua_main_conf_t     *lmcf = conf;

    if (lmcf->lua_thread_cache_max_entries < 0) {
        lmcf->lua_thread_cache_max_entries = 1024;

#ifndef HAVE_LUA_RESETTHREAD

    } else if (lmcf->lua_thread_cache_max_entries > 0) {
        njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                      "lua_thread_cache_max_entries has no effect when "
                      "LuaJIT has no support for the lua_resetthread API "
                      "(you forgot to use OpenResty's LuaJIT?)");
        return NJT_CONF_ERROR;

#endif
    }

#if (NJT_PCRE)
    if (lmcf->regex_cache_max_entries == NJT_CONF_UNSET) {
        lmcf->regex_cache_max_entries = 1024;
    }

    if (lmcf->regex_match_limit == NJT_CONF_UNSET) {
        lmcf->regex_match_limit = 0;
    }
#endif

    if (lmcf->max_pending_timers == NJT_CONF_UNSET) {
        lmcf->max_pending_timers = 1024;
    }

    if (lmcf->max_running_timers == NJT_CONF_UNSET) {
        lmcf->max_running_timers = 256;
    }

#if (NJT_HTTP_LUA_HAVE_SA_RESTART)
    if (lmcf->set_sa_restart == NJT_CONF_UNSET) {
        lmcf->set_sa_restart = 1;
    }
#endif

#if (NJT_HTTP_LUA_HAVE_MALLOC_TRIM)
    if (lmcf->malloc_trim_cycle == NJT_CONF_UNSET_UINT) {
        lmcf->malloc_trim_cycle = 1000;  /* number of reqs */
    }
#endif

    lmcf->cycle = cf->cycle;

    njt_queue_init(&lmcf->free_lua_threads);
    njt_queue_init(&lmcf->cached_lua_threads);

#ifdef HAVE_LUA_RESETTHREAD
    n = lmcf->lua_thread_cache_max_entries;

    if (n > 0) {
        trefs = njt_palloc(cf->pool, n * sizeof(njt_http_lua_thread_ref_t));
        if (trefs == NULL) {
            return NJT_CONF_ERROR;
        }

        for (i = 0; i < n; i++) {
            trefs[i].ref = LUA_NOREF;
            trefs[i].co = NULL;
            njt_queue_insert_head(&lmcf->free_lua_threads, &trefs[i].queue);
        }
    }
#endif

    if (lmcf->worker_thread_vm_pool_size == NJT_CONF_UNSET_UINT) {
        lmcf->worker_thread_vm_pool_size = 100;
    }

    if (njt_http_lua_init_builtin_headers_out(cf, lmcf) != NJT_OK) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "init header out error");

        return NJT_CONF_ERROR;
    }

    dd("init built in headers out hash size: %ld",
       lmcf->builtin_headers_out.size);

    return NJT_CONF_OK;
}


static void *
njt_http_lua_create_srv_conf(njt_conf_t *cf)
{
    njt_http_lua_srv_conf_t     *lscf;

    lscf = njt_pcalloc(cf->pool, sizeof(njt_http_lua_srv_conf_t));
    if (lscf == NULL) {
        return NULL;
    }

    /* set by njt_pcalloc:
     *      lscf->srv.ssl_client_hello_handler = NULL;
     *      lscf->srv.ssl_client_hello_src = { 0, NULL };
     *      lscf->srv.ssl_client_hello_chunkname = NULL;
     *      lscf->srv.ssl_client_hello_src_key = NULL;
     *
     *      lscf->srv.ssl_cert_handler = NULL;
     *      lscf->srv.ssl_cert_src = { 0, NULL };
     *      lscf->srv.ssl_cert_chunkname = NULL;
     *      lscf->srv.ssl_cert_src_key = NULL;
     *
     *      lscf->srv.ssl_sess_store_handler = NULL;
     *      lscf->srv.ssl_sess_store_src = { 0, NULL };
     *      lscf->srv.ssl_sess_store_chunkname = NULL;
     *      lscf->srv.ssl_sess_store_src_key = NULL;
     *
     *      lscf->srv.ssl_sess_fetch_handler = NULL;
     *      lscf->srv.ssl_sess_fetch_src = { 0, NULL };
     *      lscf->srv.ssl_sess_fetch_chunkname = NULL;
     *      lscf->srv.ssl_sess_fetch_src_key = NULL;
     *
     *      lscf->balancer.handler = NULL;
     *      lscf->balancer.src = { 0, NULL };
     *      lscf->balancer.chunkname = NULL;
     *      lscf->balancer.src_key = NULL;
     */

#if (NJT_HTTP_SSL)
    lscf->srv.ssl_client_hello_src_ref = LUA_REFNIL;
    lscf->srv.ssl_cert_src_ref = LUA_REFNIL;
    lscf->srv.ssl_sess_store_src_ref = LUA_REFNIL;
    lscf->srv.ssl_sess_fetch_src_ref = LUA_REFNIL;
#endif

    lscf->balancer.src_ref = LUA_REFNIL;

    return lscf;
}


static char *
njt_http_lua_merge_srv_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_lua_srv_conf_t *conf = child;
    njt_http_lua_srv_conf_t *prev = parent;

#if (NJT_HTTP_SSL)

    njt_http_ssl_srv_conf_t *sscf;

    dd("merge srv conf");

    if (conf->srv.ssl_client_hello_src.len == 0) {
        conf->srv.ssl_client_hello_src = prev->srv.ssl_client_hello_src;
        conf->srv.ssl_client_hello_src_ref = prev->srv.ssl_client_hello_src_ref;
        conf->srv.ssl_client_hello_src_key = prev->srv.ssl_client_hello_src_key;
        conf->srv.ssl_client_hello_handler = prev->srv.ssl_client_hello_handler;
        conf->srv.ssl_client_hello_chunkname
            = prev->srv.ssl_client_hello_chunkname;
    }

    if (conf->srv.ssl_client_hello_src.len) {
        sscf = njt_http_conf_get_module_srv_conf(cf, njt_http_ssl_module);
        if (sscf == NULL || sscf->ssl.ctx == NULL) {
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "no ssl configured for the server");

            return NJT_CONF_ERROR;
        }
#ifdef LIBRESSL_VERSION_NUMBER
        njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                      "LibreSSL does not support by ssl_client_hello_by_lua*");
        return NJT_CONF_ERROR;

#else

#ifdef SSL_ERROR_WANT_CLIENT_HELLO_CB

        SSL_CTX_set_client_hello_cb(sscf->ssl.ctx,
                                    njt_http_lua_ssl_client_hello_handler,
                                    NULL);

#else

        njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                      "OpenSSL too old to support "
                      "ssl_client_hello_by_lua*");
        return NJT_CONF_ERROR;

#endif
#endif
    }

    if (conf->srv.ssl_cert_src.len == 0) {
        conf->srv.ssl_cert_src = prev->srv.ssl_cert_src;
        conf->srv.ssl_cert_src_ref = prev->srv.ssl_cert_src_ref;
        conf->srv.ssl_cert_src_key = prev->srv.ssl_cert_src_key;
        conf->srv.ssl_cert_handler = prev->srv.ssl_cert_handler;
        conf->srv.ssl_cert_chunkname = prev->srv.ssl_cert_chunkname;
    }

    if (conf->srv.ssl_cert_src.len) {
        sscf = njt_http_conf_get_module_srv_conf(cf, njt_http_ssl_module);
        if (sscf == NULL || sscf->ssl.ctx == NULL) {
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "no ssl configured for the server");

            return NJT_CONF_ERROR;
        }

#ifdef LIBRESSL_VERSION_NUMBER

        njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                      "LibreSSL is not supported by ssl_certificate_by_lua*");
        return NJT_CONF_ERROR;

#else

#   if OPENSSL_VERSION_NUMBER >= 0x1000205fL

        SSL_CTX_set_cert_cb(sscf->ssl.ctx, njt_http_lua_ssl_cert_handler, NULL);

#   else

        njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                      "OpenSSL too old to support ssl_certificate_by_lua*");
        return NJT_CONF_ERROR;

#   endif

#endif
    }

    if (conf->srv.ssl_sess_store_src.len == 0) {
        conf->srv.ssl_sess_store_src = prev->srv.ssl_sess_store_src;
        conf->srv.ssl_sess_store_src_ref = prev->srv.ssl_sess_store_src_ref;
        conf->srv.ssl_sess_store_src_key = prev->srv.ssl_sess_store_src_key;
        conf->srv.ssl_sess_store_handler = prev->srv.ssl_sess_store_handler;
        conf->srv.ssl_sess_store_chunkname = prev->srv.ssl_sess_store_chunkname;
    }

    if (conf->srv.ssl_sess_store_src.len) {
        sscf = njt_http_conf_get_module_srv_conf(cf, njt_http_ssl_module);
        if (sscf && sscf->ssl.ctx) {
#ifdef LIBRESSL_VERSION_NUMBER
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "LibreSSL is not supported by "
                          "ssl_session_store_by_lua*");

            return NJT_CONF_ERROR;
#else
            SSL_CTX_sess_set_new_cb(sscf->ssl.ctx,
                                    njt_http_lua_ssl_sess_store_handler);
#endif
        }
    }

    if (conf->srv.ssl_sess_fetch_src.len == 0) {
        conf->srv.ssl_sess_fetch_src = prev->srv.ssl_sess_fetch_src;
        conf->srv.ssl_sess_fetch_src_ref = prev->srv.ssl_sess_fetch_src_ref;
        conf->srv.ssl_sess_fetch_src_key = prev->srv.ssl_sess_fetch_src_key;
        conf->srv.ssl_sess_fetch_handler = prev->srv.ssl_sess_fetch_handler;
        conf->srv.ssl_sess_fetch_chunkname = prev->srv.ssl_sess_fetch_chunkname;
    }

    if (conf->srv.ssl_sess_fetch_src.len) {
        sscf = njt_http_conf_get_module_srv_conf(cf, njt_http_ssl_module);
        if (sscf && sscf->ssl.ctx) {
#ifdef LIBRESSL_VERSION_NUMBER
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "LibreSSL is not supported by "
                          "ssl_session_fetch_by_lua*");

            return NJT_CONF_ERROR;
#else
            SSL_CTX_sess_set_get_cb(sscf->ssl.ctx,
                                    njt_http_lua_ssl_sess_fetch_handler);
#endif
        }
    }

#endif  /* NJT_HTTP_SSL */

    if (conf->srv.server_rewrite_src.value.len == 0) {
        conf->srv.server_rewrite_src = prev->srv.server_rewrite_src;
        conf->srv.server_rewrite_src_ref = prev->srv.server_rewrite_src_ref;
        conf->srv.server_rewrite_src_key = prev->srv.server_rewrite_src_key;
        conf->srv.server_rewrite_handler = prev->srv.server_rewrite_handler;
        conf->srv.server_rewrite_chunkname
            = prev->srv.server_rewrite_chunkname;
    }

    return NJT_CONF_OK;
}


static void *
njt_http_lua_create_loc_conf(njt_conf_t *cf)
{
    njt_http_lua_loc_conf_t *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_lua_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /* set by njt_pcalloc:
     *      conf->access_src  = {{ 0, NULL }, NULL, NULL, NULL};
     *      conf->access_src_key = NULL
     *      conf->rewrite_src = {{ 0, NULL }, NULL, NULL, NULL};
     *      conf->rewrite_src_key = NULL;
     *      conf->rewrite_handler = NULL;
     *
     *      conf->content_src = {{ 0, NULL }, NULL, NULL, NULL};
     *      conf->content_src_key = NULL;
     *      conf->content_handler = NULL;
     *
     *      conf->log_src = {{ 0, NULL }, NULL, NULL, NULL};
     *      conf->log_src_key = NULL;
     *      conf->log_handler = NULL;
     *
     *      conf->header_filter_src = {{ 0, NULL }, NULL, NULL, NULL};
     *      conf->header_filter_src_key = NULL;
     *      conf->header_filter_handler = NULL;
     *
     *      conf->body_filter_src = {{ 0, NULL }, NULL, NULL, NULL};
     *      conf->body_filter_src_key = NULL;
     *      conf->body_filter_handler = NULL;
     *
     *      conf->ssl = 0;
     *      conf->ssl_protocols = 0;
     *      conf->ssl_ciphers = { 0, NULL };
     *      conf->ssl_trusted_certificate = { 0, NULL };
     *      conf->ssl_crl = { 0, NULL };
     */

    conf->force_read_body    = NJT_CONF_UNSET;
    conf->enable_code_cache  = NJT_CONF_UNSET;
    conf->http10_buffering   = NJT_CONF_UNSET;
    conf->check_client_abort = NJT_CONF_UNSET;
    conf->use_default_type   = NJT_CONF_UNSET;

    conf->keepalive_timeout = NJT_CONF_UNSET_MSEC;
    conf->connect_timeout = NJT_CONF_UNSET_MSEC;
    conf->send_timeout = NJT_CONF_UNSET_MSEC;
    conf->read_timeout = NJT_CONF_UNSET_MSEC;
    conf->send_lowat = NJT_CONF_UNSET_SIZE;
    conf->buffer_size = NJT_CONF_UNSET_SIZE;
    conf->pool_size = NJT_CONF_UNSET_UINT;

    conf->transform_underscores_in_resp_headers = NJT_CONF_UNSET;
    conf->log_socket_errors = NJT_CONF_UNSET;

    conf->rewrite_src_ref = LUA_REFNIL;
    conf->access_src_ref = LUA_REFNIL;
    conf->content_src_ref = LUA_REFNIL;
    conf->header_filter_src_ref = LUA_REFNIL;
    conf->body_filter_src_ref = LUA_REFNIL;
    conf->log_src_ref = LUA_REFNIL;

#if (NJT_HTTP_SSL)
    conf->ssl_verify_depth = NJT_CONF_UNSET_UINT;
    conf->ssl_certificates = NJT_CONF_UNSET_PTR;
    conf->ssl_certificate_keys = NJT_CONF_UNSET_PTR;
#if (njet_version >= 1019004)
    conf->ssl_conf_commands = NJT_CONF_UNSET_PTR;
#endif
#endif

    return conf;
}


static char *
njt_http_lua_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_lua_loc_conf_t *prev = parent;
    njt_http_lua_loc_conf_t *conf = child;

    if (conf->rewrite_src.value.len == 0) {
        conf->rewrite_src = prev->rewrite_src;
        conf->rewrite_handler = prev->rewrite_handler;
        conf->rewrite_src_ref = prev->rewrite_src_ref;
        conf->rewrite_src_key = prev->rewrite_src_key;
        conf->rewrite_chunkname = prev->rewrite_chunkname;
    }

    if (conf->access_src.value.len == 0) {
        conf->access_src = prev->access_src;
        conf->access_handler = prev->access_handler;
        conf->access_src_ref = prev->access_src_ref;
        conf->access_src_key = prev->access_src_key;
        conf->access_chunkname = prev->access_chunkname;
    }

    if (conf->content_src.value.len == 0) {
        conf->content_src = prev->content_src;
        conf->content_handler = prev->content_handler;
        conf->content_src_ref = prev->content_src_ref;
        conf->content_src_key = prev->content_src_key;
        conf->content_chunkname = prev->content_chunkname;
    }

    if (conf->log_src.value.len == 0) {
        conf->log_src = prev->log_src;
        conf->log_handler = prev->log_handler;
        conf->log_src_ref = prev->log_src_ref;
        conf->log_src_key = prev->log_src_key;
        conf->log_chunkname = prev->log_chunkname;
    }

    if (conf->header_filter_src.value.len == 0) {
        conf->header_filter_src = prev->header_filter_src;
        conf->header_filter_handler = prev->header_filter_handler;
        conf->header_filter_src_ref = prev->header_filter_src_ref;
        conf->header_filter_src_key = prev->header_filter_src_key;
        conf->header_filter_chunkname = prev->header_filter_chunkname;
    }

    if (conf->body_filter_src.value.len == 0) {
        conf->body_filter_src = prev->body_filter_src;
        conf->body_filter_handler = prev->body_filter_handler;
        conf->body_filter_src_ref = prev->body_filter_src_ref;
        conf->body_filter_src_key = prev->body_filter_src_key;
        conf->body_filter_chunkname = prev->body_filter_chunkname;
    }

#if (NJT_HTTP_SSL)

    if (njt_http_lua_merge_ssl(cf, conf, prev) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    njt_conf_merge_bitmask_value(conf->ssl_protocols, prev->ssl_protocols,
                                 (NJT_CONF_BITMASK_SET
                                  |NJT_SSL_TLSv1|NJT_SSL_TLSv1_1
                                  |NJT_SSL_TLSv1_2|NJT_SSL_TLSv1_3));

    njt_conf_merge_str_value(conf->ssl_ciphers, prev->ssl_ciphers,
                             "DEFAULT");

    njt_conf_merge_uint_value(conf->ssl_verify_depth,
                              prev->ssl_verify_depth, 1);
    njt_conf_merge_ptr_value(conf->ssl_certificates,
                             prev->ssl_certificates, NULL);
    njt_conf_merge_ptr_value(conf->ssl_certificate_keys,
                             prev->ssl_certificate_keys, NULL);
    njt_conf_merge_str_value(conf->ssl_trusted_certificate,
                             prev->ssl_trusted_certificate, "");
    njt_conf_merge_str_value(conf->ssl_crl, prev->ssl_crl, "");

#if (njet_version >= 1019004)
    njt_conf_merge_ptr_value(conf->ssl_conf_commands, prev->ssl_conf_commands,
                             NULL);
#endif

    if (njt_http_lua_set_ssl(cf, conf) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

#endif

    njt_conf_merge_value(conf->force_read_body, prev->force_read_body, 0);
    njt_conf_merge_value(conf->enable_code_cache, prev->enable_code_cache, 1);
    njt_conf_merge_value(conf->http10_buffering, prev->http10_buffering, 1);
    njt_conf_merge_value(conf->check_client_abort, prev->check_client_abort, 0);
    njt_conf_merge_value(conf->use_default_type, prev->use_default_type, 1);

    njt_conf_merge_msec_value(conf->keepalive_timeout,
                              prev->keepalive_timeout, 60000);

    njt_conf_merge_msec_value(conf->connect_timeout,
                              prev->connect_timeout, 60000);

    njt_conf_merge_msec_value(conf->send_timeout,
                              prev->send_timeout, 60000);

    njt_conf_merge_msec_value(conf->read_timeout,
                              prev->read_timeout, 60000);

    njt_conf_merge_size_value(conf->send_lowat,
                              prev->send_lowat, 0);

    njt_conf_merge_size_value(conf->buffer_size,
                              prev->buffer_size,
                              (size_t) njt_pagesize);

    njt_conf_merge_uint_value(conf->pool_size, prev->pool_size, 30);

    njt_conf_merge_value(conf->transform_underscores_in_resp_headers,
                         prev->transform_underscores_in_resp_headers, 1);

    njt_conf_merge_value(conf->log_socket_errors, prev->log_socket_errors, 1);

    return NJT_CONF_OK;
}


#if (NJT_HTTP_SSL)

static njt_int_t
njt_http_lua_merge_ssl(njt_conf_t *cf,
    njt_http_lua_loc_conf_t *conf, njt_http_lua_loc_conf_t *prev)
{
    njt_uint_t  preserve;

    if (conf->ssl_protocols == 0
        && conf->ssl_ciphers.data == NULL
        && conf->ssl_verify_depth == NJT_CONF_UNSET_UINT
        && conf->ssl_certificates == NJT_CONF_UNSET_PTR
        && conf->ssl_certificate_keys == NJT_CONF_UNSET_PTR
        && conf->ssl_trusted_certificate.data == NULL
        && conf->ssl_crl.data == NULL
#if (njet_version >= 1019004)
        && conf->ssl_conf_commands == NJT_CONF_UNSET_PTR
#endif
       )
    {
        if (prev->ssl) {
            conf->ssl = prev->ssl;
            return NJT_OK;
        }

        preserve = 1;

    } else {
        preserve = 0;
    }

    conf->ssl = njt_pcalloc(cf->pool, sizeof(njt_ssl_t));
    if (conf->ssl == NULL) {
        return NJT_ERROR;
    }

    conf->ssl->log = cf->log;

    /*
     * special handling to preserve conf->ssl_* in the "http" section
     * to inherit it to all servers
     */

    if (preserve) {
        prev->ssl = conf->ssl;
    }

    return NJT_OK;
}


static njt_int_t
njt_http_lua_set_ssl(njt_conf_t *cf, njt_http_lua_loc_conf_t *llcf)
{
    njt_pool_cleanup_t  *cln;

    if (llcf->ssl->ctx) {
        return NJT_OK;
    }

    if (llcf->ssl_certificates) {
        if (llcf->ssl_certificate_keys == NULL
            || llcf->ssl_certificate_keys->nelts
            < llcf->ssl_certificates->nelts)
        {
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "no \"lua_ssl_certificate_key\" is defined "
                          "for certificate \"%V\"",
                          ((njt_str_t *) llcf->ssl_certificates->elts)
                          + llcf->ssl_certificates->nelts - 1);
            return NJT_ERROR;
        }
    }

    if (njt_ssl_create(llcf->ssl, llcf->ssl_protocols, NULL) != NJT_OK) {
        return NJT_ERROR;
    }

    cln = njt_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        njt_ssl_cleanup_ctx(llcf->ssl);
        return NJT_ERROR;
    }

    cln->handler = njt_ssl_cleanup_ctx;
    cln->data = llcf->ssl;

    if (SSL_CTX_set_cipher_list(llcf->ssl->ctx,
                                (const char *) llcf->ssl_ciphers.data)
        == 0)
    {
        njt_ssl_error(NJT_LOG_EMERG, cf->log, 0,
                      "SSL_CTX_set_cipher_list(\"%V\") failed",
                      &llcf->ssl_ciphers);
        return NJT_ERROR;
    }

    if (llcf->ssl_certificates
        && njt_ssl_certificates(cf, llcf->ssl,
                                llcf->ssl_certificates,
                                llcf->ssl_certificate_keys,
                                NULL)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    if (llcf->ssl_trusted_certificate.len
        && njt_ssl_trusted_certificate(cf, llcf->ssl,
                                       &llcf->ssl_trusted_certificate,
                                       llcf->ssl_verify_depth)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    dd("ssl crl: %.*s", (int) llcf->ssl_crl.len, llcf->ssl_crl.data);

    if (njt_ssl_crl(cf, llcf->ssl, &llcf->ssl_crl) != NJT_OK) {
        return NJT_ERROR;
    }

#if (njet_version >= 1019004)
    if (njt_ssl_conf_commands(cf, llcf->ssl, llcf->ssl_conf_commands)
        != NJT_OK)
    {
        return NJT_ERROR;
    }
#endif

    return NJT_OK;
}

#if (njet_version >= 1019004)
static char *
njt_http_lua_ssl_conf_command_check(njt_conf_t *cf, void *post, void *data)
{
#ifndef SSL_CONF_FLAG_FILE
    return "is not supported on this platform";
#endif

    return NJT_CONF_OK;
}
#endif

#endif  /* NJT_HTTP_SSL */


static char *
njt_http_lua_malloc_trim(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
#if (NJT_HTTP_LUA_HAVE_MALLOC_TRIM)

    njt_int_t       nreqs;
    njt_str_t      *value;

    njt_http_lua_main_conf_t    *lmcf = conf;

    value = cf->args->elts;

    nreqs = njt_atoi(value[1].data, value[1].len);
    if (nreqs == NJT_ERROR) {
        return "invalid number in the 1st argument";
    }

    lmcf->malloc_trim_cycle = (njt_uint_t) nreqs;

    if (nreqs == 0) {
        return NJT_CONF_OK;
    }

    lmcf->requires_log = 1;

#else

    njt_conf_log_error(NJT_LOG_WARN, cf, 0, "lua_malloc_trim is not supported "
                       "on this platform, ignored");

#endif
    return NJT_CONF_OK;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
