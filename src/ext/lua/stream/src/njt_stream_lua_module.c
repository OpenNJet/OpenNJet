
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/njt_subsys_lua_module.c.tt2
 */


/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "njt_stream_lua_directive.h"
#include "njt_stream_lua_contentby.h"
#include "njt_stream_lua_util.h"
#include "njt_stream_lua_initby.h"
#include "njt_stream_lua_initworkerby.h"
#include "njt_stream_lua_probe.h"
#include "njt_stream_lua_balancer.h"
#include "njt_stream_lua_logby.h"
#include "njt_stream_lua_semaphore.h"
#include "njt_stream_lua_ssl_client_helloby.h"
#include "njt_stream_lua_ssl_certby.h"


#include "njt_stream_lua_prereadby.h"


static void *njt_stream_lua_create_main_conf(njt_conf_t *cf);
static char *njt_stream_lua_init_main_conf(njt_conf_t *cf, void *conf);
static void *njt_stream_lua_create_srv_conf(njt_conf_t *cf);
static char *njt_stream_lua_merge_srv_conf(njt_conf_t *cf, void *parent,
    void *child);




static njt_int_t njt_stream_lua_init(njt_conf_t *cf);
static char *njt_stream_lua_lowat_check(njt_conf_t *cf, void *post, void *data);
#if (NJT_STREAM_SSL)
static njt_int_t njt_stream_lua_set_ssl(njt_conf_t *cf,
    njt_stream_lua_loc_conf_t *llcf);
#if (njet_version >= 1019004)
static char *njt_stream_lua_ssl_conf_command_check(njt_conf_t *cf, void *post,
    void *data);
#endif
#endif
static char *njt_stream_lua_malloc_trim(njt_conf_t *cf, njt_command_t *cmd,
    void *conf);
#if (NJT_PCRE2)
extern void njt_stream_lua_regex_cleanup(void *data);
#endif


static njt_conf_post_t  njt_stream_lua_lowat_post =
    { njt_stream_lua_lowat_check };
#if (NJT_STREAM_SSL)
#if (njet_version >= 1019004)
static njt_conf_post_t  njt_stream_lua_ssl_conf_command_post =
    { njt_stream_lua_ssl_conf_command_check };
#endif
#endif



#if (NJT_STREAM_SSL)

static njt_conf_bitmask_t  njt_stream_lua_ssl_protocols[] = {
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

#endif




static njt_command_t njt_stream_lua_cmds[] = {

    { njt_string("lua_load_resty_core"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_FLAG,
      njt_stream_lua_load_resty_core,
      NJT_STREAM_MAIN_CONF_OFFSET,
      0,
      NULL },

    { njt_string("lua_max_running_timers"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_STREAM_MAIN_CONF_OFFSET,
      offsetof(njt_stream_lua_main_conf_t, max_running_timers),
      NULL },

    { njt_string("lua_max_pending_timers"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_STREAM_MAIN_CONF_OFFSET,
      offsetof(njt_stream_lua_main_conf_t, max_pending_timers),
      NULL },

    { njt_string("lua_shared_dict"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_TAKE2,
      njt_stream_lua_shared_dict,
      0,
      0,
      NULL },

    { njt_string("lua_sa_restart"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_MAIN_CONF_OFFSET,
      offsetof(njt_stream_lua_main_conf_t, set_sa_restart),
      NULL },

    { njt_string("lua_capture_error_log"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_TAKE1,
      njt_stream_lua_capture_error_log,
      0,
      0,
      NULL },

#if (NJT_PCRE)
    { njt_string("lua_regex_cache_max_entries"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_STREAM_MAIN_CONF_OFFSET,
      offsetof(njt_stream_lua_main_conf_t, regex_cache_max_entries),
      NULL },

    { njt_string("lua_regex_match_limit"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_STREAM_MAIN_CONF_OFFSET,
      offsetof(njt_stream_lua_main_conf_t, regex_match_limit),
      NULL },
#endif

    { njt_string("lua_package_cpath"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_TAKE1,
      njt_stream_lua_package_cpath,
      NJT_STREAM_MAIN_CONF_OFFSET,
      0,
      NULL },

    { njt_string("lua_package_path"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_TAKE1,
      njt_stream_lua_package_path,
      NJT_STREAM_MAIN_CONF_OFFSET,
      0,
      NULL },

    { njt_string("lua_code_cache"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF
          |NJT_CONF_FLAG,
      njt_stream_lua_code_cache,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_lua_loc_conf_t, enable_code_cache),
      NULL },


     { njt_string("lua_socket_log_errors"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF
          |NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_lua_loc_conf_t, log_socket_errors),
      NULL },

    { njt_string("init_by_lua_block"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_BLOCK|NJT_CONF_NOARGS,
      njt_stream_lua_init_by_lua_block,
      NJT_STREAM_MAIN_CONF_OFFSET,
      0,
      (void *) njt_stream_lua_init_by_inline },

    { njt_string("init_by_lua"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_TAKE1,
      njt_stream_lua_init_by_lua,
      NJT_STREAM_MAIN_CONF_OFFSET,
      0,
      (void *) njt_stream_lua_init_by_inline },

    { njt_string("init_by_lua_file"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_TAKE1,
      njt_stream_lua_init_by_lua,
      NJT_STREAM_MAIN_CONF_OFFSET,
      0,
      (void *) njt_stream_lua_init_by_file },

    { njt_string("init_worker_by_lua_block"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_BLOCK|NJT_CONF_NOARGS,
      njt_stream_lua_init_worker_by_lua_block,
      NJT_STREAM_MAIN_CONF_OFFSET,
      0,
      (void *) njt_stream_lua_init_worker_by_inline },

    { njt_string("init_worker_by_lua"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_TAKE1,
      njt_stream_lua_init_worker_by_lua,
      NJT_STREAM_MAIN_CONF_OFFSET,
      0,
      (void *) njt_stream_lua_init_worker_by_inline },

    { njt_string("init_worker_by_lua_file"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_TAKE1,
      njt_stream_lua_init_worker_by_lua,
      NJT_STREAM_MAIN_CONF_OFFSET,
      0,
      (void *) njt_stream_lua_init_worker_by_file },

    /* preread_by_lua_file rel/or/abs/path/to/script */
    { njt_string("preread_by_lua_file"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_stream_lua_preread_by_lua,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      (void *) njt_stream_lua_preread_handler_file },

    /* preread_by_lua_block { <inline script> } */
    { njt_string("preread_by_lua_block"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_BLOCK|NJT_CONF_NOARGS,
      njt_stream_lua_preread_by_lua_block,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      (void *) njt_stream_lua_preread_handler_inline },


    /* content_by_lua "<inline script>" */
    { njt_string("content_by_lua"),
      NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_stream_lua_content_by_lua,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      (void *) njt_stream_lua_content_handler_inline },

    /* content_by_lua_block { <inline script> } */
    { njt_string("content_by_lua_block"),
      NJT_STREAM_SRV_CONF|NJT_CONF_BLOCK|NJT_CONF_NOARGS,
      njt_stream_lua_content_by_lua_block,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      (void *) njt_stream_lua_content_handler_inline },

    /* content_by_lua_file rel/or/abs/path/to/script */
    { njt_string("content_by_lua_file"),
      NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_stream_lua_content_by_lua,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      (void *) njt_stream_lua_content_handler_file },



    /* log_by_lua_block { <inline script> } */
    { njt_string("log_by_lua_block"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF
                        |NJT_CONF_BLOCK|NJT_CONF_NOARGS,
      njt_stream_lua_log_by_lua_block,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      (void *) njt_stream_lua_log_handler_inline },

    { njt_string("log_by_lua_file"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF
                        |NJT_CONF_TAKE1,
      njt_stream_lua_log_by_lua,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      (void *) njt_stream_lua_log_handler_file },

    { njt_string("preread_by_lua_no_postpone"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_MAIN_CONF_OFFSET,
      offsetof(njt_stream_lua_main_conf_t, postponed_to_preread_phase_end),
      NULL },

    { njt_string("balancer_by_lua_block"),
      NJT_STREAM_UPS_CONF|NJT_CONF_BLOCK|NJT_CONF_NOARGS,
      njt_stream_lua_balancer_by_lua_block,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      (void *) njt_stream_lua_balancer_handler_inline },

    { njt_string("balancer_by_lua_file"),
      NJT_STREAM_UPS_CONF|NJT_CONF_TAKE1,
      njt_stream_lua_balancer_by_lua,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      (void *) njt_stream_lua_balancer_handler_file },


    { njt_string("lua_socket_keepalive_timeout"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF
          |NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_lua_srv_conf_t, keepalive_timeout),
      NULL },

    { njt_string("lua_socket_connect_timeout"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF
          |NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_lua_srv_conf_t, connect_timeout),
      NULL },

    { njt_string("lua_socket_send_timeout"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF
          |NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_lua_srv_conf_t, send_timeout),
      NULL },

    { njt_string("lua_socket_send_lowat"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF
          |NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_lua_srv_conf_t, send_lowat),
      &njt_stream_lua_lowat_post },

    { njt_string("lua_socket_buffer_size"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF
          |NJT_CONF_TAKE1,
      njt_conf_set_size_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_lua_srv_conf_t, buffer_size),
      NULL },

    { njt_string("lua_socket_pool_size"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF
          |NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_lua_srv_conf_t, pool_size),
      NULL },

    { njt_string("lua_socket_read_timeout"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF
          |NJT_CONF_TAKE1,
      njt_conf_set_msec_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_lua_srv_conf_t, read_timeout),
      NULL },


    { njt_string("lua_check_client_abort"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF
          |NJT_CONF_FLAG,
      njt_conf_set_flag_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_lua_srv_conf_t, check_client_abort),
      NULL },



#if (NJT_STREAM_SSL)

    { njt_string("lua_ssl_protocols"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_1MORE,
      njt_conf_set_bitmask_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_lua_srv_conf_t, ssl_protocols),
      &njt_stream_lua_ssl_protocols },

    { njt_string("lua_ssl_ciphers"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_lua_srv_conf_t, ssl_ciphers),
      NULL },

    { njt_string("ssl_client_hello_by_lua_block"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_BLOCK|NJT_CONF_NOARGS,
      njt_stream_lua_ssl_client_hello_by_lua_block,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      (void *) njt_stream_lua_ssl_client_hello_handler_inline },

    { njt_string("ssl_client_hello_by_lua_file"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_stream_lua_ssl_client_hello_by_lua,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      (void *) njt_stream_lua_ssl_client_hello_handler_file },

    { njt_string("ssl_certificate_by_lua_block"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_BLOCK|NJT_CONF_NOARGS,
      njt_stream_lua_ssl_cert_by_lua_block,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      (void *) njt_stream_lua_ssl_cert_handler_inline },

    { njt_string("ssl_certificate_by_lua_file"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_stream_lua_ssl_cert_by_lua,
      NJT_STREAM_SRV_CONF_OFFSET,
      0,
      (void *) njt_stream_lua_ssl_cert_handler_file },


    { njt_string("lua_ssl_verify_depth"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_num_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_lua_srv_conf_t, ssl_verify_depth),
      NULL },

    { njt_string("lua_ssl_certificate"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_array_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_lua_srv_conf_t, ssl_certificates),
      NULL },

    { njt_string("lua_ssl_certificate_key"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_array_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_lua_srv_conf_t, ssl_certificate_keys),
      NULL },

    { njt_string("lua_ssl_trusted_certificate"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_lua_srv_conf_t, ssl_trusted_certificate),
      NULL },

    { njt_string("lua_ssl_crl"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE1,
      njt_conf_set_str_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_lua_srv_conf_t, ssl_crl),
      NULL },

#if (njet_version >= 1019004)
    { njt_string("lua_ssl_conf_command"),
      NJT_STREAM_MAIN_CONF|NJT_STREAM_SRV_CONF|NJT_CONF_TAKE2,
      njt_conf_set_keyval_slot,
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_lua_srv_conf_t, ssl_conf_commands),
      &njt_stream_lua_ssl_conf_command_post },
#endif
#endif  /* NJT_STREAM_SSL */

     { njt_string("lua_malloc_trim"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_TAKE1,
      njt_stream_lua_malloc_trim,
      NJT_STREAM_MAIN_CONF_OFFSET,
      0,
      NULL },

     { njt_string("lua_add_variable"),
      NJT_STREAM_MAIN_CONF|NJT_CONF_TAKE1,
      njt_stream_lua_add_variable,
      0,
      0,
      NULL },

    njt_null_command
};


njt_stream_module_t njt_stream_lua_module_ctx = {
    NULL,                                     /*  preconfiguration */
    njt_stream_lua_init,                /*  postconfiguration */

    njt_stream_lua_create_main_conf,    /*  create main configuration */
    njt_stream_lua_init_main_conf,      /*  init main configuration */

    njt_stream_lua_create_srv_conf,     /*  create server configuration */
    njt_stream_lua_merge_srv_conf,      /*  merge server configuration */

};


njt_module_t njt_stream_lua_module = {
    NJT_MODULE_V1,
    &njt_stream_lua_module_ctx,       /*  module context */
    njt_stream_lua_cmds,              /*  module directives */
    NJT_STREAM_MODULE,                /*  module type */
    NULL,                                   /*  init master */
    NULL,                                   /*  init module */
    njt_stream_lua_init_worker,       /*  init process */
    NULL,                                   /*  init thread */
    NULL,                                   /*  exit thread */
    NULL,                                   /*  exit process */
    NULL,                                   /*  exit master */
    NJT_MODULE_V1_PADDING
};


static njt_int_t
njt_stream_lua_init(njt_conf_t *cf)
{
    njt_int_t                           rc;
    volatile njt_cycle_t               *saved_cycle;
    njt_array_t                        *arr;
    njt_pool_cleanup_t                 *cln;

    njt_stream_handler_pt              *h;
    njt_stream_lua_main_conf_t         *lmcf;
    njt_stream_core_main_conf_t        *cmcf;


    if (njt_process == NJT_PROCESS_SIGNALLER || njt_test_config) {
        return NJT_OK;
    }

    lmcf = njt_stream_conf_get_module_main_conf(cf,
                                                njt_stream_lua_module);


    cmcf = njt_stream_conf_get_module_main_conf(cf, njt_stream_core_module);

    if (lmcf->requires_preread) {
        h = njt_array_push(&cmcf->phases[NJT_STREAM_PREREAD_PHASE].handlers);
        if (h == NULL) {
            return NJT_ERROR;
        }

        *h = njt_stream_lua_preread_handler;
    }

    if (lmcf->postponed_to_preread_phase_end == NJT_CONF_UNSET) {
        lmcf->postponed_to_preread_phase_end = 0;
    }

    dd("requires log: %d", (int) lmcf->requires_log);

    if (lmcf->requires_log) {
        arr = &cmcf->phases[NJT_STREAM_LOG_PHASE].handlers;
        h = njt_array_push(arr);
        if (h == NULL) {
            return NJT_ERROR;
        }

        if (arr->nelts > 1) {

            /*
             * if there are other log handlers, move them back and put ourself
             * to the front of the list
             */

            h = arr->elts;
            njt_memmove(&h[1], h,
                        (arr->nelts - 1) * sizeof(njt_stream_handler_pt));
        }

        *h = njt_stream_lua_log_handler;
    }


    /* add the cleanup of semaphores after the lua_close */
    cln = njt_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NJT_ERROR;
    }

    cln->data = lmcf;
    cln->handler = njt_stream_lua_sema_mm_cleanup;

#if (NJT_PCRE2)
    /* add the cleanup of pcre2 regex */
    cln = njt_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NJT_ERROR;
    }

    cln->data = lmcf;
    cln->handler = njt_stream_lua_regex_cleanup;
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
#   if !defined(HAVE_LUA_EXDATA2)
        njt_log_error(NJT_LOG_ALERT, cf->log, 0,
                      "detected an old version of OpenResty's LuaJIT missing "
                      "the exdata2 API and thus the "
                      "performance will be compromised; please upgrade to the "
                      "latest version of OpenResty's LuaJIT: "
                      "https://github.com/openresty/luajit2");
#   endif
#endif


        rc = njt_stream_lua_init_vm(&lmcf->lua, NULL, cf->cycle, cf->pool,
                                    lmcf, cf->log, NULL);
        if (rc != NJT_OK) {
            if (rc == NJT_DECLINED) {
                njt_stream_lua_assert(lmcf->lua != NULL);

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

        njt_stream_lua_assert(lmcf->lua != NULL);

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
njt_stream_lua_lowat_check(njt_conf_t *cf, void *post, void *data)
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
njt_stream_lua_create_main_conf(njt_conf_t *cf)
{
    njt_int_t       rc;

    njt_stream_lua_main_conf_t          *lmcf;

    lmcf = njt_pcalloc(cf->pool, sizeof(njt_stream_lua_main_conf_t));
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
#if (NJT_PCRE)
    lmcf->regex_cache_max_entries = NJT_CONF_UNSET;
    lmcf->regex_match_limit = NJT_CONF_UNSET;
#endif

    lmcf->postponed_to_preread_phase_end = NJT_CONF_UNSET;

    lmcf->set_sa_restart = NJT_CONF_UNSET;

#if (NJT_STREAM_LUA_HAVE_MALLOC_TRIM)
    lmcf->malloc_trim_cycle = NJT_CONF_UNSET_UINT;
#endif

    rc = njt_stream_lua_sema_mm_init(cf, lmcf);
    if (rc != NJT_OK) {
        return NULL;
    }

    dd("njet Lua module main config structure initialized!");

    return lmcf;
}


static char *
njt_stream_lua_init_main_conf(njt_conf_t *cf, void *conf)
{
    njt_stream_lua_main_conf_t       *lmcf = conf;

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

#if (NJT_STREAM_LUA_HAVE_SA_RESTART)
    if (lmcf->set_sa_restart == NJT_CONF_UNSET) {
        lmcf->set_sa_restart = 1;
    }
#endif

#if (NJT_STREAM_LUA_HAVE_MALLOC_TRIM)
    if (lmcf->malloc_trim_cycle == NJT_CONF_UNSET_UINT) {
        lmcf->malloc_trim_cycle = 1000;  /* number of reqs */
    }
#endif

    lmcf->cycle = cf->cycle;

    return NJT_CONF_OK;
}






static void *
njt_stream_lua_create_srv_conf(njt_conf_t *cf)
{
    njt_stream_lua_srv_conf_t           *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_stream_lua_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /* set by njt_pcalloc:
     *      lscf->srv.ssl_client_hello_handler = NULL;
     *      lscf->srv.ssl_client_hello_src = { 0, NULL };
     *      lscf->srv.ssl_client_hello_src_key = NULL;
     *
     *      lscf->srv.ssl_cert_handler = NULL;
     *      lscf->srv.ssl_cert_src = { 0, NULL };
     *      lscf->srv.ssl_cert_src_key = NULL;
     *
     *      lscf->srv.ssl_session_store_handler = NULL;
     *      lscf->srv.ssl_session_store_src = { 0, NULL };
     *      lscf->srv.ssl_session_store_src_key = NULL;
     *
     *      lscf->srv.ssl_session_fetch_handler = NULL;
     *      lscf->srv.ssl_session_fetch_src = { 0, NULL };
     *      lscf->srv.ssl_session_fetch_src_key = NULL;
     *
     *      lscf->balancer.handler = NULL;
     *      lscf->balancer.src = { 0, NULL };
     *      lscf->balancer.src_key = NULL;
     */

    conf->enable_code_cache  = NJT_CONF_UNSET;
    conf->check_client_abort = NJT_CONF_UNSET;

    conf->keepalive_timeout = NJT_CONF_UNSET_MSEC;
    conf->connect_timeout = NJT_CONF_UNSET_MSEC;
    conf->send_timeout = NJT_CONF_UNSET_MSEC;
    conf->read_timeout = NJT_CONF_UNSET_MSEC;
    conf->send_lowat = NJT_CONF_UNSET_SIZE;
    conf->buffer_size = NJT_CONF_UNSET_SIZE;
    conf->pool_size = NJT_CONF_UNSET_UINT;

    conf->log_socket_errors = NJT_CONF_UNSET;

#if (NJT_STREAM_SSL)
    conf->ssl_verify_depth = NJT_CONF_UNSET_UINT;
    conf->ssl_certificates = NJT_CONF_UNSET_PTR;
    conf->ssl_certificate_keys = NJT_CONF_UNSET_PTR;
#endif

    return conf;
}


static char *
njt_stream_lua_merge_srv_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_stream_lua_srv_conf_t       *prev = parent;
    njt_stream_lua_srv_conf_t       *conf = child;

#if (NJT_STREAM_SSL)
    njt_stream_ssl_conf_t           *sscf;

    dd("merge srv conf");

    sscf = njt_stream_conf_get_module_srv_conf(cf, njt_stream_ssl_module);
    if (sscf && sscf->listen) {
        if (conf->srv.ssl_client_hello_src.len == 0) {
            conf->srv.ssl_client_hello_src = prev->srv.ssl_client_hello_src;
            conf->srv.ssl_client_hello_src_key =
                prev->srv.ssl_client_hello_src_key;
            conf->srv.ssl_client_hello_handler =
                prev->srv.ssl_client_hello_handler;
        }

        if (conf->srv.ssl_client_hello_src.len) {
            if (sscf->ssl.ctx == NULL) {
                njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                              "no ssl configured for the server");

                return NJT_CONF_ERROR;
            }
#ifdef LIBRESSL_VERSION_NUMBER
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "LibreSSL does not support by "
                          "ssl_client_hello_by_lua*");
            return NJT_CONF_ERROR;

#else

#   ifdef SSL_ERROR_WANT_CLIENT_HELLO_CB

            SSL_CTX_set_client_hello_cb(sscf->ssl.ctx,
                                        njt_stream_lua_ssl_client_hello_handler,
                                        NULL);

#   else

            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "OpenSSL too old to support "
                          "ssl_client_hello_by_lua*");
            return NJT_CONF_ERROR;

#   endif
#endif
        }

        if (conf->srv.ssl_cert_src.len == 0) {
            conf->srv.ssl_cert_src = prev->srv.ssl_cert_src;
            conf->srv.ssl_cert_src_key = prev->srv.ssl_cert_src_key;
            conf->srv.ssl_cert_handler = prev->srv.ssl_cert_handler;
        }

        if (conf->srv.ssl_cert_src.len) {
            if (sscf->ssl.ctx == NULL) {
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

            SSL_CTX_set_cert_cb(sscf->ssl.ctx, njt_stream_lua_ssl_cert_handler, NULL);

#   else

            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "OpenSSL too old to support ssl_certificate_by_lua*");
            return NJT_CONF_ERROR;

#   endif

#endif
        }
    }


#endif  /* NJT_STREAM_SSL */

#if (NJT_STREAM_SSL)

    njt_conf_merge_bitmask_value(conf->ssl_protocols, prev->ssl_protocols,
                                 NJT_CONF_BITMASK_SET|NJT_SSL_SSLv3
                                 |NJT_SSL_TLSv1|NJT_SSL_TLSv1_1
                                 |NJT_SSL_TLSv1_2);

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

    if (njt_stream_lua_set_ssl(cf, conf) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

#endif

    njt_conf_merge_value(conf->enable_code_cache, prev->enable_code_cache, 1);
    njt_conf_merge_value(conf->check_client_abort, prev->check_client_abort, 0);

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

    njt_conf_merge_value(conf->log_socket_errors, prev->log_socket_errors, 1);

    if (conf->preread_src.value.len == 0) {
        conf->preread_src = prev->preread_src;
        conf->preread_handler = prev->preread_handler;
        conf->preread_src_key = prev->preread_src_key;
        conf->preread_chunkname = prev->preread_chunkname;
    }

    if (conf->log_src.value.len == 0) {
        conf->log_src = prev->log_src;
        conf->log_handler = prev->log_handler;
        conf->log_src_key = prev->log_src_key;
        conf->log_chunkname = prev->log_chunkname;
    }

    return NJT_CONF_OK;
}




#if (NJT_STREAM_SSL)

static njt_int_t
njt_stream_lua_set_ssl(njt_conf_t *cf, njt_stream_lua_srv_conf_t *lscf)
{
    njt_pool_cleanup_t  *cln;

    lscf->ssl = njt_pcalloc(cf->pool, sizeof(njt_ssl_t));
    if (lscf->ssl == NULL) {
        return NJT_ERROR;
    }

    lscf->ssl->log = cf->log;

    if (lscf->ssl_certificates) {
        if (lscf->ssl_certificate_keys == NULL
            || lscf->ssl_certificate_keys->nelts
            < lscf->ssl_certificates->nelts)
        {
            njt_log_error(NJT_LOG_EMERG, cf->log, 0,
                          "no \"lua_ssl_certificate_key\" is defined "
                          "for certificate \"%V\"",
                          ((njt_str_t *) lscf->ssl_certificates->elts)
                          + lscf->ssl_certificates->nelts - 1);
            return NJT_ERROR;
        }
    }

    if (njt_ssl_create(lscf->ssl, lscf->ssl_protocols, NULL) != NJT_OK) {
        return NJT_ERROR;
    }

    cln = njt_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NJT_ERROR;
    }

    cln->handler = njt_ssl_cleanup_ctx;
    cln->data = lscf->ssl;

    if (SSL_CTX_set_cipher_list(lscf->ssl->ctx,
                                (const char *) lscf->ssl_ciphers.data)
        == 0)
    {
        njt_ssl_error(NJT_LOG_EMERG, cf->log, 0,
                      "SSL_CTX_set_cipher_list(\"%V\") failed",
                      &lscf->ssl_ciphers);
        return NJT_ERROR;
    }

    if (lscf->ssl_certificates
        && njt_ssl_certificates(cf, lscf->ssl,
                                lscf->ssl_certificates,
                                lscf->ssl_certificate_keys,
                                NULL)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    if (lscf->ssl_trusted_certificate.len
        && njt_ssl_trusted_certificate(cf, lscf->ssl,
                                       &lscf->ssl_trusted_certificate,
                                       lscf->ssl_verify_depth)
        != NJT_OK)
    {
        return NJT_ERROR;
    }

    dd("ssl crl: %.*s", (int) lscf->ssl_crl.len, lscf->ssl_crl.data);

    if (njt_ssl_crl(cf, lscf->ssl, &lscf->ssl_crl) != NJT_OK) {
        return NJT_ERROR;
    }

#if (njet_version >= 1019004)
    if (njt_ssl_conf_commands(cf, lscf->ssl, lscf->ssl_conf_commands)
        != NJT_OK) {
        return NJT_ERROR;
    }
#endif
    return NJT_OK;
}

#if (njet_version >= 1019004)
static char *
njt_stream_lua_ssl_conf_command_check(njt_conf_t *cf, void *post, void *data)
{
#ifndef SSL_CONF_FLAG_FILE
    return "is not supported on this platform";
#endif

    return NJT_CONF_OK;
}
#endif
#endif  /* NJT_STREAM_SSL */


static char *
njt_stream_lua_malloc_trim(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
#if (NJT_STREAM_LUA_HAVE_MALLOC_TRIM)

    njt_int_t       nreqs;
    njt_str_t      *value;

    njt_stream_lua_main_conf_t          *lmcf = conf;

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
