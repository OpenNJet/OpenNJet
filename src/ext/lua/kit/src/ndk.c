
/*
 * 2010 (C) Marcus Clyne
 */

#include    <ndk.h>

#include    <ndk_config.c>


#if (NDK_HTTP_PRE_CONFIG)
static  njt_int_t   ndk_http_preconfiguration    (njt_conf_t *cf);
#endif
#if (NDK_HTTP_POST_CONFIG)
static  njt_int_t   ndk_http_postconfiguration   (njt_conf_t *cf);
#endif
#if (NDK_HTTP_CREATE_MAIN_CONF)
static void *       ndk_http_create_main_conf    (njt_conf_t *cf);
#endif
#if (NDK_HTTP_INIT_MAIN_CONF)
static char *       ndk_http_init_main_conf      (njt_conf_t *cf, void *conf);
#endif
#if (NDK_HTTP_CREATE_SRV_CONF)
static void *       ndk_http_create_srv_conf     (njt_conf_t *cf);
#endif
#if (NDK_HTTP_MERGE_SRV_CONF)
static char *       ndk_http_merge_srv_conf      (njt_conf_t *cf, void *parent, void *child);
#endif
#if (NDK_HTTP_CREATE_LOC_CONF)
static void *       ndk_http_create_loc_conf     (njt_conf_t *cf);
#endif
#if (NDK_HTTP_MERGE_LOC_CONF)
static char *       ndk_http_merge_loc_conf      (njt_conf_t *cf, void *parent, void *child);
#endif


#if (NDK_HTTP_INIT_MASTER)
static njt_int_t    ndk_http_init_master         (njt_log_t *log);
#endif
#if (NDK_HTTP_INIT_MODULE)
static njt_int_t    ndk_http_init_module         (njt_cycle_t *cycle);
#endif
#if (NDK_HTTP_INIT_PROCESS)
static njt_int_t    ndk_http_init_process        (njt_cycle_t *cycle);
#endif
#if (NDK_HTTP_EXIT_PROCESS)
static void         ndk_http_exit_process        (njt_cycle_t *cycle);
#endif
#if (NDK_HTTP_EXIT_MASTER)
static void         ndk_http_exit_master         (njt_cycle_t *cycle);
#endif


njt_http_module_t   ndk_http_module_ctx = {

#if (NDK_HTTP_PRE_CONFIG)
    ndk_http_preconfiguration,
#else
    NULL,
#endif
#if (NDK_HTTP_POST_CONFIG)
    ndk_http_postconfiguration,
#else
    NULL,
#endif

#if (NDK_HTTP_CREATE_MAIN_CONF)
    ndk_http_create_main_conf,
#else
    NULL,
#endif
#if (NDK_HTTP_INIT_MAIN_CONF)
    ndk_http_merge_main_conf,
#else
    NULL,
#endif

#if (NDK_HTTP_CREATE_SVR_CONF)
    ndk_http_create_srv_conf,
#else
    NULL,
#endif
#if (NDK_HTTP_MERGE_SVR_CONF)
    ndk_http_merge_srv_conf,
#else
    NULL,
#endif

#if (NDK_HTTP_CREATE_LOC_CONF)
    ndk_http_create_loc_conf,
#else
    NULL,
#endif
#if (NDK_HTTP_MERGE_LOC_CONF)
    ndk_http_merge_loc_conf,
#else
    NULL,
#endif

};

njt_module_t          ndk_http_module = {

    NJT_MODULE_V1,
    &ndk_http_module_ctx,          /* module context */
    ndk_http_commands,             /* module directives */
    NJT_HTTP_MODULE,               /* module type */

#if (NDK_HTTP_INIT_MASTER)
    ndk_http_init_master,
#else
    NULL,
#endif

#if (NDK_HTTP_INIT_MODULE)
    ndk_http_init_module,
#else
    NULL,
#endif
#if (NDK_HTTP_INIT_PROCESS)
    ndk_http_init_process,
#else
    NULL,
#endif

    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */

#if (NDK_HTTP_EXIT_PROCESS)
    ndk_http_exit_process,
#else
    NULL,
#endif
#if (NDK_HTTP_EXIT_MASTER)
    ndk_http_exit_master,
#else
    NULL,
#endif
    NJT_MODULE_V1_PADDING
};



#if (NDK_HTTP_CREATE_MAIN_CONF)
static void *
ndk_http_create_main_conf (njt_conf_t *cf)
{
    ndk_http_main_conf_t    *mcf;

    ndk_pcallocp_rce (mcf, cf->pool);

    return  mcf;
}
#endif

