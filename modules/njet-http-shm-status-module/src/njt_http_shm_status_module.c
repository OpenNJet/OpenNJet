

/*
 * Copyright (C), 2021-2024, TMLake(Beijing) Technology Co., Ltd.
 */



#include "njt_http_shm_status_module.h"
#include "njt_http_shm_status_display.h"


static void *njt_http_shm_status_create_loc_conf(njt_conf_t *cf);


static njt_conf_enum_t njt_http_shm_status_display_format[] = {
    { njt_string("json"), NJT_HTTP_SHM_STATUS_FORMAT_JSON},
    { njt_string("html"), NJT_HTTP_SHM_STATUS_FORMAT_HTML},
    { njt_string("jsp"), NJT_HTTP_SHM_STATUS_FORMAT_JSONP},
    { njt_string("prometheus"), NJT_HTTP_SHM_STATUS_FORMAT_PROMETHEUS},
    { njt_null_string, 0}
};


static njt_command_t njt_http_shm_status_commands[] = {

    { njt_string("shm_status_display"),
      NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_NOARGS|NJT_CONF_TAKE1,
      njt_http_shm_status_display,
      0,
      0,
      NULL },

    { njt_string("vhost_traffic_status_display_format"),
      NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_enum_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_shm_status_loc_conf_t, format),
      &njt_http_shm_status_display_format },

    njt_null_command
};   


static njt_http_module_t njt_http_shm_status_module_ctx = {
    NULL,                           /* preconfiguration */
    NULL,                           /* postconfiguration */

    NULL,                           /* create main configuration */
    NULL,                           /* init main configuration */

    NULL,                           /* create server configuration */
    NULL,                           /* merge server configuration */

    njt_http_shm_status_create_loc_conf,  /* create location configuration */
    NULL,                           /* merge location configuration */
};


njt_module_t njt_http_shm_status_module = {
    NJT_MODULE_V1,
    &njt_http_shm_status_module_ctx,   /* module context */
    njt_http_shm_status_commands,      /* module directives */
    NJT_HTTP_MODULE,                   /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    NULL,                              /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NJT_MODULE_V1_PADDING
};

static void *
njt_http_shm_status_create_loc_conf(njt_conf_t *cf)
{
    njt_http_shm_status_loc_conf_t *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_shm_status_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->format = NJT_HTTP_SHM_STATUS_FORMAT_JSON;

    return conf;
}



