
/*
 * Copyright (C), 2021-2024, TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_SHM_STATUS_MODULE_H_
#define _NJT_HTTP_SHM_STATUS_MODULE_H_

#include <njet.h>
#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>

#include <njt_shm_status_module.h>

#define NJT_HTTP_SHM_STATUS_FORMAT_NONE          0
#define NJT_HTTP_SHM_STATUS_FORMAT_JSON          1
#define NJT_HTTP_SHM_STATUS_FORMAT_HTML          2
#define NJT_HTTP_SHM_STATUS_FORMAT_JSONP         3
#define NJT_HTTP_SHM_STATUS_FORMAT_PROMETHEUS    4

#define NJT_HTTP_SHM_STATUS_DEFAULT_JSONP        "njt_http_shm_status_jsonp_callback"


typedef struct {
    njt_flag_t       format;

} njt_http_shm_status_loc_conf_t;

extern njt_module_t njt_http_shm_status_module;
extern njt_slab_pool_t *njt_shm_status_pool; 

#endif