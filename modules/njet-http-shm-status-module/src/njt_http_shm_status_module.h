
/*
 * Copyright (C), 2021-2024, TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_HTTP_SHM_STATUS_MODULE_H_
#define _NJT_HTTP_SHM_STATUS_MODULE_H_

#include <njet.h>
#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_sysinfo_util.h>
#include <njt_shm_status_module.h>

#define NJT_HTTP_SHM_STATUS_FORMAT_NONE          0
#define NJT_HTTP_SHM_STATUS_FORMAT_JSON          1
#define NJT_HTTP_SHM_STATUS_FORMAT_HTML          2
#define NJT_HTTP_SHM_STATUS_FORMAT_JSONP         3
#define NJT_HTTP_SHM_STATUS_FORMAT_PROMETHEUS    4

#define NJT_HTTP_SHM_STATUS_DEFAULT_JSONP        "njt_http_shm_status_jsonp_callback"



//sys info(cpu and mem)
typedef struct {
    njt_str_t                  pid;  //total meminfo
    size_t                     memory_use;
    float                      cpu_cpu_usage;
    time_t                     prev_pid_work;
} njt_http_shm_status_process_sysinfo;


//sys info(cpu and mem)
typedef struct {
    njt_meminfo_t                  sys_meminfo;  //total meminfo
    float                          sys_cpu_usage;

    float                          process_total_cpu;
    size_t                         process_total_mem;
    njt_lvlhsh_t                   prev_pids_work;
    njt_str_t                      old_pids;
    njt_int_t                      process_count;
    njt_int_t                      n_cpu;
    njt_int_t                      flush_interval;

    njt_pool_t                     *pool;
} njt_http_shm_status_sysinfo;



typedef struct {
    njt_http_shm_status_sysinfo             sys_info;
} njt_http_shm_status_main_conf_t;

typedef struct {
    njt_flag_t       format;
} njt_http_shm_status_loc_conf_t;

extern njt_module_t njt_http_shm_status_module;
extern njt_slab_pool_t *njt_shm_status_pool; 

#endif