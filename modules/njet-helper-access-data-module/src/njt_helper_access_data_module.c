/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_http.h>
#include <stdio.h>

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <unistd.h>
#include "njet_iot_emb.h"

#include <njt_mqconf_module.h>
#include <njt_http_client_util.h>   //包含util 头文件

#include "njt_helper_access_data_module.h"
#include "njt_rpc_result_util.h"

#include "njt_dynlog_parser.h"
#include "njt_http_kv_module.h"
#include "njt_hash_util.h"
#include "njt_http_dyn_module.h"
#include "gkhash.h"
#include "goaccess.h"
#include "xmalloc.h"
#include "settings.h"

void  free_holder (GHolder **holder);
njt_int_t njt_helper_init_output_path (njt_cycle_t     *cycle);
goaccess_shpool_ctx_t  goaccess_shpool_ctx;
helper_param g_param;
extern GHolder *holder;
extern GConf conf;

volatile njt_cycle_t  *njt_cycle;
extern njt_module_t  njt_http_log_module;
extern void * ht_db;

njt_helper_access_data_log_format_t g_njt_helper_access_data_log_format[NJT_HELPER_ACCESS_DATA_ARRAY_MAX];
njt_helper_access_data_log_format_t g_njt_helper_access_data_log_format_new[NJT_HELPER_ACCESS_DATA_ARRAY_MAX];



njt_helper_access_data_dyn_access_log_format_t g_njt_helper_access_data_dyn_access_log_format[NJT_HELPER_ACCESS_DATA_ARRAY_MAX];

njt_helper_access_data_log_format_t g_njt_helper_access_data_dyn_access_new_conf[NJT_HELPER_ACCESS_DATA_ARRAY_MAX];

njt_helper_access_data_dyn_access_api_loc_t *g_helper_access_data_dyn_access_api_loc;

volatile njt_int_t g_njt_helper_access_data_dyn_access_init_flag    = NJT_HELPER_ACCESS_DATA_DYN_ACCESS_UNITIT_FLAG; /*默认未初始化*/
volatile njt_int_t g_njt_helper_access_data_dynlog_conf_change_flag = NJT_HELPER_ACCESS_DATA_DYN_ACCESS_CONF_INIT_FLAG; /*默认未改变*/

static char g_njt_helper_access_data_prefix_path[NJT_HELPER_ACCESS_DATA_STR_LEN_MAX] = "";
                                                                                                     
void process_ctrl() {
    unsigned int cmd;
    njt_cycle_t *cycle = g_param.cycle;
    cmd = g_param.check_cmd_fp(cycle);

    if (cmd == NJT_HELPER_CMD_STOP)
    {
        njt_log_error(NJT_LOG_INFO, cycle->log, 0,
                      "helper access_data stop.\n");

        goto exit;
    }

    if (cmd == NJT_HELPER_CMD_RESTART)
    {
        njt_log_error(NJT_LOG_INFO, cycle->log, 0,
                      "helper access_data restart\n");
        goto exit;
    }
    if(conf.stop_processing) 
    {
	    goto exit;
    }
    return;
exit:
   if (conf.fifo_in != NULL && njt_delete_file(conf.fifo_in) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      njt_delete_file_n " \"%s\" failed", conf.fifo_in);
    }
    if (conf.fifo_out != NULL && njt_delete_file(conf.fifo_out) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      njt_delete_file_n " \"%s\" failed", conf.fifo_out);
    }
   exit(0);
}

void njt_helper_run(helper_param param)
{
    int argc = 5;
    char **argv;
    Logs *logs      = NULL;
    struct timespec refresh = {
    .tv_sec = 1,
    .tv_nsec = 0,
   };

    int             i; //ret;
    njt_cycle_t     *cycle;
    njt_int_t  rc;
    
    njt_http_log_main_conf_t *cmf;
    char *prefix_path;
    char debug_path[NJT_HELPER_ACCESS_DATA_STR_LEN_MAX] = "";
    g_param = param;
    //pthread_t goaccess_thread;
    
    
    char dst_format[NJT_ACCESS_DATA_FILE_LOGFORMAT_ARRAY_MAX] = "";
    njt_access_data_conf_file_logformat_t file_logformat;

    cycle = param.cycle;

    njt_cycle = cycle;
    if(goaccess_shpool_ctx.shpool == NULL) {
        njt_log_error(NJT_LOG_CRIT, cycle->log, 0, "not shpool, helper access exit");
        goto end;
    }

   
    argv = njt_alloc(argc * sizeof(char *), cycle->log);
    cmf = njt_http_cycle_get_module_main_conf(njt_cycle, njt_http_log_module);
    ht_db = cmf->sh->ht_db;

    if(goaccess_shpool_ctx.shpool == 0 || goaccess_shpool_ctx.shpool != cmf->sh->shpool) {
         goaccess_shpool_ctx.shpool = (njt_slab_pool_t *)cmf->sh->shpool;
         goaccess_shpool_ctx.rwlock = &cmf->sh->rwlock;
    }
    

    njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "helper access started");

    // 为每个argv元素分配内存并复制参数字符串
    for (i = 0; i < argc; i++) {
        argv[i] = (char *)malloc((NJT_HELPER_ACCESS_DATA_STR_LEN_MAX) * sizeof(char));
        if (argv[i] == NULL) {
            njt_log_error(NJT_LOG_ERR, cycle->log, 0, "argv[i] == NULL\n");
            goto end;
        }
        memset(argv[i],0,NJT_HELPER_ACCESS_DATA_STR_LEN_MAX);
    }


    prefix_path = njt_calloc(cycle->prefix.len + 1, cycle->log);

    njt_memcpy(prefix_path, (char *)cycle->prefix.data,cycle->prefix.len);
    njt_memcpy(g_njt_helper_access_data_prefix_path, (char *)cycle->prefix.data,cycle->prefix.len);

    strcpy(argv[0], "./goaccess");

    strcpy(argv[1], "-f");
    snprintf(argv[2], NJT_HELPER_ACCESS_DATA_STR_LEN_MAX * sizeof(char), "%s%s", prefix_path, NJT_HELPER_ACCESS_DATA_ACCESS_LOG);

    strcpy(argv[3], "-p");
    
    //snprintf(argv[4], NJT_HELPER_ACCESS_DATA_STR_LEN_MAX * sizeof(char), "%s%s", prefix_path, NJT_HELPER_ACCESS_DATA_GOACCESS_CONF);
    njt_memcpy(argv[4],param.conf_fullfn.data,param.conf_fullfn.len);

    strcpy(file_logformat.file_name, argv[2]);
    
    strcpy(file_logformat.logformat, dst_format);



    snprintf(debug_path, NJT_HELPER_ACCESS_DATA_STR_LEN_MAX * sizeof(char), "%s%s", prefix_path, NJT_HELPER_ACCESS_DATA_GOACCESS_DEBUG_LOG);
    dbg_log_open (debug_path);

    free_holder (&holder);
    logs = njet_helper_access_data_init(argc, argv);
    if (logs == NULL) {
        exit(2);
    }
    logs->glog = cmf->sh->glog; 
    rc = njt_helper_init_output_path(cycle);
    if(rc == NJT_ERROR) {
        goto end;
    }
    njet_helper_access_data_run(logs);

end:
    while(1) {
      process_ctrl();  //free_cmd_args
      if (nanosleep(&refresh, NULL) == -1 && errno != EINTR) {
        exit(0);
      }
    }
}


njt_int_t njt_helper_init_output_path (njt_cycle_t     *cycle) {
  int i;
  njt_str_t  full_name;
  for (i = 0; i < conf.output_format_idx; ++i) {
     full_name.len =  njt_strlen(conf.output_formats[i]);
     full_name.data = (u_char *)conf.output_formats[i];
     
    if(njt_conf_full_name((void *)cycle, &full_name, 0) != NJT_OK) {
         njt_log_error(NJT_LOG_ERR, cycle->log, 0,"njt_helper_init_output_path \"%V\", njt_conf_full_name error!", &full_name);
       return NJT_ERROR;
    }
    njt_log_error(NJT_LOG_DEBUG, cycle->log, 0,"njt_helper_init_output_path \"%V\"!", &full_name);
    conf.output_formats[i] = njt_str2char(cycle->pool,full_name);
    
  }
  return NJT_OK;
}


/*
注：当前版本号是 1
#define NJT_HELPER_VER          1
*/
unsigned int njt_helper_check_version (void)
{
    return NJT_HELPER_VER;
}

/*
返回1，表示该so的copilot进程，不会在reload的时候重启。
放回0，表示该so的copilot进程，会在reload的时候重启。
注1：so可以不实现该接口。若不实现，则等同于返回0。
注2：如果so实现该接口并且返回1，那么在reload的时候该so的copilot进程不会重启，
但是有一点需要注意：reload的时候配置文件中需保留原helper指令，这是配置上的强制要求，
不满足此要求会导致reload失败。
*/
/*
unsigned int njt_helper_ignore_reload(void)
{
    return 1;
}
*/

njt_module_t njt_helper_access_data_module = {
    NJT_MODULE_V1,      
    NULL,               /* module context */
    NULL,               /* module directives */
    NJT_HTTP_MODULE,    /* module type */
    NULL,               /* init master */
    NULL,               /* init module */
    NULL,               /* init process */
    NULL,               /* init thread */
    NULL,               /* exit thread */
    NULL,               /* exit process */
    NULL,               /* exit master */
    NJT_MODULE_V1_PADDING
};

int   go_strcmp (const char *s1, const char *s2) {
    return strcmp(s1,s2);
}


char *njt_str2char(njt_pool_t *pool, njt_str_t src)
{
    char *p;
    p = njt_pcalloc(pool, src.len + 1);
    if (p != NULL)
    {
        njt_memcpy(p, src.data, src.len);
    }
    return p;
}
