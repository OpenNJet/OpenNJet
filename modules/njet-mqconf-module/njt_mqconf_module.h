#ifndef NJT_MQCONF_MODULE_H_
#define NJT_MQCONF_MODULE_H_
#include <njt_core.h>
typedef struct
{
    njt_str_t admin_server;
    njt_str_t admin_client;
    njt_str_t cluster_name;
    njt_str_t node_name;
    njt_str_t dyn_conf;
	njt_int_t worker_cnt;
	njt_array_t  helper;
} njt_mqconf_conf_t;


typedef unsigned int (*helper_check_cmd_fp)(void *ctx);


#define NJT_HELPER_CMD_NO       0
#define NJT_HELPER_CMD_STOP     1
#define NJT_HELPER_CMD_RESTART  2


typedef struct {
    njt_str_t   conf_fn;
    njt_str_t   conf_fullfn;
    helper_check_cmd_fp check_cmd_fp;
    void *ctx;
    void *cycle;//njt_cycle_t *cycle;
} helper_param;

typedef void (*njt_helper_run_fp)(helper_param param);

typedef struct {
    helper_param         param;
    njt_helper_run_fp    run_fp;
    void                *handle;
    njt_str_t            file;
    njt_str_t            label;
    njt_int_t            reload;
    time_t               start_time;
    time_t               start_time_bef;
} njt_helper_ctx;


typedef unsigned int (*njt_helper_check_fp)(void);

#define NJT_HELPER_VER          1


#endif
