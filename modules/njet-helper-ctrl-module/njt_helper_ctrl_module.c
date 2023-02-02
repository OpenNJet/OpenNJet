#include <njt_http.h>
#include <stdio.h>
#include <unistd.h>


#define NJT_HELPER_CMD_NO       0
#define NJT_HELPER_CMD_STOP     1
#define NJT_HELPER_CMD_RESTART  2

#define NJT_HELPER_VER          1

typedef unsigned int (*helper_check_cmd_fp)(void *ctx);

typedef struct {
    njt_str_t   conf_fn;
    njt_str_t   conf_fullfn;
    helper_check_cmd_fp check_cmd_fp;
    void *ctx;
    void *cycle;//njt_cycle_t *cycle;
} helper_param;


void 
njt_helper_run(helper_param param)
{
    unsigned int cmd;
    char confname[128];
    njt_cycle_t *cycle;

    printf("helper ctrl started\n");

    memset(confname, 0, sizeof(confname));
    memcpy(confname, param.conf_fn.data, param.conf_fn.len);

    njt_reconfigure = 1;
    cycle = param.cycle;
    cycle->conf_file.data = param.conf_fullfn.data;
    cycle->conf_file.len = param.conf_fullfn.len;

    for ( ;; ) {
        if (njt_reconfigure) {
            njt_reconfigure = 0;

            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "ctrl reconfiguring");
            cycle = njt_init_cycle(cycle);
            if (cycle == NULL) {
                cycle = (njt_cycle_t *) njt_cycle;
                njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "ctrl reconfiguring continue");
                continue;
            }

            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "ctrl reconfiguring done");

            njt_cycle = cycle;


            njt_uint_t  i;
            for (i = 0; cycle->modules[i]; i++) {
                if (cycle->modules[i]->init_process) {
                    if (cycle->modules[i]->init_process(cycle) == NJT_ERROR) {
                        /* fatal */
                        exit(2);
                    }
                }
            }
        }

        cmd = param.check_cmd_fp(cycle);

        if (njt_reopen) {
            njt_reopen = 0;
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "reopening logs");
            njt_reopen_files(cycle, -1);
        }

        if (cmd == NJT_HELPER_CMD_STOP) {
            printf("helper ctrl stop\n");
            break;            
        }

        if (cmd == NJT_HELPER_CMD_RESTART) {
            njt_reconfigure = 1;
            continue;
        }
    }
    
    return;
}


unsigned int njt_helper_check_version(void)
{
    return NJT_HELPER_VER;
}


njt_module_t njt_helper_ctrl_module = {0};
