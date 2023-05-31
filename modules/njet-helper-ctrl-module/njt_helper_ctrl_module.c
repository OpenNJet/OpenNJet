#include <njt_http.h>
#include <stdio.h>
#include <unistd.h>


#define NJT_KEEP_MASTER_CYCLE   1

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


#if (NJT_KEEP_MASTER_CYCLE)
    njt_cycle_t *njet_master_cycle = NULL;
#endif

extern void njt_helper_process_exit(njt_cycle_t *cycle);

void 
njt_helper_run(helper_param param)
{
    unsigned int cmd;
    njt_cycle_t *cycle;

#if (NJT_KEEP_MASTER_CYCLE)
    njt_cycle_t    init_cycle;

    njet_master_cycle = param.cycle;
    njt_memzero(&init_cycle, sizeof(njt_cycle_t));
    init_cycle.prefix = njet_master_cycle->prefix;
    init_cycle.conf_prefix = njet_master_cycle->conf_prefix;
    init_cycle.log = njet_master_cycle->log;
    init_cycle.pool = njt_create_pool(1024,  njet_master_cycle->log);
    if (init_cycle.pool == NULL) {
        return ;
    }

    cycle = &init_cycle;
#else
    cycle = param.cycle;
#endif

    cycle->conf_file.data = param.conf_fullfn.data;
    cycle->conf_file.len = param.conf_fullfn.len;
    njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "helper ctrl started");
    njt_reconfigure = 1;

    for ( ;; ) {
        if (njt_reconfigure) {
            njt_reconfigure = 0;

            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "ctrl reconfiguring");
            cycle = njt_init_cycle(cycle);
            if (cycle == NULL) {
                cycle = (njt_cycle_t *) njt_cycle;
                njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "ctrl reconfiguring continue");
                return;
            }
#if (NJT_KEEP_MASTER_CYCLE)
            cycle->old_cycle = njet_master_cycle;
#endif
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "ctrl reconfiguring done");
            njt_cycle = cycle;

            njt_uint_t  i;
            for (i = 0; cycle->modules[i]; i++) {
                if (cycle->modules[i]->init_process) {
                    if (cycle->modules[i]->init_process(cycle) == NJT_ERROR) {
                        /* fatal */
                        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "ctrl fatal error");
                        njt_log_error(NJT_LOG_EMERG, cycle->log, 0, "ctrl fatal error");
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
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "helper ctrl exit");
            njt_helper_process_exit(cycle);
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
