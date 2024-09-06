#include <njt_http.h>
#include <stdio.h>
#include <unistd.h>
#include <njt_mqconf_module.h>

njt_pid_t njt_helper_registry_sync_start(njt_cycle_t *cycle, char *prefix, char *conf_fn) {
    njt_exec_ctx_t ctx;
    char *exe, *p;
    char *name = "sbin/registry-sync";
    njt_pid_t pid;
    
    exe = njt_calloc(njt_strlen(prefix) + njt_strlen(name) + 1, cycle->log); 
    p = (char *)njt_cpymem(exe, prefix, njt_strlen(prefix));
    njt_cpystrn((u_char *)p, (u_char *)name, strlen(name) + 1);

    ctx.path = exe;
    ctx.name = "registry-sync in njt_execute";
    njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "start registry: '%s %s %s  \n", exe,  "--config.file", conf_fn);
    ctx.argv = (char* const[]){exe, "--config.file", conf_fn, NULL};
    ctx.envp = (char* const[]){NULL};
    pid = njt_execute(cycle, &ctx);

    njt_free(exe);
    return pid;
}

void 
njt_helper_run(helper_param param)
{
    int signo;
    njt_err_t err;
    unsigned int cmd;
    char *prefix, *conf_fn;
    njt_cycle_t *cycle;
    njt_pid_t go_coplilot_pid;

    cycle = param.cycle;
    
    prefix = njt_calloc(cycle->prefix.len + 1, cycle->log);
    njt_cpystrn((u_char *)prefix, cycle->prefix.data, cycle->prefix.len + 1);

    conf_fn = njt_calloc(param.conf_fullfn.len + 1, cycle->log);
    njt_cpystrn((u_char *)conf_fn, param.conf_fullfn.data, param.conf_fullfn.len+1);

    njt_reconfigure = 1;
    go_coplilot_pid = NJT_INVALID_PID;

    for ( ;; ) {
        if (njt_reconfigure) {
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "helper registry-sync start/reconfiguring");
            if (go_coplilot_pid != NJT_INVALID_PID) {
                signo = njt_signal_value(NJT_TERMINATE_SIGNAL);
                if (kill(go_coplilot_pid, signo) == -1) {
                    err = njt_errno;
                    njt_log_error(NJT_LOG_ALERT, cycle->log, err,
                          "kill registry-sync ctrl-o(%P, %d) failed", go_coplilot_pid, signo);
                }
            }

            go_coplilot_pid = njt_helper_registry_sync_start(cycle, prefix, conf_fn);
            if (go_coplilot_pid == NJT_INVALID_PID) {
                njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "helper registry-sync start/reconfiguring failed");
            } else {
                njt_reconfigure = 0;
            }
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "helper registry-sync start/reconfiguring done");
        }

        cmd = param.check_cmd_fp(cycle);
        if (njt_reopen) {
            njt_reopen = 0;
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "reopening logs");
            njt_reopen_files(cycle, -1);
        }

        if (cmd == NJT_HELPER_CMD_STOP) {
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "helper registry-sync exit");
            signo = njt_signal_value(NJT_TERMINATE_SIGNAL);
            kill(go_coplilot_pid, signo);
            njt_free(prefix);
            njt_free(conf_fn);
            break;            
        }

        if (cmd == NJT_HELPER_CMD_RESTART) {
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "helper registry-sync restart");
            njt_reconfigure = 1;
        }
    }
    
    return;
}

unsigned int njt_helper_check_version(void)
{
    return NJT_HELPER_VER;
}


njt_module_t njt_helper_registry_sync_module = {0};
