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
    void *cycle;
} helper_param;


njt_pid_t njt_helper_go_dynconf_start(njt_cycle_t *cycle, char *prefix, char *full_fn);

void 
njt_helper_run(helper_param param)
{
    int signo;
    njt_err_t err;
    unsigned int cmd;
    char *prefix, *conf_fn;
    njt_cycle_t *cycle;
    njt_pid_t go_coplilot_pid;
    njt_str_t json_file;


    // printf("start dynconf helper\n");
    cycle = param.cycle;
    json_file.data = njt_calloc(28, cycle->log);
    njt_str_set(&json_file, "njet_full_conf.json");
    njt_conf_save_to_file(cycle->pool, cycle->log, cycle->conf_root, &json_file);
    
    
    
    prefix = njt_calloc(cycle->prefix.len + 1, cycle->log);
    njt_cpystrn((u_char *)prefix, cycle->prefix.data, cycle->prefix.len + 1);
    // printf("prefix: %s \n", prefix);
    conf_fn = njt_calloc(param.conf_fn.len + 1, cycle->log);
    njt_cpystrn((u_char *)conf_fn, param.conf_fn.data, param.conf_fn.len + 1);
    // printf("prefix: %s \n", conf_fn);
    njt_reconfigure = 1;
    go_coplilot_pid = NJT_INVALID_PID;

    for ( ;; ) {
        if (njt_reconfigure) {
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "helper go conf-merge start/reconfiguring");
            if (go_coplilot_pid != NJT_INVALID_PID) {
                signo = njt_signal_value(NJT_TERMINATE_SIGNAL);
                if (kill(go_coplilot_pid, signo) == -1) {
                    err = njt_errno;
                    njt_log_error(NJT_LOG_ALERT, cycle->log, err,
                          "kill go conf-merge ctrl-o(%P, %d) failed", go_coplilot_pid, signo);
                }
            }

            go_coplilot_pid = njt_helper_go_dynconf_start(cycle, prefix, conf_fn);
            if (go_coplilot_pid == NJT_INVALID_PID) {
                njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "helper go conf-merge start/reconfiguring failed");
            } else {
                njt_reconfigure = 0;
            }
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "helper go conf-merge start/reconfiguring done");
        }

        cmd = param.check_cmd_fp(cycle);
        if (njt_reopen) {
            njt_reopen = 0;
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "reopening logs");
            njt_reopen_files(cycle, -1);
        }

        if (cmd == NJT_HELPER_CMD_STOP) {
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "helper go conf-merge exit");
            signo = njt_signal_value(NJT_TERMINATE_SIGNAL);
            kill(go_coplilot_pid, signo);
            njt_free(prefix);
            njt_free(conf_fn);
            break;            
        }

        if (cmd == NJT_HELPER_CMD_RESTART) {
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "helper go conf-merge restart");
            njt_reconfigure = 1;
        }
    }
    
    return;
}

njt_pid_t njt_helper_go_dynconf_start(njt_cycle_t *cycle, char *prefix, char *conf_fn) {
    njt_exec_ctx_t ctx;
    char *n, *p;
    char *name = "go-dynconf-helper";
    njt_pid_t pid;
    
    n = njt_calloc(njt_strlen(prefix) + njt_strlen(name) + 1, cycle->log); 
    p = (char *)njt_cpymem(n, prefix, njt_strlen(prefix));
    njt_cpystrn((u_char *)p, (u_char *)name, strlen(name) + 1);

    ctx.path = n;
    ctx.name = "go-conf-merge in njt_execute";
    // printf("exe: '%s %s %s %s %s' \n", name, "-p", prefix, "-c", conf_fn);
    ctx.argv = (char* const[]){name, "-p", prefix, "-c", conf_fn, NULL};
    ctx.envp = (char* const[]){NULL};
    njt_msleep(2200);
    pid = njt_execute(cycle, &ctx);

    njt_free(n);
    return pid;
}


unsigned int njt_helper_check_version(void)
{
    return NJT_HELPER_VER;
}


njt_module_t njt_helper_dynconf_update_module = {0};
