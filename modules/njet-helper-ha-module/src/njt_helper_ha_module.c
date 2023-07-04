/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_http.h>
#include <stdio.h>
#include <unistd.h>
#include <njt_vrrp_emb.h>
#include <njt_mqconf_module.h>
#include <pthread.h>

static int njt_helper_ha_reopening=0;

static void
njt_helper_ha_sigal_handler(int signo, siginfo_t *siginfo, void *ucontext)
{
    njt_helper_ha_reopening=1;
}

void *njt_helper_emb_run(void *p)
{
    njt_vrrp_emb_run();
    return NULL;
}

void njt_helper_run(helper_param param)
{
    njt_cycle_t *cycle;
    char *vrrp_log;
    u_char *p;
    pthread_t thread1;
    int  iret1;
    unsigned int cmd;
    struct sigaction   sa;

    cycle = param.cycle;

    vrrp_log = njt_calloc(cycle->prefix.len + 14, cycle->log);
    p = njt_cpymem(vrrp_log, cycle->prefix.data, cycle->prefix.len);
    p = njt_cpymem(p, "logs/njet.log", 13);
    *p = '\0';
    if (0 != (njt_vrrp_emb_init((const char *)param.conf_fullfn.data, vrrp_log))) {
        njt_free(vrrp_log);
        njt_log_error(NJT_LOG_ERR, cycle->log, 0,
            "njt vrrp init error\n");
        exit(2);
    };

    iret1 = pthread_create(&thread1, NULL, njt_helper_emb_run, (void *)&param);
    if (iret1) {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0,
            "njt vrrp init error\n");
        exit(2);
    }
    pthread_setname_np(thread1, "vrrp main");

    njt_memzero(&sa, sizeof(struct sigaction));
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = njt_helper_ha_sigal_handler;
    sa.sa_flags = SA_SIGINFO;
    if (sigaction(SIGHUP, &sa, NULL) == -1) {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0,
            "njt add vrrp signal handler error\n");
    }

    for (;;) {
        cmd = param.check_cmd_fp(cycle);
        if (cmd == NJT_HELPER_CMD_STOP) {
            njt_log_error(NJT_LOG_INFO, cycle->log, 0,
                "helper ha stop\n");
            njt_vrrp_emb_stop();
            goto exit;
        }
        if (cmd == NJT_HELPER_CMD_RESTART) {
            njt_log_error(NJT_LOG_INFO, cycle->log, 0,
                "helper ha restart\n");
            njt_vrrp_emb_stop();
            goto exit;
        }
        if (njt_helper_ha_reopening) {
            njt_helper_ha_reopening=0;
            njt_vrrp_reload_config();
        }
    }
exit:
    pthread_join(thread1, NULL);
    njt_free(vrrp_log);
    return;
}

unsigned int njt_helper_check_version(void)
{
    return NJT_HELPER_VER;
}

unsigned int njt_helper_ignore_reload(void)
{
    return 1;
}

njt_module_t njt_helper_ha_module = { 0 };
