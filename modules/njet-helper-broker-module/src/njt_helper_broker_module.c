/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_http.h>
#include <stdio.h>
#include <unistd.h>
#include "njet_iot_emb.h"
#include <njt_mqconf_module.h>

void njt_helper_run(helper_param param)
{
    unsigned int cmd;
    njt_cycle_t *cycle;

    cycle = param.cycle;

    char *prefix;
    prefix = njt_calloc(cycle->prefix.len + 1, cycle->log);
    memcpy(prefix, cycle->prefix.data, cycle->prefix.len);
    prefix[cycle->prefix.len] = '\0';
    if (0 != njet_iot_init((const char *)prefix, (const char *)param.conf_fullfn.data))
    {
        njt_free(prefix);
        njt_log_error(NJT_LOG_ERR, cycle->log, 0,
                      "njt iot init error\n");
        exit(2);
    };
    njt_free(prefix);
    for (;;)
    {

        cmd = param.check_cmd_fp(cycle);
        if (cmd == NJT_HELPER_CMD_STOP)
        {
            njt_log_error(NJT_LOG_INFO, cycle->log, 0,
                          "helper broker stop\n");
            njet_iot_exit();
            return;
        }

        if (cmd == NJT_HELPER_CMD_RESTART)
        {
            njt_log_error(NJT_LOG_INFO, cycle->log, 0,
                          "helper broker restart\n");
            njet_iot_exit();
        }

        int ret;
        ret = njet_iot_run();
        if (ret == -8888)
            break;
    }
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

njt_module_t njt_helper_broker_module = {
    NJT_MODULE_V1,
    NULL,
    NULL,
    NJT_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NJT_MODULE_V1_PADDING};
