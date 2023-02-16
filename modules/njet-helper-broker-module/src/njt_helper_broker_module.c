#include <njt_http.h>
#include <stdio.h>
#include <unistd.h>
#include "mosquitto_emb.h"
#include <njt_mqconf_module.h>

void njt_helper_run(helper_param param)
{
    unsigned int cmd;
    njt_cycle_t *cycle;

    cycle = param.cycle;

    if (0 != mqtt_init((const char *)param.conf_fullfn.data))
    {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0,
                      "mqtt init error\n");
        exit(2);
    };

    for (;;)
    {

        cmd = param.check_cmd_fp(cycle);
        if (cmd == NJT_HELPER_CMD_STOP)
        {
            njt_log_error(NJT_LOG_INFO, cycle->log, 0,
                          "helper broker stop\n");
            mqtt_exit();
            return;
        }

        if (cmd == NJT_HELPER_CMD_RESTART)
        {
            njt_log_error(NJT_LOG_INFO, cycle->log, 0,
                          "helper broker restart\n");
            mqtt_exit();
        }

        int ret;
        ret = mqtt_run();
        if (ret == -8888)
            break;
    }
    return;
}

unsigned int njt_helper_check_version(void)
{
    return NJT_HELPER_VER;
}

njt_module_t njt_helper_broker_module = {
    NJT_MODULE_V1,
    NULL,
    NULL,
    NJT_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NJT_MODULE_V1_PADDING};
