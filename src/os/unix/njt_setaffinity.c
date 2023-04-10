
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


#if (NJT_HAVE_CPUSET_SETAFFINITY)

void
njt_setaffinity(njt_cpuset_t *cpu_affinity, njt_log_t *log)
{
    njt_uint_t  i;

    for (i = 0; i < CPU_SETSIZE; i++) {
        if (CPU_ISSET(i, cpu_affinity)) {
            njt_log_error(NJT_LOG_NOTICE, log, 0,
                          "cpuset_setaffinity(): using cpu #%ui", i);
        }
    }

    if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1,
                           sizeof(cpuset_t), cpu_affinity) == -1)
    {
        njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                      "cpuset_setaffinity() failed");
    }
}

#elif (NJT_HAVE_SCHED_SETAFFINITY)

void
njt_setaffinity(njt_cpuset_t *cpu_affinity, njt_log_t *log)
{
    njt_uint_t  i;

    for (i = 0; i < CPU_SETSIZE; i++) {
        if (CPU_ISSET(i, cpu_affinity)) {
            njt_log_error(NJT_LOG_NOTICE, log, 0,
                          "sched_setaffinity(): using cpu #%ui", i);
        }
    }

    if (sched_setaffinity(0, sizeof(cpu_set_t), cpu_affinity) == -1) {
        njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                      "sched_setaffinity() failed");
    }
}

#endif
