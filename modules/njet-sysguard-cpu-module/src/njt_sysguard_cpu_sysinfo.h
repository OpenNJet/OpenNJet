
/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */

#ifndef _NJT_SYSLOAD_SYSINFO_H_INCLUDED_
#define _NJT_SYSLOAD_SYSINFO_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>

#define SYSLOAD_MAX_WORKER_C 512

#if (NJT_HAVE_SYSINFO)
#include <sys/sysinfo.h>
#endif

typedef struct {
    time_t usr;
    time_t nice;
    time_t sys;
    time_t idle;
    time_t iowait;
    time_t irq;
    time_t softirq;
}njt_cpuinfo_t;

typedef struct {
    time_t utime;
    time_t stime;
    time_t cutime;
    time_t cstime;
}njt_process_cpuinfo_t;

njt_int_t
njt_sysload_lvlhsh_test(njt_lvlhsh_query_t *lhq, void *data);



// njt_int_t njt_sysguard_getusageavg(njt_int_t avg[], njt_int_t nelem, njt_log_t *log);


njt_int_t
njt_get_cpu_info(njt_str_t *cpunumber, njt_cpuinfo_t *cpuinfo, njt_log_t *log);

njt_int_t
njt_get_process_cpu_info(njt_str_t *pid, njt_process_cpuinfo_t *p_cpuinfo, njt_log_t *log);

njt_int_t njt_get_cpu_usage(njt_str_t *cpunumber, njt_int_t *cpu_usage, time_t *diff_total);

njt_int_t
njt_get_process_average_cpu_usage(njt_pool_t *pool, njt_int_t n_cpu, 
        njt_int_t *average_cpu_usage, njt_uint_t worker_n,
        njt_str_t *pids_v, njt_lvlhsh_t *prev_pids_work, time_t diff_total);

njt_int_t
njt_sysguard_get_cpu_number();

#endif /* _NJT_SYSLOAD_SYSINFO_H_INCLUDED_ */

