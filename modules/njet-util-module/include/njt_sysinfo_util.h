#ifndef NJET_MAIN_NJT_SYSINFO_UTIL_H
#define NJET_MAIN_NJT_SYSINFO_UTIL_H

#include <njt_core.h>
// #include <njt_stream.h>

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



typedef struct {
    unsigned long total;
    unsigned long free;
    unsigned long avaliable;
}njt_meminfo_t;


njt_int_t
njt_get_cpu_info(njt_str_t *cpunumber, njt_cpuinfo_t *cpuinfo, njt_log_t *log);


njt_int_t
njt_sysguard_get_cpu_number(njt_log_t *log);


njt_int_t
njt_get_process_cpu_info(njt_str_t *pid, njt_process_cpuinfo_t *p_cpuinfo, njt_log_t *log);


njt_int_t njt_get_sys_meminfo(njt_meminfo_t *meminfo, njt_log_t *log);
njt_int_t njt_get_process_meminfo(njt_str_t *pid, size_t *memsize, njt_log_t *log);

njt_int_t njt_get_sys_mem_usage(njt_meminfo_t *info, njt_int_t *usage, njt_log_t *log);
njt_int_t njt_get_process_mem_usage(njt_str_t *pid, size_t *memsize, njt_int_t *usage, njt_log_t *log);

#endif //NJET_MAIN_NJT_SYSINFO_UTIL_H