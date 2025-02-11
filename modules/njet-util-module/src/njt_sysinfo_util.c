/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_core.h>
#include <njt_sysinfo_util.h>

#if (NJT_HAVE_PROC_STAT)

static njt_file_t                   njt_cpuinfo_file;

#define NJT_CPUINFO_FILE            "/proc/stat"


njt_int_t
njt_get_cpu_info(njt_str_t *cpunumber, njt_cpuinfo_t *cpuinfo, njt_log_t *log)
{
    u_char              buf[1024 * 1024];
    u_char             *p, *q, *last;
    ssize_t             n;
    njt_fd_t            fd;
    time_t              cputime;
    enum {
        sw_ignore = 0,
        sw_user,
        sw_nice,
        sw_sys,
        sw_idle,
        sw_iowait,
        sw_irq,
        sw_softirq ,
    } state;

    njt_memzero(cpuinfo, sizeof(njt_cpuinfo_t));

    // if (njt_cpuinfo_file.fd == 0) {

    fd = njt_open_file(NJT_CPUINFO_FILE, NJT_FILE_RDONLY,
                        NJT_FILE_OPEN,
                        NJT_FILE_DEFAULT_ACCESS);

    if (fd == NJT_INVALID_FILE) {
        njt_log_error(NJT_LOG_EMERG, log, njt_errno,
                        njt_open_file_n " \"%s\" failed",
                        NJT_CPUINFO_FILE);

        return NJT_ERROR;
    }

    njt_cpuinfo_file.name.data = (u_char *) NJT_CPUINFO_FILE;
    njt_cpuinfo_file.name.len = njt_strlen(NJT_CPUINFO_FILE);

    njt_cpuinfo_file.fd = fd;
    // }

    njt_cpuinfo_file.log = log;
    n = njt_read_file(&njt_cpuinfo_file, buf, sizeof(buf) - 1, 0);
    if (n == NJT_ERROR) {
        njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                      njt_read_file_n " \"%s\" failed",
                      NJT_CPUINFO_FILE);

        return NJT_ERROR;
    }

    p = buf;
    last = buf + n;

    for (; p < last; p++) {
        while(*p == ' ' || *p == '\n') {
            p++;
        }

        if (njt_strncasecmp((u_char *) cpunumber->data,
                            (u_char *) p, cpunumber->len) == 0)
        {
            q = (u_char *) strtok((char *) p, " ");
            for (state = 0; q; state++)
            {
                cputime = njt_atotm(q, strlen((char *) q));

                switch (state) {
                case sw_ignore:
                    break;
                case sw_user:
                    cpuinfo->usr = cputime;
                    break;
                case sw_nice:
                    cpuinfo->nice = cputime;
                    break;
                case sw_sys:
                    cpuinfo->sys = cputime;
                    break;
                case sw_idle:
                    cpuinfo->idle = cputime;
                    break;
                case sw_iowait:
                    cpuinfo->iowait = cputime;
                    break;
                case sw_irq:
                    cpuinfo->irq = cputime;
                    break;
                case sw_softirq:
                    cpuinfo->softirq = cputime;
                    break;
                }

                q = (u_char *) strtok(NULL, " ");
            }
            break;
        }
    }

    njt_close_file(fd);

    return NJT_OK;
}

#else

njt_int_t
njt_get_cpu_info(njt_str_t *cpunumber, njt_cpuinfo_t *cpuinfo, njt_log_t *log)
{
    njt_log_error(NJT_LOG_EMERG, log, 0,
                  "njt_get_cpu_info is unsupported under current os");

    return NJT_ERROR;
}

#endif


#if (NJT_HAVE_PROC_STAT)


njt_int_t
njt_get_process_cpu_info(njt_str_t *pid, njt_process_cpuinfo_t *cpuinfo, njt_log_t *log)
{
    u_char              buf[1024 * 1024];
    u_char             *p, *q, *last;
    ssize_t             n;
    njt_fd_t            fd;
    time_t              cputime;
    // u_char              *end;
    u_char              full_name[1024];
    // njt_str_t           str_full_name;
    int                 i=0;
    njt_file_t          njt_pid_cpuinfo_file;

    enum {
        sw_utime = 0,
        sw_stime,
        sw_cutime,
        sw_cstime
    } state;

    // str_full_name.data = full_name;
    njt_memzero(full_name, 1024);
    njt_snprintf(full_name, sizeof(full_name) - 1, 
        "/proc/%V/stat", pid);
    // str_full_name.len = end - full_name;

    njt_memzero(cpuinfo, sizeof(njt_process_cpuinfo_t));

    fd = njt_open_file(full_name, NJT_FILE_RDONLY,
                        NJT_FILE_OPEN,
                        NJT_FILE_DEFAULT_ACCESS);

    if (fd == NJT_INVALID_FILE) {
        njt_log_error(NJT_LOG_EMERG, log, njt_errno,
                        njt_open_file_n " \"%s\" failed",
                        full_name);

        return NJT_ERROR;
    }

    njt_pid_cpuinfo_file.name.data = (u_char *) full_name;
    njt_pid_cpuinfo_file.name.len = njt_strlen(full_name);

    njt_pid_cpuinfo_file.fd = fd;

    njt_pid_cpuinfo_file.log = log;
    n = njt_read_file(&njt_pid_cpuinfo_file, buf, sizeof(buf) - 1, 0);
    if (n == NJT_ERROR) {
        njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                      njt_read_file_n " \"%s\" failed",
                      full_name);

        return NJT_ERROR;
    }

    p = buf;
    last = buf + n;

    for (i=0; p < last; p++) {
        if(*p == ' ') {
            i++;
            p++;
            if(i == 13){
                break;
            }
        }
    }

    if(i < 13){
        njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                      "get pid:%V cpu info error, num < 13",
                      pid);

        return NJT_ERROR;
    }

    for (i=0; p < last; p++) {
        q = (u_char *) strtok((char *) p, " ");
        for (state = 0; q; state++)
        {
            cputime = njt_atotm(q, strlen((char *) q));

            switch (state) {
            case sw_utime:
                cpuinfo->utime = cputime;
                break;
            case sw_stime:
                cpuinfo->stime = cputime;
                break;
            case sw_cutime:
                cpuinfo->cutime = cputime;
                break;
            case sw_cstime:
                cpuinfo->cstime = cputime;
                break;
            }

            q = (u_char *) strtok(NULL, " ");
        }

        break;
    }

    njt_close_file(fd);
    return NJT_OK;
}


njt_int_t njt_get_cpu_usage(njt_str_t *cpunumber, njt_int_t *cpu_usage, time_t *diff_total){
    njt_uint_t          rc;
    njt_cpuinfo_t       cpuinfo;
    static time_t       prev_total = 0, prev_work = 0;
    time_t              work, total;
    
    rc = njt_get_cpu_info(cpunumber, &cpuinfo, njt_cycle->log);
    if(rc != NJT_OK){
        return NJT_ERROR;
    }

    work = cpuinfo.usr + cpuinfo.nice + cpuinfo.sys;
    total = work + cpuinfo.idle;
    if(diff_total != NULL){
        *diff_total = total - prev_total;
    }

    *cpu_usage = (njt_int_t)(100.0 * (work - prev_work) / (total - prev_total));

    njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
        " total cpu usage:%d  usr:%T  nice:%T  sys:%T idle:%T work:%T  prev_work:%T total:%T  pre_total:%T work-:%T total-:%T", 
        *cpu_usage, cpuinfo.usr, cpuinfo.nice, cpuinfo.sys, cpuinfo.idle,
        work, prev_work, total, prev_total, work - prev_work, total - prev_total);

    prev_total = total;
    prev_work = work;


    return NJT_OK;
}

#else

njt_int_t
njt_get_process_cpu_info(njt_str_t *pid, njt_process_cpuinfo_t *cpuinfo, njt_log_t *log)
{
    njt_log_error(NJT_LOG_EMERG, log, 0,
                  "njt_get_process_cpu_info is unsupported under current os");

    return NJT_ERROR;
}

njt_int_t njt_get_cpu_usage(njt_str_t *cpunumber, njt_int_t *cpu_usage, time_t *diff_total){
    njt_log_error(NJT_LOG_EMERG, log, 0,
        "njt_get_cpu_usage is unsupported under current os");

    return NJT_ERROR;
}

#endif

#if (NJT_HAVE_PROC_STAT)

#define NJT_MEMINFO_FILE            "/proc/meminfo"

njt_int_t njt_get_sys_meminfo(njt_meminfo_t *meminfo, njt_log_t *log) {
    njt_fd_t            fd;
    char                buf[128];
    char                name[64];
    char                unit[64];

    njt_memzero(meminfo, sizeof(njt_meminfo_t));

    fd = njt_open_file(NJT_MEMINFO_FILE, NJT_FILE_RDONLY,
        NJT_FILE_OPEN,
        NJT_FILE_DEFAULT_ACCESS);

    if (fd == NJT_INVALID_FILE) {
        njt_log_error(NJT_LOG_EMERG, log, njt_errno,
                njt_open_file_n " \"%s\" failed",
                NJT_MEMINFO_FILE);

        return NJT_ERROR;
    }

    fgets(buf, sizeof(buf), fd);
    sscanf(buf, "%s %u %s", name, &meminfo->total, unit);
    fgets(buf, sizeof(buf), fd);
    sscanf(buf, "%s %u %s", name, &meminfo->free, unit);
    fgets(buf, sizeof(buf), fd);
    sscanf(buf, "%s %u %s", name, &meminfo->avaliable, unit);

    njt_close_file(fd);

    return NJT_OK;
}


njt_int_t njt_get_process_meminfo(njt_str_t *pid, size_t *memsize, njt_log_t *log) {
    njt_fd_t            fd;
    char                filename[64];
    char                buf[256];
    unsigned long       size = 0;
    unsigned long       resident = 0;

    njt_snprintf(filename, sizeof(filename) - 1, "/proc/%V/statm", pid);

    fd = njt_open_file(filename, NJT_FILE_RDONLY,
        NJT_FILE_OPEN,
        NJT_FILE_DEFAULT_ACCESS);

    if (fd == NJT_INVALID_FILE) {
        njt_log_error(NJT_LOG_EMERG, log, njt_errno,
                njt_open_file_n " \"%s\" failed",
                filename);

        return NJT_ERROR;
    }
    
    fgets(buf, sizeof(buf), fd);
    sscanf(buf, "%lu %lu", &size, &resident);

    njt_close_file(fd);

    *memsize = resident * 4;

    return NJT_OK;
}


njt_int_t njt_get_sys_mem_usage(njt_meminfo_t *info, float *usage, njt_log_t *log) {

    if(NJT_ERROR == njt_get_sys_meminfo(info, log)){
        return NJT_ERROR;
    }

    *usage = 1.0 * (info->total - info->avaliable) / info->total;

    return NJT_OK;
}


//input: pid, log
//output: memsize, usage
njt_int_t njt_get_process_mem_usage(njt_str_t *pid, size_t *memsize, float *usage, njt_log_t *log) {
    njt_meminfo_t   info;
    float           sys_usage;

    if(NJT_ERROR == njt_get_process_meminfo(pid, memsize, log)){
        return NJT_ERROR;
    }

    if(NJT_ERROR == njt_get_sys_mem_usage(&info, &sys_usage, log)){
        return NJT_ERROR;
    }

    *usage = 1.0 * (*memsize) / info.total;

    return NJT_OK;
}

#else
njt_int_t njt_get_sys_meminfo(njt_meminfo_t *meminfo, njt_log_t *log){
    njt_log_error(NJT_LOG_EMERG, log, 0,
        "njt_get_sys_meminfo is unsupported under current os");

    return NJT_ERROR;
}


njt_int_t njt_get_process_meminfo(njt_str_t *pid, size_t *memsize, njt_log_t *log){
    njt_log_error(NJT_LOG_EMERG, log, 0,
        "njt_get_process_meminfo is unsupported under current os");

    return NJT_ERROR;
}

njt_int_t njt_get_sys_mem_usage(njt_meminfo_t *info, float *usage, njt_log_t *log){
    njt_log_error(NJT_LOG_EMERG, log, 0,
        "njt_get_sys_mem_usage is unsupported under current os");

    return NJT_ERROR;
}

njt_int_t njt_get_process_mem_usage(njt_str_t *pid, size_t *memsize, float *usage, njt_log_t *log){
    njt_log_error(NJT_LOG_EMERG, log, 0,
        "njt_get_process_mem_usage is unsupported under current os");

    return NJT_ERROR;
}

#endif
