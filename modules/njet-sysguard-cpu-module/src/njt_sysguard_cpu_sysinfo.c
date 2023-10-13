
/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */


#include "njt_sysguard_cpu_sysinfo.h"

const njt_lvlhsh_proto_t  njt_sysload_lvlhsh_proto = {
    NJT_LVLHSH_LARGE_MEMALIGN,
    njt_sysload_lvlhsh_test,
    njt_lvlhsh_pool_alloc,
    njt_lvlhsh_pool_free,
};


njt_int_t
njt_sysload_lvlhsh_test(njt_lvlhsh_query_t *lhq, void *data)
{
    //ignore value compare, just return ok
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



njt_int_t
njt_get_process_average_cpu_usage(njt_pool_t *pool, njt_int_t *average_cpu_usage, njt_uint_t worker_n,
        njt_str_t *pids_v, njt_lvlhsh_t *prev_pids_work, time_t diff_total){
    njt_str_t                       s_pid;
    njt_uint_t                      i;
    njt_process_cpuinfo_t           p_cpuinfo;
    njt_uint_t                      rc;
    static time_t                   prev_pid_work;
    time_t                          total = 0, work = 0;
    njt_uint_t                      real_work = 0;
    time_t                          diff_work = 0;
    njt_int_t                       pid_cpu_usage;
    njt_int_t                       total_pid_cpu_usage = 0;
    njt_lvlhsh_query_t              lhq;
    njt_flag_t                      pid_exist;
    time_t                          *pid_work;
    u_char                          *pid_start, *pid_index;

    *average_cpu_usage = 0;

    njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
        "get all pids:%V", pids_v);

    pid_start = pids_v->data;
    pid_index = pids_v->data;

    for(i = 0; i < pids_v->len; i++){
        if(pids_v->data[i] != '_'){
            pid_index++;
        }else{
            s_pid.data = pid_start;
            s_pid.len = pid_index - pid_start;

            pid_index++;
            pid_start = pid_index;

            rc = njt_get_process_cpu_info(&s_pid, &p_cpuinfo, njt_cycle->log);
            if(rc != NJT_OK){
                njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, " get process:%V cpu info error", &s_pid);
                continue ;
            }

            prev_pid_work = 0;
            lhq.key = s_pid;
            lhq.key_hash = njt_murmur_hash2(lhq.key.data, lhq.key.len);
            lhq.proto = &njt_sysload_lvlhsh_proto;
            lhq.pool = pool;
            pid_exist = 0;
            //find
            rc = njt_lvlhsh_find(prev_pids_work, &lhq);
            if(rc == NJT_OK){
                //find
                prev_pid_work = *(time_t *)lhq.value;
                pid_exist = 1;
    //                         njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0,
    // "====================find spid:%V prev_pid_work:%d", &s_pid, prev_pid_work);   
            }else{
    //                         njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0,
    // "====================not find spid:%V  prev_pid_work:%d", &s_pid, prev_pid_work); 
            }
  
            real_work++;
            work = p_cpuinfo.utime + p_cpuinfo.stime + p_cpuinfo.cutime + p_cpuinfo.cstime;
            diff_work = work - prev_pid_work;
            total += diff_work;

            pid_cpu_usage = (njt_int_t)(100.0 * njt_ncpu * diff_work / diff_total);

            njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
                " get process:%V cpu_usage:%d njt_ncpu:%d utime:%T stime:%T cutime:%T cstime:%T work:%T pre_work:%T diff_work:%T diff_total:%T",
                &s_pid, pid_cpu_usage, njt_ncpu, p_cpuinfo.utime, p_cpuinfo.stime,
                p_cpuinfo.cutime, p_cpuinfo.cstime, work, prev_pid_work, diff_work, diff_total);
            total_pid_cpu_usage += pid_cpu_usage;

            //update pid work
            if(pid_exist){
                pid_work = lhq.value;
                *pid_work = work;
            }else{
                lhq.key = s_pid;
                lhq.key_hash = njt_murmur_hash2(lhq.key.data, lhq.key.len);
                lhq.proto = &njt_sysload_lvlhsh_proto;
                lhq.pool = pool;

                pid_work = njt_pcalloc(pool, sizeof(time_t));
                if(pid_work == NULL){
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                                "sysload create pid work malloc error");
                    continue ;
                }

                *pid_work = work;

                lhq.value = pid_work;
                rc = njt_lvlhsh_insert(prev_pids_work, &lhq);
                if(rc != NJT_OK){
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                                "sysload lvlhash insert fail");
                    continue ;
                }
            }
        }
    }

    if(real_work < 1 || diff_work == 0){
        return NJT_OK;
    }

    *average_cpu_usage = total_pid_cpu_usage / real_work;

    return NJT_OK;
}


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

    if (njt_cpuinfo_file.fd == 0) {

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
    }

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

#else

njt_int_t
njt_get_process_cpu_info(njt_str_t *pid, njt_process_cpuinfo_t *cpuinfo, njt_log_t *log)
{
    njt_log_error(NJT_LOG_EMERG, log, 0,
                  "njt_get_process_cpu_info is unsupported under current os");

    return NJT_ERROR;
}

#endif




