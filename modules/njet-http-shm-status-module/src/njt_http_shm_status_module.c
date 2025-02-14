

/*
 * Copyright (C), 2021-2024, TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_str_util.h>
#include <njt_sysinfo_util.h>
#include "njt_http_shm_status_module.h"
#include "njt_http_shm_status_display.h"


static void *njt_http_shm_status_create_loc_conf(njt_conf_t *cf);
static void njt_http_shm_status_sysinfo_update_handler(njt_event_t *ev);
njt_int_t
njt_http_shm_status_sysinfo_lvlhsh_test(njt_lvlhsh_query_t *lhq, void *data);
static njt_int_t njt_http_shm_status_init_module(njt_cycle_t *cycle);
static njt_int_t njt_http_shm_status_init_process(njt_cycle_t *cycle);
static njt_int_t njt_http_shm_status_sysinfo_get_cpu_usage(njt_str_t *cpunumber, float *cpu_usage, time_t *diff_total);

njt_int_t
njt_http_shm_status_sysinfo_of_process(njt_http_shm_status_sysinfo *sysinfo,
        njt_str_t *pids_v, njt_str_t *filter_pids_v, time_t diff_total);

extern njt_cycle_t *njet_master_cycle;

static njt_conf_enum_t njt_http_shm_status_display_format[] = {
    { njt_string("json"), NJT_HTTP_SHM_STATUS_FORMAT_JSON},
    { njt_string("html"), NJT_HTTP_SHM_STATUS_FORMAT_HTML},
    { njt_string("jsp"), NJT_HTTP_SHM_STATUS_FORMAT_JSONP},
    { njt_string("prometheus"), NJT_HTTP_SHM_STATUS_FORMAT_PROMETHEUS},
    { njt_null_string, 0}
};

const njt_lvlhsh_proto_t  njt_http_shm_status_sysinfo_lvlhsh_proto = {
    NJT_LVLHSH_LARGE_MEMALIGN,
    njt_http_shm_status_sysinfo_lvlhsh_test,
    njt_lvlhsh_pool_alloc,
    njt_lvlhsh_pool_free,
};

static njt_command_t njt_http_shm_status_commands[] = {

    { njt_string("shm_status_display"),
      NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_NOARGS|NJT_CONF_TAKE1,
      njt_http_shm_status_display,
      0,
      0,
      NULL },

    { njt_string("vhost_traffic_status_display_format"),
      NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
      njt_conf_set_enum_slot,
      NJT_HTTP_LOC_CONF_OFFSET,
      offsetof(njt_http_shm_status_loc_conf_t, format),
      &njt_http_shm_status_display_format },

    njt_null_command
};   


static njt_http_module_t njt_http_shm_status_module_ctx = {
    NULL,                           /* preconfiguration */
    NULL,                           /* postconfiguration */

    NULL,                           /* create main configuration */
    NULL,                           /* init main configuration */

    NULL,                           /* create server configuration */
    NULL,                           /* merge server configuration */

    njt_http_shm_status_create_loc_conf,  /* create location configuration */
    NULL,                           /* merge location configuration */
};


njt_module_t njt_http_shm_status_module = {
    NJT_MODULE_V1,
    &njt_http_shm_status_module_ctx,   /* module context */
    njt_http_shm_status_commands,      /* module directives */
    NJT_HTTP_MODULE,                   /* module type */
    NULL,                              /* init master */
    njt_http_shm_status_init_module,   /* init module */
    njt_http_shm_status_init_process,  /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NJT_MODULE_V1_PADDING
};

static void *
njt_http_shm_status_create_loc_conf(njt_conf_t *cf)
{
    njt_http_shm_status_loc_conf_t *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_shm_status_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->format = NJT_HTTP_SHM_STATUS_FORMAT_JSON;

    return conf;
}


njt_int_t
njt_http_shm_status_sysinfo_lvlhsh_test(njt_lvlhsh_query_t *lhq, void *data)
{
    //ignore value compare, just return ok
    return NJT_OK;
}


static njt_int_t njt_http_shm_status_init_module(njt_cycle_t *cycle) {
    njt_http_shm_status_main_conf_t       *sscf;
    sscf = njt_pcalloc(cycle->pool, sizeof(njt_http_shm_status_main_conf_t));
    if (sscf == NULL) {
        njt_log_error(NJT_LOG_EMERG, cycle->log, 0, "njt_http_shm_status alloc main conf error ");
        return NJT_ERROR;
    }

    cycle->conf_ctx[njt_http_shm_status_module.index] = (void *) sscf;
    sscf->sys_info.flush_interval = 3;         //default interval time is 3s

    return NJT_OK;
}

static njt_int_t njt_http_shm_status_init_process(njt_cycle_t *cycle){

    njt_http_shm_status_main_conf_t       *sscf;
    njt_str_t                   cpunumber;
    float                       sys_cpu_usage;
    // time_t                      diff_total;
    njt_int_t                   rc;
    njt_event_t                 *sysinfo_update_timer;

    if(njt_process != NJT_PROCESS_HELPER){
        return NJT_OK;
    }

    sscf = (njt_http_shm_status_main_conf_t *)njt_get_conf(cycle->conf_ctx, njt_http_shm_status_module);

    
    if(sscf == NULL){
        return NJT_OK;
    }

    //init sysinfo 
    // njt_queue_init(&summary->sys_meminfo.process_meminfo);
    njt_lvlhsh_init(&sscf->sys_info.prev_pids_work);
    
    sysinfo_update_timer = njt_pcalloc(cycle->pool, sizeof(njt_event_t));
    if(sysinfo_update_timer == NULL){
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "sysinfo_update_timer malloc error in function %s", __func__);
        return NJT_ERROR;
    }
    sysinfo_update_timer->data = sscf;
    sysinfo_update_timer->handler = njt_http_shm_status_sysinfo_update_handler;
    sysinfo_update_timer->cancelable = 1;
    sysinfo_update_timer->log = njt_cycle->log;

    sscf->sys_info.pool = njt_create_dynamic_pool(NJT_MIN_POOL_SIZE, njt_cycle->log);
    if (sscf->sys_info.pool == NULL) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "shm status sysinfo create dynamic pool error ");

        return NJT_ERROR;
    }
    rc = njt_sub_pool(cycle->pool, sscf->sys_info.pool);
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_sub_pool error in function %s", __func__);
        njt_destroy_pool(sscf->sys_info.pool);
        return NJT_ERROR;
    }


    sscf->sys_info.n_cpu = njt_sysguard_get_cpu_number(njt_cycle->log);

    //get inital cpu use info
    njt_str_set(&cpunumber, "cpu");

    //get sys cpu
    njt_log_error(NJT_LOG_INFO, cycle->log, 0, "njt_shm_status cpuinfo init");
    njt_http_shm_status_sysinfo_get_cpu_usage(&cpunumber, &sys_cpu_usage, NULL);

    njt_add_timer(sysinfo_update_timer, 1000);

    return NJT_OK;
}

static njt_int_t njt_http_shm_status_sysinfo_get_cpu_usage(njt_str_t *cpunumber, float *cpu_usage, time_t *diff_total){
    njt_uint_t          rc;
    njt_cpuinfo_t       cpuinfo;
    static time_t       prev_total = 0, prev_work = 0;
    time_t              work, total;
    
    rc = njt_get_cpu_info(cpunumber, &cpuinfo, njt_cycle->log);
    if(rc != NJT_OK){
        return NJT_ERROR;
    }

    total = cpuinfo.usr + cpuinfo.nice + cpuinfo.sys + cpuinfo.idle + cpuinfo.iowait + cpuinfo.irq + cpuinfo.softirq;
    work = total - cpuinfo.idle;
    if(diff_total != NULL){
        *diff_total = total - prev_total;
    }

    *cpu_usage = (100.0 * (work - prev_work) / (total - prev_total));

    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, 
        " total cpu usage:%.1f  usr:%T  nice:%T  sys:%T idle:%T work:%T  prev_work:%T total:%T  pre_total:%T work-:%T total-:%T", 
        *cpu_usage, cpuinfo.usr, cpuinfo.nice, cpuinfo.sys, cpuinfo.idle,
        work, prev_work, total, prev_total, work - prev_work, total - prev_total);

    prev_total = total;
    prev_work = work;


    return NJT_OK;
}


static njt_int_t njt_http_shm_status_sysinfo_update_pids(njt_http_shm_status_sysinfo *sysinfo, njt_str_t *in_new_pids){
    u_char          tmp_pid[4096];
    njt_str_t       new_pids;
    u_char          *end;
    u_char          s_pid[100];
    njt_str_t       local_s_pid;
    njt_str_t       local_s_pid2;
    njt_flag_t      find;
    njt_str_t       delete_s_pid;
    njt_lvlhsh_query_t              lhq;
    njt_http_shm_status_process_sysinfo          *process_sysinfo;
    u_char          *pid_start, *pid_index;
    njt_uint_t       i;

    njt_str_null(&new_pids);
    if(in_new_pids->len > 0){
        njt_memzero(tmp_pid, 4096);
        njt_memcpy(tmp_pid, in_new_pids->data, in_new_pids->len);
        new_pids.data = tmp_pid;
        new_pids.len = in_new_pids->len;
    }

    if(sysinfo->old_pids.len == 0){
        if(new_pids.len > 0){
            sysinfo->old_pids.data = njt_pcalloc(sysinfo->pool, new_pids.len);
            if(sysinfo->old_pids.data == NULL){
                return NJT_ERROR;
            }

            njt_memcpy(sysinfo->old_pids.data, new_pids.data, new_pids.len);
            sysinfo->old_pids.len = new_pids.len;

            njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, 
                " old pids is null, first set:%V", &sysinfo->old_pids);
            return NJT_OK;
        }
    }


    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, 
        " old pids:%V new pids:%V", &sysinfo->old_pids, &new_pids);

    pid_start = sysinfo->old_pids.data;
    pid_index = sysinfo->old_pids.data;
    for(i = 0; i < sysinfo->old_pids.len; i++){
        if(sysinfo->old_pids.data[i] != '_'){
            pid_index++;
        }else{
            delete_s_pid.data = pid_start;
            delete_s_pid.len = pid_index - pid_start;

            pid_index++;
            pid_start = pid_index;

            njt_memzero(s_pid, 100);
            end = njt_snprintf(s_pid, 100, "_%V_", &delete_s_pid);
            local_s_pid.len = end - s_pid;
            local_s_pid.data = s_pid;

            local_s_pid2.len = local_s_pid.len - 1;
            local_s_pid2.data = local_s_pid.data + 1;


            find = 0;
            if(new_pids.len >= local_s_pid.len){
                if (njt_strstrn(new_pids.data, (char *)local_s_pid.data, local_s_pid.len-1) != NULL) {
                    find = 1;
                }
            }

            if(!find){
                if(new_pids.len >= local_s_pid2.len){
                    if(njt_strncmp(new_pids.data, local_s_pid2.data, local_s_pid2.len) == 0){
                        find = 1;
                    }
                }
            }
        
            if(!find){
                njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, " old pid:%V need remove", &delete_s_pid);
                lhq.key = delete_s_pid;
                lhq.key_hash = njt_murmur_hash2(lhq.key.data, lhq.key.len);
                lhq.proto = &njt_http_shm_status_sysinfo_lvlhsh_proto;
                lhq.pool = sysinfo->pool;

                if(NJT_OK == njt_lvlhsh_find(&sysinfo->prev_pids_work, &lhq)){
                    process_sysinfo = (njt_http_shm_status_process_sysinfo *)lhq.value;
                    if(NJT_OK == njt_lvlhsh_delete(&sysinfo->prev_pids_work, &lhq)){
                        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, " old pid:%V remove success", &delete_s_pid);
                    }else{
                        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " old pid:%V remove fail", &delete_s_pid);
                    }

                    njt_pfree(sysinfo->pool, process_sysinfo);
                }else{
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " old pid:%V should find, but now none", &delete_s_pid);
                }
            }
        }
    }

    if(sysinfo->old_pids.len > 0){
        njt_pfree(sysinfo->pool, sysinfo->old_pids.data);
        njt_str_null(&sysinfo->old_pids);
    }

    if(new_pids.len > 0){
        sysinfo->old_pids.data = njt_pcalloc(sysinfo->pool, new_pids.len);
        if(sysinfo->old_pids.data == NULL){
            return NJT_ERROR;
        }

        njt_memcpy(sysinfo->old_pids.data, new_pids.data, new_pids.len);
        sysinfo->old_pids.len = new_pids.len;

        return NJT_OK;
    }

    return NJT_OK;
}


njt_int_t
njt_http_shm_status_sysinfo_of_process(njt_http_shm_status_sysinfo *sysinfo,
        njt_str_t *pids_v, njt_str_t *filter_pids_v, time_t diff_total){
    njt_str_t                       s_pid;
    njt_uint_t                      i;
    njt_process_cpuinfo_t           p_cpuinfo;
    njt_uint_t                      rc;
    time_t                          prev_pid_work;
    time_t                          total = 0, work = 0;
    // njt_uint_t                      real_work = 0;
    time_t                          diff_work = 0;
    float                           pid_cpu_usage;
    njt_lvlhsh_query_t              lhq;
    njt_flag_t                      pid_exist;
    u_char                          *pid_start, *pid_index;
    njt_http_shm_status_process_sysinfo  *process_sysinfo = NULL;
    size_t                          memory_use;
    u_char                          *end = filter_pids_v->data;
    njt_int_t                       len = 0;

    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, 
        "njt shm status get all pids:%V", pids_v);

    pid_start = pids_v->data;
    pid_index = pids_v->data;

    sysinfo->process_count = 0;
    sysinfo->process_total_cpu = 0;
    sysinfo->process_total_mem = 0;
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
            lhq.proto = &njt_http_shm_status_sysinfo_lvlhsh_proto;
            lhq.pool = sysinfo->pool;
            pid_exist = 0;
            //find
            rc = njt_lvlhsh_find(&sysinfo->prev_pids_work, &lhq);
            if(rc == NJT_OK){
                //find
                process_sysinfo = (njt_http_shm_status_process_sysinfo *)lhq.value;
                prev_pid_work = process_sysinfo->prev_pid_work;
                pid_exist = 1;
            }
  
            work = p_cpuinfo.utime + p_cpuinfo.stime + p_cpuinfo.cutime + p_cpuinfo.cstime;
            diff_work = work - prev_pid_work;
            total += diff_work;

            pid_cpu_usage = (100.0 * sysinfo->n_cpu * diff_work / diff_total);
            if(pid_cpu_usage > 100){
                pid_cpu_usage = 100;
            }

            njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, 
                " get process:%V cpu_usage:%.1f n_cpu:%d utime:%T stime:%T cutime:%T cstime:%T work:%T pre_work:%T diff_work:%T diff_total:%T",
                &s_pid, pid_cpu_usage, sysinfo->n_cpu, p_cpuinfo.utime, p_cpuinfo.stime,
                p_cpuinfo.cutime, p_cpuinfo.cstime, work, prev_pid_work, diff_work, diff_total);


            if(NJT_ERROR == njt_get_process_meminfo(&s_pid, &memory_use, njt_cycle->log)){
                njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                    "shm status sysinfo njt_get_process_meminfo error");
                    memory_use = 0;
            }

            //memory use M
            // if(memory_use > 0){
            //     memory_use = (memory_use < 1024) ? 1: memory_use/1024;
            // }

            njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                "get process:%V memory_use:%lu", &s_pid, memory_use);

            //filter pid
            if(len < 4000){
                end = njt_snprintf(end, 4096 - len, "%V_", &s_pid);
                len = end - filter_pids_v->data;
                filter_pids_v->len = len;
                sysinfo->process_count++;
                sysinfo->process_total_mem += memory_use;
                sysinfo->process_total_cpu += pid_cpu_usage;
                if(sysinfo->process_total_cpu > 100 * sysinfo->n_cpu){
                    sysinfo->process_total_cpu = 100 * sysinfo->n_cpu;
                }
            }

            //update pid work
            if(!pid_exist){
                lhq.key = s_pid;
                lhq.key_hash = njt_murmur_hash2(lhq.key.data, lhq.key.len);
                lhq.proto = &njt_http_shm_status_sysinfo_lvlhsh_proto;
                lhq.pool = sysinfo->pool;

                process_sysinfo = njt_pcalloc(sysinfo->pool, sizeof(njt_http_shm_status_process_sysinfo));
                if(process_sysinfo == NULL){
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                                "shm status sysinfo create process_sysinfo malloc error");
                    return NJT_ERROR;
                }

                njt_str_copy_pool(sysinfo->pool, process_sysinfo->pid, s_pid, return NJT_ERROR);

                lhq.value = process_sysinfo;
                rc = njt_lvlhsh_insert(&sysinfo->prev_pids_work, &lhq);
                if(rc != NJT_OK){
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0,
                                "shm status sys_info lvlhash insert fail");
                    continue ;
                }
            }

            if(process_sysinfo != NULL){
                process_sysinfo->prev_pid_work = work;
                process_sysinfo->cpu_cpu_usage = pid_cpu_usage;
                process_sysinfo->memory_use = memory_use;
            }
        }
    }

    return NJT_OK;
}


static void
njt_http_shm_status_sysinfo_update_handler(njt_event_t *ev)
{
    njt_http_shm_status_main_conf_t *sscf;
    njt_str_t                       cpunumber;
    time_t                          diff_total;
    njt_str_t                       pids_v;
    njt_str_t                       filter_pids_v;
    njt_int_t                       rc;
    njt_http_shm_status_sysinfo     *sysinfo;
    njt_queue_t                     *cur;
    njt_share_slab_pid_t            *node;
    njt_queue_t                     *head;
    u_char                          pids[4096];
    u_char                          filter_pids[4096];
    u_char                          *end;
    njt_int_t                       len;

    sscf = (njt_http_shm_status_main_conf_t *)ev->data;
    if (sscf != NULL) {
        sysinfo = &sscf->sys_info;
        //todo update sysinfo
        //get sys cpu info and mem info
        njt_str_set(&cpunumber, "cpu");

        //get sys cpu usage
        rc = njt_http_shm_status_sysinfo_get_cpu_usage(&cpunumber, &sysinfo->sys_cpu_usage, &diff_total);
        if(rc != NJT_OK){
            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " get cpu info error in sysguard_cpu module");
            goto shm_status_next_sys_usage;
        }

        //get sys mem info
        rc = njt_get_sys_meminfo(&sysinfo->sys_meminfo, njt_cycle->log);
        if(rc != NJT_OK){
            njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
                " njt_get_sys_meminfo error in shm status");
        }

        njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, 
            "njt shm status sysmeminfo total:%lu free:%lu avaliable:%lu", 
            sysinfo->sys_meminfo.total*1024,
            sysinfo->sys_meminfo.free*1024,
            sysinfo->sys_meminfo.avaliable*1024);

        //get all pids
        if (njet_master_cycle == NULL) {
            njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, 
                "njt shm status njet_master_cycle is null");
            goto shm_status_next_sys_usage;
        }

        if (!njet_master_cycle->shared_slab.header) {
            njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, 
                "njt shm status njet_master_cycle->shared_slab.header is null");
            goto shm_status_next_sys_usage;
        }
    
        head = &njet_master_cycle->shared_slab.queues_header->pids;
    
        njt_shmtx_lock(&njt_shared_slab_header->mutex);

    
        if (njt_queue_empty(head)) {
            njt_shmtx_unlock(&njt_shared_slab_header->mutex);
            goto shm_status_next_sys_usage;
        }
    
        cur = njt_queue_next(head);
        end = pids;
        len = 0;
        while (cur != head) {
            node = (njt_share_slab_pid_t *)njt_queue_data(cur, njt_share_slab_pid_t, queue);
            end = njt_snprintf(end, 4096 - len, 
                "%d_", node->pid);
            len = end - pids;
            if(len > 4000){
                break;
            }
            cur = njt_queue_next(cur);
        }
    
        njt_shmtx_unlock(&njt_shared_slab_header->mutex);

        // rc = njt_http_shm_status_sysinfo_get_cpu_usage(&cpunumber, &sysinfo->sys_cpu_usage, &diff_total);
        // if(rc != NJT_OK){
        //     njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " get cpu info error in sysguard_cpu module");
        //     goto shm_status_next_sys_usage;
        // }

        pids_v.data = pids;
        pids_v.len = len;
        filter_pids_v.data = filter_pids;
        //get all workers's cpu info and mem info
        rc = njt_http_shm_status_sysinfo_of_process(&sscf->sys_info, &pids_v, &filter_pids_v, diff_total);
        if(rc != NJT_OK){
            njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
                " njt_http_shm_status_sysinfo_of_process error");

        }

        //update worker pids
        njt_http_shm_status_sysinfo_update_pids(&sscf->sys_info, &filter_pids_v);
        njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, 
            "njt shm status save all pids:%V", &filter_pids_v);
    }

shm_status_next_sys_usage:
    if (!njt_exiting && !njt_quit && !njt_terminate) {
        njt_add_timer(ev, 5000);
    }
}

