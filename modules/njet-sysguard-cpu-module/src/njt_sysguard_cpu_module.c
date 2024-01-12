/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_core.h>
#include <njt_http_kv_module.h>
#include <njt_http.h>
#include <njt_http_sendmsg_module.h>
#include "njt_sysguard_cpu_sysinfo.h"


static void *njt_sysguard_cpu_module_create_conf(njt_cycle_t *cycle);
static char *njt_sysguard_cpu(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static njt_int_t njt_sysguard_cpu_init_module(njt_cycle_t *cycle);
static void njt_sysguard_cpu_timer_handler(njt_event_t *ev);


const njt_lvlhsh_proto_t  njt_sysload_cpu_lvlhsh_proto = {
    NJT_LVLHSH_LARGE_MEMALIGN,
    njt_sysload_lvlhsh_test,
    njt_lvlhsh_pool_alloc,
    njt_lvlhsh_pool_free,
};

static njt_command_t  njt_sysguard_cpu_commands[] = {

    { njt_string("sysguard_cpu"),
      NJT_MAIN_CONF|NJT_DIRECT_CONF|NJT_CONF_ANY,
      njt_sysguard_cpu,
      0,
      0,
      NULL },

      njt_null_command
};


static njt_core_module_t  njt_sysguard_cpu_module_ctx = {
    njt_string("sysguard_cpu"),
    njt_sysguard_cpu_module_create_conf,
    NULL
};

njt_module_t  njt_sysguard_cpu_module = {
    NJT_MODULE_V1,
    &njt_sysguard_cpu_module_ctx,               /* module context */
    njt_sysguard_cpu_commands,                  /* module directives */
    NJT_CORE_MODULE,                            /* module type */
    NULL,                                       /* init master */
    NULL,                                       /* init module */
    njt_sysguard_cpu_init_module,               /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};

typedef struct {
    njt_int_t            enable;
    njt_int_t            interval;          //timer interval
    njt_int_t            low_threshold;
    njt_int_t            high_threshold;
    njt_int_t            sys_high_threshold;
    njt_int_t            worker_step;
    njt_int_t            min_worker;
    njt_int_t            max_worker;
    njt_lvlhsh_t         prev_pids_work;
    njt_str_t            old_pids;
    njt_int_t            n_cpu;
    njt_pool_t           *pool;
} njt_sysguard_cpu_conf_t;


static void *
njt_sysguard_cpu_module_create_conf(njt_cycle_t *cycle)
{
    njt_sysguard_cpu_conf_t  *ccf;

    ccf = njt_pcalloc(cycle->pool, sizeof(njt_sysguard_cpu_conf_t));
    if (ccf == NULL) {
        return NULL;
    }

    ccf->enable = NJT_CONF_UNSET;
    ccf->interval = NJT_CONF_UNSET;
    ccf->low_threshold = NJT_CONF_UNSET;
    ccf->high_threshold = NJT_CONF_UNSET;
    ccf->sys_high_threshold = NJT_CONF_UNSET;
    ccf->worker_step = NJT_CONF_UNSET;
    ccf->min_worker = NJT_CONF_UNSET;
    ccf->max_worker = NJT_CONF_UNSET;
    ccf->pool = NJT_CONF_UNSET_PTR;
    ccf->n_cpu = njt_ncpu;
    njt_str_null(&ccf->old_pids);

    return ccf;
}


static char *
njt_sysguard_cpu(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t                   *value;
    njt_sysguard_cpu_conf_t     *ccf;
    njt_uint_t                  i;

    ccf = (njt_sysguard_cpu_conf_t *) conf;
    if (ccf->enable != NJT_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (njt_strncmp(value[i].data, "interval=", 9) == 0) {
            if (ccf->interval != NJT_CONF_UNSET) {
                return "interval is duplicate";
            }

            if (value[i].len == 9) {
                goto invalid;
            }

            value[i].data += 9;
            value[i].len -= 9;

            ccf->interval = njt_atoi(value[i].data, value[i].len);
            if (ccf->interval == NJT_ERROR) {
                goto invalid;
            }

            ccf->interval *= 60 * 1000;
            if (ccf->interval < 1*60*1000) {
                return "interval should more than 1min";
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "low_threshold=", 14) == 0) {
            if (ccf->low_threshold != NJT_CONF_UNSET) {
                return "low_threshold is duplicate";
            }

            if (value[i].len == 14) {
                goto invalid;
            }

            value[i].data += 14;
            value[i].len -= 14;

            ccf->low_threshold = njt_atoi(value[i].data, value[i].len);
            if (ccf->low_threshold == NJT_ERROR) {
                goto invalid;
            }

            if (ccf->low_threshold < 10) {
                return "low_threshold should more than 10";
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "high_threshold=", 15) == 0) {
            if (ccf->high_threshold != NJT_CONF_UNSET) {
                return "high_threshold is duplicate";
            }

            if (value[i].len == 15) {
                goto invalid;
            }

            value[i].data += 15;
            value[i].len -= 15;

            ccf->high_threshold = njt_atoi(value[i].data, value[i].len);
            if (ccf->high_threshold == NJT_ERROR) {
                goto invalid;
            }


            if (ccf->high_threshold < 10) {
                return "high_threshold should more than 10";
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "sys_high_threshold=", 19) == 0) {
            if (ccf->sys_high_threshold != NJT_CONF_UNSET) {
                return "sys_high_threshold is duplicate";
            }

            if (value[i].len == 19) {
                goto invalid;
            }

            value[i].data += 19;
            value[i].len -= 19;

            ccf->sys_high_threshold = njt_atoi(value[i].data, value[i].len);
            if (ccf->sys_high_threshold == NJT_ERROR) {
                goto invalid;
            }

            if (ccf->sys_high_threshold < 10) {
                return "sys_high_threshold should more than 10";
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "worker_step=", 12) == 0) {
            if (ccf->worker_step != NJT_CONF_UNSET) {
                return "worker_step is duplicate";
            }

            if (value[i].len == 12) {
                goto invalid;
            }

            value[i].data += 12;
            value[i].len -= 12;

            ccf->worker_step = njt_atoi(value[i].data, value[i].len);
            if (ccf->worker_step == NJT_ERROR) {
                goto invalid;
            }

            if (ccf->worker_step < 1) {
                return "worker_step should more than 1";
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "min_worker=", 11) == 0) {
            if (ccf->min_worker != NJT_CONF_UNSET) {
                return "worker_step is duplicate";
            }

            if (value[i].len == 11) {
                goto invalid;
            }

            value[i].data += 11;
            value[i].len -= 11;

            ccf->min_worker = njt_atoi(value[i].data, value[i].len);
            if (ccf->min_worker == NJT_ERROR) {
                goto invalid;
            }

            if (ccf->min_worker < 1) {
                return "min_worker should more than 1";
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "max_worker=", 11) == 0) {
            if (ccf->max_worker != NJT_CONF_UNSET) {
                return "worker_step is duplicate";
            }

            if (value[i].len == 11) {
                goto invalid;
            }

            value[i].data += 11;
            value[i].len -= 11;

            ccf->max_worker = njt_atoi(value[i].data, value[i].len);
            if (ccf->max_worker == NJT_ERROR) {
                goto invalid;
            }

            if (ccf->max_worker < 1) {
                return "max_worker should more than 1";
            }

            continue;
        }               
    }

    //get real cpu number
    ccf->n_cpu = njt_sysguard_get_cpu_number(cf);

    //init unconfig param
    njt_conf_init_value(ccf->interval, 1*60*1000);
    njt_conf_init_value(ccf->low_threshold, 10);
    njt_conf_init_value(ccf->high_threshold, 70);
    njt_conf_init_value(ccf->sys_high_threshold, 80);
    njt_conf_init_value(ccf->worker_step, 1);
    njt_conf_init_value(ccf->min_worker, 1);
    njt_conf_init_value(ccf->max_worker, ccf->n_cpu);

    //logic check
    if(ccf->low_threshold >= ccf->high_threshold){
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
            "low_threshold:%d should less then high_threshold:%d",
            ccf->low_threshold, ccf->high_threshold);
        
        return NJT_CONF_ERROR;
    }

    if(ccf->min_worker > ccf->max_worker){
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
            "min_worker:%d should less then max_worker:%d",
            ccf->min_worker, ccf->max_worker);
        
        return NJT_CONF_ERROR;
    }    

    ccf->enable = 1;

    return NJT_CONF_OK;

invalid:

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);

    return NJT_CONF_ERROR;
}



static njt_int_t njt_sysguard_cpu_init_module(njt_cycle_t *cycle){
    njt_event_t                 *sysguard_cpu_timer;
    njt_sysguard_cpu_conf_t     *ccf;
    njt_int_t                   cpu_usage;
    njt_str_t                   cpunumber;
    time_t                      diff_total;

    if(njt_process != NJT_PROCESS_HELPER){
        return NJT_OK;
    }

    ccf = (njt_sysguard_cpu_conf_t *)njt_get_conf(cycle->conf_ctx, njt_sysguard_cpu_module);    
    if(ccf == NULL){
        return NJT_OK;
    }

    if (ccf->enable == NJT_CONF_UNSET) {
        return NJT_OK;
    }

    //start timer event
    sysguard_cpu_timer = njt_pcalloc(cycle->pool, sizeof(njt_event_t));
    if(sysguard_cpu_timer == NULL){
        return NJT_ERROR;
    }

    ccf->pool = njt_create_dynamic_pool(njt_pagesize, cycle->log);
    if (ccf->pool == NULL || NJT_OK != njt_sub_pool(cycle->pool, ccf->pool)) {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, "njt_create_peer_map error");
        return NJT_ERROR;
    }
    njt_lvlhsh_init(&ccf->prev_pids_work);

    //get inital cpu use info
    njt_str_set(&cpunumber, "cpu");

    //get sys cpu
    njt_log_error(NJT_LOG_INFO, cycle->log, 0, "sysguard_cpu module init");
    njt_get_cpu_usage(&cpunumber, &cpu_usage, &diff_total);

    sysguard_cpu_timer->handler = njt_sysguard_cpu_timer_handler;
    sysguard_cpu_timer->log = njt_cycle->log;
    sysguard_cpu_timer->data = ccf;
    sysguard_cpu_timer->cancelable = 1;

    njt_add_timer(sysguard_cpu_timer, ccf->interval);
    // njt_add_timer(sysguard_cpu_timer, 15000);
    return NJT_OK;
}


static njt_int_t njt_sysload_update_pids(njt_sysguard_cpu_conf_t *ccf, njt_str_t *in_new_pids){
    u_char          tmp_pid[4096];
    njt_str_t       new_pids;
    u_char          *end;
    u_char          s_pid[100];
    njt_str_t       local_s_pid;
    njt_str_t       local_s_pid2;
    njt_flag_t      find;
    njt_str_t       delete_s_pid;
    njt_lvlhsh_query_t              lhq;
    time_t          *prev_pid_work;
    u_char          *pid_start, *pid_index;
    njt_uint_t       i;

    njt_str_null(&new_pids);
    if(in_new_pids->len > 0){
        njt_memzero(tmp_pid, 4096);
        njt_memcpy(tmp_pid, in_new_pids->data, in_new_pids->len);
        new_pids.data = tmp_pid;
        new_pids.len = in_new_pids->len;
    }

    if(ccf->old_pids.len == 0){
        if(new_pids.len > 0){
            ccf->old_pids.data = njt_pcalloc(ccf->pool, new_pids.len);
            if(ccf->old_pids.data == NULL){
                return NJT_ERROR;
            }

            njt_memcpy(ccf->old_pids.data, new_pids.data, new_pids.len);
            ccf->old_pids.len = new_pids.len;

            njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
                " old pids is null, first set:%V", &ccf->old_pids);
            return NJT_OK;
        }
    }


    njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
        " old pids:%V new pids:%V", &ccf->old_pids, &new_pids);

    pid_start = ccf->old_pids.data;
    pid_index = ccf->old_pids.data;
    for(i = 0; i < ccf->old_pids.len; i++){
        if(ccf->old_pids.data[i] != '_'){
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
                lhq.proto = &njt_sysload_cpu_lvlhsh_proto;
                lhq.pool = ccf->pool;

                if(NJT_OK == njt_lvlhsh_find(&ccf->prev_pids_work, &lhq)){
                    prev_pid_work = (time_t *)lhq.value;
                    if(NJT_OK == njt_lvlhsh_delete(&ccf->prev_pids_work, &lhq)){
                        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, " old pid:%V remove success", &delete_s_pid);
                    }else{
                        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " old pid:%V remove fail", &delete_s_pid);
                    }

                    njt_pfree(ccf->pool, prev_pid_work);
                }else{
                    njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " old pid:%V should find, but now none", &delete_s_pid);
                }
            }
        }
    }

    if(ccf->old_pids.len > 0){
        njt_pfree(ccf->pool, ccf->old_pids.data);
        njt_str_null(&ccf->old_pids);
    }

    if(new_pids.len > 0){
        ccf->old_pids.data = njt_pcalloc(ccf->pool, new_pids.len);
        if(ccf->old_pids.data == NULL){
            return NJT_ERROR;
        }

        njt_memcpy(ccf->old_pids.data, new_pids.data, new_pids.len);
        ccf->old_pids.len = new_pids.len;

        return NJT_OK;
    }

    return NJT_OK;
}


static void njt_sysguard_cpu_timer_handler(njt_event_t *ev){
    njt_sysguard_cpu_conf_t         *ccf;
    njt_int_t                       rc;
    njt_str_t                       cpunumber;
    njt_int_t                       cpu_usage;
    njt_int_t                       average_cpu_usage;
    njt_str_t                       worker_k = njt_string("kv_http___master_worker_count");
    njt_str_t                       worker_v;
    njt_str_t                       pids_k = njt_string("kv_http___sysguard_pids");
    njt_str_t                       pids_v;
    njt_int_t                       worker_c;
    time_t                          diff_total;
    njt_int_t                       new_worker_c = 0;
    u_char                          *end;
    u_char                          s_tmp[24];


    ccf = ev->data;
    njt_str_set(&cpunumber, "cpu");

    //get sys cpu
    rc = njt_get_cpu_usage(&cpunumber, &cpu_usage, &diff_total);
    if(rc != NJT_OK){
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, " get cpu info error in sysguard_cpu module");
        goto next_sys_usage;
    }

    //sys cpu more than sys_threshold
    if(cpu_usage >= ccf->sys_high_threshold){
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
            " cpu_usage:%d more than sys_high_threshod:%d not adujst worker",
            cpu_usage, ccf->sys_high_threshold);
        goto next_sys_usage;
    }

    //get worker number from kv
    njt_str_set(&worker_v, "");
    rc = njt_dyn_kv_get(&worker_k, &worker_v);
    if (rc == NJT_OK) {
        worker_c = njt_atoi(worker_v.data, worker_v.len);
        if (worker_c <= 0 || worker_c > SYSLOAD_MAX_WORKER_C) {
            njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "woker processes count (%V) is not valid, it should be within (0, %d])", &worker_v, SYSLOAD_MAX_WORKER_C);
            goto next_sys_usage;
        }
    } else {
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "can't get worker processes count from kv store");
        goto next_sys_usage;
    }

    //get all pids
    njt_str_set(&pids_v, "");
    rc = njt_dyn_kv_get(&pids_k, &pids_v);
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, "can't get worker processes count from kv store");
        goto next_sys_usage;
    }


    //get all workers's average cpu
    rc = njt_get_process_average_cpu_usage(ccf->pool, ccf->n_cpu, &average_cpu_usage, worker_c, &pids_v, &ccf->prev_pids_work, diff_total);
    if(rc != NJT_OK){
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
            " get process average cpu usage error, not adjust worker");

        goto next_sys_usage;
    }

    //update pids
    njt_sysload_update_pids(ccf, &pids_v);

    njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
            " average cpu usage:%d", average_cpu_usage);
    //compare low_threshold and high_threshold
    if(average_cpu_usage > ccf->low_threshold && average_cpu_usage < ccf->high_threshold){
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
            " process cpu usage:%d low_threshold:%d high_threshold:%d, not adjust worker",
            average_cpu_usage, ccf->low_threshold, ccf->high_threshold);
        goto next_sys_usage;
    }

    //compute worker number
    if(average_cpu_usage <= ccf->low_threshold){
        new_worker_c = worker_c - ccf->worker_step;
        if(new_worker_c < ccf->min_worker){
            new_worker_c = ccf->min_worker;
        }

        if(new_worker_c >= worker_c){
            njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
                " new_worker:%d >= now_work:%d , not adujst, when less than low_threshold",
                new_worker_c, worker_c);

            goto next_sys_usage;
        }
    }

    if(average_cpu_usage >= ccf->high_threshold){
        new_worker_c = worker_c + ccf->worker_step;
        if(new_worker_c > ccf->max_worker){
            new_worker_c = ccf->max_worker;
        }

        if(new_worker_c <= worker_c){
            njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
                " new_worker:%d <= now_work:%d , not adujst, when more than high_threshold",
                new_worker_c, worker_c);
            goto next_sys_usage;
        }
    }
    
    if(new_worker_c == worker_c){
        njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
                " new_worker:%d = now_work:%d , not adujst",
                new_worker_c, worker_c);
        goto next_sys_usage;
    }


    //if not equal, then update kv
    end = njt_snprintf(s_tmp, 24, "%d", new_worker_c);
    worker_v.data = s_tmp;
    worker_v.len = end - s_tmp;
    rc = njt_dyn_kv_set(&worker_k, &worker_v);
    if (rc != NJT_OK) {
        njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "error setting worker count into kvstore in sysguard_cpu");
        goto next_sys_usage;
    }

    //and send sigconf to master
    kill(njt_parent, SIGCONF);
    njt_log_error(NJT_LOG_INFO, njt_cycle->log, 0, 
        " adjust worker num from %d to %d", worker_c, new_worker_c);


next_sys_usage:
    njt_add_timer(ev, ccf->interval);
    // njt_add_timer(ev, 15000);

    return ;
}
