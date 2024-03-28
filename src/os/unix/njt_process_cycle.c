
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_channel.h>
#include <njt_mqconf_module.h>
#include <njet_iot_emb.h>
#include <njt_md5.h>

#define MAX_DYN_WORKER_C 512
#define WORKER_COUNT_KEY "kv_http___master_worker_count"

static void njt_start_worker_processes(njt_cycle_t *cycle, njt_int_t n,
    njt_int_t type);
static void njt_start_cache_manager_processes(njt_cycle_t *cycle,
    njt_uint_t respawn);
static void njt_start_privileged_agent_processes(njt_cycle_t *cycle,
    njt_uint_t respawn);
static njt_uint_t njt_start_helper_processes(njt_cycle_t *cycle,
    njt_uint_t respawn);
static njt_uint_t njt_restart_helper_processes(njt_cycle_t *cycle,
    njt_uint_t respawn);
static void njt_pass_open_channel(njt_cycle_t *cycle);
static void njt_signal_worker_processes(njt_cycle_t *cycle, int signo);
static void njt_cmd_worker_processes(njt_cycle_t *cycle, njt_uint_t cmd);
static void njt_signal_helper_processes(njt_cycle_t *cycle, int signo);
static njt_uint_t njt_reap_children(njt_cycle_t *cycle);
static void njt_master_process_exit(njt_cycle_t *cycle);
static void njt_worker_process_cycle(njt_cycle_t *cycle, void *data);
static void njt_worker_process_init(njt_cycle_t *cycle, njt_int_t worker);
static void njt_helper_process_init(njt_cycle_t *cycle, njt_int_t worker);
static void njt_worker_process_exit(njt_cycle_t *cycle);
void njt_helper_process_exit(njt_cycle_t *cycle);
static void njt_channel_handler(njt_event_t *ev);
static void njt_cache_manager_process_cycle(njt_cycle_t *cycle, void *data);
static void njt_privileged_agent_process_cycle(njt_cycle_t *cycle, void *data);
static void njt_cache_manager_process_handler(njt_event_t *ev);
static void njt_cache_loader_process_handler(njt_event_t *ev);
//for dynamic worker process changes
static njt_int_t njt_master_init_mdb(njt_cycle_t *cycle, const char *cfg);
static void njt_update_worker_processes(njt_cycle_t *cycle, njt_core_conf_t *ccf, njt_int_t worker_c);
static void njt_check_and_update_worker_count(njt_cycle_t *cycle, njt_core_conf_t *ccf);
//add by clb
njt_int_t njt_save_pids_to_kv(njt_cycle_t *cycle);
njt_int_t njt_save_register_info_to_kv(njt_cycle_t *cycle);

njt_uint_t    njt_process;
njt_uint_t    njt_worker;
njt_pid_t     njt_pid;
njt_pid_t     njt_parent;

sig_atomic_t  njt_reap;
sig_atomic_t  njt_sigio;
sig_atomic_t  njt_sigalrm;
sig_atomic_t  njt_terminate;
sig_atomic_t  njt_quit;
sig_atomic_t  njt_debug_quit;
njt_uint_t    njt_exiting;
sig_atomic_t  njt_reconfigure;
time_t        njt_reconfigure_time;
sig_atomic_t  njt_reopen;
sig_atomic_t  njt_reap_helper;
sig_atomic_t  njt_rtc;

sig_atomic_t  njt_change_binary;
njt_pid_t     njt_new_binary;
njt_uint_t    njt_inherited;
njt_uint_t    njt_daemonized;

sig_atomic_t  njt_noaccept;
njt_uint_t    njt_noaccepting;
njt_uint_t    njt_restart;

njt_uint_t    njt_is_privileged_agent = 0;
njt_uint_t    njt_privileged_agent_exited = 0;
njt_uint_t    njt_master_listening_count = 0;
njt_uint_t    njt_is_privileged_helper = 0;
njt_conf_check_cmd_handler_pt  njt_conf_check_cmd_handler = NULL;
// add for dyn conf
njt_str_t     njt_conf_json;
void         *njt_conf_pool_ptr = NULL;
void         *njt_conf_cur_ptr = NULL;
void         *njt_conf_dyn_loc_ptr = NULL;
void         *njt_conf_dyn_loc_pool = NULL;
// end for dyn conf


static u_char  master_process[] = "master process";


static njt_cache_manager_ctx_t  njt_cache_manager_ctx = {
    njt_cache_manager_process_handler, "cache manager process", 0
};

static njt_cache_manager_ctx_t  njt_cache_loader_ctx = {
    njt_cache_loader_process_handler, "cache loader process", 60000
};


static njt_cycle_t      njt_exit_cycle;
static njt_log_t        njt_exit_log;
static njt_open_file_t  njt_exit_log_file;
static struct evt_ctx_t *master_evt_ctx = NULL;

extern njt_module_t njt_register_set_module;

void
njt_master_process_cycle(njt_cycle_t *cycle)
{
    char *title;
    u_char *p;
    size_t             size;
    njt_int_t          i;
    njt_uint_t         sigio;
    sigset_t           set;
    struct itimerval   itv;
    njt_uint_t         live;
    njt_msec_t         delay;
    njt_core_conf_t *ccf;
    njt_str_t          worker_k = njt_string("kv_http___master_worker_count");
    njt_str_t          worker_v;
    njt_int_t          worker_c;
    njt_int_t          rc;
    uint32_t           val_len = 0;

    sigemptyset(&set);
    sigaddset(&set, SIGCHLD);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGIO);
    sigaddset(&set, SIGINT);
    sigaddset(&set, njt_signal_value(NJT_RECONFIGURE_SIGNAL));
    sigaddset(&set, njt_signal_value(NJT_REOPEN_SIGNAL));
    sigaddset(&set, njt_signal_value(NJT_NOACCEPT_SIGNAL));
    sigaddset(&set, njt_signal_value(NJT_TERMINATE_SIGNAL));
    sigaddset(&set, njt_signal_value(NJT_SHUTDOWN_SIGNAL));
    sigaddset(&set, njt_signal_value(NJT_CHANGEBIN_SIGNAL));
    sigaddset(&set, SIGCONF);

    if (sigprocmask(SIG_BLOCK, &set, NULL) == -1) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
            "sigprocmask() failed");
    }

    sigemptyset(&set);

    size = sizeof(master_process);

    for (i = 0; i < njt_argc; i++) {
        size += njt_strlen(njt_argv[i]) + 1;
    }

    title = njt_pnalloc(cycle->pool, size);
    if (title == NULL) {
        /* fatal */
        exit(2);
    }

    p = njt_cpymem(title, master_process, sizeof(master_process) - 1);
    for (i = 0; i < njt_argc; i++) {
        *p++ = ' ';
        p = njt_cpystrn(p, (u_char *)njt_argv[i], size);
    }

    njt_setproctitle(title);


    ccf = (njt_core_conf_t *)njt_get_conf(cycle->conf_ctx, njt_core_module);

    njt_start_worker_processes(cycle, ccf->worker_processes,
        NJT_PROCESS_RESPAWN);
    njt_start_cache_manager_processes(cycle, 0);
    njt_start_helper_processes(cycle, 0);
    njt_start_privileged_agent_processes(cycle, 0);

    if (master_evt_ctx) {
        njt_check_and_update_worker_count(cycle, ccf);

        //add by clb
        //update all pids to kv
        njt_save_pids_to_kv(cycle);

        //save register info    
        njt_save_register_info_to_kv(cycle);
    }

    njt_new_binary = 0;
    delay = 0;
    sigio = 0;
    live = 1;

    for (;; ) {
        if (delay) {
            if (njt_sigalrm) {
                sigio = 0;
                delay *= 2;
                njt_sigalrm = 0;
            }

            njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                "termination cycle: %M", delay);

            itv.it_interval.tv_sec = 0;
            itv.it_interval.tv_usec = 0;
            itv.it_value.tv_sec = delay / 1000;
            itv.it_value.tv_usec = (delay % 1000) * 1000;

            if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
                njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                    "setitimer() failed");
            }
        }

        njt_log_debug0(NJT_LOG_DEBUG_EVENT, cycle->log, 0, "sigsuspend");

        sigsuspend(&set);

        njt_time_update();

        njt_log_debug1(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
            "wake up, sigio %i", sigio);

        if (njt_reap) {
            njt_reap = 0;
            njt_log_debug0(NJT_LOG_DEBUG_EVENT, cycle->log, 0, "reap children");

            live = njt_reap_children(cycle);

            if (njt_reap_helper) {
                njt_reap_helper = 0;
                if ((njt_restart_helper_processes(cycle, 0) > 0) && (live == 0)) {
                    live = 1;
                }
            }

            //add by clb
            //update all pids to kv
            njt_save_pids_to_kv(cycle);
        }

        if (!live && (njt_terminate || njt_quit)) {
            njt_master_process_exit(cycle);
        }

        if (njt_terminate) {
            if (delay == 0) {
                delay = 50;
            }

            if (sigio) {
                sigio--;
                continue;
            }

            sigio = ccf->worker_processes + 2 /* cache processes */;

            if (delay > 1000) {
                njt_signal_worker_processes(cycle, SIGKILL);
            } else {
                njt_signal_worker_processes(cycle,
                    njt_signal_value(NJT_TERMINATE_SIGNAL));
            }

            continue;
        }

        if (njt_quit) {
            njt_signal_worker_processes(cycle,
                njt_signal_value(NJT_SHUTDOWN_SIGNAL));
            njt_close_listening_sockets(cycle);

            continue;
        }

        if (njt_reconfigure) {
            njt_reconfigure = 0;

            if (njt_new_binary) {
                njt_start_worker_processes(cycle, ccf->worker_processes,
                    NJT_PROCESS_RESPAWN);
                njt_start_cache_manager_processes(cycle, 0);
                njt_start_privileged_agent_processes(cycle, 0);
                njt_noaccepting = 0;

                //add by clb
                //update all pids to kv
                njt_save_pids_to_kv(cycle);

                njt_save_register_info_to_kv(cycle);
                continue;
            }

            // if (njt_reconfigure_time>0 && njt_time()-njt_reconfigure_time<3) {
            //     njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "ignore reconfiguring");
            //     continue;
            // }

            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "reconfiguring");

            cycle = njt_init_cycle(cycle);
            if (cycle == NULL) {
                cycle = (njt_cycle_t *)njt_cycle;
                continue;
            }

            njt_cycle = cycle;
            ccf = (njt_core_conf_t *)njt_get_conf(cycle->conf_ctx,
                njt_core_module);
            njt_check_and_update_worker_count(cycle, ccf);
            njt_start_worker_processes(cycle, ccf->worker_processes,
                NJT_PROCESS_JUST_RESPAWN);
            njt_start_cache_manager_processes(cycle, 1);

            /* allow new processes to start */
            njt_msleep(100);


            njt_reap_helper = 1;
            live = 1;
            njt_cmd_worker_processes(cycle, NJT_CMD_RESTART);
            njt_reconfigure_time = njt_time();

            //add by clb
            //update all pids to kv
            njt_save_pids_to_kv(cycle);

            //save register info to kv
            njt_save_register_info_to_kv(cycle);
        }

        if (njt_restart) {
            njt_restart = 0;
            njt_start_worker_processes(cycle, ccf->worker_processes,
                NJT_PROCESS_RESPAWN);
            njt_start_cache_manager_processes(cycle, 0);
            live = 1;

            //add by clb
            //update all pids to kv
            njt_save_pids_to_kv(cycle);
        }

        if (njt_reopen) {
            njt_reopen = 0;
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "reopening logs");
            njt_reopen_files(cycle, ccf->user);
            njt_signal_worker_processes(cycle,
                njt_signal_value(NJT_REOPEN_SIGNAL));
        }

        if (njt_change_binary) {
            njt_change_binary = 0;
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "changing binary");
            njt_signal_helper_processes(cycle,
                njt_signal_value(NJT_SHUTDOWN_SIGNAL));
            njt_new_binary = njt_exec_new_binary(cycle, njt_argv);
        }

        if (njt_noaccept) {
            njt_noaccept = 0;
            njt_noaccepting = 1;
            njt_signal_worker_processes(cycle,
                njt_signal_value(NJT_SHUTDOWN_SIGNAL));
        }

        if (master_evt_ctx && njt_rtc) {
            njt_rtc = 0;
            rc = njet_iot_client_kv_get((void *)worker_k.data, worker_k.len, (void **)&worker_v.data, &val_len, master_evt_ctx);
            worker_v.len = val_len;
            if (rc == NJT_OK) {
                worker_c = njt_atoi(worker_v.data, worker_v.len);
                if (worker_c <= 0 || worker_c > MAX_DYN_WORKER_C) {
                    njt_log_error(NJT_LOG_INFO, cycle->log, 0, "woker processes count (%V) is not valid, it should be within (0, %d])", &worker_v, MAX_DYN_WORKER_C);
                } else {
                    njt_update_worker_processes(cycle, ccf, worker_c);
                }
            } else {
                njt_log_error(NJT_LOG_INFO, cycle->log, 0, "can't get worker processes count from kv store");
            }
        }

        if (njt_privileged_agent_exited) {
            njt_start_privileged_agent_processes(cycle, 0);
        }
    }
}

void
njt_single_process_cycle(njt_cycle_t *cycle)
{
    njt_uint_t  i;

    if (njt_set_environment(cycle, NULL) == NULL) {
        /* fatal */
        exit(2);
    }

    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->init_process) {
            if (cycle->modules[i]->init_process(cycle) == NJT_ERROR) {
                /* fatal */
                exit(2);
            }
        }
    }

    for (;; ) {
        // njt_log_debug0(NJT_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");
        // openresty patch
        if (njt_exiting) {
            if (njt_event_no_timers_left() == NJT_OK) {
                njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "exiting");

                for (i = 0; cycle->modules[i]; i++) {
                    if (cycle->modules[i]->exit_process) {
                        cycle->modules[i]->exit_process(cycle);
                    }
                }

                njt_master_process_exit(cycle);
            }
        }
        // openresty patch end

        njt_process_events_and_timers(cycle);

        // if (njt_terminate || njt_quit) { // openresty patch
        if (njt_terminate) {  // openresty patch
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "exiting"); // openresty patch

            for (i = 0; cycle->modules[i]; i++) {
                if (cycle->modules[i]->exit_process) {
                    cycle->modules[i]->exit_process(cycle);
                }
            }

            njt_master_process_exit(cycle);
        }

        // openresty patch
        if (njt_quit) {
            njt_quit = 0;
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0,
                          "gracefully shutting down");
            njt_setproctitle("process is shutting down");

            if (!njt_exiting) {
                njt_exiting = 1;
                njt_set_shutdown_timer(cycle);
                njt_close_listening_sockets(cycle);
                njt_close_idle_connections(cycle);
            }
        }
        // openresty patch end



        if (njt_reconfigure) {
            njt_reconfigure = 0;
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "reconfiguring");

            cycle = njt_init_cycle(cycle);
            if (cycle == NULL) {
                cycle = (njt_cycle_t *)njt_cycle;
                continue;
            }

            njt_cycle = cycle;
        }

        if (njt_reopen) {
            njt_reopen = 0;
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "reopening logs");
            njt_reopen_files(cycle, (njt_uid_t)-1);
        }
    }
}

static void njt_check_and_update_worker_count(njt_cycle_t *cycle, njt_core_conf_t *ccf)
{
    njt_str_t          worker_k = njt_string(WORKER_COUNT_KEY);
    njt_str_t          worker_v;
    njt_int_t          worker_c;
    njt_int_t          has_worker_kv;
    njt_int_t          rc;
    u_char             s_tmp[24] = { 0 };
    u_char             *end;
    uint32_t           val_len = 0;   

    if (!master_evt_ctx) {
        njt_log_error(NJT_LOG_ERR, cycle->log, 0, "master_evt_ctx not existed, kv func not available");
        return;      
    }
    has_worker_kv = 0;
    njt_str_set(&worker_v, "");

    rc = njet_iot_client_kv_get((void *)worker_k.data, worker_k.len, (void **)&worker_v.data, &val_len, master_evt_ctx);
    worker_v.len = val_len;
    if (rc == NJT_OK) {
        worker_c = njt_atoi(worker_v.data, worker_v.len);
        if (worker_c > 0 && worker_c < MAX_DYN_WORKER_C) {
            has_worker_kv = 1;
        }
    }
    //if kv_http___master_worker_count has valid value, trigger njt_update_worker_processes
    if (has_worker_kv) {
        njt_update_worker_processes(cycle, ccf, worker_c);
    } else {
        end = njt_snprintf(s_tmp, 24, "%d", ccf->worker_processes);
        worker_v.data = s_tmp;
        worker_v.len = end - s_tmp;
        rc = njet_iot_client_kv_set((void *)worker_k.data, worker_k.len, worker_v.data, worker_v.len, NULL, master_evt_ctx);
        if (rc != NJT_OK) {
            njt_log_error(NJT_LOG_ERR, cycle->log, 0, "error setting worker count into kvstore");
        }
    }
}


njt_int_t njt_save_register_info_to_kv(njt_cycle_t *cycle){
    njt_int_t           rc;
    njt_str_t           register_info_k = njt_string("kv_http___register_info");
    njt_str_t           register_info_v;


    if (master_evt_ctx) {
        //set register info to kv
        njt_str_set(&register_info_v, "ready_register");
        njt_log_error(NJT_LOG_INFO, cycle->log, 0, 
            "set all register_info:%V", &register_info_v);

        rc = njet_iot_client_kv_set((void *)register_info_k.data, register_info_k.len,
                (void *)register_info_v.data, register_info_v.len, NULL, master_evt_ctx);
        if (rc != NJT_OK) {
            njt_log_error(NJT_LOG_ERR, cycle->log, 0, "error setting register_info into kvstore");
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


njt_int_t njt_save_pids_to_kv(njt_cycle_t *cycle){
    njt_int_t       i;
    njt_int_t       rc;
    u_char          pids[4096];
    u_char          *end;
    njt_int_t       len;
    njt_str_t       pids_k = njt_string("kv_http___sysguard_pids");
    njt_str_t       pids_v;

    end = pids;
    len = 0;
    for (i = 0; i < njt_last_process; i++) {
        if ( strlen(njt_processes[i].name)==strlen("worker process") 
            && njt_strncmp(njt_processes[i].name, "worker process",14) ==0 
            &&  njt_processes[i].pid!=-1) {
            end = njt_snprintf(end, 4096 - len, 
                    "%d_", njt_processes[i].pid);
            len = end - pids;
            if(len > 4000){
                break;
            }
        }
    }

    if (master_evt_ctx) {
        pids_v.data = pids;
        pids_v.len = len;
        njt_log_error(NJT_LOG_INFO, cycle->log, 0, 
            "set all pids:%V", &pids_v);

        rc = njet_iot_client_kv_set((void *)pids_k.data, pids_k.len, pids, len, NULL, master_evt_ctx);
        if (rc != NJT_OK) {
            njt_log_error(NJT_LOG_ERR, cycle->log, 0, "error setting pids into kvstore");
            return NJT_ERROR;
        }
    }

    return NJT_OK;
}


static void njt_update_worker_processes(njt_cycle_t *cycle, njt_core_conf_t *ccf, njt_int_t worker_c)
{
    njt_int_t  i,j,k;
    njt_pid_t  tmp_pid;
    if (njt_shrink_count != njt_shrink_finish_count) {
        njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "previous worker processes change not finish yet, ignore current change");
        return;
    }
    if (ccf->worker_processes != worker_c) {
        if (worker_c > ccf->worker_processes) {
            for (i = ccf->worker_processes; i < worker_c; i++) {
                njt_spawn_process(cycle, njt_worker_process_cycle,
                    (void *)(intptr_t)i, "worker process", NJT_PROCESS_RESPAWN, NULL);
                njt_pass_open_channel(cycle);
            }
        } else {
            k=0;
            j=ccf->worker_processes-worker_c;
            for (i= njt_last_process-1; i>=0; i--) {
                if ( strlen(njt_processes[i].name)==strlen("worker process") 
                    && njt_strncmp(njt_processes[i].name, "worker process",14) ==0 
                    &&  njt_processes[i].pid!=-1) {
                    tmp_pid=njt_processes[i].pid;
                    njt_shrink_processes[k] = njt_processes[i];
                    k++;
                    njt_processes[i].pid = -1;
                    kill(tmp_pid, SIGQUIT);
                    j--;
                    if (j==0) break;
                }
            }
            njt_shrink_finish_count=0;
            njt_shrink_count = k;
            for (i= njt_last_process-1; i>=0; i--) {
                if (njt_processes[i].pid!=-1) {
                    njt_last_process=i+1;
                    break;
                }
            }
        }
        ccf->worker_processes = worker_c;

        //add by clb
        //update all pids to kv
        njt_save_pids_to_kv(cycle);
    }
}

static void
njt_start_worker_processes(njt_cycle_t *cycle, njt_int_t n, njt_int_t type)
{
    njt_int_t  i;

    njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "start worker processes");

    for (i = 0; i < n; i++) {

        njt_spawn_process(cycle, njt_worker_process_cycle,
            (void *)(intptr_t)i, "worker process", type, NULL);

        njt_pass_open_channel(cycle);
    }
}


static void
njt_start_cache_manager_processes(njt_cycle_t *cycle, njt_uint_t respawn)
{
    njt_uint_t    i, manager, loader, purger;
    njt_path_t **path;

    manager = 0;
    loader = 0;
    purger = 0;

    path = njt_cycle->paths.elts;
    for (i = 0; i < njt_cycle->paths.nelts; i++) {

        if (path[i]->manager) {
            manager = 1;
        }

        if (path[i]->loader) {
            loader = 1;
        }

        if (path[i]->purger) {
            purger = 1;
        }
    }

    if (manager == 0 && purger == 0) {
        return;
    }

    njt_spawn_process(cycle, njt_cache_manager_process_cycle,
        &njt_cache_manager_ctx, "cache manager process",
        respawn ? NJT_PROCESS_JUST_RESPAWN : NJT_PROCESS_RESPAWN, NULL);

    njt_pass_open_channel(cycle);

    if (loader == 0) {
        return;
    }

    njt_spawn_process(cycle, njt_cache_manager_process_cycle,
        &njt_cache_loader_ctx, "cache loader process",
        respawn ? NJT_PROCESS_JUST_SPAWN : NJT_PROCESS_NORESPAWN, NULL);

    njt_pass_open_channel(cycle);
}


unsigned int njt_helper_check_cmd(void *cctx)
{
    njt_cycle_t *cycle = (njt_cycle_t *)cctx;

    njt_process_events_and_timers(cycle);

    if (njt_terminate || njt_quit) {
        // njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "exiting");
        if (njt_terminate) {
            // printf("helper found njt_terminate\n");
            return NJT_HELPER_CMD_STOP;
        }

        if (njt_quit) {
            // printf("helper found njt_quit\n");
            return NJT_HELPER_CMD_STOP;
        }
    }

    return NJT_HELPER_CMD_NO;
}


void
njt_helper_process_handler(njt_event_t *ev)
{
    njt_uint_t    i;
    njt_msec_t    next = 0, n;
    njt_path_t **path;

    path = njt_cycle->paths.elts;
    for (i = 0; i < njt_cycle->paths.nelts; i++) {

        if (path[i]->manager) {
            n = path[i]->manager(path[i]->data);

            next = (n <= next) ? n : next;

            njt_time_update();
        }
    }

    if (next == 0) {
        next = 1;
    }

    njt_add_timer(ev, next);
}


static void
njt_helper_preprocess_cycle(njt_cycle_t *cycle, void *data, njt_int_t *reload, void *proc)
{
    njt_helper_check_fp   fp = NULL;
    njt_helper_ctx *ctx = data;
    unsigned int          result;
    njt_md5_t             md5;
    njt_process_t        *process = (njt_process_t *)proc;
    // struct timeval   tv;

    // njt_gettimeofday(&tv);
    ctx->start_time_bef = ctx->start_time;
    ctx->start_time = njt_time();

    if (ctx->handle) {
        njt_dlclose(ctx->handle);
    }

    ctx->run_fp = NULL;

    ctx->handle = njt_dlopen(ctx->file.data);
    if (ctx->handle == NULL) {
        njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, njt_dlopen_n " \"%s\" failed (%s)",
            ctx->file.data, njt_dlerror());
        return;
    }

    fp = njt_dlsym(ctx->handle, "njt_helper_check_version");
    if (fp == NULL) {
        njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, njt_dlsym_n " \"%V\", \"%s\" failed (%s)",
            &ctx->file, "njt_helper_check_version", njt_dlerror());
        return;
    }

    result = fp();
    if (result != NJT_HELPER_VER) {
        njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "njet helper check version failed");
        return;
    }

    *reload = ctx->reload;

    ctx->run_fp = njt_dlsym(ctx->handle, "njt_helper_run");
    if (ctx->run_fp == NULL) {
        njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, njt_dlsym_n " \"%V\", \"%s\" failed (%s)",
            ctx->file.data, "njt_helper_run", njt_dlerror());
    }

    njt_md5_init(&md5);
    njt_md5_update(&md5, ctx->file.data, ctx->file.len);
    njt_md5_update(&md5, ctx->param.conf_fn.data, ctx->param.conf_fn.len);
    njt_md5_final(process->param_md5, &md5);
}


void
njt_helper_process_cycle(njt_cycle_t *cycle, void *data)
{
    njt_helper_ctx *ctx = data;
    void *ident[4];
    njt_event_t    ev;
    char           title[128];
    unsigned int   len, len2;

    /*
     * Set correct process type since closing listening Unix domain socket
     * in a master process also removes the Unix domain socket file.
     */
    njt_process = NJT_PROCESS_HELPER;
    njt_is_privileged_helper = 1;

    njt_close_listening_sockets(cycle);

    /* Set a moderate number of connections for a helper process. */
    cycle->connection_n = 512;

    njt_helper_process_init(cycle, -1);

    njt_memzero(&ev, sizeof(njt_event_t));
    //ev.handler = ctx->handler;
    ev.handler = njt_helper_process_handler;
    ev.data = ident;
    ev.log = cycle->log;
    ident[3] = (void *)-1;

    njt_use_accept_mutex = 0;

    len = njt_strlen("copilot process ");
    njt_memcpy(title, "copilot process ", len);

    if (ctx->param.conf_fn.len + len < 128) {
        len2 = ctx->param.conf_fn.len;
    } else {
        len2 = 127 - len;
    }

    njt_memcpy(title + len, ctx->param.conf_fn.data, len2);
    title[len + len2] = 0;
    njt_setproctitle(title);
    njt_add_timer(&ev, 0);
    ctx->param.check_cmd_fp = njt_helper_check_cmd;
    ctx->param.ctx = cycle;

    if ((ctx->start_time_bef > 0) && (ctx->start_time - ctx->start_time_bef < 12)) {
        njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "to sleep %ui seconds", 12 + ctx->start_time_bef - ctx->start_time);
        sleep(12 + ctx->start_time_bef - ctx->start_time);
    }

    if (ctx->run_fp) {
        ctx->run_fp(ctx->param);
    }

    exit(0);
}


static njt_uint_t
njt_start_helper_processes(njt_cycle_t *cycle, njt_uint_t respawn)
{
    njt_helper_ctx *helpers;
    njt_uint_t            i;
    njt_mqconf_conf_t *mqcf;
    njt_uint_t            nelts = 0;

    for (i = 0; i < cycle->modules_n; i++) {
        if (njt_strcmp(cycle->modules[i]->name, "njt_mqconf_module") != 0) continue;
        mqcf = (njt_mqconf_conf_t *)(cycle->conf_ctx[cycle->modules[i]->index]);
        if (mqcf) {
            helpers = mqcf->helper.elts;
            nelts = mqcf->helper.nelts;

            for (i = 0; i < nelts; i++) {
                njt_spawn_process(cycle, njt_helper_process_cycle,
                    &helpers[i], "copilot process",
                    respawn ? NJT_PROCESS_JUST_RESPAWN : NJT_PROCESS_RESPAWN, njt_helper_preprocess_cycle);
                njt_pass_open_channel(cycle);
            }


            njt_master_init_mdb(cycle, "");
        }
        break;
    }

    return nelts;
}

char *
njt_conf_parse_post_helper(njt_cycle_t *cycle)
{
    njt_int_t             id;
    njt_helper_ctx       *helpers;
    njt_uint_t            i;
    njt_mqconf_conf_t    *mqcf;
    njt_uint_t            nelts = 0;
    njt_md5_t             md5;
    u_char                param_md5[16];

	if (njt_process == NJT_PROCESS_HELPER ) {
        return NJT_OK;
    }

    for (id = 0; id < njt_last_process; id++) {
        if ((njt_processes[id].pid != -1) && (njt_processes[id].preproc)) {
            if (!njt_processes[id].reload) {
                njt_processes[id].confed = 0;
            }
        }
    }

    for (i=0; i<cycle->modules_n; i++) {
        if (njt_strcmp(cycle->modules[i]->name, "njt_mqconf_module") != 0) continue;
        mqcf= (njt_mqconf_conf_t *) (cycle->conf_ctx[cycle->modules[i]->index]);
        if (mqcf) {
            helpers = mqcf->helper.elts;
            nelts = mqcf->helper.nelts;
            for (i = 0; i < nelts; i++) {
                if (!helpers[i].reload) {
                    njt_md5_init(&md5);
                    njt_md5_update(&md5, helpers[i].file.data, helpers[i].file.len);
                    njt_md5_update(&md5, helpers[i].param.conf_fn.data, helpers[i].param.conf_fn.len);
                    njt_md5_final(param_md5, &md5);

                    for (id = 0; id < njt_last_process; id++) {
                        if ((njt_processes[id].pid != -1) && (njt_processes[id].preproc) && !njt_processes[id].reload && !memcmp(param_md5, njt_processes[id].param_md5, 16)) {
                            njt_processes[id].confed = 1;
                        }
                    }
                }
            }
        }
        break;
    }

    for (id = 0; id < njt_last_process; id++) {
        if ((njt_processes[id].pid != -1) && (njt_processes[id].preproc) && !njt_processes[id].reload && !njt_processes[id].confed) {
            njt_log_error(NJT_LOG_EMERG, cycle->log, 0, "Need to keep original non-reloadable helper directive!");
            return NJT_CONF_ERROR;
        }
    }

    return NJT_CONF_OK;
}

static njt_uint_t
njt_restart_helper_processes(njt_cycle_t *cycle, njt_uint_t respawn)
{
    njt_int_t             id;
    njt_helper_ctx       *helpers;
    njt_uint_t            i;
    njt_mqconf_conf_t    *mqcf;
    njt_uint_t            nelts = 0;
    njt_md5_t             md5;
    u_char                param_md5[16];

    for (id = 0; id < njt_last_process; id++) {
        if ((njt_processes[id].pid != -1) && (njt_processes[id].preproc)) {
            if (njt_processes[id].reload) {
                njt_reap_helper = 1;
                return 1;
            } else {
                njt_processes[id].data = NULL;
            }
        }
    }

    for (i=0; i<cycle->modules_n; i++) {
        if (njt_strcmp(cycle->modules[i]->name, "njt_mqconf_module") != 0) continue;
        mqcf= (njt_mqconf_conf_t *) (cycle->conf_ctx[cycle->modules[i]->index]);
        if (mqcf) {
            helpers = mqcf->helper.elts;
            nelts = mqcf->helper.nelts;
            for (i = 0; i < nelts; i++) {
                if (!helpers[i].reload) {
                    njt_md5_init(&md5);
                    njt_md5_update(&md5, helpers[i].file.data, helpers[i].file.len);
                    njt_md5_update(&md5, helpers[i].param.conf_fn.data, helpers[i].param.conf_fn.len);
                    njt_md5_final(param_md5, &md5);

                    for (id = 0; id < njt_last_process; id++) {
                        if ((njt_processes[id].pid != -1) && (njt_processes[id].preproc) && !njt_processes[id].reload && !memcmp(param_md5, njt_processes[id].param_md5, 16)) {
                            njt_log_error(NJT_LOG_CRIT, cycle->log, 0, "njt_processes[%i].data=0x%p <- &helpers[%i]=0x%p when reloading", id, njt_processes[id].data, i, &helpers[i]);
                            njt_processes[id].data = (void *)&helpers[i];
                        }
                    }
                    continue;
                }

                njt_spawn_process(cycle, njt_helper_process_cycle,
                            &helpers[i], "copilot process",
                            respawn ? NJT_PROCESS_JUST_RESPAWN : NJT_PROCESS_RESPAWN, njt_helper_preprocess_cycle);
                njt_pass_open_channel(cycle);
            }

        }
        break;
    }

    for (id = 0; id < njt_last_process; id++) {
        if ((njt_processes[id].pid != -1) && (njt_processes[id].preproc) && !njt_processes[id].reload && !njt_processes[id].data) {
            njt_log_error(NJT_LOG_EMERG, cycle->log, 0, "Wrong helper directive!");
            break;
        }
    }

    return nelts;
}


static void
njt_start_privileged_agent_processes(njt_cycle_t *cycle, njt_uint_t respawn)
{
    njt_core_conf_t       *ccf;

    ccf = (njt_core_conf_t *) njt_get_conf(cycle->conf_ctx,
                                           njt_core_module);

    if (!ccf->privileged_agent) {
        return;
    }
    if (ccf->privileged_agent_connections == 0) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                      "%ui worker_connection is not enough, "
                      "privileged agent process cannot be spawned",
                      ccf->privileged_agent_connections);
        return;
    }
    njt_privileged_agent_exited=0;
    njt_spawn_process(cycle, njt_privileged_agent_process_cycle,
                      "privileged agent process", "privileged agent process",
                      NJT_PROCESS_NORESPAWN,NULL);

    njt_pass_open_channel(cycle);
}

static void
njt_pass_open_channel(njt_cycle_t *cycle)
{
    njt_int_t      i;
    njt_channel_t  ch;

    njt_memzero(&ch, sizeof(njt_channel_t));

    ch.command = NJT_CMD_OPEN_CHANNEL;
    ch.pid = njt_processes[njt_process_slot].pid;
    ch.slot = njt_process_slot;
    ch.fd = njt_processes[njt_process_slot].channel[0];

    for (i = 0; i < njt_last_process; i++) {

        if (i == njt_process_slot
            || njt_processes[i].pid == -1
            || njt_processes[i].channel[0] == -1) {
            continue;
        }

        njt_log_debug6(NJT_LOG_DEBUG_CORE, cycle->log, 0,
            "pass channel s:%i pid:%P fd:%d to s:%i pid:%P fd:%d",
            ch.slot, ch.pid, ch.fd,
            i, njt_processes[i].pid,
            njt_processes[i].channel[0]);

        /* TODO: NJT_AGAIN */

        njt_write_channel(njt_processes[i].channel[0],
            &ch, sizeof(njt_channel_t), cycle->log);
    }
}


static void
njt_signal_worker_processes(njt_cycle_t *cycle, int signo)
{
    njt_int_t      i;
    njt_err_t      err;
    njt_channel_t  ch;

    njt_memzero(&ch, sizeof(njt_channel_t));

#if (NJT_BROKEN_SCM_RIGHTS)

    ch.command = 0;

#else

    switch (signo) {

    case njt_signal_value(NJT_SHUTDOWN_SIGNAL):
        ch.command = NJT_CMD_QUIT;
        break;

    case njt_signal_value(NJT_TERMINATE_SIGNAL):
        ch.command = NJT_CMD_TERMINATE;
        break;

    case njt_signal_value(NJT_REOPEN_SIGNAL):
        ch.command = NJT_CMD_REOPEN;
        break;

    default:
        ch.command = 0;
    }

#endif

    ch.fd = -1;


    for (i = 0; i < njt_last_process; i++) {

        njt_log_debug7(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
            "child: %i %P e:%d t:%d d:%d r:%d j:%d",
            i,
            njt_processes[i].pid,
            njt_processes[i].exiting,
            njt_processes[i].exited,
            njt_processes[i].detached,
            njt_processes[i].respawn,
            njt_processes[i].just_spawn);

        if (njt_processes[i].detached || njt_processes[i].pid == -1) {
            continue;
        }

        if (njt_processes[i].just_spawn) {
            njt_processes[i].just_spawn = 0;
            continue;
        }

        if (njt_processes[i].exiting
            && signo == njt_signal_value(NJT_SHUTDOWN_SIGNAL)) {
            continue;
        }

        if (ch.command) {
            if (njt_write_channel(njt_processes[i].channel[0],
                &ch, sizeof(njt_channel_t), cycle->log)
                == NJT_OK) {
                if (signo != njt_signal_value(NJT_REOPEN_SIGNAL)) {
                    njt_processes[i].exiting = 1;
                }

                continue;
            }
        }

        njt_log_debug2(NJT_LOG_DEBUG_CORE, cycle->log, 0,
            "kill (%P, %d)", njt_processes[i].pid, signo);

        if (kill(njt_processes[i].pid, signo) == -1) {
            err = njt_errno;
            njt_log_error(NJT_LOG_ALERT, cycle->log, err,
                "kill(%P, %d) failed", njt_processes[i].pid, signo);

            if (err == NJT_ESRCH) {
                njt_processes[i].exited = 1;
                njt_processes[i].exiting = 0;
                njt_reap = 1;
            }

            continue;
        }

        if (signo != njt_signal_value(NJT_REOPEN_SIGNAL)) {
            njt_processes[i].exiting = 1;
        }
    }
}


static void
njt_cmd_worker_processes(njt_cycle_t *cycle, njt_uint_t cmd)
{
    if (cmd != NJT_CMD_RESTART) {
        // Not support othter commands just now
        return;
    }

    int signo = njt_signal_value(NJT_SHUTDOWN_SIGNAL);
    njt_int_t      i;
    njt_err_t      err;
    njt_channel_t  ch;

    njt_memzero(&ch, sizeof(njt_channel_t));
    ch.command = NJT_CMD_QUIT;
    ch.fd = -1;

    for (i = 0; i < njt_last_process; i++) {

        njt_log_debug7(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
                       "child: %i %P e:%d t:%d d:%d r:%d j:%d",
                       i,
                       njt_processes[i].pid,
                       njt_processes[i].exiting,
                       njt_processes[i].exited,
                       njt_processes[i].detached,
                       njt_processes[i].respawn,
                       njt_processes[i].just_spawn);

        if (njt_processes[i].detached || njt_processes[i].pid == -1) {
            continue;
        }

        if (njt_processes[i].just_spawn) {
            njt_processes[i].just_spawn = 0;
            continue;
        }

        if (njt_processes[i].exiting
            && signo == njt_signal_value(NJT_SHUTDOWN_SIGNAL))
        {
            continue;
        }

        if (njt_processes[i].preproc) {
            // ch.command = NJT_CMD_RESTART;

            if (!njt_processes[i].reload) {
                continue;
            }

            if (njt_write_channel(njt_processes[i].channel[0],
                                &ch, sizeof(njt_channel_t), cycle->log)
                == NJT_OK)
            {
                njt_processes[i].exiting = 1;  
            }

            continue;
        } else {
            // ch.command = NJT_CMD_QUIT;
            if (njt_write_channel(njt_processes[i].channel[0],
                                &ch, sizeof(njt_channel_t), cycle->log)
                == NJT_OK)
            {
                if (signo != njt_signal_value(NJT_REOPEN_SIGNAL)) {
                    njt_processes[i].exiting = 1;
                }

                continue;
            }
        }

        njt_log_debug2(NJT_LOG_DEBUG_CORE, cycle->log, 0,
                       "kill (%P, %d)", njt_processes[i].pid, signo);

        if (kill(njt_processes[i].pid, signo) == -1) {
            err = njt_errno;
            njt_log_error(NJT_LOG_ALERT, cycle->log, err,
                          "kill(%P, %d) failed", njt_processes[i].pid, signo);

            if (err == NJT_ESRCH) {
                njt_processes[i].exited = 1;
                njt_processes[i].exiting = 0;
                njt_reap = 1;
            }

            continue;
        }

        if (signo != njt_signal_value(NJT_REOPEN_SIGNAL)) {
            njt_processes[i].exiting = 1;
        }
    }
}


static void
njt_signal_helper_processes(njt_cycle_t *cycle, int signo)
{
    njt_int_t      i;
    njt_err_t      err;
    njt_channel_t  ch;

    njt_memzero(&ch, sizeof(njt_channel_t));

#if (NJT_BROKEN_SCM_RIGHTS)

    ch.command = 0;

#else

    switch (signo) {

    case njt_signal_value(NJT_SHUTDOWN_SIGNAL):
        ch.command = NJT_CMD_QUIT;
        break;

    case njt_signal_value(NJT_TERMINATE_SIGNAL):
        ch.command = NJT_CMD_TERMINATE;
        break;

    case njt_signal_value(NJT_REOPEN_SIGNAL):
        ch.command = NJT_CMD_REOPEN;
        break;

    default:
        ch.command = 0;
    }

#endif

    ch.fd = -1;


    for (i = 0; i < njt_last_process; i++) {

        njt_log_debug7(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
            "child: %i %P e:%d t:%d d:%d r:%d j:%d",
            i,
            njt_processes[i].pid,
            njt_processes[i].exiting,
            njt_processes[i].exited,
            njt_processes[i].detached,
            njt_processes[i].respawn,
            njt_processes[i].just_spawn);

        if (!njt_processes[i].preproc) {
            continue;
        }

        if (njt_processes[i].detached || njt_processes[i].pid == -1) {
            continue;
        }

        if (njt_processes[i].just_spawn) {
            njt_processes[i].just_spawn = 0;
            continue;
        }

        if (njt_processes[i].exiting
            && signo == njt_signal_value(NJT_SHUTDOWN_SIGNAL)) {
            continue;
        }

        if (ch.command) {
            if (njt_write_channel(njt_processes[i].channel[0],
                &ch, sizeof(njt_channel_t), cycle->log)
                == NJT_OK) {
                if (signo != njt_signal_value(NJT_REOPEN_SIGNAL)) {
                    njt_processes[i].exiting = 1;
                }

                continue;
            }
        }

        njt_log_debug2(NJT_LOG_DEBUG_CORE, cycle->log, 0,
            "kill (%P, %d)", njt_processes[i].pid, signo);

        if (kill(njt_processes[i].pid, signo) == -1) {
            err = njt_errno;
            njt_log_error(NJT_LOG_ALERT, cycle->log, err,
                "kill(%P, %d) failed", njt_processes[i].pid, signo);

            if (err == NJT_ESRCH) {
                njt_processes[i].exited = 1;
                njt_processes[i].exiting = 0;
                njt_reap = 1;
            }

            continue;
        }

        if (signo != njt_signal_value(NJT_REOPEN_SIGNAL)) {
            njt_processes[i].exiting = 1;
        }
    }
}


static njt_uint_t
njt_reap_children(njt_cycle_t *cycle)
{
    njt_int_t         i, n;
    njt_uint_t        live;
    njt_channel_t     ch;
    njt_core_conf_t *ccf;

    njt_memzero(&ch, sizeof(njt_channel_t));

    ch.command = NJT_CMD_CLOSE_CHANNEL;
    ch.fd = -1;

    live = 0;
    for (i = 0; i < njt_last_process; i++) {

        njt_log_debug7(NJT_LOG_DEBUG_EVENT, cycle->log, 0,
            "child: %i %P e:%d t:%d d:%d r:%d j:%d",
            i,
            njt_processes[i].pid,
            njt_processes[i].exiting,
            njt_processes[i].exited,
            njt_processes[i].detached,
            njt_processes[i].respawn,
            njt_processes[i].just_spawn);

        if (njt_processes[i].pid == -1) {
            continue;
        }

        if (njt_processes[i].exited) {

            if (!njt_processes[i].detached) {
                njt_close_channel(njt_processes[i].channel, cycle->log);

                njt_processes[i].channel[0] = -1;
                njt_processes[i].channel[1] = -1;

                ch.pid = njt_processes[i].pid;
                ch.slot = i;

                for (n = 0; n < njt_last_process; n++) {
                    if (njt_processes[n].exited
                        || njt_processes[n].pid == -1
                        || njt_processes[n].channel[0] == -1) {
                        continue;
                    }

                    njt_log_debug3(NJT_LOG_DEBUG_CORE, cycle->log, 0,
                        "pass close channel s:%i pid:%P to:%P",
                        ch.slot, ch.pid, njt_processes[n].pid);

                    /* TODO: NJT_AGAIN */

                    njt_write_channel(njt_processes[n].channel[0],
                        &ch, sizeof(njt_channel_t), cycle->log);
                }
            }

            if (njt_processes[i].respawn
                && !njt_processes[i].exiting
                && !njt_terminate
                && !njt_quit) {
                if (njt_spawn_process(cycle, njt_processes[i].proc,
                    njt_processes[i].data,
                    njt_processes[i].name, i, njt_processes[i].preproc)
                    == NJT_INVALID_PID) {
                    njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                        "could not respawn %s",
                        njt_processes[i].name);
                    continue;
                }


                njt_pass_open_channel(cycle);

                live = 1;

                continue;
            }

            if (njt_processes[i].pid == njt_new_binary) {

                ccf = (njt_core_conf_t *)njt_get_conf(cycle->conf_ctx,
                    njt_core_module);

                if (njt_rename_file((char *)ccf->oldpid.data,
                    (char *)ccf->pid.data)
                    == NJT_FILE_ERROR) {
                    njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                        njt_rename_file_n " %s back to %s failed "
                        "after the new binary process \"%s\" exited",
                        ccf->oldpid.data, ccf->pid.data, njt_argv[0]);
                }

                njt_new_binary = 0;
                if (njt_noaccepting) {
                    njt_restart = 1;
                    njt_noaccepting = 0;
                }
            }

            if (i == njt_last_process - 1) {
                njt_last_process--;

            } else {
                njt_processes[i].pid = -1;
            }

        } else if (njt_processes[i].exiting || !njt_processes[i].detached) {
            live = 1;
        }
    }

    return live;
}


static void
njt_master_process_exit(njt_cycle_t *cycle)
{
    njt_uint_t  i;

    njt_delete_pidfile(cycle);

    njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "exit");

    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->exit_master) {
            cycle->modules[i]->exit_master(cycle);
        }
    }

    njt_close_listening_sockets(cycle);

    /*
     * Copy njt_cycle->log related data to the special static exit cycle,
     * log, and log file structures enough to allow a signal handler to log.
     * The handler may be called when standard njt_cycle->log allocated from
     * njt_cycle->pool is already destroyed.
     */


    njt_exit_log = *njt_log_get_file_log(njt_cycle->log);

    njt_exit_log_file.fd = njt_exit_log.file->fd;
    njt_exit_log.file = &njt_exit_log_file;
    njt_exit_log.next = NULL;
    njt_exit_log.writer = NULL;

    njt_exit_cycle.log = &njt_exit_log;
    njt_exit_cycle.files = njt_cycle->files;
    njt_exit_cycle.files_n = njt_cycle->files_n;
    njt_cycle = &njt_exit_cycle;

    // openresty patch
    if (saved_init_cycle_pool != NULL && saved_init_cycle_pool != cycle->pool) {
        njt_destroy_pool(saved_init_cycle_pool);
        saved_init_cycle_pool = NULL;
    }
    // openresty patch end

    njt_destroy_pool(cycle->pool);

    exit(0);
}


static void
njt_worker_process_cycle(njt_cycle_t *cycle, void *data)
{
    njt_int_t worker = (intptr_t)data;

    njt_process = NJT_PROCESS_WORKER;
    njt_worker = worker;

    njt_worker_process_init(cycle, worker);

    njt_setproctitle("worker process");

    for (;; ) {

        if (njt_exiting) {
            if (njt_event_no_timers_left() == NJT_OK) {
                njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "exiting");
                njt_worker_process_exit(cycle);
            }
        }

        // njt_log_debug0(NJT_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

        njt_process_events_and_timers(cycle);

        if (njt_terminate) {
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "exiting");
            njt_worker_process_exit(cycle);
        }

        if (njt_quit) {
            njt_quit = 0;
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0,
                "gracefully shutting down");
            njt_setproctitle("worker process is shutting down");

            if (!njt_exiting) {
                njt_exiting = 1;
                njt_set_shutdown_timer(cycle);
                njt_close_listening_sockets(cycle);
                njt_close_idle_connections(cycle);
                njt_event_process_posted(cycle, &njt_posted_events);
            }
        }

        if (njt_reopen) {
            njt_reopen = 0;
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "reopening logs");
            njt_reopen_files(cycle, -1);
        }
    }
}


static void
njt_worker_process_init(njt_cycle_t *cycle, njt_int_t worker)
{
    sigset_t          set;
    njt_int_t         n;
    njt_time_t *tp;
    njt_uint_t        i;
    njt_cpuset_t *cpu_affinity;
    struct rlimit     rlmt;
    njt_core_conf_t *ccf;
    // njt_listening_t *ls;

    if (njt_set_environment(cycle, NULL) == NULL) {
        /* fatal */
        exit(2);
    }

    ccf = (njt_core_conf_t *)njt_get_conf(cycle->conf_ctx, njt_core_module);

    if (worker >= 0 && ccf->priority != 0) {
        if (setpriority(PRIO_PROCESS, 0, ccf->priority) == -1) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                "setpriority(%d) failed", ccf->priority);
        }
    }

    if (ccf->rlimit_nofile != NJT_CONF_UNSET) {
        rlmt.rlim_cur = (rlim_t)ccf->rlimit_nofile;
        rlmt.rlim_max = (rlim_t)ccf->rlimit_nofile;

        if (setrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                "setrlimit(RLIMIT_NOFILE, %i) failed",
                ccf->rlimit_nofile);
        }
    }

    if (ccf->rlimit_core != NJT_CONF_UNSET) {
        rlmt.rlim_cur = (rlim_t)ccf->rlimit_core;
        rlmt.rlim_max = (rlim_t)ccf->rlimit_core;

        if (setrlimit(RLIMIT_CORE, &rlmt) == -1) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                "setrlimit(RLIMIT_CORE, %O) failed",
                ccf->rlimit_core);
        }
    }

    if (!njt_is_privileged_helper && geteuid() == 0) {
        if (setgid(ccf->group) == -1) {
            njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                "setgid(%d) failed", ccf->group);
            /* fatal */
            exit(2);
        }

        if (initgroups(ccf->username, ccf->group) == -1) {
            njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                "initgroups(%s, %d) failed",
                ccf->username, ccf->group);
        }

#if (NJT_HAVE_PR_SET_KEEPCAPS && NJT_HAVE_CAPABILITIES)
        if (ccf->transparent && ccf->user) {
            if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == -1) {
                njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                    "prctl(PR_SET_KEEPCAPS, 1) failed");
                /* fatal */
                exit(2);
            }
        }
#endif

        if (!njt_is_privileged_agent) {
            if (setuid(ccf->user) == -1) {
                njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                    "setuid(%d) failed", ccf->user);
                /* fatal */
                exit(2);
            }
        }

#if (NJT_HAVE_CAPABILITIES)
        if (ccf->transparent && ccf->user) {
            struct __user_cap_data_struct    data;
            struct __user_cap_header_struct  header;

            njt_memzero(&header, sizeof(struct __user_cap_header_struct));
            njt_memzero(&data, sizeof(struct __user_cap_data_struct));

            header.version = _LINUX_CAPABILITY_VERSION_1;
            data.effective = CAP_TO_MASK(CAP_NET_RAW);
            data.permitted = data.effective;

            if (syscall(SYS_capset, &header, &data) == -1) {
                njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                    "capset() failed");
                /* fatal */
                exit(2);
            }
        }
#endif
    }

    if (worker >= 0) {
        cpu_affinity = njt_get_cpu_affinity(worker);

        if (cpu_affinity) {
            njt_setaffinity(cpu_affinity, cycle->log);
        }
    }

#if (NJT_HAVE_PR_SET_DUMPABLE)

    /* allow coredump after setuid() in Linux 2.4.x */

    if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == -1) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
            "prctl(PR_SET_DUMPABLE) failed");
    }

#endif

    if (ccf->working_directory.len) {
        if (chdir((char *)ccf->working_directory.data) == -1) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                "chdir(\"%s\") failed", ccf->working_directory.data);
            /* fatal */
            exit(2);
        }
    }

    sigemptyset(&set);

    if (sigprocmask(SIG_SETMASK, &set, NULL) == -1) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
            "sigprocmask() failed");
    }

    tp = njt_timeofday();
    srandom(((unsigned)njt_pid << 16) ^ tp->sec ^ tp->msec);

    // /*
    //  * disable deleting previous events for the listening sockets because
    //  * in the worker processes there are no events at all at this point
    //  */
    // ls = cycle->listening.elts;
    // for (i = 0; i < cycle->listening.nelts; i++) {
    //     ls[i].previous = NULL;
    // }

    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->init_process) {
            if (cycle->modules[i]->init_process(cycle) == NJT_ERROR) {
                /* fatal */
                exit(2);
            }
        }
    }

    //for privileged agent, all listening sockets were closed
    //restore lisening.nelts for dynamic configuration
    if (njt_is_privileged_agent) {
        cycle->listening.nelts = njt_master_listening_count;
    }

    for (n = 0; n < njt_last_process; n++) {

        if (njt_processes[n].pid == -1) {
            continue;
        }

        if (n == njt_process_slot) {
            continue;
        }

        if (njt_processes[n].channel[1] == -1) {
            continue;
        }

        if (close(njt_processes[n].channel[1]) == -1) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                "close() channel failed");
        }
    }

    if (close(njt_processes[njt_process_slot].channel[0]) == -1) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
            "close() channel failed");
    }

#if 0
    njt_last_process = 0;
#endif

    if (njt_add_channel_event(cycle, njt_channel, NJT_READ_EVENT,
        njt_channel_handler)
        == NJT_ERROR) {
        /* fatal */
        exit(2);
    }
}


static void
njt_helper_process_init(njt_cycle_t *cycle, njt_int_t worker)
{
    sigset_t          set;
    njt_int_t         n;
    njt_time_t *tp;
    njt_uint_t        i;
    njt_cpuset_t *cpu_affinity;
    struct rlimit     rlmt;
    njt_core_conf_t *ccf;
    njt_listening_t *ls;

    if (njt_set_environment(cycle, NULL) == NULL) {
        /* fatal */
        exit(2);
    }

    ccf = (njt_core_conf_t *)njt_get_conf(cycle->conf_ctx, njt_core_module);

    if (worker >= 0 && ccf->priority != 0) {
        if (setpriority(PRIO_PROCESS, 0, ccf->priority) == -1) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                "setpriority(%d) failed", ccf->priority);
        }
    }

    if (ccf->rlimit_nofile != NJT_CONF_UNSET) {
        rlmt.rlim_cur = (rlim_t)ccf->rlimit_nofile;
        rlmt.rlim_max = (rlim_t)ccf->rlimit_nofile;

        if (setrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                "setrlimit(RLIMIT_NOFILE, %i) failed",
                ccf->rlimit_nofile);
        }
    }

    if (ccf->rlimit_core != NJT_CONF_UNSET) {
        rlmt.rlim_cur = (rlim_t)ccf->rlimit_core;
        rlmt.rlim_max = (rlim_t)ccf->rlimit_core;

        if (setrlimit(RLIMIT_CORE, &rlmt) == -1) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                "setrlimit(RLIMIT_CORE, %O) failed",
                ccf->rlimit_core);
        }
    }

    if (!njt_is_privileged_helper && geteuid() == 0) {
        if (setgid(ccf->group) == -1) {
            njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                "setgid(%d) failed", ccf->group);
            /* fatal */
            exit(2);
        }

        if (initgroups(ccf->username, ccf->group) == -1) {
            njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                "initgroups(%s, %d) failed",
                ccf->username, ccf->group);
        }

#if (NJT_HAVE_PR_SET_KEEPCAPS && NJT_HAVE_CAPABILITIES)
        if (ccf->transparent && ccf->user) {
            if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == -1) {
                njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                    "prctl(PR_SET_KEEPCAPS, 1) failed");
                /* fatal */
                exit(2);
            }
        }
#endif

        if (setuid(ccf->user) == -1) {
            njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                "setuid(%d) failed", ccf->user);
            /* fatal */
            exit(2);
        }

#if (NJT_HAVE_CAPABILITIES)
        if (ccf->transparent && ccf->user) {
            struct __user_cap_data_struct    data;
            struct __user_cap_header_struct  header;

            njt_memzero(&header, sizeof(struct __user_cap_header_struct));
            njt_memzero(&data, sizeof(struct __user_cap_data_struct));

            header.version = _LINUX_CAPABILITY_VERSION_1;
            data.effective = CAP_TO_MASK(CAP_NET_RAW);
            data.permitted = data.effective;

            if (syscall(SYS_capset, &header, &data) == -1) {
                njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                    "capset() failed");
                /* fatal */
                exit(2);
            }
        }
#endif
    }

    if (worker >= 0) {
        cpu_affinity = njt_get_cpu_affinity(worker);

        if (cpu_affinity) {
            njt_setaffinity(cpu_affinity, cycle->log);
        }
    }

#if (NJT_HAVE_PR_SET_DUMPABLE)

    /* allow coredump after setuid() in Linux 2.4.x */

    if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == -1) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
            "prctl(PR_SET_DUMPABLE) failed");
    }

#endif

    if (ccf->working_directory.len) {
        if (chdir((char *)ccf->working_directory.data) == -1) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                "chdir(\"%s\") failed", ccf->working_directory.data);
            /* fatal */
            exit(2);
        }
    }

    sigemptyset(&set);

    if (sigprocmask(SIG_SETMASK, &set, NULL) == -1) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
            "sigprocmask() failed");
    }

    tp = njt_timeofday();
    srandom(((unsigned)njt_pid << 16) ^ tp->sec ^ tp->msec);

    /*
     * disable deleting previous events for the listening sockets because
     * in the worker processes there are no events at all at this point
     */
    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {
        ls[i].previous = NULL;
    }

    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->init_process && njt_strcmp(cycle->modules[i]->name, "njt_event_core_module") == 0) {
            if (cycle->modules[i]->init_process(cycle) == NJT_ERROR) {
                /* fatal */
                exit(2);
            }
            break;
        }
    }

    for (n = 0; n < njt_last_process; n++) {

        if (njt_processes[n].pid == -1) {
            continue;
        }

        if (n == njt_process_slot) {
            continue;
        }

        if (njt_processes[n].channel[1] == -1) {
            continue;
        }

        if (close(njt_processes[n].channel[1]) == -1) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                "close() channel failed");
        }
    }

    if (close(njt_processes[njt_process_slot].channel[0]) == -1) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
            "close() channel failed");
    }

#if 0
    njt_last_process = 0;
#endif

    if (njt_add_channel_event(cycle, njt_channel, NJT_READ_EVENT,
        njt_channel_handler)
        == NJT_ERROR) {
        /* fatal */
        exit(2);
    }
}


static void
njt_worker_process_exit(njt_cycle_t *cycle)
{
    njt_uint_t         i;
    njt_connection_t *c;
#if (NJT_DEBUG)
    njt_event_t              *read_events;
    njt_event_t              *write_events;
#endif
    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->exit_process) {
            cycle->modules[i]->exit_process(cycle);
        }
    }

    if (njt_exiting) {
        c = cycle->connections;
        for (i = 0; i < cycle->connection_n; i++) {
            if (c[i].fd != -1
                && c[i].read
                && !c[i].read->accept
#if (HAVE_SOCKET_CLOEXEC_PATCH) // openresty patch
                && !c[i].read->skip_socket_leak_check
#endif // openresty patch end
                && !c[i].read->channel
                && !c[i].read->resolver) {
                njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                    "*%uA open socket #%d left in connection %ui",
                    c[i].number, c[i].fd, i);
                njt_debug_quit = 1;
            }
        }

        if (njt_debug_quit) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, 0, "aborting");
            njt_debug_point();
        }
    }

    /*
     * Copy njt_cycle->log related data to the special static exit cycle,
     * log, and log file structures enough to allow a signal handler to log.
     * The handler may be called when standard njt_cycle->log allocated from
     * njt_cycle->pool is already destroyed.
     */

    njt_exit_log = *njt_log_get_file_log(njt_cycle->log);

    njt_exit_log_file.fd = njt_exit_log.file->fd;
    njt_exit_log.file = &njt_exit_log_file;
    njt_exit_log.next = NULL;
    njt_exit_log.writer = NULL;

    njt_exit_cycle.log = &njt_exit_log;
    njt_exit_cycle.files = njt_cycle->files;
    njt_exit_cycle.files_n = njt_cycle->files_n;
    njt_cycle = &njt_exit_cycle;

    njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, "exit");
#if (NJT_DEBUG)
    read_events = cycle->read_events;
    write_events = cycle->write_events;
    c = cycle->connections;
#endif

    njt_destroy_pool(cycle->pool);

#if (NJT_DEBUG)
    if(c != NULL)
        njt_free(c);
    if(read_events != NULL)
        njt_free(read_events);
    if(write_events != NULL)
        njt_free(write_events);
#endif


    exit(0);
}


void
njt_helper_process_exit(njt_cycle_t *cycle)
{
    njt_uint_t          i;
    njt_connection_t    *c = NULL;
#if (NJT_DEBUG)
    njt_event_t              *read_events;
    njt_event_t              *write_events;
#endif
    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->exit_process) {
            cycle->modules[i]->exit_process(cycle);
        }
    }

    njt_close_listening_sockets(cycle);

    /*
     * Copy njt_cycle->log related data to the special static exit cycle,
     * log, and log file structures enough to allow a signal handler to log.
     * The handler may be called when standard njt_cycle->log allocated from
     * njt_cycle->pool is already destroyed.
     */

    njt_exit_log = *njt_log_get_file_log(njt_cycle->log);

    njt_exit_log_file.fd = njt_exit_log.file->fd;
    njt_exit_log.file = &njt_exit_log_file;
    njt_exit_log.next = NULL;
    njt_exit_log.writer = NULL;

    njt_exit_cycle.log = &njt_exit_log;
    njt_exit_cycle.files = njt_cycle->files;
    njt_exit_cycle.files_n = njt_cycle->files_n;
    njt_cycle = &njt_exit_cycle;

    njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, "exit");

//add by clb
//close all connection of active
    c = cycle->connections;
    for (i = 0; i < cycle->connection_n; i++) {
        if (c[i].fd == (njt_socket_t) -1
            || c[i].read == NULL
            || c[i].read->accept
            || c[i].read->channel
            || c[i].read->resolver)
        {
            continue;
        }

        c[i].close = 1;
        c[i].error = 1;

        c[i].read->handler(c[i].read);
    }
//end

#if (NJT_DEBUG)
    	read_events = cycle->read_events;
	write_events = cycle->write_events;
        c = cycle->connections;
        for (i = 0; i < cycle->connection_n; i++) {
		if (c[i].fd != -1
                && c[i].read
                && !c[i].read->accept
                && !c[i].read->channel
                && !c[i].read->resolver) {
                        njt_destroy_pool(c[i].pool);
                }
        }
#endif

    njt_destroy_pool(cycle->pool);

#if (NJT_DEBUG)
    if(c != NULL)
        njt_free(c);
    if(read_events != NULL)
        njt_free(read_events);
    if(write_events != NULL)
        njt_free(write_events);
#endif


    exit(0);
}


static void
njt_channel_handler(njt_event_t *ev)
{
    njt_int_t          n;
    njt_channel_t      ch;
    njt_connection_t *c;

    if (ev->timedout) {
        ev->timedout = 0;
        return;
    }

    c = ev->data;

    njt_log_debug0(NJT_LOG_DEBUG_CORE, ev->log, 0, "channel handler");

    for (;; ) {

        n = njt_read_channel(c->fd, &ch, sizeof(njt_channel_t), ev->log);

        njt_log_debug1(NJT_LOG_DEBUG_CORE, ev->log, 0, "channel: %i", n);

        if (n == NJT_ERROR) {

            if (njt_event_flags & NJT_USE_EPOLL_EVENT) {
                njt_del_conn(c, 0);
            }

            njt_close_connection(c);
            return;
        }

        if (njt_event_flags & NJT_USE_EVENTPORT_EVENT) {
            if (njt_add_event(ev, NJT_READ_EVENT, 0) == NJT_ERROR) {
                return;
            }
        }

        if (n == NJT_AGAIN) {
            return;
        }

        njt_log_debug1(NJT_LOG_DEBUG_CORE, ev->log, 0,
            "channel command: %ui", ch.command);

        switch (ch.command) {

        case NJT_CMD_QUIT:
            njt_quit = 1;
            break;

        case NJT_CMD_TERMINATE:
            njt_terminate = 1;
            break;

        case NJT_CMD_REOPEN:
            njt_reopen = 1;
            break;

        case NJT_CMD_OPEN_CHANNEL:

            njt_log_debug3(NJT_LOG_DEBUG_CORE, ev->log, 0,
                "get channel s:%i pid:%P fd:%d",
                ch.slot, ch.pid, ch.fd);

            njt_processes[ch.slot].pid = ch.pid;
            njt_processes[ch.slot].channel[0] = ch.fd;
            break;

        case NJT_CMD_CLOSE_CHANNEL:

            njt_log_debug4(NJT_LOG_DEBUG_CORE, ev->log, 0,
                "close channel s:%i pid:%P our:%P fd:%d",
                ch.slot, ch.pid, njt_processes[ch.slot].pid,
                njt_processes[ch.slot].channel[0]);

            if (close(njt_processes[ch.slot].channel[0]) == -1) {
                njt_log_error(NJT_LOG_ALERT, ev->log, njt_errno,
                    "close() channel failed");
            }

            njt_processes[ch.slot].channel[0] = -1;
            break;
        }
    }
}


static void
njt_cache_manager_process_cycle(njt_cycle_t *cycle, void *data)
{
    njt_cache_manager_ctx_t *ctx = data;

    void *ident[4];
    njt_event_t   ev;

    /*
     * Set correct process type since closing listening Unix domain socket
     * in a master process also removes the Unix domain socket file.
     */
    njt_process = NJT_PROCESS_HELPER;

    njt_close_listening_sockets(cycle);

    /* Set a moderate number of connections for a helper process. */
    cycle->connection_n = 512;

    njt_worker_process_init(cycle, -1);

    njt_memzero(&ev, sizeof(njt_event_t));
    ev.handler = ctx->handler;
    ev.data = ident;
    ev.log = cycle->log;
    ident[3] = (void *)-1;

    njt_use_accept_mutex = 0;

    njt_setproctitle(ctx->name);

    njt_add_timer(&ev, ctx->delay);

    for (;; ) {

        if (njt_terminate || njt_quit) {
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "exiting");
            // exit(0); openresty patch
            njt_worker_process_exit(cycle); // openresty patch
        }

        if (njt_reopen) {
            njt_reopen = 0;
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "reopening logs");
            njt_reopen_files(cycle, -1);
        }

        njt_process_events_and_timers(cycle);
    }
}


static void
njt_privileged_agent_process_cycle(njt_cycle_t *cycle, void *data)
{
    char   *name = data;

    /*
     * Set correct process type since closing listening Unix domain socket
     * in a master process also removes the Unix domain socket file.
     */
    njt_core_conf_t *ccf = (njt_core_conf_t *) njt_get_conf(cycle->conf_ctx, njt_core_module);
    njt_process = NJT_PROCESS_HELPER;
    njt_is_privileged_agent = 1;
    njt_master_listening_count = cycle->listening.nelts;

    njt_close_listening_sockets(cycle);

    /* Set a moderate number of connections for a helper process. */
    cycle->connection_n = ccf->privileged_agent_connections;
    njt_worker_process_init(cycle, -1);

    if (njt_is_privileged_agent) {
        if (setuid(0) == -1) {
            njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                "setuid(%d) failed", 0);
            /* fatal */
            exit(2);
        }
    }
    
    njt_use_accept_mutex = 0;

    njt_setproctitle(name);

    for ( ;; ) {

        if (njt_terminate || njt_quit) {
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "exiting");
            njt_worker_process_exit(cycle);
        }

        if (njt_reopen) {
            njt_reopen = 0;
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "reopening logs");
            njt_reopen_files(cycle, -1);
        }

        njt_process_events_and_timers(cycle);
    }
}



static void
njt_cache_manager_process_handler(njt_event_t *ev)
{
    njt_uint_t    i;
    njt_msec_t    next, n;
    njt_path_t **path;

    next = 60 * 60 * 1000;

    path = njt_cycle->paths.elts;
    for (i = 0; i < njt_cycle->paths.nelts; i++) {
        if (path[i]->purger) {
            n = path[i]->purger(path[i]->data);
            next = (n <= next) ? n : next;
            njt_time_update();
        }
        if (path[i]->manager) {
            n = path[i]->manager(path[i]->data);

            next = (n <= next) ? n : next;

            njt_time_update();
        }
    }

    if (next == 0) {
        next = 1;
    }

    njt_add_timer(ev, next);
}


static void
njt_cache_loader_process_handler(njt_event_t *ev)
{
    njt_uint_t     i;
    njt_path_t **path;
    njt_cycle_t *cycle;

    cycle = (njt_cycle_t *)njt_cycle;

    path = cycle->paths.elts;
    for (i = 0; i < cycle->paths.nelts; i++) {

        if (njt_terminate || njt_quit) {
            break;
        }

        if (path[i]->loader) {
            path[i]->loader(path[i]->data);
            njt_time_update();
        }
    }

    exit(0);
}

static njt_int_t njt_master_init_mdb(njt_cycle_t *cycle, const char *cfg)
{
    char *prefix;
    char log[1024] = { 0 };
    prefix = njt_calloc(cycle->prefix.len + 1, cycle->log);
    njt_memcpy(prefix, cycle->prefix.data, cycle->prefix.len);
    prefix[cycle->prefix.len] = '\0';
    memcpy(log, cycle->prefix.data, cycle->prefix.len);
    sprintf(log + cycle->prefix.len, "logs/master_iot");

    master_evt_ctx = njet_iot_client_init(prefix, "", NULL,
        NULL, "njet_master", log, cycle);
    if (!master_evt_ctx) {
        return NJT_ERROR;
    }

    return NJT_OK;
}


