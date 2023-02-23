
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) TMLake, Inc.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_channel.h>


static void njt_start_worker_processes(njt_cycle_t *cycle, njt_int_t n,
    njt_int_t type);
static void njt_start_cache_manager_processes(njt_cycle_t *cycle,
    njt_uint_t respawn);
static void njt_pass_open_channel(njt_cycle_t *cycle);
static void njt_signal_worker_processes(njt_cycle_t *cycle, int signo);
static njt_uint_t njt_reap_children(njt_cycle_t *cycle);
static void njt_master_process_exit(njt_cycle_t *cycle);
static void njt_worker_process_cycle(njt_cycle_t *cycle, void *data);
static void njt_worker_process_init(njt_cycle_t *cycle, njt_int_t worker);
static void njt_worker_process_exit(njt_cycle_t *cycle);
static void njt_channel_handler(njt_event_t *ev);
static void njt_cache_manager_process_cycle(njt_cycle_t *cycle, void *data);
static void njt_cache_manager_process_handler(njt_event_t *ev);
static void njt_cache_loader_process_handler(njt_event_t *ev);


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
sig_atomic_t  njt_reopen;

sig_atomic_t  njt_change_binary;
njt_pid_t     njt_new_binary;
njt_uint_t    njt_inherited;
njt_uint_t    njt_daemonized;

sig_atomic_t  njt_noaccept;
njt_uint_t    njt_noaccepting;
njt_uint_t    njt_restart;

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


void
njt_master_process_cycle(njt_cycle_t *cycle)
{
    char              *title;
    u_char            *p;
    size_t             size;
    njt_int_t          i;
    njt_uint_t         sigio;
    sigset_t           set;
    struct itimerval   itv;
    njt_uint_t         live;
    njt_msec_t         delay;
    njt_core_conf_t   *ccf;

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
        p = njt_cpystrn(p, (u_char *) njt_argv[i], size);
    }

    njt_setproctitle(title);


    ccf = (njt_core_conf_t *) njt_get_conf(cycle->conf_ctx, njt_core_module);

    njt_start_worker_processes(cycle, ccf->worker_processes,
                               NJT_PROCESS_RESPAWN);
    njt_start_cache_manager_processes(cycle, 0);

    njt_new_binary = 0;
    delay = 0;
    sigio = 0;
    live = 1;

    for ( ;; ) {
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
            itv.it_value.tv_usec = (delay % 1000 ) * 1000;

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
                njt_noaccepting = 0;

                continue;
            }

            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "reconfiguring");

            cycle = njt_init_cycle(cycle);
            if (cycle == NULL) {
                cycle = (njt_cycle_t *) njt_cycle;
                continue;
            }

            njt_cycle = cycle;
            ccf = (njt_core_conf_t *) njt_get_conf(cycle->conf_ctx,
                                                   njt_core_module);
            njt_start_worker_processes(cycle, ccf->worker_processes,
                                       NJT_PROCESS_JUST_RESPAWN);
            njt_start_cache_manager_processes(cycle, 1);

            /* allow new processes to start */
            njt_msleep(100);

            live = 1;
            njt_signal_worker_processes(cycle,
                                        njt_signal_value(NJT_SHUTDOWN_SIGNAL));
        }

        if (njt_restart) {
            njt_restart = 0;
            njt_start_worker_processes(cycle, ccf->worker_processes,
                                       NJT_PROCESS_RESPAWN);
            njt_start_cache_manager_processes(cycle, 0);
            live = 1;
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
            njt_new_binary = njt_exec_new_binary(cycle, njt_argv);
        }

        if (njt_noaccept) {
            njt_noaccept = 0;
            njt_noaccepting = 1;
            njt_signal_worker_processes(cycle,
                                        njt_signal_value(NJT_SHUTDOWN_SIGNAL));
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

    for ( ;; ) {
        njt_log_debug0(NJT_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

        njt_process_events_and_timers(cycle);

        if (njt_terminate || njt_quit) {

            for (i = 0; cycle->modules[i]; i++) {
                if (cycle->modules[i]->exit_process) {
                    cycle->modules[i]->exit_process(cycle);
                }
            }

            njt_master_process_exit(cycle);
        }

        if (njt_reconfigure) {
            njt_reconfigure = 0;
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "reconfiguring");

            cycle = njt_init_cycle(cycle);
            if (cycle == NULL) {
                cycle = (njt_cycle_t *) njt_cycle;
                continue;
            }

            njt_cycle = cycle;
        }

        if (njt_reopen) {
            njt_reopen = 0;
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "reopening logs");
            njt_reopen_files(cycle, (njt_uid_t) -1);
        }
    }
}


static void
njt_start_worker_processes(njt_cycle_t *cycle, njt_int_t n, njt_int_t type)
{
    njt_int_t  i;

    njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "start worker processes");

    for (i = 0; i < n; i++) {

        njt_spawn_process(cycle, njt_worker_process_cycle,
                          (void *) (intptr_t) i, "worker process", type);

        njt_pass_open_channel(cycle);
    }
}


static void
njt_start_cache_manager_processes(njt_cycle_t *cycle, njt_uint_t respawn)
{
    njt_uint_t    i, manager, loader,purger;
    njt_path_t  **path;

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
                      respawn ? NJT_PROCESS_JUST_RESPAWN : NJT_PROCESS_RESPAWN);

    njt_pass_open_channel(cycle);

    if (loader == 0) {
        return;
    }

    njt_spawn_process(cycle, njt_cache_manager_process_cycle,
                      &njt_cache_loader_ctx, "cache loader process",
                      respawn ? NJT_PROCESS_JUST_SPAWN : NJT_PROCESS_NORESPAWN);

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
            || njt_processes[i].channel[0] == -1)
        {
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
            && signo == njt_signal_value(NJT_SHUTDOWN_SIGNAL))
        {
            continue;
        }

        if (ch.command) {
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


static njt_uint_t
njt_reap_children(njt_cycle_t *cycle)
{
    njt_int_t         i, n;
    njt_uint_t        live;
    njt_channel_t     ch;
    njt_core_conf_t  *ccf;

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
                        || njt_processes[n].channel[0] == -1)
                    {
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
                && !njt_quit)
            {
                if (njt_spawn_process(cycle, njt_processes[i].proc,
                                      njt_processes[i].data,
                                      njt_processes[i].name, i)
                    == NJT_INVALID_PID)
                {
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

                ccf = (njt_core_conf_t *) njt_get_conf(cycle->conf_ctx,
                                                       njt_core_module);

                if (njt_rename_file((char *) ccf->oldpid.data,
                                    (char *) ccf->pid.data)
                    == NJT_FILE_ERROR)
                {
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

    njt_destroy_pool(cycle->pool);

    exit(0);
}


static void
njt_worker_process_cycle(njt_cycle_t *cycle, void *data)
{
    njt_int_t worker = (intptr_t) data;

    njt_process = NJT_PROCESS_WORKER;
    njt_worker = worker;

    njt_worker_process_init(cycle, worker);

    njt_setproctitle("worker process");

    for ( ;; ) {

        if (njt_exiting) {
            if (njt_event_no_timers_left() == NJT_OK) {
                njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "exiting");
                njt_worker_process_exit(cycle);
            }
        }

        njt_log_debug0(NJT_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

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
    njt_time_t       *tp;
    njt_uint_t        i;
    njt_cpuset_t     *cpu_affinity;
    struct rlimit     rlmt;
    njt_core_conf_t  *ccf;
    njt_listening_t  *ls;

    if (njt_set_environment(cycle, NULL) == NULL) {
        /* fatal */
        exit(2);
    }

    ccf = (njt_core_conf_t *) njt_get_conf(cycle->conf_ctx, njt_core_module);

    if (worker >= 0 && ccf->priority != 0) {
        if (setpriority(PRIO_PROCESS, 0, ccf->priority) == -1) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          "setpriority(%d) failed", ccf->priority);
        }
    }

    if (ccf->rlimit_nofile != NJT_CONF_UNSET) {
        rlmt.rlim_cur = (rlim_t) ccf->rlimit_nofile;
        rlmt.rlim_max = (rlim_t) ccf->rlimit_nofile;

        if (setrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          "setrlimit(RLIMIT_NOFILE, %i) failed",
                          ccf->rlimit_nofile);
        }
    }

    if (ccf->rlimit_core != NJT_CONF_UNSET) {
        rlmt.rlim_cur = (rlim_t) ccf->rlimit_core;
        rlmt.rlim_max = (rlim_t) ccf->rlimit_core;

        if (setrlimit(RLIMIT_CORE, &rlmt) == -1) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          "setrlimit(RLIMIT_CORE, %O) failed",
                          ccf->rlimit_core);
        }
    }

    if (geteuid() == 0) {
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
        if (chdir((char *) ccf->working_directory.data) == -1) {
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
    srandom(((unsigned) njt_pid << 16) ^ tp->sec ^ tp->msec);

    /*
     * disable deleting previous events for the listening sockets because
     * in the worker processes there are no events at all at this point
     */
    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {
        ls[i].previous = NULL;
    }

    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->init_process) {
            if (cycle->modules[i]->init_process(cycle) == NJT_ERROR) {
                /* fatal */
                exit(2);
            }
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
        == NJT_ERROR)
    {
        /* fatal */
        exit(2);
    }
}


static void
njt_worker_process_exit(njt_cycle_t *cycle)
{
    njt_uint_t         i;
    njt_connection_t  *c;

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
                && !c[i].read->channel
                && !c[i].read->resolver)
            {
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

    njt_destroy_pool(cycle->pool);

    njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, "exit");

    exit(0);
}


static void
njt_channel_handler(njt_event_t *ev)
{
    njt_int_t          n;
    njt_channel_t      ch;
    njt_connection_t  *c;

    if (ev->timedout) {
        ev->timedout = 0;
        return;
    }

    c = ev->data;

    njt_log_debug0(NJT_LOG_DEBUG_CORE, ev->log, 0, "channel handler");

    for ( ;; ) {

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

    void         *ident[4];
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
    ident[3] = (void *) -1;

    njt_use_accept_mutex = 0;

    njt_setproctitle(ctx->name);

    njt_add_timer(&ev, ctx->delay);

    for ( ;; ) {

        if (njt_terminate || njt_quit) {
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "exiting");
            exit(0);
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
    njt_path_t  **path;

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
    njt_path_t   **path;
    njt_cycle_t   *cycle;

    cycle = (njt_cycle_t *) njt_cycle;

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
