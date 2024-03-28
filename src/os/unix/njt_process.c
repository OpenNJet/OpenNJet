
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njt_channel.h>


typedef struct {
    int     signo;
    char   *signame;
    char   *name;
    void  (*handler)(int signo, siginfo_t *siginfo, void *ucontext);
} njt_signal_t;



static void njt_execute_proc(njt_cycle_t *cycle, void *data);
static void njt_signal_handler(int signo, siginfo_t *siginfo, void *ucontext);
static void njt_process_get_status(void);
static void njt_unlock_mutexes(njt_pid_t pid);


int              njt_argc;
char           **njt_argv;
char           **njt_os_argv;

njt_int_t        njt_process_slot;
njt_socket_t     njt_channel;
njt_int_t        njt_last_process;
njt_process_t    njt_processes[NJT_MAX_PROCESSES];
njt_process_t    njt_shrink_processes[NJT_MAX_PROCESSES]; //for dyn worker change, keep process info in this array
njt_int_t        njt_shrink_count=0;  
njt_int_t        njt_shrink_finish_count=0;  

njt_signal_t  signals[] = {
    { njt_signal_value(NJT_RECONFIGURE_SIGNAL),
      "SIG" njt_value(NJT_RECONFIGURE_SIGNAL),
      "reload",
      njt_signal_handler },

    { njt_signal_value(NJT_REOPEN_SIGNAL),
      "SIG" njt_value(NJT_REOPEN_SIGNAL),
      "reopen",
      njt_signal_handler },

    { njt_signal_value(NJT_NOACCEPT_SIGNAL),
      "SIG" njt_value(NJT_NOACCEPT_SIGNAL),
      "",
      njt_signal_handler },

    { njt_signal_value(NJT_TERMINATE_SIGNAL),
      "SIG" njt_value(NJT_TERMINATE_SIGNAL),
      "stop",
      njt_signal_handler },

    { njt_signal_value(NJT_SHUTDOWN_SIGNAL),
      "SIG" njt_value(NJT_SHUTDOWN_SIGNAL),
      "quit",
      njt_signal_handler },

    { njt_signal_value(NJT_CHANGEBIN_SIGNAL),
      "SIG" njt_value(NJT_CHANGEBIN_SIGNAL),
      "",
      njt_signal_handler },

    { SIGALRM, "SIGALRM", "", njt_signal_handler },

    { SIGINT, "SIGINT", "", njt_signal_handler },

    { SIGIO, "SIGIO", "", njt_signal_handler },

    { SIGCHLD, "SIGCHLD", "", njt_signal_handler },

    { SIGSYS, "SIGSYS, SIG_IGN", "", NULL },

    { SIGPIPE, "SIGPIPE, SIG_IGN", "", NULL },

    { SIGCONF, "SIGCONF", "", njt_signal_handler},

    { 0, NULL, "", NULL }
};


njt_pid_t
njt_spawn_process(njt_cycle_t *cycle, njt_spawn_proc_pt proc, void *data,
    char *name, njt_int_t respawn, njt_spawn_preproc_pt preproc)
{
    u_long     on;
    njt_pid_t  pid;
    njt_int_t  s;
    njt_int_t  reload = 1;

    if (respawn >= 0) {
        s = respawn;

    } else {
        for (s = 0; s < njt_last_process; s++) {
            if (njt_processes[s].pid == -1) {
                break;
            }
        }

        if (s == NJT_MAX_PROCESSES) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                          "no more than %d processes can be spawned",
                          NJT_MAX_PROCESSES);
            return NJT_INVALID_PID;
        }
    }


    if (respawn != NJT_PROCESS_DETACHED) {

        /* Solaris 9 still has no AF_LOCAL */

        if (socketpair(AF_UNIX, SOCK_STREAM, 0, njt_processes[s].channel) == -1)
        {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          "socketpair() failed while spawning \"%s\"", name);
            return NJT_INVALID_PID;
        }

        njt_log_debug2(NJT_LOG_DEBUG_CORE, cycle->log, 0,
                       "channel %d:%d",
                       njt_processes[s].channel[0],
                       njt_processes[s].channel[1]);

        if (njt_nonblocking(njt_processes[s].channel[0]) == -1) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          njt_nonblocking_n " failed while spawning \"%s\"",
                          name);
            njt_close_channel(njt_processes[s].channel, cycle->log);
            return NJT_INVALID_PID;
        }

        if (njt_nonblocking(njt_processes[s].channel[1]) == -1) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          njt_nonblocking_n " failed while spawning \"%s\"",
                          name);
            njt_close_channel(njt_processes[s].channel, cycle->log);
            return NJT_INVALID_PID;
        }

        on = 1;
        if (ioctl(njt_processes[s].channel[0], FIOASYNC, &on) == -1) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          "ioctl(FIOASYNC) failed while spawning \"%s\"", name);
            njt_close_channel(njt_processes[s].channel, cycle->log);
            return NJT_INVALID_PID;
        }

        if (fcntl(njt_processes[s].channel[0], F_SETOWN, njt_pid) == -1) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          "fcntl(F_SETOWN) failed while spawning \"%s\"", name);
            njt_close_channel(njt_processes[s].channel, cycle->log);
            return NJT_INVALID_PID;
        }

        if (fcntl(njt_processes[s].channel[0], F_SETFD, FD_CLOEXEC) == -1) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          "fcntl(FD_CLOEXEC) failed while spawning \"%s\"",
                           name);
            njt_close_channel(njt_processes[s].channel, cycle->log);
            return NJT_INVALID_PID;
        }

        if (fcntl(njt_processes[s].channel[1], F_SETFD, FD_CLOEXEC) == -1) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          "fcntl(FD_CLOEXEC) failed while spawning \"%s\"",
                           name);
            njt_close_channel(njt_processes[s].channel, cycle->log);
            return NJT_INVALID_PID;
        }

        njt_channel = njt_processes[s].channel[1];

    } else {
        njt_processes[s].channel[0] = -1;
        njt_processes[s].channel[1] = -1;
    }

    njt_process_slot = s;

    if (preproc) {
        preproc(cycle, data, &reload, &njt_processes[s]);
    }

    pid = fork();

    switch (pid) {

    case -1:
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "fork() failed while spawning \"%s\"", name);
        njt_close_channel(njt_processes[s].channel, cycle->log);
        return NJT_INVALID_PID;

    case 0:
        njt_parent = njt_pid;
        njt_pid = njt_getpid();
        proc(cycle, data);
        break;

    default:
        break;
    }

    njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "start %s %P", name, pid);

    njt_processes[s].pid = pid;
    njt_processes[s].exited = 0;

    if (respawn >= 0) {
        return pid;
    }

    njt_processes[s].proc = proc;
    njt_processes[s].preproc = preproc;
    if (reload) {
        njt_processes[s].reload = 1;
    } else {
        njt_processes[s].reload = 0;
    }
    njt_processes[s].data = data;
    njt_processes[s].name = name;
    njt_processes[s].exiting = 0;

    switch (respawn) {

    case NJT_PROCESS_NORESPAWN:
        njt_processes[s].respawn = 0;
        njt_processes[s].just_spawn = 0;
        njt_processes[s].detached = 0;
        break;

    case NJT_PROCESS_JUST_SPAWN:
        njt_processes[s].respawn = 0;
        njt_processes[s].just_spawn = 1;
        njt_processes[s].detached = 0;
        break;

    case NJT_PROCESS_RESPAWN:
        njt_processes[s].respawn = 1;
        njt_processes[s].just_spawn = 0;
        njt_processes[s].detached = 0;
        break;

    case NJT_PROCESS_JUST_RESPAWN:
        njt_processes[s].respawn = 1;
        njt_processes[s].just_spawn = 1;
        njt_processes[s].detached = 0;
        break;

    case NJT_PROCESS_DETACHED:
        njt_processes[s].respawn = 0;
        njt_processes[s].just_spawn = 0;
        njt_processes[s].detached = 1;
        break;
    }

    if (s == njt_last_process) {
        njt_last_process++;
    }

    return pid;
}


njt_pid_t
njt_execute(njt_cycle_t *cycle, njt_exec_ctx_t *ctx)
{
    return njt_spawn_process(cycle, njt_execute_proc, ctx, ctx->name,
                             NJT_PROCESS_DETACHED, NULL);
}


static void
njt_execute_proc(njt_cycle_t *cycle, void *data)
{
    njt_exec_ctx_t  *ctx = data;

    if (execve(ctx->path, ctx->argv, ctx->envp) == -1) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "execve() failed while executing %s \"%s\"",
                      ctx->name, ctx->path);
    }

    exit(1);
}


njt_int_t
njt_init_signals(njt_log_t *log)
{
    njt_signal_t      *sig;
    struct sigaction   sa;

    for (sig = signals; sig->signo != 0; sig++) {
        njt_memzero(&sa, sizeof(struct sigaction));

        if (sig->handler) {
            sa.sa_sigaction = sig->handler;
            sa.sa_flags = SA_SIGINFO;

        } else {
            sa.sa_handler = SIG_IGN;
        }

        sigemptyset(&sa.sa_mask);
        if (sigaction(sig->signo, &sa, NULL) == -1) {
#if (NJT_VALGRIND)
            njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                          "sigaction(%s) failed, ignored", sig->signame);
#else
            njt_log_error(NJT_LOG_EMERG, log, njt_errno,
                          "sigaction(%s) failed", sig->signame);
            return NJT_ERROR;
#endif
        }
    }

    return NJT_OK;
}


static void
njt_signal_handler(int signo, siginfo_t *siginfo, void *ucontext)
{
    char            *action;
    njt_int_t        ignore;
    njt_err_t        err;
    njt_signal_t    *sig;

    ignore = 0;

    err = njt_errno;

    for (sig = signals; sig->signo != 0; sig++) {
        if (sig->signo == signo) {
            break;
        }
    }

    njt_time_sigsafe_update();

    action = "";

    switch (njt_process) {

    case NJT_PROCESS_MASTER:
    case NJT_PROCESS_SINGLE:
        switch (signo) {

        case njt_signal_value(NJT_SHUTDOWN_SIGNAL):
            njt_quit = 1;
            action = ", shutting down";
            break;

        case njt_signal_value(NJT_TERMINATE_SIGNAL):
        case SIGINT:
            njt_terminate = 1;
            action = ", exiting";
            break;

        case njt_signal_value(NJT_NOACCEPT_SIGNAL):
            if (njt_daemonized) {
                njt_noaccept = 1;
                action = ", stop accepting connections";
            }
            break;

        case njt_signal_value(NJT_RECONFIGURE_SIGNAL):
            // njt_reconfigure = 1;
            // action = ", reconfiguring";
            // openresty patch
            if (njt_process == NJT_PROCESS_SINGLE) {
                njt_terminate = 1;
                action = ", exiting";

            } else {
                njt_reconfigure = 1;
                action = ", reconfiguring";
            }
            // openresty patch

            break;

        case njt_signal_value(NJT_REOPEN_SIGNAL):
            njt_reopen = 1;
            action = ", reopening logs";
            break;

        case njt_signal_value(NJT_CHANGEBIN_SIGNAL):
            if (njt_getppid() == njt_parent || njt_new_binary > 0) {

                /*
                 * Ignore the signal in the new binary if its parent is
                 * not changed, i.e. the old binary's process is still
                 * running.  Or ignore the signal in the old binary's
                 * process if the new binary's process is already running.
                 */

                action = ", ignoring";
                ignore = 1;
                break;
            }

            njt_change_binary = 1;
            action = ", changing binary";
            break;

        case SIGALRM:
            njt_sigalrm = 1;
            break;

        case SIGIO:
            njt_sigio = 1;
            break;

        case SIGCHLD:
            njt_reap = 1;
            break;

        case SIGCONF:
            njt_rtc = 1;
            break;
        }

        break;

    case NJT_PROCESS_WORKER:
    case NJT_PROCESS_HELPER:
        switch (signo) {

        case njt_signal_value(NJT_NOACCEPT_SIGNAL):
            if (!njt_daemonized) {
                break;
            }
            njt_debug_quit = 1;
            /* fall through */
        case njt_signal_value(NJT_SHUTDOWN_SIGNAL):
            njt_quit = 1;
            action = ", shutting down";
            break;

        case njt_signal_value(NJT_TERMINATE_SIGNAL):
        case SIGINT:
            njt_terminate = 1;
            action = ", exiting";
            break;

        case njt_signal_value(NJT_REOPEN_SIGNAL):
            njt_reopen = 1;
            action = ", reopening logs";
            break;

        case njt_signal_value(NJT_RECONFIGURE_SIGNAL):
        case njt_signal_value(NJT_CHANGEBIN_SIGNAL):
        case SIGIO:
            action = ", ignoring";
            break;
        }

        break;
    }

    if (siginfo && siginfo->si_pid) {
        njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0,
                      "signal %d (%s) received from %P%s",
                      signo, sig->signame, siginfo->si_pid, action);

    } else {
        njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0,
                      "signal %d (%s) received%s",
                      signo, sig->signame, action);
    }

    if (ignore) {
        njt_log_error(NJT_LOG_CRIT, njt_cycle->log, 0,
                      "the changing binary signal is ignored: "
                      "you should shutdown or terminate "
                      "before either old or new binary's process");
    }

    if (signo == SIGCHLD) {
        njt_process_get_status();
    }

    njt_set_errno(err);
}


static void
njt_process_get_status(void)
{
    int              status;
    char            *process;
    njt_pid_t        pid;
    njt_err_t        err;
    njt_int_t        i,j;
    njt_uint_t       one;

    one = 0;

    for ( ;; ) {
        pid = waitpid(-1, &status, WNOHANG);

        if (pid == 0) {
            return;
        }

        if (pid == -1) {
            err = njt_errno;

            if (err == NJT_EINTR) {
                continue;
            }

            if (err == NJT_ECHILD && one) {
                return;
            }

            /*
             * Solaris always calls the signal handler for each exited process
             * despite waitpid() may be already called for this process.
             *
             * When several processes exit at the same time FreeBSD may
             * erroneously call the signal handler for exited process
             * despite waitpid() may be already called for this process.
             */

            if (err == NJT_ECHILD) {
                njt_log_error(NJT_LOG_INFO, njt_cycle->log, err,
                              "waitpid() failed");
                return;
            }

            njt_log_error(NJT_LOG_ALERT, njt_cycle->log, err,
                          "waitpid() failed");
            return;
        }


        one = 1;
        process = "unknown process";

        for (i = 0; i < njt_last_process; i++) {
            if (njt_processes[i].pid == pid) {
                njt_processes[i].status = status;
                njt_processes[i].exited = 1;
                process = njt_processes[i].name;
                break;
            }
        }

        //if dyn change worker process, get the process info from njt_shrink_processes and close channel
        if (i == njt_last_process) {
            for (j = 0; j < njt_shrink_count; j++) {
                if (njt_shrink_processes[j].pid == pid) {
                    process = njt_shrink_processes[j].name;
                    if (!njt_shrink_processes[j].detached) {
                        njt_close_channel(njt_shrink_processes[j].channel, njt_cycle->log);
                        njt_shrink_processes[j].channel[0] = -1;
                        njt_shrink_processes[j].channel[1] = -1;
                    }
                    njt_shrink_finish_count++;
                    break;
                }
            }
        }

        if (njt_strncmp("privileged agent process", process, 24) == 0 ) {
            if (WEXITSTATUS(status) == 2) {
                njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
                          "fatal error in privileged agent process %d, check setuid capability in execute file",
                           pid);
            } else {
                njt_privileged_agent_exited = 1;
            }
        }

        if (WTERMSIG(status)) {
#ifdef WCOREDUMP
            njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
                          "%s %P exited on signal %d%s",
                          process, pid, WTERMSIG(status),
                          WCOREDUMP(status) ? " (core dumped)" : "");
#else
            njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
                          "%s %P exited on signal %d",
                          process, pid, WTERMSIG(status));
#endif

        } else {
            njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0,
                          "%s %P exited with code %d",
                          process, pid, WEXITSTATUS(status));
        }

        if (WEXITSTATUS(status) == 2 && njt_processes[i].respawn) {
            njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
                          "%s %P exited with fatal code %d "
                          "and cannot be respawned",
                          process, pid, WEXITSTATUS(status));
            njt_processes[i].respawn = 0;
        }

        njt_unlock_mutexes(pid);
    }
}


static void
njt_unlock_mutexes(njt_pid_t pid)
{
    njt_uint_t        i;
    njt_shm_zone_t   *shm_zone;
    njt_list_part_t  *part;
    njt_slab_pool_t  *sp;

    /*
     * unlock the accept mutex if the abnormally exited process
     * held it
     */

    if (njt_accept_mutex_ptr) {
        (void) njt_shmtx_force_unlock(&njt_accept_mutex, pid);
    }

    /*
     * unlock shared memory mutexes if held by the abnormally exited
     * process
     */

    part = (njt_list_part_t *) &njt_cycle->shared_memory.part;
    shm_zone = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            shm_zone = part->elts;
            i = 0;
        }

        sp = (njt_slab_pool_t *) shm_zone[i].shm.addr;

        if (njt_shmtx_force_unlock(&sp->mutex, pid)) {
            njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
                          "shared memory zone \"%V\" was locked by %P",
                          &shm_zone[i].shm.name, pid);
        }
    }
}


void
njt_debug_point(void)
{
    njt_core_conf_t  *ccf;

    ccf = (njt_core_conf_t *) njt_get_conf(njt_cycle->conf_ctx,
                                           njt_core_module);

    switch (ccf->debug_points) {

    case NJT_DEBUG_POINTS_STOP:
        raise(SIGSTOP);
        break;

    case NJT_DEBUG_POINTS_ABORT:
        njt_abort();
    }
}


njt_int_t
njt_os_signal_process(njt_cycle_t *cycle, char *name, njt_pid_t pid)
{
    njt_signal_t  *sig;

    for (sig = signals; sig->signo != 0; sig++) {
        if (njt_strcmp(name, sig->name) == 0) {
            if (kill(pid, sig->signo) != -1) {
                return 0;
            }

            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          "kill(%P, %d) failed", pid, sig->signo);
        }
    }

    return 1;
}
