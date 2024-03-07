
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_event.h>
#include <njet.h>


static void njt_console_init(njt_cycle_t *cycle);
static int __stdcall njt_console_handler(u_long type);
static njt_int_t njt_create_signal_events(njt_cycle_t *cycle);
static njt_int_t njt_start_worker_processes(njt_cycle_t *cycle, njt_int_t type);
static void njt_reopen_worker_processes(njt_cycle_t *cycle);
static void njt_quit_worker_processes(njt_cycle_t *cycle, njt_uint_t old);
static void njt_terminate_worker_processes(njt_cycle_t *cycle);
static njt_uint_t njt_reap_worker(njt_cycle_t *cycle, HANDLE h);
static void njt_master_process_exit(njt_cycle_t *cycle);
static void njt_worker_process_cycle(njt_cycle_t *cycle, char *mevn);
static void njt_worker_process_exit(njt_cycle_t *cycle);
static njt_thread_value_t __stdcall njt_worker_thread(void *data);
static njt_thread_value_t __stdcall njt_cache_manager_thread(void *data);
static void njt_cache_manager_process_handler(void);
static njt_thread_value_t __stdcall njt_cache_loader_thread(void *data);


njt_uint_t     njt_process;
njt_uint_t     njt_worker;
njt_pid_t      njt_pid;
njt_pid_t      njt_parent;

njt_uint_t     njt_inherited;
njt_pid_t      njt_new_binary;

sig_atomic_t   njt_terminate;
sig_atomic_t   njt_quit;
sig_atomic_t   njt_reopen;
sig_atomic_t   njt_reconfigure;
njt_uint_t     njt_exiting;


HANDLE         njt_master_process_event;
char           njt_master_process_event_name[NJT_PROCESS_SYNC_NAME];

static HANDLE  njt_stop_event;
static char    njt_stop_event_name[NJT_PROCESS_SYNC_NAME];
static HANDLE  njt_quit_event;
static char    njt_quit_event_name[NJT_PROCESS_SYNC_NAME];
static HANDLE  njt_reopen_event;
static char    njt_reopen_event_name[NJT_PROCESS_SYNC_NAME];
static HANDLE  njt_reload_event;
static char    njt_reload_event_name[NJT_PROCESS_SYNC_NAME];

HANDLE         njt_cache_manager_mutex;
char           njt_cache_manager_mutex_name[NJT_PROCESS_SYNC_NAME];
HANDLE         njt_cache_manager_event;


void
njt_master_process_cycle(njt_cycle_t *cycle)
{
    u_long      nev, ev, timeout;
    njt_err_t   err;
    njt_int_t   n;
    njt_msec_t  timer;
    njt_uint_t  live;
    HANDLE      events[MAXIMUM_WAIT_OBJECTS];

    njt_sprintf((u_char *) njt_master_process_event_name,
                "njt_master_%s%Z", njt_unique);

    if (njt_process == NJT_PROCESS_WORKER) {
        njt_worker_process_cycle(cycle, njt_master_process_event_name);
        return;
    }

    njt_log_debug0(NJT_LOG_DEBUG_CORE, cycle->log, 0, "master started");

    njt_console_init(cycle);

    SetEnvironmentVariable("njt_unique", njt_unique);

    njt_master_process_event = CreateEvent(NULL, 1, 0,
                                           njt_master_process_event_name);
    if (njt_master_process_event == NULL) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "CreateEvent(\"%s\") failed",
                      njt_master_process_event_name);
        exit(2);
    }

    if (njt_create_signal_events(cycle) != NJT_OK) {
        exit(2);
    }

    njt_sprintf((u_char *) njt_cache_manager_mutex_name,
                "njt_cache_manager_mutex_%s%Z", njt_unique);

    njt_cache_manager_mutex = CreateMutex(NULL, 0,
                                          njt_cache_manager_mutex_name);
    if (njt_cache_manager_mutex == NULL) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                   "CreateMutex(\"%s\") failed", njt_cache_manager_mutex_name);
        exit(2);
    }


    events[0] = njt_stop_event;
    events[1] = njt_quit_event;
    events[2] = njt_reopen_event;
    events[3] = njt_reload_event;

    njt_close_listening_sockets(cycle);

    if (njt_start_worker_processes(cycle, NJT_PROCESS_RESPAWN) == 0) {
        exit(2);
    }

    timer = 0;
    timeout = INFINITE;

    for ( ;; ) {

        nev = 4;
        for (n = 0; n < njt_last_process; n++) {
            if (njt_processes[n].handle) {
                events[nev++] = njt_processes[n].handle;
            }
        }

        if (timer) {
            timeout = timer > njt_current_msec ? timer - njt_current_msec : 0;
        }

        ev = WaitForMultipleObjects(nev, events, 0, timeout);

        err = njt_errno;
        njt_time_update();

        njt_log_debug1(NJT_LOG_DEBUG_CORE, cycle->log, 0,
                       "master WaitForMultipleObjects: %ul", ev);

        if (ev == WAIT_OBJECT_0) {
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "exiting");

            if (ResetEvent(njt_stop_event) == 0) {
                njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                              "ResetEvent(\"%s\") failed", njt_stop_event_name);
            }

            if (timer == 0) {
                timer = njt_current_msec + 5000;
            }

            njt_terminate = 1;
            njt_quit_worker_processes(cycle, 0);

            continue;
        }

        if (ev == WAIT_OBJECT_0 + 1) {
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "shutting down");

            if (ResetEvent(njt_quit_event) == 0) {
                njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                              "ResetEvent(\"%s\") failed", njt_quit_event_name);
            }

            njt_quit = 1;
            njt_quit_worker_processes(cycle, 0);

            continue;
        }

        if (ev == WAIT_OBJECT_0 + 2) {
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "reopening logs");

            if (ResetEvent(njt_reopen_event) == 0) {
                njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                              "ResetEvent(\"%s\") failed",
                              njt_reopen_event_name);
            }

            njt_reopen_files(cycle, -1);
            njt_reopen_worker_processes(cycle);

            continue;
        }

        if (ev == WAIT_OBJECT_0 + 3) {
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "reconfiguring");

            if (ResetEvent(njt_reload_event) == 0) {
                njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                              "ResetEvent(\"%s\") failed",
                              njt_reload_event_name);
            }

            cycle = njt_init_cycle(cycle);
            if (cycle == NULL) {
                cycle = (njt_cycle_t *) njt_cycle;
                continue;
            }

            njt_cycle = cycle;

            njt_close_listening_sockets(cycle);

            if (njt_start_worker_processes(cycle, NJT_PROCESS_JUST_RESPAWN)) {
                njt_quit_worker_processes(cycle, 1);
            }

            continue;
        }

        if (ev > WAIT_OBJECT_0 + 3 && ev < WAIT_OBJECT_0 + nev) {

            njt_log_debug0(NJT_LOG_DEBUG_CORE, cycle->log, 0, "reap worker");

            live = njt_reap_worker(cycle, events[ev]);

            if (!live && (njt_terminate || njt_quit)) {
                njt_master_process_exit(cycle);
            }

            continue;
        }

        if (ev == WAIT_TIMEOUT) {
            njt_terminate_worker_processes(cycle);

            njt_master_process_exit(cycle);
        }

        if (ev == WAIT_FAILED) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, err,
                          "WaitForMultipleObjects() failed");

            continue;
        }

        njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
            "WaitForMultipleObjects() returned unexpected value %ul", ev);
    }
}


static void
njt_console_init(njt_cycle_t *cycle)
{
    njt_core_conf_t  *ccf;

    ccf = (njt_core_conf_t *) njt_get_conf(cycle->conf_ctx, njt_core_module);

    if (ccf->daemon) {
        if (FreeConsole() == 0) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          "FreeConsole() failed");
        }

        return;
    }

    if (SetConsoleCtrlHandler(njt_console_handler, 1) == 0) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "SetConsoleCtrlHandler() failed");
    }
}


static int __stdcall
njt_console_handler(u_long type)
{
    char  *msg;

    switch (type) {

    case CTRL_C_EVENT:
        msg = "Ctrl-C pressed, exiting";
        break;

    case CTRL_BREAK_EVENT:
        msg = "Ctrl-Break pressed, exiting";
        break;

    case CTRL_CLOSE_EVENT:
        msg = "console closing, exiting";
        break;

    case CTRL_LOGOFF_EVENT:
        msg = "user logs off, exiting";
        break;

    default:
        return 0;
    }

    njt_log_error(NJT_LOG_NOTICE, njt_cycle->log, 0, msg);

    if (njt_stop_event == NULL) {
        return 1;
    }

    if (SetEvent(njt_stop_event) == 0) {
        njt_log_error(NJT_LOG_ALERT, njt_cycle->log, 0,
                      "SetEvent(\"%s\") failed", njt_stop_event_name);
    }

    return 1;
}


static njt_int_t
njt_create_signal_events(njt_cycle_t *cycle)
{
    njt_sprintf((u_char *) njt_stop_event_name,
                "Global\\njt_stop_%s%Z", njt_unique);

    njt_stop_event = CreateEvent(NULL, 1, 0, njt_stop_event_name);
    if (njt_stop_event == NULL) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "CreateEvent(\"%s\") failed", njt_stop_event_name);
        return NJT_ERROR;
    }


    njt_sprintf((u_char *) njt_quit_event_name,
                "Global\\njt_quit_%s%Z", njt_unique);

    njt_quit_event = CreateEvent(NULL, 1, 0, njt_quit_event_name);
    if (njt_quit_event == NULL) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "CreateEvent(\"%s\") failed", njt_quit_event_name);
        return NJT_ERROR;
    }


    njt_sprintf((u_char *) njt_reopen_event_name,
                "Global\\njt_reopen_%s%Z", njt_unique);

    njt_reopen_event = CreateEvent(NULL, 1, 0, njt_reopen_event_name);
    if (njt_reopen_event == NULL) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "CreateEvent(\"%s\") failed", njt_reopen_event_name);
        return NJT_ERROR;
    }


    njt_sprintf((u_char *) njt_reload_event_name,
                "Global\\njt_reload_%s%Z", njt_unique);

    njt_reload_event = CreateEvent(NULL, 1, 0, njt_reload_event_name);
    if (njt_reload_event == NULL) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "CreateEvent(\"%s\") failed", njt_reload_event_name);
        return NJT_ERROR;
    }

    return NJT_OK;
}


static njt_int_t
njt_start_worker_processes(njt_cycle_t *cycle, njt_int_t type)
{
    njt_int_t         n;
    njt_core_conf_t  *ccf;

    njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "start worker processes");

    ccf = (njt_core_conf_t *) njt_get_conf(cycle->conf_ctx, njt_core_module);

    for (n = 0; n < ccf->worker_processes; n++) {
        if (njt_spawn_process(cycle, "worker", type) == NJT_INVALID_PID) {
            break;
        }
    }

    return n;
}


static void
njt_reopen_worker_processes(njt_cycle_t *cycle)
{
    njt_int_t  n;

    for (n = 0; n < njt_last_process; n++) {

        if (njt_processes[n].handle == NULL) {
            continue;
        }

        if (SetEvent(njt_processes[n].reopen) == 0) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          "SetEvent(\"%s\") failed",
                          njt_processes[n].reopen_event);
        }
    }
}


static void
njt_quit_worker_processes(njt_cycle_t *cycle, njt_uint_t old)
{
    njt_int_t  n;

    for (n = 0; n < njt_last_process; n++) {

        njt_log_debug5(NJT_LOG_DEBUG_CORE, cycle->log, 0,
                       "process: %d %P %p e:%d j:%d",
                       n,
                       njt_processes[n].pid,
                       njt_processes[n].handle,
                       njt_processes[n].exiting,
                       njt_processes[n].just_spawn);

        if (old && njt_processes[n].just_spawn) {
            njt_processes[n].just_spawn = 0;
            continue;
        }

        if (njt_processes[n].handle == NULL) {
            continue;
        }

        if (SetEvent(njt_processes[n].quit) == 0) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          "SetEvent(\"%s\") failed",
                          njt_processes[n].quit_event);
        }

        njt_processes[n].exiting = 1;
    }
}


static void
njt_terminate_worker_processes(njt_cycle_t *cycle)
{
    njt_int_t  n;

    for (n = 0; n < njt_last_process; n++) {

        if (njt_processes[n].handle == NULL) {
            continue;
        }

        if (TerminateProcess(njt_processes[n].handle, 0) == 0) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          "TerminateProcess(\"%p\") failed",
                          njt_processes[n].handle);
        }

        njt_processes[n].exiting = 1;

        njt_close_handle(njt_processes[n].reopen);
        njt_close_handle(njt_processes[n].quit);
        njt_close_handle(njt_processes[n].term);
        njt_close_handle(njt_processes[n].handle);
    }
}


static njt_uint_t
njt_reap_worker(njt_cycle_t *cycle, HANDLE h)
{
    u_long     code;
    njt_int_t  n;

    for (n = 0; n < njt_last_process; n++) {

        if (njt_processes[n].handle != h) {
            continue;
        }

        if (GetExitCodeProcess(h, &code) == 0) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          "GetExitCodeProcess(%P) failed",
                          njt_processes[n].pid);
        }

        njt_log_error(NJT_LOG_NOTICE, cycle->log, 0,
                      "%s process %P exited with code %Xl",
                      njt_processes[n].name, njt_processes[n].pid, code);

        njt_close_handle(njt_processes[n].reopen);
        njt_close_handle(njt_processes[n].quit);
        njt_close_handle(njt_processes[n].term);
        njt_close_handle(h);

        njt_processes[n].handle = NULL;
        njt_processes[n].term = NULL;
        njt_processes[n].quit = NULL;
        njt_processes[n].reopen = NULL;

        if (!njt_processes[n].exiting && !njt_terminate && !njt_quit) {

            if (njt_spawn_process(cycle, njt_processes[n].name, n)
                == NJT_INVALID_PID)
            {
                njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                              "could not respawn %s", njt_processes[n].name);

                if (n == njt_last_process - 1) {
                    njt_last_process--;
                }
            }
        }

        goto found;
    }

    njt_log_error(NJT_LOG_ALERT, cycle->log, 0, "unknown process handle %p", h);

found:

    for (n = 0; n < njt_last_process; n++) {

        njt_log_debug5(NJT_LOG_DEBUG_CORE, cycle->log, 0,
                       "process: %d %P %p e:%d j:%d",
                       n,
                       njt_processes[n].pid,
                       njt_processes[n].handle,
                       njt_processes[n].exiting,
                       njt_processes[n].just_spawn);

        if (njt_processes[n].handle) {
            return 1;
        }
    }

    return 0;
}


static void
njt_master_process_exit(njt_cycle_t *cycle)
{
    njt_uint_t  i;

    njt_delete_pidfile(cycle);

    njt_close_handle(njt_cache_manager_mutex);
    njt_close_handle(njt_stop_event);
    njt_close_handle(njt_quit_event);
    njt_close_handle(njt_reopen_event);
    njt_close_handle(njt_reload_event);
    njt_close_handle(njt_master_process_event);

    njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "exit");

    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->exit_master) {
            cycle->modules[i]->exit_master(cycle);
        }
    }

    njt_destroy_pool(cycle->pool);

    exit(0);
}


static void
njt_worker_process_cycle(njt_cycle_t *cycle, char *mevn)
{
    char        wtevn[NJT_PROCESS_SYNC_NAME];
    char        wqevn[NJT_PROCESS_SYNC_NAME];
    char        wroevn[NJT_PROCESS_SYNC_NAME];
    HANDLE      mev, events[3];
    u_long      nev, ev;
    njt_err_t   err;
    njt_tid_t   wtid, cmtid, cltid;
    njt_log_t  *log;

    log = cycle->log;

    njt_log_debug0(NJT_LOG_DEBUG_CORE, log, 0, "worker started");

    njt_sprintf((u_char *) wtevn, "njt_worker_term_%P%Z", njt_pid);
    events[0] = CreateEvent(NULL, 1, 0, wtevn);
    if (events[0] == NULL) {
        njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                      "CreateEvent(\"%s\") failed", wtevn);
        goto failed;
    }

    njt_sprintf((u_char *) wqevn, "njt_worker_quit_%P%Z", njt_pid);
    events[1] = CreateEvent(NULL, 1, 0, wqevn);
    if (events[1] == NULL) {
        njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                      "CreateEvent(\"%s\") failed", wqevn);
        goto failed;
    }

    njt_sprintf((u_char *) wroevn, "njt_worker_reopen_%P%Z", njt_pid);
    events[2] = CreateEvent(NULL, 1, 0, wroevn);
    if (events[2] == NULL) {
        njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                      "CreateEvent(\"%s\") failed", wroevn);
        goto failed;
    }

    mev = OpenEvent(EVENT_MODIFY_STATE, 0, mevn);
    if (mev == NULL) {
        njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                      "OpenEvent(\"%s\") failed", mevn);
        goto failed;
    }

    if (SetEvent(mev) == 0) {
        njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                      "SetEvent(\"%s\") failed", mevn);
        goto failed;
    }


    njt_sprintf((u_char *) njt_cache_manager_mutex_name,
                "njt_cache_manager_mutex_%s%Z", njt_unique);

    njt_cache_manager_mutex = OpenMutex(SYNCHRONIZE, 0,
                                        njt_cache_manager_mutex_name);
    if (njt_cache_manager_mutex == NULL) {
        njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                      "OpenMutex(\"%s\") failed", njt_cache_manager_mutex_name);
        goto failed;
    }

    njt_cache_manager_event = CreateEvent(NULL, 1, 0, NULL);
    if (njt_cache_manager_event == NULL) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "CreateEvent(\"njt_cache_manager_event\") failed");
        goto failed;
    }


    if (njt_create_thread(&wtid, njt_worker_thread, NULL, log) != 0) {
        goto failed;
    }

    if (njt_create_thread(&cmtid, njt_cache_manager_thread, NULL, log) != 0) {
        goto failed;
    }

    if (njt_create_thread(&cltid, njt_cache_loader_thread, NULL, log) != 0) {
        goto failed;
    }

    for ( ;; ) {
        ev = WaitForMultipleObjects(3, events, 0, INFINITE);

        err = njt_errno;
        njt_time_update();

        njt_log_debug1(NJT_LOG_DEBUG_CORE, log, 0,
                       "worker WaitForMultipleObjects: %ul", ev);

        if (ev == WAIT_OBJECT_0) {
            njt_terminate = 1;
            njt_log_error(NJT_LOG_NOTICE, log, 0, "exiting");

            if (ResetEvent(events[0]) == 0) {
                njt_log_error(NJT_LOG_ALERT, log, 0,
                              "ResetEvent(\"%s\") failed", wtevn);
            }

            break;
        }

        if (ev == WAIT_OBJECT_0 + 1) {
            njt_quit = 1;
            njt_log_error(NJT_LOG_NOTICE, log, 0, "gracefully shutting down");
            break;
        }

        if (ev == WAIT_OBJECT_0 + 2) {
            njt_reopen = 1;
            njt_log_error(NJT_LOG_NOTICE, log, 0, "reopening logs");

            if (ResetEvent(events[2]) == 0) {
                njt_log_error(NJT_LOG_ALERT, log, 0,
                              "ResetEvent(\"%s\") failed", wroevn);
            }

            continue;
        }

        if (ev == WAIT_FAILED) {
            njt_log_error(NJT_LOG_ALERT, log, err,
                          "WaitForMultipleObjects() failed");

            goto failed;
        }
    }

    /* wait threads */

    if (SetEvent(njt_cache_manager_event) == 0) {
        njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                      "SetEvent(\"njt_cache_manager_event\") failed");
    }

    events[1] = wtid;
    events[2] = cmtid;

    nev = 3;

    for ( ;; ) {
        ev = WaitForMultipleObjects(nev, events, 0, INFINITE);

        err = njt_errno;
        njt_time_update();

        njt_log_debug1(NJT_LOG_DEBUG_CORE, log, 0,
                       "worker exit WaitForMultipleObjects: %ul", ev);

        if (ev == WAIT_OBJECT_0) {
            break;
        }

        if (ev == WAIT_OBJECT_0 + 1) {
            if (nev == 2) {
                break;
            }

            events[1] = events[2];
            nev = 2;
            continue;
        }

        if (ev == WAIT_OBJECT_0 + 2) {
            nev = 2;
            continue;
        }

        if (ev == WAIT_FAILED) {
            njt_log_error(NJT_LOG_ALERT, log, err,
                          "WaitForMultipleObjects() failed");
            break;
        }
    }

    njt_close_handle(njt_cache_manager_event);
    njt_close_handle(events[0]);
    njt_close_handle(events[1]);
    njt_close_handle(events[2]);
    njt_close_handle(mev);

    njt_worker_process_exit(cycle);

failed:

    exit(2);
}


static njt_thread_value_t __stdcall
njt_worker_thread(void *data)
{
    njt_int_t     n;
    njt_time_t   *tp;
    njt_cycle_t  *cycle;

    tp = njt_timeofday();
    srand((njt_pid << 16) ^ (unsigned) tp->sec ^ tp->msec);

    cycle = (njt_cycle_t *) njt_cycle;

    for (n = 0; cycle->modules[n]; n++) {
        if (cycle->modules[n]->init_process) {
            if (cycle->modules[n]->init_process(cycle) == NJT_ERROR) {
                /* fatal */
                exit(2);
            }
        }
    }

    while (!njt_quit) {

        if (njt_exiting) {
            if (njt_event_no_timers_left() == NJT_OK) {
                break;
            }
        }

        // njt_log_debug0(NJT_LOG_DEBUG_CORE, cycle->log, 0, "worker cycle");

        njt_process_events_and_timers(cycle);

        if (njt_terminate) {
            return 0;
        }

        if (njt_quit) {
            njt_quit = 0;

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
            njt_reopen_files(cycle, -1);
        }
    }

    njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "exiting");

    return 0;
}


static void
njt_worker_process_exit(njt_cycle_t *cycle)
{
    njt_uint_t         i;
    njt_connection_t  *c;

    njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "exit");

    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->exit_process) {
            cycle->modules[i]->exit_process(cycle);
        }
    }

    if (njt_exiting) {
        c = cycle->connections;
        for (i = 0; i < cycle->connection_n; i++) {
            if (c[i].fd != (njt_socket_t) -1
                && c[i].read
                && !c[i].read->accept
                && !c[i].read->channel
                && !c[i].read->resolver)
            {
                njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                              "*%uA open socket #%d left in connection %ui",
                              c[i].number, c[i].fd, i);
            }
        }
    }

    njt_destroy_pool(cycle->pool);

    exit(0);
}


static njt_thread_value_t __stdcall
njt_cache_manager_thread(void *data)
{
    u_long        ev;
    HANDLE        events[2];
    njt_err_t     err;
    njt_cycle_t  *cycle;

    cycle = (njt_cycle_t *) njt_cycle;

    events[0] = njt_cache_manager_event;
    events[1] = njt_cache_manager_mutex;

    for ( ;; ) {
        ev = WaitForMultipleObjects(2, events, 0, INFINITE);

        err = njt_errno;
        njt_time_update();

        njt_log_debug1(NJT_LOG_DEBUG_CORE, cycle->log, 0,
                       "cache manager WaitForMultipleObjects: %ul", ev);

        if (ev == WAIT_FAILED) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, err,
                          "WaitForMultipleObjects() failed");
        }

        /*
         * ev == WAIT_OBJECT_0
         * ev == WAIT_OBJECT_0 + 1
         * ev == WAIT_ABANDONED_0 + 1
         */

        if (njt_terminate || njt_quit || njt_exiting) {
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "exiting");
            return 0;
        }

        break;
    }

    for ( ;; ) {

        if (njt_terminate || njt_quit || njt_exiting) {
            njt_log_error(NJT_LOG_NOTICE, cycle->log, 0, "exiting");
            break;
        }

        njt_cache_manager_process_handler();
    }

    if (ReleaseMutex(njt_cache_manager_mutex) == 0) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "ReleaseMutex() failed");
    }

    return 0;
}


static void
njt_cache_manager_process_handler(void)
{
    u_long        ev;
    njt_uint_t    i;
    njt_msec_t    next, n;
    njt_path_t  **path;

    next = 60 * 60 * 1000;

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

    ev = WaitForSingleObject(njt_cache_manager_event, (u_long) next);

    if (ev != WAIT_TIMEOUT) {

        njt_time_update();

        njt_log_debug1(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,
                       "cache manager WaitForSingleObject: %ul", ev);
    }
}


static njt_thread_value_t __stdcall
njt_cache_loader_thread(void *data)
{
    njt_uint_t     i;
    njt_path_t   **path;
    njt_cycle_t   *cycle;

    njt_msleep(60000);

    cycle = (njt_cycle_t *) njt_cycle;

    path = cycle->paths.elts;
    for (i = 0; i < cycle->paths.nelts; i++) {

        if (njt_terminate || njt_quit || njt_exiting) {
            break;
        }

        if (path[i]->loader) {
            path[i]->loader(path[i]->data);
            njt_time_update();
        }
    }

    return 0;
}


void
njt_single_process_cycle(njt_cycle_t *cycle)
{
    njt_tid_t  tid;

    njt_console_init(cycle);

    if (njt_create_signal_events(cycle) != NJT_OK) {
        exit(2);
    }

    if (njt_create_thread(&tid, njt_worker_thread, NULL, cycle->log) != 0) {
        /* fatal */
        exit(2);
    }

    /* STUB */
    WaitForSingleObject(njt_stop_event, INFINITE);
}


njt_int_t
njt_os_signal_process(njt_cycle_t *cycle, char *sig, njt_pid_t pid)
{
    HANDLE     ev;
    njt_int_t  rc;
    char       evn[NJT_PROCESS_SYNC_NAME];

    njt_sprintf((u_char *) evn, "Global\\njt_%s_%P%Z", sig, pid);

    ev = OpenEvent(EVENT_MODIFY_STATE, 0, evn);
    if (ev == NULL) {
        njt_log_error(NJT_LOG_ERR, cycle->log, njt_errno,
                      "OpenEvent(\"%s\") failed", evn);
        return 1;
    }

    if (SetEvent(ev) == 0) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "SetEvent(\"%s\") failed", evn);
        rc = 1;

    } else {
        rc = 0;
    }

    njt_close_handle(ev);

    return rc;
}


void
njt_close_handle(HANDLE h)
{
    if (CloseHandle(h) == 0) {
        njt_log_error(NJT_LOG_ALERT, njt_cycle->log, njt_errno,
                      "CloseHandle(%p) failed", h);
    }
}
