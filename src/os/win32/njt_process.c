
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


int              njt_argc;
char           **njt_argv;
char           **njt_os_argv;

njt_int_t        njt_last_process;
njt_process_t    njt_processes[NJT_MAX_PROCESSES];


njt_pid_t
njt_spawn_process(njt_cycle_t *cycle, char *name, njt_int_t respawn)
{
    u_long          rc, n, code;
    njt_int_t       s;
    njt_pid_t       pid;
    njt_exec_ctx_t  ctx;
    HANDLE          events[2];
    char            file[MAX_PATH + 1];

    if (respawn >= 0) {
        s = respawn;

    } else {
        for (s = 0; s < njt_last_process; s++) {
            if (njt_processes[s].handle == NULL) {
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

    n = GetModuleFileName(NULL, file, MAX_PATH);

    if (n == 0) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "GetModuleFileName() failed");
        return NJT_INVALID_PID;
    }

    file[n] = '\0';

    njt_log_debug1(NJT_LOG_DEBUG_CORE, cycle->log, 0,
                   "GetModuleFileName: \"%s\"", file);

    ctx.path = file;
    ctx.name = name;
    ctx.args = GetCommandLine();
    ctx.argv = NULL;
    ctx.envp = NULL;

    pid = njt_execute(cycle, &ctx);

    if (pid == NJT_INVALID_PID) {
        return pid;
    }

    njt_memzero(&njt_processes[s], sizeof(njt_process_t));

    njt_processes[s].handle = ctx.child;
    njt_processes[s].pid = pid;
    njt_processes[s].name = name;

    njt_sprintf(njt_processes[s].term_event, "njt_%s_term_%P%Z", name, pid);
    njt_sprintf(njt_processes[s].quit_event, "njt_%s_quit_%P%Z", name, pid);
    njt_sprintf(njt_processes[s].reopen_event, "njt_%s_reopen_%P%Z",
                name, pid);

    events[0] = njt_master_process_event;
    events[1] = ctx.child;

    rc = WaitForMultipleObjects(2, events, 0, 5000);

    njt_time_update();

    njt_log_debug1(NJT_LOG_DEBUG_CORE, cycle->log, 0,
                   "WaitForMultipleObjects: %ul", rc);

    switch (rc) {

    case WAIT_OBJECT_0:

        njt_processes[s].term = OpenEvent(EVENT_MODIFY_STATE, 0,
                                          (char *) njt_processes[s].term_event);
        if (njt_processes[s].term == NULL) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          "OpenEvent(\"%s\") failed",
                          njt_processes[s].term_event);
            goto failed;
        }

        njt_processes[s].quit = OpenEvent(EVENT_MODIFY_STATE, 0,
                                          (char *) njt_processes[s].quit_event);
        if (njt_processes[s].quit == NULL) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          "OpenEvent(\"%s\") failed",
                          njt_processes[s].quit_event);
            goto failed;
        }

        njt_processes[s].reopen = OpenEvent(EVENT_MODIFY_STATE, 0,
                                       (char *) njt_processes[s].reopen_event);
        if (njt_processes[s].reopen == NULL) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          "OpenEvent(\"%s\") failed",
                          njt_processes[s].reopen_event);
            goto failed;
        }

        if (ResetEvent(njt_master_process_event) == 0) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                          "ResetEvent(\"%s\") failed",
                          njt_master_process_event_name);
            goto failed;
        }

        break;

    case WAIT_OBJECT_0 + 1:
        if (GetExitCodeProcess(ctx.child, &code) == 0) {
            njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                          "GetExitCodeProcess(%P) failed", pid);
        }

        njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                      "%s process %P exited with code %Xl",
                      name, pid, code);

        goto failed;

    case WAIT_TIMEOUT:
        njt_log_error(NJT_LOG_ALERT, cycle->log, 0,
                      "the event \"%s\" was not signaled for 5s",
                      njt_master_process_event_name);
        goto failed;

    case WAIT_FAILED:
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "WaitForSingleObject(\"%s\") failed",
                      njt_master_process_event_name);

        goto failed;
    }

    if (respawn >= 0) {
        return pid;
    }

    switch (respawn) {

    case NJT_PROCESS_RESPAWN:
        njt_processes[s].just_spawn = 0;
        break;

    case NJT_PROCESS_JUST_RESPAWN:
        njt_processes[s].just_spawn = 1;
        break;
    }

    if (s == njt_last_process) {
        njt_last_process++;
    }

    return pid;

failed:

    if (njt_processes[s].reopen) {
        njt_close_handle(njt_processes[s].reopen);
    }

    if (njt_processes[s].quit) {
        njt_close_handle(njt_processes[s].quit);
    }

    if (njt_processes[s].term) {
        njt_close_handle(njt_processes[s].term);
    }

    TerminateProcess(njt_processes[s].handle, 2);

    if (njt_processes[s].handle) {
        njt_close_handle(njt_processes[s].handle);
        njt_processes[s].handle = NULL;
    }

    return NJT_INVALID_PID;
}


njt_pid_t
njt_execute(njt_cycle_t *cycle, njt_exec_ctx_t *ctx)
{
    STARTUPINFO          si;
    PROCESS_INFORMATION  pi;

    njt_memzero(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);

    njt_memzero(&pi, sizeof(PROCESS_INFORMATION));

    if (CreateProcess(ctx->path, ctx->args,
                      NULL, NULL, 0, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)
        == 0)
    {
        njt_log_error(NJT_LOG_CRIT, cycle->log, njt_errno,
                      "CreateProcess(\"%s\") failed", njt_argv[0]);

        return 0;
    }

    ctx->child = pi.hProcess;

    if (CloseHandle(pi.hThread) == 0) {
        njt_log_error(NJT_LOG_ALERT, cycle->log, njt_errno,
                      "CloseHandle(pi.hThread) failed");
    }

    njt_log_error(NJT_LOG_NOTICE, cycle->log, 0,
                  "start %s process %P", ctx->name, pi.dwProcessId);

    return pi.dwProcessId;
}
