
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_PROCESS_H_INCLUDED_
#define _NJT_PROCESS_H_INCLUDED_


typedef DWORD               njt_pid_t;
#define NJT_INVALID_PID     0


#define njt_getpid          GetCurrentProcessId
#define njt_getppid()       0
#define njt_log_pid         njt_pid


#define NJT_PROCESS_SYNC_NAME                                                 \
    (sizeof("njt_cache_manager_mutex_") + NJT_INT32_LEN)


typedef uint64_t            njt_cpuset_t;


typedef struct {
    HANDLE                  handle;
    njt_pid_t               pid;
    char                   *name;

    HANDLE                  term;
    HANDLE                  quit;
    HANDLE                  reopen;

    u_char                  term_event[NJT_PROCESS_SYNC_NAME];
    u_char                  quit_event[NJT_PROCESS_SYNC_NAME];
    u_char                  reopen_event[NJT_PROCESS_SYNC_NAME];

    unsigned                just_spawn:1;
    unsigned                exiting:1;
} njt_process_t;


typedef struct {
    char                   *path;
    char                   *name;
    char                   *args;
    char *const            *argv;
    char *const            *envp;
    HANDLE                  child;
} njt_exec_ctx_t;


njt_pid_t njt_spawn_process(njt_cycle_t *cycle, char *name, njt_int_t respawn);
njt_pid_t njt_execute(njt_cycle_t *cycle, njt_exec_ctx_t *ctx);

#define njt_debug_point()
#define njt_sched_yield()   SwitchToThread()


#define NJT_MAX_PROCESSES         (MAXIMUM_WAIT_OBJECTS - 4)

#define NJT_PROCESS_RESPAWN       -2
#define NJT_PROCESS_JUST_RESPAWN  -3


extern int                  njt_argc;
extern char               **njt_argv;
extern char               **njt_os_argv;

extern njt_int_t            njt_last_process;
extern njt_process_t        njt_processes[NJT_MAX_PROCESSES];

extern njt_pid_t            njt_pid;
extern njt_pid_t            njt_parent;


#endif /* _NJT_PROCESS_H_INCLUDED_ */
