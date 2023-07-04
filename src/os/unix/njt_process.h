
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_PROCESS_H_INCLUDED_
#define _NJT_PROCESS_H_INCLUDED_


#include <njt_setaffinity.h>
#include <njt_setproctitle.h>


typedef pid_t       njt_pid_t;

#define NJT_INVALID_PID  -1

typedef void (*njt_spawn_preproc_pt) (njt_cycle_t *cycle, void *data, njt_int_t *reload, void *process);
typedef void (*njt_spawn_proc_pt) (njt_cycle_t *cycle, void *data);

typedef struct {
    njt_pid_t           pid;
    int                 status;
    njt_socket_t        channel[2];

    njt_spawn_proc_pt   proc;
    njt_spawn_preproc_pt   preproc;
    void               *data;
    char               *name;
    u_char              param_md5[16];
    unsigned            respawn:1;
    unsigned            just_spawn:1;
    unsigned            detached:1;
    unsigned            exiting:1;
    unsigned            exited:1;
    unsigned            reload:1;
    unsigned            confed:1;
} njt_process_t;


typedef struct {
    char         *path;
    char         *name;
    char *const  *argv;
    char *const  *envp;
} njt_exec_ctx_t;


#define NJT_MAX_PROCESSES         1024

#define NJT_PROCESS_NORESPAWN     -1
#define NJT_PROCESS_JUST_SPAWN    -2
#define NJT_PROCESS_RESPAWN       -3
#define NJT_PROCESS_JUST_RESPAWN  -4
#define NJT_PROCESS_DETACHED      -5


#define njt_getpid   getpid
#define njt_getppid  getppid

#ifndef njt_log_pid
#define njt_log_pid  njt_pid
#endif


njt_pid_t njt_spawn_process(njt_cycle_t *cycle,
    njt_spawn_proc_pt proc, void *data, char *name, njt_int_t respawn, njt_spawn_preproc_pt preproc);
njt_pid_t njt_execute(njt_cycle_t *cycle, njt_exec_ctx_t *ctx);
njt_int_t njt_init_signals(njt_log_t *log);
void njt_debug_point(void);


#if (NJT_HAVE_SCHED_YIELD)
#define njt_sched_yield()  sched_yield()
#else
#define njt_sched_yield()  usleep(1)
#endif


extern int            njt_argc;
extern char         **njt_argv;
extern char         **njt_os_argv;

extern njt_pid_t      njt_pid;
extern njt_pid_t      njt_parent;
extern njt_socket_t   njt_channel;
extern njt_int_t      njt_process_slot;
extern njt_int_t      njt_last_process;
extern njt_process_t  njt_processes[NJT_MAX_PROCESSES];
extern njt_process_t  njt_shrink_processes[NJT_MAX_PROCESSES];
extern njt_int_t      njt_shrink_count;
extern njt_int_t      njt_shrink_finish_count;

#endif /* _NJT_PROCESS_H_INCLUDED_ */
