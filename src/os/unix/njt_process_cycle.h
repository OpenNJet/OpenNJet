
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_PROCESS_CYCLE_H_INCLUDED_
#define _NJT_PROCESS_CYCLE_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


#define NJT_CMD_OPEN_CHANNEL   1
#define NJT_CMD_CLOSE_CHANNEL  2
#define NJT_CMD_QUIT           3
#define NJT_CMD_TERMINATE      4
#define NJT_CMD_REOPEN         5
#define NJT_CMD_RESTART        6

#define NJT_PROCESS_SINGLE     0
#define NJT_PROCESS_MASTER     1
#define NJT_PROCESS_SIGNALLER  2
#define NJT_PROCESS_WORKER     3
#define NJT_PROCESS_HELPER     4


typedef struct {
    njt_event_handler_pt       handler;
    char                      *name;
    njt_msec_t                 delay;
} njt_cache_manager_ctx_t;


void njt_master_process_cycle(njt_cycle_t *cycle);
void njt_single_process_cycle(njt_cycle_t *cycle);


extern njt_uint_t      njt_process;
extern njt_uint_t      njt_worker;
extern njt_pid_t       njt_pid;
extern njt_pid_t       njt_new_binary;
extern njt_uint_t      njt_inherited;
extern njt_uint_t      njt_daemonized;
extern njt_uint_t      njt_exiting;

extern sig_atomic_t    njt_reap;
extern sig_atomic_t    njt_sigio;
extern njt_uint_t      njt_is_privileged_agent;
extern sig_atomic_t    njt_sigalrm;
extern sig_atomic_t    njt_quit;
extern sig_atomic_t    njt_debug_quit;
extern sig_atomic_t    njt_terminate;
extern sig_atomic_t    njt_noaccept;
extern sig_atomic_t    njt_reconfigure;
extern sig_atomic_t    njt_reopen;
extern sig_atomic_t    njt_change_binary;
extern sig_atomic_t    njt_reap_helper;
extern sig_atomic_t    njt_rtc;
extern njt_uint_t      njt_is_privileged_helper;
extern njt_uint_t      njt_privileged_agent_exited;
#endif /* _NJT_PROCESS_CYCLE_H_INCLUDED_ */
