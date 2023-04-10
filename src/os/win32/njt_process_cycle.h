
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_PROCESS_CYCLE_H_INCLUDED_
#define _NJT_PROCESS_CYCLE_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


#define NJT_PROCESS_SINGLE     0
#define NJT_PROCESS_MASTER     1
#define NJT_PROCESS_SIGNALLER  2
#define NJT_PROCESS_WORKER     3


void njt_master_process_cycle(njt_cycle_t *cycle);
void njt_single_process_cycle(njt_cycle_t *cycle);
void njt_close_handle(HANDLE h);


extern njt_uint_t      njt_process;
extern njt_uint_t      njt_worker;
extern njt_pid_t       njt_pid;
extern njt_uint_t      njt_exiting;

extern sig_atomic_t    njt_quit;
extern sig_atomic_t    njt_terminate;
extern sig_atomic_t    njt_reopen;

extern njt_uint_t      njt_inherited;
extern njt_pid_t       njt_new_binary;


extern HANDLE          njt_master_process_event;
extern char            njt_master_process_event_name[];


#endif /* _NJT_PROCESS_CYCLE_H_INCLUDED_ */
